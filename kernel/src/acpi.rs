//! Static ACPI table parsing: RSDP → XSDT → SPCR / MADT / MCFG / GTDT.
//! No AML/DSDT interpreter by design (PLAN.md §1) — only fixed-layout tables.
//!
//! XSDT entries sit at offset 36 and are NOT 8-byte aligned; with
//! +strict-align every multi-byte field read here must be `read_unaligned`.

#[derive(Clone, Copy)]
pub struct AcpiInfo {
    pub rsdp: u64,
    pub xsdt: u64,
    /// SPCR UART MMIO base (0 if absent) + interface subtype.
    pub uart_base: u64,
    pub uart_subtype: u8,
    pub gicd_base: u64,
    pub gic_version: u8,
    /// GICR discovery range from MADT type 0x0E, or per-CPU GICR base from
    /// the GICC entry when no 0x0E entry exists.
    pub gicr_base: u64,
    pub gicr_len: u32,
    pub its_base: u64,
    pub ecam_base: u64,
    pub bus_start: u8,
    pub bus_end: u8,
    pub vtimer_gsiv: u32,
}

impl AcpiInfo {
    pub const fn empty() -> Self {
        AcpiInfo {
            rsdp: 0,
            xsdt: 0,
            uart_base: 0,
            uart_subtype: 0,
            gicd_base: 0,
            gic_version: 0,
            gicr_base: 0,
            gicr_len: 0,
            its_base: 0,
            ecam_base: 0,
            bus_start: 0,
            bus_end: 0,
            vtimer_gsiv: 27, // architectural default (PPI 27) if GTDT is missing
        }
    }
}

#[inline]
unsafe fn ru8(p: u64) -> u8 {
    core::ptr::read_volatile(p as *const u8)
}
#[inline]
unsafe fn ru32(p: u64) -> u32 {
    core::ptr::read_unaligned(p as *const u32)
}
#[inline]
unsafe fn ru64(p: u64) -> u64 {
    core::ptr::read_unaligned(p as *const u64)
}

unsafe fn checksum_ok(base: u64, len: usize) -> bool {
    let mut sum = 0u8;
    for i in 0..len {
        sum = sum.wrapping_add(ru8(base + i as u64));
    }
    sum == 0
}

unsafe fn sig_at(base: u64) -> [u8; 4] {
    [ru8(base), ru8(base + 1), ru8(base + 2), ru8(base + 3)]
}

/// Parse everything we need from the RSDP pointer found in the UEFI
/// configuration table. Safe to call before or after ExitBootServices (the
/// tables live in AcpiReclaim memory, which we never reuse).
pub unsafe fn parse(rsdp: u64) -> AcpiInfo {
    let mut info = AcpiInfo::empty();
    info.rsdp = rsdp;

    // RSDP: "RSD PTR ", revision >= 2 for XSDT (OCI + QEMU are ACPI 2.0+).
    let sig_ok = (0..8).all(|i| ru8(rsdp + i) == b"RSD PTR "[i as usize]);
    if !sig_ok || ru8(rsdp + 15) < 2 || !checksum_ok(rsdp, 20) {
        return info;
    }
    let xsdt = ru64(rsdp + 24);
    if xsdt == 0 {
        return info;
    }
    info.xsdt = xsdt;

    let xsdt_len = ru32(xsdt + 4) as u64;
    if &sig_at(xsdt) != b"XSDT" || !checksum_ok(xsdt, xsdt_len as usize) {
        return info;
    }

    let n_entries = (xsdt_len - 36) / 8;
    for i in 0..n_entries {
        let table = ru64(xsdt + 36 + i * 8);
        if table == 0 {
            continue;
        }
        let len = ru32(table + 4) as usize;
        if !checksum_ok(table, len) {
            continue;
        }
        match &sig_at(table) {
            b"SPCR" => parse_spcr(table, &mut info),
            b"APIC" => parse_madt(table, len, &mut info),
            b"MCFG" => parse_mcfg(table, len, &mut info),
            b"GTDT" => parse_gtdt(table, len, &mut info),
            _ => {}
        }
    }
    info
}

unsafe fn parse_spcr(t: u64, info: &mut AcpiInfo) {
    // Offset 36: interface subtype (0x03 = PL011, 0x0e = SBSA 32-bit, ...).
    // Offset 40: Generic Address Structure; the MMIO address is at GAS+4.
    info.uart_subtype = ru8(t + 36);
    let space_id = ru8(t + 40);
    if space_id == 0 {
        // System Memory space
        info.uart_base = ru64(t + 44);
    }
}

unsafe fn parse_madt(t: u64, len: usize, info: &mut AcpiInfo) {
    let mut off = 44u64; // interrupt controller structures start here
    let mut gicc_gicr = 0u64;
    while (off as usize) < len {
        let typ = ru8(t + off);
        let elen = ru8(t + off + 1) as u64;
        if elen == 0 {
            break;
        }
        match typ {
            0x0b => {
                // GICC: GICR Base Address at offset 60 (per-CPU, fallback only)
                if elen >= 68 {
                    gicc_gicr = ru64(t + off + 60);
                }
            }
            0x0c => {
                // GICD: physical base at offset 8, version at offset 20
                info.gicd_base = ru64(t + off + 8);
                info.gic_version = ru8(t + off + 20);
            }
            0x0e => {
                // GICR discovery range: base at 4, length at 12
                info.gicr_base = ru64(t + off + 4);
                info.gicr_len = ru32(t + off + 12);
            }
            0x0f => {
                // GIC ITS: physical base at offset 8
                info.its_base = ru64(t + off + 8);
            }
            _ => {}
        }
        off += elen;
    }
    if info.gicr_base == 0 {
        info.gicr_base = gicc_gicr;
    }
}

unsafe fn parse_mcfg(t: u64, len: usize, info: &mut AcpiInfo) {
    // Header 36 bytes + 8 reserved, then 16-byte allocation entries.
    if len < 60 {
        return;
    }
    let e = t + 44;
    info.ecam_base = ru64(e);
    info.bus_start = ru8(e + 10);
    info.bus_end = ru8(e + 11);
}

unsafe fn parse_gtdt(t: u64, len: usize, info: &mut AcpiInfo) {
    // Virtual EL1 timer GSIV at offset 64.
    if len >= 68 {
        let gsiv = ru32(t + 64);
        if gsiv != 0 {
            info.vtimer_gsiv = gsiv;
        }
    }
}
