//! 4-level, 4 KiB-granule identity-mapped (VA == PA) page tables in TTBR0_EL1.
//!
//! MAIR: Attr0 = Device-nGnRnE (idx 0), Attr1 = Normal Write-Back (idx 1).
//! RAM gets 2 MiB blocks where possible; the kernel image region is forced to
//! 4 KiB pages so PE sections get exact W^X and the stack guard can be punched.

use crate::mm::frames;

pub const MAIR: u64 = 0xFF << 8; // Attr0=0x00 Device-nGnRnE, Attr1=0xFF Normal WB

const BLOCK_2M: u64 = 2 * 1024 * 1024;
const PAGE: u64 = 4096;

// Descriptor bits
const VALID: u64 = 1 << 0;
const TABLE: u64 = 1 << 1; // in non-leaf levels
const PAGE_DESC: u64 = 1 << 1; // in level 3
const AF: u64 = 1 << 10;
const SH_INNER: u64 = 3 << 8;
const AP_RO: u64 = 1 << 7;
const PXN: u64 = 1 << 53;
const UXN: u64 = 1 << 54;
const ATTR_DEVICE: u64 = 0 << 2;
const ATTR_NORMAL: u64 = 1 << 2;

#[derive(Clone, Copy, PartialEq)]
pub enum Attr {
    NormalRw,
    NormalRo,
    /// RO + executable at EL1 (kernel .text)
    NormalRx,
    Device,
}

fn leaf_bits(a: Attr) -> u64 {
    match a {
        Attr::NormalRw => ATTR_NORMAL | SH_INNER | AF | PXN | UXN,
        Attr::NormalRo => ATTR_NORMAL | SH_INNER | AF | AP_RO | PXN | UXN,
        Attr::NormalRx => ATTR_NORMAL | SH_INNER | AF | AP_RO | UXN,
        Attr::Device => ATTR_DEVICE | AF | PXN | UXN,
    }
}

static mut ROOT: u64 = 0;

fn root() -> u64 {
    unsafe { ROOT }
}

#[inline]
unsafe fn entry(table: u64, idx: usize) -> *mut u64 {
    (table as *mut u64).add(idx)
}

/// Walk to the table at `level` for va, allocating intermediate tables.
/// Levels: 0 (512 GiB) → 1 (1 GiB) → 2 (2 MiB) → 3 (4 KiB).
unsafe fn table_for(va: u64, level: usize) -> u64 {
    let mut t = root();
    for l in 0..level {
        let shift = 39 - 9 * l;
        let idx = ((va >> shift) & 0x1ff) as usize;
        let e = entry(t, idx);
        let v = e.read();
        if v & VALID == 0 {
            let new = frames::alloc().expect("oom: page table");
            e.write(new | VALID | TABLE);
            t = new;
        } else {
            debug_assert!(v & TABLE != 0, "splitting blocks is unsupported");
            t = v & 0x0000_FFFF_FFFF_F000;
        }
    }
    t
}

/// Identity-map [pa, pa+len) with `attr`. Ranges overlapping
/// [no_block_start, no_block_end) are forced down to 4 KiB pages.
pub fn map_range(pa: u64, len: u64, attr: Attr, no_block: (u64, u64)) {
    let mut cur = pa & !(PAGE - 1);
    let end = (pa + len + PAGE - 1) & !(PAGE - 1);
    unsafe {
        while cur < end {
            let in_noblock = cur < no_block.1 && cur + BLOCK_2M > no_block.0;
            if cur % BLOCK_2M == 0 && cur + BLOCK_2M <= end && !in_noblock {
                let t = table_for(cur, 2);
                let idx = ((cur >> 21) & 0x1ff) as usize;
                entry(t, idx).write(cur | leaf_bits(attr) | VALID); // block: bit1=0
                cur += BLOCK_2M;
            } else {
                let t = table_for(cur, 3);
                let idx = ((cur >> 12) & 0x1ff) as usize;
                entry(t, idx).write(cur | leaf_bits(attr) | VALID | PAGE_DESC);
                cur += PAGE;
            }
        }
    }
}

/// Rewrite existing 4 KiB leaf PTEs (image region) with new attributes.
pub fn protect_range(pa: u64, len: u64, attr: Attr) {
    let mut cur = pa & !(PAGE - 1);
    let end = (pa + len + PAGE - 1) & !(PAGE - 1);
    unsafe {
        while cur < end {
            let t = table_for(cur, 3);
            let idx = ((cur >> 12) & 0x1ff) as usize;
            entry(t, idx).write(cur | leaf_bits(attr) | VALID | PAGE_DESC);
            cur += PAGE;
        }
    }
}

/// Remove a single 4 KiB mapping (guard pages).
pub fn unmap_page(pa: u64) {
    unsafe {
        let t = table_for(pa, 3);
        entry(t, ((pa >> 12) & 0x1ff) as usize).write(0);
    }
}

/// Map device MMIO at runtime (M4: PCI BARs). Safe post-enable: new leaf
/// entries need no break-before-make, just a barrier before first use.
pub fn map_device(pa: u64, len: u64) {
    map_range(pa, len, Attr::Device, (0, 0));
    unsafe {
        core::arch::asm!("dsb ishst; tlbi vmalle1; dsb ish; isb");
    }
}

const MEM_MMIO: u32 = 11;
const MEM_MMIO_PORT: u32 = 12;
const MEM_UNUSABLE: u32 = 8;
const MEM_RESERVED: u32 = 0;

/// Build the full identity map from the UEFI memory map + ACPI MMIO bases,
/// apply PE W^X + stack guard, then switch TTBR0_EL1 (via arch::enable_mmu).
pub fn init(bi: &crate::BootInfo, stack_guard_page: u64) {
    unsafe {
        ROOT = frames::alloc().expect("oom: root table");
    }

    let image = (bi.image_base, bi.image_base + bi.image_size);

    // RAM + firmware regions from the UEFI map. Everything Normal RW except
    // MMIO (Device) and truly unusable ranges (skipped).
    for d in bi.mmap.iter() {
        let len = d.number_of_pages * PAGE;
        match d.typ {
            MEM_UNUSABLE | MEM_RESERVED => {}
            MEM_MMIO | MEM_MMIO_PORT => map_range(d.physical_start, len, Attr::Device, (0, 0)),
            _ => map_range(d.physical_start, len, Attr::NormalRw, image),
        }
    }

    // MMIO the firmware may not list in the memory map: UART, GIC, ECAM.
    let a = &bi.acpi;
    if a.uart_base != 0 {
        map_range(a.uart_base, PAGE, Attr::Device, (0, 0));
    }
    if a.gicd_base != 0 {
        map_range(a.gicd_base, 0x10000, Attr::Device, (0, 0));
    }
    if a.gicr_base != 0 {
        let len = if a.gicr_len != 0 { a.gicr_len as u64 } else { 0x20000 };
        map_range(a.gicr_base, len, Attr::Device, (0, 0));
    }
    if a.its_base != 0 {
        map_range(a.its_base, 0x20000, Attr::Device, (0, 0));
    }
    if a.ecam_base != 0 {
        let buses = (a.bus_end as u64 - a.bus_start as u64) + 1;
        map_range(a.ecam_base, buses << 20, Attr::Device, (0, 0));
    }

    // PE W^X: walk our own section table and tighten the image mapping.
    apply_pe_wx(bi.image_base);

    // Stack guard: punch a hole below the kernel stack.
    unmap_page(stack_guard_page);

    unsafe { crate::arch::enable_mmu(root(), tcr(), MAIR) };
}

fn tcr() -> u64 {
    // 48-bit VA (T0SZ=16), 4 KiB granule, inner-shareable WB walks, no TTBR1.
    let parange = {
        let v: u64;
        unsafe { core::arch::asm!("mrs {}, id_aa64mmfr0_el1", out(reg) v) };
        (v & 0xf).min(5)
    };
    (16 << 0) | (1 << 8) | (1 << 10) | (3 << 12) | (1 << 23) | (parange << 32)
}

fn apply_pe_wx(base: u64) {
    const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
    const SCN_MEM_WRITE: u32 = 0x8000_0000;
    unsafe {
        let e_lfanew = core::ptr::read_unaligned((base + 0x3c) as *const u32) as u64;
        let pe = base + e_lfanew;
        if core::ptr::read_unaligned(pe as *const u32) != 0x0000_4550 {
            return; // "PE\0\0" missing — leave image RW
        }
        let coff = pe + 4;
        let nsections = core::ptr::read_unaligned((coff + 2) as *const u16) as u64;
        let opt_size = core::ptr::read_unaligned((coff + 16) as *const u16) as u64;
        let sections = coff + 20 + opt_size;
        for i in 0..nsections {
            let s = sections + i * 40;
            let vsize = core::ptr::read_unaligned((s + 8) as *const u32) as u64;
            let va = core::ptr::read_unaligned((s + 12) as *const u32) as u64;
            let ch = core::ptr::read_unaligned((s + 36) as *const u32);
            let attr = if ch & SCN_MEM_EXECUTE != 0 {
                Attr::NormalRx
            } else if ch & SCN_MEM_WRITE != 0 {
                Attr::NormalRw
            } else {
                Attr::NormalRo
            };
            protect_range(base + va, vsize, attr);
        }
    }
}
