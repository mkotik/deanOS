//! GICv3: Distributor + first Redistributor + system-register CPU interface.
//! Single-core bring-up; ITS/LPI setup arrives with the VirtIO MSI-X work (M4).
//!
//! ICC_* system registers use explicit S3_* encodings so the integrated
//! assembler accepts them regardless of target CPU features.

use core::sync::atomic::{AtomicU64, Ordering};

static GICD: AtomicU64 = AtomicU64::new(0);
static GICR_SGI: AtomicU64 = AtomicU64::new(0);

const GICD_CTLR: usize = 0x0000;
const GICD_ISENABLER: usize = 0x0100;
const GICD_ICENABLER: usize = 0x0180;
const GICD_IPRIORITYR: usize = 0x0400;
const GICD_IGROUPR: usize = 0x0080;
const GICD_IROUTER: usize = 0x6100;

const GICR_WAKER: usize = 0x0014; // RD frame
const GICR_IGROUPR0: usize = 0x0080; // SGI frame
const GICR_ISENABLER0: usize = 0x0100;
const GICR_IPRIORITYR: usize = 0x0400;

#[inline]
fn w32(base: u64, off: usize, v: u32) {
    unsafe { core::ptr::write_volatile((base as usize + off) as *mut u32, v) }
}
#[inline]
fn r32(base: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base as usize + off) as *const u32) }
}

macro_rules! sysreg_rw {
    ($read:ident, $write:ident, $reg:literal) => {
        #[inline]
        pub fn $read() -> u64 {
            let v: u64;
            unsafe { core::arch::asm!(concat!("mrs {}, ", $reg), out(reg) v) };
            v
        }
        #[inline]
        pub fn $write(v: u64) {
            unsafe { core::arch::asm!(concat!("msr ", $reg, ", {}"), in(reg) v) };
        }
    };
}

sysreg_rw!(icc_sre_read, icc_sre_write, "S3_0_C12_C12_5"); // ICC_SRE_EL1
sysreg_rw!(icc_pmr_read, icc_pmr_write, "S3_0_C4_C6_0"); // ICC_PMR_EL1
sysreg_rw!(icc_igrpen1_read, icc_igrpen1_write, "S3_0_C12_C12_7"); // ICC_IGRPEN1_EL1
sysreg_rw!(icc_iar1_read, icc_iar1_write, "S3_0_C12_C12_0"); // ICC_IAR1_EL1 (RO)
sysreg_rw!(icc_eoir1_read, icc_eoir1_write, "S3_0_C12_C12_1"); // ICC_EOIR1_EL1 (WO)

/// Initialize GICD + our redistributor + CPU interface. `gicr_base` is the
/// start of the redistributor discovery range; single core → first frame.
pub fn init(gicd_base: u64, gicr_base: u64) {
    GICD.store(gicd_base, Ordering::Release);
    // Redistributor: RD frame at +0, SGI frame at +0x10000 (GICv3 stride).
    GICR_SGI.store(gicr_base + 0x10000, Ordering::Release);

    // Distributor: ARE first, then enable Group 1 (same bit positions in both
    // the DS=1 and non-secure DS=0 views).
    w32(gicd_base, GICD_CTLR, r32(gicd_base, GICD_CTLR) | (1 << 4)); // ARE
    while r32(gicd_base, GICD_CTLR) & (1 << 31) != 0 {} // RWP
    w32(gicd_base, GICD_CTLR, r32(gicd_base, GICD_CTLR) | (1 << 1)); // EnableGrp1
    while r32(gicd_base, GICD_CTLR) & (1 << 31) != 0 {}

    // Redistributor wake: clear ProcessorSleep, wait for ChildrenAsleep=0.
    let rd = gicr_base;
    w32(rd, GICR_WAKER, r32(rd, GICR_WAKER) & !(1 << 1));
    while r32(rd, GICR_WAKER) & (1 << 2) != 0 {}

    // All SGIs/PPIs → Group 1.
    let sgi = GICR_SGI.load(Ordering::Acquire);
    w32(sgi, GICR_IGROUPR0, 0xffff_ffff);

    // CPU interface.
    icc_sre_write(icc_sre_read() | 1); // SRE: sysreg interface
    unsafe { core::arch::asm!("isb") };
    icc_pmr_write(0xff); // allow all priorities
    icc_igrpen1_write(1); // enable Group 1
    unsafe { core::arch::asm!("isb") };
}

/// Enable a PPI/SGI (intid < 32) at the redistributor.
pub fn enable_ppi(intid: u32) {
    let sgi = GICR_SGI.load(Ordering::Acquire);
    // Priority 0x80 (one byte per intid).
    let off = GICR_IPRIORITYR + intid as usize;
    unsafe { core::ptr::write_volatile((sgi as usize + off) as *mut u8, 0x80) };
    w32(sgi, GICR_ISENABLER0, 1 << intid);
}

/// Enable an SPI (32..1020) at the distributor, routed to CPU 0.
pub fn enable_spi(intid: u32) {
    let d = GICD.load(Ordering::Acquire);
    w32(d, GICD_IGROUPR + (intid as usize / 32) * 4, {
        r32(d, GICD_IGROUPR + (intid as usize / 32) * 4) | (1 << (intid % 32))
    });
    unsafe {
        core::ptr::write_volatile((d as usize + GICD_IPRIORITYR + intid as usize) as *mut u8, 0x80);
        // IROUTER: affinity 0.0.0.0 (this CPU)
        core::ptr::write_volatile(
            (d as usize + GICD_IROUTER + (intid as usize - 32) * 8) as *mut u64,
            0,
        );
    }
    w32(d, GICD_ISENABLER + (intid as usize / 32) * 4, 1 << (intid % 32));
}

#[allow(dead_code)]
pub fn disable_spi(intid: u32) {
    let d = GICD.load(Ordering::Acquire);
    w32(d, GICD_ICENABLER + (intid as usize / 32) * 4, 1 << (intid % 32));
}

/// Acknowledge one pending interrupt. Returns None when spurious (1020..1023).
pub fn ack() -> Option<u32> {
    let id = (icc_iar1_read() & 0xff_ffff) as u32;
    if (1020..1024).contains(&id) {
        None
    } else {
        Some(id)
    }
}

pub fn eoi(intid: u32) {
    icc_eoir1_write(intid as u64);
}
