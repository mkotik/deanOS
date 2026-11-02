//! PL011 / SBSA Generic UART driver (output only for M1).
//!
//! The SBSA Generic UART is a fixed-config PL011 subset: we never touch baud
//! or line-control registers (firmware owns them), only DR and FR — which is
//! exactly the subset shared by both SPCR subtypes.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

const DR: usize = 0x000;
const FR: usize = 0x018;
const FR_TXFF: u32 = 1 << 5;

/// MMIO base of the console UART; 0 = not initialized (writes are dropped).
/// Single core, but written once at boot and read from panic/IRQ contexts,
/// so keep it atomic.
static UART_BASE: AtomicU64 = AtomicU64::new(0);

pub fn init(base: u64) {
    UART_BASE.store(base, Ordering::Release);
}

#[inline]
fn mmio_read(base: u64, off: usize) -> u32 {
    unsafe { core::ptr::read_volatile((base as usize + off) as *const u32) }
}

#[inline]
fn mmio_write(base: u64, off: usize, val: u32) {
    unsafe { core::ptr::write_volatile((base as usize + off) as *mut u32, val) }
}

pub fn putb(b: u8) {
    let base = UART_BASE.load(Ordering::Acquire);
    if base == 0 {
        return;
    }
    while mmio_read(base, FR) & FR_TXFF != 0 {
        core::hint::spin_loop();
    }
    mmio_write(base, DR, b as u32);
}

// --- Raw formatting helpers -------------------------------------------------
// The prebuilt `core` is NOT strict-align: core::fmt faults while the MMU is
// off (all memory Device-nGnRnE). These helpers compile in our strict-align
// crate only, so they are safe in the pre-MMU window. Use core::fmt (kprint!)
// only once the MMU is on.

pub fn puts(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            putb(b'\r');
        }
        putb(b);
    }
}

pub fn put_hex(v: u64) {
    puts("0x");
    let mut started = false;
    for i in (0..16).rev() {
        let d = ((v >> (i * 4)) & 0xf) as u8;
        if d == 0 && !started && i != 0 {
            continue;
        }
        started = true;
        putb(if d < 10 { b'0' + d } else { b'a' + d - 10 });
    }
}

pub fn put_dec(v: u64) {
    let mut buf = [0u8; 20];
    let mut i = buf.len();
    let mut v = v;
    loop {
        i -= 1;
        buf[i] = b'0' + (v % 10) as u8;
        v /= 10;
        if v == 0 {
            break;
        }
    }
    for &b in &buf[i..] {
        putb(b);
    }
}

/// Zero-sized `fmt::Write` sink over the global console UART.
pub struct Console;

impl fmt::Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                putb(b'\r');
            }
            putb(b);
        }
        Ok(())
    }
}

#[macro_export]
macro_rules! kprint {
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = write!($crate::drivers::uart::Console, $($arg)*);
    }};
}

#[macro_export]
macro_rules! kprintln {
    () => { $crate::kprint!("\n") };
    ($($arg:tt)*) => {{
        use core::fmt::Write;
        let _ = writeln!($crate::drivers::uart::Console, $($arg)*);
    }};
}
