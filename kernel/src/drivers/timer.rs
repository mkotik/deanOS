//! ARM Generic Virtual Timer (CNTV): monotonic clock + one-shot deadline.

#[inline]
pub fn freq() -> u64 {
    let f: u64;
    unsafe { core::arch::asm!("mrs {}, cntfrq_el0", out(reg) f) };
    f
}

/// Raw monotonic ticks (CNTVCT_EL0, guest-virtual: CNTVOFF already zeroed).
#[inline]
pub fn ticks() -> u64 {
    let t: u64;
    unsafe { core::arch::asm!("isb; mrs {}, cntvct_el0", out(reg) t) };
    t
}

#[inline]
pub fn ms_to_ticks(ms: u64) -> u64 {
    ms * freq() / 1000
}

#[inline]
pub fn ticks_to_ms(t: u64) -> u64 {
    t * 1000 / freq()
}

pub fn now_ms() -> u64 {
    ticks_to_ms(ticks())
}

/// Arm the one-shot virtual timer to fire at absolute tick `deadline`.
pub fn arm(deadline: u64) {
    unsafe {
        core::arch::asm!(
            "msr cntv_cval_el0, {d}",
            "mov {t}, #1",
            "msr cntv_ctl_el0, {t}", // ENABLE=1, IMASK=0
            d = in(reg) deadline,
            t = out(reg) _,
        );
    }
}

/// Stop the timer (also used by the ISR: CNTV is level-triggered, so it must
/// be silenced before EOI or it re-fires forever).
pub fn disarm() {
    unsafe { core::arch::asm!("msr cntv_ctl_el0, xzr") };
}
