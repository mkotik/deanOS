//! Single-thread async executor (PLAN.md §2.5).
//!
//! Fixed task slots + an atomic wake bitmap. Wakers store the task id in the
//! RawWaker data pointer; `wake` is one ISR-safe `fetch_or`. The idle loop is
//! the race-free DAIF/wfi sequence: drain → mask → re-check → wfi → unmask
//! (ARM64 wfi wakes on a pending GIC IRQ even with PSTATE.I masked).

use crate::drivers::{gicv3, timer};
use alloc::boxed::Box;
use core::future::Future;
use core::pin::Pin;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use core::task::{Context, Poll, RawWaker, RawWakerVTable, Waker};

pub const MAX_TASKS: usize = 64;

struct Slots {
    tasks: [Option<Pin<Box<dyn Future<Output = ()>>>>; MAX_TASKS],
}

const NONE: Option<Pin<Box<dyn Future<Output = ()>>>> = None;
static mut SLOTS: Slots = Slots {
    tasks: [NONE; MAX_TASKS],
};

/// Wake bitmap — the only state ISRs touch besides hardware.
static WAKE: AtomicU64 = AtomicU64::new(0);
/// Set by the timer ISR after silencing CNTV; the loop re-arms from the queue.
pub static TIMER_FIRED: AtomicBool = AtomicBool::new(false);

// --- Waker ------------------------------------------------------------------

static VTABLE: RawWakerVTable = RawWakerVTable::new(
    |d| RawWaker::new(d, &VTABLE),
    |d| wake_task(d as usize),
    |d| wake_task(d as usize),
    |_| {},
);

fn wake_task(id: usize) {
    WAKE.fetch_or(1 << id, Ordering::Release);
}

fn waker(id: usize) -> Waker {
    unsafe { Waker::from_raw(RawWaker::new(id as *const (), &VTABLE)) }
}

// --- Timer queue (executor context only; ISR never touches it) --------------

struct TimerQ {
    entries: alloc::vec::Vec<(u64, Waker)>, // (absolute deadline ticks, waker)
}

static mut TIMERQ: TimerQ = TimerQ {
    entries: alloc::vec::Vec::new(),
};

/// Called from Sleep::poll (executor context).
pub fn register_timer(deadline: u64, w: Waker) {
    #[allow(static_mut_refs)]
    unsafe {
        TIMERQ.entries.push((deadline, w))
    };
}

/// Wake expired entries; return the next pending deadline.
fn drain_timers(now: u64) -> Option<u64> {
    #[allow(static_mut_refs)]
    let q = unsafe { &mut TIMERQ };
    let mut i = 0;
    while i < q.entries.len() {
        if q.entries[i].0 <= now {
            let (_, w) = q.entries.swap_remove(i);
            w.wake();
        } else {
            i += 1;
        }
    }
    q.entries.iter().map(|e| e.0).min()
}

// --- Spawn / run -------------------------------------------------------------

/// Deferred spawn queue: tasks may spawn tasks mid-poll without aliasing the
/// slot table — run() installs them between polls.
static PENDING: crate::runtime::SingleCore<alloc::vec::Vec<Pin<Box<dyn Future<Output = ()>>>>> =
    crate::runtime::SingleCore::new(alloc::vec::Vec::new());

pub fn spawn(fut: impl Future<Output = ()> + 'static) {
    PENDING.0.borrow_mut().push(Box::pin(fut));
}

fn install_pending() {
    let mut q = PENDING.0.borrow_mut();
    if q.is_empty() {
        return;
    }
    #[allow(static_mut_refs)]
    let slots = unsafe { &mut SLOTS };
    while let Some(fut) = q.pop() {
        let Some(i) = slots.tasks.iter().position(|s| s.is_none()) else {
            panic!("executor: no free task slots");
        };
        slots.tasks[i] = Some(fut);
        wake_task(i);
    }
}

#[inline]
fn irq_mask() {
    unsafe { core::arch::asm!("msr daifset, #2") };
}
#[inline]
fn irq_unmask() {
    unsafe { core::arch::asm!("msr daifclr, #2") };
}

pub fn run() -> ! {
    irq_unmask();
    loop {
        // 0. Install tasks spawned since the last round.
        install_pending();

        // 1. Drain the wake bitmap and poll every runnable task.
        let mut bits = WAKE.swap(0, Ordering::Acquire);
        while bits != 0 {
            let id = bits.trailing_zeros() as usize;
            bits &= !(1 << id);
            #[allow(static_mut_refs)]
            let slot = unsafe { &mut SLOTS.tasks[id] };
            if let Some(fut) = slot {
                let w = waker(id);
                let mut cx = Context::from_waker(&w);
                if let Poll::Ready(()) = fut.as_mut().poll(&mut cx) {
                    *slot = None;
                }
            }
        }

        // 2. Expire timers and arm the next deadline.
        TIMER_FIRED.store(false, Ordering::Relaxed);
        match drain_timers(timer::ticks()) {
            Some(next) => timer::arm(next),
            None => timer::disarm(),
        }

        // 3. Race-free idle: mask, re-check, wfi (wakes on pending IRQ even
        //    while masked), unmask (ISR runs here), repeat.
        irq_mask();
        if WAKE.load(Ordering::Acquire) == 0
            && !TIMER_FIRED.load(Ordering::Relaxed)
            && PENDING.0.borrow().is_empty()
        {
            unsafe { core::arch::asm!("dsb sy", "wfi") };
        }
        irq_unmask();
        unsafe { core::arch::asm!("isb") };
    }
}

// --- IRQ dispatch (called from the vector asm, all GPRs/SIMD saved) ----------

/// MSI/LPI and SPI handlers registered by drivers (M4+): intid -> waker bit.
static IRQ_WAKE_TASK: [AtomicU64; 4] = [
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
];
static IRQ_WAKE_INTID: [AtomicU64; 4] = [
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
    AtomicU64::new(u64::MAX),
];

/// Route `intid` to wake task `task_id` (driver bring-up, executor context).
pub fn route_irq(intid: u32, task_id: usize) {
    for i in 0..4 {
        if IRQ_WAKE_INTID[i].load(Ordering::Relaxed) == u64::MAX {
            IRQ_WAKE_INTID[i].store(intid as u64, Ordering::Relaxed);
            IRQ_WAKE_TASK[i].store(task_id as u64, Ordering::Release);
            return;
        }
    }
    panic!("route_irq: table full");
}

/// The virtual-timer PPI from ACPI GTDT (27 on QEMU/OCI; set at init).
pub static VTIMER_GSIV: AtomicU64 = AtomicU64::new(27);

#[no_mangle]
extern "C" fn rust_irq() {
    while let Some(intid) = gicv3::ack() {
        if intid as u64 == VTIMER_GSIV.load(Ordering::Relaxed) {
            // CNTV is level-triggered: silence before EOI, let the loop re-arm.
            timer::disarm();
            TIMER_FIRED.store(true, Ordering::Release);
        } else {
            for i in 0..4 {
                if IRQ_WAKE_INTID[i].load(Ordering::Relaxed) == intid as u64 {
                    let t = IRQ_WAKE_TASK[i].load(Ordering::Acquire);
                    if t != u64::MAX {
                        wake_task(t as usize);
                    }
                }
            }
        }
        gicv3::eoi(intid);
    }
}
