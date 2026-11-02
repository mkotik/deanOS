//! Async timer sleep on top of the executor's timer queue.

use crate::drivers::timer;
use crate::runtime::executor;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub struct Sleep {
    deadline: u64, // absolute ticks
}

impl Future for Sleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
        if timer::ticks() >= self.deadline {
            Poll::Ready(())
        } else {
            executor::register_timer(self.deadline, cx.waker().clone());
            Poll::Pending
        }
    }
}

pub fn sleep_ms(ms: u64) -> Sleep {
    Sleep {
        deadline: timer::ticks() + timer::ms_to_ticks(ms),
    }
}

pub fn sleep_until(deadline_ticks: u64) -> Sleep {
    Sleep {
        deadline: deadline_ticks,
    }
}
