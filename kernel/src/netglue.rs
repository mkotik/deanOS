//! Kernel-side glue between the HW-independent net stack and the executor:
//! a single-core shared cell holding the Stack, plus the polling net task.

use crate::drivers::virtio_net::VirtioNet;
use crate::drivers::{pci::Ecam, timer};
use crate::net::stack::Stack;
use crate::net::tcp::Tcp;
use crate::runtime::sleep::sleep_ms;
use crate::runtime::SingleCore;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

pub static NET: SingleCore<Option<Stack<VirtioNet>>> = SingleCore::new(None);
pub static TCP: SingleCore<Option<Tcp>> = SingleCore::new(None);

/// Borrow the stack for a short, non-await section.
pub fn with_net<R>(f: impl FnOnce(&mut Stack<VirtioNet>) -> R) -> R {
    let mut g = NET.0.borrow_mut();
    f(g.as_mut().expect("net stack not initialized"))
}

pub fn net_ready() -> bool {
    NET.0.borrow().is_some()
}

pub fn with_tcp<R>(f: impl FnOnce(&mut Tcp) -> R) -> R {
    let mut g = TCP.0.borrow_mut();
    f(g.as_mut().expect("tcp not initialized"))
}

/// Push every queued outbound TCP segment down to the IP layer.
pub fn tcp_flush() {
    let now = timer::now_ms();
    let segs = with_tcp(|t| t.take_outbox());
    for (ip, mut seg) in segs {
        with_net(|s| s.send_tcp_segment(ip, &mut seg, now));
    }
}

/// Bring up virtio-net and poll the stack forever (poll-mode RX, ~1 ms cadence).
pub async fn net_task(ecam: Ecam) {
    let Some(dev) = VirtioNet::init(&ecam) else {
        crate::kprintln!("net  : FATAL no virtio-net device");
        return;
    };
    let m = dev.mac;
    crate::kprintln!(
        "net  : virtio-net up, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    );
    let xid = timer::ticks() as u32 ^ 0xdea0_05;
    *NET.0.borrow_mut() = Some(Stack::new(dev, xid));
    *TCP.0.borrow_mut() = Some(Tcp::new((
        timer::ticks() ^ 0x6465_616e_4f53_2121,
        timer::ticks().rotate_left(31) ^ 0x7463_7021,
    )));

    let mut last_tick = 0u64;
    loop {
        let now = timer::now_ms();
        with_net(|s| s.poll(now));
        // Hand received TCP segments to the transport.
        let segs = with_net(|s| core::mem::take(&mut s.tcp_rx));
        for (src, dst, seg) in segs {
            with_tcp(|t| t.on_segment(src, dst, &seg, now));
        }
        // Transport timers (RTO, TIME_WAIT) every ~5 ms.
        if now.saturating_sub(last_tick) >= 5 {
            last_tick = now;
            with_tcp(|t| t.tick(now));
        }
        tcp_flush();
        sleep_ms(1).await;
    }
}

// --- Async socket API ---------------------------------------------------------

pub fn tcp_listen(port: u16) {
    with_tcp(|t| t.listen(port));
}

pub struct Accept {
    port: u16,
}

impl Future for Accept {
    type Output = usize;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        with_tcp(|t| match t.accept(self.port) {
            Some(h) => Poll::Ready(h),
            None => {
                t.accept_wakers.push((self.port, cx.waker().clone()));
                Poll::Pending
            }
        })
    }
}

pub fn tcp_accept(port: u16) -> Accept {
    Accept { port }
}

pub struct Read<'a> {
    h: usize,
    buf: &'a mut [u8],
}

impl Future for Read<'_> {
    type Output = usize; // 0 = EOF or connection gone
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<usize> {
        let me = self.get_mut();
        let r = with_tcp(|t| match t.sock(me.h) {
            None => Poll::Ready(0),
            Some(s) => {
                let n = s.read(me.buf);
                if n > 0 {
                    Poll::Ready(n)
                } else if s.eof() {
                    Poll::Ready(0)
                } else {
                    s.rx_waker = Some(cx.waker().clone());
                    Poll::Pending
                }
            }
        });
        if let Poll::Ready(n) = r {
            if n > 0 {
                // Window reopened: let the peer know promptly.
                with_tcp(|t| t.pump(me.h, timer::now_ms()));
                tcp_flush();
            }
        }
        r
    }
}

/// Read some bytes (await). Returns 0 on EOF/teardown.
pub fn tcp_read(h: usize, buf: &mut [u8]) -> Read<'_> {
    Read { h, buf }
}

pub struct WriteAll<'a> {
    h: usize,
    data: &'a [u8],
    off: usize,
}

impl Future for WriteAll<'_> {
    type Output = bool; // false = connection died mid-write
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<bool> {
        let me = self.get_mut();
        loop {
            let res = with_tcp(|t| match t.sock(me.h) {
                None => Some(false),
                Some(s) => {
                    if s.writable() == 0 && !matches!(s.state, crate::net::tcp::State::Established | crate::net::tcp::State::CloseWait) {
                        return Some(false);
                    }
                    let n = s.write(&me.data[me.off..]);
                    me.off += n;
                    if me.off >= me.data.len() {
                        Some(true)
                    } else if n == 0 {
                        s.tx_waker = Some(cx.waker().clone());
                        None // buffer full: wait
                    } else {
                        None // partial: pump then continue looping
                    }
                }
            });
            // Push whatever we buffered onto the wire.
            with_tcp(|t| t.pump(me.h, timer::now_ms()));
            tcp_flush();
            match res {
                Some(done) => return Poll::Ready(done),
                None => {
                    // Either waiting on buffer space (waker set) or looping.
                    let full = with_tcp(|t| {
                        t.sock(me.h).map(|s| s.writable() == 0).unwrap_or(true)
                    });
                    if full {
                        return Poll::Pending;
                    }
                }
            }
        }
    }
}

/// Write the whole buffer (await). False if the peer vanished.
pub fn tcp_write_all<'a>(h: usize, data: &'a [u8]) -> WriteAll<'a> {
    WriteAll { h, data, off: 0 }
}

/// Graceful close (FIN).
pub fn tcp_close(h: usize) {
    with_tcp(|t| t.close(h, timer::now_ms()));
    tcp_flush();
}
