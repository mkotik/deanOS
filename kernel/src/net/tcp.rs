//! From-scratch TCP (PLAN.md M6): full server-side state machine, ring
//! buffers, RTO retransmission, dup-ACK fast retransmit, minimal congestion
//! control (slow start + halve-on-loss), SipHash ISNs, MSS 1460 clamp.
//!
//! Hardware-independent and sans-io: `on_segment`/`tick` consume inputs and
//! push outbound segments into an outbox the caller drains to the IP layer.

use super::ring::Ring;
use super::wire::{be16, be32, put16, put32, Csum};
use alloc::vec::Vec;
use core::task::Waker;

pub const MSS: usize = 1460;
const RX_CAP: usize = 32 * 1024;
const TX_CAP: usize = 32 * 1024;
const MAX_SOCKETS: usize = 64;
const TIME_WAIT_MS: u64 = 10_000;
const RTO_INIT_MS: u64 = 300;
const RTO_MAX_MS: u64 = 8_000;
const MAX_RETRIES: u32 = 8;

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const PSH: u8 = 0x08;
const ACK: u8 = 0x10;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    SynRcvd,
    Established,
    FinWait1,
    FinWait2,
    Closing,
    CloseWait,
    LastAck,
    TimeWait,
    Closed,
}

#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
#[inline]
fn seq_le(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) <= 0
}

pub struct Socket {
    pub state: State,
    pub local_ip: u32,
    pub local_port: u16,
    pub remote_ip: u32,
    pub remote_port: u16,

    snd_una: u32,
    snd_nxt: u32,
    snd_wnd: u32,
    rcv_nxt: u32,

    rx: Ring,
    tx: Ring, // bytes from snd_una onward (unacked + unsent)
    tx_unsent: usize, // offset into tx of first never-sent byte

    peer_mss: usize,
    cwnd: usize,
    ssthresh: usize,
    dup_acks: u32,

    rto_ms: u64,
    rtx_deadline: Option<u64>,
    retries: u32,

    fin_queued: bool, // close() requested: send FIN once tx drains
    fin_sent: bool,
    fin_seq: u32,
    time_wait_until: u64,
    ack_pending: bool,

    pub rx_waker: Option<Waker>,
    pub tx_waker: Option<Waker>,
}

impl Socket {
    fn new(local_ip: u32, local_port: u16, remote_ip: u32, remote_port: u16) -> Self {
        Socket {
            state: State::SynRcvd,
            local_ip,
            local_port,
            remote_ip,
            remote_port,
            snd_una: 0,
            snd_nxt: 0,
            snd_wnd: MSS as u32,
            rcv_nxt: 0,
            rx: Ring::new(RX_CAP),
            tx: Ring::new(TX_CAP),
            tx_unsent: 0,
            peer_mss: 536,
            cwnd: 2 * MSS,
            ssthresh: 64 * 1024,
            dup_acks: 0,
            rto_ms: RTO_INIT_MS,
            rtx_deadline: None,
            retries: 0,
            fin_queued: false,
            fin_sent: false,
            fin_seq: 0,
            time_wait_until: 0,
            ack_pending: false,
            rx_waker: None,
            tx_waker: None,
        }
    }

    /// Readable bytes (0 + eof() means clean EOF).
    pub fn readable(&self) -> usize {
        self.rx.len()
    }

    pub fn eof(&self) -> bool {
        matches!(
            self.state,
            State::CloseWait | State::LastAck | State::Closing | State::TimeWait | State::Closed
        )
    }

    pub fn writable(&self) -> usize {
        if self.fin_queued || !matches!(self.state, State::Established | State::CloseWait) {
            0
        } else {
            self.tx.free()
        }
    }

    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = self.rx.read(out);
        if n > 0 {
            // Window may have reopened; let tick() advertise it via an ACK.
            self.ack_pending = true;
        }
        n
    }

    pub fn write(&mut self, data: &[u8]) -> usize {
        self.tx.write(data)
    }

    fn wake_rx(&mut self) {
        if let Some(w) = self.rx_waker.take() {
            w.wake();
        }
    }
    fn wake_tx(&mut self) {
        if let Some(w) = self.tx_waker.take() {
            w.wake();
        }
    }

    fn rcv_wnd(&self) -> u16 {
        self.rx.free().min(0xffff) as u16
    }

    fn flight(&self) -> usize {
        self.snd_nxt.wrapping_sub(self.snd_una) as usize
    }
}

/// One outbound segment: (remote ip, raw tcp segment bytes).
pub type OutSeg = (u32, Vec<u8>);

pub struct Tcp {
    pub sockets: Vec<Option<Socket>>,
    listeners: Vec<(u16, Vec<usize>)>, // (port, established-not-yet-accepted)
    pub accept_wakers: Vec<(u16, Waker)>,
    outbox: Vec<OutSeg>,
    isn_key: (u64, u64),
}

impl Tcp {
    pub fn new(isn_key: (u64, u64)) -> Self {
        Tcp {
            sockets: (0..MAX_SOCKETS).map(|_| None).collect(),
            listeners: Vec::new(),
            accept_wakers: Vec::new(),
            outbox: Vec::new(),
            isn_key,
        }
    }

    pub fn listen(&mut self, port: u16) {
        if !self.listeners.iter().any(|(p, _)| *p == port) {
            self.listeners.push((port, Vec::new()));
        }
    }

    /// Pop an established connection for `port` (async accept polls this).
    pub fn accept(&mut self, port: u16) -> Option<usize> {
        let l = self.listeners.iter_mut().find(|(p, _)| *p == port)?;
        if l.1.is_empty() {
            None
        } else {
            Some(l.1.remove(0))
        }
    }

    pub fn take_outbox(&mut self) -> Vec<OutSeg> {
        core::mem::take(&mut self.outbox)
    }

    pub fn sock(&mut self, h: usize) -> Option<&mut Socket> {
        self.sockets.get_mut(h).and_then(|s| s.as_mut())
    }

    /// Application close: queue FIN after pending data.
    pub fn close(&mut self, h: usize, now: u64) {
        if let Some(s) = self.sock(h) {
            match s.state {
                State::Established | State::CloseWait | State::SynRcvd => {
                    s.fin_queued = true;
                }
                _ => {}
            }
        }
        self.pump(h, now);
    }

    /// Drop a socket immediately (RST to peer if still open).
    pub fn abort(&mut self, h: usize, _now: u64) {
        if let Some(s) = self.sockets.get_mut(h).and_then(|s| s.take()) {
            if !matches!(s.state, State::Closed | State::TimeWait) {
                let seg = build_segment(
                    s.local_port,
                    s.remote_port,
                    s.snd_nxt,
                    s.rcv_nxt,
                    RST | ACK,
                    0,
                    &[],
                    false,
                );
                self.outbox.push((s.remote_ip, seg));
            }
        }
    }

    // ------------------------------------------------------------------ RX --

    pub fn on_segment(&mut self, src_ip: u32, dst_ip: u32, seg: &[u8], now: u64) {
        if seg.len() < 20 {
            return;
        }
        // Verify checksum (pseudo-header).
        let mut c = Csum::new();
        super::wire::feed_pseudo(&mut c, src_ip, dst_ip, 6, seg.len() as u16);
        c.feed(seg);
        if c.finish() != 0 {
            return;
        }

        let sport = be16(&seg[0..2]);
        let dport = be16(&seg[2..4]);
        let seq = be32(&seg[4..8]);
        let ack = be32(&seg[8..12]);
        let doff = ((seg[12] >> 4) as usize) * 4;
        let flags = seg[13];
        let wnd = be16(&seg[14..16]) as u32;
        if doff < 20 || doff > seg.len() {
            return;
        }
        let payload = &seg[doff..];

        // Existing connection?
        let found = self.sockets.iter().position(|s| {
            s.as_ref().is_some_and(|s| {
                s.remote_ip == src_ip
                    && s.remote_port == sport
                    && s.local_port == dport
                    && s.state != State::Closed
            })
        });

        if let Some(h) = found {
            self.segment_arrives(h, seq, ack, flags, wnd, payload, &seg[20..doff], now);
            self.pump(h, now);
            return;
        }

        // New SYN to a listener?
        if flags & (SYN | ACK | RST) == SYN {
            if self.listeners.iter().any(|(p, _)| *p == dport) {
                self.on_syn(src_ip, dst_ip, sport, dport, seq, &seg[20..doff], now);
                return;
            }
        }

        // Otherwise: RST (unless the packet itself was a RST).
        if flags & RST == 0 {
            let (rseq, rack, rflags) = if flags & ACK != 0 {
                (ack, 0, RST)
            } else {
                let advance = payload.len() as u32
                    + u32::from(flags & SYN != 0)
                    + u32::from(flags & FIN != 0);
                (0, seq.wrapping_add(advance), RST | ACK)
            };
            let out = build_segment(dport, sport, rseq, rack, rflags, 0, &[], false);
            self.outbox.push((src_ip, out));
        }
    }

    fn on_syn(
        &mut self,
        src_ip: u32,
        dst_ip: u32,
        sport: u16,
        dport: u16,
        seq: u32,
        options: &[u8],
        now: u64,
    ) {
        let Some(h) = self.sockets.iter().position(|s| s.is_none()) else {
            return; // table full: silently drop the SYN
        };
        let mut s = Socket::new(dst_ip, dport, src_ip, sport);
        s.rcv_nxt = seq.wrapping_add(1);
        s.peer_mss = parse_mss(options).unwrap_or(536).min(MSS);
        let isn = self.isn(src_ip, dst_ip, sport, dport, now);
        s.snd_una = isn;
        s.snd_nxt = isn.wrapping_add(1);
        // SYN-ACK with our MSS option.
        let seg = build_segment(dport, sport, isn, s.rcv_nxt, SYN | ACK, s.rcv_wnd(), &[], true);
        s.rtx_deadline = Some(now + s.rto_ms);
        self.outbox.push((src_ip, seg));
        self.sockets[h] = Some(s);
    }

    #[allow(clippy::too_many_arguments)]
    fn segment_arrives(
        &mut self,
        h: usize,
        seq: u32,
        ack: u32,
        flags: u8,
        wnd: u32,
        payload: &[u8],
        _options: &[u8],
        now: u64,
    ) {
        let Some(s) = self.sockets[h].as_mut() else {
            return;
        };

        if flags & RST != 0 {
            // Validate RST is in-window-ish, then kill.
            if seq_le(s.rcv_nxt, seq) || s.state == State::SynRcvd {
                s.state = State::Closed;
                s.wake_rx();
                s.wake_tx();
            }
            return;
        }

        // Retransmitted SYN: resend the SYN-ACK (SynRcvd) or challenge-ACK.
        if flags & SYN != 0 {
            if s.state == State::SynRcvd {
                self.retransmit(h, now);
            } else {
                s.ack_pending = true;
            }
            return;
        }

        if flags & ACK == 0 {
            return;
        }

        // --- ACK processing ---
        if s.state == State::SynRcvd {
            if ack == s.snd_nxt {
                s.state = State::Established;
                s.snd_una = ack; // our SYN is acked
                s.rtx_deadline = None;
                s.retries = 0;
                // Hand to the listener's accept queue.
                let port = s.local_port;
                if let Some(l) = self.listeners.iter_mut().find(|(p, _)| *p == port) {
                    l.1.push(h);
                }
                let mut i = 0;
                while i < self.accept_wakers.len() {
                    if self.accept_wakers[i].0 == port {
                        self.accept_wakers.swap_remove(i).1.wake();
                    } else {
                        i += 1;
                    }
                }
                // Reborrow after listener bookkeeping.
                let s = self.sockets[h].as_mut().unwrap();
                s.snd_wnd = wnd;
                self.process_data(h, seq, flags, payload, now);
                return;
            } else {
                // Bogus ACK in SYN_RCVD: RST per RFC.
                let seg = build_segment(s.local_port, s.remote_port, ack, 0, RST, 0, &[], false);
                self.outbox.push((s.remote_ip, seg));
                return;
            }
        }

        s.snd_wnd = wnd;
        let una_advanced = seq_lt(s.snd_una, ack) && seq_le(ack, s.snd_nxt);
        if una_advanced {
            let newly_acked = ack.wrapping_sub(s.snd_una) as usize;
            // FIN occupies one seq; data bytes acked exclude it.
            let fin_acked_now = s.fin_sent && ack == s.fin_seq.wrapping_add(1);
            let data_acked = newly_acked - usize::from(fin_acked_now);
            s.tx.consume(data_acked);
            s.tx_unsent = s.tx_unsent.saturating_sub(data_acked);
            s.snd_una = ack;
            s.dup_acks = 0;
            s.retries = 0;
            s.rto_ms = RTO_INIT_MS;
            s.rtx_deadline = if s.flight() > 0 || (s.fin_sent && !fin_acked_now) {
                Some(now + s.rto_ms)
            } else {
                None
            };
            // Congestion: slow start below ssthresh, else +MSS per RTT-ish.
            if s.cwnd < s.ssthresh {
                s.cwnd += data_acked.min(MSS);
            } else {
                s.cwnd += MSS * MSS / s.cwnd.max(1);
            }
            s.wake_tx();

            if fin_acked_now {
                match s.state {
                    State::FinWait1 => s.state = State::FinWait2,
                    State::Closing => {
                        s.state = State::TimeWait;
                        s.time_wait_until = now + TIME_WAIT_MS;
                    }
                    State::LastAck => {
                        s.state = State::Closed;
                        s.wake_rx();
                    }
                    _ => {}
                }
            }
        } else if ack == s.snd_una && s.flight() > 0 && payload.is_empty() {
            s.dup_acks += 1;
            if s.dup_acks == 3 {
                // Fast retransmit + halve.
                s.ssthresh = (s.flight() / 2).max(2 * MSS);
                s.cwnd = s.ssthresh;
                self.retransmit(h, now);
                return self.process_data(h, seq, flags, payload, now);
            }
        }

        self.process_data(h, seq, flags, payload, now);
    }

    fn process_data(&mut self, h: usize, seq: u32, flags: u8, payload: &[u8], now: u64) {
        let Some(s) = self.sockets[h].as_mut() else {
            return;
        };
        let mut payload = payload;
        let mut seq = seq;
        // Sequence of the FIN flag, if present: first byte AFTER the payload.
        let fin_seq = seq.wrapping_add(payload.len() as u32);

        if !payload.is_empty() {
            // Trim already-received prefix.
            if seq_lt(seq, s.rcv_nxt) {
                let dup = s.rcv_nxt.wrapping_sub(seq) as usize;
                if dup >= payload.len() {
                    s.ack_pending = true; // pure retransmit: re-ack
                    payload = &[];
                } else {
                    payload = &payload[dup..];
                    seq = s.rcv_nxt;
                }
            }
            if !payload.is_empty() {
                if seq == s.rcv_nxt {
                    let accepted = s.rx.write(payload);
                    s.rcv_nxt = s.rcv_nxt.wrapping_add(accepted as u32);
                    s.ack_pending = true;
                    s.wake_rx();
                } else {
                    // Out-of-order: drop, dup-ACK (sender retransmits).
                    s.ack_pending = true;
                }
            }
        }

        if flags & FIN != 0 && fin_seq == s.rcv_nxt {
            s.rcv_nxt = s.rcv_nxt.wrapping_add(1);
            s.ack_pending = true;
            match s.state {
                State::Established | State::SynRcvd => s.state = State::CloseWait,
                State::FinWait1 => {
                    // Our FIN not yet acked -> simultaneous close.
                    s.state = State::Closing;
                }
                State::FinWait2 => {
                    s.state = State::TimeWait;
                    s.time_wait_until = now + TIME_WAIT_MS;
                }
                _ => {}
            }
            s.wake_rx();
        }
    }

    // ------------------------------------------------------------------ TX --

    /// Emit queued data/FIN/ACK for socket `h` within cwnd + peer window.
    pub fn pump(&mut self, h: usize, now: u64) {
        let mut out: Vec<OutSeg> = Vec::new();
        let Some(s) = self.sockets[h].as_mut() else {
            return;
        };
        let remote = s.remote_ip;

        if matches!(s.state, State::SynRcvd | State::TimeWait | State::Closed) {
            if s.ack_pending && s.state != State::Closed {
                s.ack_pending = false;
                out.push((
                    remote,
                    build_segment(
                        s.local_port,
                        s.remote_port,
                        s.snd_nxt,
                        s.rcv_nxt,
                        ACK,
                        s.rcv_wnd(),
                        &[],
                        false,
                    ),
                ));
            }
            self.outbox.append(&mut out);
            return;
        }

        let mut sent_any = false;

        // Data within min(cwnd, peer window).
        while s.tx_unsent < s.tx.len() && !s.fin_sent {
            let limit = s.cwnd.min(s.snd_wnd as usize);
            if s.flight() >= limit {
                break;
            }
            let room = limit - s.flight();
            let mut chunk = [0u8; MSS];
            let want = room.min(s.peer_mss).min(MSS);
            let n = s.tx.peek_at(s.tx_unsent, &mut chunk[..want]);
            if n == 0 {
                break;
            }
            out.push((
                remote,
                build_segment(
                    s.local_port,
                    s.remote_port,
                    s.snd_nxt,
                    s.rcv_nxt,
                    ACK | PSH,
                    s.rcv_wnd(),
                    &chunk[..n],
                    false,
                ),
            ));
            s.snd_nxt = s.snd_nxt.wrapping_add(n as u32);
            s.tx_unsent += n;
            s.ack_pending = false;
            s.rtx_deadline.get_or_insert(now + s.rto_ms);
            sent_any = true;
        }

        // FIN once all data is flushed.
        if s.fin_queued && !s.fin_sent && s.tx_unsent >= s.tx.len() {
            s.fin_seq = s.snd_nxt;
            out.push((
                remote,
                build_segment(
                    s.local_port,
                    s.remote_port,
                    s.snd_nxt,
                    s.rcv_nxt,
                    FIN | ACK,
                    s.rcv_wnd(),
                    &[],
                    false,
                ),
            ));
            s.snd_nxt = s.snd_nxt.wrapping_add(1);
            s.fin_sent = true;
            s.ack_pending = false;
            s.rtx_deadline.get_or_insert(now + s.rto_ms);
            match s.state {
                State::Established => s.state = State::FinWait1,
                State::CloseWait => s.state = State::LastAck,
                _ => {}
            }
            sent_any = true;
        }

        if s.ack_pending && !sent_any {
            s.ack_pending = false;
            out.push((
                remote,
                build_segment(
                    s.local_port,
                    s.remote_port,
                    s.snd_nxt,
                    s.rcv_nxt,
                    ACK,
                    s.rcv_wnd(),
                    &[],
                    false,
                ),
            ));
        }
        self.outbox.append(&mut out);
    }

    fn retransmit(&mut self, h: usize, now: u64) {
        let Some(s) = self.sockets[h].as_mut() else {
            return;
        };
        match s.state {
            State::SynRcvd => {
                // Re-send SYN-ACK.
                let isn = s.snd_una;
                let seg = build_segment(
                    s.local_port,
                    s.remote_port,
                    isn,
                    s.rcv_nxt,
                    SYN | ACK,
                    s.rcv_wnd(),
                    &[],
                    true,
                );
                self.outbox.push((s.remote_ip, seg));
            }
            _ => {
                let unacked_data = s.tx.len().min(s.tx_unsent);
                if unacked_data > 0 {
                    let mut chunk = [0u8; MSS];
                    let want = unacked_data.min(s.peer_mss).min(MSS);
                    let n = s.tx.peek_at(0, &mut chunk[..want]);
                    let seg = build_segment(
                        s.local_port,
                        s.remote_port,
                        s.snd_una,
                        s.rcv_nxt,
                        ACK | PSH,
                        s.rcv_wnd(),
                        &chunk[..n],
                        false,
                    );
                    self.outbox.push((s.remote_ip, seg));
                } else if s.fin_sent {
                    let seg = build_segment(
                        s.local_port,
                        s.remote_port,
                        s.fin_seq,
                        s.rcv_nxt,
                        FIN | ACK,
                        s.rcv_wnd(),
                        &[],
                        false,
                    );
                    self.outbox.push((s.remote_ip, seg));
                }
            }
        }
        let Some(s) = self.sockets[h].as_mut() else {
            return;
        };
        s.rtx_deadline = Some(now + s.rto_ms);
    }

    /// Periodic timers: RTO, TIME_WAIT reaping. Call every few ms.
    pub fn tick(&mut self, now: u64) {
        for h in 0..self.sockets.len() {
            let Some(s) = self.sockets[h].as_mut() else {
                continue;
            };
            match s.state {
                State::TimeWait => {
                    if now >= s.time_wait_until {
                        s.state = State::Closed;
                    }
                    continue;
                }
                State::Closed => continue,
                _ => {}
            }
            if let Some(dl) = s.rtx_deadline {
                if now >= dl {
                    s.retries += 1;
                    if s.retries > MAX_RETRIES {
                        s.state = State::Closed;
                        s.wake_rx();
                        s.wake_tx();
                        continue;
                    }
                    s.rto_ms = (s.rto_ms * 2).min(RTO_MAX_MS);
                    s.ssthresh = (s.flight() / 2).max(2 * MSS);
                    s.cwnd = MSS;
                    self.retransmit(h, now);
                }
            }
            // Opportunistic pump (window/ack updates).
            self.pump(h, now);
        }
        // Reap closed sockets not sitting in an accept queue.
        for h in 0..self.sockets.len() {
            let dead = self.sockets[h]
                .as_ref()
                .is_some_and(|s| s.state == State::Closed && s.rx.is_empty());
            let queued = self.listeners.iter().any(|(_, q)| q.contains(&h));
            if dead && !queued {
                self.sockets[h] = None;
            }
        }
    }

    fn isn(&self, a: u32, b: u32, c: u16, d: u16, now: u64) -> u32 {
        let mut m = [0u8; 16];
        put32(&mut m[0..4], a);
        put32(&mut m[4..8], b);
        put16(&mut m[8..10], c);
        put16(&mut m[10..12], d);
        put32(&mut m[12..16], now as u32);
        (siphash24(self.isn_key.0, self.isn_key.1, &m) as u32).wrapping_add((now as u32) << 6)
    }
}

fn parse_mss(mut opts: &[u8]) -> Option<usize> {
    while !opts.is_empty() {
        match opts[0] {
            0 => return None,
            1 => opts = &opts[1..],
            2 if opts.len() >= 4 && opts[1] == 4 => {
                return Some(be16(&opts[2..4]) as usize);
            }
            _ => {
                let l = *opts.get(1)? as usize;
                if l < 2 || l > opts.len() {
                    return None;
                }
                opts = &opts[l..];
            }
        }
    }
    None
}

/// Build a TCP segment. Checksum is left ZERO — the IP layer fills it (it
/// knows src/dst). `mss_opt` appends our MSS=1460 option (SYN-ACK only).
fn build_segment(
    sport: u16,
    dport: u16,
    seq: u32,
    ack: u32,
    flags: u8,
    wnd: u16,
    payload: &[u8],
    mss_opt: bool,
) -> Vec<u8> {
    let optlen = if mss_opt { 4 } else { 0 };
    let hdr = 20 + optlen;
    let mut s = alloc::vec![0u8; hdr + payload.len()];
    put16(&mut s[0..2], sport);
    put16(&mut s[2..4], dport);
    put32(&mut s[4..8], seq);
    put32(&mut s[8..12], ack);
    s[12] = ((hdr / 4) as u8) << 4;
    s[13] = flags;
    put16(&mut s[14..16], wnd);
    if mss_opt {
        s[20] = 2;
        s[21] = 4;
        put16(&mut s[22..24], MSS as u16);
    }
    s[hdr..].copy_from_slice(payload);
    s
}

/// SipHash-2-4 (64-bit) — ISN generator keyed with boot-time entropy.
fn siphash24(k0: u64, k1: u64, msg: &[u8]) -> u64 {
    let mut v0 = 0x736f_6d65_7073_6575_u64 ^ k0;
    let mut v1 = 0x646f_7261_6e64_6f6d_u64 ^ k1;
    let mut v2 = 0x6c79_6765_6e65_7261_u64 ^ k0;
    let mut v3 = 0x7465_6462_7974_6573_u64 ^ k1;

    macro_rules! round {
        () => {
            v0 = v0.wrapping_add(v1);
            v1 = v1.rotate_left(13);
            v1 ^= v0;
            v0 = v0.rotate_left(32);
            v2 = v2.wrapping_add(v3);
            v3 = v3.rotate_left(16);
            v3 ^= v2;
            v0 = v0.wrapping_add(v3);
            v3 = v3.rotate_left(21);
            v3 ^= v0;
            v2 = v2.wrapping_add(v1);
            v1 = v1.rotate_left(17);
            v1 ^= v2;
            v2 = v2.rotate_left(32);
        };
    }

    let mut chunks = msg.chunks_exact(8);
    for c in &mut chunks {
        let m = u64::from_le_bytes(c.try_into().unwrap());
        v3 ^= m;
        round!();
        round!();
        v0 ^= m;
    }
    let rem = chunks.remainder();
    let mut last = (msg.len() as u64) << 56;
    for (i, &b) in rem.iter().enumerate() {
        last |= (b as u64) << (8 * i);
    }
    v3 ^= last;
    round!();
    round!();
    v0 ^= last;
    v2 ^= 0xff;
    round!();
    round!();
    round!();
    round!();
    v0 ^ v1 ^ v2 ^ v3
}
