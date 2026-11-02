//! Segment-level TCP state machine tests (M6 gate, host-side).

use crate::net::tcp::{State, Tcp, MSS};
use crate::net::wire::{be16, be32, put16, put32, Csum};

const CLIENT_IP: u32 = 0x0a000202;
const SERVER_IP: u32 = 0x0a00020f;
const CLIENT_PORT: u16 = 40000;
const SERVER_PORT: u16 = 80;

/// Build a client->server segment with a VALID checksum.
fn client_seg(seq: u32, ack: u32, flags: u8, wnd: u16, payload: &[u8], mss_opt: bool) -> Vec<u8> {
    let optlen = if mss_opt { 4 } else { 0 };
    let hdr = 20 + optlen;
    let mut s = vec![0u8; hdr + payload.len()];
    put16(&mut s[0..2], CLIENT_PORT);
    put16(&mut s[2..4], SERVER_PORT);
    put32(&mut s[4..8], seq);
    put32(&mut s[8..12], ack);
    s[12] = ((hdr / 4) as u8) << 4;
    s[13] = flags;
    put16(&mut s[14..16], wnd);
    if mss_opt {
        s[20] = 2;
        s[21] = 4;
        put16(&mut s[22..24], 1460);
    }
    s[hdr..].copy_from_slice(payload);
    let mut c = Csum::new();
    crate::net::wire::feed_pseudo(&mut c, CLIENT_IP, SERVER_IP, 6, s.len() as u16);
    c.feed(&s);
    let csum = c.finish();
    put16(&mut s[16..18], csum);
    s
}

const FIN: u8 = 0x01;
const SYN: u8 = 0x02;
const RST: u8 = 0x04;
const ACK: u8 = 0x10;

struct Parsed {
    seq: u32,
    ack: u32,
    flags: u8,
    payload_len: usize,
    mss: Option<u16>,
}

fn parse(seg: &[u8]) -> Parsed {
    let doff = ((seg[12] >> 4) as usize) * 4;
    let mut mss = None;
    if doff > 20 && seg[20] == 2 && seg[21] == 4 {
        mss = Some(be16(&seg[22..24]));
    }
    Parsed {
        seq: be32(&seg[4..8]),
        ack: be32(&seg[8..12]),
        flags: seg[13],
        payload_len: seg.len() - doff,
        mss,
    }
}

/// Complete a handshake; returns (tcp, handle, client_seq, server_isn).
fn establish() -> (Tcp, usize, u32, u32) {
    let mut t = Tcp::new((0x1234, 0x5678));
    t.listen(SERVER_PORT);
    let iss = 1000u32;
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(iss, 0, SYN, 65535, &[], true), 0);
    let out = t.take_outbox();
    assert_eq!(out.len(), 1, "expected SYN-ACK");
    let synack = parse(&out[0].1);
    assert_eq!(synack.flags, SYN | ACK);
    assert_eq!(synack.ack, iss + 1);
    assert_eq!(synack.mss, Some(1460), "SYN-ACK must advertise MSS 1460");
    let server_isn = synack.seq;

    t.on_segment(
        CLIENT_IP,
        SERVER_IP,
        &client_seg(iss + 1, server_isn + 1, ACK, 65535, &[], false),
        1,
    );
    let h = t.accept(SERVER_PORT).expect("accepted connection");
    assert_eq!(t.sock(h).unwrap().state, State::Established);
    t.take_outbox();
    (t, h, iss + 1, server_isn)
}

#[test]
fn handshake_and_accept() {
    let (_t, _h, _, _) = establish();
}

#[test]
fn syn_to_closed_port_gets_rst() {
    let mut t = Tcp::new((1, 2));
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(5, 0, SYN, 1000, &[], false), 0);
    let out = t.take_outbox();
    assert_eq!(out.len(), 1);
    let p = parse(&out[0].1);
    assert!(p.flags & RST != 0);
    assert_eq!(p.ack, 6); // seq+1 for the SYN
}

#[test]
fn data_rx_acks_and_delivers() {
    let (mut t, h, cseq, _sisn) = establish();
    let body = b"hello dean";
    t.on_segment(
        CLIENT_IP,
        SERVER_IP,
        &client_seg(cseq, 0, ACK, 65535, body, false),
        10,
    );
    let out = t.take_outbox();
    assert!(!out.is_empty());
    let ackseg = parse(&out.last().unwrap().1);
    assert_eq!(ackseg.ack, cseq + body.len() as u32);
    let s = t.sock(h).unwrap();
    let mut buf = [0u8; 64];
    let n = s.read(&mut buf);
    assert_eq!(&buf[..n], body);
}

#[test]
fn data_tx_pump_and_ack_consumes() {
    let (mut t, h, cseq, sisn) = establish();
    let payload = vec![0x42u8; 5000]; // > 3 MSS
    assert_eq!(t.sock(h).unwrap().write(&payload), 5000);
    t.pump(h, 20);
    let out = t.take_outbox();
    let total: usize = out.iter().map(|(_, s)| parse(s).payload_len).sum();
    assert!(total >= 2 * MSS, "cwnd allows at least 2 MSS initially, sent {total}");
    let first = parse(&out[0].1);
    assert_eq!(first.seq, sisn + 1);

    // ACK everything sent so far: more data flows.
    let acked = sisn + 1 + total as u32;
    t.on_segment(
        CLIENT_IP,
        SERVER_IP,
        &client_seg(cseq, acked, ACK, 65535, &[], false),
        30,
    );
    let out2 = t.take_outbox();
    let total2: usize = out2.iter().map(|(_, s)| parse(s).payload_len).sum();
    assert!(total2 > 0, "window update must release more data");
    assert_eq!(t.sock(h).unwrap().state, State::Established);
}

#[test]
fn rto_retransmits_and_backs_off() {
    let (mut t, h, _cseq, sisn) = establish();
    t.sock(h).unwrap().write(b"abc");
    t.pump(h, 100);
    let out = t.take_outbox();
    assert_eq!(parse(&out[0].1).payload_len, 3);

    // Data sent at t=100 -> RTO deadline 400 ms.
    t.tick(450);
    let r1 = t.take_outbox();
    let rtx: Vec<_> = r1.iter().filter(|(_, s)| parse(s).payload_len == 3).collect();
    assert_eq!(rtx.len(), 1, "one retransmission");
    assert_eq!(parse(&rtx[0].1).seq, sisn + 1);

    // Backoff doubled: next deadline 450 + 600.
    t.tick(900);
    assert!(t.take_outbox().is_empty(), "too early for doubled RTO");
    t.tick(1100);
    let r2 = t.take_outbox();
    assert!(r2.iter().any(|(_, s)| parse(s).payload_len == 3));
}

#[test]
fn triple_dup_ack_fast_retransmit() {
    let (mut t, h, cseq, sisn) = establish();
    t.sock(h).unwrap().write(&[7u8; 3000]);
    t.pump(h, 10);
    t.take_outbox();

    for i in 0..3 {
        t.on_segment(
            CLIENT_IP,
            SERVER_IP,
            &client_seg(cseq, sisn + 1, ACK, 65535, &[], false),
            20 + i,
        );
    }
    let out = t.take_outbox();
    let rtx: Vec<_> = out.iter().filter(|(_, s)| parse(s).payload_len > 0).collect();
    assert!(!rtx.is_empty(), "fast retransmit after 3 dup ACKs");
    assert_eq!(parse(&rtx[0].1).seq, sisn + 1, "retransmit from snd_una");
}

#[test]
fn client_initiated_close() {
    let (mut t, h, cseq, sisn) = establish();
    // Client FIN.
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(cseq, sisn + 1, FIN | ACK, 65535, &[], false), 10);
    assert_eq!(t.sock(h).unwrap().state, State::CloseWait);
    let out = t.take_outbox();
    assert_eq!(parse(&out.last().unwrap().1).ack, cseq + 1, "FIN consumed one seq");

    // Server closes: FIN out, LastAck.
    t.close(h, 20);
    let out = t.take_outbox();
    let fin = parse(&out.last().unwrap().1);
    assert!(fin.flags & FIN != 0);
    assert_eq!(t.sock(h).unwrap().state, State::LastAck);

    // Client ACKs our FIN: socket reaped on next tick.
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(cseq + 1, fin.seq + 1, ACK, 65535, &[], false), 30);
    assert_eq!(t.sock(h).unwrap().state, State::Closed);
    t.tick(40);
    assert!(t.sock(h).is_none(), "closed socket reaped");
}

#[test]
fn server_initiated_close_time_wait() {
    let (mut t, h, cseq, _sisn) = establish();
    t.close(h, 10);
    let out = t.take_outbox();
    let fin = parse(&out.last().unwrap().1);
    assert!(fin.flags & FIN != 0);
    assert_eq!(t.sock(h).unwrap().state, State::FinWait1);

    // Client ACKs FIN -> FinWait2; client FIN -> TimeWait; reap after 10 s.
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(cseq, fin.seq + 1, ACK, 65535, &[], false), 20);
    assert_eq!(t.sock(h).unwrap().state, State::FinWait2);
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(cseq, fin.seq + 1, FIN | ACK, 65535, &[], false), 30);
    assert_eq!(t.sock(h).unwrap().state, State::TimeWait);
    t.tick(30 + 10_001);
    t.tick(30 + 10_002);
    assert!(t.sock(h).is_none(), "TIME_WAIT expired and reaped");
}

#[test]
fn out_of_order_dropped_with_dup_ack() {
    let (mut t, h, cseq, _s) = establish();
    // Segment 1000 bytes ahead of rcv_nxt.
    t.on_segment(
        CLIENT_IP,
        SERVER_IP,
        &client_seg(cseq + 1000, 0, ACK, 65535, b"xxxx", false),
        10,
    );
    let out = t.take_outbox();
    let ackseg = parse(&out.last().expect("dup-ack emitted").1);
    assert_eq!(ackseg.ack, cseq, "dup ACK re-asserts rcv_nxt");
    assert_eq!(t.sock(h).unwrap().readable(), 0);
}

#[test]
fn rst_kills_connection() {
    let (mut t, h, cseq, _s) = establish();
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(cseq, 0, RST, 0, &[], false), 10);
    assert_eq!(t.sock(h).unwrap().state, State::Closed);
}

#[test]
fn bad_checksum_ignored() {
    let (mut t, h, cseq, _s) = establish();
    let mut seg = client_seg(cseq, 0, ACK, 65535, b"corrupt", false);
    seg[25] ^= 0xff; // flip a payload byte after checksumming
    t.on_segment(CLIENT_IP, SERVER_IP, &seg, 10);
    assert_eq!(t.sock(h).unwrap().readable(), 0, "corrupted segment dropped");
}

#[test]
fn isn_differs_across_tuples() {
    let mut t = Tcp::new((0xdead, 0xbeef));
    t.listen(SERVER_PORT);
    t.on_segment(CLIENT_IP, SERVER_IP, &client_seg(1, 0, SYN, 1000, &[], false), 0);
    let isn1 = parse(&t.take_outbox()[0].1).seq;
    let mut t2 = Tcp::new((0xdead, 0xbeef));
    t2.listen(SERVER_PORT);
    // Different client port -> different ISN.
    let mut seg = client_seg(1, 0, SYN, 1000, &[], false);
    put16(&mut seg[0..2], CLIENT_PORT + 1);
    put16(&mut seg[16..18], 0);
    let mut c = Csum::new();
    crate::net::wire::feed_pseudo(&mut c, CLIENT_IP, SERVER_IP, 6, seg.len() as u16);
    c.feed(&seg);
    let csum = c.finish();
    put16(&mut seg[16..18], csum);
    t2.on_segment(CLIENT_IP, SERVER_IP, &seg, 0);
    let isn2 = parse(&t2.take_outbox()[0].1).seq;
    assert_ne!(isn1, isn2);
}
