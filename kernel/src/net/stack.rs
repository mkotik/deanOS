//! The network stack core: L2 demux, ARP resolution, IPv4 RX/TX, ICMP echo,
//! UDP (DHCP client), and — from M6 — TCP dispatch.
//!
//! Hardware-independent: drivers implement `L2Device`; time comes in as
//! milliseconds from the caller. One instance, polled by the net task.

use super::arp::{self, ArpCache, ETHERTYPE_ARP};
use super::dhcp::{self, DhcpClient};
use super::icmp;
use super::ipv4::{self, ETHERTYPE_IPV4, PROTO_ICMP, PROTO_TCP, PROTO_UDP};
use super::wire::{be16, put16, Csum};
use alloc::vec::Vec;

pub trait L2Device {
    fn mac(&self) -> [u8; 6];
    /// Non-blocking frame TX; false if the ring is full.
    fn send(&mut self, frame: &[u8]) -> bool;
    /// Non-blocking frame RX (virtio header already stripped).
    fn recv(&mut self, out: &mut [u8]) -> Option<usize>;
}

const BCAST_MAC: [u8; 6] = [0xff; 6];
pub const MTU: usize = 1500; // hard clamp (PLAN.md: never OCI's 9000)

#[derive(Default, Clone, Copy)]
pub struct IpConfig {
    pub ip: u32,
    pub mask: u32,
    pub gw: u32,
    pub dns: u32,
    pub up: bool,
}

pub struct Stack<D: L2Device> {
    pub dev: D,
    mac: [u8; 6],
    pub cfg: IpConfig,
    arp: ArpCache,
    dhcp: DhcpClient,
    ip_id: u16,
    rxbuf: [u8; 2048],
    // Diagnostics / M5 gate:
    pub pongs: Vec<(u16, u16)>, // (id, seq) echo replies received
    pub rx_frames: u64,
    pub tx_frames: u64,
    /// M6 hook: (src_ip, dst_ip, tcp segment) handed to the TCP layer.
    pub tcp_rx: Vec<(u32, u32, Vec<u8>)>,
}

impl<D: L2Device> Stack<D> {
    pub fn new(dev: D, xid: u32) -> Self {
        let mac = dev.mac();
        Stack {
            dev,
            mac,
            cfg: IpConfig::default(),
            arp: ArpCache::new(),
            dhcp: DhcpClient::new(mac, xid),
            ip_id: 1,
            rxbuf: [0; 2048],
            pongs: Vec::new(),
            rx_frames: 0,
            tx_frames: 0,
            tcp_rx: Vec::new(),
        }
    }

    /// Drain device RX + run protocol timers. Call frequently (net task).
    pub fn poll(&mut self, now: u64) {
        while let Some(n) = {
            let Stack { dev, rxbuf, .. } = self;
            dev.recv(rxbuf)
        } {
            self.on_frame(n, now);
        }
        if let Some(payload) = self.dhcp.step(now) {
            self.send_dhcp(&payload);
        }
        self.arp.expire_pending(now);
    }

    // ------------------------------------------------------------------ RX --

    fn on_frame(&mut self, len: usize, now: u64) {
        if len < 14 {
            return;
        }
        self.rx_frames += 1;
        let dst_ok = self.rxbuf[0..6] == self.mac || self.rxbuf[0..6] == BCAST_MAC;
        if !dst_ok {
            return;
        }
        match be16(&self.rxbuf[12..14]) {
            ETHERTYPE_ARP => self.on_arp(len, now),
            ETHERTYPE_IPV4 => self.on_ipv4(len, now),
            _ => {}
        }
    }

    fn on_arp(&mut self, len: usize, now: u64) {
        let Some(pkt) = arp::parse(&self.rxbuf[14..len]) else {
            return;
        };
        self.arp.insert(pkt.spa, pkt.sha, now);
        // Flush frames that were waiting on this resolution.
        for f in self.arp.take_resolved(pkt.spa, pkt.sha, now) {
            self.dev.send(&f);
            self.tx_frames += 1;
        }
        // Reply to requests for our address.
        if pkt.op == 1 && self.cfg.up && pkt.tpa == self.cfg.ip {
            let mut frame = [0u8; 42];
            frame[0..6].copy_from_slice(&pkt.sha);
            frame[6..12].copy_from_slice(&self.mac);
            put16(&mut frame[12..14], ETHERTYPE_ARP);
            arp::build(&mut frame[14..], 2, self.mac, self.cfg.ip, pkt.sha, pkt.spa);
            self.dev.send(&frame);
            self.tx_frames += 1;
        }
    }

    fn on_ipv4(&mut self, len: usize, now: u64) {
        let (src, dst, proto, p_off, p_len) = match ipv4::parse(&self.rxbuf[14..len]) {
            Some(ip) => {
                let ihl = ((self.rxbuf[14] & 0xf) as usize) * 4;
                (ip.src, ip.dst, ip.proto, 14 + ihl, ip.payload.len())
            }
            None => return,
        };
        let for_us = !self.cfg.up || dst == self.cfg.ip || dst == 0xffff_ffff;
        if !for_us {
            return;
        }
        match proto {
            PROTO_ICMP => {
                let mut reply = [0u8; 1600];
                let payload = &self.rxbuf[p_off..p_off + p_len];
                if let Some(n) = icmp::echo_reply(payload, &mut reply) {
                    self.send_ipv4(src, PROTO_ICMP, &reply[..n], now);
                } else if let Some((id, seq)) = icmp::parse_echo_reply(payload) {
                    self.pongs.push((id, seq));
                }
            }
            PROTO_UDP => {
                let p = &self.rxbuf[p_off..p_off + p_len];
                if p.len() < 8 {
                    return;
                }
                let dport = be16(&p[2..4]);
                let udp_len = (be16(&p[4..6]) as usize).min(p.len());
                if dport == dhcp::CLIENT_PORT && udp_len > 8 {
                    let body: Vec<u8> = p[8..udp_len].to_vec();
                    let mut bound = false;
                    let reply = self.dhcp.on_packet(&body, now, &mut bound);
                    if bound {
                        let l = self.dhcp.lease;
                        self.cfg = IpConfig {
                            ip: l.ip,
                            mask: l.mask,
                            gw: l.router,
                            dns: l.dns,
                            up: true,
                        };
                    }
                    if let Some(r) = reply {
                        self.send_dhcp(&r);
                    }
                }
            }
            PROTO_TCP => {
                // M6: queue for the TCP layer.
                let seg = self.rxbuf[p_off..p_off + p_len].to_vec();
                if self.tcp_rx.len() < 128 {
                    self.tcp_rx.push((src, dst, seg));
                }
            }
            _ => {}
        }
    }

    // ------------------------------------------------------------------ TX --

    /// Send an IPv4 packet, resolving the next hop via ARP (queued if pending).
    pub fn send_ipv4(&mut self, dst: u32, proto: u8, payload: &[u8], now: u64) {
        assert!(payload.len() + ipv4::HDR_LEN <= MTU, "IPv4 payload exceeds MTU");
        let next_hop = if !self.cfg.up {
            dst
        } else if dst & self.cfg.mask == self.cfg.ip & self.cfg.mask || dst == 0xffff_ffff {
            dst
        } else {
            self.cfg.gw
        };

        let total = 14 + ipv4::HDR_LEN + payload.len();
        let id = self.ip_id;
        self.ip_id = self.ip_id.wrapping_add(1);
        let src_ip = self.cfg.ip;
        let mac = self.mac;

        let build = |dst_mac: [u8; 6], buf: &mut [u8]| {
            buf[0..6].copy_from_slice(&dst_mac);
            buf[6..12].copy_from_slice(&mac);
            put16(&mut buf[12..14], ETHERTYPE_IPV4);
            ipv4::build_header(&mut buf[14..], src_ip, dst, proto, payload.len(), id);
            buf[14 + ipv4::HDR_LEN..total].copy_from_slice(payload);
        };

        if dst == 0xffff_ffff {
            let mut f = [0u8; 1600];
            build(BCAST_MAC, &mut f);
            self.dev.send(&f[..total]);
            self.tx_frames += 1;
            return;
        }

        match self.arp.lookup(next_hop, now) {
            Some(m) => {
                let mut f = [0u8; 1600];
                build(m, &mut f);
                self.dev.send(&f[..total]);
                self.tx_frames += 1;
            }
            None => {
                let mut f = alloc::vec![0u8; total];
                build([0; 6], &mut f);
                self.arp.enqueue_pending(next_hop, f, now);
                self.send_arp_request(next_hop);
            }
        }
    }

    fn send_arp_request(&mut self, ip: u32) {
        let mut frame = [0u8; 42];
        frame[0..6].copy_from_slice(&BCAST_MAC);
        frame[6..12].copy_from_slice(&self.mac);
        put16(&mut frame[12..14], ETHERTYPE_ARP);
        arp::build(&mut frame[14..], 1, self.mac, self.cfg.ip, [0; 6], ip);
        self.dev.send(&frame);
        self.tx_frames += 1;
    }

    /// UDP send with proper checksum.
    pub fn send_udp(&mut self, dst: u32, sport: u16, dport: u16, body: &[u8], now: u64) {
        let udp_len = 8 + body.len();
        let mut p = alloc::vec![0u8; udp_len];
        put16(&mut p[0..2], sport);
        put16(&mut p[2..4], dport);
        put16(&mut p[4..6], udp_len as u16);
        p[8..].copy_from_slice(body);
        let mut c = Csum::new();
        super::wire::feed_pseudo(&mut c, self.cfg.ip, dst, PROTO_UDP, udp_len as u16);
        c.feed(&p);
        let mut csum = c.finish();
        if csum == 0 {
            csum = 0xffff;
        }
        put16(&mut p[6..8], csum);
        self.send_ipv4(dst, PROTO_UDP, &p, now);
    }

    fn send_dhcp(&mut self, payload: &[u8]) {
        // DHCP goes out as src 0.0.0.0 → 255.255.255.255 while unconfigured;
        // send_udp uses cfg.ip (0 pre-lease) which is exactly right.
        self.send_udp(0xffff_ffff, dhcp::CLIENT_PORT, dhcp::SERVER_PORT, payload, 0);
    }

    /// Fire an ICMP echo request (diagnostics / gate test).
    pub fn ping(&mut self, dst: u32, id: u16, seq: u16, now: u64) {
        let mut req = [0u8; 64];
        let n = icmp::echo_request(&mut req, id, seq);
        self.send_ipv4(dst, PROTO_ICMP, &req[..n], now);
    }

    pub fn dhcp_state(&self) -> dhcp::State {
        self.dhcp.state
    }

    /// Raw TCP segment TX (M6 uses this; checksum computed here).
    pub fn send_tcp_segment(&mut self, dst: u32, seg: &mut [u8], now: u64) {
        let mut c = Csum::new();
        super::wire::feed_pseudo(&mut c, self.cfg.ip, dst, PROTO_TCP, seg.len() as u16);
        put16(&mut seg[16..18], 0);
        c.feed(seg);
        let csum = c.finish();
        put16(&mut seg[16..18], csum);
        self.send_ipv4(dst, PROTO_TCP, seg, now);
    }
}
