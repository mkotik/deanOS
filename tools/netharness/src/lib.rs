//! Host test harness: compiles the kernel's hardware-independent net modules
//! verbatim and unit-tests them under std.

extern crate alloc;

#[path = "../../../kernel/src/net/mod.rs"]
pub mod net;

#[path = "../../../kernel/src/http/mod.rs"]
pub mod http;

#[cfg(test)]
mod tcp_tests;

#[cfg(test)]
mod http_tests;

#[cfg(test)]
mod tests {
    use crate::net::stack::{IpConfig, L2Device, Stack};
    use crate::net::{arp, dhcp, icmp, ipv4, wire};

    // ---------------------------------------------------------------- wire --

    #[test]
    fn checksum_rfc1071_vector() {
        // Classic example: 0x0001f203f4f5f6f7 -> 0x220d complement
        let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(wire::checksum(&data), 0x220d);
    }

    #[test]
    fn checksum_odd_and_split_feeds() {
        let data = [0x45, 0x00, 0x00, 0x73, 0x00, 0x00, 0x40, 0x00, 0x40];
        let whole = wire::checksum(&data);
        let mut c = wire::Csum::new();
        c.feed(&data[..3]);
        c.feed(&data[3..4]);
        c.feed(&data[4..]);
        assert_eq!(whole, c.finish());
    }

    // ---------------------------------------------------------------- ipv4 --

    #[test]
    fn ipv4_roundtrip_and_checksum() {
        let mut h = [0u8; 40];
        ipv4::build_header(&mut h, 0x0a00020f, 0x0a000202, 17, 20, 42);
        let pkt = ipv4::parse(&h).expect("parse");
        assert_eq!(pkt.src, 0x0a00020f);
        assert_eq!(pkt.dst, 0x0a000202);
        assert_eq!(pkt.proto, 17);
        assert_eq!(pkt.payload.len(), 20);
        // Corrupt a byte -> checksum must reject.
        let mut bad = h;
        bad[8] = 1;
        assert!(ipv4::parse(&bad).is_none());
    }

    #[test]
    fn ipv4_rejects_fragments() {
        let mut h = [0u8; 20];
        ipv4::build_header(&mut h, 1, 2, 6, 0, 1);
        h[6] = 0x20; // MF set
        h[10] = 0;
        h[11] = 0;
        let c = wire::checksum(&h);
        wire::put16(&mut h[10..12], c);
        assert!(ipv4::parse(&h).is_none());
    }

    // ---------------------------------------------------------------- icmp --

    #[test]
    fn icmp_echo_reply_flips_type_and_checksums() {
        let mut req = [0u8; 48];
        let n = icmp::echo_request(&mut req, 0x1234, 7);
        let mut rep = [0u8; 64];
        let m = icmp::echo_reply(&req[..n], &mut rep).expect("reply");
        assert_eq!(m, n);
        assert_eq!(rep[0], 0); // echo reply
        assert_eq!(wire::checksum(&rep[..m]), 0); // valid checksum
        assert_eq!(&rep[4..8], &req[4..8]); // id/seq preserved
        assert_eq!(icmp::parse_echo_reply(&rep[..m]), None.or(Some((0x1234, 7))));
    }

    #[test]
    fn icmp_rejects_bad_checksum() {
        let mut req = [0u8; 48];
        let n = icmp::echo_request(&mut req, 1, 1);
        req[8] ^= 0xff;
        let mut rep = [0u8; 64];
        assert!(icmp::echo_reply(&req[..n], &mut rep).is_none());
    }

    // ----------------------------------------------------------------- arp --

    #[test]
    fn arp_build_parse_roundtrip() {
        let mut buf = [0u8; 28];
        arp::build(&mut buf, 1, [1, 2, 3, 4, 5, 6], 0x0a000201, [0; 6], 0x0a000202);
        let p = arp::parse(&buf).expect("parse");
        assert_eq!(p.op, 1);
        assert_eq!(p.sha, [1, 2, 3, 4, 5, 6]);
        assert_eq!(p.spa, 0x0a000201);
        assert_eq!(p.tpa, 0x0a000202);
    }

    #[test]
    fn arp_cache_insert_lookup_expire() {
        let mut c = arp::ArpCache::new();
        c.insert(42, [9; 6], 1000);
        assert_eq!(c.lookup(42, 1001), Some([9; 6]));
        assert_eq!(c.lookup(42, 1000 + 130_000), None); // TTL expired
        // Eviction under pressure: fill >16 entries.
        for i in 0..40u32 {
            c.insert(100 + i, [i as u8; 6], 2000 + i as u64);
        }
        assert_eq!(c.lookup(139, 2100), Some([39u8; 6]));
    }

    // ---------------------------------------------------- stack + mock dev --

    struct MockDev {
        mac: [u8; 6],
        /// frames the stack transmitted
        tx: Vec<Vec<u8>>,
        /// frames queued for the stack to receive
        rx: std::collections::VecDeque<Vec<u8>>,
    }

    impl MockDev {
        fn new() -> Self {
            MockDev {
                mac: [0x02, 0, 0, 0, 0, 1],
                tx: Vec::new(),
                rx: Default::default(),
            }
        }
    }

    impl L2Device for MockDev {
        fn mac(&self) -> [u8; 6] {
            self.mac
        }
        fn send(&mut self, frame: &[u8]) -> bool {
            self.tx.push(frame.to_vec());
            true
        }
        fn recv(&mut self, out: &mut [u8]) -> Option<usize> {
            let f = self.rx.pop_front()?;
            out[..f.len()].copy_from_slice(&f);
            Some(f.len())
        }
    }

    const CLIENT_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 1];
    const SERVER_IP: u32 = 0x0a000202; // 10.0.2.2
    const OFFER_IP: u32 = 0x0a000264; // 10.0.2.100

    /// Craft a DHCP server reply frame (eth+ip+udp 67->68).
    fn dhcp_reply_frame(msg: u8, xid: u32) -> Vec<u8> {
        let mut b = vec![0u8; 240];
        b[0] = 2; // BOOTREPLY
        b[1] = 1;
        b[2] = 6;
        wire::put32(&mut b[4..8], xid);
        wire::put32(&mut b[16..20], OFFER_IP); // yiaddr
        b[28..34].copy_from_slice(&CLIENT_MAC);
        wire::put32(&mut b[236..240], 0x63825363);
        b.extend_from_slice(&[53, 1, msg]);
        b.extend_from_slice(&[1, 4, 255, 255, 255, 0]); // mask
        b.extend_from_slice(&[3, 4, 10, 0, 2, 2]); // router
        b.extend_from_slice(&[6, 4, 10, 0, 2, 3]); // dns
        b.extend_from_slice(&[51, 4, 0, 0, 0x0e, 0x10]); // lease 3600
        b.extend_from_slice(&[54, 4, 10, 0, 2, 2]); // server id
        b.push(255);

        // UDP
        let udp_len = 8 + b.len();
        let mut u = vec![0u8; udp_len];
        wire::put16(&mut u[0..2], 67);
        wire::put16(&mut u[2..4], 68);
        wire::put16(&mut u[4..6], udp_len as u16);
        u[8..].copy_from_slice(&b);
        // IP (broadcast reply)
        let mut ip = vec![0u8; 20 + udp_len];
        ipv4::build_header(&mut ip, SERVER_IP, 0xffff_ffff, 17, udp_len, 7);
        ip[20..].copy_from_slice(&u);
        // Eth
        let mut f = vec![0u8; 14 + ip.len()];
        f[0..6].fill(0xff);
        f[6..12].copy_from_slice(&[0x52, 0x55, 0x0a, 0, 2, 2]);
        wire::put16(&mut f[12..14], 0x0800);
        f[14..].copy_from_slice(&ip);
        f
    }

    /// Extract the DHCP message type the stack just transmitted (if any).
    fn tx_dhcp_msg(frame: &[u8]) -> Option<u8> {
        if frame.len() < 14 + 20 + 8 + 241 {
            return None;
        }
        if wire::be16(&frame[12..14]) != 0x0800 || frame[23] != 17 {
            return None;
        }
        let dhcp = &frame[14 + 20 + 8..];
        let mut o = 240;
        while o + 2 < dhcp.len() {
            if dhcp[o] == 53 {
                return Some(dhcp[o + 2]);
            }
            if dhcp[o] == 255 {
                break;
            }
            o += 2 + dhcp[o + 1] as usize;
        }
        None
    }

    #[test]
    fn stack_dhcp_full_handshake_then_echo_reply() {
        let mut s = Stack::new(MockDev::new(), 0xabcd);

        // t=0: stack should emit DISCOVER.
        s.poll(10);
        let disc = s.dev.tx.iter().find_map(|f| tx_dhcp_msg(f));
        assert_eq!(disc, Some(1), "expected DISCOVER");

        // Server OFFERs; stack must REQUEST.
        s.dev.rx.push_back(dhcp_reply_frame(2, 0xabcd));
        s.dev.tx.clear();
        s.poll(20);
        let req = s.dev.tx.iter().find_map(|f| tx_dhcp_msg(f));
        assert_eq!(req, Some(3), "expected REQUEST");

        // Server ACKs; stack must bind.
        s.dev.rx.push_back(dhcp_reply_frame(5, 0xabcd));
        s.poll(30);
        let cfg: IpConfig = s.cfg;
        assert!(cfg.up);
        assert_eq!(cfg.ip, OFFER_IP);
        assert_eq!(cfg.gw, SERVER_IP);
        assert_eq!(cfg.mask, 0xffff_ff00);

        // Inbound ICMP echo request -> stack emits a reply (via ARP pending,
        // since the requester's MAC is unknown: expect an ARP request first,
        // then the reply after we answer it).
        let mut icmp_req = vec![0u8; 40];
        let n = icmp::echo_request(&mut icmp_req, 0xbeef, 3);
        let mut ip = vec![0u8; 20 + n];
        ipv4::build_header(&mut ip, SERVER_IP, OFFER_IP, 1, n, 9);
        ip[20..].copy_from_slice(&icmp_req[..n]);
        let mut f = vec![0u8; 14 + ip.len()];
        f[0..6].copy_from_slice(&CLIENT_MAC);
        f[6..12].copy_from_slice(&[0x52, 0x55, 0x0a, 0, 2, 2]);
        wire::put16(&mut f[12..14], 0x0800);
        f[14..].copy_from_slice(&ip);

        s.dev.tx.clear();
        s.dev.rx.push_back(f);
        s.poll(40);

        // The stack doesn't know SERVER_IP's MAC yet -> ARP request on the wire.
        let arp_req = s
            .dev
            .tx
            .iter()
            .find(|f| wire::be16(&f[12..14]) == 0x0806)
            .expect("ARP request for echo requester");
        let p = arp::parse(&arp_req[14..]).unwrap();
        assert_eq!(p.op, 1);
        assert_eq!(p.tpa, SERVER_IP);

        // Answer the ARP; pending echo reply must flush.
        let mut reply = vec![0u8; 42];
        reply[0..6].copy_from_slice(&CLIENT_MAC);
        reply[6..12].copy_from_slice(&[0x52, 0x55, 0x0a, 0, 2, 2]);
        wire::put16(&mut reply[12..14], 0x0806);
        arp::build(
            &mut reply[14..],
            2,
            [0x52, 0x55, 0x0a, 0, 2, 2],
            SERVER_IP,
            CLIENT_MAC,
            OFFER_IP,
        );
        s.dev.tx.clear();
        s.dev.rx.push_back(reply);
        s.poll(50);

        let echo = s
            .dev
            .tx
            .iter()
            .find(|f| f.len() > 34 && wire::be16(&f[12..14]) == 0x0800 && f[23] == 1)
            .expect("flushed ICMP echo reply");
        let ipp = ipv4::parse(&echo[14..]).unwrap();
        assert_eq!(ipp.dst, SERVER_IP);
        assert_eq!(ipp.payload[0], 0); // echo reply type
        assert_eq!(wire::checksum(ipp.payload), 0);
        assert_eq!(wire::be16(&ipp.payload[4..6]), 0xbeef);
    }

    #[test]
    fn dhcp_client_retransmits_discover() {
        let mut c = dhcp::DhcpClient::new(CLIENT_MAC, 1);
        assert!(c.step(0).is_some()); // DISCOVER
        assert!(c.step(100).is_none()); // too soon
        assert!(c.step(1200).is_some()); // retransmit after 1s backoff
    }
}
