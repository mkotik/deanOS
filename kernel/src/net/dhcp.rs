//! DHCPv4 client: DISCOVER → OFFER → REQUEST → ACK with renewal (T1) timer.
//!
//! Driven by Stack: `step()` for timers (emits packets to send), `on_packet()`
//! for server replies arriving on UDP 68.

use super::wire::{be32, put16, put32};
use alloc::vec::Vec;

pub const CLIENT_PORT: u16 = 68;
pub const SERVER_PORT: u16 = 67;

const MSG_DISCOVER: u8 = 1;
const MSG_OFFER: u8 = 2;
const MSG_REQUEST: u8 = 3;
const MSG_ACK: u8 = 5;
const MSG_NAK: u8 = 6;

const MAGIC: u32 = 0x6382_5363;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum State {
    Init,
    Selecting,
    Requesting,
    Bound,
    Renewing,
}

#[derive(Clone, Copy, Default)]
pub struct Lease {
    pub ip: u32,
    pub mask: u32,
    pub router: u32,
    pub dns: u32,
    pub server: u32,
    pub lease_secs: u32,
}

pub struct DhcpClient {
    pub state: State,
    mac: [u8; 6],
    xid: u32,
    pub lease: Lease,
    offered: Lease,
    last_tx_ms: u64,
    bound_at_ms: u64,
    tries: u32,
}

impl DhcpClient {
    pub fn new(mac: [u8; 6], xid: u32) -> Self {
        DhcpClient {
            state: State::Init,
            mac,
            xid,
            lease: Lease::default(),
            offered: Lease::default(),
            last_tx_ms: 0,
            bound_at_ms: 0,
            tries: 0,
        }
    }

    /// Timer step. Returns a DHCP payload to broadcast (UDP 68 -> 67) if due.
    pub fn step(&mut self, now: u64) -> Option<Vec<u8>> {
        match self.state {
            State::Init => {
                self.state = State::Selecting;
                self.last_tx_ms = now;
                self.tries = 0;
                Some(self.build(MSG_DISCOVER, 0, 0))
            }
            State::Selecting | State::Requesting => {
                // Retransmit with backoff; restart after 5 tries.
                let wait = 1000u64 << self.tries.min(4);
                if now.saturating_sub(self.last_tx_ms) >= wait {
                    self.tries += 1;
                    self.last_tx_ms = now;
                    if self.tries > 5 {
                        self.state = State::Init;
                        return None;
                    }
                    let msg = if self.state == State::Selecting {
                        self.build(MSG_DISCOVER, 0, 0)
                    } else {
                        self.build(MSG_REQUEST, self.offered.ip, self.offered.server)
                    };
                    return Some(msg);
                }
                None
            }
            State::Bound => {
                // Renew at T1 = lease/2.
                let t1_ms = (self.lease.lease_secs as u64) * 500;
                if now.saturating_sub(self.bound_at_ms) >= t1_ms {
                    self.state = State::Renewing;
                    self.last_tx_ms = now;
                    self.tries = 0;
                    return Some(self.build(MSG_REQUEST, self.lease.ip, 0));
                }
                None
            }
            State::Renewing => {
                let lease_ms = (self.lease.lease_secs as u64) * 1000;
                if now.saturating_sub(self.bound_at_ms) >= lease_ms {
                    // Lease expired: start over.
                    self.state = State::Init;
                    self.lease = Lease::default();
                    return None;
                }
                if now.saturating_sub(self.last_tx_ms) >= 5000 {
                    self.last_tx_ms = now;
                    return Some(self.build(MSG_REQUEST, self.lease.ip, 0));
                }
                None
            }
        }
    }

    /// Handle a server payload (UDP dst 68). Returns a reply to broadcast,
    /// and sets `newly_bound` when a lease was just acquired/renewed.
    pub fn on_packet(&mut self, p: &[u8], now: u64, newly_bound: &mut bool) -> Option<Vec<u8>> {
        let (msg, lease) = parse(p, self.xid)?;
        match (self.state, msg) {
            (State::Selecting, MSG_OFFER) => {
                self.offered = lease;
                self.state = State::Requesting;
                self.last_tx_ms = now;
                self.tries = 0;
                Some(self.build(MSG_REQUEST, lease.ip, lease.server))
            }
            (State::Requesting | State::Renewing, MSG_ACK) => {
                self.lease = lease;
                if self.lease.lease_secs == 0 {
                    self.lease.lease_secs = 3600;
                }
                self.state = State::Bound;
                self.bound_at_ms = now;
                *newly_bound = true;
                None
            }
            (State::Requesting | State::Renewing, MSG_NAK) => {
                self.state = State::Init;
                self.lease = Lease::default();
                None
            }
            _ => None,
        }
    }

    fn build(&self, msg: u8, requested_ip: u32, server_id: u32) -> Vec<u8> {
        let mut p = alloc::vec![0u8; 300];
        p[0] = 1; // BOOTREQUEST
        p[1] = 1; // ethernet
        p[2] = 6; // hlen
        put32(&mut p[4..8], self.xid);
        put16(&mut p[10..12], 0x8000); // broadcast flag: reply to ff:ff
        // ciaddr: only valid when bound/renewing
        if msg == MSG_REQUEST && server_id == 0 && self.lease.ip != 0 {
            put32(&mut p[12..16], self.lease.ip);
        }
        p[28..34].copy_from_slice(&self.mac);
        put32(&mut p[236..240], MAGIC);
        let mut o = 240;
        p[o] = 53;
        p[o + 1] = 1;
        p[o + 2] = msg;
        o += 3;
        if requested_ip != 0 && server_id != 0 {
            p[o] = 50;
            p[o + 1] = 4;
            put32(&mut p[o + 2..o + 6], requested_ip);
            o += 6;
        }
        if server_id != 0 {
            p[o] = 54;
            p[o + 1] = 4;
            put32(&mut p[o + 2..o + 6], server_id);
            o += 6;
        }
        // Parameter request: mask, router, dns, lease time.
        p[o..o + 6].copy_from_slice(&[55, 4, 1, 3, 6, 51]);
        o += 6;
        p[o] = 255;
        p.truncate(o + 1);
        p
    }
}

/// Parse a BOOTREPLY for our xid: returns (message type, lease fields).
fn parse(p: &[u8], xid: u32) -> Option<(u8, Lease)> {
    if p.len() < 241 || p[0] != 2 || be32(&p[4..8]) != xid || be32(&p[236..240]) != MAGIC {
        return None;
    }
    let mut lease = Lease {
        ip: be32(&p[16..20]), // yiaddr
        ..Lease::default()
    };
    let mut msg = 0u8;
    let mut o = 240;
    while o + 1 < p.len() {
        let (code, len) = (p[o], *p.get(o + 1).unwrap_or(&0) as usize);
        if code == 255 {
            break;
        }
        if code == 0 {
            o += 1;
            continue;
        }
        if o + 2 + len > p.len() {
            break;
        }
        let v = &p[o + 2..o + 2 + len];
        match code {
            53 if len >= 1 => msg = v[0],
            1 if len >= 4 => lease.mask = be32(v),
            3 if len >= 4 => lease.router = be32(v),
            6 if len >= 4 => lease.dns = be32(v),
            51 if len >= 4 => lease.lease_secs = be32(v),
            54 if len >= 4 => lease.server = be32(v),
            _ => {}
        }
        o += 2 + len;
    }
    if msg == 0 {
        None
    } else {
        Some((msg, lease))
    }
}
