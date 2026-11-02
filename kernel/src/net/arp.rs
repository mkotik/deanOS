//! ARP: bounded cache + pending-frame queue (resolved-on-reply TX).

use alloc::vec::Vec;

pub const ETHERTYPE_ARP: u16 = 0x0806;

const CACHE_SLOTS: usize = 16;
const PENDING_MAX: usize = 8;
const ENTRY_TTL_MS: u64 = 120_000;
const MAX_PENDING_AGE_MS: u64 = 3_000;

#[derive(Clone, Copy, Default)]
struct Entry {
    ip: u32,
    mac: [u8; 6],
    ts: u64,
    valid: bool,
}

pub struct ArpCache {
    entries: [Entry; CACHE_SLOTS],
    /// Frames waiting on resolution: (next-hop ip, enqueued-at, full frame
    /// with a zeroed dst MAC to patch).
    pending: Vec<(u32, u64, Vec<u8>)>,
}

impl ArpCache {
    pub fn new() -> Self {
        ArpCache {
            entries: [Entry::default(); CACHE_SLOTS],
            pending: Vec::new(),
        }
    }

    pub fn lookup(&self, ip: u32, now: u64) -> Option<[u8; 6]> {
        self.entries
            .iter()
            .find(|e| e.valid && e.ip == ip && now.saturating_sub(e.ts) < ENTRY_TTL_MS)
            .map(|e| e.mac)
    }

    pub fn insert(&mut self, ip: u32, mac: [u8; 6], now: u64) {
        if let Some(e) = self.entries.iter_mut().find(|e| e.valid && e.ip == ip) {
            e.mac = mac;
            e.ts = now;
            return;
        }
        // Free slot, else evict the oldest.
        let idx = self
            .entries
            .iter()
            .position(|e| !e.valid)
            .unwrap_or_else(|| {
                let mut oldest = 0;
                for (i, e) in self.entries.iter().enumerate() {
                    if e.ts < self.entries[oldest].ts {
                        oldest = i;
                    }
                }
                oldest
            });
        self.entries[idx] = Entry {
            ip,
            mac,
            ts: now,
            valid: true,
        };
    }

    /// Queue a frame awaiting resolution of `next_hop`. Frame's dst MAC
    /// (bytes 0..6) is patched when the reply arrives.
    pub fn enqueue_pending(&mut self, next_hop: u32, frame: Vec<u8>, now: u64) {
        if self.pending.len() >= PENDING_MAX {
            self.pending.remove(0); // drop oldest
        }
        self.pending.push((next_hop, now, frame));
    }

    /// On resolution: return all frames for `ip` with dst MAC patched in.
    pub fn take_resolved(&mut self, ip: u32, mac: [u8; 6], now: u64) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut i = 0;
        while i < self.pending.len() {
            if self.pending[i].0 == ip {
                let (_, ts, mut f) = self.pending.swap_remove(i);
                if now.saturating_sub(ts) <= MAX_PENDING_AGE_MS {
                    f[0..6].copy_from_slice(&mac);
                    out.push(f);
                }
            } else {
                i += 1;
            }
        }
        out
    }

    pub fn expire_pending(&mut self, now: u64) {
        self.pending
            .retain(|(_, ts, _)| now.saturating_sub(*ts) <= MAX_PENDING_AGE_MS);
    }
}

/// Build an ARP packet (request op=1 / reply op=2) into a 28-byte buffer.
pub fn build(
    out: &mut [u8],
    op: u16,
    sha: [u8; 6],
    spa: u32,
    tha: [u8; 6],
    tpa: u32,
) -> usize {
    use super::wire::{put16, put32};
    put16(&mut out[0..2], 1); // htype ethernet
    put16(&mut out[2..4], 0x0800); // ptype ipv4
    out[4] = 6;
    out[5] = 4;
    put16(&mut out[6..8], op);
    out[8..14].copy_from_slice(&sha);
    put32(&mut out[14..18], spa);
    out[18..24].copy_from_slice(&tha);
    put32(&mut out[24..28], tpa);
    28
}

pub struct ArpPacket {
    pub op: u16,
    pub sha: [u8; 6],
    pub spa: u32,
    pub tpa: u32,
}

pub fn parse(p: &[u8]) -> Option<ArpPacket> {
    use super::wire::{be16, be32};
    if p.len() < 28 || be16(&p[0..2]) != 1 || be16(&p[2..4]) != 0x0800 {
        return None;
    }
    let mut sha = [0u8; 6];
    sha.copy_from_slice(&p[8..14]);
    Some(ArpPacket {
        op: be16(&p[6..8]),
        sha,
        spa: be32(&p[14..18]),
        tpa: be32(&p[24..28]),
    })
}
