//! Big-endian field access + RFC 1071 ones'-complement checksums.

#[inline]
pub fn be16(b: &[u8]) -> u16 {
    u16::from_be_bytes([b[0], b[1]])
}

#[inline]
pub fn be32(b: &[u8]) -> u32 {
    u32::from_be_bytes([b[0], b[1], b[2], b[3]])
}

#[inline]
pub fn put16(b: &mut [u8], v: u16) {
    b[0..2].copy_from_slice(&v.to_be_bytes());
}

#[inline]
pub fn put32(b: &mut [u8], v: u32) {
    b[0..4].copy_from_slice(&v.to_be_bytes());
}

/// Incremental RFC 1071 checksum accumulator (handles odd-length feeds).
#[derive(Default)]
pub struct Csum {
    sum: u32,
    odd: Option<u8>,
}

impl Csum {
    pub fn new() -> Self {
        Csum::default()
    }

    pub fn feed(&mut self, mut data: &[u8]) {
        if let Some(hi) = self.odd.take() {
            if let Some((&lo, rest)) = data.split_first() {
                self.sum += u32::from(u16::from_be_bytes([hi, lo]));
                data = rest;
            } else {
                self.odd = Some(hi);
                return;
            }
        }
        let mut chunks = data.chunks_exact(2);
        for c in &mut chunks {
            self.sum += u32::from(u16::from_be_bytes([c[0], c[1]]));
        }
        if let [last] = chunks.remainder() {
            self.odd = Some(*last);
        }
    }

    pub fn finish(mut self) -> u16 {
        if let Some(hi) = self.odd.take() {
            self.sum += u32::from(u16::from_be_bytes([hi, 0]));
        }
        while self.sum >> 16 != 0 {
            self.sum = (self.sum & 0xffff) + (self.sum >> 16);
        }
        !(self.sum as u16)
    }
}

/// One-shot checksum over a single slice.
pub fn checksum(data: &[u8]) -> u16 {
    let mut c = Csum::new();
    c.feed(data);
    c.finish()
}

/// TCP/UDP pseudo-header feed (IPv4).
pub fn feed_pseudo(c: &mut Csum, src: u32, dst: u32, proto: u8, len: u16) {
    let mut ph = [0u8; 12];
    put32(&mut ph[0..4], src);
    put32(&mut ph[4..8], dst);
    ph[9] = proto;
    put16(&mut ph[10..12], len);
    c.feed(&ph);
}
