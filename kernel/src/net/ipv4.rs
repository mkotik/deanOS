//! IPv4 header parse/build. No fragmentation (DF always set; fragments dropped).

use super::wire::{be16, be32, checksum, put16, put32};

pub const ETHERTYPE_IPV4: u16 = 0x0800;
pub const PROTO_ICMP: u8 = 1;
pub const PROTO_TCP: u8 = 6;
pub const PROTO_UDP: u8 = 17;

pub const HDR_LEN: usize = 20;

pub struct Ipv4Packet<'a> {
    pub src: u32,
    pub dst: u32,
    pub proto: u8,
    pub payload: &'a [u8],
}

pub fn parse(p: &[u8]) -> Option<Ipv4Packet<'_>> {
    if p.len() < HDR_LEN || p[0] >> 4 != 4 {
        return None;
    }
    let ihl = ((p[0] & 0xf) as usize) * 4;
    let total = be16(&p[2..4]) as usize;
    if ihl < HDR_LEN || total < ihl || total > p.len() {
        return None;
    }
    // Drop fragments (offset != 0 or MF set).
    let frag = be16(&p[6..8]);
    if frag & 0x3fff != 0 {
        return None;
    }
    if checksum(&p[..ihl]) != 0 {
        return None;
    }
    Some(Ipv4Packet {
        src: be32(&p[12..16]),
        dst: be32(&p[16..20]),
        proto: p[9],
        payload: &p[ihl..total],
    })
}

/// Write a 20-byte header for `payload_len` bytes of `proto` into out[0..20].
pub fn build_header(out: &mut [u8], src: u32, dst: u32, proto: u8, payload_len: usize, id: u16) {
    out[0] = 0x45;
    out[1] = 0;
    put16(&mut out[2..4], (HDR_LEN + payload_len) as u16);
    put16(&mut out[4..6], id);
    put16(&mut out[6..8], 0x4000); // DF
    out[8] = 64; // TTL
    out[9] = proto;
    put16(&mut out[10..12], 0); // csum below
    put32(&mut out[12..16], src);
    put32(&mut out[16..20], dst);
    let c = checksum(&out[..HDR_LEN]);
    put16(&mut out[10..12], c);
}
