//! ICMPv4: echo reply (server side) + echo request (diagnostics).

use super::wire::{be16, checksum, put16};

pub const TYPE_ECHO_REPLY: u8 = 0;
pub const TYPE_ECHO_REQUEST: u8 = 8;

/// If `payload` is an echo request, write the matching reply into `out`
/// (same id/seq/data) and return its length.
pub fn echo_reply(payload: &[u8], out: &mut [u8]) -> Option<usize> {
    if payload.len() < 8 || payload[0] != TYPE_ECHO_REQUEST || payload[1] != 0 {
        return None;
    }
    if checksum(payload) != 0 {
        return None;
    }
    let n = payload.len().min(out.len());
    out[..n].copy_from_slice(&payload[..n]);
    out[0] = TYPE_ECHO_REPLY;
    put16(&mut out[2..4], 0);
    let c = checksum(&out[..n]);
    put16(&mut out[2..4], c);
    Some(n)
}

/// Build an echo request with `id`/`seq` and a fixed 32-byte pattern payload.
pub fn echo_request(out: &mut [u8], id: u16, seq: u16) -> usize {
    let n = 8 + 32;
    out[0] = TYPE_ECHO_REQUEST;
    out[1] = 0;
    put16(&mut out[2..4], 0);
    put16(&mut out[4..6], id);
    put16(&mut out[6..8], seq);
    for i in 0..32 {
        out[8 + i] = b'a' + (i % 23) as u8;
    }
    let c = checksum(&out[..n]);
    put16(&mut out[2..4], c);
    n
}

/// Parse an echo reply; returns (id, seq).
pub fn parse_echo_reply(p: &[u8]) -> Option<(u16, u16)> {
    if p.len() < 8 || p[0] != TYPE_ECHO_REPLY || checksum(p) != 0 {
        return None;
    }
    Some((be16(&p[4..6]), be16(&p[6..8])))
}
