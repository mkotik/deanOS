//! Byte ring buffer for TCP RX/TX. The TX ring supports non-consuming reads
//! at an offset (retransmission reads from snd_una + k without consuming).

use alloc::vec;
use alloc::vec::Vec;

pub struct Ring {
    buf: Vec<u8>,
    head: usize, // read position
    len: usize,
}

impl Ring {
    pub fn new(cap: usize) -> Self {
        Ring {
            buf: vec![0; cap],
            head: 0,
            len: 0,
        }
    }

    pub fn capacity(&self) -> usize {
        self.buf.len()
    }
    pub fn len(&self) -> usize {
        self.len
    }
    pub fn free(&self) -> usize {
        self.buf.len() - self.len
    }
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Append as much of `data` as fits; returns bytes written.
    pub fn write(&mut self, data: &[u8]) -> usize {
        let n = data.len().min(self.free());
        let cap = self.buf.len();
        let tail = (self.head + self.len) % cap;
        let first = n.min(cap - tail);
        self.buf[tail..tail + first].copy_from_slice(&data[..first]);
        self.buf[..n - first].copy_from_slice(&data[first..n]);
        self.len += n;
        n
    }

    /// Copy up to out.len() bytes starting `offset` into the stored data,
    /// WITHOUT consuming. Returns bytes copied.
    pub fn peek_at(&self, offset: usize, out: &mut [u8]) -> usize {
        if offset >= self.len {
            return 0;
        }
        let n = out.len().min(self.len - offset);
        let cap = self.buf.len();
        let start = (self.head + offset) % cap;
        let first = n.min(cap - start);
        out[..first].copy_from_slice(&self.buf[start..start + first]);
        out[first..n].copy_from_slice(&self.buf[..n - first]);
        n
    }

    /// Consume up to `n` bytes from the front; returns bytes dropped.
    pub fn consume(&mut self, n: usize) -> usize {
        let n = n.min(self.len);
        self.head = (self.head + n) % self.buf.len();
        self.len -= n;
        n
    }

    /// Read (copy + consume) up to out.len() bytes.
    pub fn read(&mut self, out: &mut [u8]) -> usize {
        let n = self.peek_at(0, out);
        self.consume(n);
        n
    }
}
