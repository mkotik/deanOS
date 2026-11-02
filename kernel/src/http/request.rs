//! Streaming HTTP/1.1 request parser: feed bytes as they arrive; emits a
//! complete Request once headers + Content-Length body are in. Enforces
//! header/body limits. Keep-alive per HTTP/1.1 defaults.

use alloc::string::String;
use alloc::vec::Vec;

const MAX_HEADER: usize = 8 * 1024;
const MAX_BODY: usize = 256 * 1024;

#[derive(Clone, Copy, PartialEq, Debug)]
pub enum Method {
    Get,
    Post,
    Put,
    Delete,
    Head,
    Other,
}

pub struct Request {
    pub method: Method,
    pub path: String,
    pub body: Vec<u8>,
    pub keep_alive: bool,
}

pub enum Poll {
    /// Need more bytes.
    Incomplete,
    /// A full request (and how many input bytes beyond it were consumed: 0 —
    /// parser retains any pipelined surplus internally).
    Ready(Request),
    /// Unrecoverable parse error / limits exceeded: close the connection.
    Bad,
}

pub struct Parser {
    buf: Vec<u8>,
}

impl Parser {
    pub fn new() -> Self {
        Parser { buf: Vec::new() }
    }

    /// Append newly received bytes.
    pub fn feed(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    /// Try to extract one complete request from the buffer.
    pub fn poll(&mut self) -> Poll {
        // Find end of header block.
        let hdr_end = match find(&self.buf, b"\r\n\r\n") {
            Some(i) => i + 4,
            None => {
                return if self.buf.len() > MAX_HEADER {
                    Poll::Bad
                } else {
                    Poll::Incomplete
                };
            }
        };
        if hdr_end > MAX_HEADER {
            return Poll::Bad;
        }

        let head = &self.buf[..hdr_end - 4];
        let mut lines = head.split(|&b| b == b'\n').map(|l| l.strip_suffix(b"\r").unwrap_or(l));

        // Request line: METHOD SP PATH SP VERSION
        let Some(reqline) = lines.next() else {
            return Poll::Bad;
        };
        let mut parts = reqline.split(|&b| b == b' ').filter(|p| !p.is_empty());
        let (Some(m), Some(p), Some(v)) = (parts.next(), parts.next(), parts.next()) else {
            return Poll::Bad;
        };
        let method = match m {
            b"GET" => Method::Get,
            b"POST" => Method::Post,
            b"PUT" => Method::Put,
            b"DELETE" => Method::Delete,
            b"HEAD" => Method::Head,
            _ => Method::Other,
        };
        let http11 = v == b"HTTP/1.1";
        if !http11 && v != b"HTTP/1.0" {
            return Poll::Bad;
        }
        let Ok(path) = core::str::from_utf8(p) else {
            return Poll::Bad;
        };
        let path = String::from(path);

        // Headers we care about.
        let mut content_length = 0usize;
        let mut keep_alive = http11; // 1.1 default on, 1.0 default off
        for line in lines {
            let Some(colon) = line.iter().position(|&b| b == b':') else {
                continue;
            };
            let name = &line[..colon];
            let value = core::str::from_utf8(&line[colon + 1..]).unwrap_or("").trim();
            if eq_ignore_case(name, b"content-length") {
                match value.parse::<usize>() {
                    Ok(n) if n <= MAX_BODY => content_length = n,
                    _ => return Poll::Bad,
                }
            } else if eq_ignore_case(name, b"connection") {
                if value.eq_ignore_ascii_case("close") {
                    keep_alive = false;
                } else if value.eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            } else if eq_ignore_case(name, b"transfer-encoding") {
                // Chunked bodies unsupported: reject rather than misparse.
                return Poll::Bad;
            }
        }

        let total = hdr_end + content_length;
        if self.buf.len() < total {
            return Poll::Incomplete;
        }
        let body = self.buf[hdr_end..total].to_vec();
        // Retain pipelined surplus.
        self.buf.drain(..total);
        Poll::Ready(Request {
            method,
            path,
            body,
            keep_alive,
        })
    }
}

fn eq_ignore_case(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).all(|(x, y)| x.to_ascii_lowercase() == *y)
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}
