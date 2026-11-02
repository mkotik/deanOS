//! Buffered HTTP/1.1 response writer.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

pub fn status_text(code: u16) -> &'static str {
    match code {
        200 => "OK",
        201 => "Created",
        204 => "No Content",
        400 => "Bad Request",
        404 => "Not Found",
        405 => "Method Not Allowed",
        408 => "Request Timeout",
        500 => "Internal Server Error",
        _ => "Unknown",
    }
}

/// Serialize a complete response (headers + body) ready for the socket.
pub fn build(code: u16, content_type: &str, body: &[u8], keep_alive: bool) -> Vec<u8> {
    let mut head = String::new();
    let _ = write!(
        head,
        "HTTP/1.1 {} {}\r\nServer: deanOS/0.1\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: {}\r\n\r\n",
        code,
        status_text(code),
        content_type,
        body.len(),
        if keep_alive { "keep-alive" } else { "close" },
    );
    let mut out = head.into_bytes();
    out.extend_from_slice(body);
    out
}

pub fn json(code: u16, body: &str, keep_alive: bool) -> Vec<u8> {
    build(code, "application/json", body.as_bytes(), keep_alive)
}

pub fn error(code: u16, keep_alive: bool) -> Vec<u8> {
    let mut b = String::new();
    let _ = write!(b, "{{\"error\":\"{}\"}}", status_text(code));
    json(code, &b, keep_alive)
}
