//! Host tests for the streaming HTTP parser and JSON codec (M7).

use crate::http::json::{self, Json};
use crate::http::request::{Method, Parser, Poll};

fn ready(p: &mut Parser) -> crate::http::request::Request {
    match p.poll() {
        Poll::Ready(r) => r,
        Poll::Incomplete => panic!("incomplete"),
        Poll::Bad => panic!("bad"),
    }
}

#[test]
fn parses_simple_get() {
    let mut p = Parser::new();
    p.feed(b"GET /health HTTP/1.1\r\nHost: x\r\n\r\n");
    let r = ready(&mut p);
    assert_eq!(r.method, Method::Get);
    assert_eq!(r.path, "/health");
    assert!(r.keep_alive, "HTTP/1.1 defaults to keep-alive");
    assert!(r.body.is_empty());
}

#[test]
fn byte_at_a_time_streaming() {
    let raw = b"POST /api/items HTTP/1.1\r\nContent-Length: 4\r\n\r\nabcd";
    let mut p = Parser::new();
    for (i, b) in raw.iter().enumerate() {
        p.feed(core::slice::from_ref(b));
        match p.poll() {
            Poll::Incomplete if i + 1 < raw.len() => {}
            Poll::Ready(r) if i + 1 == raw.len() => {
                assert_eq!(r.method, Method::Post);
                assert_eq!(r.body, b"abcd");
                return;
            }
            Poll::Incomplete => panic!("never completed"),
            _ => panic!("unexpected state at byte {i}"),
        }
    }
}

#[test]
fn pipelined_requests_preserved() {
    let mut p = Parser::new();
    p.feed(b"GET /a HTTP/1.1\r\n\r\nGET /b HTTP/1.1\r\nConnection: close\r\n\r\n");
    let r1 = ready(&mut p);
    assert_eq!(r1.path, "/a");
    let r2 = ready(&mut p);
    assert_eq!(r2.path, "/b");
    assert!(!r2.keep_alive, "Connection: close honored");
    assert!(matches!(p.poll(), Poll::Incomplete));
}

#[test]
fn http10_defaults_to_close() {
    let mut p = Parser::new();
    p.feed(b"GET / HTTP/1.0\r\n\r\n");
    assert!(!ready(&mut p).keep_alive);
}

#[test]
fn rejects_chunked_and_garbage() {
    let mut p = Parser::new();
    p.feed(b"POST / HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n");
    assert!(matches!(p.poll(), Poll::Bad));

    let mut p2 = Parser::new();
    p2.feed(b"NONSENSE\r\n\r\n");
    assert!(matches!(p2.poll(), Poll::Bad));
}

#[test]
fn oversized_headers_rejected() {
    let mut p = Parser::new();
    p.feed(b"GET / HTTP/1.1\r\n");
    for _ in 0..600 {
        p.feed(b"X-Pad: aaaaaaaaaaaaaaaaaaaa\r\n");
    }
    assert!(matches!(p.poll(), Poll::Bad));
}

// ---------------------------------------------------------------- JSON ----

#[test]
fn json_roundtrip() {
    let src = br#"{"name":"widget","qty":3,"tags":["a","b"],"nested":{"ok":true,"n":null},"price":9.75}"#;
    let v = json::parse(src).expect("parse");
    assert_eq!(v.get("name").unwrap().as_str(), Some("widget"));
    assert_eq!(v.get("qty").unwrap().as_f64(), Some(3.0));
    assert_eq!(v.get("price").unwrap().as_f64(), Some(9.75));
    let out = json::serialize(&v);
    let v2 = json::parse(out.as_bytes()).expect("reparse");
    assert_eq!(v, v2);
}

#[test]
fn json_escapes_and_unicode() {
    let v = json::parse(br#""a\"b\\c\ndA""#).unwrap();
    assert_eq!(v.as_str(), Some("a\"b\\c\ndA"));
    let s = json::serialize(&Json::Str("x\"y\n\t".into()));
    assert_eq!(s, r#""x\"y\n\t""#);
}

#[test]
fn json_numbers() {
    assert_eq!(json::parse(b"-12.5e2").unwrap().as_f64(), Some(-1250.0));
    assert_eq!(json::parse(b"0").unwrap().as_f64(), Some(0.0));
    assert_eq!(json::serialize(&Json::Num(42.0)), "42");
    assert_eq!(json::serialize(&Json::Num(1.5)), "1.5");
}

#[test]
fn json_rejects_malformed() {
    for bad in [
        &b"{"[..],
        b"{\"a\":}",
        b"[1,]",
        b"tru",
        b"\"unterminated",
        b"{\"a\":1} trailing",
        b"",
    ] {
        assert!(json::parse(bad).is_none(), "accepted: {bad:?}");
    }
}

#[test]
fn json_depth_limited() {
    let mut deep = Vec::new();
    for _ in 0..200 {
        deep.push(b'[');
    }
    assert!(json::parse(&deep).is_none());
}
