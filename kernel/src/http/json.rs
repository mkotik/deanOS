//! Recursive-descent JSON parser + serializer (RFC 8259 subset: no \u escapes
//! beyond BMP passthrough, numbers as f64).

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write;

#[derive(Clone, Debug, PartialEq)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    pub fn get(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(kv) => kv.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    pub fn as_str(&self) -> Option<&str> {
        match self {
            Json::Str(s) => Some(s),
            _ => None,
        }
    }

    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Json::Num(n) => Some(*n),
            _ => None,
        }
    }
}

const MAX_DEPTH: u32 = 32;

pub fn parse(input: &[u8]) -> Option<Json> {
    let mut p = P { b: input, i: 0 };
    p.ws();
    let v = p.value(0)?;
    p.ws();
    if p.i == p.b.len() {
        Some(v)
    } else {
        None
    }
}

struct P<'a> {
    b: &'a [u8],
    i: usize,
}

impl P<'_> {
    fn peek(&self) -> Option<u8> {
        self.b.get(self.i).copied()
    }
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t' | b'\r' | b'\n')) {
            self.i += 1;
        }
    }
    fn eat(&mut self, c: u8) -> bool {
        if self.peek() == Some(c) {
            self.i += 1;
            true
        } else {
            false
        }
    }
    fn lit(&mut self, s: &[u8]) -> bool {
        if self.b[self.i..].starts_with(s) {
            self.i += s.len();
            true
        } else {
            false
        }
    }

    fn value(&mut self, depth: u32) -> Option<Json> {
        if depth > MAX_DEPTH {
            return None;
        }
        self.ws();
        match self.peek()? {
            b'n' => self.lit(b"null").then_some(Json::Null),
            b't' => self.lit(b"true").then_some(Json::Bool(true)),
            b'f' => self.lit(b"false").then_some(Json::Bool(false)),
            b'"' => Some(Json::Str(self.string()?)),
            b'[' => {
                self.i += 1;
                let mut arr = Vec::new();
                self.ws();
                if self.eat(b']') {
                    return Some(Json::Arr(arr));
                }
                loop {
                    arr.push(self.value(depth + 1)?);
                    self.ws();
                    if self.eat(b']') {
                        return Some(Json::Arr(arr));
                    }
                    if !self.eat(b',') {
                        return None;
                    }
                }
            }
            b'{' => {
                self.i += 1;
                let mut obj = Vec::new();
                self.ws();
                if self.eat(b'}') {
                    return Some(Json::Obj(obj));
                }
                loop {
                    self.ws();
                    let k = self.string()?;
                    self.ws();
                    if !self.eat(b':') {
                        return None;
                    }
                    obj.push((k, self.value(depth + 1)?));
                    self.ws();
                    if self.eat(b'}') {
                        return Some(Json::Obj(obj));
                    }
                    if !self.eat(b',') {
                        return None;
                    }
                }
            }
            _ => self.number(),
        }
    }

    fn string(&mut self) -> Option<String> {
        if !self.eat(b'"') {
            return None;
        }
        let mut s = Vec::new();
        loop {
            let c = self.peek()?;
            self.i += 1;
            match c {
                b'"' => break,
                b'\\' => {
                    let e = self.peek()?;
                    self.i += 1;
                    match e {
                        b'"' => s.push(b'"'),
                        b'\\' => s.push(b'\\'),
                        b'/' => s.push(b'/'),
                        b'n' => s.push(b'\n'),
                        b't' => s.push(b'\t'),
                        b'r' => s.push(b'\r'),
                        b'b' => s.push(0x08),
                        b'f' => s.push(0x0c),
                        b'u' => {
                            let h = self.b.get(self.i..self.i + 4)?;
                            self.i += 4;
                            let cp = u32::from_str_radix(core::str::from_utf8(h).ok()?, 16).ok()?;
                            let ch = char::from_u32(cp).unwrap_or('\u{fffd}');
                            let mut buf = [0u8; 4];
                            s.extend_from_slice(ch.encode_utf8(&mut buf).as_bytes());
                        }
                        _ => return None,
                    }
                }
                0x00..=0x1f => return None, // control chars must be escaped
                _ => s.push(c),
            }
        }
        String::from_utf8(s).ok()
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.i;
        if self.eat(b'-') {}
        while matches!(self.peek(), Some(b'0'..=b'9')) {
            self.i += 1;
        }
        if self.eat(b'.') {
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        if matches!(self.peek(), Some(b'e' | b'E')) {
            self.i += 1;
            if matches!(self.peek(), Some(b'+' | b'-')) {
                self.i += 1;
            }
            while matches!(self.peek(), Some(b'0'..=b'9')) {
                self.i += 1;
            }
        }
        let txt = core::str::from_utf8(&self.b[start..self.i]).ok()?;
        if txt.is_empty() || txt == "-" {
            return None;
        }
        parse_f64(txt).map(Json::Num)
    }
}

/// Minimal decimal -> f64 (fine for REST payload magnitudes).
fn parse_f64(s: &str) -> Option<f64> {
    let b = s.as_bytes();
    let mut i = 0;
    let neg = b[0] == b'-';
    if neg {
        i = 1;
    }
    let mut int = 0f64;
    let mut any = false;
    while i < b.len() && b[i].is_ascii_digit() {
        int = int * 10.0 + (b[i] - b'0') as f64;
        i += 1;
        any = true;
    }
    let mut frac = 0f64;
    let mut scale = 0.1f64;
    if i < b.len() && b[i] == b'.' {
        i += 1;
        while i < b.len() && b[i].is_ascii_digit() {
            frac += (b[i] - b'0') as f64 * scale;
            scale *= 0.1;
            i += 1;
            any = true;
        }
    }
    if !any {
        return None;
    }
    let mut v = int + frac;
    if i < b.len() && (b[i] == b'e' || b[i] == b'E') {
        i += 1;
        let eneg = i < b.len() && b[i] == b'-';
        if eneg || (i < b.len() && b[i] == b'+') {
            i += 1;
        }
        let mut e = 0i32;
        while i < b.len() && b[i].is_ascii_digit() {
            e = e * 10 + (b[i] - b'0') as i32;
            i += 1;
        }
        let mut k = 0;
        while k < e.min(308) {
            v = if eneg { v / 10.0 } else { v * 10.0 };
            k += 1;
        }
    }
    if i != b.len() {
        return None;
    }
    Some(if neg { -v } else { v })
}

pub fn serialize(j: &Json) -> String {
    let mut s = String::new();
    ser(j, &mut s);
    s
}

fn ser(j: &Json, out: &mut String) {
    match j {
        Json::Null => out.push_str("null"),
        Json::Bool(true) => out.push_str("true"),
        Json::Bool(false) => out.push_str("false"),
        Json::Num(n) => {
            // Integers print without decimal point. (fract()/abs() are std-only.)
            let as_int = *n as i64;
            if *n == as_int as f64 && (-9e15..9e15).contains(n) {
                let _ = write!(out, "{}", as_int);
            } else {
                let _ = write!(out, "{}", n);
            }
        }
        Json::Str(s) => ser_str(s, out),
        Json::Arr(a) => {
            out.push('[');
            for (i, v) in a.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser(v, out);
            }
            out.push(']');
        }
        Json::Obj(o) => {
            out.push('{');
            for (i, (k, v)) in o.iter().enumerate() {
                if i > 0 {
                    out.push(',');
                }
                ser_str(k, out);
                out.push(':');
                ser(v, out);
            }
            out.push('}');
        }
    }
}

fn ser_str(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                let _ = write!(out, "\\u{:04x}", c as u32);
            }
            c => out.push(c),
        }
    }
    out.push('"');
}
