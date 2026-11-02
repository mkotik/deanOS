//! M7: HTTP/1.1 REST server on the async TCP API.
//!
//! Routes: GET /health · GET/POST /api/items · GET/PUT/DELETE /api/items/:id
//! Items live in RAM (stateless-by-design: PLAN.md §1).

use crate::http::json::{self, Json};
use crate::http::request::{Method, Parser, Poll as HPoll, Request};
use crate::http::response;
use crate::netglue::{self, tcp_accept, tcp_close, tcp_listen, tcp_read, tcp_write_all};
use crate::runtime::sleep::sleep_ms;
use crate::runtime::SingleCore;
use alloc::format;
use alloc::string::String;
use alloc::vec::Vec;
use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll};

static STORE: SingleCore<Vec<(u64, Json)>> = SingleCore::new(Vec::new());
static NEXT_ID: SingleCore<u64> = SingleCore::new(1);

const IDLE_TIMEOUT_MS: u64 = 30_000;

pub async fn serve(port: u16) {
    while !netglue::net_ready() {
        sleep_ms(20).await;
    }
    tcp_listen(port);
    crate::kprintln!("http : REST server on :{port} — M7 READY");
    loop {
        let h = tcp_accept(port).await;
        crate::runtime::executor::spawn(conn(h));
    }
}

/// Race a future against an idle deadline.
struct Timeout<F> {
    fut: F,
    sleep: crate::runtime::sleep::Sleep,
}

impl<F: Future + Unpin> Future for Timeout<F> {
    type Output = Option<F::Output>;
    fn poll(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        let me = self.get_mut();
        if let Poll::Ready(v) = Pin::new(&mut me.fut).poll(cx) {
            return Poll::Ready(Some(v));
        }
        if Pin::new(&mut me.sleep).poll(cx).is_ready() {
            return Poll::Ready(None); // timed out
        }
        Poll::Pending
    }
}

fn with_timeout<F: Future + Unpin>(fut: F, ms: u64) -> Timeout<F> {
    Timeout {
        fut,
        sleep: crate::runtime::sleep::sleep_ms(ms),
    }
}

async fn conn(h: usize) {
    let mut parser = Parser::new();
    let mut buf = alloc::boxed::Box::new([0u8; 2048]);
    'conn: loop {
        match parser.poll() {
            HPoll::Ready(req) => {
                let keep = req.keep_alive;
                let resp = route(&req);
                if !tcp_write_all(h, &resp).await || !keep {
                    break 'conn;
                }
            }
            HPoll::Incomplete => {
                match with_timeout(tcp_read(h, &mut buf[..]), IDLE_TIMEOUT_MS).await {
                    Some(0) | None => break 'conn, // EOF or idle timeout
                    Some(n) => parser.feed(&buf[..n]),
                }
            }
            HPoll::Bad => {
                let _ = tcp_write_all(h, &response::error(400, false)).await;
                break 'conn;
            }
        }
    }
    tcp_close(h);
}

fn route(req: &Request) -> Vec<u8> {
    let keep = req.keep_alive;
    let path = req.path.as_str();
    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();

    match (req.method, segs.as_slice()) {
        (Method::Get, ["health"]) => {
            let body = format!(
                "{{\"status\":\"ok\",\"os\":\"deanOS\",\"uptime_ms\":{}}}",
                crate::drivers::timer::now_ms()
            );
            response::json(200, &body, keep)
        }

        (Method::Get, ["api", "items"]) => {
            let store = STORE.0.borrow();
            let arr = Json::Arr(
                store
                    .iter()
                    .map(|(id, v)| wrap_item(*id, v.clone()))
                    .collect(),
            );
            response::json(200, &json::serialize(&arr), keep)
        }

        (Method::Post, ["api", "items"]) => {
            let Some(val) = json::parse(&req.body) else {
                return response::error(400, keep);
            };
            let mut id_g = NEXT_ID.0.borrow_mut();
            let id = *id_g;
            *id_g += 1;
            STORE.0.borrow_mut().push((id, val.clone()));
            response::json(201, &json::serialize(&wrap_item(id, val)), keep)
        }

        (Method::Get, ["api", "items", id]) => match find(id) {
            Some((id, v)) => response::json(200, &json::serialize(&wrap_item(id, v)), keep),
            None => response::error(404, keep),
        },

        (Method::Put, ["api", "items", id]) => {
            let Some(val) = json::parse(&req.body) else {
                return response::error(400, keep);
            };
            let Ok(idn) = id.parse::<u64>() else {
                return response::error(400, keep);
            };
            let mut store = STORE.0.borrow_mut();
            match store.iter_mut().find(|(i, _)| *i == idn) {
                Some(slot) => {
                    slot.1 = val.clone();
                    drop(store);
                    response::json(200, &json::serialize(&wrap_item(idn, val)), keep)
                }
                None => response::error(404, keep),
            }
        }

        (Method::Delete, ["api", "items", id]) => {
            let Ok(idn) = id.parse::<u64>() else {
                return response::error(400, keep);
            };
            let mut store = STORE.0.borrow_mut();
            let before = store.len();
            store.retain(|(i, _)| *i != idn);
            if store.len() < before {
                response::build(204, "application/json", b"", keep)
            } else {
                response::error(404, keep)
            }
        }

        (_, ["health" | "api", ..]) => response::error(405, keep),
        _ => response::error(404, keep),
    }
}

fn find(id: &str) -> Option<(u64, Json)> {
    let idn: u64 = id.parse().ok()?;
    STORE
        .0
        .borrow()
        .iter()
        .find(|(i, _)| *i == idn)
        .map(|(i, v)| (*i, v.clone()))
}

fn wrap_item(id: u64, v: Json) -> Json {
    Json::Obj(alloc::vec![
        (String::from("id"), Json::Num(id as f64)),
        (String::from("value"), v),
    ])
}
