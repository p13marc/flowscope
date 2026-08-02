//! Route gRPC calls and report their real outcome.
//!
//! The thing to take away: **a failed gRPC call still returns HTTP
//! 200.** The transport succeeded; the call did not. A proxy that
//! logs `:status` records every application failure as a success.
//! The real result is `grpc-status`, and it arrives in the trailers —
//! or, for a Trailers-Only response, in the stream's single `HEADERS`
//! block, which is a *head* rather than trailers.
//!
//! This matters only for **terminated** gRPC. gRPC over TLS routes by
//! SNI like any other connection and needs none of this.
//!
//! Usage:
//!     cargo run --features http2 --example grpc_routing

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{Http2Event, Http2Parser, PREFACE, grpc_call, grpc_status, grpc_status_of};

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let len = payload.len() as u32;
    v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    v.push(kind);
    v.push(flags);
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x40, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

const HEADERS: u8 = 0x1;
const DATA: u8 = 0x0;
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

/// A gRPC length-prefixed message: 1 compression flag + 4-byte BE
/// length + the payload.
fn lpm(body: &[u8]) -> Vec<u8> {
    let mut v = vec![0u8];
    v.extend_from_slice(&(body.len() as u32).to_be_bytes());
    v.extend_from_slice(body);
    v
}

fn main() {
    let mut p = Http2Parser::new();
    let mut wire = PREFACE.to_vec();

    // ── Stream 1: a unary call that succeeds ─────────────────────
    let mut req = vec![0x83, 0x87]; // :method POST, :scheme https
    req.extend(literal(":authority", "grpc.example"));
    req.extend(literal(":path", "/routeguide.RouteGuide/GetFeature"));
    req.extend(literal("content-type", "application/grpc+proto"));
    wire.extend(frame(HEADERS, END_HEADERS, 1, &req));
    wire.extend(frame(DATA, 0, 1, &lpm(b"request-message")));

    // ── Stream 3: a call that FAILS at the application level ─────
    let mut req3 = vec![0x83, 0x87];
    req3.extend(literal(":authority", "grpc.example"));
    req3.extend(literal(":path", "/routeguide.RouteGuide/ListFeatures"));
    req3.extend(literal("content-type", "application/grpc"));
    wire.extend(frame(HEADERS, END_HEADERS, 3, &req3));

    p.push(FlowSide::Initiator, &Bytes::from(wire));

    println!("── requests ──");
    while let Some(ev) = p.next_event() {
        if let Http2Event::Head(h) = ev {
            match grpc_call(&h) {
                Some(call) => println!(
                    "stream {}: gRPC {} :: {}  (authority {})",
                    h.stream_id,
                    call.service,
                    call.method,
                    h.authority().unwrap_or("?")
                ),
                None => println!("stream {}: not a gRPC stream", h.stream_id),
            }
        }
    }

    // ── responses ────────────────────────────────────────────────
    let mut resp = Vec::new();

    // Stream 1: 200, a message, then OK trailers.
    let mut ok_head = vec![0x88]; // :status 200
    ok_head.extend(literal("content-type", "application/grpc"));
    resp.extend(frame(HEADERS, END_HEADERS, 1, &ok_head));
    resp.extend(frame(DATA, 0, 1, &lpm(b"response-message")));
    let mut ok_trailers = Vec::new();
    ok_trailers.extend(literal("grpc-status", "0"));
    resp.extend(frame(HEADERS, END_HEADERS | END_STREAM, 1, &ok_trailers));

    // Stream 3: Trailers-Only — one HEADERS block, END_STREAM, no
    // body. HTTP says 200; gRPC says NOT_FOUND.
    let mut only = vec![0x88]; // :status 200
    only.extend(literal("content-type", "application/grpc"));
    only.extend(literal("grpc-status", "5"));
    only.extend(literal("grpc-message", "feature not found"));
    resp.extend(frame(HEADERS, END_HEADERS | END_STREAM, 3, &only));

    p.push(FlowSide::Responder, &Bytes::from(resp));

    println!("\n── outcomes ──");
    while let Some(ev) = p.next_event() {
        match ev {
            Http2Event::Head(h) => {
                let http_status = h.status().unwrap_or(0);
                // Trailers-Only puts the gRPC status in the head.
                match grpc_status_of(&h) {
                    Some(s) => println!(
                        "stream {}: HTTP {http_status}, gRPC {} ({}) — trailers-only",
                        h.stream_id,
                        s.code,
                        s.name().unwrap_or("?"),
                    ),
                    None => println!(
                        "stream {}: HTTP {http_status}, awaiting trailers",
                        h.stream_id
                    ),
                }
            }
            Http2Event::Trailers {
                stream_id, fields, ..
            } => {
                if let Some(s) = grpc_status(&fields) {
                    println!(
                        "stream {stream_id}: gRPC {} ({})",
                        s.code,
                        s.name().unwrap_or("?")
                    );
                }
            }
            _ => {}
        }
    }

    println!(
        "\nBoth streams returned HTTP 200. Only one of them succeeded —\n\
         which is why a gRPC access log must read grpc-status, not :status."
    );
}
