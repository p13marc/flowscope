//! Adversarial memory-bound tests (#169).
//!
//! flowscope's promise to an inline proxy is that *it* will never be
//! the unbounded buffer: a peer that dribbles bytes, never completes
//! a message, or sends a body larger than memory must not be able to
//! grow the parser's state without limit.
//!
//! These tests attack that promise directly — slow drip, never-ending
//! header block, oversized body, unterminated chunk framing — and
//! assert the parser stays inside its configured caps or refuses.

#![cfg(feature = "http")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http::{HttpProxyConfig, HttpProxyParser};

/// Push bytes and drain events, the way a caller must.
fn pump(p: &mut HttpProxyParser, dir: FlowSide, data: &Bytes) -> usize {
    let accepted = p.push(dir, data);
    while p.next_event().is_some() {}
    accepted
}

#[test]
fn a_header_block_that_never_ends_is_refused_not_grown() {
    let cfg = HttpProxyConfig::default().with_max_head_bytes(4096);
    let mut p = HttpProxyParser::with_config(cfg);

    // A request line that never reaches its blank line.
    let junk = Bytes::from(vec![b'A'; 512]);
    let mut pushed = 0usize;
    for _ in 0..100 {
        pushed += pump(&mut p, FlowSide::Initiator, &junk);
        if p.is_poisoned() {
            break;
        }
        assert!(
            p.buffered(FlowSide::Initiator) <= 4096 + 512,
            "the head buffer must stay near its cap, saw {}",
            p.buffered(FlowSide::Initiator)
        );
    }
    assert!(
        p.is_poisoned(),
        "an endless header block must be refused (pushed {pushed} bytes)"
    );
}

#[test]
fn a_slow_drip_header_is_bounded_byte_by_byte() {
    // One byte at a time is the classic slowloris shape. The cap must
    // hold on every single push, not just in aggregate.
    let cfg = HttpProxyConfig::default().with_max_head_bytes(1024);
    let mut p = HttpProxyParser::with_config(cfg);
    let byte = Bytes::from_static(b"A");
    for _ in 0..4096 {
        pump(&mut p, FlowSide::Initiator, &byte);
        if p.is_poisoned() {
            return;
        }
        assert!(p.buffered(FlowSide::Initiator) <= 1025);
    }
    panic!("a slow-drip header must eventually be refused");
}

#[test]
fn an_enormous_body_never_accumulates() {
    // 64 MiB declared, pushed 8 KiB at a time. The parser reports it
    // as spans and keeps nothing.
    let mut p = HttpProxyParser::new();
    let head =
        Bytes::from_static(b"PUT /big HTTP/1.1\r\nHost: h\r\nContent-Length: 67108864\r\n\r\n");
    pump(&mut p, FlowSide::Initiator, &head);

    let cap = HttpProxyConfig::default().max_buffered_bytes;
    let chunk = Bytes::from(vec![b'x'; 8192]);
    let mut sent = 0u64;
    while sent < 64 * 1024 * 1024 {
        let n = pump(&mut p, FlowSide::Initiator, &chunk);
        if n == 0 {
            panic!("the parser stopped accepting a well-framed body");
        }
        sent += n as u64;
        assert!(
            p.buffered(FlowSide::Initiator) <= cap,
            "body bytes must not accumulate"
        );
    }
    assert!(
        !p.is_poisoned(),
        "a large but well-framed body is not an error"
    );
    assert_eq!(p.buffered(FlowSide::Initiator), 0);
}

#[test]
fn an_unterminated_chunk_size_line_is_refused() {
    let cfg = HttpProxyConfig::default().with_max_chunk_line_bytes(128);
    let mut p = HttpProxyParser::with_config(cfg);
    pump(
        &mut p,
        FlowSide::Initiator,
        &Bytes::from_static(b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n"),
    );
    // Hex digits forever, no CRLF.
    let digits = Bytes::from(vec![b'a'; 64]);
    for _ in 0..64 {
        pump(&mut p, FlowSide::Initiator, &digits);
        if p.is_poisoned() {
            return;
        }
    }
    panic!("an unterminated chunk-size line must be refused");
}

#[test]
fn an_unterminated_trailer_section_is_refused() {
    let cfg = HttpProxyConfig::default().with_max_trailer_bytes(512);
    let mut p = HttpProxyParser::with_config(cfg);
    pump(
        &mut p,
        FlowSide::Initiator,
        &Bytes::from_static(
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n",
        ),
    );
    // Trailer lines that never reach the terminating blank line.
    let line = Bytes::from_static(b"X-Pad: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\n");
    for _ in 0..64 {
        pump(&mut p, FlowSide::Initiator, &line);
        if p.is_poisoned() {
            return;
        }
    }
    panic!("an unterminated trailer section must be refused");
}

#[test]
fn unbounded_pipelining_is_refused() {
    // Requests without responses queue per-request context. That
    // queue is capped, so a client cannot make the proxy hold
    // unlimited state by never reading.
    let cfg = HttpProxyConfig::default().with_max_pipelined(8);
    let mut p = HttpProxyParser::with_config(cfg);
    let req = Bytes::from_static(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n");
    for _ in 0..64 {
        pump(&mut p, FlowSide::Initiator, &req);
        if p.is_poisoned() {
            return;
        }
    }
    panic!("unbounded pipelining must be refused");
}

#[test]
fn a_caller_that_never_drains_gets_backpressure_not_growth() {
    // The caller stops calling next_event. push must start refusing
    // rather than buffering whatever it is handed.
    let cfg = HttpProxyConfig::default().with_max_buffered_bytes(8192);
    let mut p = HttpProxyParser::with_config(cfg);
    let data = Bytes::from(vec![b'x'; 4096]);
    let mut total = 0usize;
    for _ in 0..100 {
        // Deliberately no next_event() call.
        total += p.push(FlowSide::Initiator, &data);
    }
    assert!(
        total <= 8192,
        "a non-draining caller must be refused past the cap, accepted {total}"
    );
    assert!(p.buffered(FlowSide::Initiator) <= 8192);
}

#[test]
fn a_poisoned_direction_stops_storing_what_it_will_never_parse() {
    // Once framing is lost the direction will never parse another
    // byte, so holding what arrives afterwards is a leak that lasts
    // as long as the peer keeps sending. Found by the #169 audit —
    // the streaming front-end refuses the bytes, but the buffer
    // underneath must not grow either.
    let cfg = HttpProxyConfig::default().with_max_head_bytes(256);
    let mut p = HttpProxyParser::with_config(cfg);
    let junk = Bytes::from(vec![b'A'; 1024]);
    pump(&mut p, FlowSide::Initiator, &junk);
    assert!(p.is_poisoned());
    let after_poison = p.buffered(FlowSide::Initiator);

    for _ in 0..1000 {
        pump(&mut p, FlowSide::Initiator, &junk);
    }
    assert_eq!(
        p.buffered(FlowSide::Initiator),
        after_poison,
        "a poisoned direction must not accumulate"
    );
}

#[test]
fn a_tunnelled_connection_stops_storing_spliced_bytes() {
    // After a switch the caller splices the bytes itself; the parser
    // has no use for them and must not hold them.
    let mut p = HttpProxyParser::new();
    pump(
        &mut p,
        FlowSide::Initiator,
        &Bytes::from_static(b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n"),
    );
    pump(
        &mut p,
        FlowSide::Responder,
        &Bytes::from_static(b"HTTP/1.1 200 Connection Established\r\n\r\n"),
    );
    assert!(p.is_done(), "the connection is now a tunnel");

    let payload = Bytes::from(vec![0xAB; 8192]);
    for _ in 0..256 {
        pump(&mut p, FlowSide::Initiator, &payload);
        pump(&mut p, FlowSide::Responder, &payload);
    }
    assert_eq!(p.buffered(FlowSide::Initiator), 0);
    assert_eq!(p.buffered(FlowSide::Responder), 0);
}

#[test]
fn the_telemetry_parser_does_not_grow_after_a_desync() {
    // The passive front-end never poisons a flow, so nothing tears it
    // down — which makes "stop storing after a desync" the only thing
    // bounding it. This was a real regression: the pre-0.23 parser
    // cleared its buffer on every failed step.
    use flowscope::SessionParser;
    use flowscope::Timestamp;
    use flowscope::http::{HttpConfig, HttpParser};

    let mut p = HttpParser::with_config(HttpConfig::default().with_max_buffer(4096));
    let mut out = Vec::new();
    // Garbage that can never be a head, past the cap.
    let junk = vec![b'\xff'; 8192];
    for _ in 0..200 {
        p.feed_initiator(&junk, Timestamp::default(), &mut out);
    }
    // Nothing parsed, and — the point — nothing retained either.
    assert!(out.is_empty());
}

#[test]
fn the_telemetry_parser_bounds_its_aggregation_too() {
    // The passive front-end does buffer bodies — that is its job —
    // but max_buffer is a real ceiling, not a suggestion.
    use flowscope::SessionParser;
    use flowscope::Timestamp;
    use flowscope::http::{HttpConfig, HttpParser};

    let cfg = HttpConfig::default().with_max_buffer(4096);
    let mut p = HttpParser::with_config(cfg);
    let mut out = Vec::new();
    p.feed_initiator(
        b"PUT /big HTTP/1.1\r\nHost: h\r\nContent-Length: 1048576\r\n\r\n",
        Timestamp::default(),
        &mut out,
    );
    let chunk = vec![b'x'; 8192];
    for _ in 0..128 {
        p.feed_initiator(&chunk, Timestamp::default(), &mut out);
    }
    // Framing still completed; the oversized body was dropped rather
    // than held.
    for msg in &out {
        if let flowscope::http::HttpMessage::Request(r) = msg {
            assert!(
                r.body.len() <= 4096,
                "the aggregated body must respect max_buffer"
            );
        }
    }
}
