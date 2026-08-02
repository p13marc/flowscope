//! End-to-end HTTP/2 stream routing (#170).
//!
//! Drives a realistic exchange — a Huffman-coded request, an
//! interleaved second stream, a response with trailers — through
//! [`Http2Parser`] and checks the routing keys come out. The HPACK
//! encodings here are the RFC 7541 Appendix C vectors, so the bytes
//! are what a real encoder emits rather than what a decoder happens
//! to accept.

#![cfg(feature = "http2")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{Http2Config, Http2Error, Http2Event, Http2Parser, PREFACE};

/// Frame flag bits used here.
const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

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

/// Literal header field with incremental indexing, uncompressed.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x40, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

fn drain(p: &mut Http2Parser) -> Vec<Http2Event> {
    let mut out = Vec::new();
    while let Some(ev) = p.next_event() {
        out.push(ev);
    }
    out
}

fn heads(evs: &[Http2Event]) -> Vec<(u32, Option<String>, Option<String>)> {
    evs.iter()
        .filter_map(|e| match e {
            Http2Event::Head(h) => Some((
                h.stream_id,
                h.authority().map(str::to_owned),
                h.path().map(str::to_owned),
            )),
            _ => None,
        })
        .collect()
}

#[test]
fn a_huffman_coded_request_yields_its_routing_key() {
    // RFC 7541 C.4.1: :method GET, :scheme http, :path /,
    // :authority www.example.com — with the authority Huffman-coded,
    // which is what a real client sends.
    let block = [
        0x82, 0x86, 0x84, 0x41, 0x8c, 0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90,
        0xf4, 0xff,
    ];
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    p.push(
        FlowSide::Initiator,
        &Bytes::from(frame(0x1, END_HEADERS | END_STREAM, 1, &block)),
    );
    let evs = drain(&mut p);
    assert_eq!(
        heads(&evs),
        vec![(1, Some("www.example.com".into()), Some("/".into()))]
    );
    assert!(
        evs.iter()
            .any(|e| matches!(e, Http2Event::End { stream_id: 1, .. }))
    );
}

#[test]
fn a_full_exchange_carries_head_body_and_trailers() {
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

    // Request: POST /v1/echo to api.example.
    let mut req = vec![0x83, 0x87]; // :method POST, :scheme https
    req.extend(literal(":authority", "api.example"));
    req.extend(literal(":path", "/v1/echo"));
    req.extend(literal("content-type", "application/grpc"));
    let mut wire = frame(0x1, END_HEADERS, 1, &req);
    wire.extend(frame(0x0, END_STREAM, 1, b"request-payload"));
    p.push(FlowSide::Initiator, &Bytes::from(wire));
    let client_events = drain(&mut p);

    assert_eq!(
        heads(&client_events),
        vec![(1, Some("api.example".into()), Some("/v1/echo".into()))]
    );
    let body: Vec<u8> = client_events
        .iter()
        .filter_map(|e| match e {
            Http2Event::Body { data, .. } => Some(data.to_vec()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .concat();
    assert_eq!(body, b"request-payload");

    // Response: 200, a data frame, then trailers.
    let mut resp = frame(0x1, END_HEADERS, 1, &[0x88]); // :status 200
    resp.extend(frame(0x0, 0, 1, b"response-payload"));
    let mut trailers = Vec::new();
    trailers.extend(literal("grpc-status", "0"));
    resp.extend(frame(0x1, END_HEADERS | END_STREAM, 1, &trailers));
    p.push(FlowSide::Responder, &Bytes::from(resp));
    let server_events = drain(&mut p);

    let status = server_events.iter().find_map(|e| match e {
        Http2Event::Head(h) => h.status(),
        _ => None,
    });
    assert_eq!(status, Some(200));

    let trailer_fields = server_events
        .iter()
        .find_map(|e| match e {
            Http2Event::Trailers { fields, .. } => Some(fields.clone()),
            _ => None,
        })
        .expect("trailers must be reported");
    assert_eq!(trailer_fields[0].0.as_ref(), b"grpc-status");
}

#[test]
fn concurrent_streams_keep_their_routing_keys_apart() {
    // Two requests whose HEADERS and DATA interleave — the normal h2
    // case, and the reason per-stream state exists.
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

    let mut a = vec![0x82, 0x87];
    a.extend(literal(":authority", "alpha.example"));
    a.extend(literal(":path", "/a"));
    let mut b = vec![0x82, 0x87];
    b.extend(literal(":authority", "beta.example"));
    b.extend(literal(":path", "/b"));

    let mut wire = frame(0x1, END_HEADERS, 1, &a);
    wire.extend(frame(0x1, END_HEADERS, 3, &b));
    wire.extend(frame(0x0, 0, 3, b"beta-data"));
    wire.extend(frame(0x0, 0, 1, b"alpha-data"));
    wire.extend(frame(0x0, END_STREAM, 1, b""));
    p.push(FlowSide::Initiator, &Bytes::from(wire));
    let evs = drain(&mut p);

    let mut seen = heads(&evs);
    seen.sort_by_key(|(id, _, _)| *id);
    assert_eq!(
        seen,
        vec![
            (1, Some("alpha.example".into()), Some("/a".into())),
            (3, Some("beta.example".into()), Some("/b".into())),
        ]
    );

    let data_for = |id: u32| -> Vec<u8> {
        evs.iter()
            .filter_map(|e| match e {
                Http2Event::Body {
                    stream_id, data, ..
                } if *stream_id == id => Some(data.to_vec()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .concat()
    };
    assert_eq!(data_for(1), b"alpha-data");
    assert_eq!(data_for(3), b"beta-data");
}

#[test]
fn the_dynamic_table_carries_across_streams() {
    // The property that makes HPACK unskippable: stream 3 references
    // a table entry that stream 1's block created. A parser that
    // ignored blocks it did not care about would decode this wrong.
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

    let mut first = vec![0x82, 0x87];
    first.extend(literal(":authority", "shared.example"));
    // Index 62 is the first dynamic entry — the authority just added.
    let second = vec![0x82, 0x87, 0xbe];

    let mut wire = frame(0x1, END_HEADERS, 1, &first);
    wire.extend(frame(0x1, END_HEADERS, 3, &second));
    p.push(FlowSide::Initiator, &Bytes::from(wire));
    let evs = drain(&mut p);

    let authorities: Vec<Option<String>> = heads(&evs).into_iter().map(|(_, a, _)| a).collect();
    assert_eq!(
        authorities,
        vec![Some("shared.example".into()), Some("shared.example".into())],
        "stream 3 must resolve the entry stream 1 inserted"
    );
}

#[test]
fn framing_does_not_depend_on_how_bytes_arrive() {
    let mut block = vec![0x82, 0x87];
    block.extend(literal(":authority", "drip.example"));
    block.extend(literal(":path", "/x"));
    let mut wire = PREFACE.to_vec();
    wire.extend(frame(0x1, END_HEADERS, 1, &block));
    wire.extend(frame(0x0, END_STREAM, 1, b"payload"));

    let mut whole = Http2Parser::new();
    whole.push(FlowSide::Initiator, &Bytes::from(wire.clone()));
    let a = drain(&mut whole);

    let mut drip = Http2Parser::new();
    let mut b = Vec::new();
    for byte in &wire {
        drip.push(FlowSide::Initiator, &Bytes::copy_from_slice(&[*byte]));
        b.extend(drain(&mut drip));
    }
    assert_eq!(heads(&a), heads(&b));
    assert!(!heads(&a).is_empty());
}

#[test]
fn a_connection_that_is_not_http2_fails_immediately() {
    let mut p = Http2Parser::new();
    p.push(
        FlowSide::Initiator,
        &Bytes::from_static(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n"),
    );
    assert_eq!(p.error(), Some(Http2Error::BadPreface));
    assert_eq!(
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE)),
        0,
        "a failed connection accepts nothing further"
    );
}

#[test]
fn stream_state_is_bounded() {
    // The peer decides how many streams to open, so the parser must
    // decide how many it will track.
    let mut p = Http2Parser::with_config(Http2Config::default().with_max_concurrent_streams(16));
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    for i in 0..128u32 {
        let id = i * 2 + 1;
        p.push(
            FlowSide::Initiator,
            &Bytes::from(frame(0x1, END_HEADERS, id, &[0x82])),
        );
        drain(&mut p);
        assert!(
            p.tracked_streams() <= 16,
            "tracked {} streams",
            p.tracked_streams()
        );
        if p.is_failed() {
            assert_eq!(p.error(), Some(Http2Error::TooManyStreams));
            return;
        }
    }
    panic!("unbounded stream tracking must be refused");
}
