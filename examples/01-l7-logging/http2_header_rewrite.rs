//! Read an HTTP/2 request, change a header, and put it back on the
//! wire — the loop a terminating h2 proxy runs.
//!
//! This is the one thing HTTP/1 gets for free and HTTP/2 does not.
//! An HTTP/1 proxy that rewrites a header re-serializes text. HTTP/2
//! header fields are a *stateful compressed encoding*: the bytes on
//! the wire depend on every field block that came before them on the
//! connection, so the moment you change anything you have to
//! re-encode.
//!
//! Three things this demonstrates, each printed as it happens:
//!
//! 1. **The table is shared, so compression compounds.** The first
//!    rewritten block is bigger than what arrived — it gained a
//!    header, against an empty table. From the second onward the
//!    repeated fields are one-byte indices and the block shrinks,
//!    but only because the encoder's dynamic table and the peer's
//!    decoder stayed identical.
//! 2. **Credentials are never indexed.** `authorization` is re-sent
//!    in full every time. That costs bytes on purpose: an indexed
//!    repeat proves a value recurred, which is the CRIME-family
//!    oracle.
//! 3. **A block is not a header.** `write_headers` frames it, and
//!    splits into `CONTINUATION` when the peer's `max_frame_size`
//!    requires — getting that wrong is a connection-fatal error at
//!    the far end, several frames from the mistake.
//!
//! Usage:
//!     cargo run --features http2 --example http2_header_rewrite

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{HpackEncoder, Http2Event, Http2Parser, PREFACE, StreamHead, write_headers};

fn field(name: &str, value: &str) -> (Bytes, Bytes) {
    (
        Bytes::copy_from_slice(name.as_bytes()),
        Bytes::copy_from_slice(value.as_bytes()),
    )
}

/// Build a client request block with a real encoder, so the input to
/// this example is itself valid HTTP/2 rather than hand-rolled bytes.
fn client_request(enc: &mut HpackEncoder, path: &str, token: &str) -> Vec<u8> {
    let fields = vec![
        field(":method", "GET"),
        field(":scheme", "https"),
        field(":authority", "api.example"),
        field(":path", path),
        field("user-agent", "demo-client/1.0"),
        field("authorization", token),
    ];
    enc.encode(&fields).expect("a valid request")
}

/// The rewrite itself: drop one hop-by-hop-ish header, add a
/// forwarding header, leave everything else alone.
fn rewrite(head: &StreamHead) -> Vec<(Bytes, Bytes)> {
    let mut out: Vec<(Bytes, Bytes)> = head
        .fields
        .iter()
        .filter(|(n, _)| n.as_ref() != b"user-agent")
        .cloned()
        .collect();
    out.push(field("x-forwarded-for", "203.0.113.7"));
    out
}

fn main() {
    // Two encoders and two parsers: one pair per direction of the
    // proxy. The client-facing decoder and the upstream-facing
    // encoder are different HPACK contexts and must never be mixed.
    let mut client_enc = HpackEncoder::new();
    let mut inbound = Http2Parser::new();
    let mut upstream_enc = HpackEncoder::new();
    let mut upstream = Http2Parser::new();

    inbound.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    upstream.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

    let requests = [
        ("/v1/orders", "Bearer aaaaaaaaaaaaaaaaaaaa"),
        ("/v1/orders?page=2", "Bearer aaaaaaaaaaaaaaaaaaaa"),
        ("/v1/customers", "Bearer aaaaaaaaaaaaaaaaaaaa"),
    ];

    for (i, (path, token)) in requests.iter().enumerate() {
        let stream = i as u32 * 2 + 1;

        // ── what arrives from the client ─────────────────────────
        let block = client_request(&mut client_enc, path, token);
        let wire = write_headers(stream, &block, true, 16_384).expect("framable");
        inbound.push(FlowSide::Initiator, &Bytes::from(wire));

        let Some(Http2Event::Head(head)) = inbound.next_event() else {
            panic!("expected a head on stream {stream}");
        };
        while inbound.next_event().is_some() {}

        // ── rewrite and re-emit ──────────────────────────────────
        let rewritten = rewrite(&head);
        let out_block = upstream_enc
            .encode(&rewritten)
            .expect("the rewrite is still a legal header list");
        // The peer's advertised frame size; here we just ask the
        // upstream parser what it will accept.
        let max_frame = upstream.max_frame_size(FlowSide::Initiator);
        let out_wire = write_headers(stream, &out_block, true, max_frame).expect("framable");

        println!(
            "stream {stream}  {}  in {:>3} B  out {:>3} B   encoder table {:>3} B",
            head.path().unwrap_or("?"),
            block.len(),
            out_block.len(),
            upstream_enc.table_size(),
        );

        // ── prove it is real HTTP/2 by reading it back ───────────
        upstream.push(FlowSide::Initiator, &Bytes::from(out_wire));
        let Some(Http2Event::Head(seen)) = upstream.next_event() else {
            panic!("the upstream parser rejected our own output");
        };
        while upstream.next_event().is_some() {}

        assert_eq!(seen.fields, rewritten, "what we sent is what arrives");
        assert!(seen.field("user-agent").is_none(), "the header was dropped");
        assert_eq!(seen.field("x-forwarded-for"), Some(&b"203.0.113.7"[..]));
    }

    println!(
        "\nThe first block out is *larger* than the one that came in — it\n\
         gained a header, and its fields are new to a fresh table. From\n\
         the second onward they are one-byte indices, so the block\n\
         shrinks even though the request did not. That only works\n\
         because the encoder's table is a *model of the peer's decoder*:\n\
         build a block and then drop it instead of sending it, and the\n\
         two go permanently out of step."
    );

    // The authorization header is re-sent in full every time, so its
    // bytes never stop counting. That is the point.
    let auth_len = requests[0].1.len();
    println!(
        "\n`authorization` ({auth_len} B) is never indexed, so it costs\n\
         those bytes on every request rather than one byte after the\n\
         first. An indexed repeat would prove the value recurred, which\n\
         is exactly the signal a CRIME-family attack reads — and it\n\
         matters most when one upstream connection is shared across\n\
         clients. `HpackEncoder::with_sensitivity` overrides it if your\n\
         deployment does not have that shape."
    );

    // ── the framing rule that bites people ───────────────────────
    let big: Vec<(Bytes, Bytes)> = std::iter::once(field(":method", "GET"))
        .chain((0..80).map(|i| field(&format!("x-pad-{i}"), &"v".repeat(300))))
        .collect();
    let block = HpackEncoder::new()
        .with_max_block_bytes(1024 * 1024)
        .encode(&big)
        .expect("encodable");
    let frames = write_headers(1, &block, true, 16_384).expect("framable");

    // Walk the frame headers: 3-byte length, then the type octet.
    let mut kinds = Vec::new();
    let mut at = 0usize;
    while at + 9 <= frames.len() {
        let len =
            (frames[at] as usize) << 16 | (frames[at + 1] as usize) << 8 | frames[at + 2] as usize;
        kinds.push(frames[at + 3]);
        at += 9 + len;
    }
    let continuations = kinds.iter().filter(|&&k| k == 0x9).count();
    println!(
        "\nA {} B block does not fit one 16 KiB frame: write_headers\n\
         split it into 1 HEADERS + {continuations} CONTINUATION. Sending it as a\n\
         single frame instead is a FRAME_SIZE_ERROR at the far end —\n\
         fatal to the whole connection, and reported nowhere near the\n\
         cause.",
        block.len(),
    );
}
