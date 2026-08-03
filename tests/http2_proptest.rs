//! Property tests for the HTTP/2 parser.
//!
//! The unit tests pin specific RFC behaviours; these pin the
//! invariants that must hold for *any* input, which is where a
//! stateful parser like this one tends to go wrong — HPACK carries
//! state across every field block on the connection, so a bug shows
//! up as corruption several frames later rather than as an immediate
//! failure.

#![cfg(feature = "http2")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{
    HeaderSensitivity, HpackEncoder, Http2Config, Http2Event, Http2Parser, PREFACE, write_headers,
};
use proptest::prelude::*;

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

fn drain(p: &mut Http2Parser) -> Vec<Http2Event> {
    let mut out = Vec::new();
    while let Some(ev) = p.next_event() {
        out.push(ev);
    }
    out
}

/// Reduce an event to a comparable shape, so two runs over the same
/// bytes can be checked for equality without depending on `Bytes`
/// identity.
fn shape(evs: &[Http2Event]) -> Vec<String> {
    evs.iter()
        .map(|e| match e {
            Http2Event::Head(h) => format!(
                "head {} {:?} {:?} {}",
                h.stream_id,
                h.method(),
                h.path(),
                h.end_stream
            ),
            Http2Event::Body {
                stream_id, data, ..
            } => format!("body {} {}", stream_id, data.len()),
            Http2Event::Trailers {
                stream_id, fields, ..
            } => format!("trailers {} {}", stream_id, fields.len()),
            Http2Event::End { stream_id, .. } => format!("end {stream_id}"),
            Http2Event::StreamReset { stream_id, .. } => format!("rst {stream_id}"),
            Http2Event::GoAway { last_stream_id, .. } => format!("goaway {last_stream_id}"),
            other => format!("{other:?}"),
        })
        .collect()
}

/// A plausible connection: a preface, then some well-formed frames on
/// odd stream IDs, with the payloads fuzzed.
fn connection() -> impl Strategy<Value = Vec<u8>> {
    proptest::collection::vec(
        (
            prop_oneof![Just(0x0u8), Just(0x1), Just(0x3), Just(0x4), Just(0x8)],
            any::<u8>(),
            1u32..8,
            proptest::collection::vec(any::<u8>(), 0..24),
        ),
        0..12,
    )
    .prop_map(|frames| {
        let mut wire = PREFACE.to_vec();
        for (kind, flags, stream, payload) in frames {
            wire.extend(frame(kind, flags, stream * 2 - 1, &payload));
        }
        wire
    })
}

proptest! {
    /// Framing must not depend on how the bytes are delivered. This
    /// is the property that catches state kept in the wrong place.
    #[test]
    fn split_feeds_produce_the_same_events(wire in connection(), split in 1usize..400) {
        let mut whole = Http2Parser::new();
        whole.push(FlowSide::Initiator, &Bytes::from(wire.clone()));
        let a = drain(&mut whole);

        let at = split.min(wire.len().saturating_sub(1)).max(1);
        let mut parts = Http2Parser::new();
        let mut b = Vec::new();
        for chunk in [&wire[..at], &wire[at..]] {
            parts.push(FlowSide::Initiator, &Bytes::copy_from_slice(chunk));
            b.extend(drain(&mut parts));
        }
        prop_assert_eq!(shape(&a), shape(&b));
        prop_assert_eq!(whole.is_failed(), parts.is_failed());
    }

    /// Stream tracking is bounded by config, whatever arrives.
    #[test]
    fn tracked_streams_never_exceed_the_cap(wire in connection()) {
        let mut p = Http2Parser::with_config(
            Http2Config::default().with_max_concurrent_streams(4),
        );
        p.push(FlowSide::Initiator, &Bytes::from(wire));
        while p.next_event().is_some() {
            prop_assert!(p.tracked_streams() <= 4);
        }
        prop_assert!(p.tracked_streams() <= 4);
    }

    /// A failed connection stays failed and inert. HPACK state is
    /// shared, so continuing after a decode failure would produce
    /// plausible-looking nonsense rather than an obvious error.
    #[test]
    fn failure_is_terminal(wire in connection(), extra in proptest::collection::vec(any::<u8>(), 0..64)) {
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from(wire));
        while p.next_event().is_some() {}
        if p.is_failed() {
            let before = p.error();
            prop_assert_eq!(p.push(FlowSide::Initiator, &Bytes::from(extra)), 0);
            prop_assert!(p.next_event().is_none());
            prop_assert_eq!(p.error(), before, "the first failure is the reported one");
        }
    }

    /// Buffered bytes stay under the cap on every push.
    #[test]
    fn buffering_is_bounded(chunks in proptest::collection::vec(
        proptest::collection::vec(any::<u8>(), 0..512), 0..12,
    )) {
        let cap = 8192;
        let mut p = Http2Parser::with_config(
            Http2Config::default().with_max_buffered_bytes(cap),
        );
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        for c in chunks {
            p.push(FlowSide::Initiator, &Bytes::from(c));
            while p.next_event().is_some() {}
            prop_assert!(p.buffered(FlowSide::Initiator) <= cap);
        }
    }

    /// Arbitrary bytes must never panic, with or without a preface.
    #[test]
    fn never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..512)) {
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        p.push(FlowSide::Initiator, &Bytes::copy_from_slice(&bytes));
        p.push(FlowSide::Responder, &Bytes::copy_from_slice(&bytes));
        while p.next_event().is_some() {}

        let mut bare = Http2Parser::new();
        bare.push(FlowSide::Initiator, &Bytes::from(bytes));
        while bare.next_event().is_some() {}
    }

    /// Whatever the encoder produces, a real parser reads back
    /// unchanged — across a *sequence* of blocks, which is the only
    /// way the shared dynamic table is exercised. A single-block
    /// round trip would pass even with the table wired up wrong.
    #[test]
    fn encoded_blocks_round_trip_through_the_parser(blocks in block_sequence()) {
        fn index_everything(_: &[u8], _: &[u8]) -> HeaderSensitivity {
            HeaderSensitivity::Indexable
        }
        let mut enc = HpackEncoder::new().with_sensitivity(index_everything);
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

        for (i, fields) in blocks.iter().enumerate() {
            let block = match enc.encode(fields) {
                Ok(b) => b,
                // A refusal is a legitimate outcome; what must never
                // happen is a block that encodes and then decodes to
                // something else.
                Err(_) => continue,
            };
            let stream = i as u32 * 2 + 1;
            let wire = write_headers(stream, &block, true, 16_384).unwrap();
            p.push(FlowSide::Initiator, &Bytes::from(wire));

            let mut got = None;
            while let Some(ev) = p.next_event() {
                if let Http2Event::Head(h) = ev {
                    got = Some(h);
                }
            }
            let head = got.expect("a head per block");
            prop_assert_eq!(&head.fields, fields, "block {} changed in flight", i);
        }
        prop_assert!(!p.is_failed(), "{:?}", p.error());
    }

    /// The encoder's table never exceeds what it was configured to
    /// hold, however many blocks go through it.
    #[test]
    fn the_encoder_table_stays_bounded(blocks in block_sequence()) {
        const CAP: usize = 512;
        let mut enc = HpackEncoder::new().with_max_table_size(CAP);
        for fields in &blocks {
            let _ = enc.encode(fields);
            prop_assert!(
                enc.table_size() <= CAP,
                "table grew to {}",
                enc.table_size()
            );
        }
    }
}

/// Field names biased toward the static table, so indexed and
/// literal representations both get exercised, with values that are
/// legal to send (no NUL/CR/LF, no edge whitespace).
fn field_pair() -> impl Strategy<Value = (Bytes, Bytes)> {
    let name = prop_oneof![
        Just(":method".to_string()),
        Just(":scheme".to_string()),
        Just(":authority".to_string()),
        Just("accept".to_string()),
        Just("user-agent".to_string()),
        "[a-z][a-z0-9-]{0,12}",
    ];
    let value = prop_oneof![
        Just("GET".to_string()),
        Just("https".to_string()),
        "[a-zA-Z0-9/._-]{0,40}",
    ];
    (name, value).prop_map(|(n, v)| {
        (
            Bytes::copy_from_slice(n.as_bytes()),
            Bytes::copy_from_slice(v.as_bytes()),
        )
    })
}

/// A run of field blocks on one connection. Pseudo-headers must
/// precede regular fields, so each block is sorted that way.
fn block_sequence() -> impl Strategy<Value = Vec<Vec<(Bytes, Bytes)>>> {
    proptest::collection::vec(
        proptest::collection::vec(field_pair(), 0..8).prop_map(|mut fields| {
            fields.sort_by_key(|(n, _)| !n.starts_with(b":"));
            fields
        }),
        0..6,
    )
}
