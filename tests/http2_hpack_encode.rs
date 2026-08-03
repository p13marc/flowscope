//! HPACK encoding end to end (#197).
//!
//! The unit tests pin exact RFC bytes. This pins the property that
//! actually closes the issue: what the encoder produces, framed by
//! `write_headers`, is bytes a real HTTP/2 parser reads back as the
//! headers you started with.
//!
//! `decode(encode(x)) == x` against our own decoder is a necessary
//! oracle but not a sufficient one — two symmetric bugs cancel. Going
//! through `Http2Parser`, which adds framing, CONTINUATION
//! reassembly, and the per-direction table, is the closest thing to
//! an independent check the crate can make of itself.

#![cfg(feature = "http2")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{
    HeaderSensitivity, HpackEncoder, Http2Event, Http2Parser, PREFACE, StreamHead, write_headers,
};

fn f(pairs: &[(&str, &str)]) -> Vec<(Bytes, Bytes)> {
    pairs
        .iter()
        .map(|(n, v)| {
            (
                Bytes::copy_from_slice(n.as_bytes()),
                Bytes::copy_from_slice(v.as_bytes()),
            )
        })
        .collect()
}

/// A parser with the preface already consumed.
fn parser() -> Http2Parser {
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    p
}

fn heads(p: &mut Http2Parser) -> Vec<StreamHead> {
    let mut out = Vec::new();
    while let Some(ev) = p.next_event() {
        if let Http2Event::Head(h) = ev {
            out.push(h);
        }
    }
    out
}

#[test]
fn an_encoded_block_reads_back_as_the_headers_it_came_from() {
    let mut enc = HpackEncoder::new();
    let fields = f(&[
        (":method", "POST"),
        (":scheme", "https"),
        (":authority", "api.example"),
        (":path", "/v1/orders"),
        ("content-type", "application/grpc"),
        ("user-agent", "flowscope/0.23"),
    ]);

    let block = enc.encode(&fields).expect("encodable");
    let wire = write_headers(1, &block, true, 16_384).expect("framable");

    let mut p = parser();
    p.push(FlowSide::Initiator, &Bytes::from(wire));
    let heads = heads(&mut p);

    assert_eq!(heads.len(), 1, "{:?}", p.error());
    assert_eq!(heads[0].fields, fields, "every field survives, in order");
    assert_eq!(heads[0].method(), Some("POST"));
    assert_eq!(heads[0].authority(), Some("api.example"));
    assert!(heads[0].end_stream);
}

/// A block larger than one frame has to be split, and the split must
/// be invisible on the far side.
#[test]
fn a_block_split_across_continuation_frames_reassembles() {
    let mut enc = HpackEncoder::new().with_max_block_bytes(1024 * 1024);
    let long = "v".repeat(300);
    let mut pairs: Vec<(String, String)> = vec![
        (":method".into(), "GET".into()),
        (":scheme".into(), "https".into()),
        (":authority".into(), "big.example".into()),
        (":path".into(), "/".into()),
    ];
    for i in 0..100 {
        pairs.push((format!("x-pad-{i}"), long.clone()));
    }
    let fields: Vec<(Bytes, Bytes)> = pairs
        .iter()
        .map(|(n, v)| {
            (
                Bytes::copy_from_slice(n.as_bytes()),
                Bytes::copy_from_slice(v.as_bytes()),
            )
        })
        .collect();

    let block = enc.encode(&fields).expect("encodable");
    assert!(block.len() > 16_384, "the block must actually need a split");

    let wire = write_headers(1, &block, false, 16_384).expect("framable");
    let mut p = Http2Parser::with_config(
        flowscope::http2::Http2Config::default().with_max_header_block_bytes(1024 * 1024),
    );
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    p.push(FlowSide::Initiator, &Bytes::from(wire));

    let heads = heads(&mut p);
    assert_eq!(heads.len(), 1, "{:?}", p.error());
    assert_eq!(heads[0].fields, fields);
}

/// The property the whole `DynamicTable` extraction exists to
/// guarantee: blocks two and three only decode correctly if the
/// encoder's table and the parser's decoder table stayed identical.
#[test]
fn sequential_blocks_share_the_dynamic_table() {
    fn index_everything(_: &[u8], _: &[u8]) -> HeaderSensitivity {
        HeaderSensitivity::Indexable
    }
    let mut enc = HpackEncoder::new().with_sensitivity(index_everything);
    let mut p = parser();

    let blocks = [
        f(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a.example"),
            (":path", "/one"),
        ]),
        f(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a.example"),
            (":path", "/two"),
            ("x-trace", "abc"),
        ]),
        f(&[
            (":method", "GET"),
            (":scheme", "https"),
            (":authority", "a.example"),
            (":path", "/two"),
            ("x-trace", "abc"),
        ]),
    ];

    let mut sizes = Vec::new();
    for (i, fields) in blocks.iter().enumerate() {
        let block = enc.encode(fields).expect("encodable");
        sizes.push(block.len());
        let wire = write_headers(i as u32 * 2 + 1, &block, true, 16_384).unwrap();
        p.push(FlowSide::Initiator, &Bytes::from(wire));
        let got = heads(&mut p);
        assert_eq!(got.len(), 1, "block {i}: {:?}", p.error());
        assert_eq!(&got[0].fields, fields, "block {i} round-trips");
    }

    // The third block repeats the second exactly, so by then every
    // field is a one-byte index. If the tables had diverged this
    // would either be larger or fail to decode.
    assert!(
        sizes[2] < sizes[1],
        "a repeated block must compress: {sizes:?}"
    );
    assert_eq!(sizes[2], blocks[2].len(), "one index byte per field");
}

/// The peer's `SETTINGS_HEADER_TABLE_SIZE` arrives as an event, and
/// applying it mid-connection must not desync the two tables.
#[test]
fn a_settings_change_mid_connection_keeps_both_sides_in_step() {
    let mut enc = HpackEncoder::new();
    let mut p = parser();

    let first = enc.encode(&f(&[(":method", "GET")])).unwrap();
    p.push(
        FlowSide::Initiator,
        &Bytes::from(write_headers(1, &first, true, 16_384).unwrap()),
    );
    assert_eq!(heads(&mut p).len(), 1);

    // The server advertises a smaller table. SETTINGS from the
    // responder govern what the responder receives, so they apply to
    // the encoder writing toward the server.
    let mut settings = Vec::new();
    settings.extend_from_slice(&[0, 0, 6, 0x4, 0, 0, 0, 0, 0]); // SETTINGS, len 6
    settings.extend_from_slice(&[0x00, 0x01, 0, 0, 0x01, 0x00]); // table size = 256
    p.push(FlowSide::Responder, &Bytes::from(settings));

    let reported = std::iter::from_fn(|| p.next_event()).find_map(|e| match e {
        Http2Event::Settings {
            dir,
            header_table_size,
            ..
        } => Some((dir, header_table_size)),
        _ => None,
    });
    assert_eq!(
        reported,
        Some((FlowSide::Responder, Some(256))),
        "the parser must surface the peer's table size"
    );
    enc.set_peer_max_table_size(256);

    // The next block carries the size update and still decodes.
    let fields = f(&[(":method", "GET"), (":authority", "a.example")]);
    let second = enc.encode(&fields).unwrap();
    p.push(
        FlowSide::Initiator,
        &Bytes::from(write_headers(3, &second, true, 16_384).unwrap()),
    );
    let got = heads(&mut p);
    assert_eq!(got.len(), 1, "{:?}", p.error());
    assert_eq!(got[0].fields, fields);
    assert!(
        enc.table_size() <= 256,
        "the encoder must respect the peer's limit"
    );
}

/// A field the encoder refuses is one the peer would have rejected —
/// and refusing must leave the connection usable.
#[test]
fn a_refused_field_does_not_poison_the_connection() {
    let mut enc = HpackEncoder::new();
    let mut p = parser();

    assert!(
        enc.encode(&f(&[("x-ok", "v\r\nSmuggled: 1")])).is_err(),
        "CRLF in a value is the h2->h1 downgrade smuggling primitive"
    );

    let fields = f(&[(":method", "GET"), (":path", "/after")]);
    let block = enc.encode(&fields).expect("the encoder is still usable");
    p.push(
        FlowSide::Initiator,
        &Bytes::from(write_headers(1, &block, true, 16_384).unwrap()),
    );
    let got = heads(&mut p);
    assert_eq!(got.len(), 1, "{:?}", p.error());
    assert_eq!(got[0].fields, fields);
}
