#![no_main]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{
    HeaderSensitivity, HpackEncoder, Http2Event, Http2Parser, PREFACE, write_headers,
};
use libfuzzer_sys::fuzz_target;

/// The encoder's dynamic table is a model of the peer's decoder, and
/// a divergence between them shows up several blocks later as
/// plausible-looking nonsense rather than as an error. So the
/// invariant to fuzz is not "does not panic" but **what goes in comes
/// out** — across a sequence of blocks, since a single block never
/// exercises the shared table.
///
/// Derives field blocks from arbitrary bytes, which reaches the
/// eviction and size-update state space far past what the proptest
/// strategies cover.
fn index_everything(_: &[u8], _: &[u8]) -> HeaderSensitivity {
    HeaderSensitivity::Indexable
}

/// Carve `data` into blocks of fields. Names are forced lowercase and
/// values stripped of the octets HTTP/2 forbids, so the encoder's
/// validation is not the thing under test here.
fn blocks(data: &[u8]) -> Vec<Vec<(Bytes, Bytes)>> {
    let mut out = Vec::new();
    let mut block = Vec::new();
    let mut i = 0usize;
    while i + 2 <= data.len() {
        let nlen = (data[i] % 16) as usize + 1;
        let vlen = (data[i + 1] % 32) as usize;
        i += 2;
        if i + nlen + vlen > data.len() {
            break;
        }
        let name: Vec<u8> = data[i..i + nlen]
            .iter()
            .map(|b| {
                let c = b.to_ascii_lowercase();
                if c.is_ascii_lowercase() || c.is_ascii_digit() {
                    c
                } else {
                    b'x'
                }
            })
            .collect();
        i += nlen;
        let value: Vec<u8> = data[i..i + vlen]
            .iter()
            .map(|b| match b {
                0 | b'\r' | b'\n' | b' ' | b'\t' => b'.',
                other => *other,
            })
            .collect();
        i += vlen;

        block.push((Bytes::from(name), Bytes::from(value)));
        // A zero-length value closes the block, so block boundaries
        // are input-controlled too.
        if vlen == 0 || block.len() >= 24 {
            out.push(std::mem::take(&mut block));
        }
    }
    if !block.is_empty() {
        out.push(block);
    }
    out
}

fuzz_target!(|data: &[u8]| {
    let blocks = blocks(data);
    if blocks.is_empty() {
        return;
    }

    let mut enc = HpackEncoder::new().with_sensitivity(index_everything);
    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));

    for (i, fields) in blocks.iter().enumerate() {
        let Ok(block) = enc.encode(fields) else {
            // A refusal is fine and leaves the encoder in step; what
            // must never happen is a block that encodes and then
            // decodes to something else.
            continue;
        };
        assert!(
            enc.table_size() <= 4096,
            "the encoder table must stay inside its cap"
        );

        let stream = (i as u32 % 1000) * 2 + 1;
        let wire = write_headers(stream, &block, true, 16_384).expect("framable");
        p.push(FlowSide::Initiator, &Bytes::from(wire));

        let mut got = None;
        while let Some(ev) = p.next_event() {
            if let Http2Event::Head(h) = ev {
                got = Some(h);
            }
        }
        match got {
            Some(head) => assert_eq!(
                &head.fields, fields,
                "block {i} did not survive the round trip"
            ),
            // The parser bounds what it will hold; hitting one of its
            // caps is a legitimate refusal, not a round-trip failure.
            None => assert!(p.is_failed(), "a block vanished without an error"),
        }
        if p.is_failed() {
            break;
        }
    }
});
