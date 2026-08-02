//! Route HTTP/2 by stream: pull `:authority` and `:path` off each
//! stream's headers while several streams interleave on one
//! connection.
//!
//! HTTP/2 differs from HTTP/1 in three ways that shape the code
//! below, and each is visible in the output:
//!
//! 1. **Streams interleave**, so events are keyed by stream ID and
//!    two requests' DATA frames arrive mixed together.
//! 2. **HPACK is connection-wide.** The header table is built from
//!    every field block in order, so a later stream can reference an
//!    entry an earlier one inserted — you cannot skip blocks you do
//!    not care about.
//! 3. **Headers can span frames** (`HEADERS` + `CONTINUATION`), and
//!    nothing may interleave in between.
//!
//! No pcap: h2 is almost always inside TLS, so a capture would show
//! ciphertext. The frames here are built by hand, which also makes
//! the wire format legible.
//!
//! Usage:
//!     cargo run --features http2 --example http2_streams

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{Http2Config, Http2Event, Http2Parser, PREFACE};

/// Assemble one frame: 3-byte length, type, flags, 4-byte stream ID.
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

/// An HPACK literal header with incremental indexing — the form that
/// inserts into the dynamic table.
fn literal(name: &str, value: &str) -> Vec<u8> {
    let mut v = vec![0x40, name.len() as u8];
    v.extend_from_slice(name.as_bytes());
    v.push(value.len() as u8);
    v.extend_from_slice(value.as_bytes());
    v
}

const HEADERS: u8 = 0x1;
const DATA: u8 = 0x0;
const RST_STREAM: u8 = 0x3;
const GOAWAY: u8 = 0x7;
const CONTINUATION: u8 = 0x9;

const END_STREAM: u8 = 0x1;
const END_HEADERS: u8 = 0x4;

fn main() {
    // A tight stream cap, to show it holding.
    let cfg = Http2Config::default().with_max_concurrent_streams(8);
    let mut p = Http2Parser::with_config(cfg);

    let mut wire = PREFACE.to_vec();

    // Stream 1: a plain GET. 0x82 / 0x87 are static-table indices for
    // ":method: GET" and ":scheme: https".
    let mut s1 = vec![0x82, 0x87];
    s1.extend(literal(":authority", "alpha.example"));
    s1.extend(literal(":path", "/alpha"));
    wire.extend(frame(HEADERS, END_HEADERS, 1, &s1));

    // Stream 3: headers split across HEADERS + CONTINUATION. Note
    // ":authority" is *not* re-sent as a literal — it is referenced
    // by index into the table stream 1 built.
    //
    // The dynamic table is ordered **most-recently-inserted first**,
    // starting at index 62. Stream 1 inserted ":authority" and then
    // ":path", so ":path" is 62 and ":authority" is 63. Getting this
    // backwards silently yields the wrong header rather than an
    // error, which is why the decoder must see every block in order.
    let mut s3 = vec![0x83, 0x87]; // :method POST, :scheme https
    s3.push(0xbf); // dynamic index 63 -> :authority alpha.example
    s3.extend(literal(":path", "/beta"));
    let (head, tail) = s3.split_at(2);
    wire.extend(frame(HEADERS, 0, 3, head));
    wire.extend(frame(CONTINUATION, END_HEADERS, 3, tail));

    // Bodies interleave between the two streams.
    wire.extend(frame(DATA, 0, 3, b"beta-body-part-1"));
    wire.extend(frame(DATA, END_STREAM, 1, b"alpha-body"));
    wire.extend(frame(DATA, END_STREAM, 3, b"beta-body-part-2"));

    // Stream 5 opens and is immediately cancelled.
    wire.extend(frame(HEADERS, END_HEADERS, 5, &[0x82, 0x87]));
    wire.extend(frame(RST_STREAM, 0, 5, &8u32.to_be_bytes())); // CANCEL

    // The peer winds the connection down.
    wire.extend(frame(GOAWAY, 0, 0, &[0, 0, 0, 5, 0, 0, 0, 0]));

    p.push(FlowSide::Initiator, &Bytes::from(wire));

    println!("stream  event");
    println!("------  -----------------------------------------------");
    let mut bodies: Vec<(u32, Vec<u8>)> = Vec::new();
    while let Some(ev) = p.next_event() {
        match ev {
            Http2Event::Head(h) => {
                println!(
                    "{:>6}  {} {} -> {}",
                    h.stream_id,
                    h.method().unwrap_or("?"),
                    h.path().unwrap_or("?"),
                    h.authority().unwrap_or("?"),
                );
            }
            Http2Event::Body {
                stream_id, data, ..
            } => {
                println!("{stream_id:>6}  {} body bytes", data.len());
                match bodies.iter_mut().find(|(id, _)| *id == stream_id) {
                    Some((_, buf)) => buf.extend_from_slice(&data),
                    None => bodies.push((stream_id, data.to_vec())),
                }
            }
            Http2Event::Trailers {
                stream_id, fields, ..
            } => println!("{stream_id:>6}  trailers ({} fields)", fields.len()),
            Http2Event::End { stream_id, .. } => println!("{stream_id:>6}  complete"),
            Http2Event::StreamReset {
                stream_id,
                error_code,
            } => println!("{stream_id:>6}  reset (code {error_code})"),
            Http2Event::GoAway { last_stream_id, .. } => {
                println!("     -  goaway, last stream {last_stream_id}")
            }
            _ => {}
        }
    }

    println!("\nreassembled per stream:");
    for (id, body) in &bodies {
        println!("  stream {id}: {:?}", String::from_utf8_lossy(body));
    }

    // Stream 3's authority came from the dynamic table, which only
    // works because every field block was decoded in order.
    assert_eq!(
        bodies
            .iter()
            .find(|(id, _)| *id == 3)
            .map(|(_, b)| b.as_slice()),
        Some(&b"beta-body-part-1beta-body-part-2"[..]),
    );
    println!("\ntracked streams still open: {}", p.tracked_streams());
    assert!(!p.is_failed());
}
