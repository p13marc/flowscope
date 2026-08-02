//! HTTP/2 — frame layer, HPACK, and per-stream events.
//!
//! A router that terminates h2 needs one thing from it: the routing
//! key per stream (`:authority` and `:path`). Getting there means
//! implementing rather more than that, because HTTP/2 is stateful in
//! ways HTTP/1 is not:
//!
//! * **HPACK is connection-wide.** The decoder's dynamic table is
//!   built from every field block in order, so a block you skip
//!   corrupts every block after it. There is no "parse only the
//!   streams I care about".
//! * **Field blocks span frames.** `HEADERS` continues into
//!   `CONTINUATION`, and nothing else may interleave on that stream
//!   until `END_HEADERS` (RFC 9113 §6.10).
//! * **Everything is concurrent.** Streams interleave at frame
//!   granularity, so per-stream state is unavoidable — and must be
//!   bounded, since the peer decides how many streams to open.
//!
//! [`Http2Parser`] handles that and reports the same vocabulary the
//! HTTP/1 streaming parser uses — head, body, trailers, end — keyed
//! by stream ID, so a consumer written against one shape works with
//! the other.
//!
//! ```
//! use bytes::Bytes;
//! use flowscope::FlowSide;
//! use flowscope::http2::{Http2Event, Http2Parser, PREFACE};
//!
//! let mut p = Http2Parser::new();
//! p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
//!
//! // A HEADERS frame on stream 1, ":method: GET" as static index 2.
//! let mut frame = vec![0, 0, 1, 0x1, 0x05, 0, 0, 0, 1];
//! frame.push(0x82);
//! p.push(FlowSide::Initiator, &Bytes::from(frame));
//!
//! let Some(Http2Event::Head(head)) = p.next_event() else {
//!     panic!("expected a head")
//! };
//! assert_eq!(head.stream_id, 1);
//! assert_eq!(head.method(), Some("GET"));
//! ```
//!
//! # Scope
//!
//! This is an observer and a router, not an endpoint. It reads frames
//! and field blocks; it does not manage flow control, priority, or
//! push. `WINDOW_UPDATE` and `PRIORITY` are recognised and skipped —
//! a forwarding proxy relays them untouched.

mod error;
mod frame;
mod hpack;
mod huffman;
mod stream;

pub use error::Http2Error;
pub use frame::{FrameKind, PREFACE};
pub use stream::{Http2Config, Http2Event, Http2Parser, StreamHead};

/// Slug returned by [`Http2Parser`]'s `parser_kind()`.
pub const PARSER_KIND: &str = "http/2";
