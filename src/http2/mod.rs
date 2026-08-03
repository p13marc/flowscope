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
//! # gRPC
//!
//! gRPC rides on this directly: the call is named by the h2
//! pseudo-headers and its outcome arrives in trailers. See
//! [`grpc_call`] and [`grpc_status`]. Note a gRPC call that *failed*
//! still carries HTTP `200` — the status is in the trailers, which is
//! what makes reading them necessary rather than optional.
//!
//! # Driving it
//!
//! [`Http2Parser`] is sans-IO: you own the sockets, you feed it, and
//! you read the accepted count as backpressure. To let flowscope
//! drive the bytes instead — port-routed or heuristic slots on the
//! typed `Driver`, pcap replay, the `emit` writers — register
//! [`Http2Session`], the [`SessionParser`](crate::SessionParser)
//! adapter, exactly as HTTP/1 registers
//! [`HttpProxySession`](crate::http::HttpProxySession).
//!
//! The multiplexing does not disappear at that boundary, it moves:
//! the envelope's `side` is the transport direction the bytes arrived
//! on, and the routing key stays the `stream_id` on the event.
//! `Http2Session` also tolerates a missing connection preface by
//! default, because a driver may hand it a flow already in progress.
//!
//! # Re-emitting headers
//!
//! A proxy that *modifies* a header cannot forward the original
//! bytes: HTTP/2 header fields are a stateful compressed encoding,
//! not text. [`HpackEncoder`] produces a new field block and
//! [`write_headers`] frames it as `HEADERS` plus any `CONTINUATION`
//! the peer's `SETTINGS_MAX_FRAME_SIZE` requires.
//!
//! The encoder's dynamic table is **a model of the peer's decoder**,
//! so every block it produces must actually be sent, in order. A
//! block built and then dropped puts the two tables permanently out
//! of step, and the corruption surfaces frames later on an unrelated
//! stream. Use one encoder per direction.
//!
//! By default the encoder never indexes credential-bearing fields
//! (`authorization`, `cookie`, …), because an indexed repeat is the
//! CRIME-family oracle — see [`default_sensitivity`].
//!
//! # Scope
//!
//! This reads frames and field blocks, and can re-emit a field block.
//! It is not an endpoint: it does not manage flow control, priority,
//! or push, and it does not own a socket. `WINDOW_UPDATE` and
//! `PRIORITY` are recognised and skipped — a forwarding proxy relays
//! them untouched.

mod error;
mod frame;
mod grpc;
mod hpack;
mod hpack_encode;
mod huffman;
mod session;
mod stream;

pub use error::Http2Error;
pub use frame::{FrameKind, PREFACE, write_headers};
pub use grpc::{
    GrpcCall, GrpcStatus, grpc_call, grpc_status, grpc_status_of, is_grpc_content_type,
};
pub use hpack_encode::{
    HeaderSensitivity, HpackEncoder, HuffmanPolicy, SensitivityFn, default_sensitivity,
};
pub use session::Http2Session;
pub use stream::{Http2Config, Http2Event, Http2Parser, StreamHead};

/// Stable slug for HTTP/2, matching
/// [`ParserKind::Http2`](crate::ParserKind::Http2)`.as_str()`.
///
/// Use this constant at match sites that switch on a parser slug.
pub const PARSER_KIND: &str = "http/2";
