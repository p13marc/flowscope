//! `flowscope` — passive flow & session tracking for packet capture.
//!
//! Cross-platform, runtime-free library for **observing** what's
//! happening on the wire. Pair with any source of `&[u8]` frames:
//! `netring` (Linux AF_PACKET / AF_XDP), pcap files, tun-tap,
//! eBPF, embedded.
//!
//! ## What's here
//!
//! Core (always on):
//!
//! - [`PacketView`] / [`Timestamp`] — the abstract input.
//! - [`FlowExtractor`] — turn a frame into a flow descriptor.
//! - [`FlowTracker`] — bidirectional flow accounting + TCP state
//!   machine + idle/eviction policy. Hot-cache fast path on
//!   monoflow workloads.
//! - [`Reassembler`] — sync per-(flow, side) TCP byte stream hook.
//!   Optional per-side buffer cap with [`OverflowPolicy`]
//!   (sliding-window or drop-flow).
//! - [`SessionParser`] / [`DatagramParser`] — typed L7 message
//!   parsing per flow.
//! - [`FlowDriver`] — sync wrapper combining the tracker with a
//!   reassembler factory; optional anomaly emission via
//!   [`FlowDriver::with_emit_anomalies`].
//! - [`FlowSessionDriver`] — sync mirror of netring's
//!   `session_stream` for offline / no-tokio session-event consumers.
//!
//! Built-in extractors and decap combinators (`extractors` feature):
//!
//! - [`extract::FiveTuple`], [`extract::IpPair`], [`extract::MacPair`]
//! - [`extract::StripVlan`], [`extract::StripMpls`],
//!   [`extract::InnerVxlan`], [`extract::InnerGtpU`],
//!   [`extract::InnerGre`], [`extract::AutoDetectEncap`],
//!   [`extract::FlowLabel`]
//!
//! Protocol parsers (each behind its own feature):
//!
//! | Feature | Module    | What you get |
//! |---------|-----------|--------------|
//! | `http`  | [`http`]  | HTTP/1.x request/response parser |
//! | `tls`   | [`tls`]   | TLS handshake observer (ClientHello/ServerHello/Alert), optional JA3 |
//! | `dns`   | [`dns`]   | DNS-over-UDP and DNS-over-TCP message parsers + query/response correlator |
//! | `pcap`  | [`pcap`]  | pcap file source for offline replay |
//!
//! Observability (each behind its own feature, zero-cost when off):
//!
//! | Feature   | What you get |
//! |-----------|--------------|
//! | `metrics` | Prometheus / OpenTelemetry counters, gauges, histograms (see [`obs`]) |
//! | `tracing` | Structured events on flow lifecycle + anomalies |
//!
//! ## Tokio integration
//!
//! For async iteration over flow / session / datagram events, see
//! [`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`
//! / `.session_stream` / `.datagram_stream`. Those depend on this
//! crate's traits. The sync analogue for `session_stream` is
//! [`FlowSessionDriver`].
//!
//! ## Re-exporting flowscope types
//!
//! Crates that re-export flowscope types (`netring`, sister crates,
//! internal forks) should write intra-doc links in the bare
//! `` [`FlowSessionDriver`] `` form, **not** the explicit
//! `` [`FlowSessionDriver`](flowscope::FlowSessionDriver) `` form.
//! The explicit path duplicates what rustdoc already resolves through
//! the re-export and trips the `redundant_explicit_links` lint under
//! `-D warnings`. See recipes.md's "Re-exporting flowscope types"
//! section for the worked example.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod error;
mod timestamp;
mod view;

pub use error::{Error, ErrorCode, ErrorKind, Module, Result};

pub mod extractor;

pub mod well_known;

#[cfg(feature = "extractors")]
pub mod extract;

#[cfg(feature = "extractors")]
pub mod layers;

#[cfg(feature = "tracker")]
pub mod event;
#[cfg(feature = "tracker")]
pub mod history;
#[cfg(all(feature = "tracker", any(test, feature = "test-helpers")))]
pub mod tcp_state;
#[cfg(all(feature = "tracker", not(any(test, feature = "test-helpers"))))]
mod tcp_state;
#[cfg(feature = "tracker")]
pub mod tracker;

#[cfg(feature = "tracker")]
pub mod correlate;

#[cfg(feature = "tracker")]
pub mod obs;

#[cfg(feature = "reassembler")]
pub mod driver;
#[cfg(feature = "reassembler")]
pub mod reassembler;

#[cfg(feature = "reassembler")]
pub mod segment_reassembler;

#[cfg(feature = "reassembler")]
pub use segment_reassembler::SegmentBufferReassembler;

#[cfg(feature = "tracker")]
pub mod dedup;

#[cfg(all(feature = "reassembler", feature = "session"))]
pub mod session_driver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub mod datagram_driver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub mod multi_session_driver;

#[cfg(feature = "session")]
pub mod driver_builder;

#[cfg(feature = "session")]
pub use driver_builder::FlowSessionDriverBuilder;
#[cfg(all(feature = "extractors", feature = "session"))]
pub use driver_builder::FlowDatagramDriverBuilder;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use multi_session_driver::FlowMultiSessionDriver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub mod pipeline;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use pipeline::{Event, EventKind, NoDatagramParser, NoSessionParser, Pipeline, PipelineBuilder};

#[cfg(feature = "emit")]
pub mod emit;

pub mod prelude;

#[cfg(feature = "session")]
pub mod session;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "icmp")]
pub mod icmp;
#[cfg(feature = "pcap")]
pub mod pcap;
#[cfg(feature = "tls")]
pub mod tls;

/// Parser stubs for downstream test crates. Gated by the
/// `test-helpers` feature; not for production use.
#[cfg(all(feature = "session", any(test, feature = "test-helpers")))]
pub mod test_helpers;

pub use timestamp::Timestamp;
pub use view::{AsPacketView, OwnedPacketView, PacketView};

/// Re-export of every shipped parser-kind constant under one path.
///
/// Use these constants at match sites instead of string literals so
/// typos fail to resolve (compile error) rather than silently miss
/// at runtime. Each constant is cfg-gated by its parser's feature.
///
/// ```ignore
/// use flowscope::parser_kinds;
/// match parser_kind {
///     k if k == parser_kinds::DNS_UDP => /* DNS lookup */,
///     k if k == parser_kinds::HTTP => /* HTTP request */,
///     _ => {}
/// }
/// ```
pub mod parser_kinds {
    #[cfg(feature = "dns")]
    pub use crate::dns::PARSER_KIND_TCP as DNS_TCP;
    #[cfg(feature = "dns")]
    pub use crate::dns::PARSER_KIND_UDP as DNS_UDP;
    #[cfg(feature = "http")]
    pub use crate::http::PARSER_KIND as HTTP;
    #[cfg(feature = "icmp")]
    pub use crate::icmp::PARSER_KIND as ICMP;
    #[cfg(feature = "tls")]
    pub use crate::tls::PARSER_KIND as TLS;
}

#[cfg(feature = "tracker")]
pub use dedup::Dedup;

pub use extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};

#[cfg(feature = "tracker")]
pub use event::{
    AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats, OverflowPolicy,
};
#[cfg(feature = "tracker")]
pub use history::HistoryString;
#[cfg(feature = "tracker")]
pub use tracker::{FlowEntry, FlowEvents, FlowTracker, FlowTrackerConfig, FlowTrackerStats};

#[cfg(feature = "reassembler")]
pub use driver::FlowDriver;
#[cfg(feature = "reassembler")]
pub use reassembler::{
    BufferedReassembler, BufferedReassemblerFactory, Reassembler, ReassemblerFactory,
};

#[cfg(feature = "session")]
pub use session::{
    DatagramParser, DatagramParserFactory, SessionEvent, SessionParser, SessionParserFactory,
};

#[cfg(all(feature = "reassembler", feature = "session"))]
pub use session_driver::FlowSessionDriver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use datagram_driver::FlowDatagramDriver;
