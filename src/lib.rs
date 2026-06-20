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
pub mod mac_addr;
pub mod parser_kind;
pub mod rx_metadata;
mod timestamp;
mod view;

pub use error::{Error, ErrorCode, ErrorKind, Module, Result};
pub use mac_addr::MacAddr;
pub use parser_kind::ParserKind;
pub use rx_metadata::{ChecksumStatus, RssHashType, RxHash, RxMetadata, VlanProto, VlanTag};

pub mod extractor;

#[cfg(feature = "aggregate")]
pub mod aggregate;

pub mod detect;

pub mod well_known;

#[cfg(feature = "extractors")]
pub mod extract;

#[cfg(feature = "extractors")]
pub mod layers;

#[cfg(feature = "tracker")]
pub mod anomaly;
pub mod anomaly_fields;
#[cfg(feature = "tracker")]
pub use anomaly::{DetectorScore, OwnedAnomaly};
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
pub mod flow_driver;
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
pub mod driver;

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
// Plan 162 (0.14): top-level re-export for the unified
// ICMPv4/v6 Destination Unreachable classification. Parallels
// `pub use anomaly::OwnedAnomaly` (0.13) — frequently-imported
// enum surfaced at the crate root.
#[cfg(feature = "icmp")]
pub use icmp::{DestUnreachableKind, MtuSignalKind};
// Issue #1 (0.17): ARP visibility — opt-in via the `arp` feature.
#[cfg(feature = "arp")]
pub mod arp;
#[cfg(feature = "arp")]
pub use arp::{ArpMessage, ArpOp};
// Issue #6 (0.18): NDP (IPv6 Neighbor Discovery) — the ARP
// sibling. Pairs with the always-on `NeighborTable<Ipv6Addr,
// MacAddr>` for binding tracking.
#[cfg(feature = "ndp")]
pub mod ndp;
#[cfg(feature = "ndp")]
pub use ndp::{NdpKind, NdpMessage};
// Issue #11 (0.18): DHCP — UDP/67-68 BOOTP + RFC 2132 options
// + Fingerbank-style option-55 + option-60 fingerprint.
#[cfg(feature = "dhcp")]
pub mod dhcp;
#[cfg(feature = "dhcp")]
pub use dhcp::{DhcpMessage, DhcpMessageType, DhcpOp};
// Issue #23 (0.18): LLDP — IEEE 802.1AB-2016 L2 discovery.
// Asset / rogue-switch visibility for infrastructure devices.
#[cfg(feature = "lldp")]
pub mod lldp;
#[cfg(feature = "lldp")]
pub use lldp::{ChassisId, LldpMessage, PortId, SystemCapabilities};
// Issue #25 (0.18): CDP — Cisco Discovery Protocol, the LLDP
// sibling. Asset / topology / rogue-switch visibility on
// Cisco gear.
#[cfg(feature = "cdp")]
pub mod cdp;
#[cfg(feature = "cdp")]
pub use cdp::{CdpAddress, CdpCapabilities, CdpMessage};
// Issue #9 (0.18): p0f-style passive TCP/IP fingerprint.
// License-clean alternative to FoxIO's JA4T / JA4TS.
#[cfg(feature = "tcp_fingerprint")]
pub mod tcp_fingerprint;
#[cfg(feature = "tcp_fingerprint")]
pub use tcp_fingerprint::{TcpDirection, TcpFingerprint};
// Issue #16 sub-piece (0.18): IPFIX IE vocabulary. The full
// FlowRecord re-key stays open in #16.
#[cfg(feature = "ipfix")]
pub mod ipfix;
// Issue #7 (0.18): SSH handshake parser + HASSH fingerprint.
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "ssh")]
pub use ssh::{SshKexInit, SshMessage, SshParser};
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
/// **Deprecated — soft-deprecation window**.
///
/// Use the typed [`ParserKind`] enum (added in 0.18 — issue #21)
/// for new code. The string constants here resolve to the same
/// slugs `ParserKind::as_str()` returns and will stay shipped
/// for one minor cycle to give downstream consumers time to
/// migrate match arms. Removed in 0.19.
#[deprecated(
    since = "0.18.0",
    note = "use the typed `flowscope::ParserKind` enum instead — same slug vocabulary via `.as_str()`"
)]
pub mod parser_kinds {
    #![allow(deprecated)]
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
    #[cfg(feature = "tls")]
    pub use crate::tls::handshake::PARSER_KIND as TLS_HANDSHAKE;
}

pub use anomaly_fields::{AnomalyFields, KeyFields};
#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use datagram_driver::FlowDatagramDriver;
#[cfg(feature = "tracker")]
pub use dedup::Dedup;
#[cfg(feature = "tracker")]
pub use event::{
    AnomalyKind, EndReason, FlowEvent, FlowSide, FlowState, FlowStats, OverflowPolicy,
};
pub use extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};
#[cfg(feature = "reassembler")]
pub use flow_driver::FlowDriver;
#[cfg(feature = "tracker")]
pub use history::HistoryString;
#[cfg(feature = "reassembler")]
pub use reassembler::{
    BufferedReassembler, BufferedReassemblerFactory, NoopReassembler, NoopReassemblerFactory,
    Reassembler, ReassemblerFactory,
};
#[cfg(feature = "session")]
pub use session::{
    AccumulatingSessionParser, BufferedFrameDrain, DatagramParser, DatagramParserFactory,
    FrameDrainError, PerDatagramParser, SessionEvent, SessionParser, SessionParserFactory,
};
#[cfg(all(feature = "reassembler", feature = "session"))]
pub use session_driver::FlowSessionDriver;
#[cfg(feature = "tracker")]
pub use tracker::{FlowEntry, FlowEvents, FlowTracker, FlowTrackerConfig, FlowTrackerStats};
