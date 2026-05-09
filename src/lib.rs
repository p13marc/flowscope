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
//!   machine + idle/eviction policy.
//! - [`Reassembler`] — sync per-(flow, side) TCP byte stream hook.
//! - [`SessionParser`] / [`DatagramParser`] — typed L7 message
//!   parsing per flow.
//!
//! Built-in extractors and decap combinators (`extractors` feature):
//!
//! - [`extract::FiveTuple`], [`extract::IpPair`], [`extract::MacPair`]
//! - [`extract::StripVlan`], [`extract::StripMpls`],
//!   [`extract::InnerVxlan`], [`extract::InnerGtpU`]
//!
//! Protocol parsers (each behind its own feature):
//!
//! | Feature | Module    | What you get |
//! |---------|-----------|--------------|
//! | `http`  | [`http`]  | HTTP/1.x request/response parser |
//! | `tls`   | [`tls`]   | TLS handshake observer (ClientHello/ServerHello/Alert), optional JA3 |
//! | `dns`   | [`dns`]   | DNS-over-UDP message parser + query/response correlator |
//! | `pcap`  | [`pcap`]  | pcap file source for offline replay |
//!
//! ## Tokio integration
//!
//! For async iteration over flow / session / datagram events, see
//! [`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`
//! / `.session_stream` / `.datagram_stream`. Those depend on this
//! crate's traits.

#![cfg_attr(docsrs, feature(doc_cfg))]

mod timestamp;
mod view;

pub mod extractor;

#[cfg(feature = "extractors")]
pub mod extract;

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

#[cfg(feature = "reassembler")]
pub mod driver;
#[cfg(feature = "reassembler")]
pub mod reassembler;

#[cfg(feature = "session")]
pub mod session;

#[cfg(feature = "dns")]
pub mod dns;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "pcap")]
pub mod pcap;
#[cfg(feature = "tls")]
pub mod tls;

pub use timestamp::Timestamp;
pub use view::PacketView;

pub use extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};

#[cfg(feature = "tracker")]
pub use event::{EndReason, FlowEvent, FlowSide, FlowState, FlowStats};
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
