//! Capture-file source for offline replay — classic pcap and pcapng.
//!
//! Wraps [`pcap-file`](https://crates.io/crates/pcap-file);
//! [`CaptureReader`] detects the format from the magic number, applies
//! pcapng per-interface timestamp resolution and offset (saturating on
//! hostile values), reports each packet's [`CaptureDirection`] when
//! the capture records it, and normalises Linux cooked (`LINUX_SLL`,
//! `LINUX_SLL2`), raw IP and BSD loopback link types to Ethernet
//! ([`CapturedPacket::into_ethernet`]). With only the `pcap-reader`
//! feature this module is just that reader; the `pcap` feature adds
//! the sources and helpers that remove the boilerplate every program
//! needs to feed a capture into a [`FlowTracker`](crate::FlowTracker)
//! (other link types are skipped and counted, see
//! `ViewIter::unsupported`).
//!
//! # Quick start
//!
//! ```no_run
//! use flowscope::pcap::PcapFlowSource;
//! use flowscope::extract::FiveTuple;
//! use flowscope::FlowEvent;
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! for evt in PcapFlowSource::open("trace.pcap")?.with_extractor(FiveTuple::bidirectional()) {
//!     if let FlowEvent::Started { key, .. } = evt? {
//!         println!("{} <-> {}", key.a, key.b);
//!     }
//! }
//! # Ok(()) }
//! ```

// Generic per-parser message iterators (issue #86) — need the
// session pipeline to drive a SessionParser / DatagramParser.
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
mod messages;
// Unified lifecycle + message stream (issue #111).
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
mod pulses;
mod reader;
#[cfg(feature = "pcap")]
mod source;
#[cfg(all(feature = "pcap", feature = "tracker"))]
mod summaries;

#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
pub use messages::{datagram_messages, session_messages};
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
pub use pulses::{Pulse, datagram_pulses, session_pulses};
pub use reader::{CaptureDirection, CaptureFormat, CaptureReader, CapturedPacket, DataLink};
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
pub use source::{DatagramIter, SessionIter};
#[cfg(feature = "pcap")]
pub use source::{EventIter, OwnedPacketView, PcapFlowSource, ViewIter};
#[cfg(all(feature = "pcap", feature = "tracker"))]
#[allow(deprecated)]
pub use summaries::{FlowSummary, flow_summaries, flow_summaries_from_pcap};
