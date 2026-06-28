//! pcap file source for offline replay.
//!
//! Wraps [`pcap-file`](https://crates.io/crates/pcap-file). Removes
//! the boilerplate every program needs to feed a pcap into a
//! [`FlowTracker`](crate::FlowTracker).
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
#[cfg(all(feature = "session", feature = "reassembler"))]
mod messages;
mod source;
#[cfg(feature = "tracker")]
mod summaries;

#[cfg(all(feature = "session", feature = "reassembler"))]
pub use messages::{datagram_messages, session_messages};
pub use source::{EventIter, OwnedPacketView, PcapFlowSource, ViewIter};
#[cfg(feature = "tracker")]
#[allow(deprecated)]
pub use summaries::{FlowSummary, flow_summaries, flow_summaries_from_pcap};
