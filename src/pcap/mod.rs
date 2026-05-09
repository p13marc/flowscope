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

mod source;

pub use source::{Error, EventIter, OwnedPacketView, PcapFlowSource, ViewIter};
