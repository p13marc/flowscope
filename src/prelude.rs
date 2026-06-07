//! `use flowscope::prelude::*;` — one import for the common types.
//!
//! Re-exports the types most users want without typing
//! `use flowscope::{Pipeline, Event, Timestamp, …};` every time.
//! Power users can keep the explicit imports; this module is the
//! "I'm starting a new project" convenience.
//!
//! ```no_run
//! use flowscope::prelude::*;
//!
//! # fn main() -> flowscope::Result<()> {
//! let mut pipeline = Pipeline::builder(FiveTuple::bidirectional()).build();
//! for event in pipeline.run_pcap("trace.pcap")? {
//!     let _ = event?;
//! }
//! # Ok(()) }
//! ```

pub use crate::{AsPacketView, Error, ErrorCode, ErrorKind, Module, PacketView, Result, Timestamp};

#[cfg(feature = "extractors")]
pub use crate::extract::FiveTuple;

#[cfg(feature = "extractors")]
pub use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};

#[cfg(feature = "tracker")]
pub use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};

#[cfg(feature = "tracker")]
pub use crate::tracker::{FlowTracker, FlowTrackerConfig};

#[cfg(feature = "session")]
pub use crate::session::{DatagramParser, SessionEvent, SessionParser};

#[cfg(all(feature = "reassembler", feature = "session"))]
pub use crate::FlowSessionDriver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::FlowDatagramDriver;

#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::{Event, EventKind, Pipeline, PipelineBuilder};

#[cfg(feature = "extractors")]
pub use crate::layers::{Layer, LayerKind, LayerParser, LayerStack, Layers};

#[cfg(feature = "pcap")]
pub use crate::pcap::PcapFlowSource;
