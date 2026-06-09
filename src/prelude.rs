//! `use flowscope::prelude::*;` — one import for the common types.
//!
//! Re-exports the types most users want without typing
//! `use flowscope::{Driver, Event, Timestamp, …};` every time.
//! Power users can keep the explicit imports; this module is the
//! "I'm starting a new project" convenience.
//!
//! ```ignore
//! use flowscope::prelude::*;
//!
//! let mut builder = Driver::builder(FiveTuple::bidirectional());
//! let mut driver = builder.build();
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

/// The typed [`crate::driver::Driver`] +
/// [`crate::driver::SlotHandle`] shape (plan 121).
#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::driver::{Driver, DriverBuilder, Event, SlotHandle, SlotMessage};

#[cfg(feature = "extractors")]
pub use crate::layers::{Layer, LayerKind, LayerParser, LayerStack, Layers};

#[cfg(feature = "pcap")]
pub use crate::pcap::PcapFlowSource;
