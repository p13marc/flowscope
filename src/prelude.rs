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

// Issue #1 (0.17): ARP visibility surface.
#[cfg(feature = "arp")]
pub use crate::arp::{ArpMessage, ArpOp};
// Issue #6 (0.18): NDP (IPv6 Neighbor Discovery) — IPv6 sibling
// of ARP.
#[cfg(feature = "ndp")]
pub use crate::ndp::{NdpKind, NdpMessage};
// Issue #11 (0.18): DHCP — passive asset / OS discovery.
#[cfg(feature = "dhcp")]
pub use crate::dhcp::{DhcpMessage, DhcpMessageType, DhcpOp};
// Issue #23 (0.18): LLDP — L2 asset discovery + rogue-switch
// detection.
#[cfg(feature = "lldp")]
pub use crate::lldp::{ChassisId, LldpMessage, PortId, SystemCapabilities};
// Issue #25 (0.18): CDP — LLDP sibling for Cisco gear.
#[cfg(feature = "cdp")]
pub use crate::cdp::{CdpAddress, CdpCapabilities, CdpMessage};
// Issue #14 sub-piece (0.18): NTP — UDP/123 visibility +
// amplification detection.
#[cfg(feature = "ntp")]
pub use crate::ntp::{NtpLeapIndicator, NtpMessage, NtpMode};
// Issue #14 sub-piece (0.18): SSDP — IoT / UPnP asset
// discovery.
#[cfg(feature = "ssdp")]
pub use crate::ssdp::{SsdpKind, SsdpMessage};
// Issue #9 (0.18): p0f-style passive TCP/IP fingerprint.
#[cfg(feature = "tcp_fingerprint")]
pub use crate::tcp_fingerprint::{TcpDirection, TcpFingerprint};
// Issue #7 (0.18): SSH handshake + HASSH fingerprint.
#[cfg(feature = "ssh")]
pub use crate::ssh::{SshKexInit, SshMessage, SshParser};
// Plan 167 (0.14): discoverability sweep — surface the
// `correlate::*` primitives in the prelude so users don't
// have to know the module path to find them.
#[cfg(all(feature = "tracker", feature = "extractors"))]
pub use crate::correlate::FlowStateMap;
#[cfg(feature = "tracker")]
pub use crate::correlate::{
    BurstDetector, Ewma, KeyIndexed, RollingRate, TimeBucketedCounter, TimeBucketedSet, TopK,
};
// Issue #1 (0.17): NeighborTable IP→link-layer binding tracker.
#[cfg(feature = "tracker")]
pub use crate::correlate::{NeighborBinding, NeighborEvent, NeighborTable};
// Issue #4 (0.17): behavioural-fingerprint primitives.
#[cfg(feature = "fingerprint")]
pub use crate::detect::fingerprint::{FingerprintBuilder, FlowFingerprint};
/// The typed [`crate::driver::Driver`] +
/// [`crate::driver::SlotHandle`] shape (plan 121).
#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::driver::{Driver, DriverBuilder, Event, SlotHandle, SlotMessage};
#[cfg(feature = "tracker")]
pub use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};
#[cfg(feature = "extractors")]
pub use crate::extract::{FiveTuple, Tagged, TaggedKey};
#[cfg(feature = "extractors")]
pub use crate::extractor::{Extracted, FlowExtractor, L4Proto, Orientation, TcpFlags, TcpInfo};
// Plan 162 (0.14): ICMP error classification — frequently
// imported by `on_icmp_error` consumers.
// Plan 170 (0.14): `MtuSignalKind` added for PMTU events.
#[cfg(feature = "icmp")]
pub use crate::icmp::{DestUnreachableKind, IcmpInner, IcmpMessage, IcmpType, MtuSignalKind};
#[cfg(feature = "extractors")]
pub use crate::layers::{Layer, LayerKind, LayerParser, LayerStack, Layers};
#[cfg(feature = "pcap")]
pub use crate::pcap::PcapFlowSource;
// Issue #8 (0.18): ECH GREASE-vs-real classification — surface
// next to the rest of the TLS handshake vocabulary.
#[cfg(feature = "session")]
pub use crate::session::{DatagramParser, SessionEvent, SessionParser};
#[cfg(feature = "tls")]
pub use crate::tls::EchState;
#[cfg(feature = "tracker")]
pub use crate::tracker::{FlowTracker, FlowTrackerConfig};
// Plan 165 (0.14): site-custom port label table.
#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::FlowDatagramDriver;
#[cfg(all(feature = "reassembler", feature = "session"))]
pub use crate::FlowSessionDriver;
#[cfg(feature = "extractors")]
pub use crate::well_known::LabelTable;
pub use crate::{
    AnomalyFields, AsPacketView, ChecksumStatus, Error, ErrorCode, ErrorKind, KeyFields, MacAddr,
    Module, PacketView, Result, RssHashType, RxHash, RxMetadata, Timestamp, VlanProto, VlanTag,
};
