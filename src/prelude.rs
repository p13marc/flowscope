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
// Issue #14 sub-piece (0.18): TFTP — device-config transfer
// visibility.
#[cfg(feature = "tftp")]
pub use crate::tftp::{TftpErrorCode, TftpMessage, TftpMode, TftpOpcode};
// Issue #27 (0.18): asset-inventory composition.
#[cfg(feature = "asset")]
pub use crate::asset::{Asset, AssetCapabilities, AssetSourceSet, Inventory};
// Issue #9 (0.18): p0f-style passive TCP/IP fingerprint.
#[cfg(feature = "tcp_fingerprint")]
pub use crate::tcp_fingerprint::{TcpDirection, TcpFingerprint};
// Issue #7 (0.18): SSH handshake + HASSH fingerprint.
#[cfg(feature = "ssh")]
pub use crate::ssh::{SshKexInit, SshMessage, SshParser};
// Issue #14 sub-piece (0.18): mDNS — RFC 6762 multicast DNS.
#[cfg(feature = "mdns")]
pub use crate::mdns::{MdnsParser, ServiceRecord};
// Issue #14 sub-piece (0.18): NetBIOS Name Service —
// Windows-side broadcast name service.
#[cfg(feature = "netbios-ns")]
pub use crate::netbios_ns::{NbnsMessage, NbnsOpcode, NbnsParser};
// Issue #14 sub-piece (0.18): FTP control channel —
// cleartext credentials + transfer detection.
#[cfg(feature = "ftp")]
pub use crate::ftp::{FtpCommand, FtpMessage, FtpParser, FtpReplyClass, TransferKind};
// Issue #14 sub-piece (0.18): SMTP control channel — cleartext
// AUTH PLAIN/LOGIN + named-exfil (MAIL FROM/RCPT TO).
#[cfg(feature = "smtp")]
pub use crate::smtp::{SmtpCommand, SmtpMessage, SmtpParser};
// Issue #14 sub-piece (0.18): WireGuard — passive
// VPN-handshake detection.
#[cfg(feature = "wireguard")]
pub use crate::wireguard::{WireGuardKind, WireGuardMessage, WireGuardParser};
// Issue #14 sub-piece (0.18): Modbus/TCP — ICS visibility.
#[cfg(feature = "modbus")]
pub use crate::modbus::{ModbusExceptionCode, ModbusFunction, ModbusMessage, ModbusParser};
// Issue #14 sub-piece (0.18): STUN — WebRTC peer / NAT
// discovery.
#[cfg(feature = "stun")]
pub use crate::stun::{StunClass, StunMessage, StunParser};
// Issue #14 sub-piece (0.18): RDP X.224 negotiation —
// metadata-only lateral-movement (T1021.001) detection.
#[cfg(feature = "rdp")]
pub use crate::rdp::{RdpFailureCode, RdpMessage, RdpParser, RdpProtocols};
// Issue #14 sub-piece (0.18): SNMP v1/v2c — asset enum +
// DDoS amplification + cleartext community-string capture.
#[cfg(feature = "snmp")]
pub use crate::snmp::{SnmpMessage, SnmpParser, SnmpPduKind, SnmpVersion};
// Issue #14 sub-piece (0.18): RADIUS — identity correlation,
// NAC / wireless-auth visibility.
#[cfg(feature = "radius")]
pub use crate::radius::{RadiusCodeKind, RadiusMessage, RadiusParser};
// Issue #29 (0.18): DNP3 — OT/SCADA visibility,
// metadata-only.
#[cfg(feature = "dnp3")]
pub use crate::dnp3::{
    DnpAppFunctionKind, DnpApplication, DnpInternalIndications, DnpLinkFunctionKind, DnpMessage,
    DnpParser,
};
// Issue #13 (0.18): Kerberos passive metadata
// (AS-REQ / TGS-REQ / RC4 Kerberoast signal).
#[cfg(feature = "kerberos")]
pub use crate::kerberos::{
    KerberosEtype, KerberosMessage, KerberosMessageKind, KerberosTcpParser, KerberosUdpParser,
};
// Issue #13 (0.18): LDAP — AD recon + SPN-query detection.
#[cfg(feature = "ldap")]
pub use crate::ldap::{LdapAuthKind, LdapMessage, LdapOperation, LdapParser};
// Issue #12 (0.18): SMB2/3 — lateral-movement visibility.
#[cfg(feature = "smb")]
pub use crate::smb::{
    DceRpcInterfaceUuid, NtlmAuth, SmbCommand, SmbDialect, SmbMessage, SmbParser,
};
// Issue #3 (0.18): QUIC Initial — passive-decryptable SNI /
// ALPN extraction for HTTP/3 + DoQ visibility.
#[cfg(feature = "quic")]
pub use crate::quic::{QuicInitial, QuicUdpParser, QuicVersion};
// Issue #16 / #28 (0.18): IPFIX canonical record + binary
// wire encoder.
#[cfg(feature = "ipfix")]
pub use crate::FlowRecord;
// Issue #15 (0.18): CICFlowMeter-compatible ML feature
// vector (totals + per-packet IAT + active/idle).
#[cfg(feature = "ml-features")]
pub use crate::ml_features::CicFlowFeatures;
// Issue #30 (0.18): nPrint per-packet ternary header-bit
// matrix (raw-bit ML mode).
#[cfg(feature = "ml-features-nprint")]
pub use crate::nprint::{NPrintConfig, NPrintMatrix, NPrintRow};
// Issue #15 sub-piece (0.18): running statistics primitive
// (used by FlowStats IAT + Active/Idle).
#[cfg(feature = "tracker")]
pub use crate::correlate::WelfordStats;
// Plan 167 (0.14): discoverability sweep — surface the
// `correlate::*` primitives in the prelude so users don't
// have to know the module path to find them.
#[cfg(all(feature = "tracker", feature = "extractors"))]
pub use crate::correlate::FlowStateMap;
#[cfg(feature = "tracker")]
pub use crate::correlate::{
    BurstDetector, Ewma, KeyIndexed, RollingRate, TimeBucketedCounter, TimeBucketedSet, TopK,
};
// Issue #75: mergeable streaming sketches — siblings of
// `HyperLogLog`. The whole `correlate` module is `tracker`-gated,
// so these re-exports must be too.
#[cfg(feature = "tracker")]
pub use crate::correlate::{BloomFilter, CountMinSketch};
// Issue #74: xbits/hostbits-style named-bit TTL store.
#[cfg(feature = "tracker")]
pub use crate::correlate::BitStore;
// Issue #1 (0.17): NeighborTable IP→link-layer binding tracker.
#[cfg(feature = "tracker")]
pub use crate::correlate::{NeighborBinding, NeighborEvent, NeighborTable};
// Issue #4 (0.17): behavioural-fingerprint primitives.
#[cfg(feature = "fingerprint")]
pub use crate::detect::fingerprint::{FingerprintBuilder, FlowFingerprint};
// Issue #72: threat-intel indicator membership set.
pub use crate::detect::{IocKind, IocMatch, IocSet};
// Issue #73: nDPI-style flow-risk taxonomy.
pub use crate::detect::{FlowRisk, RiskSeverity};
// Issue #83: analysis composition layer — enriched flow records.
#[cfg(feature = "analysis")]
pub use crate::analysis::{AnalyzedFlow, FlowAnalyzer, L7Summary};
/// The typed [`crate::driver::Driver`] +
/// [`crate::driver::SlotHandle`] shape (plan 121).
#[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
pub use crate::driver::{
    BroadcastSlotHandle, Driver, DriverBuilder, Event, SlotDrain, SlotHandle, SlotMessage,
};
#[cfg(feature = "tracker")]
pub use crate::event::{AnomalyKind, EndReason, EventMask, FlowEvent, FlowSide, FlowStats};
#[cfg(feature = "extractors")]
pub use crate::extract::{FiveTuple, FiveTupleKey, Tagged, TaggedKey};
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
// The blessed offline one-call message iterators (the generic
// building block under the per-parser `*_from_pcap` helpers).
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
pub use crate::pcap::{datagram_messages, session_messages};
// Issue #111 (0.20): unified offline lifecycle + message stream.
#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
pub use crate::pcap::{Pulse, datagram_pulses, session_pulses};
// Issue #109 (0.20): typed parser identity — returned by
// `SessionParser`/`DatagramParser::parser_kind` and carried on
// `Event::ParserClosed` / `SlotHandle::parser_kind`.
#[cfg(feature = "session")]
pub use crate::parser_kind::ParserKind;
// Issue #133 (0.21): typed detector identity — carried on
// `OwnedAnomaly::kind` and returned by `DetectorScore::kind`;
// `attack_technique()` maps to MITRE ATT&CK Txxxx IDs.
#[cfg(feature = "tracker")]
pub use crate::detector_kind::DetectorKind;
// Issue #8 (0.18): ECH GREASE-vs-real classification — surface
// next to the rest of the TLS handshake vocabulary.
#[cfg(feature = "session")]
pub use crate::session::{DatagramParser, SessionParser};
#[cfg(feature = "tls")]
pub use crate::tls::EchState;
#[cfg(feature = "tracker")]
pub use crate::tracker::{FlowTracker, FlowTrackerConfig};
// Plan 165 (0.14): site-custom port label table.
#[cfg(feature = "extractors")]
pub use crate::well_known::LabelTable;
pub use crate::{
    AnomalyFields, AsPacketView, ChecksumStatus, Error, ErrorCode, ErrorKind, KeyFields, MacAddr,
    Module, PacketView, Result, RssHashType, RxHash, RxMetadata, Timestamp, VlanProto, VlanTag,
};
