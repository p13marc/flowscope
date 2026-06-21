//! `FlowRecord` — flowscope's canonical flow record, keyed
//! 1:1 to IANA IPFIX Information Element identities (RFC 7011 +
//! the IANA IPFIX IE registry).
//!
//! # Why
//!
//! Every emitter (CSV / Zeek conn.log / NDJSON / EVE) and
//! every downstream consumer (Suricata-compatible pipelines,
//! goflow2 producers, ML feature extractors per #15) wants
//! a per-flow record. Hand-shaping that record per format
//! invites per-format drift — fields get named differently,
//! units diverge, semantics drift.
//!
//! [`FlowRecord`] is keyed to the IANA IPFIX IE registry so
//! every consumer sees the same field with the same name,
//! same type, same units. Emitters become *views* over one
//! canonical record. ML feature extractors compute their
//! derived features once over `FlowRecord`, not per-format.
//!
//! # Status
//!
//! Issue #16 scoped sub-piece — the **type is shipped
//! additively**. Emitters (`flowscope::emit::*`) still use
//! their own field-sets today; the migration is the next
//! focused PR. New code building flow exporters / ML
//! pipelines should target [`FlowRecord`] directly.
//!
//! # Field mapping
//!
//! Every field in [`FlowRecord`] maps to exactly one IANA
//! IPFIX IE. The mapping is documented per-field. Where
//! `Option<T>` is used, the IE is absent from the wire when
//! `None` — no zero-value sentinel.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use super::types::{FlowEndReason, encode_tcp_control_bits};

/// One canonical per-flow record. Field set covers the
/// IPFIX IEs that mainstream tools (Suricata flow event,
/// goflow2, nProbe, Zeek conn.log) consume + the
/// commonly-missing fields called out in #16's body
/// (`flowEndReason`, `tcpControlBits`).
///
/// `#[non_exhaustive]` — fields land additively as new IEs
/// become operationally important.
///
/// # Per-direction vs. totals
///
/// Per RFC 5103 (biflow), flowscope is a biflow analyzer:
/// every flow has an initiator and responder direction.
/// `FlowRecord` carries `*_initiator` + `*_responder`
/// counters (per IPFIX `octet/packetTotalCount` IEs 85/86
/// in their reverse-PEN form) PLUS the convenience union
/// `bytes_total` / `packets_total` (IEs 85/86 in the
/// non-reverse form).
///
/// # Construction
///
/// Build via [`FlowRecord::from_parts`] (the typical path —
/// from `(stats, key, end_reason)`) or via [`Self::default`]
/// + mutate.
///
/// Issue #16 scoped sub-piece.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct FlowRecord {
    // ── L3 / L4 keys (IPFIX IEs 4 / 7 / 8 / 11 / 12 / 27 / 28) ──
    /// IANA IE 4 — `protocolIdentifier` (IP protocol number;
    /// 6=TCP, 17=UDP, 1=ICMP, etc.).
    pub protocol_identifier: u8,

    /// IANA IE 8 — `sourceIPv4Address`. `None` when the flow
    /// is IPv6 (use [`Self::source_ipv6_address`]).
    pub source_ipv4_address: Option<Ipv4Addr>,
    /// IANA IE 12 — `destinationIPv4Address`.
    pub destination_ipv4_address: Option<Ipv4Addr>,
    /// IANA IE 27 — `sourceIPv6Address`. `None` when IPv4.
    pub source_ipv6_address: Option<Ipv6Addr>,
    /// IANA IE 28 — `destinationIPv6Address`.
    pub destination_ipv6_address: Option<Ipv6Addr>,
    /// IANA IE 7 — `sourceTransportPort`.
    pub source_transport_port: u16,
    /// IANA IE 11 — `destinationTransportPort`.
    pub destination_transport_port: u16,

    // ── Counters (IEs 1 / 2 / 23 / 24 / 85 / 86) ────────────
    /// IANA IE 1 — `octetDeltaCount` initiator → responder
    /// direction. Per RFC 5103 biflow this is the forward-
    /// direction byte count.
    pub octet_delta_count_initiator: u64,
    /// IANA IE 1 reverse — responder → initiator octets.
    pub octet_delta_count_responder: u64,
    /// IANA IE 2 — `packetDeltaCount` initiator direction.
    pub packet_delta_count_initiator: u64,
    /// IANA IE 2 reverse — responder direction.
    pub packet_delta_count_responder: u64,
    /// IANA IE 85 — `octetTotalCount` (both directions
    /// summed). Convenience, populated by [`Self::from_parts`].
    pub octet_total_count: u64,
    /// IANA IE 86 — `packetTotalCount`.
    pub packet_total_count: u64,

    // ── Timing (IEs 152 / 153 / 154 / 155) ──────────────────
    /// IANA IE 152 — `flowStartMilliseconds` (absolute time
    /// of the first packet, ms since Unix epoch).
    pub flow_start_milliseconds: u64,
    /// IANA IE 153 — `flowEndMilliseconds`.
    pub flow_end_milliseconds: u64,

    // ── TCP state (IE 6) ────────────────────────────────────
    /// IANA IE 6 — `tcpControlBits`. Cumulative OR of all
    /// observed TCP flags across the flow (initiator
    /// direction). `None` for non-TCP.
    pub tcp_control_bits_initiator: Option<u16>,
    /// IE 6 reverse — responder-direction cumulative flags.
    pub tcp_control_bits_responder: Option<u16>,

    // ── Termination (IE 136) ────────────────────────────────
    /// IANA IE 136 — `flowEndReason`. Mapped from
    /// flowscope's `EndReason` per the IPFIX-canonical
    /// 5-state vocabulary; see [`FlowEndReason`].
    pub flow_end_reason: Option<FlowEndReason>,

    // ── L2 / interface (IEs 56 / 80 / 10 / 14) ──────────────
    /// IANA IE 56 — `sourceMacAddress`. `None` when the
    /// capture point didn't surface an L2 address (raw-IP
    /// captures, encap stripping).
    pub source_mac_address: Option<[u8; 6]>,
    /// IANA IE 80 — `destinationMacAddress`.
    pub destination_mac_address: Option<[u8; 6]>,
    /// IANA IE 10 — `ingressInterface` (capture-point /
    /// NIC-queue index). `None` when not surfaced.
    pub ingress_interface: Option<u32>,
    /// IANA IE 14 — `egressInterface`. Almost always `None`
    /// for a passive observer — included for emitter-shape
    /// completeness.
    pub egress_interface: Option<u32>,

    // ── Application + VLAN tags (IEs 95 / 58 / 351) ─────────
    /// IANA IE 95 — `applicationId`. The "type:value" byte
    /// shape Cisco / Palo Alto exporters use; flowscope
    /// leaves the encoding to the consumer.
    pub application_id: Option<Vec<u8>>,
    /// IANA IE 96 — `applicationName`. Human-readable app
    /// name. flowscope populates this from
    /// `FiveTupleKey::app_label()` when [`Self::from_parts`]
    /// is used.
    pub application_name: Option<String>,
    /// IANA IE 58 — `vlanId` (802.1Q on ingress).
    pub vlan_id: Option<u16>,
    /// IANA IE 351 — `layer2SegmentId` (VxLAN VNI / NVGRE
    /// VSID per RFC 7637).
    pub layer2_segment_id: Option<u64>,

    // ── Class-of-service (IE 5) ─────────────────────────────
    /// IANA IE 5 — `ipClassOfService` (IPv4 TOS byte or IPv6
    /// Traffic Class).
    pub ip_class_of_service: Option<u8>,

    // ── flowscope private-enterprise extensions ──────────────
    //
    // The IPFIX private-enterprise IE namespace (32768+) is
    // assigned per-vendor; rather than register a vendor ID
    // we surface these as struct fields the emitter writers
    // consume. Documented as flowscope-specific so consumers
    // of FlowRecord interop don't expect IANA-standard names
    // for them.
    /// flowscope ext — TCP retransmit count on the initiator
    /// side. Populated from `FlowStats::retransmits_initiator`
    /// by [`Self::from_parts`].
    pub retransmits_initiator: u64,
    /// flowscope ext — TCP retransmit count on the responder
    /// side.
    pub retransmits_responder: u64,
}

impl FlowRecord {
    /// Build a `FlowRecord` from flowscope's existing
    /// per-flow state — the `FlowStats` counters, the
    /// `FiveTupleKey`, and the lifecycle `EndReason`.
    ///
    /// Thin wrapper around [`Self::from_key_fields`] kept
    /// for the `FiveTupleKey`-specialised call site. Both
    /// produce identical [`FlowRecord`]s.
    ///
    /// The conversion handles:
    /// - IPv4 / IPv6 routing (which IE fields populate
    ///   based on `key`).
    /// - Per-direction → total roll-up (IEs 85 / 86).
    /// - `flow_start/end_milliseconds` conversion from
    ///   [`crate::Timestamp`].
    /// - `EndReason` → [`FlowEndReason`] mapping (IE 136).
    /// - Protocol identifier from `key.proto`.
    ///
    /// Fields the per-flow state doesn't carry (mgmt
    /// interface, application id, VLAN, segment id, CoS)
    /// stay `None`; consumers populate them themselves
    /// from per-packet metadata.
    #[cfg(feature = "tracker")]
    pub fn from_parts(
        stats: &crate::FlowStats,
        key: &crate::extract::FiveTupleKey,
        end_reason: Option<crate::EndReason>,
    ) -> Self {
        Self::from_key_fields(stats, key, end_reason)
    }

    /// Generic constructor — build a [`FlowRecord`] from any
    /// `K: KeyFields`. Used by every emit writer's
    /// `write_event(FlowEnded)` path so the IE-keyed FlowRecord
    /// is the single canonical record shape; emit writers are
    /// pure views over it.
    ///
    /// Defaults:
    /// - IPv4 / IPv6 addresses populate from `K::src_ip`/
    ///   `K::dest_ip`; absent → fields stay `None`.
    /// - Ports from `K::src_port`/`K::dest_port`; absent → `0`.
    /// - `protocol_identifier` from `K::protocol_identifier`;
    ///   absent → `0` (IPFIX IE 4 = 0 is reserved for
    ///   HOPOPT but commonly used as "unspecified" in
    ///   tracking systems).
    /// - `application_name` from `K::app_proto_str` when
    ///   present.
    ///
    /// Issue #16.
    #[cfg(feature = "tracker")]
    pub fn from_key_fields<K>(
        stats: &crate::FlowStats,
        key: &K,
        end_reason: Option<crate::EndReason>,
    ) -> Self
    where
        K: crate::KeyFields + ?Sized,
    {
        let mut rec = Self {
            protocol_identifier: key.protocol_identifier().unwrap_or(0),
            source_transport_port: key.src_port().unwrap_or(0),
            destination_transport_port: key.dest_port().unwrap_or(0),
            octet_delta_count_initiator: stats.bytes_initiator,
            octet_delta_count_responder: stats.bytes_responder,
            packet_delta_count_initiator: stats.packets_initiator,
            packet_delta_count_responder: stats.packets_responder,
            octet_total_count: stats.bytes_initiator + stats.bytes_responder,
            packet_total_count: stats.packets_initiator + stats.packets_responder,
            flow_start_milliseconds: timestamp_to_unix_ms(stats.started),
            flow_end_milliseconds: timestamp_to_unix_ms(stats.last_seen),
            flow_end_reason: end_reason.map(FlowEndReason::from),
            retransmits_initiator: stats.retransmits_initiator,
            retransmits_responder: stats.retransmits_responder,
            ..Self::default()
        };
        if let Some(ip) = key.src_ip() {
            match ip {
                IpAddr::V4(v4) => rec.source_ipv4_address = Some(v4),
                IpAddr::V6(v6) => rec.source_ipv6_address = Some(v6),
            }
        }
        if let Some(ip) = key.dest_ip() {
            match ip {
                IpAddr::V4(v4) => rec.destination_ipv4_address = Some(v4),
                IpAddr::V6(v6) => rec.destination_ipv6_address = Some(v6),
            }
        }
        if let Some(app) = key.app_proto_str()
            && !app.is_empty()
        {
            rec.application_name = Some(app.to_string());
        }
        rec
    }

    /// Fold the TCP-flags-observed bitmask into the record's
    /// `tcp_control_bits_*` field for the given direction.
    /// Bitwise-OR with any prior value — IE 6 is cumulative
    /// per RFC 7125.
    ///
    /// Convenience wrapper around [`encode_tcp_control_bits`].
    #[allow(clippy::too_many_arguments)]
    pub fn observe_tcp_flags(
        &mut self,
        from_initiator: bool,
        fin: bool,
        syn: bool,
        rst: bool,
        psh: bool,
        ack: bool,
        urg: bool,
        ece: bool,
        cwr: bool,
    ) {
        let bits = encode_tcp_control_bits(fin, syn, rst, psh, ack, urg, ece, cwr);
        let slot = if from_initiator {
            &mut self.tcp_control_bits_initiator
        } else {
            &mut self.tcp_control_bits_responder
        };
        *slot = Some(slot.unwrap_or(0) | bits);
    }

    /// IPFIX IE 4 alias — convenience for emitters routing
    /// on protocol.
    pub fn protocol(&self) -> u8 {
        self.protocol_identifier
    }

    /// Returns the canonical `(SocketAddr, SocketAddr)` pair
    /// for the flow, reconstructed from whichever of the v4
    /// / v6 fields are populated. Useful for consumers that
    /// stored a record and need to recover the key.
    pub fn sockets(&self) -> Option<(SocketAddr, SocketAddr)> {
        let s_ip = self
            .source_ipv4_address
            .map(IpAddr::V4)
            .or_else(|| self.source_ipv6_address.map(IpAddr::V6))?;
        let d_ip = self
            .destination_ipv4_address
            .map(IpAddr::V4)
            .or_else(|| self.destination_ipv6_address.map(IpAddr::V6))?;
        Some((
            SocketAddr::new(s_ip, self.source_transport_port),
            SocketAddr::new(d_ip, self.destination_transport_port),
        ))
    }
}

/// Convert a flowscope [`crate::Timestamp`] to Unix
/// milliseconds — the wire form for IPFIX IEs 152/153.
///
/// Only used by [`FlowRecord::from_parts`] today; cfg-gated
/// on `tracker` to keep the `ipfix`-only build (no tracker /
/// no Timestamp consumer) free of dead-code warnings.
#[cfg(feature = "tracker")]
#[inline]
fn timestamp_to_unix_ms(ts: crate::Timestamp) -> u64 {
    let secs = ts.sec as u64;
    let ms_from_ns = (ts.nsec / 1_000_000) as u64;
    secs.saturating_mul(1000).saturating_add(ms_from_ns)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_record_is_all_zero_none() {
        let r = FlowRecord::default();
        assert_eq!(r.protocol_identifier, 0);
        assert_eq!(r.octet_total_count, 0);
        assert!(r.source_ipv4_address.is_none());
        assert!(r.source_ipv6_address.is_none());
        assert!(r.flow_end_reason.is_none());
    }

    #[test]
    fn observe_tcp_flags_accumulates_per_direction() {
        let mut r = FlowRecord::default();
        // First SYN from initiator.
        r.observe_tcp_flags(true, false, true, false, false, false, false, false, false);
        assert_eq!(r.tcp_control_bits_initiator, Some(0x02));
        assert!(r.tcp_control_bits_responder.is_none());

        // Later FIN+ACK from initiator — bits should OR in.
        r.observe_tcp_flags(true, true, false, false, false, true, false, false, false);
        // SYN | FIN | ACK = 0x02 | 0x01 | 0x10 = 0x13.
        assert_eq!(r.tcp_control_bits_initiator, Some(0x13));

        // Responder's flags populate the reverse slot.
        r.observe_tcp_flags(false, false, true, false, false, true, false, false, false);
        // SYN+ACK = 0x12.
        assert_eq!(r.tcp_control_bits_responder, Some(0x12));
    }

    #[test]
    fn sockets_recovers_v4_pair() {
        let r = FlowRecord {
            source_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            destination_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            source_transport_port: 1234,
            destination_transport_port: 80,
            ..FlowRecord::default()
        };
        let (s, d) = r.sockets().unwrap();
        assert_eq!(s.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(s.port(), 1234);
        assert_eq!(d.ip(), IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
        assert_eq!(d.port(), 80);
    }

    #[test]
    fn sockets_recovers_v6_pair() {
        let r = FlowRecord {
            source_ipv6_address: Some(Ipv6Addr::LOCALHOST),
            destination_ipv6_address: Some(Ipv6Addr::UNSPECIFIED),
            source_transport_port: 9999,
            destination_transport_port: 443,
            ..FlowRecord::default()
        };
        let (s, d) = r.sockets().unwrap();
        assert!(matches!(s.ip(), IpAddr::V6(_)));
        assert!(matches!(d.ip(), IpAddr::V6(_)));
    }

    #[test]
    fn sockets_returns_none_when_no_ip_populated() {
        let r = FlowRecord::default();
        assert!(r.sockets().is_none());
    }

    #[test]
    fn protocol_accessor_matches_field() {
        let r = FlowRecord {
            protocol_identifier: 6,
            ..FlowRecord::default()
        };
        assert_eq!(r.protocol(), 6);
    }

    #[cfg(feature = "tracker")]
    mod from_parts {
        use super::super::*;
        use crate::extractor::L4Proto;
        use crate::{EndReason, FlowStats, Timestamp};
        use std::net::{IpAddr, SocketAddr};

        fn make_v4_tcp_key() -> crate::extract::FiveTupleKey {
            crate::extract::FiveTupleKey {
                proto: L4Proto::Tcp,
                a: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234),
                b: SocketAddr::new(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), 80),
            }
        }

        fn make_stats() -> FlowStats {
            FlowStats {
                bytes_initiator: 1000,
                bytes_responder: 5000,
                packets_initiator: 10,
                packets_responder: 12,
                started: Timestamp::new(1, 500_000_000), // 1.5 s
                last_seen: Timestamp::new(5, 0),         // 5.0 s
                ..FlowStats::default()
            }
        }

        #[test]
        fn from_parts_populates_ipv4_fields() {
            let key = make_v4_tcp_key();
            let stats = make_stats();
            let r = FlowRecord::from_parts(&stats, &key, Some(EndReason::Fin));
            assert_eq!(r.protocol_identifier, 6);
            assert_eq!(r.source_ipv4_address, Some(Ipv4Addr::new(10, 0, 0, 1)));
            assert_eq!(r.destination_ipv4_address, Some(Ipv4Addr::new(10, 0, 0, 2)));
            assert!(r.source_ipv6_address.is_none());
            assert_eq!(r.source_transport_port, 1234);
            assert_eq!(r.destination_transport_port, 80);
        }

        #[test]
        fn from_parts_rolls_up_octets_and_packets() {
            let key = make_v4_tcp_key();
            let stats = make_stats();
            let r = FlowRecord::from_parts(&stats, &key, None);
            assert_eq!(r.octet_delta_count_initiator, 1000);
            assert_eq!(r.octet_delta_count_responder, 5000);
            assert_eq!(r.octet_total_count, 6000);
            assert_eq!(r.packet_total_count, 22);
        }

        #[test]
        fn from_parts_converts_timestamps_to_unix_ms() {
            let key = make_v4_tcp_key();
            let stats = make_stats();
            let r = FlowRecord::from_parts(&stats, &key, None);
            // 1.5 s → 1500 ms; 5.0 s → 5000 ms.
            assert_eq!(r.flow_start_milliseconds, 1500);
            assert_eq!(r.flow_end_milliseconds, 5000);
        }

        #[test]
        fn from_parts_maps_end_reason_to_ipfix_canonical() {
            let key = make_v4_tcp_key();
            let stats = make_stats();
            // Fin → EndOfFlowDetected (IPFIX IE 136 value = 3).
            let r = FlowRecord::from_parts(&stats, &key, Some(EndReason::Fin));
            assert_eq!(r.flow_end_reason, Some(FlowEndReason::EndOfFlowDetected));
            // Evicted → LackOfResources (value = 5).
            let r = FlowRecord::from_parts(&stats, &key, Some(EndReason::Evicted));
            assert_eq!(r.flow_end_reason, Some(FlowEndReason::LackOfResources));
            // IdleTimeout → IdleTimeout (value = 1).
            let r = FlowRecord::from_parts(&stats, &key, Some(EndReason::IdleTimeout));
            assert_eq!(r.flow_end_reason, Some(FlowEndReason::IdleTimeout));
        }

        #[test]
        fn from_parts_populates_app_name_from_known_port() {
            let key = make_v4_tcp_key();
            let stats = make_stats();
            let r = FlowRecord::from_parts(&stats, &key, None);
            // Port 80 → "http" via the well-known port table.
            assert_eq!(r.application_name.as_deref(), Some("http"));
        }
    }
}
