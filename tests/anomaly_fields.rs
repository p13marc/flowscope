//! Plan 126 — `AnomalyFields` impls on `FiveTupleKey`,
//! `L4Proto`, and `AnomalyKind`.

#![cfg(all(feature = "extractors", feature = "tracker"))]

use std::net::IpAddr;

use flowscope::event::{AnomalyKind, FlowSide, OverflowPolicy};
use flowscope::extract::FiveTupleKey;
use flowscope::{AnomalyFields, L4Proto};

// ── L4Proto ───────────────────────────────────────────────────

#[test]
fn l4proto_tcp_returns_uppercase_tcp() {
    assert_eq!(L4Proto::Tcp.proto_str(), Some("TCP"));
}

#[test]
fn l4proto_udp_returns_uppercase_udp() {
    assert_eq!(L4Proto::Udp.proto_str(), Some("UDP"));
}

#[test]
fn l4proto_icmp_v4_and_v6() {
    assert_eq!(L4Proto::Icmp.proto_str(), Some("ICMP"));
    assert_eq!(L4Proto::IcmpV6.proto_str(), Some("ICMPv6"));
}

#[test]
fn l4proto_sctp() {
    assert_eq!(L4Proto::Sctp.proto_str(), Some("SCTP"));
}

#[test]
fn l4proto_other_returns_none() {
    assert_eq!(L4Proto::Other(47).proto_str(), None);
}

// ── FiveTupleKey ──────────────────────────────────────────────

fn key() -> FiveTupleKey {
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: "10.0.0.1:33000".parse().unwrap(),
        b: "10.0.0.2:80".parse().unwrap(),
    }
}

#[test]
fn five_tuple_key_returns_split_ip_port() {
    let k = key();
    assert_eq!(k.src_ip(), Some("10.0.0.1".parse::<IpAddr>().unwrap()));
    assert_eq!(k.src_port(), Some(33000));
    assert_eq!(k.dest_ip(), Some("10.0.0.2".parse::<IpAddr>().unwrap()));
    assert_eq!(k.dest_port(), Some(80));
    assert_eq!(k.proto_str(), Some("TCP"));
}

#[test]
fn five_tuple_key_app_proto_via_well_known_port() {
    // dest_port 80 → "http" per well_known.
    let k = key();
    assert_eq!(k.app_proto_str(), Some("http"));
}

#[test]
fn five_tuple_key_anomaly_fields_return_none_by_default() {
    // FiveTupleKey doesn't carry anomaly classification — that's
    // AnomalyKind's job.
    let k = key();
    assert_eq!(k.anomaly_type(), None);
    assert_eq!(k.anomaly_event(), None);
}

// ── AnomalyKind ───────────────────────────────────────────────

#[test]
fn anomaly_kind_buffer_overflow_classifies_as_stream() {
    let k = AnomalyKind::BufferOverflow {
        side: FlowSide::Initiator,
        bytes: 100,
        policy: OverflowPolicy::SlidingWindow,
    };
    assert_eq!(k.anomaly_type(), Some("stream"));
    assert_eq!(k.anomaly_event(), Some("buffer_overflow"));
}

#[test]
fn anomaly_kind_ooo_segment_classifies_as_stream() {
    let k = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 1,
    };
    assert_eq!(k.anomaly_type(), Some("stream"));
    assert_eq!(k.anomaly_event(), Some("ooo_segment"));
}

#[test]
fn anomaly_kind_session_parse_error_classifies_as_applayer() {
    let k = AnomalyKind::SessionParseError {
        side: FlowSide::Responder,
        reason: Some("bad frame".to_string()),
    };
    assert_eq!(k.anomaly_type(), Some("applayer"));
    assert_eq!(k.anomaly_event(), Some("parse_error"));
}

#[test]
fn anomaly_kind_flow_table_eviction_classifies_as_stream() {
    let k = AnomalyKind::FlowTableEvictionPressure {
        evicted_in_tick: 1,
        evicted_total: 42,
    };
    assert_eq!(k.anomaly_type(), Some("stream"));
    assert_eq!(k.anomaly_event(), Some("flow_table_eviction"));
}

#[test]
fn anomaly_kind_retransmit_classifies_as_stream() {
    let k = AnomalyKind::RetransmittedSegment {
        side: FlowSide::Initiator,
        count: 3,
    };
    assert_eq!(k.anomaly_type(), Some("stream"));
    assert_eq!(k.anomaly_event(), Some("retransmit"));
}

#[test]
fn anomaly_kind_reassembler_high_watermark_classifies_as_stream() {
    let k = AnomalyKind::ReassemblerHighWatermark {
        side: FlowSide::Initiator,
        bytes: 800,
        cap: 1000,
        threshold_pct: 80,
    };
    assert_eq!(k.anomaly_type(), Some("stream"));
    assert_eq!(k.anomaly_event(), Some("reassembler_high_watermark"));
}

#[test]
fn anomaly_event_matches_short_kind() {
    let k = AnomalyKind::BufferOverflow {
        side: FlowSide::Initiator,
        bytes: 100,
        policy: OverflowPolicy::SlidingWindow,
    };
    assert_eq!(k.anomaly_event(), Some(k.short_kind()));
}
