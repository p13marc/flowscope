//! Plan 126 + 130 — `AnomalyFields` impl on `AnomalyKind`.
//!
//! Plan 130 split `KeyFields` out of `AnomalyFields`; this
//! file now covers only the `AnomalyKind` anomaly-classification
//! surface. The key-field tests moved to
//! [`tests/key_fields.rs`].

#![cfg(all(feature = "extractors", feature = "tracker"))]

use flowscope::AnomalyFields;
use flowscope::event::{AnomalyKind, FlowSide, OverflowPolicy};

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
