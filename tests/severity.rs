//! Plan 82 — `Severity` enum + `AnomalyKind::severity()`.
//! Every variant maps to the documented default; ordering
//! works for `>=` filter thresholds.

#![cfg(feature = "reassembler")]

use flowscope::event::{AnomalyKind, FlowSide, OverflowPolicy, Severity};

#[test]
fn severity_ordering_is_ascending() {
    assert!(Severity::Info < Severity::Warning);
    assert!(Severity::Warning < Severity::Error);
    assert!(Severity::Error < Severity::Critical);
    // Sanity: equality on the same variant.
    assert_eq!(Severity::Warning, Severity::Warning);
}

#[test]
fn severity_is_copy_and_hash() {
    fn assert_copy<T: Copy>() {}
    fn assert_hash<T: std::hash::Hash>() {}
    assert_copy::<Severity>();
    assert_hash::<Severity>();
}

#[test]
fn out_of_order_segment_defaults_info() {
    let kind = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 3,
    };
    assert_eq!(kind.severity(), Severity::Info);
}

#[test]
fn retransmitted_segment_defaults_info() {
    let kind = AnomalyKind::RetransmittedSegment {
        side: FlowSide::Responder,
        count: 1,
    };
    assert_eq!(kind.severity(), Severity::Info);
}

#[test]
fn buffer_overflow_defaults_warning() {
    let kind = AnomalyKind::BufferOverflow {
        side: FlowSide::Initiator,
        bytes: 1024,
        policy: OverflowPolicy::SlidingWindow,
    };
    assert_eq!(kind.severity(), Severity::Warning);
    // DropFlow policy maps the same way — the policy variation
    // is operator information, not severity.
    let kind = AnomalyKind::BufferOverflow {
        side: FlowSide::Initiator,
        bytes: 1024,
        policy: OverflowPolicy::DropFlow,
    };
    assert_eq!(kind.severity(), Severity::Warning);
}

#[test]
fn reassembler_high_watermark_defaults_warning() {
    let kind = AnomalyKind::ReassemblerHighWatermark {
        side: FlowSide::Initiator,
        bytes: 800,
        cap: 1000,
        threshold_pct: 80,
    };
    assert_eq!(kind.severity(), Severity::Warning);
}

#[test]
fn flow_table_eviction_pressure_defaults_warning() {
    let kind = AnomalyKind::FlowTableEvictionPressure {
        evicted_in_tick: 5,
        evicted_total: 42,
    };
    assert_eq!(kind.severity(), Severity::Warning);
}

#[test]
fn session_parse_error_defaults_error() {
    let kind = AnomalyKind::SessionParseError {
        side: FlowSide::Initiator,
        reason: Some("bad frame".into()),
    };
    assert_eq!(kind.severity(), Severity::Error);
}

#[test]
fn severity_display_renders_lowercase() {
    assert_eq!(format!("{}", Severity::Info), "info");
    assert_eq!(format!("{}", Severity::Warning), "warning");
    assert_eq!(format!("{}", Severity::Error), "error");
    assert_eq!(format!("{}", Severity::Critical), "critical");
}

#[test]
fn short_kind_matches_display() {
    // Plan 88: short_kind() returns the same string as Display.
    let kinds = [
        AnomalyKind::BufferOverflow {
            side: FlowSide::Initiator,
            bytes: 0,
            policy: OverflowPolicy::SlidingWindow,
        },
        AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        AnomalyKind::FlowTableEvictionPressure {
            evicted_in_tick: 1,
            evicted_total: 42,
        },
        AnomalyKind::SessionParseError {
            side: FlowSide::Initiator,
            reason: None,
        },
        AnomalyKind::RetransmittedSegment {
            side: FlowSide::Initiator,
            count: 2,
        },
        AnomalyKind::ReassemblerHighWatermark {
            side: FlowSide::Initiator,
            bytes: 800,
            cap: 1000,
            threshold_pct: 80,
        },
    ];
    for kind in &kinds {
        assert_eq!(kind.short_kind(), format!("{kind}"));
    }
}

#[test]
fn short_kind_is_static_str() {
    // Type-asserts the zero-allocation contract.
    let kind = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 1,
    };
    let _s: &'static str = kind.short_kind();
}

#[test]
fn severity_filter_threshold_works() {
    // Canonical operator pattern: route only Warning+ to alerts.
    let kinds = [
        AnomalyKind::OutOfOrderSegment {
            side: FlowSide::Initiator,
            count: 1,
        },
        AnomalyKind::BufferOverflow {
            side: FlowSide::Initiator,
            bytes: 1,
            policy: OverflowPolicy::SlidingWindow,
        },
        AnomalyKind::SessionParseError {
            side: FlowSide::Initiator,
            reason: None,
        },
    ];
    let high_sev: Vec<_> = kinds
        .iter()
        .filter(|k| k.severity() >= Severity::Warning)
        .collect();
    assert_eq!(high_sev.len(), 2); // BufferOverflow + SessionParseError
}
