//! Plan 77 — `Display` impls on `L4Proto`, `EndReason`,
//! `AnomalyKind`. Every variant rendered, every render matches the
//! corresponding metric-label vocabulary. The cross-check tests
//! pin Display and the metric labels together so any future drift
//! fires at test time.

#![cfg(feature = "tracker")]

use flowscope::{event::EndReason, extractor::L4Proto};

#[test]
fn display_l4proto_renders_every_variant() {
    assert_eq!(format!("{}", L4Proto::Tcp), "tcp");
    assert_eq!(format!("{}", L4Proto::Udp), "udp");
    assert_eq!(format!("{}", L4Proto::Icmp), "other");
    assert_eq!(format!("{}", L4Proto::IcmpV6), "other");
    assert_eq!(format!("{}", L4Proto::Sctp), "other");
    assert_eq!(format!("{}", L4Proto::Other(99)), "other");
}

#[test]
fn display_endreason_renders_every_variant() {
    assert_eq!(format!("{}", EndReason::Fin), "fin");
    assert_eq!(format!("{}", EndReason::Rst), "rst");
    assert_eq!(format!("{}", EndReason::IdleTimeout), "idle");
    assert_eq!(format!("{}", EndReason::Evicted), "evicted");
    assert_eq!(format!("{}", EndReason::BufferOverflow), "buffer_overflow");
    assert_eq!(format!("{}", EndReason::ParseError), "parse_error");
}

#[cfg(feature = "reassembler")]
#[test]
fn display_anomalykind_renders_every_variant() {
    use flowscope::event::{AnomalyKind, FlowSide, OverflowPolicy};

    assert_eq!(
        format!(
            "{}",
            AnomalyKind::BufferOverflow {
                side: FlowSide::Initiator,
                bytes: 0,
                policy: OverflowPolicy::SlidingWindow,
            }
        ),
        "buffer_overflow"
    );
    assert_eq!(
        format!(
            "{}",
            AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Responder,
                count: 1,
            }
        ),
        "ooo_segment"
    );
    assert_eq!(
        format!(
            "{}",
            AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 42,
            }
        ),
        "flow_table_eviction"
    );
    assert_eq!(
        format!(
            "{}",
            AnomalyKind::SessionParseError {
                side: FlowSide::Initiator,
                reason: None,
            }
        ),
        "parse_error"
    );
    assert_eq!(
        format!(
            "{}",
            AnomalyKind::RetransmittedSegment {
                side: FlowSide::Initiator,
                count: 2,
            }
        ),
        "retransmit"
    );
    assert_eq!(
        format!(
            "{}",
            AnomalyKind::ReassemblerHighWatermark {
                side: FlowSide::Initiator,
                bytes: 800,
                cap: 1000,
                threshold_pct: 80,
            }
        ),
        "reassembler_high_watermark"
    );
}

// ── Format-context smoke tests ────────────────────────────────────
//
// Catch the failure mode where Display works in isolation but
// gets dropped inside `write!` (e.g. via a missing Display
// trait import elsewhere).

#[test]
fn display_l4proto_in_format_arg() {
    let l4 = L4Proto::Tcp;
    let s = format!("flow over {l4}");
    assert_eq!(s, "flow over tcp");
}

#[test]
fn display_endreason_in_format_arg() {
    let reason = EndReason::IdleTimeout;
    let s = format!("ended: {reason}");
    assert_eq!(s, "ended: idle");
}
