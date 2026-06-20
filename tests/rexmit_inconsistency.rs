//! Issue #17 sub-piece — rexmit_inconsistency signal.
//!
//! Verifies that [`flowscope::SegmentBufferReassembler`] detects
//! Ptacek-Newsham TCP overlap evasion: a new segment whose bytes
//! disagree with bytes already pending in the OOO buffer for the
//! same sequence range.

#![cfg(feature = "reassembler")]

use flowscope::{Reassembler, SegmentBufferReassembler, Timestamp};

fn ts(s: u32) -> Timestamp {
    Timestamp::new(s, 0)
}

#[test]
fn no_overlap_no_inconsistency() {
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1005, b" world", ts(0));
    assert_eq!(r.rexmit_inconsistencies(), 0);
}

#[test]
fn ooo_segment_with_matching_overlap_is_not_an_inconsistency() {
    // Original at 1000 establishes ISN; OOO at 1010; retransmit of
    // the same OOO range with the same bytes — no inconsistency.
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1010, b"world", ts(1));
    r.segment(1010, b"world", ts(2)); // exact retransmit
    assert_eq!(r.rexmit_inconsistencies(), 0);
}

#[test]
fn ooo_segment_with_diverging_overlap_is_an_inconsistency() {
    // Classic overlap-evasion shape: original OOO bytes don't
    // match the retransmit at the same seq range.
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1010, b"world", ts(1));
    r.segment(1010, b"WORLD", ts(2)); // diverging
    assert_eq!(r.rexmit_inconsistencies(), 1);
}

#[test]
fn partial_overlap_with_diverging_bytes_fires() {
    // Pending segment at 1010 covers 1010..1015 ("world"). A new
    // segment at 1012 covers 1012..1017 ("xyz12"), overlapping
    // 1012..1015. Bytes there are "rld" in the original vs "xyz"
    // in the new — divergent.
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1010, b"world", ts(1));
    r.segment(1012, b"xyz12", ts(2));
    assert_eq!(r.rexmit_inconsistencies(), 1);
}

#[test]
fn partial_overlap_with_matching_bytes_does_not_fire() {
    // Same partial-overlap shape but the overlapping bytes match.
    // Pending: 1010..1015 = "world"; new: 1012..1017 = "rldXY"
    // overlaps "rld" — matches.
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1010, b"world", ts(1));
    r.segment(1012, b"rldXY", ts(2));
    assert_eq!(r.rexmit_inconsistencies(), 0);
}

#[test]
fn multiple_diverging_segments_count_independently() {
    let mut r = SegmentBufferReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1010, b"world", ts(1));
    r.segment(1010, b"WORLD", ts(2));
    r.segment(1020, b"abcde", ts(3));
    r.segment(1020, b"ABCDE", ts(4));
    assert_eq!(r.rexmit_inconsistencies(), 2);
}

#[test]
fn trait_default_returns_zero_for_buffered_reassembler() {
    // The simpler `BufferedReassembler` doesn't retain history
    // and inherits the trait's `rexmit_inconsistencies() = 0`
    // default.
    let mut r = flowscope::BufferedReassembler::new();
    r.segment(1000, b"hello", ts(0));
    r.segment(1000, b"WORLD", ts(1));
    // Counts as a retransmit but NOT as an inconsistency, because
    // the simpler reassembler doesn't see the divergence.
    assert!(r.retransmits() > 0);
    assert_eq!(r.rexmit_inconsistencies(), 0);
}

#[test]
fn anomaly_kind_variant_has_stable_slug() {
    use flowscope::{AnomalyKind, FlowSide};
    let k = AnomalyKind::TcpRexmitInconsistency {
        side: FlowSide::Initiator,
        count: 3,
    };
    assert_eq!(k.short_kind(), "tcp_rexmit_inconsistency");
}

#[test]
fn anomaly_severity_is_error_not_info() {
    use flowscope::event::Severity;
    use flowscope::{AnomalyKind, FlowSide};
    let k = AnomalyKind::TcpRexmitInconsistency {
        side: FlowSide::Initiator,
        count: 1,
    };
    // Distinct from RetransmittedSegment (Info) — divergent
    // bytes are an IOC, not benign.
    assert_eq!(k.severity(), Severity::Error);
}
