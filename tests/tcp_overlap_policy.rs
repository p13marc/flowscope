//! Issue #17 — byte-level TCP overlap-policy resolution.
//!
//! Models the Ptacek-Newsham (1998) overlap-evasion scenario:
//! two segments cover the same sequence range with different
//! content; the analyzer must reconstruct the bytes the same
//! way the target host would, or attackers smuggle content
//! past detection.

#![cfg(feature = "reassembler")]

use flowscope::{Reassembler, SegmentBufferReassembler, TcpOverlapPolicy, Timestamp};

fn ts(s: u32) -> Timestamp {
    Timestamp::new(s, 0)
}

/// Build a reassembler primed with an in-order anchor at seq=1000
/// so the OOO buffer is the only thing the rest of the test
/// touches.
fn primed(policy: TcpOverlapPolicy) -> SegmentBufferReassembler {
    let mut r = SegmentBufferReassembler::new().with_tcp_overlap_policy(policy);
    r.segment(1000, b"hello", ts(0));
    // After this, next_seq=1005; pending=empty; ready="hello".
    r
}

/// Set up an OOO pending entry at seq 1010 containing 5 bytes,
/// then arrive a second segment at seq 1010 covering the same
/// range with different content. Then fill the hole and drain.
fn run_exact_overlap(policy: TcpOverlapPolicy) -> Vec<u8> {
    let mut r = primed(policy);
    r.segment(1010, b"FIRST", ts(1));
    r.segment(1010, b"laTeR", ts(2));
    // Fill the hole 1005..1010.
    r.segment(1005, b"PAUSE", ts(3));
    // Drain.
    r.take()
}

#[test]
fn first_policy_keeps_earlier_arrived_bytes() {
    // Default behavior. First-arrived ("FIRST") wins the exact
    // overlap region.
    let out = run_exact_overlap(TcpOverlapPolicy::First);
    assert_eq!(out, b"helloPAUSEFIRST");
}

#[test]
fn last_policy_uses_later_arrived_bytes() {
    let out = run_exact_overlap(TcpOverlapPolicy::Last);
    assert_eq!(out, b"helloPAUSElaTeR");
}

#[test]
fn lower_seq_policy_with_exact_overlap_keeps_first_inserted() {
    // Both segments have the same start seq (1010), so the
    // lower-seq policy can't distinguish. The first one
    // inserted wins by stability (no overwrite when equal).
    let out = run_exact_overlap(TcpOverlapPolicy::LowerSeq);
    assert_eq!(out, b"helloPAUSEFIRST");
}

#[test]
fn higher_seq_policy_with_exact_overlap_keeps_first_inserted() {
    let out = run_exact_overlap(TcpOverlapPolicy::HigherSeq);
    assert_eq!(out, b"helloPAUSEFIRST");
}

#[test]
fn partial_overlap_lower_seq_keeps_lower_starting_segment() {
    // Pending at 1010..1015 = "AAAAA"; new at 1012..1017 = "BBBBB".
    // Overlap is 1012..1015 (3 bytes). LowerSeq policy keeps
    // the bytes from start=1010 (lower start) for the overlap.
    let mut r = primed(TcpOverlapPolicy::LowerSeq);
    r.segment(1010, b"AAAAA", ts(1));
    r.segment(1012, b"BBBBB", ts(2));
    // Fill 1005..1010.
    r.segment(1005, b"-----", ts(3));
    // Drain — union range is 1010..1017 = 7 bytes:
    //   1010..1012: from existing (lower seq) — "AA"
    //   1012..1015: overlap, lower-seq wins — "AAA"
    //   1015..1017: from new only — "BB"
    let out = r.take();
    assert_eq!(out, b"hello-----AAAAABB");
}

#[test]
fn partial_overlap_higher_seq_keeps_higher_starting_segment() {
    // Same shape — HigherSeq policy this time. Overlap bytes
    // come from start=1012 (higher start).
    let mut r = primed(TcpOverlapPolicy::HigherSeq);
    r.segment(1010, b"AAAAA", ts(1));
    r.segment(1012, b"BBBBB", ts(2));
    r.segment(1005, b"-----", ts(3));
    // 1010..1012 from existing: "AA"
    // 1012..1015 overlap, higher-seq wins: "BBB"
    // 1015..1017 from new: "BB"
    let out = r.take();
    assert_eq!(out, b"hello-----AABBBBB");
}

#[test]
fn partial_overlap_first_policy_takes_existing_in_overlap() {
    // 1010..1015 "AAAAA" arrived first; new 1012..1017 "BBBBB".
    // First policy: existing bytes win overlap (1012..1015).
    let mut r = primed(TcpOverlapPolicy::First);
    r.segment(1010, b"AAAAA", ts(1));
    r.segment(1012, b"BBBBB", ts(2));
    r.segment(1005, b"-----", ts(3));
    // 1010..1012 from existing: "AA"
    // 1012..1015 overlap, first wins: "AAA"
    // 1015..1017 from new: "BB"
    let out = r.take();
    assert_eq!(out, b"hello-----AAAAABB");
}

#[test]
fn partial_overlap_last_policy_takes_new_in_overlap() {
    let mut r = primed(TcpOverlapPolicy::Last);
    r.segment(1010, b"AAAAA", ts(1));
    r.segment(1012, b"BBBBB", ts(2));
    r.segment(1005, b"-----", ts(3));
    // 1010..1012 from existing: "AA"
    // 1012..1015 overlap, last wins: "BBB"
    // 1015..1017 from new: "BB"
    let out = r.take();
    assert_eq!(out, b"hello-----AABBBBB");
}

#[test]
fn divergent_overlap_increments_inconsistency_counter() {
    // The signal fires regardless of policy choice (a passive
    // analyzer must surface the divergence even if it picks a
    // side for reassembly).
    for policy in [
        TcpOverlapPolicy::First,
        TcpOverlapPolicy::Last,
        TcpOverlapPolicy::LowerSeq,
        TcpOverlapPolicy::HigherSeq,
    ] {
        let mut r = primed(policy);
        r.segment(1010, b"FIRST", ts(1));
        r.segment(1010, b"laTeR", ts(2));
        assert_eq!(
            r.rexmit_inconsistencies(),
            1,
            "policy {policy:?} should still flag divergence"
        );
    }
}

#[test]
fn identical_overlap_does_not_increment_inconsistency() {
    // Pure retransmit (same bytes) is benign.
    let mut r = primed(TcpOverlapPolicy::First);
    r.segment(1010, b"hello", ts(1));
    r.segment(1010, b"hello", ts(2));
    assert_eq!(r.rexmit_inconsistencies(), 0);
}

#[test]
fn overlap_policy_default_is_first() {
    // The non-policy `new()` constructor selects the BSD
    // default to match Suricata's OS_POLICY_DEFAULT = BSD.
    let r = SegmentBufferReassembler::new();
    assert_eq!(r.tcp_overlap_policy(), TcpOverlapPolicy::First);
}

#[test]
fn overlap_policy_round_trip_via_with_builder() {
    let r = SegmentBufferReassembler::new().with_tcp_overlap_policy(TcpOverlapPolicy::Last);
    assert_eq!(r.tcp_overlap_policy(), TcpOverlapPolicy::Last);
}

#[test]
fn slug_vocabulary_locked() {
    // Downstream metric pipelines depend on these.
    assert_eq!(TcpOverlapPolicy::First.as_str(), "first");
    assert_eq!(TcpOverlapPolicy::Last.as_str(), "last");
    assert_eq!(TcpOverlapPolicy::LowerSeq.as_str(), "lower_seq");
    assert_eq!(TcpOverlapPolicy::HigherSeq.as_str(), "higher_seq");
}
