//! Property test (issue #184): `SegmentBufferReassembler` delivers
//! exactly what a naive per-byte model delivers, under every
//! `TcpOverlapPolicy`, for arbitrary overlapping / reordered
//! segments — and (#212) for bytes a snap length cut
//! ([`Reassembler::missing`]).

use std::collections::BTreeMap;

use flowscope::{Reassembler, SegmentBufferReassembler, StreamChunks, TcpOverlapPolicy, Timestamp};
use proptest::prelude::*;

const BASE: u32 = 0xffff_ff00; // exercises sequence wrap too

#[derive(Debug, Clone)]
enum Op {
    /// A captured segment at this stream offset.
    Seg(u64, Vec<u8>),
    /// `len` bytes at this stream offset were on the wire, not in the
    /// capture.
    Missing(u64, u32),
}

/// Per-byte reference: bytes past the stream position are held with
/// the start offset of the segment that supplied them; bytes behind
/// it are gone. Missing bytes the stream has reached are skipped at
/// once (held bytes among them are delivered); missing bytes past a
/// hole only prove the stream reaches their end. The flush at the end
/// skips the holes, then up to the furthest proof.
fn model(policy: TcpOverlapPolicy, ops: &[Op]) -> (Vec<u8>, u64) {
    let mut next = 0u64;
    let mut held: BTreeMap<u64, (u8, u64)> = BTreeMap::new();
    let mut out = Vec::new();
    let mut gap = 0u64;
    let mut evidence = 0u64;
    for op in ops {
        match op {
            Op::Seg(start, data) => {
                for (i, &b) in data.iter().enumerate() {
                    let off = start + i as u64;
                    if off < next {
                        continue;
                    }
                    match held.get(&off) {
                        None => {
                            held.insert(off, (b, *start));
                        }
                        Some(&(_, seg)) => {
                            let wins = match policy {
                                TcpOverlapPolicy::Last => true,
                                TcpOverlapPolicy::LowerSeq => *start < seg,
                                TcpOverlapPolicy::HigherSeq => *start > seg,
                                _ => false,
                            };
                            if wins {
                                held.insert(off, (b, *start));
                            }
                        }
                    }
                }
            }
            Op::Missing(start, len) => {
                let end = start + u64::from(*len);
                if *len == 0 || end <= next {
                    continue;
                }
                if *start <= next {
                    while next < end {
                        match held.remove(&next) {
                            Some((b, _)) => out.push(b),
                            None => gap += 1,
                        }
                        next += 1;
                    }
                } else {
                    evidence = evidence.max(end);
                }
            }
        }
        while let Some(&(b, _)) = held.get(&next) {
            held.remove(&next);
            out.push(b);
            next += 1;
        }
    }
    for (off, (b, _)) in held {
        gap += off - next;
        out.push(b);
        next = off + 1;
    }
    if evidence > next {
        gap += evidence - next;
    }
    (out, gap)
}

fn run(policy: TcpOverlapPolicy, ops: &[Op]) -> (Vec<u8>, u64) {
    let mut r = SegmentBufferReassembler::new()
        .with_tcp_overlap_policy(policy)
        .with_max_ooo_buffer(usize::MAX / 2)
        .with_max_ahead(1 << 40);
    r.set_origin(BASE);
    let ts = Timestamp::new(1, 0);
    for op in ops {
        match op {
            Op::Seg(start, data) => r.segment(BASE.wrapping_add(*start as u32), data, ts),
            Op::Missing(start, len) => r.missing(BASE.wrapping_add(*start as u32), *len, ts),
        }
    }
    r.flush_pending();
    let mut out = StreamChunks::new();
    r.drain_into(&mut out);
    assert_eq!(out.gap_bytes(), r.gap_bytes(), "gap counter = gap marks");
    (out.data().to_vec(), out.gap_bytes())
}

fn policies() -> impl Strategy<Value = TcpOverlapPolicy> {
    prop_oneof![
        Just(TcpOverlapPolicy::First),
        Just(TcpOverlapPolicy::Last),
        Just(TcpOverlapPolicy::LowerSeq),
        Just(TcpOverlapPolicy::HigherSeq),
    ]
}

fn segment() -> impl Strategy<Value = Op> {
    (0u64..200, proptest::collection::vec(any::<u8>(), 1..24)).prop_map(|(s, d)| Op::Seg(s, d))
}

fn segments() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(segment(), 1..40)
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    proptest::collection::vec(
        prop_oneof![
            4 => segment(),
            1 => (0u64..200, 0u32..40).prop_map(|(s, l)| Op::Missing(s, l)),
        ],
        1..40,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn sbr_matches_naive_model(policy in policies(), segs in segments()) {
        prop_assert_eq!(run(policy, &segs), model(policy, &segs));
    }

    /// #212: cut bytes are skipped where the stream reaches them and
    /// never held back, around reordered and overlapping segments.
    #[test]
    fn sbr_with_missing_bytes_matches_naive_model(policy in policies(), ops in ops()) {
        prop_assert_eq!(run(policy, &ops), model(policy, &ops));
    }
}
