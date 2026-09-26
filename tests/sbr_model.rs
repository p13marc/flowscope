//! Property test (issue #184): `SegmentBufferReassembler` delivers
//! exactly what a naive per-byte model delivers, under every
//! `TcpOverlapPolicy`, for arbitrary overlapping / reordered
//! segments.

use std::collections::BTreeMap;

use flowscope::{Reassembler, SegmentBufferReassembler, StreamChunks, TcpOverlapPolicy, Timestamp};
use proptest::prelude::*;

const BASE: u32 = 0xffff_ff00; // exercises sequence wrap too

/// Per-byte reference: bytes past the stream position are held with
/// the start offset of the segment that supplied them; bytes behind
/// it are gone. The flush at the end skips the holes.
fn model(policy: TcpOverlapPolicy, segs: &[(u64, Vec<u8>)]) -> (Vec<u8>, u64) {
    let mut next = 0u64;
    let mut held: BTreeMap<u64, (u8, u64)> = BTreeMap::new();
    let mut out = Vec::new();
    for (start, data) in segs {
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
        while let Some(&(b, _)) = held.get(&next) {
            held.remove(&next);
            out.push(b);
            next += 1;
        }
    }
    let mut gap = 0;
    for (off, (b, _)) in held {
        gap += off - next;
        out.push(b);
        next = off + 1;
    }
    (out, gap)
}

fn run(policy: TcpOverlapPolicy, segs: &[(u64, Vec<u8>)]) -> (Vec<u8>, u64) {
    let mut r = SegmentBufferReassembler::new()
        .with_tcp_overlap_policy(policy)
        .with_max_ooo_buffer(usize::MAX / 2)
        .with_max_ahead(1 << 40);
    r.set_origin(BASE);
    let ts = Timestamp::new(1, 0);
    for (start, data) in segs {
        r.segment(BASE.wrapping_add(*start as u32), data, ts);
    }
    r.flush_pending();
    let mut out = StreamChunks::new();
    r.drain_into(&mut out);
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

fn segments() -> impl Strategy<Value = Vec<(u64, Vec<u8>)>> {
    proptest::collection::vec(
        (0u64..200, proptest::collection::vec(any::<u8>(), 1..24)),
        1..40,
    )
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn sbr_matches_naive_model(policy in policies(), segs in segments()) {
        prop_assert_eq!(run(policy, &segs), model(policy, &segs));
    }
}
