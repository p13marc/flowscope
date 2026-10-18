//! Property tests for the built-in reassemblers.
//!
//! * Exact models (#184, #212): with one packet time (no deadline or
//!   ACK grace runs out) and no window limit, `SegmentBufferReassembler`
//!   under every `TcpOverlapPolicy`, and `BufferedReassembler`, place
//!   every byte and every gap where a naive per-byte model does: for
//!   overlapping / reordered segments, bytes a snap length cut
//!   ([`Reassembler::missing`]), the peer's ACKs and this side's FIN,
//!   across sequence wrap.
//! * Invariants: with packet times that run out the ACK grace and the
//!   reorder deadlines, a small `max_ahead` (strays, resyncs), a small
//!   out-of-order cap and drains in between, each delivered byte is
//!   one a segment carried at that stream offset, the stream never
//!   runs past what was seen or proven (nor, without a window limit,
//!   stops short of a segment), the gap counter equals the gap marks
//!   and nothing is held after `flush_pending`.

#![cfg(feature = "reassembler")]

use std::collections::{BTreeMap, HashMap};
use std::time::Duration;

use flowscope::{
    BufferedReassembler, Chunk, Reassembler, SegmentBufferReassembler, StreamChunks,
    TcpOverlapPolicy, Timestamp, reassembler::SegmentOutcome,
};
use proptest::prelude::*;

#[derive(Debug, Clone)]
enum Op {
    /// A captured segment at this stream offset.
    Seg(u64, Vec<u8>),
    /// `len` bytes at this stream offset were on the wire, not in the
    /// capture.
    Missing(u64, u32),
    /// The peer acknowledged up to this stream offset.
    Ack(u64),
    /// This side's FIN at this stream offset.
    Fin(u64),
}

/// The stream as placed: `Some(byte)` or `None` (a gap) per stream
/// offset from the origin.
type Placed = Vec<Option<u8>>;

fn placed(c: &StreamChunks) -> Placed {
    let mut v = Vec::new();
    for chunk in c.iter() {
        match chunk {
            Chunk::Data(d) => v.extend(d.iter().map(|&b| Some(b))),
            Chunk::Gap(n) => v.resize(v.len() + n as usize, None),
        }
    }
    v
}

/// What ACKs, FINs and cut bytes past a hole prove: the stream
/// reaches `evidence`, but never past this side's FIN. Proof behind
/// the stream position is void.
#[derive(Default)]
struct Proof {
    evidence: u64,
    fin: Option<u64>,
}

impl Proof {
    fn reach(&mut self, next: u64, off: i64) {
        if off <= next as i64 {
            return;
        }
        let off = self.fin.map_or(off as u64, |f| f.min(off as u64));
        if off > next {
            self.evidence = self.evidence.max(off);
        }
    }

    fn fin(&mut self, next: u64, off: u64) {
        if off < next {
            return;
        }
        self.fin = Some(off);
        self.evidence = self.evidence.min(off);
        self.reach(next, off as i64);
    }

    /// An ACK covers this side's FIN too: it proves one byte less.
    fn ack(&mut self, next: u64, ack: u64) {
        self.reach(next, ack as i64 - 1);
    }
}

/// Per-byte reference for `SegmentBufferReassembler`: bytes past the
/// stream position are held with the start offset of the segment that
/// supplied them; bytes behind it are gone. Missing bytes the stream
/// has reached are skipped at once (held bytes among them are
/// delivered); missing bytes past a hole only prove the stream reaches
/// their end, as ACKs and the FIN do. The flush at the end skips the
/// holes, then up to the proof.
fn sbr_model(policy: TcpOverlapPolicy, ops: &[Op]) -> Placed {
    let mut held: BTreeMap<u64, (u8, u64)> = BTreeMap::new();
    let mut out: Placed = Vec::new();
    let mut proof = Proof::default();
    for op in ops {
        let next = out.len() as u64;
        match op {
            Op::Seg(start, data) => {
                for (i, &b) in data.iter().enumerate() {
                    let off = start + i as u64;
                    if off < next {
                        continue;
                    }
                    let wins = match held.get(&off) {
                        None => true,
                        Some(&(_, seg)) => match policy {
                            TcpOverlapPolicy::Last => true,
                            TcpOverlapPolicy::LowerSeq => *start < seg,
                            TcpOverlapPolicy::HigherSeq => *start > seg,
                            _ => false,
                        },
                    };
                    if wins {
                        held.insert(off, (b, *start));
                    }
                }
            }
            Op::Missing(start, len) => {
                let end = start + u64::from(*len);
                if *len == 0 || end <= next {
                    continue;
                }
                if *start <= next {
                    while (out.len() as u64) < end {
                        let at = out.len() as u64;
                        out.push(held.remove(&at).map(|(b, _)| b));
                    }
                } else {
                    proof.reach(next, end as i64);
                }
            }
            Op::Ack(ack) => proof.ack(next, *ack),
            Op::Fin(off) => proof.fin(next, *off),
        }
        while let Some((b, _)) = held.remove(&(out.len() as u64)) {
            out.push(Some(b));
        }
    }
    for (off, (b, _)) in held {
        out.resize(off as usize, None);
        out.push(Some(b));
    }
    if proof.evidence > out.len() as u64 {
        out.resize(proof.evidence as usize, None);
    }
    out
}

/// Reference for `BufferedReassembler`: one segment ahead of the
/// stream waits for the hole in front of it; a second one gives that
/// hole up (a gap, then the waiting segment). Otherwise as
/// [`sbr_model`].
#[derive(Default)]
struct BufferedModel {
    out: Placed,
    waiting: Option<(u64, Vec<u8>)>,
    proof: Proof,
}

impl BufferedModel {
    fn next(&self) -> u64 {
        self.out.len() as u64
    }

    fn skip_to(&mut self, to: u64) {
        if to > self.next() {
            self.out.resize(to as usize, None);
        }
    }

    /// Bytes from `off` (at or behind the stream position) on.
    fn deliver(&mut self, off: u64, data: &[u8]) {
        for (i, &b) in data.iter().enumerate() {
            if off + i as u64 == self.next() {
                self.out.push(Some(b));
            }
        }
    }

    fn give_up(&mut self) {
        if let Some((off, data)) = self.waiting.take() {
            self.skip_to(off);
            self.deliver(off, &data);
        }
    }

    fn reached(&mut self) {
        if self.waiting.as_ref().is_some_and(|w| w.0 <= self.next()) {
            let (off, data) = self.waiting.take().expect("checked");
            self.deliver(off, &data);
        }
    }

    fn segment(&mut self, start: u64, data: &[u8]) {
        if start + data.len() as u64 <= self.next() {
            return;
        }
        if start > self.next() {
            if self.waiting.is_some() {
                self.give_up();
                return self.segment(start, data);
            }
            self.waiting = Some((start, data.to_vec()));
            return;
        }
        self.deliver(start, data);
        self.reached();
    }

    fn missing(&mut self, start: u64, len: u32) {
        let end = start + u64::from(len);
        if len == 0 || end <= self.next() {
            return;
        }
        if start > self.next() {
            let next = self.next();
            self.proof.reach(next, end as i64);
            return;
        }
        while self.next() < end {
            let to = self.waiting.as_ref().map_or(end, |w| w.0.min(end));
            self.skip_to(to);
            self.reached();
        }
    }

    fn run(ops: &[Op]) -> Placed {
        let mut m = Self::default();
        for op in ops {
            let next = m.next();
            match op {
                Op::Seg(start, data) => m.segment(*start, data),
                Op::Missing(start, len) => m.missing(*start, *len),
                Op::Ack(ack) => m.proof.ack(next, *ack),
                Op::Fin(off) => m.proof.fin(next, *off),
            }
        }
        m.give_up();
        let evidence = m.proof.evidence;
        m.skip_to(evidence);
        m.out
    }
}

fn run(r: &mut dyn Reassembler, base: u32, ops: &[Op]) -> Placed {
    let seq = |off: u64| base.wrapping_add(off as u32);
    r.set_origin(base);
    let ts = Timestamp::new(1, 0);
    for op in ops {
        match op {
            Op::Seg(start, data) => r.segment(seq(*start), data, ts),
            Op::Missing(start, len) => r.missing(seq(*start), *len, ts),
            Op::Ack(ack) => r.peer_ack(seq(*ack), ts),
            Op::Fin(off) => r.fin_seen(seq(*off), ts),
        }
    }
    r.flush_pending();
    let mut out = StreamChunks::new();
    r.drain_into(&mut out);
    assert_eq!(out.gap_bytes(), r.gap_bytes(), "gap counter = gap marks");
    placed(&out)
}

fn sbr(policy: TcpOverlapPolicy) -> SegmentBufferReassembler {
    SegmentBufferReassembler::new()
        .with_tcp_overlap_policy(policy)
        .with_max_ooo_buffer(usize::MAX / 2)
        .with_max_ahead(1 << 40)
}

fn policies() -> impl Strategy<Value = TcpOverlapPolicy> {
    prop_oneof![
        Just(TcpOverlapPolicy::First),
        Just(TcpOverlapPolicy::Last),
        Just(TcpOverlapPolicy::LowerSeq),
        Just(TcpOverlapPolicy::HigherSeq),
    ]
}

/// Initial sequence numbers: mostly just below the wrap, so the
/// stream crosses it.
fn bases() -> impl Strategy<Value = u32> {
    prop_oneof![3 => (u32::MAX - 250)..=u32::MAX, 1 => any::<u32>()]
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
            8 => segment(),
            2 => (0u64..200, 0u32..40).prop_map(|(s, l)| Op::Missing(s, l)),
            1 => (0u64..240).prop_map(Op::Ack),
            1 => (0u64..240).prop_map(Op::Fin),
        ],
        1..40,
    )
}

/// Byte a truthful segment carries at stream offset `off`.
fn truth(off: i64) -> u8 {
    ((off as u64).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 56) as u8
}

#[derive(Debug, Clone)]
enum Step {
    /// A segment; `true`: through `Reassembler::segment_into`, taking
    /// a passthrough as delivered.
    Seg(i64, Vec<u8>, bool),
    Missing(i64, u32),
    Ack(i64),
    Fin(i64),
    /// `Reassembler::advance_time`.
    Tick,
    /// Drain the ready output (the checks see all drains together).
    Drain,
}

#[derive(Debug, Clone)]
enum Raw {
    Seg(i64, usize, Option<Vec<u8>>, bool),
    Missing(i64, u32),
    Ack(i64),
    Fin(i64),
    Tick,
    Drain,
}

/// Offsets relative to the end of the previous segment (or cut
/// range): mostly near it — reordering, overlap, small holes — now
/// and then far away.
fn delta() -> impl Strategy<Value = i64> {
    prop_oneof![8 => -40i64..60, 1 => -400i64..400]
}

/// Steps with the time (µs) since the previous one: below and above
/// the 10 ms ACK grace, the 50 ms reorder deadline and four of them,
/// and now and then backwards.
fn steps() -> impl Strategy<Value = Vec<(i64, Step)>> {
    let dt = prop_oneof![
        6 => Just(0i64),
        3 => Just(1_000),
        2 => Just(15_000),
        2 => Just(60_000),
        1 => Just(250_000),
        1 => Just(-30_000),
    ];
    let noise = proptest::option::weighted(0.2, proptest::collection::vec(any::<u8>(), 24));
    let raw = prop_oneof![
        10 => (delta(), 1usize..24, noise, any::<bool>())
            .prop_map(|(d, l, noise, pass)| Raw::Seg(d, l, noise, pass)),
        2 => (delta(), 0u32..40).prop_map(|(d, l)| Raw::Missing(d, l)),
        2 => delta().prop_map(Raw::Ack),
        1 => delta().prop_map(Raw::Fin),
        1 => Just(Raw::Tick),
        1 => Just(Raw::Drain),
    ];
    proptest::collection::vec((dt, raw), 1..60).prop_map(|raw| {
        let mut cursor = 0i64;
        raw.into_iter()
            .map(|(dt, r)| {
                let step = match r {
                    Raw::Seg(d, len, noise, pass) => {
                        let off = cursor + d;
                        cursor = off + len as i64;
                        let data = match noise {
                            Some(v) => v[..len].to_vec(),
                            None => (off..cursor).map(truth).collect(),
                        };
                        Step::Seg(off, data, pass)
                    }
                    Raw::Missing(d, len) => {
                        let off = cursor + d;
                        cursor = off + i64::from(len);
                        Step::Missing(off, len)
                    }
                    Raw::Ack(d) => Step::Ack(cursor + d),
                    Raw::Fin(d) => Step::Fin(cursor + d),
                    Raw::Tick => Step::Tick,
                    Raw::Drain => Step::Drain,
                };
                (dt, step)
            })
            .collect()
    })
}

#[derive(Debug, Clone, Copy)]
enum Kind {
    Buffered,
    Segment(TcpOverlapPolicy, usize),
}

fn kinds() -> impl Strategy<Value = Kind> {
    let caps = prop_oneof![Just(0usize), Just(200), Just(4096), Just(usize::MAX / 2)];
    prop_oneof![
        1 => Just(Kind::Buffered),
        3 => (policies(), caps).prop_map(|(p, cap)| Kind::Segment(p, cap)),
    ]
}

const GRACE: Duration = Duration::from_millis(10);
const DEADLINE: Duration = Duration::from_millis(50);

fn build(kind: Kind, max_ahead: u64) -> Box<dyn Reassembler> {
    match kind {
        Kind::Buffered => Box::new(
            BufferedReassembler::new()
                .with_max_ahead(max_ahead)
                .with_ack_grace(GRACE)
                .with_reorder_deadline(DEADLINE),
        ),
        Kind::Segment(policy, cap) => Box::new(
            SegmentBufferReassembler::new()
                .with_tcp_overlap_policy(policy)
                .with_max_ooo_buffer(cap)
                .with_max_ahead(max_ahead)
                .with_ack_grace(GRACE)
                .with_ooo_deadline(DEADLINE),
        ),
    }
}

fn check_invariants(
    kind: Kind,
    max_ahead: u64,
    base: u32,
    origin: bool,
    steps: &[(i64, Step)],
) -> Result<(), TestCaseError> {
    let seq = |off: i64| base.wrapping_add(off as u32);
    let mut r = build(kind, max_ahead);
    if origin {
        r.set_origin(base);
    }
    // The stream offset the output starts at.
    let mut anchor = origin.then_some(0i64);
    let mut offered: HashMap<i64, Vec<u8>> = HashMap::new();
    let mut proven = i64::MIN;
    let mut seg_end = i64::MIN;
    let mut now: i64 = 1_000_000_000;
    let mut out = StreamChunks::new();
    for (dt, step) in steps {
        now = (now + dt).max(0);
        let ts = Timestamp::new((now / 1_000_000) as u32, (now % 1_000_000) as u32 * 1000);
        match step {
            Step::Seg(off, data, pass) => {
                anchor.get_or_insert(*off);
                for (i, &b) in data.iter().enumerate() {
                    offered.entry(off + i as i64).or_default().push(b);
                }
                let end = off + data.len() as i64;
                proven = proven.max(end);
                seg_end = seg_end.max(end);
                if !pass {
                    r.segment(seq(*off), data, ts);
                } else if let SegmentOutcome::Passthrough { skip } =
                    r.segment_into(seq(*off), data, ts)
                {
                    out.push_data(&data[skip..]);
                }
            }
            Step::Missing(off, len) => {
                if *len > 0 {
                    anchor.get_or_insert(*off);
                }
                proven = proven.max(off + i64::from(*len));
                r.missing(seq(*off), *len, ts);
            }
            Step::Ack(ack) => {
                proven = proven.max(ack - 1);
                r.peer_ack(seq(*ack), ts);
            }
            Step::Fin(off) => {
                proven = proven.max(*off);
                r.fin_seen(seq(*off), ts);
            }
            Step::Tick => r.advance_time(ts),
            Step::Drain => r.drain_into(&mut out),
        }
    }
    r.flush_pending();
    r.drain_into(&mut out);

    prop_assert_eq!(out.gap_bytes(), r.gap_bytes(), "gap counter = gap marks");
    prop_assert!(out.gap_count() as u64 <= r.gaps());
    prop_assert_eq!(r.current_bytes(), 0, "nothing held after the flush");
    r.flush_pending();
    let mut again = StreamChunks::new();
    r.drain_into(&mut again);
    prop_assert!(again.is_empty(), "a second flush delivers nothing");

    let Some(anchor) = anchor else {
        prop_assert!(out.is_empty());
        return Ok(());
    };
    let mut pos = anchor;
    for chunk in out.iter() {
        match chunk {
            Chunk::Data(d) => {
                for &b in d {
                    prop_assert!(
                        offered.get(&pos).is_some_and(|v| v.contains(&b)),
                        "byte {:#04x} at stream offset {} was never sent there",
                        b,
                        pos
                    );
                    pos += 1;
                }
            }
            Chunk::Gap(n) => pos += n as i64,
        }
    }
    prop_assert!(
        pos <= proven.max(anchor),
        "the stream ends at {} past everything seen or proven ({})",
        pos,
        proven
    );
    if max_ahead >= 1 << 40 {
        prop_assert!(
            pos >= seg_end,
            "the stream ends at {} short of a segment ending at {}",
            pos,
            seg_end
        );
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn sbr_matches_naive_model(policy in policies(), base in bases(), segs in segments()) {
        prop_assert_eq!(run(&mut sbr(policy), base, &segs), sbr_model(policy, &segs));
    }

    /// #212: cut bytes are skipped where the stream reaches them and
    /// never held back, around reordered and overlapping segments;
    /// ACKs and the FIN prove a trailing gap.
    #[test]
    fn sbr_with_cuts_acks_and_fin_matches_naive_model(
        policy in policies(),
        base in bases(),
        ops in ops(),
    ) {
        prop_assert_eq!(run(&mut sbr(policy), base, &ops), sbr_model(policy, &ops));
    }

    #[test]
    fn buffered_matches_naive_model(base in bases(), ops in ops()) {
        let mut r = BufferedReassembler::new().with_max_ahead(1 << 40);
        prop_assert_eq!(run(&mut r, base, &ops), BufferedModel::run(&ops));
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(5000))]

    /// Deadlines, ACK grace, strays and resyncs never misplace a byte
    /// or lose track of a gap.
    #[test]
    fn reassemblers_keep_their_invariants(
        kind in kinds(),
        max_ahead in prop_oneof![Just(32u64), Just(100), Just(1 << 40)],
        base in bases(),
        origin in any::<bool>(),
        steps in steps(),
    ) {
        check_invariants(kind, max_ahead, base, origin, &steps)?;
    }
}
