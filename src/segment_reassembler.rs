//! [`SegmentBufferReassembler`] — TCP reassembler with
//! out-of-order hole-fill.
//!
//! [`crate::BufferedReassembler`] holds at most one out-of-order
//! segment. `SegmentBufferReassembler` buffers out-of-order data and
//! fills holes when the missing bytes arrive, which is what binary
//! protocols (HTTP/2 HPACK, TLS record alignment, length-prefixed
//! framing) need when the capture reorders packets.
//!
//! A hole is **not** waited for forever — a passive observer may
//! simply never see the missing bytes (capture drop, asymmetric
//! routing). A hole is given up on, skipped and reported as a gap
//! (see [`crate::StreamChunks`]) when:
//!
//! - the peer has acknowledged the missing bytes (they were sent;
//!   the capture lost them) and
//!   [`with_ack_grace`](SegmentBufferReassembler::with_ack_grace) has
//!   passed;
//! - the stream has made no progress for
//!   [`with_ooo_deadline`](SegmentBufferReassembler::with_ooo_deadline)
//!   and the hole is corroborated (at least two out-of-order segments
//!   or ACK evidence) — or for four deadlines without corroboration;
//! - the out-of-order data would exceed
//!   [`with_max_ooo_buffer`](SegmentBufferReassembler::with_max_ooo_buffer)
//!   (a cap of `0` means "never wait": skip immediately);
//! - the flow ends ([`crate::Reassembler::flush_pending`]).
//!
//! Deadlines are checked on every segment of this side and on every
//! driver sweep ([`crate::Reassembler::advance_time`]), in O(1).
//!
//! A segment starting more than
//! [`with_max_ahead`](SegmentBufferReassembler::with_max_ahead) past
//! the stream position is held as a suspected stray and dropped
//! unless a second segment or an ACK corroborates it (see
//! [`crate::BufferedReassembler`]).
//!
//! # Memory
//!
//! Out-of-order data is kept as disjoint, coalescing *pieces*.
//! Everything held is charged against the out-of-order budget —
//! payload plus [`PIECE_OVERHEAD`] per piece (and [`RUN_OVERHEAD`] per
//! provenance run under the sequence-based overlap policies) — so a
//! peer sending one-byte segments cannot make the reassembler hold
//! more than the budget. The out-of-order state is freed when empty.
//!
//! # Overlaps
//!
//! When segments overlap with different content, the
//! [`TcpOverlapPolicy`] decides which bytes are delivered — for bytes
//! still waiting out of order **and** for an in-order segment that
//! overlaps waiting data. Each divergence counts a
//! `rexmit_inconsistencies` (TCP overlap evasion, Ptacek-Newsham).
//!
//! Sequence numbers are mapped onto 64-bit stream offsets, so
//! wrap-around at 2³² is handled uniformly.

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use smallvec::SmallVec;

use crate::Timestamp;
use crate::event::{FlowSide, OverflowPolicy, TcpOverlapPolicy};
use crate::reassembler::{
    Candidate, FarOutcome, Reassembler, ReassemblerFactory, ReassemblyStop, SegmentOutcome,
    StreamChunks, StreamRules, Track,
};
use crate::tracker::FlowTrackerConfig;

/// Default per-side out-of-order buffer cap.
pub const DEFAULT_OOO_BUFFER: usize = 256 * 1024;
/// Default time a hole may block a stream before it is skipped.
pub const DEFAULT_OOO_DEADLINE: Duration = Duration::from_secs(1);
/// Bookkeeping charged per out-of-order piece (map node, buffer
/// header) against the out-of-order budget.
pub const PIECE_OVERHEAD: usize = 64;
/// Bookkeeping charged per provenance run (only kept under
/// [`TcpOverlapPolicy::LowerSeq`] / [`TcpOverlapPolicy::HigherSeq`]).
pub const RUN_OVERHEAD: usize = 32;

/// Does a segment starting at `seg` win a byte currently supplied by
/// the segment starting at `existing`?
fn new_wins(policy: TcpOverlapPolicy, seg: u64, existing: Option<u64>) -> bool {
    match policy {
        TcpOverlapPolicy::Last => true,
        TcpOverlapPolicy::LowerSeq => existing.is_some_and(|e| seg < e),
        TcpOverlapPolicy::HigherSeq => existing.is_some_and(|e| seg > e),
        // First, and any future policy: the bytes already held win.
        _ => false,
    }
}

/// Out-of-order state; allocated while something is held.
#[derive(Debug, Default)]
struct Ooo {
    /// Disjoint, non-adjacent pieces keyed by stream offset.
    pieces: BTreeMap<u64, VecDeque<u8>>,
    /// Which segment (by start offset) supplied each byte range:
    /// `start → (end, segment start)`. Only for the sequence-based
    /// overlap policies.
    runs: BTreeMap<u64, (u64, u64)>,
    bytes: usize,
    /// Allocated capacity of all pieces (what is charged).
    capacity: usize,
    /// Out-of-order arrivals since the stream last progressed.
    arrivals: u32,
}

impl Ooo {
    fn charged(&self) -> usize {
        self.capacity + self.pieces.len() * PIECE_OVERHEAD + self.runs.len() * RUN_OVERHEAD
    }

    fn first_start(&self) -> Option<u64> {
        self.pieces.first_key_value().map(|(s, _)| *s)
    }

    /// Record that `[start, end)` came from the segment starting at
    /// `seg`, replacing whatever was recorded there.
    fn set_runs(&mut self, start: u64, end: u64, seg: u64) {
        if start >= end {
            return;
        }
        self.cut_runs(start, end);
        self.runs.insert(start, (end, seg));
    }

    /// Remove provenance for `[start, end)`, splitting runs that
    /// straddle the edges.
    fn cut_runs(&mut self, start: u64, end: u64) {
        // A run starting before `start` that reaches into the range.
        if let Some((&s, &(e, seg))) = self.runs.range(..start).next_back()
            && e > start
        {
            self.runs.insert(s, (start, seg));
            if e > end {
                self.runs.insert(end, (e, seg));
            }
        }
        let inside: SmallVec<[u64; 8]> = self.runs.range(start..end).map(|(s, _)| *s).collect();
        for s in inside {
            let (e, seg) = self.runs.remove(&s).expect("collected");
            if e > end {
                self.runs.insert(end, (e, seg));
            }
        }
    }

    /// Segment start that supplied the byte at `off`.
    fn seg_of(&self, off: u64) -> Option<u64> {
        self.runs
            .range(..=off)
            .next_back()
            .and_then(|(_, &(e, seg))| (off < e).then_some(seg))
    }

    /// End of the provenance run covering `off` (or `off + 1`).
    fn run_end(&self, off: u64) -> u64 {
        self.runs
            .range(..=off)
            .next_back()
            .map_or(off + 1, |(_, &(e, _))| e.max(off + 1))
    }
}

/// TCP reassembler with out-of-order hole-fill and bounded waiting.
/// See the [module docs](self).
pub struct SegmentBufferReassembler {
    ready: StreamChunks,
    track: Track,
    rules: StreamRules,
    ooo: Option<Box<Ooo>>,

    // Configuration.
    max_buffer: Option<usize>,
    max_ooo_buffer: usize,
    overflow_policy: OverflowPolicy,
    overlap_policy: TcpOverlapPolicy,
    high_watermark_threshold_pct: Option<u8>,

    // Counters.
    holes_filled: u64,
    gaps: u64,
    gap_bytes: u64,
    ack_confirmed_gaps: u64,
    dropped_segments: u64,
    retransmits: u64,
    rexmit_inconsistencies: u64,
    bytes_dropped_oversize: u64,
    high_watermark: u64,
    above_threshold: bool,
    high_watermark_crossings: u64,
    stop: Option<ReassemblyStop>,
}

impl Default for SegmentBufferReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Debug for SegmentBufferReassembler {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentBufferReassembler")
            .field("next_off", &self.track.next_off)
            .field("ready", &self.ready.len())
            .field("ooo_bytes", &self.buffered_ooo_bytes())
            .field("gaps", &self.gaps)
            .field("stop", &self.stop)
            .finish_non_exhaustive()
    }
}

impl SegmentBufferReassembler {
    pub fn new() -> Self {
        Self {
            ready: StreamChunks::new(),
            track: Track::default(),
            rules: StreamRules {
                deadline: DEFAULT_OOO_DEADLINE,
                ..StreamRules::default()
            },
            ooo: None,
            max_buffer: None,
            max_ooo_buffer: DEFAULT_OOO_BUFFER,
            overflow_policy: OverflowPolicy::SlidingWindow,
            overlap_policy: TcpOverlapPolicy::First,
            high_watermark_threshold_pct: None,
            holes_filled: 0,
            gaps: 0,
            gap_bytes: 0,
            ack_confirmed_gaps: 0,
            dropped_segments: 0,
            retransmits: 0,
            rexmit_inconsistencies: 0,
            bytes_dropped_oversize: 0,
            high_watermark: 0,
            above_threshold: false,
            high_watermark_crossings: 0,
            stop: None,
        }
    }

    /// Set the in-order ready-buffer cap.
    pub fn with_max_buffer(mut self, bytes: usize) -> Self {
        self.max_buffer = Some(bytes);
        self
    }

    /// Set the out-of-order budget (payload plus bookkeeping). When
    /// exceeded, the oldest hole is skipped (reported as a gap)
    /// instead of discarding data. `0` disables out-of-order
    /// buffering. Default: 256 KiB.
    pub fn with_max_ooo_buffer(mut self, bytes: usize) -> Self {
        self.max_ooo_buffer = bytes;
        self
    }

    /// How long the stream may make no progress with a hole open
    /// before the hole is skipped. Default: 1 second.
    pub fn with_ooo_deadline(mut self, deadline: Duration) -> Self {
        self.rules.deadline = deadline;
        self
    }

    /// How far ahead of the stream position a segment may start and
    /// still be believed without corroboration. Default 1 MiB.
    pub fn with_max_ahead(mut self, bytes: u64) -> Self {
        self.rules.max_ahead = bytes;
        self
    }

    /// How long a hole the peer already acknowledged is still waited
    /// for. Default 10 ms.
    pub fn with_ack_grace(mut self, grace: Duration) -> Self {
        self.rules.ack_grace = grace;
        self
    }

    /// Overflow policy for the in-order ready buffer.
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// TCP overlap-resolution policy — which bytes win when
    /// two segments cover the same sequence range with
    /// different content. Default is [`TcpOverlapPolicy::First`]
    /// (BSD-family default).
    pub fn with_tcp_overlap_policy(mut self, policy: TcpOverlapPolicy) -> Self {
        self.overlap_policy = policy;
        self
    }

    /// Fire a [`crate::AnomalyKind::ReassemblerHighWatermark`] when
    /// ready-buffer occupancy crosses `percent` % of the
    /// [`with_max_buffer`](Self::with_max_buffer) cap. Values outside
    /// `1..=100` are clamped.
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self {
        self.high_watermark_threshold_pct = Some(percent.clamp(1, 100));
        self
    }

    /// Currently-configured TCP overlap policy.
    pub fn tcp_overlap_policy(&self) -> TcpOverlapPolicy {
        self.overlap_policy
    }

    /// Take the ready (in-order) bytes; leaves the buffer empty.
    /// **Gap markers are discarded** — use
    /// [`Reassembler::drain_into`] to observe them.
    pub fn take(&mut self) -> Vec<u8> {
        self.above_threshold = false;
        self.ready.take_bytes()
    }

    /// Holes filled by a late-arriving segment.
    pub fn holes_filled(&self) -> u64 {
        self.holes_filled
    }

    /// Payload bytes currently held out of order.
    pub fn buffered_ooo_bytes(&self) -> usize {
        self.ooo.as_ref().map_or(0, |o| o.bytes)
    }

    /// Out-of-order pieces currently held.
    pub fn ooo_pieces(&self) -> usize {
        self.ooo.as_ref().map_or(0, |o| o.pieces.len())
    }

    /// Running count of TCP overlap-inconsistencies — segments whose
    /// bytes diverge from bytes still held out of order for the same
    /// sequence range (Ptacek-Newsham TCP-overlap evasion; cf. Zeek's
    /// `rexmit_inconsistency`). Bytes already delivered are not kept,
    /// so a divergent retransmit of them is not detected.
    pub fn rexmit_inconsistencies(&self) -> u64 {
        self.rexmit_inconsistencies
    }

    fn seq_policy(&self) -> bool {
        matches!(
            self.overlap_policy,
            TcpOverlapPolicy::LowerSeq | TcpOverlapPolicy::HigherSeq
        )
    }

    fn append_ready(&mut self, bytes: &[u8]) {
        if self.stop.is_some() || bytes.is_empty() {
            return;
        }
        if let Some(cap) = self.max_buffer
            && self.ready.len() + bytes.len() > cap
        {
            match self.overflow_policy {
                OverflowPolicy::SlidingWindow => {
                    let drop_n = (self.ready.len() + bytes.len() - cap).min(self.ready.len());
                    self.bytes_dropped_oversize += drop_n as u64;
                    self.ready.drop_front(drop_n);
                    if bytes.len() > cap {
                        let extra = bytes.len() - cap;
                        self.bytes_dropped_oversize += extra as u64;
                        self.ready.push_gap(extra as u64);
                        self.ready.push_data(&bytes[extra..]);
                        self.update_watermark();
                        return;
                    }
                }
                OverflowPolicy::DropFlow => {
                    self.bytes_dropped_oversize += bytes.len() as u64;
                    self.stop = Some(ReassemblyStop::Overflow);
                    self.ooo = None;
                    self.track.drop_stray();
                    return;
                }
            }
        }
        self.ready.push_data(bytes);
        self.update_watermark();
    }

    /// Bytes let through count as momentarily buffered (see
    /// [`crate::BufferedReassembler`]).
    fn note_passthrough(&mut self, len: usize) {
        self.high_watermark = self.high_watermark.max(len as u64);
        if let (Some(pct), Some(cap)) = (self.high_watermark_threshold_pct, self.max_buffer)
            && len as u64 >= (cap as u64).saturating_mul(pct as u64) / 100
        {
            self.high_watermark_crossings = self.high_watermark_crossings.saturating_add(1);
        }
        self.above_threshold = false;
    }

    fn update_watermark(&mut self) {
        let len = (self.ready.len() + self.buffered_ooo_bytes()) as u64;
        if len > self.high_watermark {
            self.high_watermark = len;
        }
        if let (Some(pct), Some(cap)) = (self.high_watermark_threshold_pct, self.max_buffer) {
            let trigger = (cap as u64).saturating_mul(pct as u64) / 100;
            if self.ready.len() as u64 >= trigger {
                if !self.above_threshold {
                    self.above_threshold = true;
                    self.high_watermark_crossings = self.high_watermark_crossings.saturating_add(1);
                }
            } else {
                self.above_threshold = false;
            }
        }
    }

    /// Report a gap up to `to` and move the stream there.
    fn skip_to(&mut self, to: u64, ts: Timestamp) {
        let from = self.track.next_off;
        if to <= from {
            return;
        }
        let missing = to - from;
        self.gaps += 1;
        self.gap_bytes += missing;
        self.track.record_skip(from, to);
        self.ready.push_gap(missing);
        self.track.advance_to(to, ts);
    }

    /// Deliver the first piece if the stream reached it. Returns
    /// whether something was delivered.
    fn deliver_first(&mut self, ts: Timestamp) -> bool {
        let next = self.track.next_off;
        let Some(ooo) = self.ooo.as_mut() else {
            return false;
        };
        let Some(entry) = ooo.pieces.first_entry() else {
            return false;
        };
        if *entry.key() > next {
            return false;
        }
        let (start, mut data) = entry.remove_entry();
        ooo.bytes -= data.len();
        ooo.capacity -= data.capacity();
        let end = start + data.len() as u64;
        ooo.cut_runs(start, end);
        ooo.arrivals = 0;
        if ooo.pieces.is_empty() {
            self.ooo = None;
        }
        if end > next {
            data.drain(..(next - start) as usize);
            self.track.advance_to(end, ts);
            // Hand the buffer over without copying when possible.
            self.append_ready_owned(Vec::from(data));
        }
        true
    }

    fn append_ready_owned(&mut self, bytes: Vec<u8>) {
        let fits = self
            .max_buffer
            .is_none_or(|cap| self.ready.len() + bytes.len() <= cap);
        if fits && self.stop.is_none() && self.ready.is_empty_data() {
            self.ready.push_owned(bytes);
            self.update_watermark();
        } else {
            self.append_ready(&bytes);
        }
    }

    /// Give up on the hole in front of the first piece.
    fn skip_to_first(&mut self, ts: Timestamp) {
        let Some(first) = self.ooo.as_ref().and_then(|o| o.first_start()) else {
            return;
        };
        self.skip_to(first, ts);
        self.deliver_first(ts);
    }

    /// Skip every hole: deliver all out-of-order data with gaps.
    fn flush_ooo(&mut self, ts: Timestamp) {
        while self.stop.is_none() && self.ooo.is_some() {
            self.skip_to_first(ts);
        }
    }

    fn enforce_ooo_cap(&mut self, ts: Timestamp) {
        while self.stop.is_none()
            && self
                .ooo
                .as_ref()
                .is_some_and(|o| o.charged() > self.max_ooo_buffer)
        {
            self.skip_to_first(ts);
        }
    }

    /// Deadlines and ACK evidence. O(1).
    fn check_timers(&mut self, now: Timestamp) {
        if self.stop.is_some() {
            return;
        }
        if let Some(frontier) = self.track.evidence_due(now, self.rules.ack_grace) {
            match self.ooo.as_ref().and_then(|o| o.first_start()) {
                Some(first) if first <= frontier => {
                    self.ack_confirmed_gaps += 1;
                    while self
                        .ooo
                        .as_ref()
                        .and_then(|o| o.first_start())
                        .is_some_and(|f| f <= frontier)
                        && self.stop.is_none()
                    {
                        self.skip_to_first(now);
                    }
                }
                Some(_) => {}
                None => {
                    self.ack_confirmed_gaps += 1;
                    self.skip_to(frontier, now);
                }
            }
        }
        if let Some(ooo) = self.ooo.as_ref() {
            let stalled = now.saturating_sub(self.track.last_progress);
            let first = ooo.first_start().unwrap_or(u64::MAX);
            let corroborated = ooo.arrivals >= 2
                || ooo.pieces.len() >= 2
                || self.track.evidence_frontier().is_some_and(|f| f >= first);
            if (corroborated && stalled > self.rules.deadline) || stalled > self.rules.deadline * 4
            {
                self.skip_to_first(now);
            }
        }
        self.track.expire_stray(now, self.rules.deadline * 4);
    }

    /// Insert `[start, start + payload.len())` (at or past the stream
    /// position) into the out-of-order pieces, resolving overlaps
    /// with the policy and coalescing with neighbours.
    fn absorb(&mut self, start: u64, payload: &[u8]) {
        let end = start + payload.len() as u64;
        let seq_policy = self.seq_policy();
        let policy = self.overlap_policy;
        let ooo = self.ooo.get_or_insert_with(Default::default);
        ooo.arrivals = ooo.arrivals.saturating_add(1);

        // Pieces overlapping or touching [start, end), in order.
        let mut hit: SmallVec<[u64; 4]> = SmallVec::new();
        for (&s, d) in ooo.pieces.range(..=end).rev() {
            if s + (d.len() as u64) < start {
                break;
            }
            hit.push(s);
        }
        hit.reverse();

        // Resolve overlaps inside existing pieces.
        let mut divergent = false;
        let mut overlapped = false;
        let mut writes: SmallVec<[(u64, u64); 4]> = SmallVec::new();
        for &s in &hit {
            let d = &ooo.pieces[&s];
            let e = s + d.len() as u64;
            let (o_start, o_end) = (start.max(s), end.min(e));
            if o_start >= o_end {
                continue; // merely adjacent
            }
            overlapped = true;
            let old = d.range((o_start - s) as usize..(o_end - s) as usize);
            let new = &payload[(o_start - start) as usize..(o_end - start) as usize];
            if !divergent && !old.eq(new.iter()) {
                divergent = true;
            }
            // Which parts of the overlap the new segment wins.
            let mut at = o_start;
            while at < o_end {
                let run_end = if seq_policy {
                    ooo.run_end(at).min(o_end)
                } else {
                    o_end
                };
                let existing = if seq_policy { ooo.seg_of(at) } else { None };
                if new_wins(policy, start, existing) {
                    writes.push((at, run_end));
                }
                at = run_end;
            }
        }
        for (a, b) in writes {
            let s = *ooo
                .pieces
                .range(..=a)
                .next_back()
                .expect("inside a piece")
                .0;
            let d = ooo.pieces.get_mut(&s).expect("exists");
            for off in a..b {
                d[(off - s) as usize] = payload[(off - start) as usize];
            }
            if seq_policy {
                ooo.set_runs(a, b, start);
            }
        }
        if divergent {
            self.rexmit_inconsistencies = self.rexmit_inconsistencies.saturating_add(1);
        }
        if overlapped {
            self.retransmits += 1;
        }

        // Coalesce: every hit piece plus the new bytes not covered by
        // any of them become one piece. The largest piece is grown in
        // place (bytes before it pushed to the front, after it to the
        // back), so each byte is moved O(log n) times overall.
        let mut parts: SmallVec<[(u64, VecDeque<u8>); 4]> = SmallVec::new();
        for s in hit {
            let d = ooo.pieces.remove(&s).expect("hit");
            ooo.capacity -= d.capacity();
            parts.push((s, d));
        }
        let union_start = parts.first().map_or(start, |(s, _)| (*s).min(start));
        let union_end = parts
            .last()
            .map_or(end, |(s, d)| (*s + d.len() as u64).max(end));
        let base_idx = parts
            .iter()
            .enumerate()
            .max_by_key(|(_, (_, d))| d.len())
            .map(|(i, _)| i);
        // The union in stream order: existing pieces (by index) and
        // new ranges (`None`), all contiguous.
        let mut fill: SmallVec<[(u64, u64, Option<usize>); 8]> = SmallVec::new();
        let mut cursor = union_start;
        for (i, (s, d)) in parts.iter().enumerate() {
            if *s > cursor {
                fill.push((cursor, *s, None));
            }
            fill.push((*s, *s + d.len() as u64, Some(i)));
            cursor = *s + d.len() as u64;
        }
        if cursor < union_end {
            fill.push((cursor, union_end, None));
        }
        let (mut base, base_pos) = match base_idx {
            Some(i) => {
                let pos = fill
                    .iter()
                    .position(|f| f.2 == Some(i))
                    .expect("base is in the fill");
                (std::mem::take(&mut parts[i].1), pos)
            }
            None => (VecDeque::with_capacity(payload.len()), 0),
        };
        // Grow the base once, and never much past the budget: the
        // out-of-order data at rest stays near `max_ooo_buffer`.
        let incoming: usize = fill
            .iter()
            .filter(|f| f.2 != base_idx || base_idx.is_none())
            .map(|f| (f.1 - f.0) as usize)
            .sum();
        let need = base.len() + incoming;
        if need > base.capacity() {
            let others = ooo.charged();
            let room = self.max_ooo_buffer.saturating_sub(others + PIECE_OVERHEAD);
            let target = (base.capacity() * 2).min(room).max(need);
            base.reserve_exact(target - base.len());
        }
        let mut added = 0usize;
        for &(lo, hi, src) in fill[..base_pos].iter().rev() {
            match src {
                Some(i) => {
                    for &b in parts[i].1.iter().rev() {
                        base.push_front(b);
                    }
                }
                None => {
                    for &b in payload[(lo - start) as usize..(hi - start) as usize]
                        .iter()
                        .rev()
                    {
                        base.push_front(b);
                    }
                    added += (hi - lo) as usize;
                    if seq_policy {
                        ooo.set_runs(lo, hi, start);
                    }
                }
            }
        }
        let after = if base_idx.is_some() { base_pos + 1 } else { 0 };
        for &(lo, hi, src) in fill[after..].iter() {
            match src {
                Some(i) => base.extend(parts[i].1.iter().copied()),
                None => {
                    base.extend(
                        payload[(lo - start) as usize..(hi - start) as usize]
                            .iter()
                            .copied(),
                    );
                    added += (hi - lo) as usize;
                    if seq_policy {
                        ooo.set_runs(lo, hi, start);
                    }
                }
            }
        }
        ooo.bytes += added;
        ooo.capacity += base.capacity();
        ooo.pieces.insert(union_start, base);
    }

    fn resync(&mut self, c: &Candidate, ts: Timestamp) {
        self.flush_ooo(ts);
        self.skip_to(c.off, ts);
        let seq = self.track.seq_of(c.off);
        self.feed(seq, &c.data, ts, false);
    }

    fn feed(&mut self, seq: u32, payload: &[u8], ts: Timestamp, pass: bool) -> SegmentOutcome {
        if self.stop.is_some() || payload.is_empty() {
            return SegmentOutcome::Buffered;
        }
        self.track.anchor(seq, ts);
        let start = self.track.offset_of(seq);
        let end = start + payload.len() as i64;
        let next = self.track.next_off as i64;
        let max_ahead = self.rules.max_ahead as i64;

        if start - next > max_ahead {
            if let FarOutcome::Resync(c) =
                self.track
                    .far_ahead(start as u64, payload, ts, self.rules.max_ahead)
            {
                self.resync(&c, ts);
                return self.feed(seq, payload, ts, false);
            }
            return SegmentOutcome::Buffered;
        }
        if end <= next {
            if end < next - max_ahead {
                self.track.out_of_window += 1;
            } else if start >= 0 && self.track.in_skipped(start as u64, end as u64) {
                self.dropped_segments += 1;
            } else {
                self.retransmits += 1;
                self.on_duplicate(seq, payload, ts);
            }
            self.check_timers(ts);
            return SegmentOutcome::Buffered;
        }
        let skip = if start < next {
            // Head already delivered, tail new.
            self.retransmits += 1;
            self.on_duplicate(seq, payload, ts);
            (next - start) as usize
        } else {
            0
        };
        let start = start.max(next) as u64;
        let data = &payload[skip..];

        if self.ooo.is_none() && start == next as u64 {
            // In order, nothing waiting.
            self.track.advance_to(start + data.len() as u64, ts);
            if pass && self.ready.is_empty() && self.max_buffer.is_none_or(|cap| data.len() <= cap)
            {
                self.note_passthrough(data.len());
                return SegmentOutcome::Passthrough { skip };
            }
            self.append_ready(data);
            self.check_timers(ts);
            return SegmentOutcome::Buffered;
        }
        let was_blocked = self.ooo.is_some();
        if !was_blocked {
            // A hole opens now.
            self.track.last_progress = ts;
        }
        self.absorb(start, data);
        if start == next as u64 && was_blocked {
            self.holes_filled += 1;
        }
        while self.deliver_first(ts) {}
        self.enforce_ooo_cap(ts);
        self.update_watermark();
        self.check_timers(ts);
        SegmentOutcome::Buffered
    }
}

impl Reassembler for SegmentBufferReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        self.feed(seq, payload, ts, false);
    }

    fn segment_into(&mut self, seq: u32, payload: &[u8], ts: Timestamp) -> SegmentOutcome {
        self.feed(seq, payload, ts, true)
    }

    fn set_origin(&mut self, seq: u32) {
        self.track.anchor(seq, Timestamp::default());
    }

    fn peer_ack(&mut self, ack: u32, ts: Timestamp) {
        if self.stop.is_some() {
            return;
        }
        if let Some(c) = self
            .track
            .evidence(ack.wrapping_sub(1), ts, self.rules.max_ahead)
        {
            self.resync(&c, ts);
        }
        self.check_timers(ts);
    }

    fn fin_seen(&mut self, end: u32, ts: Timestamp) {
        if self.stop.is_some() {
            return;
        }
        if let Some(c) = self.track.fin(end, ts, self.rules.max_ahead) {
            self.resync(&c, ts);
        }
    }

    fn drain_into(&mut self, out: &mut StreamChunks) {
        self.above_threshold = false;
        out.append(&mut self.ready);
        if let Some(stop) = self.stop {
            out.set_stop(stop);
        }
    }

    fn flush_pending(&mut self) {
        let ts = self.track.last_progress;
        self.flush_ooo(ts);
        if self.stop.is_none()
            && let Some(frontier) = self.track.evidence_frontier()
        {
            self.ack_confirmed_gaps += 1;
            self.skip_to(frontier, ts);
        }
        self.track.drop_stray();
    }

    fn advance_time(&mut self, now: Timestamp) {
        self.check_timers(now);
    }

    fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    fn gaps(&self) -> u64 {
        self.gaps
    }

    fn gap_bytes(&self) -> u64 {
        self.gap_bytes
    }

    fn bytes_dropped_oversize(&self) -> u64 {
        self.bytes_dropped_oversize
    }

    fn is_poisoned(&self) -> bool {
        self.stop.is_some()
    }

    fn stop_reason(&self) -> Option<ReassemblyStop> {
        self.stop
    }

    fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    fn bytes_in_flight(&self) -> u64 {
        (self.ready.len() + self.buffered_ooo_bytes()) as u64
    }

    fn high_watermark_crossings(&self) -> u64 {
        self.high_watermark_crossings
    }

    fn high_watermark_threshold(&self) -> Option<(u64, u8)> {
        match (self.max_buffer, self.high_watermark_threshold_pct) {
            (Some(cap), Some(pct)) => Some((cap as u64, pct)),
            _ => None,
        }
    }

    fn retransmits(&self) -> u64 {
        self.retransmits
    }

    fn rexmit_inconsistencies(&self) -> u64 {
        self.rexmit_inconsistencies
    }

    /// Drop both the ready buffer and the out-of-order data, and
    /// stop accepting bytes. See [`Reassembler::release`].
    fn release(&mut self) {
        self.ready.clear();
        self.ready.release();
        self.ooo = None;
        self.track.drop_stray();
        self.stop.get_or_insert(ReassemblyStop::Memcap);
    }

    fn current_bytes(&self) -> u64 {
        let ooo = self.ooo.as_ref().map_or(0, |o| o.charged());
        (self.ready.len() + ooo + self.track.heap_bytes()) as u64
    }

    fn out_of_window_segments(&self) -> u64 {
        self.track.out_of_window
    }

    fn ack_confirmed_gaps(&self) -> u64 {
        self.ack_confirmed_gaps
    }

    fn origin_resets(&self) -> u64 {
        self.track.origin_resets
    }
}

/// Factory for [`SegmentBufferReassembler`] — the reassembler of the
/// session engines ([`crate::session::SessionDriver`],
/// [`crate::driver::Driver`]).
///
/// Settings not set explicitly with a `with_*` builder come from the
/// tracker config ([`ReassemblerFactory::apply_config`]):
/// [`FlowTrackerConfig::max_reassembler_buffer`],
/// [`FlowTrackerConfig::overflow_policy`],
/// [`FlowTrackerConfig::reassembler_high_watermark_pct`],
/// [`FlowTrackerConfig::tcp_overlap_policy`],
/// [`FlowTrackerConfig::reassembly_ooo_buffer`],
/// [`FlowTrackerConfig::reassembly_ooo_deadline`],
/// [`FlowTrackerConfig::reassembly_max_ahead`] and
/// [`FlowTrackerConfig::reassembly_ack_grace`].
#[derive(Debug, Clone)]
pub struct SegmentBufferReassemblerFactory {
    max_buffer: Option<usize>,
    max_ooo_buffer: usize,
    overflow_policy: OverflowPolicy,
    overlap_policy: TcpOverlapPolicy,
    high_watermark_threshold_pct: Option<u8>,
    rules: StreamRules,
    pinned_max_buffer: bool,
    pinned_ooo: bool,
    pinned_overlap: bool,
    pinned_rules: bool,
}

impl Default for SegmentBufferReassemblerFactory {
    fn default() -> Self {
        Self::from_config(&FlowTrackerConfig::default())
    }
}

impl SegmentBufferReassemblerFactory {
    /// Factory using the reassembly settings of `config`.
    pub fn from_config(config: &FlowTrackerConfig) -> Self {
        let mut f = Self {
            max_buffer: None,
            max_ooo_buffer: DEFAULT_OOO_BUFFER,
            overflow_policy: OverflowPolicy::SlidingWindow,
            overlap_policy: TcpOverlapPolicy::First,
            high_watermark_threshold_pct: None,
            rules: StreamRules::default(),
            pinned_max_buffer: false,
            pinned_ooo: false,
            pinned_overlap: false,
            pinned_rules: false,
        };
        <Self as ReassemblerFactory<()>>::apply_config(&mut f, config);
        f
    }

    /// Ready-buffer cap and overflow policy, overriding the config.
    pub fn with_max_buffer(mut self, cap: Option<usize>, policy: OverflowPolicy) -> Self {
        self.max_buffer = cap;
        self.overflow_policy = policy;
        self.pinned_max_buffer = true;
        self
    }

    /// Out-of-order budget and hole deadline, overriding the config.
    pub fn with_ooo(mut self, max_ooo_buffer: usize, deadline: Duration) -> Self {
        self.max_ooo_buffer = max_ooo_buffer;
        self.rules.deadline = deadline;
        self.pinned_ooo = true;
        self
    }

    /// Stray window and ACK grace, overriding the config.
    pub fn with_window(mut self, max_ahead: u64, ack_grace: Duration) -> Self {
        self.rules.max_ahead = max_ahead;
        self.rules.ack_grace = ack_grace;
        self.pinned_rules = true;
        self
    }

    /// Overlap policy, overriding the config.
    pub fn with_tcp_overlap_policy(mut self, policy: TcpOverlapPolicy) -> Self {
        self.overlap_policy = policy;
        self.pinned_overlap = true;
        self
    }
}

impl<K: Send + 'static> ReassemblerFactory<K> for SegmentBufferReassemblerFactory {
    type Reassembler = SegmentBufferReassembler;

    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> SegmentBufferReassembler {
        let mut r = SegmentBufferReassembler::new()
            .with_max_ooo_buffer(self.max_ooo_buffer)
            .with_ooo_deadline(self.rules.deadline)
            .with_max_ahead(self.rules.max_ahead)
            .with_ack_grace(self.rules.ack_grace)
            .with_overflow_policy(self.overflow_policy)
            .with_tcp_overlap_policy(self.overlap_policy);
        if let Some(cap) = self.max_buffer {
            r = r.with_max_buffer(cap);
        }
        if let Some(pct) = self.high_watermark_threshold_pct {
            r = r.with_high_watermark_threshold(pct);
        }
        r
    }

    fn apply_config(&mut self, config: &FlowTrackerConfig) {
        if !self.pinned_max_buffer {
            self.max_buffer = config.max_reassembler_buffer;
            self.overflow_policy = config.overflow_policy;
        }
        if !self.pinned_ooo {
            self.max_ooo_buffer = config.reassembly_ooo_buffer;
            self.rules.deadline = config.reassembly_ooo_deadline;
        }
        if !self.pinned_rules {
            self.rules.max_ahead = config.reassembly_max_ahead;
            self.rules.ack_grace = config.reassembly_ack_grace;
        }
        if !self.pinned_overlap {
            self.overlap_policy = config.tcp_overlap_policy;
        }
        self.high_watermark_threshold_pct = config.reassembler_high_watermark_pct;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::reassembler::Chunk;

    fn ts(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
    }

    fn drain(r: &mut SegmentBufferReassembler) -> StreamChunks {
        let mut out = StreamChunks::new();
        r.drain_into(&mut out);
        out
    }

    #[test]
    fn in_order_segments_drain_directly() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(1000, b"hello", ts(0));
        r.segment(1005, b" world", ts(0));
        assert_eq!(r.take(), b"hello world");
    }

    #[test]
    fn ooo_fills_when_hole_arrives() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(1000, b"hello", ts(0));
        r.segment(1010, b" flowscope", ts(0));
        r.segment(1005, b"world", ts(0));
        assert_eq!(r.take(), b"helloworld flowscope");
        assert_eq!(r.holes_filled(), 1);
        assert_eq!(r.gaps(), 0);
        assert_eq!(r.current_bytes(), 0, "out-of-order state freed");
    }

    #[test]
    fn a_segment_larger_than_the_cap_is_trimmed() {
        let mut r = SegmentBufferReassembler::new().with_max_buffer(8);
        r.segment(1000, b"abcd", ts(0));
        r.segment(1004, &[b'x'; 64], ts(0));
        let out = drain(&mut r);
        assert_eq!(out.data(), vec![b'x'; 8]);
        assert_eq!(r.bytes_dropped_oversize(), 60);
        assert_eq!(out.gap_bytes(), 60);
    }

    /// Pre-0.25, an expired hole was forgotten but the stream
    /// position never moved, so every later segment piled up behind
    /// it forever.
    #[test]
    fn expired_hole_is_skipped_and_stream_resumes() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_millis(500));
        r.segment(1000, b"hello", ts(0));
        r.segment(1010, b"later", ts(0)); // hole 1005..1010
        r.advance_time(ts(10));
        assert_eq!(r.gaps(), 1);
        r.segment(1015, b"!", ts(10));
        let out = drain(&mut r);
        let v: Vec<_> = out.iter().collect();
        assert_eq!(
            v,
            vec![Chunk::Data(b"hello"), Chunk::Gap(5), Chunk::Data(b"later!")]
        );
        assert_eq!(r.gap_bytes(), 5);
    }

    #[test]
    fn corroborated_hole_expires_after_one_deadline() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_secs(1));
        r.segment(0, b"a", ts(0));
        r.segment(5, b"b", ts(0)); // waits
        r.segment(10, b"c", ts(5)); // 5 s later: corroborated, stalled
        assert!(r.gaps() >= 1);
        assert!(r.take().starts_with(b"ab"));
    }

    /// A lone in-window segment ahead of a stream that keeps
    /// progressing must not kill it.
    #[test]
    fn stall_deadline_does_not_kill_progressing_stream() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_secs(1));
        r.segment(0, b"x", ts(0));
        r.segment(100, b"far", ts(0)); // waits at 100
        for i in 1..100u32 {
            // One byte per second, in order, towards it.
            r.segment(i, b"y", ts(i));
        }
        assert_eq!(r.gaps(), 0, "the stream kept progressing");
        let out = drain(&mut r);
        assert_eq!(out.data().len(), 103);
    }

    #[test]
    fn lone_segment_waits_four_deadlines() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_secs(1));
        r.segment(0, b"a", ts(0));
        r.segment(5, b"b", ts(0));
        r.advance_time(ts(3));
        assert_eq!(r.gaps(), 0);
        r.advance_time(ts(5));
        assert_eq!(r.gaps(), 1);
    }

    #[test]
    fn ooo_cap_skips_the_oldest_hole_instead_of_dropping_data() {
        let piece = 11 + PIECE_OVERHEAD;
        let mut r = SegmentBufferReassembler::new().with_max_ooo_buffer(2 * piece + 10);
        r.segment(1000, b"x", ts(0));
        r.segment(2000, b"01234567890", ts(1));
        r.segment(3000, b"abcdefghijk", ts(2));
        assert_eq!(r.gaps(), 0);
        r.segment(4000, b"ABCDEFGHIJK", ts(3)); // over the budget → skip hole @1001
        assert_eq!(r.gaps(), 1);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert_eq!(r.buffered_ooo_bytes(), 22);
        let out = drain(&mut r);
        assert_eq!(out.data(), b"x01234567890");
    }

    #[test]
    fn zero_ooo_buffer_means_never_wait() {
        let mut r = SegmentBufferReassembler::new().with_max_ooo_buffer(0);
        r.segment(0, b"ab", ts(0));
        r.segment(4, b"ef", ts(0));
        assert_eq!(r.gaps(), 1);
        assert_eq!(r.take(), b"abef");
    }

    #[test]
    fn late_segment_after_skip_counts_as_dropped() {
        let mut r = SegmentBufferReassembler::new().with_max_ooo_buffer(0);
        r.segment(0, b"ab", ts(0));
        r.segment(4, b"ef", ts(0)); // skips 2..4
        r.segment(2, b"cd", ts(0)); // late
        assert_eq!(r.dropped_segments(), 1);
        assert_eq!(r.retransmits(), 0);
    }

    #[test]
    fn flush_pending_delivers_everything_with_gaps() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"a", ts(0));
        r.segment(3, b"d", ts(0));
        r.segment(6, b"g", ts(0));
        r.flush_pending();
        let out = drain(&mut r);
        let v: Vec<_> = out.iter().collect();
        assert_eq!(
            v,
            vec![
                Chunk::Data(b"a"),
                Chunk::Gap(2),
                Chunk::Data(b"d"),
                Chunk::Gap(2),
                Chunk::Data(b"g")
            ]
        );
    }

    #[test]
    fn retransmits_counted_not_appended() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(1000, b"hello", ts(0));
        r.segment(1000, b"hello", ts(1));
        assert_eq!(r.take(), b"hello");
        assert_eq!(r.retransmits(), 1);
    }

    #[test]
    fn partial_overlap_delivers_the_new_tail() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"hello", ts(0));
        r.segment(3, b"lo world", ts(0));
        assert_eq!(r.take(), b"hello world");
        assert_eq!(r.retransmits(), 1);
    }

    #[test]
    fn ooo_across_sequence_wrap_is_ordered_correctly() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(u32::MAX - 4, b"abc", ts(0)); // next = MAX-1
        r.segment(1, b"fg", ts(0)); // OOO past the wrap
        r.segment(u32::MAX - 1, b"de", ts(0)); // MAX-1, MAX; then 0 missing
        r.segment(0, b"X", ts(0));
        assert_eq!(r.take(), b"abcdeXfg");
        assert_eq!(r.gaps(), 0);
    }

    #[test]
    fn drop_flow_stops_on_ready_overflow_and_frees_pending() {
        let mut r = SegmentBufferReassembler::new()
            .with_max_buffer(4)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, b"ab", ts(0));
        r.segment(10, b"zz", ts(0));
        r.segment(2, b"cdefgh", ts(0)); // overflow
        assert_eq!(r.stop_reason(), Some(ReassemblyStop::Overflow));
        assert_eq!(r.buffered_ooo_bytes(), 0);
        let out = drain(&mut r);
        assert_eq!(out.data(), b"ab");
        assert_eq!(out.stop(), Some(ReassemblyStop::Overflow));
    }

    #[test]
    fn rst_does_not_stop_reassembly() {
        let mut r = SegmentBufferReassembler::new();
        r.rst();
        assert!(!r.is_poisoned());
    }

    #[test]
    fn high_watermark_is_a_peak() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, &[0; 10], ts(0));
        r.segment(20, &[0; 30], ts(0));
        assert_eq!(r.high_watermark(), 40);
        let _ = r.take();
        assert_eq!(r.high_watermark(), 40);
    }

    #[test]
    fn factory_follows_the_tracker_config() {
        let cfg = FlowTrackerConfig {
            reassembly_ooo_buffer: 0,
            tcp_overlap_policy: TcpOverlapPolicy::Last,
            ..Default::default()
        };
        let mut f = SegmentBufferReassemblerFactory::from_config(&cfg);
        let mut r: SegmentBufferReassembler = f.new_reassembler(&(), FlowSide::Initiator);
        assert_eq!(r.tcp_overlap_policy(), TcpOverlapPolicy::Last);
        r.segment(0, b"a", ts(0));
        r.segment(5, b"b", ts(0));
        assert_eq!(r.gaps(), 1, "ooo buffer 0 → immediate skip");
    }

    // ── origin, window, evidence ────────────────────────────────

    /// Issue #182: with the SYN seen, reordered first data segments
    /// are no longer mistaken for a retransmit.
    #[test]
    fn syn_seed_recovers_reordered_first_segments() {
        let mut r = SegmentBufferReassembler::new();
        r.set_origin(1001);
        r.segment(1006, b"world", ts(0));
        r.segment(1001, b"hello", ts(0));
        assert_eq!(r.take(), b"helloworld");
        assert_eq!(r.retransmits(), 0);
    }

    #[test]
    fn stray_beyond_window_is_dropped_and_counted() {
        let mut r = SegmentBufferReassembler::new().with_max_ahead(1000);
        r.segment(0, b"abc", ts(0));
        r.segment(1_000_000, b"STRAY", ts(0));
        r.segment(3, b"def", ts(0));
        assert_eq!(r.take(), b"abcdef");
        assert_eq!(r.gaps(), 0);
        assert_eq!(r.out_of_window_segments(), 1);
    }

    #[test]
    fn lone_stray_is_forgotten_after_four_deadlines() {
        let mut r = SegmentBufferReassembler::new()
            .with_max_ahead(1000)
            .with_ooo_deadline(Duration::from_secs(1));
        r.segment(0, b"abc", ts(0));
        r.segment(1_000_000, b"STRAY", ts(0));
        let _ = r.take();
        assert!(r.current_bytes() > 0, "the stray is held");
        r.advance_time(ts(10));
        assert_eq!(r.current_bytes(), 0);
        // A later segment near the old stray does not resync.
        r.segment(1_000_010, b"X", ts(10));
        assert_eq!(r.origin_resets(), 0);
        assert_eq!(r.out_of_window_segments(), 2);
    }

    /// Two consistent far segments: massive capture loss, not a
    /// stray. The stream resyncs with a gap.
    #[test]
    fn large_loss_resyncs_on_second_segment() {
        let mut r = SegmentBufferReassembler::new().with_max_ahead(1000);
        r.segment(0, b"abc", ts(0));
        r.segment(1_000_000, b"far1", ts(0));
        r.segment(1_000_004, b"far2", ts(0));
        let out = drain(&mut r);
        let v: Vec<_> = out.iter().collect();
        assert_eq!(
            v,
            vec![
                Chunk::Data(b"abc"),
                Chunk::Gap(1_000_000 - 3),
                Chunk::Data(b"far1far2")
            ]
        );
        assert_eq!(r.origin_resets(), 1);
        assert_eq!(r.out_of_window_segments(), 0);
    }

    #[test]
    fn ack_confirms_hole_after_grace() {
        let mut r = SegmentBufferReassembler::new().with_ack_grace(Duration::from_millis(10));
        r.segment(0, b"abc", ts(0));
        r.segment(6, b"ghi", ts(0)); // hole 3..6
        r.peer_ack(9, ts(0)); // receiver has everything up to 9
        assert_eq!(r.gaps(), 0, "grace not over yet");
        r.advance_time(Timestamp::new(0, 20_000_000));
        assert_eq!(r.gaps(), 1);
        assert_eq!(r.ack_confirmed_gaps(), 1);
        assert_eq!(r.take(), b"abcghi");
    }

    #[test]
    fn late_data_within_grace_fills_the_hole() {
        let mut r = SegmentBufferReassembler::new().with_ack_grace(Duration::from_millis(10));
        r.segment(0, b"abc", ts(0));
        r.peer_ack(7, ts(0)); // ACK captured before the data
        r.segment(3, b"def", Timestamp::new(0, 1_000_000));
        r.advance_time(ts(1));
        assert_eq!(r.gaps(), 0);
        assert_eq!(r.take(), b"abcdef");
    }

    /// A lost final segment is only visible through the ACK.
    #[test]
    fn trailing_gap_from_ack() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"abc", ts(0));
        r.peer_ack(11, ts(0)); // 0..10 acked, 3..10 never seen
        r.flush_pending();
        let out = drain(&mut r);
        assert_eq!(out.data(), b"abc");
        assert_eq!(out.gap_bytes(), 7);
    }

    #[test]
    fn fin_bounds_ack_evidence() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"abc", ts(0));
        r.fin_seen(3, ts(0));
        r.peer_ack(4, ts(0)); // ACK of the FIN
        r.flush_pending();
        assert_eq!(r.gaps(), 0);
    }

    // ── overlaps and memory ─────────────────────────────────────

    /// Issue #184: an in-order segment overlapping bytes held out of
    /// order goes through the overlap policy too.
    #[test]
    fn in_order_does_not_override_pending_first() {
        let mut r = SegmentBufferReassembler::new(); // First
        r.segment(0, b"a", ts(0));
        r.segment(3, b"XYZ", ts(0)); // held
        r.segment(1, b"bcdef", ts(0)); // in order, overlaps 3..6
        assert_eq!(r.take(), b"abcXYZ");
        assert_eq!(r.rexmit_inconsistencies(), 1);
    }

    #[test]
    fn last_policy_takes_the_newest_bytes() {
        let mut r = SegmentBufferReassembler::new().with_tcp_overlap_policy(TcpOverlapPolicy::Last);
        r.segment(0, b"a", ts(0));
        r.segment(3, b"XYZ", ts(0));
        r.segment(1, b"bcdef", ts(0));
        assert_eq!(r.take(), b"abcdef");
    }

    /// A third overlapping segment is resolved against the segment
    /// that really supplied each byte.
    #[test]
    fn third_segment_uses_original_provenance() {
        let mut r =
            SegmentBufferReassembler::new().with_tcp_overlap_policy(TcpOverlapPolicy::LowerSeq);
        r.segment(0, b"_", ts(0));
        r.segment(10, b"AAAA", ts(0)); // 10..14 from seg@10
        r.segment(12, b"BBBB", ts(0)); // 14..16 new; 12..14 lose (12 > 10)
        r.segment(11, b"CCCC", ts(0)); // 11..15: wins over seg@12 bytes (14), loses to seg@10
        r.flush_pending();
        let out = drain(&mut r);
        // 10..14 from seg@10 (lower than 11 and 12), 14 from seg@11
        // (lower than 12), 15 from seg@12.
        assert_eq!(&out.data()[1..], b"AAAACB");
    }

    #[test]
    fn reverse_one_byte_segments_coalesce_to_one_piece() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"a", ts(0));
        for off in (2..2000u32).rev() {
            r.segment(off, b"x", ts(0));
        }
        assert_eq!(r.ooo_pieces(), 1);
        assert_eq!(r.buffered_ooo_bytes(), 1998);
        r.segment(1, b"b", ts(0));
        assert_eq!(r.take().len(), 2000);
        assert_eq!(r.current_bytes(), 0);
    }

    #[test]
    fn piece_overhead_is_charged() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(0, b"a", ts(0));
        r.segment(10, b"b", ts(0));
        r.segment(20, b"c", ts(0));
        let _ = r.take();
        assert_eq!(r.current_bytes(), 2 + 2 * PIECE_OVERHEAD as u64);
    }

    #[test]
    fn passthrough_only_when_nothing_is_waiting() {
        let mut r = SegmentBufferReassembler::new();
        assert_eq!(
            r.segment_into(0, b"abc", ts(0)),
            SegmentOutcome::Passthrough { skip: 0 }
        );
        assert_eq!(
            r.segment_into(1, b"bcde", ts(0)),
            SegmentOutcome::Passthrough { skip: 2 }
        );
        assert_eq!(r.segment_into(10, b"x", ts(0)), SegmentOutcome::Buffered);
        assert_eq!(r.segment_into(5, b"fghij", ts(0)), SegmentOutcome::Buffered);
        assert_eq!(r.take(), b"fghijx");
    }
}
