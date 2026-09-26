//! [`SegmentBufferReassembler`] — TCP reassembler with
//! out-of-order hole-fill.
//!
//! [`crate::BufferedReassembler`] holds no out-of-order data: a
//! reordered segment costs a gap. `SegmentBufferReassembler` buffers
//! out-of-order segments and fills holes when the missing bytes
//! arrive, which is what binary protocols (HTTP/2 HPACK, TLS record
//! alignment, length-prefixed framing) need when the capture
//! reorders packets.
//!
//! A hole is **not** waited for forever — a passive observer may
//! simply never see the missing bytes (capture drop, asymmetric
//! routing). A hole is given up on, skipped and reported as a gap
//! (see [`crate::StreamChunks`]) when:
//!
//! - the oldest segment waiting behind it has waited longer than
//!   [`with_ooo_deadline`](SegmentBufferReassembler::with_ooo_deadline)
//!   (checked on every segment of this side and on every driver
//!   sweep through [`crate::Reassembler::advance_time`]);
//! - the out-of-order buffer would exceed
//!   [`with_max_ooo_buffer`](SegmentBufferReassembler::with_max_ooo_buffer)
//!   (a cap of `0` means "never wait": skip immediately);
//! - the flow ends ([`crate::Reassembler::flush_pending`]).
//!
//! Sequence numbers are mapped onto 64-bit stream offsets, so
//! wrap-around at 2³² is handled uniformly.
//!
//! Counters exposed via the [`crate::Reassembler`] trait:
//! - `gaps` / `gap_bytes` — holes skipped and bytes missing.
//! - `dropped_segments` — segments that arrived after their hole was
//!   already skipped.
//! - `bytes_dropped_oversize` — bytes dropped by the ready-buffer cap.
//! - `retransmits` — duplicate (or partly duplicate) segments.
//! - `rexmit_inconsistencies` — overlapping segments whose bytes
//!   disagree (TCP overlap evasion).

use std::collections::{BTreeMap, VecDeque};
use std::time::Duration;

use crate::Timestamp;
use crate::event::{FlowSide, OverflowPolicy, TcpOverlapPolicy};
use crate::reassembler::{Reassembler, ReassemblerFactory, ReassemblyStop, StreamChunks};
use crate::tracker::FlowTrackerConfig;

/// Default per-side out-of-order buffer cap.
pub const DEFAULT_OOO_BUFFER: usize = 256 * 1024;
/// Default time an out-of-order segment waits for its hole to fill.
pub const DEFAULT_OOO_DEADLINE: Duration = Duration::from_secs(1);

/// How many recently skipped holes are remembered to classify late
/// segments as dropped (rather than as retransmits).
const SKIPPED_HISTORY: usize = 8;

/// TCP reassembler with out-of-order hole-fill and bounded waiting.
/// See the [module docs](self).
pub struct SegmentBufferReassembler {
    /// Sequence number of the next in-order byte. `None` until the
    /// first segment establishes it.
    next_seq: Option<u32>,
    /// Stream offset of `next_seq` — bytes delivered or skipped so far.
    next_off: u64,
    /// In-order output, with gap markers, awaiting a drain.
    ready: StreamChunks,
    /// Out-of-order segments keyed by stream offset; value is
    /// (bytes, arrival time of the oldest byte in the entry).
    pending: BTreeMap<u64, (Vec<u8>, Timestamp)>,
    pending_bytes: usize,
    /// Recently skipped holes as `[from, to)` stream offsets.
    skipped: VecDeque<(u64, u64)>,

    // Configuration.
    max_buffer: Option<usize>,
    max_ooo_buffer: usize,
    ooo_deadline: Duration,
    overflow_policy: OverflowPolicy,
    overlap_policy: TcpOverlapPolicy,
    high_watermark_threshold_pct: Option<u8>,

    // Counters.
    holes_filled: u64,
    gaps: u64,
    gap_bytes: u64,
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
            .field("next_seq", &self.next_seq)
            .field("ready", &self.ready.len())
            .field("pending_bytes", &self.pending_bytes)
            .field("gaps", &self.gaps)
            .field("stop", &self.stop)
            .finish_non_exhaustive()
    }
}

impl SegmentBufferReassembler {
    pub fn new() -> Self {
        Self {
            next_seq: None,
            next_off: 0,
            ready: StreamChunks::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            skipped: VecDeque::new(),
            max_buffer: None,
            max_ooo_buffer: DEFAULT_OOO_BUFFER,
            ooo_deadline: DEFAULT_OOO_DEADLINE,
            overflow_policy: OverflowPolicy::SlidingWindow,
            overlap_policy: TcpOverlapPolicy::First,
            high_watermark_threshold_pct: None,
            holes_filled: 0,
            gaps: 0,
            gap_bytes: 0,
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

    /// Set the out-of-order buffer cap. When exceeded, the oldest
    /// hole is skipped (reported as a gap) instead of discarding
    /// data. `0` disables out-of-order buffering. Default: 256 KiB.
    pub fn with_max_ooo_buffer(mut self, bytes: usize) -> Self {
        self.max_ooo_buffer = bytes;
        self
    }

    /// How long an out-of-order segment may wait for its hole to
    /// fill before the hole is skipped. Default: 1 second.
    pub fn with_ooo_deadline(mut self, deadline: Duration) -> Self {
        self.ooo_deadline = deadline;
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

    /// Holes given up on (skipped and reported as gaps). Same as
    /// [`Reassembler::gaps`].
    pub fn holes_expired(&self) -> u64 {
        self.gaps
    }

    /// Bytes currently held out of order.
    pub fn buffered_ooo_bytes(&self) -> usize {
        self.pending_bytes
    }

    /// Running count of TCP overlap-inconsistencies — incoming
    /// segments whose bytes diverge from already-pending OOO
    /// bytes in the same sequence range. Classic Ptacek-Newsham
    /// TCP-overlap evasion signal (cf. Zeek's
    /// `rexmit_inconsistency`).
    ///
    /// Detection scope: only the OOO buffer is consulted —
    /// pure post-drain retransmits aren't compared because the
    /// original bytes have already been handed to the consumer.
    pub fn rexmit_inconsistencies(&self) -> u64 {
        self.rexmit_inconsistencies
    }

    /// Skip every hole whose oldest waiting segment is older than
    /// the deadline relative to `now`. Returns the number of holes
    /// skipped. Same as [`Reassembler::advance_time`], with a count.
    pub fn evict_expired_ooo(&mut self, now: Timestamp) -> u64 {
        let before = self.gaps;
        self.expire_by_age(now);
        self.gaps - before
    }

    /// Signed distance from `next_seq`, as a stream offset.
    fn offset_of(&self, seq: u32) -> i64 {
        let next = self.next_seq.unwrap_or(seq);
        self.next_off as i64 + i64::from(seq.wrapping_sub(next) as i32)
    }

    fn advance(&mut self, to: u64) {
        let delta = to - self.next_off;
        self.next_off = to;
        if let Some(n) = self.next_seq.as_mut() {
            *n = n.wrapping_add(delta as u32);
        }
    }

    fn in_skipped(&self, start: u64, end: u64) -> bool {
        self.skipped.iter().any(|&(f, t)| start < t && f < end)
    }

    /// Deliver bytes that start exactly at `next_off`.
    fn deliver(&mut self, bytes: &[u8]) {
        let end = self.next_off + bytes.len() as u64;
        self.advance(end);
        self.append_ready(bytes);
        self.try_drain_pending();
    }

    fn try_drain_pending(&mut self) {
        while self.stop.is_none() {
            let Some((&start, _)) = self.pending.first_key_value() else {
                return;
            };
            if start > self.next_off {
                return;
            }
            let (bytes, _) = self.pending.remove(&start).expect("first key");
            self.pending_bytes -= bytes.len();
            let end = start + bytes.len() as u64;
            if end <= self.next_off {
                continue; // wholly superseded by in-order data
            }
            let trim = (self.next_off - start) as usize;
            self.holes_filled += 1;
            self.advance(end);
            self.append_ready(&bytes[trim..]);
        }
    }

    /// Give up on the hole in front of the first pending segment.
    fn skip_to_first_pending(&mut self) {
        let Some((&start, _)) = self.pending.first_key_value() else {
            return;
        };
        if start > self.next_off {
            let missing = start - self.next_off;
            self.gaps += 1;
            self.gap_bytes += missing;
            if self.skipped.len() == SKIPPED_HISTORY {
                self.skipped.pop_front();
            }
            self.skipped.push_back((self.next_off, start));
            self.ready.push_gap(missing);
            self.advance(start);
        }
        self.try_drain_pending();
    }

    fn expire_by_age(&mut self, now: Timestamp) {
        while self.stop.is_none() && !self.pending.is_empty() {
            let oldest = self
                .pending
                .values()
                .map(|(_, ts)| *ts)
                .min()
                .expect("non-empty");
            if now.saturating_sub(oldest) <= self.ooo_deadline {
                return;
            }
            self.skip_to_first_pending();
        }
    }

    fn enforce_ooo_cap(&mut self) {
        while self.stop.is_none() && self.pending_bytes > self.max_ooo_buffer {
            self.skip_to_first_pending();
        }
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
                    self.pending.clear();
                    self.pending_bytes = 0;
                    return;
                }
            }
        }
        self.ready.push_data(bytes);
        self.update_watermark();
    }

    fn update_watermark(&mut self) {
        let len = (self.ready.len() + self.pending_bytes) as u64;
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

    /// Insert an OOO segment into pending, applying the
    /// configured [`TcpOverlapPolicy`] for byte-level overlap
    /// resolution against any pre-existing pending entries.
    ///
    /// Algorithm:
    /// 1. Find every existing entry whose range intersects
    ///    `[start, start+payload.len())`.
    /// 2. For each, detect content divergence in the overlap
    ///    region — increment `rexmit_inconsistencies` on the
    ///    first divergence (one per arrival, not per overlap).
    /// 3. Build a merged buffer for the *full union range*
    ///    where every byte comes from the policy-chosen
    ///    winner.
    /// 4. Replace the absorbed entries with the merged range.
    fn absorb_ooo(&mut self, start: u64, payload: &[u8], ts: Timestamp) {
        let new_end = start + payload.len() as u64;

        let mut overlapping: Vec<u64> = Vec::new();
        let mut union_start = start;
        let mut union_end = new_end;
        let mut divergence_seen = false;
        for (&s, (existing, _)) in self.pending.range(..new_end) {
            let e = s + existing.len() as u64;
            if e <= start {
                continue;
            }
            overlapping.push(s);
            union_start = union_start.min(s);
            union_end = union_end.max(e);
            if !divergence_seen {
                let o_start = start.max(s);
                let o_end = new_end.min(e);
                let len = (o_end - o_start) as usize;
                let off_existing = (o_start - s) as usize;
                let off_new = (o_start - start) as usize;
                if existing[off_existing..off_existing + len] != payload[off_new..off_new + len] {
                    self.rexmit_inconsistencies = self.rexmit_inconsistencies.saturating_add(1);
                    divergence_seen = true;
                }
            }
        }

        if overlapping.is_empty() {
            self.pending_bytes += payload.len();
            self.pending.insert(start, (payload.to_vec(), ts));
            return;
        }

        // Duplicate arrivals of pending bytes are retransmits too.
        self.retransmits += 1;

        let union_len = (union_end - union_start) as usize;
        let mut merged = vec![0u8; union_len];
        // Per byte: (arrival ts, start offset) of the segment whose
        // byte currently fills that position.
        let mut owner: Vec<Option<(Timestamp, u64)>> = vec![None; union_len];
        let mut oldest = ts;
        for &s in &overlapping {
            let (bytes, e_ts) = self.pending.remove(&s).expect("just collected");
            self.pending_bytes -= bytes.len();
            oldest = oldest.min(e_ts);
            self.merge_into(s, &bytes, e_ts, union_start, &mut merged, &mut owner);
        }
        self.merge_into(start, payload, ts, union_start, &mut merged, &mut owner);

        self.pending_bytes += merged.len();
        self.pending.insert(union_start, (merged, oldest));
    }

    /// Per-policy byte-level merge of `[start, start+bytes.len())`.
    fn merge_into(
        &self,
        start: u64,
        bytes: &[u8],
        ts: Timestamp,
        union_start: u64,
        merged: &mut [u8],
        owner: &mut [Option<(Timestamp, u64)>],
    ) {
        let base = (start - union_start) as usize;
        for (i, &b) in bytes.iter().enumerate() {
            let dst = base + i;
            let take_new = match owner[dst] {
                None => true,
                Some((prev_ts, prev_start)) => match self.overlap_policy {
                    // First-arrived wins → never overwrite.
                    TcpOverlapPolicy::First => false,
                    // Last-arrived wins; ties keep the earlier byte.
                    TcpOverlapPolicy::Last => ts > prev_ts,
                    TcpOverlapPolicy::LowerSeq => start < prev_start,
                    TcpOverlapPolicy::HigherSeq => start > prev_start,
                },
            };
            if take_new {
                merged[dst] = b;
                owner[dst] = Some((ts, start));
            }
        }
    }
}

impl Reassembler for SegmentBufferReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        if self.stop.is_some() || payload.is_empty() {
            return;
        }
        if self.next_seq.is_none() {
            // First segment establishes the stream origin.
            self.next_seq = Some(seq);
            self.deliver(payload);
            return;
        }
        let start = self.offset_of(seq);
        let end = start + payload.len() as i64;
        let next = self.next_off as i64;

        if end <= next {
            if start >= 0 && self.in_skipped(start as u64, end as u64) {
                self.dropped_segments += 1;
            } else {
                self.retransmits += 1;
                self.on_duplicate(seq, payload, ts);
            }
        } else if start < next {
            // Head already delivered, tail new.
            self.retransmits += 1;
            self.on_duplicate(seq, payload, ts);
            let trim = (next - start) as usize;
            self.deliver(&payload[trim..]);
        } else if start == next {
            self.deliver(payload);
        } else {
            self.absorb_ooo(start as u64, payload, ts);
            self.enforce_ooo_cap();
            self.update_watermark();
        }
        self.expire_by_age(ts);
    }

    fn drain_into(&mut self, out: &mut StreamChunks) {
        self.above_threshold = false;
        out.append(&mut self.ready);
        if let Some(stop) = self.stop {
            out.set_stop(stop);
        }
    }

    fn flush_pending(&mut self) {
        while self.stop.is_none() && !self.pending.is_empty() {
            self.skip_to_first_pending();
        }
    }

    fn advance_time(&mut self, now: Timestamp) {
        self.expire_by_age(now);
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
        self.current_bytes()
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

    /// Drop both the ready buffer and the out-of-order queue, and
    /// stop accepting bytes. See [`Reassembler::release`].
    fn release(&mut self) {
        self.ready.clear();
        self.ready.release();
        self.pending.clear();
        self.pending_bytes = 0;
        self.stop.get_or_insert(ReassemblyStop::Memcap);
    }

    fn current_bytes(&self) -> u64 {
        (self.pending_bytes + self.ready.len()) as u64
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
/// [`FlowTrackerConfig::reassembly_ooo_buffer`] and
/// [`FlowTrackerConfig::reassembly_ooo_deadline`].
#[derive(Debug, Clone)]
pub struct SegmentBufferReassemblerFactory {
    max_buffer: Option<usize>,
    max_ooo_buffer: usize,
    ooo_deadline: Duration,
    overflow_policy: OverflowPolicy,
    overlap_policy: TcpOverlapPolicy,
    high_watermark_threshold_pct: Option<u8>,
    pinned_max_buffer: bool,
    pinned_ooo: bool,
    pinned_overlap: bool,
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
            ooo_deadline: DEFAULT_OOO_DEADLINE,
            overflow_policy: OverflowPolicy::SlidingWindow,
            overlap_policy: TcpOverlapPolicy::First,
            high_watermark_threshold_pct: None,
            pinned_max_buffer: false,
            pinned_ooo: false,
            pinned_overlap: false,
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

    /// Out-of-order buffer cap and hole deadline, overriding the
    /// config.
    pub fn with_ooo(mut self, max_ooo_buffer: usize, deadline: Duration) -> Self {
        self.max_ooo_buffer = max_ooo_buffer;
        self.ooo_deadline = deadline;
        self.pinned_ooo = true;
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
            .with_ooo_deadline(self.ooo_deadline)
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
            self.ooo_deadline = config.reassembly_ooo_deadline;
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

    /// Pre-0.25, an expired hole was forgotten but `next_seq` never
    /// moved, so every later segment piled up behind it forever.
    #[test]
    fn expired_hole_is_skipped_and_stream_resumes() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_millis(500));
        r.segment(1000, b"hello", ts(0));
        r.segment(1010, b"later", ts(0)); // hole 1005..1010
        assert_eq!(r.evict_expired_ooo(ts(10)), 1);
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
    fn deadline_is_also_checked_on_segment_arrival() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_secs(1));
        r.segment(0, b"a", ts(0));
        r.segment(5, b"b", ts(0)); // waits
        r.segment(10, b"c", ts(5)); // 5 s later: first hole expires
        assert!(r.gaps() >= 1);
        assert!(r.take().starts_with(b"ab"));
    }

    #[test]
    fn ooo_cap_skips_the_oldest_hole_instead_of_dropping_data() {
        let mut r = SegmentBufferReassembler::new().with_max_ooo_buffer(20);
        r.segment(1000, b"x", ts(0));
        r.segment(2000, b"01234567890", ts(1));
        r.segment(3000, b"abcdefghijk", ts(2)); // over cap → skip hole @1001
        assert_eq!(r.gaps(), 1);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert_eq!(r.buffered_ooo_bytes(), 11);
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
        r.segment(u32::MAX - 1, b"de", ts(0)); // wait: MAX-1, MAX → then 0 missing
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
}
