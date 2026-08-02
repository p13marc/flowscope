//! [`SegmentBufferReassembler`] — TCP reassembler with
//! out-of-order hole-fill.
//!
//! The default [`crate::BufferedReassembler`] drops out-of-order
//! segments outright — sufficient for protocols that re-sync at
//! message boundaries (HTTP/1.x), but inadequate for binary
//! protocols (HTTP/2 HPACK, TLS record alignment) where a
//! dropped middle segment desyncs the parser permanently.
//!
//! `SegmentBufferReassembler` buffers OOO segments in a
//! BTreeMap keyed by start sequence. Each new segment that fills
//! a hole drains the contiguous prefix into a ready buffer.
//! Segments that linger past `ooo_deadline` are dropped; the
//! `holes_expired` counter ticks.
//!
//! Counters exposed via the [`crate::Reassembler`] trait:
//! - `dropped_segments` — OOO segments expired before fill.
//! - `bytes_dropped_oversize` — bytes evicted by the buffer cap.
//! - `retransmits` — duplicate segments observed.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::Timestamp;
use crate::event::{OverflowPolicy, TcpOverlapPolicy};
use crate::reassembler::Reassembler;

const DEFAULT_OOO_CAP: usize = 256 * 1024;
const DEFAULT_OOO_DEADLINE: Duration = Duration::from_secs(1);

/// TCP reassembler with out-of-order hole-fill.
///
/// Holds OOO segments in a `BTreeMap<start_seq, segment>` until
/// the preceding hole is filled, then drains contiguous bytes
/// into the ready buffer. Segments older than `ooo_deadline`
/// are evicted; the `holes_expired` counter ticks.
pub struct SegmentBufferReassembler {
    /// Sequence number where the next in-order byte should
    /// start. `None` until first segment establishes ISN.
    next_seq: Option<u32>,
    /// In-order bytes ready for consumer drain.
    ready: Vec<u8>,
    /// OOO segments. Key = start sequence; value = (bytes, arrival ts).
    pending: BTreeMap<u32, (Vec<u8>, Timestamp)>,
    /// Total OOO bytes currently buffered (sum over `pending`).
    pending_bytes: usize,

    // Configuration.
    max_buffer: Option<usize>,
    max_ooo_buffer: usize,
    ooo_deadline: Duration,
    overflow_policy: OverflowPolicy,
    /// Which bytes win overlap regions when two segments cover
    /// the same sequence range with different content. See
    /// [`TcpOverlapPolicy`] for the per-policy semantics.
    overlap_policy: TcpOverlapPolicy,

    // Counters.
    holes_filled: u64,
    holes_expired: u64,
    retransmits: u64,
    rexmit_inconsistencies: u64,
    bytes_dropped_oversize: u64,
    poisoned: bool,
    fin_observed: bool,
}

impl Default for SegmentBufferReassembler {
    fn default() -> Self {
        Self::new()
    }
}

impl SegmentBufferReassembler {
    pub fn new() -> Self {
        Self {
            next_seq: None,
            ready: Vec::new(),
            pending: BTreeMap::new(),
            pending_bytes: 0,
            max_buffer: None,
            max_ooo_buffer: DEFAULT_OOO_CAP,
            ooo_deadline: DEFAULT_OOO_DEADLINE,
            overflow_policy: OverflowPolicy::SlidingWindow,
            overlap_policy: TcpOverlapPolicy::First,
            holes_filled: 0,
            holes_expired: 0,
            retransmits: 0,
            rexmit_inconsistencies: 0,
            bytes_dropped_oversize: 0,
            poisoned: false,
            fin_observed: false,
        }
    }

    /// Set the in-order ready-buffer cap.
    pub fn with_max_buffer(mut self, bytes: usize) -> Self {
        self.max_buffer = Some(bytes);
        self
    }

    /// Set the OOO-pending-buffer cap. Default: 256 KiB.
    pub fn with_max_ooo_buffer(mut self, bytes: usize) -> Self {
        self.max_ooo_buffer = bytes;
        self
    }

    /// How long an OOO segment may sit in the pending queue
    /// before being expired. Default: 1 second.
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
    ///
    /// Issue #17 (0.18 close).
    pub fn with_tcp_overlap_policy(mut self, policy: TcpOverlapPolicy) -> Self {
        self.overlap_policy = policy;
        self
    }

    /// Currently-configured TCP overlap policy.
    pub fn tcp_overlap_policy(&self) -> TcpOverlapPolicy {
        self.overlap_policy
    }

    /// Take the ready (in-order) bytes; leaves the buffer empty.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.ready)
    }

    pub fn holes_filled(&self) -> u64 {
        self.holes_filled
    }

    pub fn holes_expired(&self) -> u64 {
        self.holes_expired
    }

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
    /// For a flow under evasion, the divergence is typically
    /// visible in the OOO window (attackers send fake fragments
    /// into unfilled holes), so this catches the common case.
    ///
    /// New in 0.18.0 (issue #17 sub-piece).
    pub fn rexmit_inconsistencies(&self) -> u64 {
        self.rexmit_inconsistencies
    }

    /// Evict OOO segments older than `ooo_deadline` relative to
    /// `now`. Returns the number of expired segments.
    pub fn evict_expired_ooo(&mut self, now: Timestamp) -> u64 {
        let now_dur = now.to_duration();
        let mut expired_keys: Vec<u32> = Vec::new();
        for (k, (_, ts)) in &self.pending {
            let age = now_dur.saturating_sub(ts.to_duration());
            if age > self.ooo_deadline {
                expired_keys.push(*k);
            }
        }
        let count = expired_keys.len() as u64;
        for k in expired_keys {
            if let Some((bytes, _)) = self.pending.remove(&k) {
                self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
                self.holes_expired += 1;
            }
        }
        // If we expired anything, the reassembler is desynced
        // for the corresponding region — poison per policy.
        if count > 0 && self.overflow_policy == OverflowPolicy::DropFlow {
            self.poisoned = true;
        }
        count
    }

    fn try_drain_pending(&mut self) {
        loop {
            let Some(&next_expected) = self.next_seq.as_ref() else {
                return;
            };
            let Some((&start_seq, _)) = self.pending.iter().next() else {
                return;
            };
            if start_seq != next_expected {
                return;
            }
            let (bytes, _) = self.pending.remove(&start_seq).unwrap();
            self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
            self.append_ready(&bytes);
            self.next_seq = Some(next_expected.wrapping_add(bytes.len() as u32));
            self.holes_filled += 1;
        }
    }

    fn append_ready(&mut self, bytes: &[u8]) {
        if let Some(cap) = self.max_buffer
            && self.ready.len() + bytes.len() > cap
        {
            match self.overflow_policy {
                OverflowPolicy::SlidingWindow => {
                    // Drop oldest bytes; keep flow alive.
                    let drop_n = self.ready.len() + bytes.len() - cap;
                    let drop_n = drop_n.min(self.ready.len());
                    self.ready.drain(..drop_n);
                    self.bytes_dropped_oversize += drop_n as u64;
                    // Dropping everything buffered is not enough when
                    // the payload alone exceeds the cap — appending it
                    // whole would leave the buffer above the limit.
                    // Keep the newest `cap` bytes, matching
                    // `BufferedReassembler` (issue #188).
                    if bytes.len() > cap {
                        let extra = bytes.len() - cap;
                        self.bytes_dropped_oversize += extra as u64;
                        self.ready.extend_from_slice(&bytes[extra..]);
                        return;
                    }
                }
                OverflowPolicy::DropFlow => {
                    self.poisoned = true;
                    return;
                }
            }
        }
        self.ready.extend_from_slice(bytes);
    }

    fn evict_oldest_ooo(&mut self, target_bytes: usize) {
        // Drop the oldest (by arrival ts) until we're under cap.
        let mut by_age: Vec<(Timestamp, u32)> =
            self.pending.iter().map(|(k, (_, ts))| (*ts, *k)).collect();
        by_age.sort();
        for (_, key) in by_age {
            if self.pending_bytes <= target_bytes {
                break;
            }
            if let Some((bytes, _)) = self.pending.remove(&key) {
                self.pending_bytes = self.pending_bytes.saturating_sub(bytes.len());
                self.bytes_dropped_oversize += bytes.len() as u64;
            }
        }
    }

    /// Insert an OOO segment into pending, applying the
    /// configured [`TcpOverlapPolicy`] for byte-level overlap
    /// resolution against any pre-existing pending entries.
    ///
    /// Algorithm:
    /// 1. Find every existing entry whose range intersects
    ///    `[seq, seq+payload.len())`.
    /// 2. For each, detect content divergence in the overlap
    ///    region — increment `rexmit_inconsistencies` on the
    ///    first divergence (one per arrival, not per overlap).
    /// 3. Build a merged buffer for the *full union range*
    ///    where every byte comes from the policy-chosen
    ///    winner.
    /// 4. Apply the OOO-buffer cap (evict-oldest-if-over).
    /// 5. Remove the absorbed existing entries and insert the
    ///    merged range as a single new pending entry keyed at
    ///    `union_start`.
    fn absorb_ooo_with_policy(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        let new_end = seq.wrapping_add(payload.len() as u32);

        // Step 1+2: walk overlaps, collect inconsistency signal,
        // compute the union range.
        let mut overlapping_keys: Vec<u32> = Vec::new();
        let mut union_start = seq;
        let mut union_end = new_end;
        let mut divergence_seen = false;
        for (&start, (existing, _)) in &self.pending {
            let end = start.wrapping_add(existing.len() as u32);
            if !ranges_overlap(seq, new_end, start, end) {
                continue;
            }
            overlapping_keys.push(start);
            // Track the union [min(start), max(end)] in
            // sequence-space order.
            if seq_compare(start, union_start).is_lt() {
                union_start = start;
            }
            if seq_compare(end, union_end).is_gt() {
                union_end = end;
            }
            if !divergence_seen {
                let overlap_start = if seq_compare(seq, start).is_ge() {
                    seq
                } else {
                    start
                };
                let overlap_end = if seq_compare(new_end, end).is_le() {
                    new_end
                } else {
                    end
                };
                let overlap_len = overlap_end.wrapping_sub(overlap_start) as usize;
                let off_existing = overlap_start.wrapping_sub(start) as usize;
                let off_new = overlap_start.wrapping_sub(seq) as usize;
                if existing[off_existing..off_existing + overlap_len]
                    != payload[off_new..off_new + overlap_len]
                {
                    self.rexmit_inconsistencies = self.rexmit_inconsistencies.saturating_add(1);
                    divergence_seen = true;
                }
            }
        }

        // Hot path: no overlap → just insert.
        if overlapping_keys.is_empty() {
            self.cap_and_insert_ooo(seq, payload.to_vec(), ts);
            return;
        }

        // Step 3: build the merged buffer over the union range.
        let union_len = union_end.wrapping_sub(union_start) as usize;
        let mut merged: Vec<u8> = vec![0u8; union_len];
        // Track ownership per byte: arrival-ts of the segment
        // whose bytes are currently filled in that position.
        // `None` means "no segment yet" (sentinel).
        let mut owner_ts: Vec<Option<Timestamp>> = vec![None; union_len];
        let mut owner_seq: Vec<Option<u32>> = vec![None; union_len];

        // Process pending entries in insertion-order (BTreeMap
        // iteration is seq-sorted, so this lays older content
        // first; the policy decides whether to overwrite).
        for &start in &overlapping_keys {
            let (bytes, e_ts) = self.pending.get(&start).expect("just collected").clone();
            let end = start.wrapping_add(bytes.len() as u32);
            self.apply_segment_to_merge(
                start,
                end,
                &bytes,
                e_ts,
                union_start,
                &mut merged,
                &mut owner_ts,
                &mut owner_seq,
            );
        }
        // Now the new arrival.
        self.apply_segment_to_merge(
            seq,
            new_end,
            payload,
            ts,
            union_start,
            &mut merged,
            &mut owner_ts,
            &mut owner_seq,
        );

        // Step 4 + 5: drop absorbed entries from pending and the
        // pending-byte accounting, then re-insert the merged
        // range — subject to the OOO cap.
        for k in &overlapping_keys {
            if let Some((existing, _)) = self.pending.remove(k) {
                self.pending_bytes = self.pending_bytes.saturating_sub(existing.len());
            }
        }
        self.cap_and_insert_ooo(union_start, merged, ts);
    }

    /// Per-policy byte-level merge: copy bytes from `[start, end)`
    /// into `merged[start - union_start..end - union_start]`
    /// subject to the configured `overlap_policy`.
    #[allow(clippy::too_many_arguments)]
    fn apply_segment_to_merge(
        &self,
        start: u32,
        end: u32,
        bytes: &[u8],
        ts: Timestamp,
        union_start: u32,
        merged: &mut [u8],
        owner_ts: &mut [Option<Timestamp>],
        owner_seq: &mut [Option<u32>],
    ) {
        let union_offset = start.wrapping_sub(union_start) as usize;
        let len = end.wrapping_sub(start) as usize;
        for (i, &new_byte) in bytes.iter().take(len).enumerate() {
            let dst = union_offset + i;
            let take_new = match owner_ts[dst] {
                None => true, // no prior content — always take new
                Some(prev_ts) => {
                    let prev_seq = owner_seq[dst].expect("ts implies seq");
                    match self.overlap_policy {
                        TcpOverlapPolicy::First => {
                            // First-arrived wins → keep prev (only
                            // overwrite when no prior content).
                            false
                        }
                        TcpOverlapPolicy::Last => {
                            // Last-arrived wins → overwrite if new
                            // arrived strictly after prev. Tie →
                            // keep prev (stable).
                            ts > prev_ts
                        }
                        TcpOverlapPolicy::LowerSeq => {
                            // Segment with lower start-seq wins.
                            seq_compare(start, prev_seq).is_lt()
                        }
                        TcpOverlapPolicy::HigherSeq => {
                            // Segment with higher start-seq wins.
                            seq_compare(start, prev_seq).is_gt()
                        }
                    }
                }
            };
            if take_new {
                merged[dst] = new_byte;
                owner_ts[dst] = Some(ts);
                owner_seq[dst] = Some(start);
            }
        }
    }

    /// Apply the OOO buffer cap and insert a (possibly merged)
    /// range as a new pending entry.
    fn cap_and_insert_ooo(&mut self, seq: u32, bytes: Vec<u8>, ts: Timestamp) {
        if self.pending_bytes + bytes.len() > self.max_ooo_buffer {
            self.evict_oldest_ooo(self.max_ooo_buffer.saturating_sub(bytes.len()));
            if self.pending_bytes + bytes.len() > self.max_ooo_buffer {
                // Even after eviction, won't fit.
                self.bytes_dropped_oversize += bytes.len() as u64;
                return;
            }
        }
        self.pending_bytes += bytes.len();
        self.pending.insert(seq, (bytes, ts));
    }
}

impl Reassembler for SegmentBufferReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        if self.poisoned || payload.is_empty() {
            return;
        }

        // First segment establishes ISN.
        let next_expected = match self.next_seq {
            Some(n) => n,
            None => {
                self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_ready(payload);
                return;
            }
        };

        // In-order: append directly, then try to drain pending.
        if seq == next_expected {
            self.next_seq = Some(seq.wrapping_add(payload.len() as u32));
            self.append_ready(payload);
            self.try_drain_pending();
            return;
        }

        // Already-seen bytes (full or partial retransmit). RFC 5722:
        // strict overlap — reject the duplicate. Count it.
        if seq_compare(seq, next_expected).is_lt() {
            // Could be a partial retransmit or pure duplicate. We
            // count the segment but ignore its payload.
            self.retransmits += 1;
            return;
        }

        // OOO future segment. The pending buffer is a BTreeMap
        // of (start_seq → (bytes, arrival_ts)). To honour
        // [`TcpOverlapPolicy`] we:
        //   1. Walk every existing entry that overlaps with the
        //      new segment.
        //   2. For each overlapping pair, if the overlap-region
        //      bytes diverge, increment `rexmit_inconsistencies`
        //      (the IOC fires regardless of which side later
        //      wins the byte-level resolution).
        //   3. Apply the policy to merge: build a fresh byte
        //      buffer for the new segment's seq range where
        //      each overlapping byte comes from whichever
        //      segment wins, then replace the affected pending
        //      entries with the merged result.
        self.absorb_ooo_with_policy(seq, payload, ts);
    }

    fn fin(&mut self) {
        self.fin_observed = true;
    }

    fn rst(&mut self) {
        self.poisoned = true;
    }

    fn dropped_segments(&self) -> u64 {
        self.holes_expired
    }

    fn bytes_dropped_oversize(&self) -> u64 {
        self.bytes_dropped_oversize
    }

    fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    fn high_watermark(&self) -> u64 {
        self.pending_bytes as u64 + self.ready.len() as u64
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
        self.ready.shrink_to_fit();
        self.pending.clear();
        self.pending_bytes = 0;
        self.poisoned = true;
    }

    fn current_bytes(&self) -> u64 {
        // Ready + OOO-pending. `high_watermark` returns the
        // peak; `current_bytes` is the instantaneous occupancy
        // the cross-flow memcap layer reads.
        self.pending_bytes as u64 + self.ready.len() as u64
    }
}

/// Compare two TCP sequence numbers respecting 32-bit wrap.
/// Per RFC 1982 — comparing as a circle.
fn seq_compare(a: u32, b: u32) -> std::cmp::Ordering {
    let diff = a.wrapping_sub(b) as i32;
    diff.cmp(&0)
}

/// `true` when the two TCP-seq ranges `[a_start, a_end)` and
/// `[b_start, b_end)` overlap. Wrap-aware via `seq_compare`.
#[inline]
fn ranges_overlap(a_start: u32, a_end: u32, b_start: u32, b_end: u32) -> bool {
    seq_compare(a_start, b_end).is_lt() && seq_compare(b_start, a_end).is_lt()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
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
        // hello (5) at 1000, next = 1005
        r.segment(1000, b"hello", ts(0));
        // " flowscope" (10) at 1010, OOO — waits for hole.
        r.segment(1010, b" flowscope", ts(1));
        // "world" (5) at 1005 fills the hole. next = 1010 → drain pending.
        r.segment(1005, b"world", ts(2));
        let out = r.take();
        assert_eq!(out, b"helloworld flowscope");
        assert!(r.holes_filled() >= 1);
    }

    /// Issue #188: a single segment larger than the whole cap must
    /// not be appended whole. Dropping every buffered byte is not
    /// enough — the payload itself has to be trimmed, or the cap is
    /// a suggestion rather than a bound.
    #[test]
    fn a_segment_larger_than_the_cap_is_trimmed() {
        let mut r = SegmentBufferReassembler::new().with_max_buffer(8);
        r.segment(1000, b"abcd", ts(0));
        r.segment(1004, &[b'x'; 64], ts(0));

        let out = r.take();
        assert_eq!(out.len(), 8, "the buffer must respect its cap");
        assert_eq!(out, vec![b'x'; 8], "and keep the newest bytes");
        assert_eq!(
            r.bytes_dropped_oversize(),
            60,
            "every discarded byte is accounted for: 4 buffered + 56 trimmed"
        );
    }

    #[test]
    fn ooo_expires_past_deadline() {
        let mut r = SegmentBufferReassembler::new().with_ooo_deadline(Duration::from_millis(500));
        r.segment(1000, b"hello", ts(0));
        // Future OOO segment arriving at t=0.
        r.segment(1010, b"future", ts(0));
        // Sweep at t=10 — well past deadline.
        let expired = r.evict_expired_ooo(ts(10));
        assert_eq!(expired, 1);
        assert_eq!(r.holes_expired(), 1);
    }

    #[test]
    fn retransmits_counted_not_appended() {
        let mut r = SegmentBufferReassembler::new();
        r.segment(1000, b"hello", ts(0));
        // Re-send the same segment.
        r.segment(1000, b"hello", ts(1));
        assert_eq!(r.take(), b"hello");
        assert!(r.retransmits() >= 1);
    }

    #[test]
    fn ooo_cap_evicts_oldest() {
        let mut r = SegmentBufferReassembler::new().with_max_ooo_buffer(20);
        r.segment(1000, b"x", ts(0)); // in-order
        // Two OOO segments totalling > cap.
        r.segment(2000, b"01234567890", ts(1)); // 11 bytes
        r.segment(3000, b"01234567890", ts(2)); // 11 bytes — over cap
        // Should have evicted the older one.
        assert!(r.bytes_dropped_oversize() > 0);
    }

    #[test]
    fn drop_flow_policy_poisons_on_expiry() {
        let mut r = SegmentBufferReassembler::new()
            .with_ooo_deadline(Duration::from_millis(100))
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(1000, b"x", ts(0));
        r.segment(2000, b"future", ts(0));
        r.evict_expired_ooo(ts(10));
        assert!(r.is_poisoned());
    }

    #[test]
    fn rst_poisons() {
        let mut r = SegmentBufferReassembler::new();
        r.rst();
        assert!(r.is_poisoned());
    }
}
