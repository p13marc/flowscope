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
use crate::event::OverflowPolicy;
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

    // Counters.
    holes_filled: u64,
    holes_expired: u64,
    retransmits: u64,
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
            holes_filled: 0,
            holes_expired: 0,
            retransmits: 0,
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

        // OOO future segment.
        if self.pending_bytes + payload.len() > self.max_ooo_buffer {
            self.evict_oldest_ooo(self.max_ooo_buffer.saturating_sub(payload.len()));
            if self.pending_bytes + payload.len() > self.max_ooo_buffer {
                // Even after eviction, won't fit. Drop this segment.
                self.bytes_dropped_oversize += payload.len() as u64;
                return;
            }
        }
        self.pending.insert(seq, (payload.to_vec(), ts));
        self.pending_bytes += payload.len();
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
}

/// Compare two TCP sequence numbers respecting 32-bit wrap.
/// Per RFC 1982 — comparing as a circle.
fn seq_compare(a: u32, b: u32) -> std::cmp::Ordering {
    let diff = a.wrapping_sub(b) as i32;
    diff.cmp(&0)
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
