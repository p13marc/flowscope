//! Sync TCP reassembly hooks.
//!
//! [`Reassembler`] is the trait users implement to consume TCP byte
//! streams from one direction of one session. [`BufferedReassembler`]
//! is the simplest possible impl: in-order accumulation into a
//! `Vec<u8>`, with out-of-order segments dropped.
//!
//! For tokio users with backpressure needs, see `netring`'s
//! `AsyncReassembler` and `channel_factory`.

use crate::{
    Timestamp,
    event::{FlowSide, OverflowPolicy},
};

/// Receives TCP segments for one direction of one session. Sync —
/// implementors don't await; for blocking consumers (Vec buffer,
/// `std::sync::mpsc`, sync protocol parsers).
pub trait Reassembler: Send + 'static {
    /// New segment arrived in this direction.
    ///
    /// `payload` borrows from the underlying frame — copy if you
    /// need it after returning. `ts` is the kernel/source timestamp
    /// of the packet carrying the segment; custom reassemblers can
    /// use it for RTT estimation, staleness tracking, etc.
    ///
    /// **Breaking change in 0.5.0:** the `ts` parameter is new (was
    /// just `seq, payload`). Existing impls need a one-line
    /// signature update; the default [`BufferedReassembler`] uses
    /// `ts` only when forwarding a duplicate segment via
    /// [`on_duplicate`](Self::on_duplicate).
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp);

    /// FIN observed in this direction. Default: no-op.
    fn fin(&mut self) {}

    /// RST observed in this direction (or session aborted).
    /// Default: no-op.
    fn rst(&mut self) {}

    /// Number of TCP segments dropped because they arrived out of
    /// order for this side. Default: 0.
    ///
    /// A default-zero return means "this implementation doesn't
    /// track that counter," not "the counter is zero." Custom
    /// reassemblers may surface their own drop accounting via this
    /// method. Distinct from [`retransmits`](Self::retransmits) —
    /// out-of-order means the segment carries bytes the reassembler
    /// hasn't yet seen; a retransmit re-delivers already-accounted
    /// bytes.
    fn dropped_segments(&self) -> u64 {
        0
    }

    /// Number of payload bytes dropped because the per-side buffer
    /// cap was exceeded. Default: 0.
    ///
    /// A default-zero return means "this implementation doesn't
    /// track that counter." Only meaningful when the reassembler
    /// implements a cap (see [`BufferedReassembler::with_max_buffer`]).
    fn bytes_dropped_oversize(&self) -> u64 {
        0
    }

    /// True after a fatal-style overflow (e.g.
    /// [`crate::OverflowPolicy::DropFlow`]). The driver checks this
    /// once per tick; `true` triggers synthesis of an
    /// `Ended { reason: BufferOverflow }` event for the flow.
    /// Default: `false`.
    fn is_poisoned(&self) -> bool {
        false
    }

    /// Peak in-flight buffer occupancy ever observed for this side.
    /// Default: `0` (custom reassemblers may not track this).
    ///
    /// A default-zero return means "this implementation doesn't
    /// track that counter," not "the buffer never had bytes." Only
    /// meaningful when the reassembler implements an in-memory
    /// buffer (see [`BufferedReassembler::high_watermark`]).
    fn high_watermark(&self) -> u64 {
        0
    }

    /// Bytes currently buffered, awaiting parser consumption.
    /// Default: `0`. Mirrors the contract of [`Self::high_watermark`]
    /// — only meaningful for impls that actually buffer bytes.
    fn bytes_in_flight(&self) -> u64 {
        0
    }

    /// Running count of below→above transitions of the configured
    /// high-watermark threshold (see [`BufferedReassembler::
    /// with_high_watermark_threshold`]). Default: `0`. The driver
    /// uses per-tick deltas of this counter to emit
    /// [`crate::AnomalyKind::ReassemblerHighWatermark`] events
    /// without spamming on repeated above-threshold ticks.
    fn high_watermark_crossings(&self) -> u64 {
        0
    }

    /// `Some((cap, percent))` when a high-watermark threshold is
    /// configured; `None` otherwise. Lets the driver enrich
    /// [`crate::AnomalyKind::ReassemblerHighWatermark`] events with
    /// the cap and threshold percent at emission time. Default:
    /// `None`.
    fn high_watermark_threshold(&self) -> Option<(u64, u8)> {
        None
    }

    /// Number of TCP segments classified as retransmits — re-deliveries
    /// of bytes the reassembler has already accounted for
    /// (`seq + len <= expected_seq`). New in 0.5.0; default `0`.
    ///
    /// A default-zero return means "this implementation doesn't
    /// classify duplicates," not "no retransmits occurred." The
    /// built-in [`BufferedReassembler`] populates this; custom
    /// reassemblers may override.
    fn retransmits(&self) -> u64 {
        0
    }

    /// Hook called when a segment is classified as a retransmit
    /// rather than appended to the buffer. Default no-op. Custom
    /// reassemblers can use this to drive RTT estimators,
    /// retransmit-rate metrics, etc. Called by
    /// [`BufferedReassembler`] for each classified retransmit; not
    /// called for fresh or OOO segments.
    fn on_duplicate(&mut self, _seq: u32, _payload: &[u8], _ts: Timestamp) {}

    /// Running count of retransmits whose bytes differ from what
    /// the reassembler previously saw for the overlapping
    /// sequence range — the classic Ptacek-Newsham TCP overlap
    /// evasion IOC (cf. Zeek's `rexmit_inconsistency`). Default
    /// `0` for implementations that don't retain enough history
    /// to detect the divergence.
    ///
    /// Detection scope today is implementation-specific:
    /// [`crate::SegmentBufferReassembler`] compares incoming
    /// segments against bytes still pending in its OOO buffer
    /// before draining; the simpler [`BufferedReassembler`]
    /// returns `0` because it doesn't retain the original bytes
    /// after they drain.
    ///
    /// New in 0.18.0 (issue #17 sub-piece).
    fn rexmit_inconsistencies(&self) -> u64 {
        0
    }
}

/// Build a [`Reassembler`] for a brand-new session, given its key
/// and side. Modeled after gopacket's `StreamFactory`.
pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
}

/// Discards every segment without buffering. Used by the unified
/// [`crate::driver::Driver`] as the central
/// [`FlowDriver`](crate::FlowDriver)'s reassembler factory when
/// the driver itself doesn't need byte-stream reassembly — that
/// work happens inside each registered slot's own
/// [`FlowSessionDriver`](crate::FlowSessionDriver). Plan-116
/// support.
///
/// New in 0.10.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopReassembler;

impl Reassembler for NoopReassembler {
    fn segment(&mut self, _seq: u32, _payload: &[u8], _ts: Timestamp) {}
}

/// Factory for [`NoopReassembler`]. New in 0.10.0.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopReassemblerFactory;

impl<K> ReassemblerFactory<K> for NoopReassemblerFactory {
    type Reassembler = NoopReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> NoopReassembler {
        NoopReassembler
    }
}

/// Built-in: drop OOO segments, accumulate in-order bytes into a
/// `Vec<u8>` per direction. Drain via [`take`](Self::take).
///
/// Sync, no channel dep. Users who want a channel send via
/// `std::sync::mpsc` themselves, or use `netring`'s
/// `TokioChannelReassembler` for tokio integration.
///
/// Optionally bounded via [`with_max_buffer`](Self::with_max_buffer).
/// When the cap is reached the [`OverflowPolicy`] decides whether to
/// rotate bytes out (sliding window) or poison the reassembler so
/// the driver can tear the flow down on the next tick.
#[derive(Debug, Default)]
pub struct BufferedReassembler {
    buffer: Vec<u8>,
    expected_seq: Option<u32>,
    dropped_segments: u64,
    bytes_dropped_oversize: u64,
    max_buffer: Option<usize>,
    overflow_policy: OverflowPolicy,
    poisoned: bool,
    high_watermark: u64,
    /// Threshold (% of `max_buffer`) above which a
    /// `ReassemblerHighWatermark` anomaly fires. `None` = off.
    high_watermark_threshold_pct: Option<u8>,
    /// `true` when occupancy is currently at or above the
    /// configured threshold. Cleared when occupancy falls back
    /// below, so a second crossing re-arms the event.
    above_threshold: bool,
    /// Running count of below→above transitions.
    high_watermark_crossings: u64,
    /// Running count of segments classified as retransmits.
    retransmits: u64,
}

impl BufferedReassembler {
    pub fn new() -> Self {
        Self::default()
    }

    /// Set a maximum in-flight buffer size in bytes. When new
    /// in-order segments would push `buffered_len()` past this cap,
    /// the configured [`OverflowPolicy`] kicks in.
    ///
    /// Default policy is [`OverflowPolicy::SlidingWindow`]. Pair with
    /// [`with_overflow_policy`](Self::with_overflow_policy) to switch
    /// to [`OverflowPolicy::DropFlow`] for framed binary protocols.
    pub fn with_max_buffer(mut self, max_bytes: usize) -> Self {
        self.max_buffer = Some(max_bytes);
        self
    }

    /// Override the overflow policy. Has no effect unless
    /// [`with_max_buffer`](Self::with_max_buffer) is also called.
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// Fire a [`crate::AnomalyKind::ReassemblerHighWatermark`]
    /// anomaly when buffer occupancy crosses `percent` % of
    /// `max_buffer` from below — once per crossing (debounced;
    /// occupancy must drop back below before the next event
    /// re-arms). Default: off.
    ///
    /// No effect unless [`with_max_buffer`](Self::with_max_buffer)
    /// is also set. Values outside `1..=100` are clamped.
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self {
        self.high_watermark_threshold_pct = Some(percent.clamp(1, 100));
        self
    }

    /// Drain accumulated in-order bytes, leaving the buffer empty.
    /// `expected_seq` is preserved so subsequent in-order segments
    /// keep accumulating. Also re-arms the high-watermark threshold
    /// (if configured): once drained, the next time occupancy
    /// climbs back above the threshold counts as a fresh crossing.
    pub fn take(&mut self) -> Vec<u8> {
        let bytes = std::mem::take(&mut self.buffer);
        // Drain → definitely below threshold → re-arm the
        // below→above edge detector.
        self.above_threshold = false;
        bytes
    }

    /// Number of segments dropped because they were out of order.
    pub fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    /// Number of payload bytes dropped because the per-side buffer
    /// cap was exceeded. Zero when no cap is set or when the cap has
    /// not yet been hit.
    pub fn bytes_dropped_oversize(&self) -> u64 {
        self.bytes_dropped_oversize
    }

    /// Bytes currently buffered (not yet drained).
    pub fn buffered_len(&self) -> usize {
        self.buffer.len()
    }

    /// True after an [`OverflowPolicy::DropFlow`] overflow. The
    /// driver checks this once per tick; `true` triggers an
    /// `Ended { reason: BufferOverflow }` event for the flow.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned
    }

    /// Peak buffer occupancy ever observed for this reassembler.
    /// Updated on every `append_with_cap` call, reflecting
    /// post-rotation state under [`OverflowPolicy::SlidingWindow`].
    /// Survives [`take`](Self::take) — useful for tuning
    /// [`crate::FlowTrackerConfig::max_reassembler_buffer`].
    pub fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Number of TCP segments classified as retransmits on this
    /// side — `seq + len <= expected_seq`. Distinct from
    /// [`dropped_segments`](Self::dropped_segments), which counts
    /// strictly-out-of-order segments ahead of `expected_seq`.
    /// New in 0.5.0.
    pub fn retransmits(&self) -> u64 {
        self.retransmits
    }

    fn append_with_cap(&mut self, payload: &[u8]) {
        let Some(cap) = self.max_buffer else {
            self.buffer.extend_from_slice(payload);
            self.update_watermark();
            return;
        };
        if self.poisoned {
            return;
        }
        let projected = self.buffer.len() + payload.len();
        if projected <= cap {
            self.buffer.extend_from_slice(payload);
            self.update_watermark();
            return;
        }
        match self.overflow_policy {
            OverflowPolicy::DropFlow => {
                self.bytes_dropped_oversize += payload.len() as u64;
                self.buffer.clear();
                self.poisoned = true;
            }
            OverflowPolicy::SlidingWindow => {
                let to_drop = projected - cap;
                if to_drop >= self.buffer.len() {
                    self.bytes_dropped_oversize += self.buffer.len() as u64;
                    self.buffer.clear();
                    if payload.len() > cap {
                        let extra = payload.len() - cap;
                        self.bytes_dropped_oversize += extra as u64;
                        self.buffer.extend_from_slice(&payload[extra..]);
                    } else {
                        self.buffer.extend_from_slice(payload);
                    }
                } else {
                    self.bytes_dropped_oversize += to_drop as u64;
                    self.buffer.drain(..to_drop);
                    self.buffer.extend_from_slice(payload);
                }
                self.update_watermark();
            }
        }
    }

    #[inline]
    fn update_watermark(&mut self) {
        let len = self.buffer.len() as u64;
        if len > self.high_watermark {
            self.high_watermark = len;
        }
        // High-watermark threshold edge detection.
        if let (Some(pct), Some(cap)) = (self.high_watermark_threshold_pct, self.max_buffer) {
            let trigger = (cap as u64).saturating_mul(pct as u64) / 100;
            if len >= trigger {
                if !self.above_threshold {
                    self.above_threshold = true;
                    self.high_watermark_crossings = self.high_watermark_crossings.saturating_add(1);
                }
            } else {
                self.above_threshold = false;
            }
        }
    }
}

impl BufferedReassembler {
    /// Running count of below→above transitions of the configured
    /// high-watermark threshold. Zero when no threshold is set.
    pub fn high_watermark_crossings(&self) -> u64 {
        self.high_watermark_crossings
    }
}

impl Reassembler for BufferedReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        if payload.is_empty() {
            return;
        }
        if self.poisoned {
            return;
        }
        match self.expected_seq {
            None => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_with_cap(payload);
            }
            Some(exp) if seq == exp => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_with_cap(payload);
            }
            Some(exp) => {
                // Classify against `expected_seq` in wrap-aware
                // sequence-space. A segment whose end is at-or-before
                // `exp` is a retransmit (already accounted for); a
                // segment strictly past `exp` is out-of-order.
                // Partial overlap (`seq < exp < seq+len`) is
                // classified as a retransmit because
                // `BufferedReassembler` doesn't gap-fill; users who
                // need byte-exact accounting want a custom
                // reassembler or [`SegmentBufferReassembler`] when
                // Plan 74 lands.
                let end = seq.wrapping_add(payload.len() as u32);
                if seq_lte(end, exp) {
                    self.retransmits += 1;
                    self.on_duplicate(seq, payload, ts);
                } else if seq_lt(seq, exp) {
                    // Partial overlap — count as retransmit.
                    self.retransmits += 1;
                    self.on_duplicate(seq, payload, ts);
                } else {
                    self.dropped_segments += 1;
                }
            }
        }
    }

    fn dropped_segments(&self) -> u64 {
        Self::dropped_segments(self)
    }

    fn bytes_dropped_oversize(&self) -> u64 {
        Self::bytes_dropped_oversize(self)
    }

    fn is_poisoned(&self) -> bool {
        Self::is_poisoned(self)
    }

    fn high_watermark(&self) -> u64 {
        Self::high_watermark(self)
    }

    fn bytes_in_flight(&self) -> u64 {
        self.buffer.len() as u64
    }

    fn high_watermark_crossings(&self) -> u64 {
        Self::high_watermark_crossings(self)
    }

    fn high_watermark_threshold(&self) -> Option<(u64, u8)> {
        match (self.max_buffer, self.high_watermark_threshold_pct) {
            (Some(cap), Some(pct)) => Some((cap as u64, pct)),
            _ => None,
        }
    }

    fn retransmits(&self) -> u64 {
        Self::retransmits(self)
    }
}

/// `a < b` in TCP sequence-space (wrap-aware). Treats `a` and `b`
/// as `u32` sequence numbers; differences exceeding 2^31 are
/// interpreted as backward via two's-complement.
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}

/// `a <= b` in TCP sequence-space.
#[inline]
fn seq_lte(a: u32, b: u32) -> bool {
    a == b || seq_lt(a, b)
}

/// Default factory that builds a fresh [`BufferedReassembler`] per
/// (flow, side). Useful when you want byte buffers without
/// implementing a custom factory.
///
/// Optionally configures the per-reassembler buffer cap and overflow
/// policy via [`with_max_buffer`](Self::with_max_buffer) /
/// [`with_overflow_policy`](Self::with_overflow_policy). The same
/// settings apply to every reassembler this factory creates.
#[derive(Debug, Default)]
pub struct BufferedReassemblerFactory {
    max_buffer: Option<usize>,
    overflow_policy: OverflowPolicy,
    high_watermark_threshold_pct: Option<u8>,
}

impl BufferedReassemblerFactory {
    /// Apply the same cap to every reassembler this factory creates.
    pub fn with_max_buffer(mut self, max_bytes: usize) -> Self {
        self.max_buffer = Some(max_bytes);
        self
    }

    /// Apply the same overflow policy to every reassembler this
    /// factory creates. Has no effect unless
    /// [`with_max_buffer`](Self::with_max_buffer) is also called.
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    /// Apply the same high-watermark threshold (% of `max_buffer`)
    /// to every reassembler this factory creates. See
    /// [`BufferedReassembler::with_high_watermark_threshold`].
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self {
        self.high_watermark_threshold_pct = Some(percent.clamp(1, 100));
        self
    }
}

impl<K: Send + 'static> ReassemblerFactory<K> for BufferedReassemblerFactory {
    type Reassembler = BufferedReassembler;

    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> BufferedReassembler {
        let mut r = BufferedReassembler::new();
        if let Some(cap) = self.max_buffer {
            r = r
                .with_max_buffer(cap)
                .with_overflow_policy(self.overflow_policy);
        }
        if let Some(pct) = self.high_watermark_threshold_pct {
            r = r.with_high_watermark_threshold(pct);
        }
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_concatenates() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"abc", Timestamp::default());
        r.segment(103, b"def", Timestamp::default());
        r.segment(106, b"gh", Timestamp::default());
        assert_eq!(r.take(), b"abcdefgh");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn ooo_dropped() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"hello", Timestamp::default()); // expect_next = 105
        r.segment(110, b"world", Timestamp::default()); // out of order — dropped
        assert_eq!(r.take(), b"hello");
        assert_eq!(r.dropped_segments(), 1);
    }

    #[test]
    fn take_resets_buffer_only() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc", Timestamp::default()); // expect_next = 3
        let drained = r.take();
        assert_eq!(drained, b"abc");
        assert_eq!(r.buffered_len(), 0);
        // Subsequent in-order segment continues from where we were.
        r.segment(3, b"def", Timestamp::default());
        assert_eq!(r.take(), b"def");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn empty_payload_ignored() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"", Timestamp::default());
        assert_eq!(r.expected_seq, None);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn factory_creates_fresh_reassembler() {
        let mut f = BufferedReassemblerFactory::default();
        let mut r1: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Initiator);
        let mut r2: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Responder);
        r1.segment(0, b"x", Timestamp::default());
        r2.segment(0, b"y", Timestamp::default());
        assert_eq!(r1.take(), b"x");
        assert_eq!(r2.take(), b"y");
    }

    #[test]
    fn fin_rst_default_noops_compile() {
        let mut r = BufferedReassembler::new();
        r.fin();
        r.rst();
        // No-op defaults exist; this test just confirms they compile.
    }

    #[test]
    fn cap_unbounded_by_default() {
        let mut r = BufferedReassembler::new();
        r.segment(0, &[0u8; 10_000], Timestamp::default());
        assert_eq!(r.buffered_len(), 10_000);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert!(!r.is_poisoned());
    }

    #[test]
    fn cap_drops_oldest_on_overflow_sliding_window() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        // Next segment is in-order (seq = 80, len = 80) — would push
        // buffer to 160; cap is 100 so 60 oldest 'a's get dropped.
        r.segment(80, &[b'b'; 80], Timestamp::default());
        assert_eq!(r.buffered_len(), 100);
        assert_eq!(r.bytes_dropped_oversize(), 60);
        let drained = r.take();
        assert_eq!(&drained[..20], &[b'a'; 20][..]);
        assert_eq!(&drained[20..], &[b'b'; 80][..]);
    }

    #[test]
    fn cap_payload_bigger_than_cap_keeps_tail() {
        let mut r = BufferedReassembler::new().with_max_buffer(50);
        let payload: Vec<u8> = (0u8..100).collect();
        r.segment(0, &payload, Timestamp::default());
        assert_eq!(r.buffered_len(), 50);
        assert_eq!(r.bytes_dropped_oversize(), 50);
        assert_eq!(r.take(), (50u8..100).collect::<Vec<u8>>());
    }

    #[test]
    fn cap_skips_ooo_segments_without_changing_overflow_counter() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        r.segment(200, &[b'b'; 80], Timestamp::default()); // OOO — dropped via existing path
        assert_eq!(r.dropped_segments(), 1);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert_eq!(r.buffered_len(), 80);
    }

    #[test]
    fn cap_take_resets_buffer_but_not_counters() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        r.segment(80, &[b'b'; 80], Timestamp::default()); // bytes_dropped_oversize += 60
        let _ = r.take();
        r.segment(160, &[b'c'; 80], Timestamp::default()); // buf = 80
        assert_eq!(r.buffered_len(), 80);
        assert_eq!(r.bytes_dropped_oversize(), 60);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn cap_poisons_on_overflow_drop_flow() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        assert!(!r.is_poisoned());
        r.segment(80, &[b'b'; 80], Timestamp::default()); // would overflow → poison
        assert!(r.is_poisoned());
        assert_eq!(r.bytes_dropped_oversize(), 80);
        assert_eq!(r.buffered_len(), 0);
        // Subsequent segments are no-ops.
        r.segment(160, &[b'c'; 10], Timestamp::default());
        assert_eq!(r.buffered_len(), 0);
        assert_eq!(r.bytes_dropped_oversize(), 80);
    }

    #[test]
    fn cap_drop_flow_does_not_poison_under_cap() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 50], Timestamp::default());
        r.segment(50, &[b'b'; 50], Timestamp::default()); // exactly at cap — no poison
        assert!(!r.is_poisoned());
        assert_eq!(r.buffered_len(), 100);
        assert_eq!(r.bytes_dropped_oversize(), 0);
    }

    #[test]
    fn factory_propagates_cap_and_policy() {
        let mut f = BufferedReassemblerFactory::default()
            .with_max_buffer(64)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 100], Timestamp::default());
        assert!(r.is_poisoned());
    }

    #[test]
    fn factory_default_unbounded() {
        let mut f = BufferedReassemblerFactory::default();
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 10_000], Timestamp::default());
        assert_eq!(r.buffered_len(), 10_000);
        assert!(!r.is_poisoned());
    }

    #[test]
    fn high_watermark_tracks_peak_buffer_unbounded() {
        let mut r = BufferedReassembler::new();
        r.segment(0, &[b'a'; 50], Timestamp::default());
        assert_eq!(r.high_watermark(), 50);
        let _ = r.take(); // drains buffer but does NOT reset watermark
        assert_eq!(r.high_watermark(), 50);
        r.segment(50, &[b'b'; 20], Timestamp::default());
        assert_eq!(r.high_watermark(), 50, "buffer is now 20 < 50; unchanged");
        let _ = r.take();
        r.segment(70, &[b'c'; 100], Timestamp::default());
        assert_eq!(r.high_watermark(), 100);
    }

    #[test]
    fn high_watermark_reflects_post_rotation_under_sliding_window() {
        // Cap = 100, sliding window. Push 80, watermark = 80.
        // Push 80 more: 60 dropped from front, buffer ends at 100,
        // watermark bumps to 100.
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        assert_eq!(r.high_watermark(), 80);
        r.segment(80, &[b'b'; 80], Timestamp::default());
        assert_eq!(r.high_watermark(), 100);
    }

    #[test]
    fn high_watermark_stays_at_pre_poison_peak_drop_flow() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 80], Timestamp::default());
        assert_eq!(r.high_watermark(), 80);
        r.segment(80, &[b'b'; 80], Timestamp::default()); // poisons; buffer cleared
        assert!(r.is_poisoned());
        assert_eq!(r.high_watermark(), 80);
        // Post-poison segments are no-ops; watermark stays.
        r.segment(160, &[b'c'; 10], Timestamp::default());
        assert_eq!(r.high_watermark(), 80);
    }

    /// Plan 44: threshold off by default — no crossings.
    #[test]
    fn high_watermark_threshold_off_by_default() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 95], Timestamp::default());
        assert_eq!(r.high_watermark_crossings(), 0);
    }

    /// Plan 44: threshold crossing fires once per below→above
    /// transition (debounced).
    #[test]
    fn high_watermark_threshold_crosses_once() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_high_watermark_threshold(80);
        // Below threshold — no crossing yet.
        r.segment(0, &[b'a'; 50], Timestamp::default());
        assert_eq!(r.high_watermark_crossings(), 0);
        // Cross to 90 (>= 80% of 100) — first crossing.
        r.segment(50, &[b'b'; 40], Timestamp::default());
        assert_eq!(r.high_watermark_crossings(), 1);
        // Stay above — no new crossing (debounce).
        r.segment(90, &[b'c'; 5], Timestamp::default());
        assert_eq!(r.high_watermark_crossings(), 1);
        // Drain back below threshold.
        let _ = r.take();
        // Re-cross by feeding new bytes — second crossing.
        r.segment(95, &[b'd'; 85], Timestamp::default());
        assert_eq!(r.high_watermark_crossings(), 2);
    }

    /// Plan 44: `high_watermark_threshold()` surfaces the config so
    /// the driver can enrich the anomaly event.
    #[test]
    fn high_watermark_threshold_info_visible_via_trait() {
        use super::Reassembler;
        let r = BufferedReassembler::new()
            .with_max_buffer(200)
            .with_high_watermark_threshold(75);
        assert_eq!(r.high_watermark_threshold(), Some((200, 75)));
        // Without max_buffer the threshold is inert (None).
        let r2 = BufferedReassembler::new().with_high_watermark_threshold(75);
        assert_eq!(r2.high_watermark_threshold(), None);
        // And `bytes_in_flight` matches actual buffered length.
        let mut r3 = BufferedReassembler::new().with_max_buffer(100);
        r3.segment(0, &[b'x'; 42], Timestamp::default());
        assert_eq!(r3.bytes_in_flight(), 42);
    }

    /// Percent values outside `1..=100` are clamped.
    #[test]
    fn high_watermark_threshold_percent_clamped() {
        use super::Reassembler;
        let r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_high_watermark_threshold(0);
        assert_eq!(r.high_watermark_threshold(), Some((100, 1)));
        let r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_high_watermark_threshold(200);
        assert_eq!(r.high_watermark_threshold(), Some((100, 100)));
    }

    #[test]
    fn exact_retransmit_classified_as_retransmit_not_ooo() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", Timestamp::new(1, 0));
        r.segment(0, b"hello", Timestamp::new(2, 0)); // exact retransmit
        assert_eq!(r.retransmits(), 1);
        assert_eq!(r.dropped_segments(), 0);
        assert_eq!(r.buffered_len(), 5);
        assert_eq!(r.take(), b"hello");
    }

    #[test]
    fn partial_overlap_classified_as_retransmit() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", Timestamp::new(1, 0)); // exp = 5
        r.segment(3, b"lo", Timestamp::new(2, 0)); // ends at 5 — already accounted
        assert_eq!(r.retransmits(), 1);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn strict_ooo_classified_as_dropped_not_retransmit() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", Timestamp::new(1, 0)); // exp = 5
        r.segment(100, b"x", Timestamp::new(2, 0)); // strictly past expected
        assert_eq!(r.retransmits(), 0);
        assert_eq!(r.dropped_segments(), 1);
    }

    #[test]
    fn on_duplicate_receives_ts() {
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct Spy {
            inner: BufferedReassembler,
            seen: Arc<Mutex<Vec<Timestamp>>>,
        }
        impl Reassembler for Spy {
            fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
                self.inner.segment(seq, payload, ts);
            }
            fn on_duplicate(&mut self, _seq: u32, _payload: &[u8], ts: Timestamp) {
                self.seen.lock().unwrap().push(ts);
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut spy = Spy {
            inner: BufferedReassembler::new(),
            seen: seen.clone(),
        };
        spy.segment(0, b"hello", Timestamp::new(1, 0));
        // Drive `on_duplicate` directly — the Spy's `segment` impl
        // forwards to BufferedReassembler but doesn't call
        // `on_duplicate` on Self; that confirms the contract: the
        // base impl only calls on_duplicate on itself, custom
        // wrappers need explicit forwarding. (Tested with a direct
        // call here to verify the signature surfaces ts at all.)
        spy.on_duplicate(0, b"hello", Timestamp::new(7, 42));
        assert_eq!(seen.lock().unwrap().as_slice(), &[Timestamp::new(7, 42)]);
    }

    #[test]
    fn retransmits_survives_take() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc", Timestamp::default()); // exp = 3
        r.segment(0, b"abc", Timestamp::default()); // retransmit
        let _ = r.take();
        assert_eq!(r.retransmits(), 1);
        r.segment(3, b"def", Timestamp::default());
        r.segment(3, b"def", Timestamp::default()); // retransmit #2
        assert_eq!(r.retransmits(), 2);
    }

    #[test]
    fn retransmit_and_ooo_counters_are_independent() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abcdefgh", Timestamp::default()); // exp = 8
        r.segment(0, b"abc", Timestamp::default()); // retransmit
        r.segment(100, b"x", Timestamp::default()); // OOO
        r.segment(2, b"cd", Timestamp::default()); // partial-overlap retransmit
        assert_eq!(r.retransmits(), 2);
        assert_eq!(r.dropped_segments(), 1);
    }
}
