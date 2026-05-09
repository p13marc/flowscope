//! Sync TCP reassembly hooks.
//!
//! [`Reassembler`] is the trait users implement to consume TCP byte
//! streams from one direction of one session. [`BufferedReassembler`]
//! is the simplest possible impl: in-order accumulation into a
//! `Vec<u8>`, with out-of-order segments dropped.
//!
//! For tokio users with backpressure needs, see `netring`'s
//! `AsyncReassembler` and `channel_factory`.

use crate::event::{FlowSide, OverflowPolicy};

/// Receives TCP segments for one direction of one session. Sync —
/// implementors don't await; for blocking consumers (Vec buffer,
/// `std::sync::mpsc`, sync protocol parsers).
pub trait Reassembler: Send + 'static {
    /// New segment arrived in this direction.
    ///
    /// `payload` borrows from the underlying frame — copy if you
    /// need it after returning.
    fn segment(&mut self, seq: u32, payload: &[u8]);

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
    /// method.
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
}

/// Build a [`Reassembler`] for a brand-new session, given its key
/// and side. Modeled after gopacket's `StreamFactory`.
pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;
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

    /// Drain accumulated in-order bytes, leaving the buffer empty.
    /// `expected_seq` is preserved so subsequent in-order segments
    /// keep accumulating.
    pub fn take(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.buffer)
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

    fn append_with_cap(&mut self, payload: &[u8]) {
        let Some(cap) = self.max_buffer else {
            self.buffer.extend_from_slice(payload);
            return;
        };
        if self.poisoned {
            return;
        }
        let projected = self.buffer.len() + payload.len();
        if projected <= cap {
            self.buffer.extend_from_slice(payload);
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
            }
        }
    }
}

impl Reassembler for BufferedReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8]) {
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
            Some(_) => {
                self.dropped_segments += 1;
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
        r
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn in_order_concatenates() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"abc");
        r.segment(103, b"def");
        r.segment(106, b"gh");
        assert_eq!(r.take(), b"abcdefgh");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn ooo_dropped() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"hello"); // expect_next = 105
        r.segment(110, b"world"); // out of order — dropped
        assert_eq!(r.take(), b"hello");
        assert_eq!(r.dropped_segments(), 1);
    }

    #[test]
    fn take_resets_buffer_only() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc"); // expect_next = 3
        let drained = r.take();
        assert_eq!(drained, b"abc");
        assert_eq!(r.buffered_len(), 0);
        // Subsequent in-order segment continues from where we were.
        r.segment(3, b"def");
        assert_eq!(r.take(), b"def");
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn empty_payload_ignored() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"");
        assert_eq!(r.expected_seq, None);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn factory_creates_fresh_reassembler() {
        let mut f = BufferedReassemblerFactory::default();
        let mut r1: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Initiator);
        let mut r2: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Responder);
        r1.segment(0, b"x");
        r2.segment(0, b"y");
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
        r.segment(0, &[0u8; 10_000]);
        assert_eq!(r.buffered_len(), 10_000);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert!(!r.is_poisoned());
    }

    #[test]
    fn cap_drops_oldest_on_overflow_sliding_window() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80]);
        // Next segment is in-order (seq = 80, len = 80) — would push
        // buffer to 160; cap is 100 so 60 oldest 'a's get dropped.
        r.segment(80, &[b'b'; 80]);
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
        r.segment(0, &payload);
        assert_eq!(r.buffered_len(), 50);
        assert_eq!(r.bytes_dropped_oversize(), 50);
        assert_eq!(r.take(), (50u8..100).collect::<Vec<u8>>());
    }

    #[test]
    fn cap_skips_ooo_segments_without_changing_overflow_counter() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80]);
        r.segment(200, &[b'b'; 80]); // OOO — dropped via existing path
        assert_eq!(r.dropped_segments(), 1);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert_eq!(r.buffered_len(), 80);
    }

    #[test]
    fn cap_take_resets_buffer_but_not_counters() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80]);
        r.segment(80, &[b'b'; 80]); // bytes_dropped_oversize += 60
        let _ = r.take();
        r.segment(160, &[b'c'; 80]); // buf = 80
        assert_eq!(r.buffered_len(), 80);
        assert_eq!(r.bytes_dropped_oversize(), 60);
        assert_eq!(r.dropped_segments(), 0);
    }

    #[test]
    fn cap_poisons_on_overflow_drop_flow() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 80]);
        assert!(!r.is_poisoned());
        r.segment(80, &[b'b'; 80]); // would overflow → poison
        assert!(r.is_poisoned());
        assert_eq!(r.bytes_dropped_oversize(), 80);
        assert_eq!(r.buffered_len(), 0);
        // Subsequent segments are no-ops.
        r.segment(160, &[b'c'; 10]);
        assert_eq!(r.buffered_len(), 0);
        assert_eq!(r.bytes_dropped_oversize(), 80);
    }

    #[test]
    fn cap_drop_flow_does_not_poison_under_cap() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 50]);
        r.segment(50, &[b'b'; 50]); // exactly at cap — no poison
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
        r.segment(0, &[0u8; 100]);
        assert!(r.is_poisoned());
    }

    #[test]
    fn factory_default_unbounded() {
        let mut f = BufferedReassemblerFactory::default();
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 10_000]);
        assert_eq!(r.buffered_len(), 10_000);
        assert!(!r.is_poisoned());
    }
}
