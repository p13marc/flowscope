//! Sync TCP reassembly hooks.
//!
//! [`Reassembler`] is the trait users implement to consume TCP byte
//! streams from one direction of one session. Two built-in
//! implementations ship:
//!
//! - [`BufferedReassembler`] — in-order accumulation into a buffer.
//!   It holds no out-of-order data: a segment that arrives ahead of
//!   the expected sequence number makes it skip the hole and report
//!   a **gap**.
//! - [`crate::SegmentBufferReassembler`] — buffers out-of-order
//!   segments and fills holes when the missing bytes arrive; a hole
//!   that cannot be filled (deadline, buffer cap, end of stream) is
//!   skipped and reported as a gap.
//!
//! # Gaps
//!
//! A passive observer sees packets the endpoints may never have
//! needed to retransmit (capture drops, asymmetric routing), so a
//! hole in the sequence space is not always going to be filled. A
//! reassembler that waits for it forever wedges the whole direction.
//! Both built-ins therefore skip unfillable holes and say so: the
//! reassembled output is a [`StreamChunks`] — in-order bytes
//! interleaved with gap markers — so the consumer (typically a
//! [`crate::SessionParser`], through [`crate::SessionParser::on_gap`])
//! knows exactly where bytes are missing instead of being handed a
//! silently spliced stream.
//!
//! For tokio users with backpressure needs, see `netring`'s
//! `AsyncReassembler` and `channel_factory`.

pub use crate::event::ReassemblyStop;
use crate::{
    Timestamp,
    event::{FlowSide, OverflowPolicy},
    tracker::FlowTrackerConfig,
};

/// A gap marker inside a [`StreamChunks`]: `len` bytes are missing
/// immediately before byte offset `at`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct GapMark {
    at: usize,
    len: u64,
}

/// Reassembled output of one direction of a stream: in-order bytes,
/// the gaps between them, and an optional terminal
/// [`ReassemblyStop`].
///
/// Built-in reassemblers use it as their ready buffer and append it
/// to the caller's `StreamChunks` on [`Reassembler::drain_into`], so
/// a driver can keep one scratch value and reuse its capacity across
/// packets (no allocation in steady state).
///
/// Walk it in stream order with [`Self::iter`]:
///
/// ```
/// use flowscope::{Chunk, StreamChunks};
///
/// let mut s = StreamChunks::new();
/// s.push_data(b"GET / HTTP/1.1\r\n");
/// s.push_gap(1200);
/// s.push_data(b"Host: example\r\n");
/// let parts: Vec<_> = s.iter().collect();
/// assert_eq!(parts[0], Chunk::Data(b"GET / HTTP/1.1\r\n"));
/// assert_eq!(parts[1], Chunk::Gap(1200));
/// assert_eq!(parts[2], Chunk::Data(b"Host: example\r\n"));
/// ```
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct StreamChunks {
    bytes: Vec<u8>,
    gaps: Vec<GapMark>,
    stop: Option<ReassemblyStop>,
}

/// One element of a [`StreamChunks`] walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Chunk<'a> {
    /// Contiguous in-order bytes.
    Data(&'a [u8]),
    /// This many bytes are missing here.
    Gap(u64),
}

impl StreamChunks {
    /// Empty value (no allocation).
    pub const fn new() -> Self {
        Self {
            bytes: Vec::new(),
            gaps: Vec::new(),
            stop: None,
        }
    }

    /// Clear bytes, gaps and stop; keeps the allocated capacity.
    pub fn clear(&mut self) {
        self.bytes.clear();
        self.gaps.clear();
        self.stop = None;
    }

    /// `true` when there are no bytes, no gaps and no stop.
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty() && self.gaps.is_empty() && self.stop.is_none()
    }

    /// Number of data bytes (gaps excluded).
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Append contiguous bytes.
    pub fn push_data(&mut self, data: &[u8]) {
        self.bytes.extend_from_slice(data);
    }

    /// Append owned bytes, taking the buffer over when no data is
    /// held yet.
    pub(crate) fn push_owned(&mut self, data: Vec<u8>) {
        if self.bytes.is_empty() {
            self.bytes = data;
        } else {
            self.bytes.extend_from_slice(&data);
        }
    }

    /// `true` when no data bytes are held (gaps may be).
    pub(crate) fn is_empty_data(&self) -> bool {
        self.bytes.is_empty()
    }

    /// Record that `len` bytes are missing at the current end.
    /// Adjacent gaps coalesce; `len == 0` is ignored.
    pub fn push_gap(&mut self, len: u64) {
        if len == 0 {
            return;
        }
        let at = self.bytes.len();
        match self.gaps.last_mut() {
            Some(last) if last.at == at => last.len = last.len.saturating_add(len),
            _ => self.gaps.push(GapMark { at, len }),
        }
    }

    /// Mark the stream as stopped. The first reason wins.
    pub fn set_stop(&mut self, stop: ReassemblyStop) {
        self.stop.get_or_insert(stop);
    }

    /// Why the stream stopped, if it did.
    pub fn stop(&self) -> Option<ReassemblyStop> {
        self.stop
    }

    /// All data bytes, concatenated, **without** gap information.
    /// Use [`Self::iter`] when gaps matter (they usually do).
    pub fn data(&self) -> &[u8] {
        &self.bytes
    }

    /// Number of gap markers.
    pub fn gap_count(&self) -> usize {
        self.gaps.len()
    }

    /// Total bytes missing across all gap markers.
    pub fn gap_bytes(&self) -> u64 {
        self.gaps.iter().map(|g| g.len).sum()
    }

    /// Walk data and gaps in stream order.
    pub fn iter(&self) -> Chunks<'_> {
        Chunks {
            chunks: self,
            pos: 0,
            gap_idx: 0,
        }
    }

    /// Move everything from `other` onto the end of `self`, leaving
    /// `other` empty **and without capacity**: a reassembler drained
    /// into a caller's buffer keeps no memory. When `self` is empty
    /// the buffers are moved, not copied.
    pub fn append(&mut self, other: &mut StreamChunks) {
        if self.bytes.is_empty() && self.gaps.is_empty() {
            self.bytes = std::mem::take(&mut other.bytes);
            self.gaps = std::mem::take(&mut other.gaps);
        } else {
            let base = self.bytes.len();
            for g in other.gaps.drain(..) {
                let at = base + g.at;
                match self.gaps.last_mut() {
                    Some(last) if last.at == at => last.len = last.len.saturating_add(g.len),
                    _ => self.gaps.push(GapMark { at, len: g.len }),
                }
            }
            self.bytes.extend_from_slice(&other.bytes);
            other.release();
        }
        if let Some(stop) = other.stop.take() {
            self.set_stop(stop);
        }
    }

    /// Turn the first `n` data bytes into a gap (they were dropped
    /// before the consumer saw them). Gap markers inside the dropped
    /// region merge into it.
    pub(crate) fn drop_front(&mut self, n: usize) {
        let n = n.min(self.bytes.len());
        if n == 0 {
            return;
        }
        self.bytes.drain(..n);
        let mut front = n as u64;
        self.gaps.retain_mut(|g| {
            if g.at <= n {
                front = front.saturating_add(g.len);
                false
            } else {
                g.at -= n;
                true
            }
        });
        self.gaps.insert(0, GapMark { at: 0, len: front });
    }

    /// Take the data bytes out, discarding gap markers and stop.
    pub(crate) fn take_bytes(&mut self) -> Vec<u8> {
        self.gaps.clear();
        self.stop = None;
        std::mem::take(&mut self.bytes)
    }

    /// Release the backing memory.
    pub(crate) fn release(&mut self) {
        self.bytes = Vec::new();
        self.gaps = Vec::new();
    }
}

/// Iterator returned by [`StreamChunks::iter`].
pub struct Chunks<'a> {
    chunks: &'a StreamChunks,
    pos: usize,
    gap_idx: usize,
}

impl<'a> Iterator for Chunks<'a> {
    type Item = Chunk<'a>;

    fn next(&mut self) -> Option<Chunk<'a>> {
        let c = self.chunks;
        if let Some(g) = c.gaps.get(self.gap_idx)
            && g.at == self.pos
        {
            self.gap_idx += 1;
            return Some(Chunk::Gap(g.len));
        }
        if self.pos >= c.bytes.len() {
            return None;
        }
        let end = c
            .gaps
            .get(self.gap_idx)
            .map_or(c.bytes.len(), |g| g.at.min(c.bytes.len()));
        let data = &c.bytes[self.pos..end];
        self.pos = end;
        Some(Chunk::Data(data))
    }
}

/// Receives TCP segments for one direction of one session. Sync —
/// implementors don't await; for blocking consumers (Vec buffer,
/// `std::sync::mpsc`, sync protocol parsers).
///
/// Two consumption styles are supported:
///
/// - **Pull** (the built-in reassemblers): segments accumulate in the
///   reassembler and the driver drains them with
///   [`Self::drain_into`]. This is what the session engines
///   ([`crate::session::SessionDriver`], [`crate::driver::Driver`])
///   use.
/// - **Push**: a custom reassembler forwards bytes from `segment`
///   (to a channel, a file, …) and leaves `drain_into` at its
///   no-op default.
pub trait Reassembler: Send + 'static {
    /// New segment arrived in this direction.
    ///
    /// `payload` borrows from the underlying frame — copy if you
    /// need it after returning. `ts` is the kernel/source timestamp
    /// of the packet carrying the segment.
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp);

    /// Like [`Self::segment`], for a caller that can deliver the
    /// segment's bytes itself, straight from the packet.
    ///
    /// Return [`SegmentOutcome::Passthrough`] when `payload[skip..]`
    /// are exactly the next in-order bytes and nothing else is ready:
    /// the reassembler advances its position **without buffering
    /// them**, and the caller delivers them. Otherwise behave like
    /// `segment` and return [`SegmentOutcome::Buffered`] (the
    /// default). The session engines use this so in-order data is
    /// never copied or held per flow. New in 0.25.0.
    fn segment_into(&mut self, seq: u32, payload: &[u8], ts: Timestamp) -> SegmentOutcome {
        self.segment(seq, payload, ts);
        SegmentOutcome::Buffered
    }

    /// The first byte of this direction has sequence number `seq`
    /// (ISN + 1, from the SYN / SYN-ACK). Called before the first
    /// segment when the handshake was seen; lets a reassembler anchor
    /// the stream instead of trusting the first data segment to
    /// arrive first. Default: no-op. New in 0.25.0.
    fn set_origin(&mut self, _seq: u32) {}

    /// The peer acknowledged every byte of this direction below
    /// `ack`: those bytes were sent, even if the capture never saw
    /// them. Reassemblers use it to give up on holes the receiver
    /// already has (capture loss) instead of waiting for a deadline.
    /// Default: no-op. New in 0.25.0.
    fn peer_ack(&mut self, _ack: u32, _ts: Timestamp) {}

    /// This direction sent a FIN whose sequence number is `end`: the
    /// stream ends there. Default: no-op. New in 0.25.0.
    fn fin_seen(&mut self, _end: u32, _ts: Timestamp) {}

    /// Move the reassembled output produced since the last call
    /// (in-order bytes, gap markers, and a stop reason if the
    /// reassembler stopped) onto the end of `out`. Default: no-op,
    /// for push-style reassemblers that deliver bytes themselves.
    fn drain_into(&mut self, _out: &mut StreamChunks) {}

    /// Give up on every hole still open: skip each one (reporting a
    /// gap) and make all buffered out-of-order data drainable. The
    /// driver calls this once when the flow ends, before the final
    /// drain. Default: no-op.
    fn flush_pending(&mut self) {}

    /// Time moved on without a segment for this side (the driver's
    /// sweep). Reassemblers that wait for holes to fill use it to
    /// expire holes past their deadline. Default: no-op.
    fn advance_time(&mut self, _now: Timestamp) {}

    /// FIN observed in this direction. Default: no-op.
    fn fin(&mut self) {}

    /// RST observed in this direction (or session aborted).
    /// Default: no-op.
    fn rst(&mut self) {}

    /// Segments whose bytes were discarded without ever being
    /// delivered — a segment that arrived after the hole it belonged
    /// to had already been skipped. Default: 0.
    ///
    /// A default-zero return means "this implementation doesn't
    /// track that counter," not "the counter is zero." Distinct from
    /// [`retransmits`](Self::retransmits), which counts re-deliveries
    /// of bytes already accounted for.
    fn dropped_segments(&self) -> u64 {
        0
    }

    /// Number of holes skipped (reported as gaps). Default: 0.
    fn gaps(&self) -> u64 {
        0
    }

    /// Total bytes skipped across all gaps — Zeek's `missed_bytes`.
    /// Default: 0.
    fn gap_bytes(&self) -> u64 {
        0
    }

    /// Number of payload bytes dropped because the per-side buffer
    /// cap was exceeded. Default: 0.
    fn bytes_dropped_oversize(&self) -> u64 {
        0
    }

    /// Why the reassembler stopped accepting bytes, if it did (see
    /// [`ReassemblyStop`]). Default: `None`.
    fn stop_reason(&self) -> Option<ReassemblyStop> {
        None
    }

    /// Peak buffer occupancy ever observed for this side.
    /// Default: `0` (custom reassemblers may not track this).
    fn high_watermark(&self) -> u64 {
        0
    }

    /// Bytes currently buffered, awaiting consumption. Default: `0`.
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
    /// configured; `None` otherwise. Default: `None`.
    fn high_watermark_threshold(&self) -> Option<(u64, u8)> {
        None
    }

    /// Number of TCP segments classified as retransmits —
    /// re-deliveries of bytes the reassembler has already accounted
    /// for. Default `0`.
    fn retransmits(&self) -> u64 {
        0
    }

    /// Hook called when a segment is classified as a retransmit
    /// rather than appended to the buffer. Default no-op. Custom
    /// reassemblers can use this to drive RTT estimators,
    /// retransmit-rate metrics, etc.
    fn on_duplicate(&mut self, _seq: u32, _payload: &[u8], _ts: Timestamp) {}

    /// Running count of retransmits whose bytes differ from what
    /// the reassembler previously saw for the overlapping
    /// sequence range — the classic Ptacek-Newsham TCP overlap
    /// evasion IOC (cf. Zeek's `rexmit_inconsistency`). Default
    /// `0` for implementations that don't retain enough history
    /// to detect the divergence.
    fn rexmit_inconsistencies(&self) -> u64 {
        0
    }

    /// Stop reassembling and release whatever is buffered.
    ///
    /// Called by the driver when the tracker-wide reassembly memcap
    /// reclaims this side. The flow stays tracked and keeps accruing
    /// stats; only its L7 reassembly is abandoned. After a release,
    /// [`Self::stop_reason`] should report [`ReassemblyStop::Memcap`].
    ///
    /// The default is a no-op — an implementation that does not
    /// override it cannot honour the memcap, and the driver's byte
    /// accounting will correctly observe that nothing was freed.
    fn release(&mut self) {}

    /// Current live byte occupancy (ready bytes plus any
    /// out-of-order data held, including bookkeeping overhead). The
    /// tracker-wide memcap sums this across flows. Default `0`.
    fn current_bytes(&self) -> u64 {
        0
    }

    /// Segments dropped because they started too far from the
    /// expected sequence number (see
    /// [`crate::FlowTrackerConfig::reassembly_max_ahead`]) and were
    /// never corroborated — strays from an earlier connection on the
    /// same ports, injected segments. Default `0`. New in 0.25.0.
    fn out_of_window_segments(&self) -> u64 {
        0
    }

    /// Holes skipped early because the peer had acknowledged the
    /// missing bytes (capture loss). Included in [`Self::gaps`].
    /// Default `0`. New in 0.25.0.
    fn ack_confirmed_gaps(&self) -> u64 {
        0
    }

    /// Times the stream was re-anchored after corroborated
    /// out-of-window data (massive loss). Default `0`. New in 0.25.0.
    fn origin_resets(&self) -> u64 {
        0
    }
}

/// What [`Reassembler::segment_into`] did with a segment.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentOutcome {
    /// Handled like [`Reassembler::segment`]: buffered, dropped or
    /// counted; drain to see the result.
    Buffered,
    /// `payload[skip..]` are the next in-order bytes; the caller
    /// delivers them (nothing was buffered).
    Passthrough {
        /// Leading bytes already delivered earlier (retransmitted head).
        skip: usize,
    },
}

/// Build a [`Reassembler`] for a brand-new session, given its key
/// and side. Modeled after gopacket's `StreamFactory`.
pub trait ReassemblerFactory<K>: Send + 'static {
    type Reassembler: Reassembler;
    fn new_reassembler(&mut self, key: &K, side: FlowSide) -> Self::Reassembler;

    /// Adopt the reassembly settings of `config`
    /// ([`FlowTrackerConfig::max_reassembler_buffer`],
    /// [`FlowTrackerConfig::overflow_policy`], …).
    ///
    /// [`crate::FlowDriver`] calls this whenever it is constructed or
    /// reconfigured, which makes the tracker config the single source
    /// of truth for reassembly limits. Reassemblers already created
    /// keep their settings; new ones pick the change up. Default:
    /// no-op (custom factories that take no configuration).
    fn apply_config(&mut self, _config: &FlowTrackerConfig) {}
}

/// Discards every segment without buffering. Used as the reassembler
/// factory by drivers that don't need byte streams.
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

pub use crate::tracker::{DEFAULT_ACK_GRACE, DEFAULT_MAX_AHEAD};

/// Default time a hole may block a stream before it is skipped.
pub const DEFAULT_REORDER_DEADLINE: std::time::Duration = std::time::Duration::from_secs(1);

/// How many recently skipped holes are remembered, to tell a late
/// segment (counted in `dropped_segments`) from a retransmit.
const SKIPPED_HISTORY: usize = 8;

/// A segment held back: out of window (a stray until corroborated) or
/// waiting for the hole in front of it.
#[derive(Debug)]
pub(crate) struct Candidate {
    pub(crate) off: u64,
    pub(crate) data: Vec<u8>,
    pub(crate) ts: Timestamp,
}

/// What a far-away (out-of-window) segment led to.
pub(crate) enum FarOutcome {
    /// Held or dropped as a stray; nothing else to do.
    Held,
    /// Corroborated: re-anchor the stream at the returned candidate
    /// (deliver it after a gap) and process the new segment normally.
    Resync(Box<Candidate>),
}

/// Stream-position bookkeeping shared by the built-in reassemblers:
/// the sequence → stream-offset mapping, the out-of-window candidate,
/// ACK / FIN evidence and recently skipped holes.
#[derive(Debug, Default)]
pub(crate) struct Track {
    anchored: bool,
    next_seq: u32,
    /// Stream offset of the next in-order byte (bytes delivered or
    /// skipped so far).
    pub(crate) next_off: u64,
    /// Highest stream offset the peer's ACKs (or this side's FIN)
    /// prove was sent.
    evidence: u64,
    /// When `evidence` first went past `next_off`.
    evidence_since: Option<Timestamp>,
    /// Stream offset of this side's FIN, once seen.
    fin_off: Option<u64>,
    /// One out-of-window segment, until corroborated or expired.
    oow: Option<Box<Candidate>>,
    skipped: [(u64, u64); SKIPPED_HISTORY],
    skipped_len: usize,
    skipped_head: usize,
    /// Packet time of the last forward progress (or of the moment a
    /// hole appeared).
    pub(crate) last_progress: Timestamp,
    pub(crate) out_of_window: u64,
    pub(crate) origin_resets: u64,
}

impl Track {
    #[cfg(test)]
    pub(crate) fn anchored(&self) -> bool {
        self.anchored
    }

    /// Anchor the stream at `seq` unless already anchored.
    pub(crate) fn anchor(&mut self, seq: u32, ts: Timestamp) {
        if !self.anchored {
            self.anchored = true;
            self.next_seq = seq;
            self.last_progress = ts;
        }
    }

    /// Sequence number of stream offset `off`.
    pub(crate) fn seq_of(&self, off: u64) -> u32 {
        self.next_seq
            .wrapping_add(off.wrapping_sub(self.next_off) as u32)
    }

    /// Signed stream offset of `seq`.
    pub(crate) fn offset_of(&self, seq: u32) -> i64 {
        self.next_off as i64 + i64::from(seq.wrapping_sub(self.next_seq) as i32)
    }

    /// Move the stream position forward to `off`.
    pub(crate) fn advance_to(&mut self, off: u64, ts: Timestamp) {
        if off <= self.next_off {
            return;
        }
        let delta = off - self.next_off;
        self.next_off = off;
        self.next_seq = self.next_seq.wrapping_add(delta as u32);
        self.last_progress = self.last_progress.max(ts);
        if self.evidence <= self.next_off {
            self.evidence_since = None;
        }
    }

    pub(crate) fn record_skip(&mut self, from: u64, to: u64) {
        let i = (self.skipped_head + self.skipped_len) % SKIPPED_HISTORY;
        self.skipped[i] = (from, to);
        if self.skipped_len < SKIPPED_HISTORY {
            self.skipped_len += 1;
        } else {
            self.skipped_head = (self.skipped_head + 1) % SKIPPED_HISTORY;
        }
    }

    /// Whether `[start, end)` overlaps a recently skipped hole.
    pub(crate) fn in_skipped(&self, start: u64, end: u64) -> bool {
        (0..self.skipped_len).any(|i| {
            let (f, t) = self.skipped[(self.skipped_head + i) % SKIPPED_HISTORY];
            start < t && f < end
        })
    }

    /// A segment starting more than `max_ahead` past the stream
    /// position. The first one is held as a candidate stray; a second
    /// one within `max_ahead` of it corroborates it.
    pub(crate) fn far_ahead(
        &mut self,
        off: u64,
        payload: &[u8],
        ts: Timestamp,
        max_ahead: u64,
    ) -> FarOutcome {
        if let Some(c) = &self.oow
            && off.abs_diff(c.off) <= max_ahead
        {
            // The held candidate was counted as a stray; it is used
            // after all.
            self.out_of_window -= 1;
            self.origin_resets += 1;
            return FarOutcome::Resync(self.oow.take().expect("checked"));
        }
        // Counted now; un-counted if a later segment corroborates it.
        self.out_of_window += 1;
        self.oow = Some(Box::new(Candidate {
            off,
            data: payload.to_vec(),
            ts,
        }));
        FarOutcome::Held
    }

    /// Record proof that the stream extends to `seq`. Far-ahead proof
    /// corroborates a held stray (returned for a resync).
    pub(crate) fn evidence(
        &mut self,
        seq: u32,
        ts: Timestamp,
        max_ahead: u64,
    ) -> Option<Box<Candidate>> {
        if !self.anchored {
            return None;
        }
        let off = self.offset_of(seq);
        if off <= self.next_off as i64 {
            return None;
        }
        let mut off = off as u64;
        if let Some(fin) = self.fin_off {
            off = off.min(fin);
        }
        if off - self.next_off > max_ahead {
            if let Some(c) = &self.oow
                && off >= c.off
            {
                self.out_of_window -= 1;
                self.origin_resets += 1;
                return self.oow.take();
            }
            return None;
        }
        if off > self.evidence {
            self.evidence = off;
        }
        if self.evidence > self.next_off {
            self.evidence_since.get_or_insert(ts);
        }
        None
    }

    /// Record this side's FIN at `seq`.
    pub(crate) fn fin(
        &mut self,
        seq: u32,
        ts: Timestamp,
        max_ahead: u64,
    ) -> Option<Box<Candidate>> {
        if !self.anchored {
            return None;
        }
        let off = self.offset_of(seq);
        if off < self.next_off as i64 {
            return None;
        }
        self.fin_off = Some(off as u64);
        if self.evidence > off as u64 {
            self.evidence = off as u64;
        }
        self.evidence(seq, ts, max_ahead)
    }

    /// The acknowledged-but-unseen frontier, once `grace` has passed
    /// since it appeared.
    pub(crate) fn evidence_due(&self, now: Timestamp, grace: std::time::Duration) -> Option<u64> {
        let since = self.evidence_since?;
        (self.evidence > self.next_off && now.saturating_sub(since) >= grace)
            .then_some(self.evidence)
    }

    /// The acknowledged-but-unseen frontier, ignoring the grace
    /// period (end of stream).
    pub(crate) fn evidence_frontier(&self) -> Option<u64> {
        (self.evidence > self.next_off).then_some(self.evidence)
    }

    /// Forget a lone out-of-window candidate older than `max_age`.
    pub(crate) fn expire_stray(&mut self, now: Timestamp, max_age: std::time::Duration) {
        if self
            .oow
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.ts) > max_age)
        {
            self.oow = None;
        }
    }

    pub(crate) fn drop_stray(&mut self) {
        self.oow = None;
    }

    pub(crate) fn heap_bytes(&self) -> usize {
        self.oow
            .as_ref()
            .map_or(0, |c| std::mem::size_of::<Candidate>() + c.data.capacity())
    }
}

/// Settings shared by the built-in reassemblers.
#[derive(Debug, Clone, Copy)]
pub(crate) struct StreamRules {
    pub(crate) max_ahead: u64,
    pub(crate) ack_grace: std::time::Duration,
    pub(crate) deadline: std::time::Duration,
}

impl Default for StreamRules {
    fn default() -> Self {
        Self {
            max_ahead: DEFAULT_MAX_AHEAD,
            ack_grace: DEFAULT_ACK_GRACE,
            deadline: DEFAULT_REORDER_DEADLINE,
        }
    }
}

/// Built-in in-order reassembler: accumulates in-order bytes per
/// direction; drain with [`Reassembler::drain_into`] (bytes + gaps)
/// or [`take`](Self::take) (bytes only).
///
/// It holds at most **one** out-of-order segment. A segment that
/// arrives ahead of the expected sequence number waits for the hole
/// in front of it; the hole is skipped (and reported as a **gap**)
/// when a second out-of-order segment arrives, when the peer has
/// acknowledged the missing bytes for
/// [`with_ack_grace`](Self::with_ack_grace), after
/// [`with_reorder_deadline`](Self::with_reorder_deadline), or when the
/// flow ends. A segment that later turns up inside a skipped hole is
/// discarded and counted in [`dropped_segments`](Self::dropped_segments).
/// This never wedges. Use [`crate::SegmentBufferReassembler`] when
/// reordering is common (multi-queue capture, tap merges).
///
/// A segment starting more than
/// [`with_max_ahead`](Self::with_max_ahead) past the stream position
/// is not believed on its own (a stray from an earlier connection, an
/// injected segment): it is dropped and counted in
/// [`Reassembler::out_of_window_segments`] unless a second such
/// segment or an ACK corroborates it, in which case the stream skips
/// to it (massive capture loss, [`Reassembler::origin_resets`]).
///
/// Optionally bounded via [`with_max_buffer`](Self::with_max_buffer).
/// When the cap is reached the [`OverflowPolicy`] decides whether to
/// drop the oldest undelivered bytes (reported as a gap) or stop
/// reassembling this side (see [`ReassemblyStop::Overflow`]).
#[derive(Debug, Default)]
pub struct BufferedReassembler {
    ready: StreamChunks,
    track: Track,
    rules: StreamRules,
    /// The one segment waiting for the hole in front of it.
    reorder: Option<Box<Candidate>>,
    dropped_segments: u64,
    gaps: u64,
    gap_bytes: u64,
    ack_confirmed_gaps: u64,
    bytes_dropped_oversize: u64,
    max_buffer: Option<usize>,
    overflow_policy: OverflowPolicy,
    stop: Option<ReassemblyStop>,
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

    /// How far ahead of the stream position a segment may start and
    /// still be believed without corroboration. Default 1 MiB.
    pub fn with_max_ahead(mut self, bytes: u64) -> Self {
        self.rules.max_ahead = bytes;
        self
    }

    /// How long a hole the peer already acknowledged is still waited
    /// for. Default 10 ms.
    pub fn with_ack_grace(mut self, grace: std::time::Duration) -> Self {
        self.rules.ack_grace = grace;
        self
    }

    /// How long a hole may block the stream before it is skipped.
    /// Default 1 s.
    pub fn with_reorder_deadline(mut self, deadline: std::time::Duration) -> Self {
        self.rules.deadline = deadline;
        self
    }

    /// Drain accumulated in-order bytes, leaving the buffer empty.
    /// **Gap markers are discarded** — use
    /// [`Reassembler::drain_into`] to observe them.
    ///
    /// The stream position is preserved so subsequent in-order
    /// segments keep accumulating. Also re-arms the high-watermark
    /// threshold.
    pub fn take(&mut self) -> Vec<u8> {
        self.above_threshold = false;
        self.ready.take_bytes()
    }

    /// Segments discarded because they arrived after their hole had
    /// already been skipped.
    pub fn dropped_segments(&self) -> u64 {
        self.dropped_segments
    }

    /// Number of holes skipped.
    pub fn gaps(&self) -> u64 {
        self.gaps
    }

    /// Bytes skipped across all holes.
    pub fn gap_bytes(&self) -> u64 {
        self.gap_bytes
    }

    /// Number of payload bytes dropped because the per-side buffer
    /// cap was exceeded. Zero when no cap is set or when the cap has
    /// not yet been hit.
    pub fn bytes_dropped_oversize(&self) -> u64 {
        self.bytes_dropped_oversize
    }

    /// Bytes currently buffered (not yet drained).
    pub fn buffered_len(&self) -> usize {
        self.ready.len()
    }

    /// True once this side stopped (overflow under
    /// [`OverflowPolicy::DropFlow`], or a memcap release).
    pub fn is_stopped(&self) -> bool {
        self.stop.is_some()
    }

    /// Peak buffer occupancy ever observed for this reassembler.
    /// Survives [`take`](Self::take) — useful for tuning
    /// [`crate::FlowTrackerConfig::max_reassembler_buffer`].
    pub fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Number of TCP segments classified as retransmits on this
    /// side (bytes already delivered, fully or partly).
    pub fn retransmits(&self) -> u64 {
        self.retransmits
    }

    /// Running count of below→above transitions of the configured
    /// high-watermark threshold. Zero when no threshold is set.
    pub fn high_watermark_crossings(&self) -> u64 {
        self.high_watermark_crossings
    }

    fn append_with_cap(&mut self, payload: &[u8]) {
        if self.stop.is_some() || payload.is_empty() {
            return;
        }
        let Some(cap) = self.max_buffer else {
            self.ready.push_data(payload);
            self.update_watermark();
            return;
        };
        let projected = self.ready.len() + payload.len();
        if projected <= cap {
            self.ready.push_data(payload);
            self.update_watermark();
            return;
        }
        match self.overflow_policy {
            OverflowPolicy::DropFlow => {
                // Bytes already buffered were received in order and
                // stay deliverable; this payload and everything after
                // it is abandoned.
                self.bytes_dropped_oversize += payload.len() as u64;
                self.stop = Some(ReassemblyStop::Overflow);
                self.reorder = None;
                self.track.drop_stray();
            }
            OverflowPolicy::SlidingWindow => {
                let to_drop = projected - cap;
                let buffered = self.ready.len();
                if to_drop >= buffered {
                    self.bytes_dropped_oversize += buffered as u64;
                    self.ready.drop_front(buffered);
                    let extra = payload.len().saturating_sub(cap);
                    self.bytes_dropped_oversize += extra as u64;
                    self.ready.push_gap(extra as u64);
                    self.ready.push_data(&payload[extra..]);
                } else {
                    self.bytes_dropped_oversize += to_drop as u64;
                    self.ready.drop_front(to_drop);
                    self.ready.push_data(payload);
                }
                self.update_watermark();
            }
        }
    }

    /// Bytes let through count as momentarily buffered: the peak and
    /// threshold crossings match what buffering and draining them
    /// right away would have recorded.
    fn note_passthrough(&mut self, len: usize) {
        self.high_watermark = self.high_watermark.max(len as u64);
        if let (Some(pct), Some(cap)) = (self.high_watermark_threshold_pct, self.max_buffer)
            && len as u64 >= (cap as u64).saturating_mul(pct as u64) / 100
        {
            self.high_watermark_crossings = self.high_watermark_crossings.saturating_add(1);
        }
        self.above_threshold = false;
    }

    #[inline]
    fn update_watermark(&mut self) {
        let len = self.ready.len() as u64;
        if len > self.high_watermark {
            self.high_watermark = len;
        }
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

    /// Skip the hole in front of `to` (report a gap).
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

    /// Deliver in-order bytes that start at or before the stream
    /// position (the part before it is a retransmitted head).
    fn deliver_at(&mut self, off: u64, data: &[u8], ts: Timestamp) {
        let next = self.track.next_off;
        let end = off + data.len() as u64;
        if end <= next {
            return;
        }
        let skip = (next.saturating_sub(off)) as usize;
        self.track.advance_to(end, ts);
        self.append_with_cap(&data[skip..]);
    }

    /// Give up on the hole in front of the reorder candidate and
    /// deliver it.
    fn release_reorder(&mut self, ts: Timestamp) {
        if let Some(c) = self.reorder.take() {
            self.skip_to(c.off, ts);
            self.deliver_at(c.off, &c.data, ts);
        }
    }

    /// Deliver the reorder candidate if the stream reached it.
    fn try_reorder(&mut self, ts: Timestamp) {
        if self
            .reorder
            .as_ref()
            .is_some_and(|c| c.off <= self.track.next_off)
        {
            let c = self.reorder.take().expect("checked");
            self.deliver_at(c.off, &c.data, ts);
        }
    }

    fn resync(&mut self, c: &Candidate, ts: Timestamp) {
        self.release_reorder(ts);
        self.skip_to(c.off, ts);
        self.deliver_at(c.off, &c.data, ts);
    }

    /// Deadlines: an acknowledged hole after the grace period, any
    /// hole after the reorder deadline, a lone stray after four.
    fn check_timers(&mut self, now: Timestamp) {
        if self.stop.is_some() {
            return;
        }
        if let Some(frontier) = self.track.evidence_due(now, self.rules.ack_grace) {
            match self.reorder.as_ref().map(|c| c.off) {
                Some(off) if off <= frontier => {
                    self.ack_confirmed_gaps += 1;
                    self.release_reorder(now);
                }
                Some(_) => {}
                None => {
                    self.ack_confirmed_gaps += 1;
                    self.skip_to(frontier, now);
                }
            }
        }
        if self
            .reorder
            .as_ref()
            .is_some_and(|c| now.saturating_sub(c.ts) > self.rules.deadline)
        {
            self.release_reorder(now);
        }
        self.track.expire_stray(now, self.rules.deadline * 4);
    }

    fn feed(&mut self, seq: u32, payload: &[u8], ts: Timestamp, pass: bool) -> SegmentOutcome {
        if payload.is_empty() || self.stop.is_some() {
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
            self.retransmits += 1;
            self.on_duplicate(seq, payload, ts);
            (next - start) as usize
        } else {
            0
        };
        if start > next {
            // Ahead of the stream: wait for the hole, unless another
            // segment is already waiting — then give up on that hole.
            if self.reorder.is_some() {
                self.release_reorder(ts);
                return self.feed(seq, payload, ts, false);
            }
            self.reorder = Some(Box::new(Candidate {
                off: start as u64,
                data: payload.to_vec(),
                ts,
            }));
            self.track.last_progress = ts;
            self.check_timers(ts);
            return SegmentOutcome::Buffered;
        }
        // In order.
        let len = payload.len() - skip;
        if pass
            && self.ready.is_empty()
            && self.reorder.is_none()
            && self.max_buffer.is_none_or(|cap| len <= cap)
        {
            self.track.advance_to(end as u64, ts);
            self.note_passthrough(len);
            return SegmentOutcome::Passthrough { skip };
        }
        self.track.advance_to(end as u64, ts);
        self.append_with_cap(&payload[skip..]);
        self.try_reorder(ts);
        self.check_timers(ts);
        SegmentOutcome::Buffered
    }
}

impl Reassembler for BufferedReassembler {
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
        // An ACK covers this side's FIN too (one sequence number): be
        // conservative by one byte until the FIN position is known.
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
        if self.stop.is_some() {
            return;
        }
        let ts = self.track.last_progress;
        self.release_reorder(ts);
        // Bytes acknowledged (or before this side's FIN) but never
        // seen: a trailing gap.
        if let Some(frontier) = self.track.evidence_frontier() {
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

    fn stop_reason(&self) -> Option<ReassemblyStop> {
        self.stop
    }

    fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    fn bytes_in_flight(&self) -> u64 {
        self.ready.len() as u64
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

    /// Drop the buffer and stop accepting bytes. See
    /// [`Reassembler::release`].
    fn release(&mut self) {
        self.ready.clear();
        self.ready.release();
        self.reorder = None;
        self.track.drop_stray();
        self.stop.get_or_insert(ReassemblyStop::Memcap);
    }

    fn current_bytes(&self) -> u64 {
        let held = self
            .reorder
            .as_ref()
            .map_or(0, |c| std::mem::size_of::<Candidate>() + c.data.capacity());
        (self.ready.len() + held + self.track.heap_bytes()) as u64
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

/// Default factory that builds a fresh [`BufferedReassembler`] per
/// (flow, side).
///
/// Settings come from two places, explicit ones first:
///
/// 1. the `with_*` builders — always win;
/// 2. the tracker config, applied by [`crate::FlowDriver`] through
///    [`ReassemblerFactory::apply_config`] (or by
///    [`from_config`](Self::from_config)) — fills every setting not
///    set explicitly.
#[derive(Debug, Default, Clone)]
pub struct BufferedReassemblerFactory {
    max_buffer: Option<usize>,
    overflow_policy: OverflowPolicy,
    high_watermark_threshold_pct: Option<u8>,
    pinned: Pinned,
}

/// Which settings were set explicitly (and so survive
/// [`ReassemblerFactory::apply_config`]).
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Pinned {
    pub(crate) max_buffer: bool,
    pub(crate) overflow_policy: bool,
    pub(crate) high_watermark: bool,
}

impl BufferedReassemblerFactory {
    /// Factory using the reassembly settings of `config`.
    pub fn from_config(config: &FlowTrackerConfig) -> Self {
        let mut f = Self::default();
        <Self as ReassemblerFactory<()>>::apply_config(&mut f, config);
        f
    }

    /// Apply the same cap to every reassembler this factory creates.
    /// Overrides [`FlowTrackerConfig::max_reassembler_buffer`].
    pub fn with_max_buffer(mut self, max_bytes: usize) -> Self {
        self.max_buffer = Some(max_bytes);
        self.pinned.max_buffer = true;
        self
    }

    /// No per-side cap, whatever the tracker config says.
    pub fn unbounded(mut self) -> Self {
        self.max_buffer = None;
        self.pinned.max_buffer = true;
        self
    }

    /// Apply the same overflow policy to every reassembler this
    /// factory creates. Overrides [`FlowTrackerConfig::overflow_policy`].
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self.pinned.overflow_policy = true;
        self
    }

    /// Apply the same high-watermark threshold (% of `max_buffer`)
    /// to every reassembler this factory creates. See
    /// [`BufferedReassembler::with_high_watermark_threshold`].
    pub fn with_high_watermark_threshold(mut self, percent: u8) -> Self {
        self.high_watermark_threshold_pct = Some(percent.clamp(1, 100));
        self.pinned.high_watermark = true;
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

    fn apply_config(&mut self, config: &FlowTrackerConfig) {
        if !self.pinned.max_buffer {
            self.max_buffer = config.max_reassembler_buffer;
        }
        if !self.pinned.overflow_policy {
            self.overflow_policy = config.overflow_policy;
        }
        if !self.pinned.high_watermark {
            self.high_watermark_threshold_pct = config.reassembler_high_watermark_pct;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t() -> Timestamp {
        Timestamp::default()
    }

    fn drain(r: &mut impl Reassembler) -> StreamChunks {
        let mut out = StreamChunks::new();
        r.drain_into(&mut out);
        out
    }

    // ── StreamChunks ────────────────────────────────────────────

    #[test]
    fn chunks_iterate_in_stream_order() {
        let mut s = StreamChunks::new();
        s.push_gap(3);
        s.push_data(b"ab");
        s.push_gap(2);
        s.push_gap(5); // coalesces
        s.push_data(b"c");
        let v: Vec<_> = s.iter().collect();
        assert_eq!(
            v,
            vec![
                Chunk::Gap(3),
                Chunk::Data(b"ab"),
                Chunk::Gap(7),
                Chunk::Data(b"c")
            ]
        );
        assert_eq!(s.gap_bytes(), 10);
        assert_eq!(s.data(), b"abc");
    }

    #[test]
    fn chunks_trailing_gap_is_yielded() {
        let mut s = StreamChunks::new();
        s.push_data(b"ab");
        s.push_gap(4);
        let v: Vec<_> = s.iter().collect();
        assert_eq!(v, vec![Chunk::Data(b"ab"), Chunk::Gap(4)]);
    }

    #[test]
    fn chunks_append_rebases_gaps_and_keeps_stop() {
        let mut a = StreamChunks::new();
        a.push_data(b"xy");
        let mut b = StreamChunks::new();
        b.push_gap(1);
        b.push_data(b"z");
        b.set_stop(ReassemblyStop::Overflow);
        a.append(&mut b);
        assert!(b.is_empty());
        let v: Vec<_> = a.iter().collect();
        assert_eq!(
            v,
            vec![Chunk::Data(b"xy"), Chunk::Gap(1), Chunk::Data(b"z")]
        );
        assert_eq!(a.stop(), Some(ReassemblyStop::Overflow));
    }

    #[test]
    fn drop_front_turns_bytes_into_a_leading_gap() {
        let mut s = StreamChunks::new();
        s.push_data(b"abc");
        s.push_gap(10);
        s.push_data(b"def");
        s.drop_front(4); // "abc" + gap + "d"
        let v: Vec<_> = s.iter().collect();
        assert_eq!(v, vec![Chunk::Gap(14), Chunk::Data(b"ef")]);
    }

    // ── BufferedReassembler ─────────────────────────────────────

    #[test]
    fn in_order_concatenates() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"abc", t());
        r.segment(103, b"def", t());
        r.segment(106, b"gh", t());
        assert_eq!(r.take(), b"abcdefgh");
        assert_eq!(r.gaps(), 0);
    }

    /// The pre-0.25 behaviour dropped every segment after the first
    /// hole, forever. A hole is now skipped and reported.
    #[test]
    fn hole_is_skipped_and_reported_not_wedged() {
        let mut r = BufferedReassembler::new();
        r.segment(100, b"hello", t()); // exp = 105
        r.segment(110, b"world", t()); // 105..110 missing
        r.segment(115, b"!!", t()); // in order again
        let out = drain(&mut r);
        let v: Vec<_> = out.iter().collect();
        assert_eq!(
            v,
            vec![
                Chunk::Data(b"hello"),
                Chunk::Gap(5),
                Chunk::Data(b"world!!")
            ]
        );
        assert_eq!(r.gaps(), 1);
        assert_eq!(r.gap_bytes(), 5);
    }

    /// One reordered segment waits for its hole instead of costing a
    /// gap (issue #182).
    #[test]
    fn a_single_reordering_is_repaired() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", t());
        r.segment(10, b"world", t()); // waits for 5..10
        r.segment(5, b"MIDDL", t());
        assert_eq!(r.gaps(), 0);
        assert_eq!(r.take(), b"helloMIDDLworld");
    }

    #[test]
    fn late_segment_inside_a_skipped_hole_is_dropped_not_a_retransmit() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", t());
        r.segment(10, b"world", t()); // waits for 5..10
        r.segment(20, b"again", t()); // second OOO: skip 5..10
        r.segment(5, b"MIDDL", t()); // arrives late
        assert_eq!(r.dropped_segments(), 1);
        assert_eq!(r.retransmits(), 0);
        assert_eq!(r.take(), b"helloworld");
    }

    #[test]
    fn stray_beyond_the_window_is_dropped() {
        let mut r = BufferedReassembler::new().with_max_ahead(1000);
        r.segment(0, b"abc", t());
        r.segment(5_000_000, b"STRAY", t());
        r.segment(3, b"def", t());
        assert_eq!(r.take(), b"abcdef");
        assert_eq!(r.out_of_window_segments(), 1);
        assert_eq!(r.gaps(), 0);
    }

    #[test]
    fn syn_origin_repairs_reordered_first_segments() {
        let mut r = BufferedReassembler::new();
        r.set_origin(100);
        r.segment(105, b"world", t());
        r.segment(100, b"hello", t());
        assert_eq!(r.take(), b"helloworld");
        assert_eq!(r.retransmits(), 0);
    }

    #[test]
    fn acked_hole_is_skipped_after_the_grace() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc", Timestamp::new(1, 0));
        r.segment(6, b"ghi", Timestamp::new(1, 0));
        r.peer_ack(9, Timestamp::new(1, 0));
        assert_eq!(r.gaps(), 0);
        r.advance_time(Timestamp::new(2, 0));
        assert_eq!(r.ack_confirmed_gaps(), 1);
        assert_eq!(r.take(), b"abcghi");
    }

    #[test]
    fn take_resets_buffer_only() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc", t());
        assert_eq!(r.take(), b"abc");
        assert_eq!(r.buffered_len(), 0);
        r.segment(3, b"def", t());
        assert_eq!(r.take(), b"def");
    }

    #[test]
    fn empty_payload_ignored() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"", t());
        assert!(!r.track.anchored());
    }

    #[test]
    fn factory_creates_fresh_reassembler() {
        let mut f = BufferedReassemblerFactory::default();
        let mut r1: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Initiator);
        let mut r2: BufferedReassembler = f.new_reassembler(&42u32, FlowSide::Responder);
        r1.segment(0, b"x", t());
        r2.segment(0, b"y", t());
        assert_eq!(r1.take(), b"x");
        assert_eq!(r2.take(), b"y");
    }

    #[test]
    fn cap_unbounded_by_default() {
        let mut r = BufferedReassembler::new();
        r.segment(0, &[0u8; 10_000], t());
        assert_eq!(r.buffered_len(), 10_000);
        assert_eq!(r.bytes_dropped_oversize(), 0);
        assert!(!r.is_stopped());
    }

    #[test]
    fn sliding_window_drop_is_reported_as_a_leading_gap() {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        r.segment(0, &[b'a'; 80], t());
        r.segment(80, &[b'b'; 80], t()); // 60 oldest 'a' dropped
        assert_eq!(r.buffered_len(), 100);
        assert_eq!(r.bytes_dropped_oversize(), 60);
        let out = drain(&mut r);
        let v: Vec<_> = out.iter().collect();
        assert_eq!(v[0], Chunk::Gap(60));
        assert_eq!(out.data()[..20], [b'a'; 20]);
        assert_eq!(out.data()[20..], [b'b'; 80]);
        // Oversize drops are not capture gaps.
        assert_eq!(r.gaps(), 0);
    }

    #[test]
    fn cap_payload_bigger_than_cap_keeps_tail() {
        let mut r = BufferedReassembler::new().with_max_buffer(50);
        let payload: Vec<u8> = (0u8..100).collect();
        r.segment(0, &payload, t());
        assert_eq!(r.buffered_len(), 50);
        assert_eq!(r.bytes_dropped_oversize(), 50);
        let out = drain(&mut r);
        assert_eq!(out.gap_bytes(), 50);
        assert_eq!(out.data(), (50u8..100).collect::<Vec<u8>>());
    }

    #[test]
    fn drop_flow_stops_but_keeps_what_was_already_in_order() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 80], t());
        assert!(!r.is_stopped());
        r.segment(80, &[b'b'; 80], t()); // overflow → stop
        assert!(r.is_stopped());
        assert_eq!(r.stop_reason(), Some(ReassemblyStop::Overflow));
        assert_eq!(r.bytes_dropped_oversize(), 80);
        r.segment(160, &[b'c'; 10], t()); // no-op
        let out = drain(&mut r);
        assert_eq!(out.data(), &[b'a'; 80][..]);
        assert_eq!(out.stop(), Some(ReassemblyStop::Overflow));
        // The stop is sticky across drains.
        assert_eq!(drain(&mut r).stop(), Some(ReassemblyStop::Overflow));
    }

    #[test]
    fn cap_drop_flow_does_not_poison_under_cap() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        r.segment(0, &[b'a'; 50], t());
        r.segment(50, &[b'b'; 50], t());
        assert!(!r.is_stopped());
        assert_eq!(r.buffered_len(), 100);
    }

    #[test]
    fn factory_propagates_cap_and_policy() {
        let mut f = BufferedReassemblerFactory::default()
            .with_max_buffer(64)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 100], t());
        assert!(r.is_stopped());
    }

    #[test]
    fn factory_from_config_uses_the_tracker_config() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(10),
            overflow_policy: OverflowPolicy::DropFlow,
            reassembler_high_watermark_pct: Some(50),
            ..Default::default()
        };
        let mut f = BufferedReassemblerFactory::from_config(&cfg);
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        assert_eq!(r.high_watermark_threshold(), Some((10, 50)));
        r.segment(0, &[0u8; 11], t());
        assert!(r.is_stopped());
    }

    #[test]
    fn explicit_factory_settings_win_over_the_config() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(1_000),
            overflow_policy: OverflowPolicy::DropFlow,
            ..Default::default()
        };
        let mut f = BufferedReassemblerFactory::default().with_max_buffer(10);
        <BufferedReassemblerFactory as ReassemblerFactory<u32>>::apply_config(&mut f, &cfg);
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 11], t());
        // Cap pinned at 10, policy filled in from the config.
        assert!(r.is_stopped());

        let mut f = BufferedReassemblerFactory::default().unbounded();
        <BufferedReassemblerFactory as ReassemblerFactory<u32>>::apply_config(&mut f, &cfg);
        let mut r: BufferedReassembler = f.new_reassembler(&0u32, FlowSide::Initiator);
        r.segment(0, &[0u8; 5_000], t());
        assert_eq!(r.buffered_len(), 5_000);
    }

    #[test]
    fn release_stops_with_memcap_reason() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"abc", t());
        r.release();
        assert_eq!(r.current_bytes(), 0);
        assert_eq!(r.stop_reason(), Some(ReassemblyStop::Memcap));
        r.segment(3, b"def", t());
        assert_eq!(r.current_bytes(), 0);
    }

    #[test]
    fn high_watermark_tracks_peak_buffer_unbounded() {
        let mut r = BufferedReassembler::new();
        r.segment(0, &[b'a'; 50], t());
        assert_eq!(r.high_watermark(), 50);
        let _ = r.take();
        assert_eq!(r.high_watermark(), 50);
        r.segment(50, &[b'b'; 20], t());
        assert_eq!(r.high_watermark(), 50);
        let _ = r.take();
        r.segment(70, &[b'c'; 100], t());
        assert_eq!(r.high_watermark(), 100);
    }

    #[test]
    fn high_watermark_threshold_crosses_once() {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_high_watermark_threshold(80);
        r.segment(0, &[b'a'; 50], t());
        assert_eq!(r.high_watermark_crossings(), 0);
        r.segment(50, &[b'b'; 40], t());
        assert_eq!(r.high_watermark_crossings(), 1);
        r.segment(90, &[b'c'; 5], t());
        assert_eq!(r.high_watermark_crossings(), 1);
        let _ = drain(&mut r);
        r.segment(95, &[b'd'; 85], t());
        assert_eq!(r.high_watermark_crossings(), 2);
    }

    #[test]
    fn high_watermark_threshold_info_visible_via_trait() {
        let r = BufferedReassembler::new()
            .with_max_buffer(200)
            .with_high_watermark_threshold(75);
        assert_eq!(r.high_watermark_threshold(), Some((200, 75)));
        let r2 = BufferedReassembler::new().with_high_watermark_threshold(75);
        assert_eq!(r2.high_watermark_threshold(), None);
        let r3 = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_high_watermark_threshold(0);
        assert_eq!(r3.high_watermark_threshold(), Some((100, 1)));
    }

    #[test]
    fn exact_retransmit_classified_as_retransmit() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", Timestamp::new(1, 0));
        r.segment(0, b"hello", Timestamp::new(2, 0));
        assert_eq!(r.retransmits(), 1);
        assert_eq!(r.dropped_segments(), 0);
        assert_eq!(r.take(), b"hello");
    }

    /// A segment straddling the expected sequence number used to be
    /// dropped whole, losing its new tail.
    #[test]
    fn partial_overlap_delivers_the_new_tail() {
        let mut r = BufferedReassembler::new();
        r.segment(0, b"hello", t()); // exp = 5
        r.segment(3, b"lo world", t()); // 3..11, new part 5..11
        assert_eq!(r.retransmits(), 1);
        assert_eq!(r.take(), b"hello world");
    }

    #[test]
    fn sequence_wraparound_is_seamless() {
        let mut r = BufferedReassembler::new();
        r.segment(u32::MAX - 2, b"abc", t());
        r.segment(0, b"def", t());
        assert_eq!(r.gaps(), 0);
        assert_eq!(r.take(), b"abcdef");
    }

    #[test]
    fn on_duplicate_receives_ts() {
        use std::sync::{Arc, Mutex};
        #[derive(Default)]
        struct Spy {
            seen: Arc<Mutex<Vec<Timestamp>>>,
        }
        impl Reassembler for Spy {
            fn segment(&mut self, _seq: u32, _payload: &[u8], _ts: Timestamp) {}
            fn on_duplicate(&mut self, _seq: u32, _payload: &[u8], ts: Timestamp) {
                self.seen.lock().unwrap().push(ts);
            }
        }
        let seen = Arc::new(Mutex::new(Vec::new()));
        let mut spy = Spy { seen: seen.clone() };
        spy.on_duplicate(0, b"hello", Timestamp::new(7, 42));
        assert_eq!(seen.lock().unwrap().as_slice(), &[Timestamp::new(7, 42)]);
    }

    #[test]
    fn default_stop_reason_is_none() {
        struct P;
        impl Reassembler for P {
            fn segment(&mut self, _: u32, _: &[u8], _: Timestamp) {}
        }
        assert_eq!(P.stop_reason(), None);
    }
}
