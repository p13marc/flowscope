//! Heuristic-routed slots for [`super::typed::Driver`].
//!
//! Mirror of [`super::heuristic`] adapted to the typed
//! `SlotHandle` pattern. Each slot holds a per-flow detection
//! state machine; when the signature matches it pins to the
//! parser and pushes typed messages into the slot's
//! `Arc<SegQueue<SlotMessage<M, K>>>`.

use std::{collections::HashMap, hash::Hash, marker::PhantomData, sync::Arc};

use arrayvec::ArrayVec;
use crossbeam_queue::SegQueue;

use super::{
    slot::{SlotHandle, SlotMessage},
    typed::Event,
    typed_slot::{ErasedSlot, route_session_event_pub},
};
use crate::{
    PacketView, Timestamp,
    datagram_driver::FlowDatagramDriver,
    detect::signatures::{SignatureFn, SignatureMatch},
    extract::parse::{self, ParsedL4},
    extractor::{Extracted, FlowExtractor, Orientation},
    parser_kind::ParserKind,
    session::{DatagramParser, SessionEvent, SessionParser},
    session_driver::FlowSessionDriver,
    tracker::FlowTrackerConfig,
};

/// Buffer cap per side during the probing phase. Every shipped
/// signature decides within ≤ 64 B.
pub const PROBE_BUFFER_CAP: usize = 64;

/// Default probing-budget if the user doesn't override.
pub const DEFAULT_PROBE_PACKETS: u8 = 4;

/// Cap on the bytes held for replay while probing one flow.
///
/// Probe packets are kept so the parser can be given the *whole*
/// stream once a signature pins, not just the packet that happened
/// to match. That means holding frames, so it is bounded: a flow
/// whose probe frames exceed this replays nothing and the parser
/// starts from the pinning packet (the pre-0.23 behaviour).
const PROBE_REPLAY_BYTE_CAP: usize = 16 * 1024;

/// Cap on per-flow detection entries held by one slot.
///
/// Most entries are released when their flow ends, but a flow the
/// signature ruled out is never registered with the inner driver, so
/// it never produces an `Ended` event to release it. Without a cap a
/// scan against a heuristic slot would leak one entry per source.
/// When the cap is reached, decided entries are dropped first; if
/// that is not enough the map is cleared and the flows still probing
/// simply start over, which costs a few packets of detection and no
/// correctness.
const MAX_PROBE_STATES: usize = 65_536;

/// Per-flow detection state inside a heuristic slot.
pub(super) enum FlowDetection {
    Probing {
        seen: u8,
        init_buf: ArrayVec<u8, PROBE_BUFFER_CAP>,
        resp_buf: ArrayVec<u8, PROBE_BUFFER_CAP>,
        /// Frames seen while probing, in arrival order, so they can
        /// be replayed into the parser when the signature pins.
        replay: Vec<Vec<u8>>,
        /// Total bytes in `replay`; once it passes
        /// [`PROBE_REPLAY_BYTE_CAP`] the queue is dropped and replay
        /// is abandoned for this flow.
        replay_bytes: usize,
    },
    Pinned,
    GaveUp,
}

impl Default for FlowDetection {
    fn default() -> Self {
        Self::Probing {
            seen: 0,
            init_buf: ArrayVec::new(),
            resp_buf: ArrayVec::new(),
            replay: Vec::new(),
            replay_bytes: 0,
        }
    }
}

/// Heuristic-routed session slot.
pub(super) struct TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor,
    P: SessionParser + Sync,
    P::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    extractor: E,
    driver: FlowSessionDriver<E, P, ()>,
    signature: SignatureFn,
    max_probe_packets: u8,
    parser_kind: ParserKind,
    states: HashMap<E::Key, FlowDetection>,
    msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, P::Message>>,
    _marker: PhantomData<P>,
}

impl<E, P> TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor + Clone,
    P: SessionParser + Clone + Sync,
    P::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    pub(super) fn new(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        signature: SignatureFn,
        max_probe_packets: u8,
        monotonic_timestamps: bool,
    ) -> (Self, SlotHandle<P::Message, E::Key>)
    where
        E::Key: Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        let msg_buf = Arc::new(SegQueue::new());
        let handle = SlotHandle {
            inner: Arc::clone(&msg_buf),
            parser_kind,
        };
        let slot = Self::with_queue(
            extractor,
            parser,
            config,
            signature,
            max_probe_packets,
            monotonic_timestamps,
            msg_buf,
        );
        (slot, handle)
    }

    pub(super) fn with_queue(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        signature: SignatureFn,
        max_probe_packets: u8,
        monotonic_timestamps: bool,
        msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>>,
    ) -> Self
    where
        E::Key: Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowSessionDriver::with_config(extractor.clone(), parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            extractor,
            signature,
            max_probe_packets,
            parser_kind,
            states: HashMap::new(),
            msg_buf,
            session_scratch: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<E, P> TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Send + Sync + 'static,
    P: SessionParser + Sync,
    P::Message: Send + Sync + 'static,
{
    /// Drop per-flow probe state for flows that just ended, so the
    /// map does not grow for the lifetime of the slot.
    fn forget_ended(&mut self, events: &[Event<E::Key>]) {
        for ev in events {
            if let Event::Ended { key, .. } = ev {
                self.states.remove(key);
            }
        }
    }

    /// Keep the detection map bounded. See [`MAX_PROBE_STATES`].
    fn bound_states(&mut self) {
        if self.states.len() < MAX_PROBE_STATES {
            return;
        }
        // Flows already decided against are pure residue.
        self.states
            .retain(|_, v| !matches!(v, FlowDetection::GaveUp));
        if self.states.len() >= MAX_PROBE_STATES {
            self.states.clear();
        }
    }
}

impl<E, P> ErasedSlot<E::Key> for TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
    P::Message: Send + Sync + 'static,
{
    fn track_into(
        &mut self,
        view: PacketView<'_>,
        _ts: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        let Some(extracted) = self.extractor.extract(view) else {
            return;
        };
        let Extracted {
            key, orientation, ..
        } = extracted;
        let Some(payload) = tcp_payload(view.frame) else {
            return;
        };

        if !self.states.contains_key(&key) {
            self.bound_states();
        }
        let state = self.states.entry(key.clone()).or_default();
        // Frames buffered before the pin, to be replayed in order so
        // the parser sees the connection from its first byte.
        let mut replay_frames: Vec<Vec<u8>> = Vec::new();
        let should_dispatch = match state {
            FlowDetection::Pinned => true,
            FlowDetection::GaveUp => false,
            FlowDetection::Probing {
                seen,
                init_buf,
                resp_buf,
                replay,
                replay_bytes,
            } => {
                match orientation {
                    Orientation::Forward => extend_probe(init_buf, payload),
                    Orientation::Reverse => extend_probe(resp_buf, payload),
                }
                let init_match = (self.signature)(init_buf);
                let resp_match = (self.signature)(resp_buf);
                if matches!(init_match, SignatureMatch::Match)
                    || matches!(resp_match, SignatureMatch::Match)
                {
                    // Hand over everything seen before this packet;
                    // the pinning frame itself is dispatched below.
                    replay_frames = std::mem::take(replay);
                    *state = FlowDetection::Pinned;
                    true
                } else if definitely_not(init_match) && definitely_not(resp_match) {
                    // `SignatureMatch` is tri-state precisely so a
                    // definitive miss can stop early: more bytes
                    // cannot turn a NoMatch into a Match, so burning
                    // the rest of the budget only delays the verdict.
                    *state = FlowDetection::GaveUp;
                    false
                } else {
                    *seen = seen.saturating_add(1);
                    if *seen >= self.max_probe_packets {
                        *state = FlowDetection::GaveUp;
                    } else if *replay_bytes + view.frame.len() <= PROBE_REPLAY_BYTE_CAP {
                        *replay_bytes += view.frame.len();
                        replay.push(view.frame.to_vec());
                    } else {
                        // Too much to hold: give up on replaying
                        // rather than growing without bound.
                        replay.clear();
                        *replay_bytes = usize::MAX;
                    }
                    false
                }
            }
        };
        if !should_dispatch {
            return;
        }
        let parser_kind = self.parser_kind;
        let before = lifecycle_out.len();
        for frame in &replay_frames {
            self.session_scratch.clear();
            let replayed = PacketView::new(frame, view.timestamp);
            self.driver.track_into(replayed, &mut self.session_scratch);
            for ev in self.session_scratch.drain(..) {
                route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
            }
        }
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        for ev in self.session_scratch.drain(..) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
        self.forget_ended(&lifecycle_out[before..]);
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let before = lifecycle_out.len();
        for ev in self.driver.sweep(now) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
        self.forget_ended(&lifecycle_out[before..]);
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let before = lifecycle_out.len();
        for ev in self.driver.finish() {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
        self.forget_ended(&lifecycle_out[before..]);
    }

    fn force_close_into(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        // Drop any per-flow heuristic detection state.
        self.states.remove(key);
        let parser_kind = self.parser_kind;
        for ev in self.driver.force_close(key, now) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }
}

/// Heuristic-routed datagram slot.
pub(super) struct TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor,
    D: DatagramParser + Sync,
    D::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    extractor: E,
    driver: FlowDatagramDriver<E, D, ()>,
    signature: SignatureFn,
    max_probe_packets: u8,
    parser_kind: ParserKind,
    states: HashMap<E::Key, FlowDetection>,
    msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, D::Message>>,
    _marker: PhantomData<D>,
}

impl<E, D> TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor + Clone,
    D: DatagramParser + Clone + Sync,
    D::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    pub(super) fn new(
        extractor: E,
        parser: D,
        config: FlowTrackerConfig,
        signature: SignatureFn,
        max_probe_packets: u8,
        monotonic_timestamps: bool,
    ) -> (Self, SlotHandle<D::Message, E::Key>)
    where
        E::Key: Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        let msg_buf = Arc::new(SegQueue::new());
        let handle = SlotHandle {
            inner: Arc::clone(&msg_buf),
            parser_kind,
        };
        let slot = Self::with_queue(
            extractor,
            parser,
            config,
            signature,
            max_probe_packets,
            monotonic_timestamps,
            msg_buf,
        );
        (slot, handle)
    }

    pub(super) fn with_queue(
        extractor: E,
        parser: D,
        config: FlowTrackerConfig,
        signature: SignatureFn,
        max_probe_packets: u8,
        monotonic_timestamps: bool,
        msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>>,
    ) -> Self
    where
        E::Key: Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowDatagramDriver::with_config(extractor.clone(), parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            extractor,
            signature,
            max_probe_packets,
            parser_kind,
            states: HashMap::new(),
            msg_buf,
            session_scratch: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<E, D> TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Send + Sync + 'static,
    D: DatagramParser + Sync,
    D::Message: Send + Sync + 'static,
{
    /// Drop per-flow probe state for flows that just ended.
    fn forget_ended(&mut self, events: &[Event<E::Key>]) {
        for ev in events {
            if let Event::Ended { key, .. } = ev {
                self.states.remove(key);
            }
        }
    }

    /// Keep the detection map bounded. See [`MAX_PROBE_STATES`].
    fn bound_states(&mut self) {
        if self.states.len() < MAX_PROBE_STATES {
            return;
        }
        // Flows already decided against are pure residue.
        self.states
            .retain(|_, v| !matches!(v, FlowDetection::GaveUp));
        if self.states.len() >= MAX_PROBE_STATES {
            self.states.clear();
        }
    }
}

impl<E, D> ErasedSlot<E::Key> for TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    D: DatagramParser + Send + Sync + 'static,
    D::Message: Send + Sync + 'static,
{
    fn track_into(
        &mut self,
        view: PacketView<'_>,
        _ts: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        let Some(Extracted { key, .. }) = self.extractor.extract(view) else {
            return;
        };
        let Some(payload) = udp_payload(view.frame) else {
            return;
        };
        if !self.states.contains_key(&key) {
            self.bound_states();
        }
        let state = self.states.entry(key.clone()).or_default();
        let should_dispatch = match state {
            FlowDetection::Pinned => true,
            FlowDetection::GaveUp => false,
            FlowDetection::Probing { seen, .. } => {
                let verdict = (self.signature)(payload);
                if matches!(verdict, SignatureMatch::Match) {
                    *state = FlowDetection::Pinned;
                    true
                } else {
                    // A definitive miss ends probing now: more
                    // datagrams cannot turn a NoMatch into a Match.
                    *seen = seen.saturating_add(1);
                    if definitely_not(verdict) || *seen >= self.max_probe_packets {
                        *state = FlowDetection::GaveUp;
                    }
                    false
                }
            }
        };
        if !should_dispatch {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        for ev in self.session_scratch.drain(..) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let before = lifecycle_out.len();
        for ev in self.driver.sweep(now) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
        self.forget_ended(&lifecycle_out[before..]);
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let before = lifecycle_out.len();
        for ev in self.driver.finish() {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
        self.forget_ended(&lifecycle_out[before..]);
    }

    fn force_close_into(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        self.states.remove(key);
        let parser_kind = self.parser_kind;
        for ev in self.driver.force_close(key, now) {
            route_session_event_pub(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }
}

// ── Helpers (duplicated from `heuristic.rs` to avoid making
//             those private fns crate-visible just for re-use). ──

/// Append to a probe buffer, silently stopping at the cap.
///
/// Truncation is fine for *deciding*: every shipped signature reaches
/// a verdict well inside [`PROBE_BUFFER_CAP`]. It is not fine for
/// *parsing*, which is why the frames themselves are kept separately
/// for replay rather than these buffers being reused as input.
fn extend_probe(buf: &mut ArrayVec<u8, PROBE_BUFFER_CAP>, payload: &[u8]) {
    let room = PROBE_BUFFER_CAP - buf.len();
    let to_take = room.min(payload.len());
    let _ = buf.try_extend_from_slice(&payload[..to_take]);
}

/// A verdict that more bytes cannot overturn.
///
/// [`SignatureMatch::NeedMoreData`] means "a valid prefix so far", so
/// only an outright `NoMatch` is conclusive. An empty buffer reports
/// `NeedMoreData`, so a direction that has not spoken yet never
/// counts as a miss.
fn definitely_not(m: SignatureMatch) -> bool {
    matches!(m, SignatureMatch::NoMatch)
}

fn tcp_payload(frame: &[u8]) -> Option<&[u8]> {
    let parsed = parse::parse_eth(frame)?;
    let ParsedL4::Tcp(t) = parsed.l4? else {
        return None;
    };
    let end = t.payload_offset.checked_add(t.payload_len)?;
    if end > frame.len() {
        return None;
    }
    Some(&frame[t.payload_offset..end])
}

fn udp_payload(frame: &[u8]) -> Option<&[u8]> {
    let parsed = parse::parse_eth(frame)?;
    let ParsedL4::Udp(u) = parsed.l4? else {
        return None;
    };
    let end = u.payload_offset.checked_add(u.payload_len)?;
    if end > frame.len() {
        return None;
    }
    Some(&frame[u.payload_offset..end])
}
