//! Heuristic-routed slots for [`super::typed::Driver`].
//!
//! Mirror of [`super::heuristic`] adapted to the typed
//! `SlotHandle` pattern. Each slot holds a per-flow detection
//! state machine; when the signature matches it pins to the
//! parser and writes typed messages into the slot's
//! `Rc<RefCell<SlotBuf>>`.

use std::cell::RefCell;
use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;
use std::rc::Rc;

use arrayvec::ArrayVec;

use crate::PacketView;
use crate::Timestamp;
use crate::datagram_driver::FlowDatagramDriver;
use crate::detect::signatures::{SignatureFn, SignatureMatch};
use crate::extract::parse::{self, ParsedL4};
use crate::extractor::{Extracted, FlowExtractor, Orientation};
use crate::session::{DatagramParser, SessionEvent, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;

use super::slot::{SlotBuf, SlotHandle};
use super::typed::Event;
use super::typed_slot::{ErasedSlot, route_session_event_pub};

/// Buffer cap per side during the probing phase. Every shipped
/// signature decides within ≤ 64 B.
pub const PROBE_BUFFER_CAP: usize = 64;

/// Default probing-budget if the user doesn't override.
pub const DEFAULT_PROBE_PACKETS: u8 = 4;

/// Per-flow detection state inside a heuristic slot.
pub(super) enum FlowDetection {
    Probing {
        seen: u8,
        init_buf: ArrayVec<u8, PROBE_BUFFER_CAP>,
        resp_buf: ArrayVec<u8, PROBE_BUFFER_CAP>,
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
        }
    }
}

/// Heuristic-routed session slot.
pub(super) struct TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor,
    P: SessionParser,
{
    extractor: E,
    driver: FlowSessionDriver<E, P, ()>,
    signature: SignatureFn,
    max_probe_packets: u8,
    parser_kind: &'static str,
    states: HashMap<E::Key, FlowDetection>,
    msg_buf: Rc<RefCell<SlotBuf<P::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, P::Message>>,
    _marker: PhantomData<P>,
}

impl<E, P> TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor + Clone,
    P: SessionParser + Clone,
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
        E::Key: 'static,
        P::Message: 'static,
    {
        let parser_kind = parser.parser_kind();
        let msg_buf = Rc::new(RefCell::new(SlotBuf::new()));
        let handle = SlotHandle {
            inner: Rc::clone(&msg_buf),
            parser_kind,
        };
        let slot = Self {
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
        };
        (slot, handle)
    }
}

impl<E, P> ErasedSlot<E::Key> for TypedHeuristicSessionSlot<E, P>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Send + 'static,
    P::Message: Send + 'static,
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

        let state = self.states.entry(key.clone()).or_default();
        let should_dispatch = match state {
            FlowDetection::Pinned => true,
            FlowDetection::GaveUp => false,
            FlowDetection::Probing {
                seen,
                init_buf,
                resp_buf,
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
                    *state = FlowDetection::Pinned;
                    true
                } else {
                    *seen = seen.saturating_add(1);
                    if *seen >= self.max_probe_packets {
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
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.session_scratch.drain(..) {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.sweep(now) {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.finish() {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }
}

/// Heuristic-routed datagram slot.
pub(super) struct TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor,
    D: DatagramParser,
{
    extractor: E,
    driver: FlowDatagramDriver<E, D, ()>,
    signature: SignatureFn,
    max_probe_packets: u8,
    parser_kind: &'static str,
    states: HashMap<E::Key, FlowDetection>,
    msg_buf: Rc<RefCell<SlotBuf<D::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, D::Message>>,
    _marker: PhantomData<D>,
}

impl<E, D> TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor + Clone,
    D: DatagramParser + Clone,
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
        E::Key: 'static,
        D::Message: 'static,
    {
        let parser_kind = parser.parser_kind();
        let msg_buf = Rc::new(RefCell::new(SlotBuf::new()));
        let handle = SlotHandle {
            inner: Rc::clone(&msg_buf),
            parser_kind,
        };
        let slot = Self {
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
        };
        (slot, handle)
    }
}

impl<E, D> ErasedSlot<E::Key> for TypedHeuristicDatagramSlot<E, D>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    D: DatagramParser + Send + 'static,
    D::Message: Send + 'static,
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
        let state = self.states.entry(key.clone()).or_default();
        let should_dispatch = match state {
            FlowDetection::Pinned => true,
            FlowDetection::GaveUp => false,
            FlowDetection::Probing { seen, .. } => {
                if matches!((self.signature)(payload), SignatureMatch::Match) {
                    *state = FlowDetection::Pinned;
                    true
                } else {
                    *seen = seen.saturating_add(1);
                    if *seen >= self.max_probe_packets {
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
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.session_scratch.drain(..) {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.sweep(now) {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.finish() {
            route_session_event_pub(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }
}

// ── Helpers (duplicated from `heuristic.rs` to avoid making
//             those private fns crate-visible just for re-use). ──

fn extend_probe(buf: &mut ArrayVec<u8, PROBE_BUFFER_CAP>, payload: &[u8]) {
    let room = PROBE_BUFFER_CAP - buf.len();
    let to_take = room.min(payload.len());
    let _ = buf.try_extend_from_slice(&payload[..to_take]);
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
