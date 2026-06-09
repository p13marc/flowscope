//! Heuristic (payload-signature) routing slots for the unified
//! [`super::Driver`].
//!
//! Folds plan 113 sub-B (`Routing::Heuristic`) onto the plan-116
//! `Driver<E, M>` foundation. Each heuristic slot wraps an
//! inner [`crate::session_driver::FlowSessionDriver`] (or
//! [`crate::datagram_driver::FlowDatagramDriver`]) plus a
//! per-flow detection state machine:
//!
//! - `Probing` — buffer the first `max_probe_packets` payload
//!   bytes per side, run the signature on each side. Pin on
//!   first `Match`.
//! - `Pinned` — forward every subsequent packet to the inner
//!   driver. O(1) dispatch.
//! - `GaveUp` — budget exhausted without a match; drop
//!   subsequent packets.

use std::collections::HashMap;
use std::hash::Hash;
use std::marker::PhantomData;

use arrayvec::ArrayVec;

use crate::PacketView;
use crate::Timestamp;
use crate::datagram_driver::FlowDatagramDriver;
use crate::detect::signatures::{SignatureFn, SignatureMatch};
use crate::extract::parse::{self, ParsedL4};
use crate::extractor::{Extracted, FlowExtractor, Orientation};
use crate::session::{DatagramParser, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;

use super::Event;
use super::erased::DriverSlot;

/// Buffer cap per side during the probing phase. Matches plan
/// 113's spec; every shipped signature decides within ≤ 64 B.
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

/// Heuristic-routed session-parser slot.
///
/// Holds its own `extractor` (cheap clone) so it can pull the
/// flow key + side + payload before deciding whether to forward
/// to the inner [`FlowSessionDriver`].
pub(super) struct HeuristicSessionSlot<E, P, M, F>
where
    E: FlowExtractor,
    P: SessionParser,
{
    pub(super) extractor: E,
    pub(super) driver: FlowSessionDriver<E, P, ()>,
    pub(super) signature: SignatureFn,
    pub(super) max_probe_packets: u8,
    pub(super) lift: F,
    pub(super) parser_kind: &'static str,
    pub(super) states: HashMap<E::Key, FlowDetection>,
    pub(super) _marker: PhantomData<M>,
}

impl<E, P, M, F> HeuristicSessionSlot<E, P, M, F>
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
        lift: F,
    ) -> Self {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowSessionDriver::with_config(extractor.clone(), parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            extractor,
            signature,
            max_probe_packets,
            lift,
            parser_kind,
            states: HashMap::new(),
            _marker: PhantomData,
        }
    }
}

impl<E, P, M, F> DriverSlot<E::Key, M> for HeuristicSessionSlot<E, P, M, F>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Send + 'static,
    P::Message: Send + 'static,
    F: Fn(P::Message) -> M + Send + 'static,
    M: Send + 'static,
{
    fn track_into(&mut self, view: PacketView<'_>, ts: Timestamp, out: &mut Vec<Event<E::Key, M>>) {
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
        for ev in self.driver.track(view) {
            if let Some(lifted) = super::erased::lift_event_pub(ev, &self.lift, ts, parser_kind) {
                out.push(lifted);
            }
        }
    }

    fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key, M>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.sweep(now) {
            if let Some(lifted) = super::erased::lift_event_pub(ev, &self.lift, now, parser_kind) {
                out.push(lifted);
            }
        }
    }

    fn finish_into(&mut self, out: &mut Vec<Event<E::Key, M>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.finish() {
            if let Some(lifted) =
                super::erased::lift_event_pub(ev, &self.lift, Timestamp::MAX, parser_kind)
            {
                out.push(lifted);
            }
        }
    }
}

/// Heuristic-routed datagram (UDP) slot. Each datagram is its
/// own probe — no per-side buffering, since one UDP packet
/// usually contains the whole protocol header.
pub(super) struct HeuristicDatagramSlot<E, D, M, F>
where
    E: FlowExtractor,
    D: DatagramParser,
{
    pub(super) extractor: E,
    pub(super) driver: FlowDatagramDriver<E, D, ()>,
    pub(super) signature: SignatureFn,
    pub(super) max_probe_packets: u8,
    pub(super) lift: F,
    pub(super) parser_kind: &'static str,
    pub(super) states: HashMap<E::Key, FlowDetection>,
    pub(super) _marker: PhantomData<M>,
}

impl<E, D, M, F> HeuristicDatagramSlot<E, D, M, F>
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
        lift: F,
    ) -> Self {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowDatagramDriver::with_config(extractor.clone(), parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            extractor,
            signature,
            max_probe_packets,
            lift,
            parser_kind,
            states: HashMap::new(),
            _marker: PhantomData,
        }
    }
}

impl<E, D, M, F> DriverSlot<E::Key, M> for HeuristicDatagramSlot<E, D, M, F>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    D: DatagramParser + Send + 'static,
    D::Message: Send + 'static,
    F: Fn(D::Message) -> M + Send + 'static,
    M: Send + 'static,
{
    fn track_into(&mut self, view: PacketView<'_>, ts: Timestamp, out: &mut Vec<Event<E::Key, M>>) {
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
                if matches!((self.signature)(&payload), SignatureMatch::Match) {
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
        for ev in self.driver.track(view) {
            if let Some(lifted) = super::erased::lift_event_pub(ev, &self.lift, ts, parser_kind) {
                out.push(lifted);
            }
        }
    }

    fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key, M>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.sweep(now) {
            if let Some(lifted) = super::erased::lift_event_pub(ev, &self.lift, now, parser_kind) {
                out.push(lifted);
            }
        }
    }

    fn finish_into(&mut self, out: &mut Vec<Event<E::Key, M>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.finish() {
            if let Some(lifted) =
                super::erased::lift_event_pub(ev, &self.lift, Timestamp::MAX, parser_kind)
            {
                out.push(lifted);
            }
        }
    }
}

/// Extend a probing buffer with up to `PROBE_BUFFER_CAP - len`
/// bytes from `payload`. Silent overflow.
fn extend_probe(buf: &mut ArrayVec<u8, PROBE_BUFFER_CAP>, payload: &[u8]) {
    let room = PROBE_BUFFER_CAP - buf.len();
    let to_take = room.min(payload.len());
    let _ = buf.try_extend_from_slice(&payload[..to_take]);
}

/// Best-effort TCP payload slice from an L2 Ethernet frame.
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

/// Best-effort UDP payload slice from an L2 Ethernet frame.
fn udp_payload(frame: &[u8]) -> Option<Vec<u8>> {
    let parsed = parse::parse_eth(frame)?;
    let ParsedL4::Udp(u) = parsed.l4? else {
        return None;
    };
    let end = u.payload_offset.checked_add(u.payload_len)?;
    if end > frame.len() {
        return None;
    }
    Some(frame[u.payload_offset..end].to_vec())
}
