//! The engine shared by [`super::SessionDriver`],
//! [`super::DatagramDriver`] and [`crate::driver::Driver`]: one
//! [`FlowDriver`] (flow table + reassembly) feeding one or more
//! parser cores through a [`Dispatch`].
//!
//! Per packet, in order:
//!
//! 1. The flow driver tracks the packet (dedup, clamping, TCP state,
//!    reassembly). In-order TCP payload is let through without being
//!    copied ([`crate::SegmentOutcome::Passthrough`]).
//! 2. Lifecycle events are handed to the dispatch in order; the
//!    packet's reassembly anomalies come right before the packet's
//!    own `Ended`. Right before that `Ended` (or after the last
//!    event), the packet's data is dispatched: the let-through bytes
//!    or the side's drained stream, or the datagram payload.
//! 3. For each ended flow: flush (anomalies) → final bytes → parser
//!    closes → `Ended`. A consumer sees a flow's final messages and
//!    parser closes before its end.
//!
//! Per sweep, in order: parser ticks (stamped with the clamped
//! `now`), then data released by hole deadlines on flows that are
//! still tracked, then the flows the sweep ends (step 3). Released
//! data is therefore never drained from a flow after its end was
//! decided (before 0.25 it was, and dropped).
//!
//! Dispatch is keyed off [`FlowDriver::last_packet`], never off
//! `FlowEvent::Packet`, so shedding `Packet` events with
//! [`crate::EventMask`] does not stop L7 parsing. The event mask and
//! pause only affect what reaches the consumer: parsers still see
//! every flow end.

use std::hash::Hash;

use crate::Timestamp;
use crate::event::{EndReason, EventMask, FlowEvent, FlowSide, FlowStats};
use crate::extract::parse::{self, ParsedL4};
use crate::extractor::{FlowExtractor, L4Proto, Orientation};
use crate::flow_driver::{FlowDriver, PacketInfo};
use crate::reassembler::StreamChunks;
use crate::segment_reassembler::SegmentBufferReassemblerFactory;
use crate::session::core::{Ctx, Ports, Stream};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// What an engine drives: one or more parser cores plus the
/// translation of lifecycle events into the consumer's output type.
pub(crate) trait Dispatch<K> {
    /// Output buffer (lifecycle events, and messages for the session
    /// drivers).
    type Out;

    /// Whether any core needs packet ports (port-bound selectors).
    fn needs_ports(&self) -> bool;

    /// Whether some core wants the TCP byte stream of a flow whose
    /// packet has these ports (drives reassembler creation).
    fn wants_stream(&self, ports: Ports) -> bool;

    /// Whether some core wants datagrams of this transport with
    /// these ports.
    fn wants_datagram(&self, ports: Ports, l4: Option<L4Proto>) -> bool;

    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        stream: &Stream<'_>,
        out: &mut Self::Out,
    );

    /// After `on_stream`, per side (initiator, responder): `true`
    /// when no core can use that side's byte stream any more (every
    /// interested parser closed, stopped the side or rejected the
    /// flow), so the engine can stop reassembling it.
    fn streams_done(&self, key: &K, ports: Ports) -> [bool; 2];

    fn on_datagram(&mut self, cx: &Ctx<'_, K>, ports: Ports, payload: &[u8], out: &mut Self::Out);

    #[allow(clippy::too_many_arguments)]
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        ports: Ports,
        anomalies: bool,
        out: &mut Self::Out,
    );

    /// Parser ticks. Parsers see `now` (`Timestamp::MAX` at the end
    /// of input); their output is stamped `stamp`.
    fn on_tick(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut Self::Out,
    );

    fn retain(&mut self, alive: &dyn Fn(&K) -> bool);

    /// Forward one lifecycle event (`packet_tcp` is the packet's TCP
    /// header for the `Packet` event of the tracked packet).
    fn lifecycle(
        &mut self,
        ev: FlowEvent<K>,
        packet_tcp: Option<crate::extractor::TcpInfo>,
        out: &mut Self::Out,
    );
}

/// Source/destination ports of an Ethernet frame, if it carries TCP
/// or UDP. Fallback for extractors that report no [`crate::L4Meta`].
pub(crate) fn ports_of(frame: &[u8]) -> Ports {
    let parsed = parse::parse_eth(frame)?;
    match parsed.l4? {
        ParsedL4::Tcp(t) => Some((t.src_port, t.dst_port)),
        ParsedL4::Udp(u) => Some((u.src_port, u.dst_port)),
        _ => None,
    }
}

/// The payload a datagram parser receives: the UDP payload, or the
/// whole ICMPv4 / ICMPv6 message (0.14.1: ICMP parsers ride the
/// datagram path). Fallback for extractors that report no
/// [`crate::L4Meta`].
fn datagram_payload(frame: &[u8]) -> Option<&[u8]> {
    let sp = etherparse::SlicedPacket::from_ethernet(frame).ok()?;
    match sp.transport? {
        etherparse::TransportSlice::Udp(udp) => Some(udp.payload()),
        etherparse::TransportSlice::Icmpv4(icmp) => Some(icmp.slice()),
        etherparse::TransportSlice::Icmpv6(icmp) => Some(icmp.slice()),
        _ => None,
    }
}

/// Flow driver + scratch buffers. See the [module docs](self).
pub(crate) struct Engine<E>
where
    E: FlowExtractor,
{
    pub(crate) flow: FlowDriver<E, SegmentBufferReassemblerFactory, ()>,
    scratch: StreamChunks,
    finals: [StreamChunks; 2],
    anomalies: Vec<FlowEvent<E::Key>>,
}

impl<E> Engine<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone,
{
    pub(crate) fn new(extractor: E, config: FlowTrackerConfig) -> Self {
        Self::from_tracker(FlowTracker::with_config(extractor, config))
    }

    pub(crate) fn from_tracker(tracker: FlowTracker<E, ()>) -> Self {
        let mut flow =
            FlowDriver::from_tracker(tracker, SegmentBufferReassemblerFactory::default());
        flow.set_passthrough(true);
        Self {
            flow,
            scratch: StreamChunks::new(),
            finals: [StreamChunks::new(), StreamChunks::new()],
            anomalies: Vec::new(),
        }
    }

    pub(crate) fn track<'v, D: Dispatch<E::Key>>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let view: PacketView<'v> = view.into();
        let needs_ports = dispatch.needs_ports();
        let frame = view.frame;
        let mut events = self.flow.track_raw(view, |p| {
            let ports = match p.l4_meta {
                Some(m) => m.ports,
                None if needs_ports => ports_of(frame),
                None => None,
            };
            dispatch.wants_stream(ports)
        });
        let packet = self.flow.last_packet().cloned();
        let ports = match packet.as_ref().and_then(|p| p.l4_meta) {
            Some(m) => m.ports,
            None if needs_ports && packet.is_some() => ports_of(frame),
            None => None,
        };
        let anomalies = self.flow.emits_anomalies();

        let mut data_pending = packet.is_some();
        let mut packet_tcp = packet.as_ref().and_then(|p| p.tcp);
        for ev in events.drain(..) {
            if let (true, Some(p), FlowEvent::Ended { key, .. }) = (data_pending, &packet, &ev)
                && key == &p.key
            {
                self.dispatch_packet(p, view, ports, anomalies, dispatch, out);
                data_pending = false;
            }
            self.forward(ev, &mut packet_tcp, anomalies, dispatch, out);
        }
        if data_pending && let Some(p) = &packet {
            self.dispatch_packet(p, view, ports, anomalies, dispatch, out);
        }
        if let Some(p) = &packet
            && self.flow.auto_sweep_due(p.ts)
        {
            self.sweep(p.ts, dispatch, out);
        }
    }

    pub(crate) fn sweep<D: Dispatch<E::Key>>(
        &mut self,
        now: Timestamp,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let now = self.flow.clamp_now(now);
        let anomalies = self.flow.emits_anomalies();
        // 1. Ticks: a flow this sweep closes still gets its final
        //    tick, and the tick's messages land ahead of its end.
        self.tick(now, now, anomalies, dispatch, out);
        // 2. Holes past their deadline release data — on flows that
        //    are still tracked.
        let emit_flow_anomalies = self.flow.emits_mask(EventMask::FLOW_ANOMALY);
        self.flow
            .advance_streams(now, Some(&mut self.scratch), |r| {
                for a in r.anomalies.drain(..) {
                    if emit_flow_anomalies {
                        dispatch.lifecycle(a, None, out);
                    }
                }
                if let Some(data) = r.data.as_deref()
                    && !data.is_empty()
                {
                    let cx = Ctx {
                        key: r.key,
                        l4: Some(L4Proto::Tcp),
                        side: r.side,
                        orientation: r.orientation,
                        ts: now,
                        anomalies,
                    };
                    dispatch.on_stream(&cx, r.ports, &Stream::Chunks(data), out);
                }
            });
        // 3. Flows the sweep ends.
        let events = self.flow.sweep_raw(now);
        let mut none = None;
        for ev in events {
            self.forward(ev, &mut none, anomalies, dispatch, out);
        }
        let tracker = self.flow.tracker();
        dispatch.retain(&|k| tracker.get(k).is_some());
    }

    /// End of input: every flow ends. Parsers' `on_tick` sees
    /// `Timestamp::MAX`; everything is stamped with the latest packet
    /// time, and the monotonic clock is left alone.
    pub(crate) fn finish<D: Dispatch<E::Key>>(&mut self, dispatch: &mut D, out: &mut D::Out) {
        let stamp = self.flow.max_timestamp();
        let anomalies = self.flow.emits_anomalies();
        self.tick(Timestamp::MAX, stamp, anomalies, dispatch, out);
        let events = self.flow.finish_raw();
        let mut none = None;
        for ev in events {
            self.forward(ev, &mut none, anomalies, dispatch, out);
        }
    }

    fn tick<D: Dispatch<E::Key>>(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        anomalies: bool,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let tracker = self.flow.tracker();
        let orientation_of = |k: &E::Key| {
            tracker
                .get(k)
                .map(|e| e.initiator_orientation())
                .unwrap_or_default()
        };
        dispatch.on_tick(now, stamp, &orientation_of, anomalies, out);
    }

    pub(crate) fn force_close<D: Dispatch<E::Key>>(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let anomalies = self.flow.emits_anomalies();
        let events = self.flow.force_close_raw(key, now);
        let mut none = None;
        for ev in events {
            self.forward(ev, &mut none, anomalies, dispatch, out);
        }
    }

    /// Dispatch the data carried by the tracked packet.
    fn dispatch_packet<D: Dispatch<E::Key>>(
        &mut self,
        p: &PacketInfo<E::Key>,
        view: PacketView<'_>,
        ports: Ports,
        anomalies: bool,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let cx = Ctx {
            key: &p.key,
            l4: p.l4,
            side: p.side,
            orientation: p.orientation,
            ts: p.ts,
            anomalies,
        };
        match p.l4 {
            Some(L4Proto::Tcp) => {
                if let Some(bytes) = p.passthrough_bytes(view.frame) {
                    if bytes.is_empty() {
                        return;
                    }
                    dispatch.on_stream(&cx, ports, &Stream::Bytes(bytes), out);
                } else {
                    self.scratch.clear();
                    if !self.flow.drain_stream(&p.key, p.side, &mut self.scratch)
                        || self.scratch.is_empty()
                    {
                        return;
                    }
                    dispatch.on_stream(&cx, ports, &Stream::Chunks(&self.scratch), out);
                }
                match dispatch.streams_done(&p.key, ports) {
                    [true, true] => self.flow.discard_stream(&p.key),
                    [true, false] => self.flow.discard_side(&p.key, FlowSide::Initiator),
                    [false, true] => self.flow.discard_side(&p.key, FlowSide::Responder),
                    [false, false] => {}
                }
            }
            _ if dispatch.wants_datagram(ports, p.l4) => {
                let payload = match p.l4_meta {
                    Some(m) => Some(m.payload(view.frame)),
                    None => datagram_payload(view.frame),
                };
                if let Some(payload) = payload {
                    dispatch.on_datagram(&cx, ports, payload, out);
                }
            }
            _ => {}
        }
    }

    /// Forward one lifecycle event; for an `Ended`, first flush the
    /// flow (anomalies), hand its last bytes to the cores, close its
    /// parsers and release its stream state.
    fn forward<D: Dispatch<E::Key>>(
        &mut self,
        mut ev: FlowEvent<E::Key>,
        packet_tcp: &mut Option<crate::extractor::TcpInfo>,
        anomalies: bool,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        if let FlowEvent::Ended {
            key, reason, stats, ..
        } = &mut ev
        {
            self.anomalies.clear();
            self.flow.close_flow(key, stats, &mut self.anomalies);
            for a in self.anomalies.drain(..) {
                if self.flow.emits(&a) {
                    dispatch.lifecycle(a, None, out);
                }
            }
            let [init, resp] = &mut self.finals;
            init.clear();
            resp.clear();
            self.flow.drain_stream(key, FlowSide::Initiator, init);
            self.flow.drain_stream(key, FlowSide::Responder, resp);
            let ports = self.flow.stream_ports(key);
            dispatch.on_flow_end(key, *reason, stats, [&*init, &*resp], ports, anomalies, out);
            self.flow.finalize_flow(key, *reason);
        }
        if !self.flow.emits(&ev) {
            return;
        }
        let tcp = if matches!(ev, FlowEvent::Packet { .. }) {
            packet_tcp.take()
        } else {
            None
        };
        dispatch.lifecycle(ev, tcp, out);
    }
}
