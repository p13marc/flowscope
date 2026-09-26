//! The engine shared by [`super::SessionDriver`],
//! [`super::DatagramDriver`] and [`crate::driver::Driver`]: one
//! [`FlowDriver`] (flow table + reassembly) feeding one or more
//! parser cores through a [`Dispatch`].
//!
//! Per packet, in order:
//!
//! 1. The flow driver tracks the packet (dedup, clamping, TCP state,
//!    reassembly, reassembly anomalies).
//! 2. Lifecycle events are handed to the dispatch in order. Right
//!    before the packet's own flow ends (or after the last event), the
//!    packet's data is dispatched: the side's reassembled stream is
//!    drained **once** and offered to every interested core, or the
//!    UDP payload is.
//! 3. For each ended flow the last stream bytes are drained and the
//!    cores close their parsers — before the `Ended` itself is
//!    forwarded, so a consumer sees a flow's final messages and
//!    parser closes before its end.
//!
//! Dispatch is keyed off [`FlowDriver::last_packet`], never off
//! `FlowEvent::Packet`, so shedding `Packet` events with
//! [`crate::EventMask`] does not stop L7 parsing.

use std::hash::Hash;

use crate::Timestamp;
use crate::event::{EndReason, FlowEvent, FlowSide, FlowStats};
use crate::extract::parse::{self, ParsedL4};
use crate::extractor::{FlowExtractor, L4Proto, Orientation};
use crate::flow_driver::{FlowDriver, PacketInfo};
use crate::reassembler::StreamChunks;
use crate::segment_reassembler::SegmentBufferReassemblerFactory;
use crate::session::core::{Ctx, Ports};
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

    /// Whether some core wants UDP datagrams with these ports.
    fn wants_datagram(&self, ports: Ports) -> bool;

    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &StreamChunks,
        out: &mut Self::Out,
    );

    /// After `on_stream`: `true` when no core can use this flow's
    /// byte stream any more (every interested parser closed or
    /// rejected it), so the engine can stop reassembling it.
    fn stream_done(&self, key: &K, ports: Ports) -> bool;

    fn on_datagram(&mut self, cx: &Ctx<'_, K>, ports: Ports, payload: &[u8], out: &mut Self::Out);

    #[allow(clippy::too_many_arguments)]
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        anomalies: bool,
        out: &mut Self::Out,
    );

    fn on_tick(
        &mut self,
        now: Timestamp,
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
/// or UDP.
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
/// datagram path).
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
        Self {
            flow: FlowDriver::from_tracker(tracker, SegmentBufferReassemblerFactory::default()),
            scratch: StreamChunks::new(),
            finals: [StreamChunks::new(), StreamChunks::new()],
        }
    }

    pub(crate) fn track<'v, D: Dispatch<E::Key>>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let view: PacketView<'v> = view.into();
        let ports = if dispatch.needs_ports() {
            ports_of(view.frame)
        } else {
            None
        };
        let reassemble = dispatch.wants_stream(ports);
        let mut events = self.flow.track_pending_with(view, reassemble);
        // `forward` finalizes each ended flow itself, right after its
        // last bytes are dispatched.
        let packet = self.flow.last_packet().cloned();
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
    }

    pub(crate) fn sweep<D: Dispatch<E::Key>>(
        &mut self,
        now: Timestamp,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let anomalies = self.flow.emits_anomalies();
        // Ticks first: a flow this sweep closes still gets its final
        // tick, and the tick's messages land ahead of its end.
        {
            let tracker = self.flow.tracker();
            let orientation_of = |k: &E::Key| {
                tracker
                    .get(k)
                    .map(|e| e.initiator_orientation())
                    .unwrap_or_default()
            };
            dispatch.on_tick(now, &orientation_of, anomalies, out);
        }
        let events = self.flow.sweep_pending(now);
        // Holes that expired in this sweep released data on sides
        // that may have gone quiet: hand it over.
        self.dispatch_released(anomalies, dispatch, out);
        let mut none = None;
        for ev in events {
            self.forward(ev, &mut none, anomalies, dispatch, out);
        }
        let tracker = self.flow.tracker();
        dispatch.retain(&|k| tracker.get(k).is_some());
    }

    pub(crate) fn force_close<D: Dispatch<E::Key>>(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let anomalies = self.flow.emits_anomalies();
        let events = self.flow.force_close_pending(key, now);
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
            side: p.side,
            orientation: p.orientation,
            ts: p.ts,
            anomalies,
        };
        match p.l4 {
            Some(L4Proto::Tcp) => {
                self.scratch.clear();
                if self.flow.drain_stream(&p.key, p.side, &mut self.scratch)
                    && !self.scratch.is_empty()
                {
                    dispatch.on_stream(&cx, ports, &self.scratch, out);
                    if dispatch.stream_done(&p.key, ports) {
                        self.flow.discard_stream(&p.key);
                    }
                }
            }
            _ if dispatch.wants_datagram(ports) => {
                if let Some(payload) = datagram_payload(view.frame) {
                    dispatch.on_datagram(&cx, ports, payload, out);
                }
            }
            _ => {}
        }
    }

    /// After a sweep, drain every side whose reassembler released
    /// data (expired holes) and dispatch it.
    fn dispatch_released<D: Dispatch<E::Key>>(
        &mut self,
        anomalies: bool,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        let keys: Vec<(E::Key, FlowSide)> = self.flow.reassembler_keys().collect();
        for (key, side) in keys {
            self.scratch.clear();
            self.flow.drain_stream(&key, side, &mut self.scratch);
            if self.scratch.data().is_empty() && self.scratch.gap_count() == 0 {
                // Nothing new (a sticky stop alone was already acted on).
                continue;
            }
            let Some(entry) = self.flow.tracker().get(&key) else {
                continue;
            };
            let initiator = entry.initiator_orientation();
            let orientation = match side {
                FlowSide::Initiator => initiator,
                FlowSide::Responder => initiator.flipped(),
            };
            let cx = Ctx {
                key: &key,
                side,
                orientation,
                ts: entry.stats.last_seen,
                anomalies,
            };
            dispatch.on_stream(&cx, None, &self.scratch, out);
        }
    }

    /// Forward one lifecycle event; for an `Ended`, first hand the
    /// flow's last bytes to the cores and release its reassemblers.
    fn forward<D: Dispatch<E::Key>>(
        &mut self,
        ev: FlowEvent<E::Key>,
        packet_tcp: &mut Option<crate::extractor::TcpInfo>,
        anomalies: bool,
        dispatch: &mut D,
        out: &mut D::Out,
    ) {
        if let FlowEvent::Ended {
            key, reason, stats, ..
        } = &ev
        {
            let [init, resp] = &mut self.finals;
            init.clear();
            resp.clear();
            self.flow.drain_stream(key, FlowSide::Initiator, init);
            self.flow.drain_stream(key, FlowSide::Responder, resp);
            dispatch.on_flow_end(key, *reason, stats, [&*init, &*resp], anomalies, out);
            self.flow.finalize_flow(key, *reason);
        }
        let tcp = if matches!(ev, FlowEvent::Packet { .. }) {
            packet_tcp.take()
        } else {
            None
        };
        dispatch.lifecycle(ev, tcp, out);
    }
}
