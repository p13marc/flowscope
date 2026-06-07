//! `flowscope::driver_unified` — preview of the plan 116
//! unified `Driver<E, M>` + `Event<K, M>` surface.
//!
//! Plan 116 collapses the 0.9-era 6 driver types (`FlowDriver`,
//! `FlowSessionDriver`, `FlowDatagramDriver`,
//! `FlowMultiSessionDriver`, `Pipeline`) and 4 event types
//! (`FlowEvent`, `SessionEvent`, planned `MultiEvent`,
//! `pipeline::Event`) into ONE `Driver<E, M>` + ONE
//! `Event<K, M>` + a thin `Pipeline` wrapper.
//!
//! This module ships the new types **alongside** the legacy
//! ones in 0.10 as a migration preview. The PR series:
//!
//! 1. **PR 1 (this commit)** — purely additive; new types
//!    available behind `flowscope::driver_unified`. Old drivers
//!    untouched.
//! 2. PR 2 — adds UDP / datagram dispatch + heuristic routing.
//! 3. PR 3 — migrates `Pipeline` to wrap the unified driver
//!    internally.
//! 4. PR 4 — migrates tests + examples.
//! 5. PR 5 — deletes legacy types; renames `driver_unified` →
//!    top-level `driver`.
//!
//! ## Builder knob coverage
//!
//! | Plan-116 knob | Status | Notes |
//! |---------------|--------|-------|
//! | [`DriverBuilder::config`] | ✅ | Override the central tracker config. |
//! | [`DriverBuilder::monotonic_timestamps`] | ✅ | Forwarded to every slot's inner driver. |
//! | [`DriverBuilder::emit_packet_details`] | ✅ | Populates [`Event::FlowPacket`]'s `tcp` + `frame` fields. |
//! | `emit_anomalies(bool)` | ⏸ deferred | The central [`crate::FlowTracker`] doesn't synthesise anomalies (that lives on [`crate::FlowDriver`]); plumbing it cleanly without N× duplication needs either a "primary slot" pattern or replacing the central tracker. |
//! | `dedup(Dedup)` | ⏸ deferred | Same shape constraint as `emit_anomalies`. |
//! | `idle_timeout_fn(F)` | 🟡 workaround | Available today via `driver.tracker_mut().set_idle_timeout_fn(f)` — direct builder method queued. |
//!
//! ```ignore
//! use flowscope::driver_unified::{Driver, Event};
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::{HttpMessage, HttpParser};
//!
//! let mut driver = Driver::<_, HttpMessage>::builder(FiveTuple::bidirectional())
//!     .session_on_ports(HttpParser::default(), [80, 8080], |m| m)
//!     .build();
//!
//! for view in views() {
//!     for event in driver.track(view) {
//!         match event {
//!             Event::Message { message, .. } => { /* L7 message */ }
//!             Event::FlowStarted { .. } | Event::FlowEnded { .. } => { /* lifecycle */ }
//!             _ => {}
//!         }
//!     }
//! }
//! ```

mod erased;
mod event;
mod heuristic;
mod pipeline;

pub use event::Event;
pub use heuristic::{DEFAULT_PROBE_PACKETS, PROBE_BUFFER_CAP};
pub use pipeline::{Pipeline, PipelineBuilder, PipelineIter};

use std::hash::Hash;
use std::marker::PhantomData;

use crate::PacketView;
use crate::Timestamp;
use crate::detect::signatures::SignatureFn;
use crate::event::FlowEvent;
use crate::extractor::{FlowExtractor, TcpInfo};
use crate::session::{DatagramParser, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};

use erased::{ConcreteDatagramSlot, ConcreteSlot, DriverSlot};
use heuristic::{HeuristicDatagramSlot, HeuristicSessionSlot};

/// Unified flow + session driver.
///
/// One central [`FlowTracker`] owns the per-flow lifecycle; each
/// registered parser observes packets matching its routing rule
/// and produces [`Event::Message`] / [`Event::ParserClosed`]
/// outputs lifted into the composite message type `M`.
///
/// Build via [`Self::builder`]:
///
/// ```ignore
/// let mut driver = Driver::<_, MyL7>::builder(FiveTuple::bidirectional())
///     .session_on_ports(HttpParser::default(), [80, 8080], MyL7::Http)
///     .session_on_ports(TlsParser::default(),  [443],       MyL7::Tls)
///     .build();
/// ```
pub struct Driver<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    tracker: FlowTracker<E, ()>,
    extractor: E,
    emit_packet_details: bool,
    slots: Vec<Box<dyn DriverSlot<E::Key, M>>>,
    _marker: PhantomData<M>,
}

impl<E, M> Driver<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Begin building a new driver.
    pub fn builder(extractor: E) -> DriverBuilder<E, M> {
        DriverBuilder {
            extractor,
            config: FlowTrackerConfig::default(),
            monotonic_timestamps: false,
            emit_packet_details: false,
            slots: Vec::new(),
            _marker: PhantomData,
        }
    }

    /// Process one packet. Returns the merged event stream:
    /// flow-lifecycle events from the central tracker plus
    /// parser-sourced events ([`Event::Message`] /
    /// [`Event::ParserClosed`]) from any matching registered
    /// slot.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<Event<E::Key, M>> {
        let view: PacketView<'v> = view.into();
        let ts = view.timestamp;
        let mut out: Vec<Event<E::Key, M>> = Vec::new();

        // Optionally pre-extract TcpInfo + frame bytes for
        // emit_packet_details enrichment. We re-extract here
        // because the central FlowTracker doesn't surface tcp
        // info on FlowEvent::Packet; this is the cheapest way
        // to honour plan 108's spec without changing the
        // tracker's event shape.
        let (tcp_for_packet, frame_for_packet): (Option<TcpInfo>, Option<Vec<u8>>) =
            if self.emit_packet_details {
                let tcp = self.extractor.extract(view).and_then(|e| e.tcp);
                (tcp, Some(view.frame.to_vec()))
            } else {
                (None, None)
            };

        // Central tracker emits flow-lifecycle events. The
        // pre-extracted enrichment is consumed by the FIRST
        // FlowEvent::Packet we see (there's usually exactly one
        // per track() call); subsequent events get None.
        let mut tcp_slot = tcp_for_packet;
        let mut frame_slot = frame_for_packet;
        for flow_ev in self.tracker.track(view).into_iter() {
            let (this_tcp, this_frame) = if matches!(flow_ev, FlowEvent::Packet { .. }) {
                let pair = (tcp_slot, frame_slot.take());
                tcp_slot = None; // consumed; subsequent Packets in this call get None
                pair
            } else {
                (None, None)
            };
            out.extend(map_flow_event_with_details::<E::Key, M>(
                flow_ev, this_tcp, this_frame,
            ));
        }

        // Slots emit Message + ParserClosed only (filtered).
        for slot in &mut self.slots {
            out.extend(slot.track(view, ts));
        }
        out
    }

    /// Periodic sweep: drives idle-timeout `FlowEnded` events
    /// from the central tracker plus per-slot `on_tick` output.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key, M>> {
        let mut out: Vec<Event<E::Key, M>> = Vec::new();
        for flow_ev in self.tracker.sweep(now) {
            out.extend(map_flow_event_with_details::<E::Key, M>(flow_ev, None, None));
        }
        for slot in &mut self.slots {
            out.extend(slot.sweep(now));
        }
        out
    }

    /// End-of-input flush: force-closes all live flows and
    /// drains every parser's pending state.
    pub fn finish(&mut self) -> Vec<Event<E::Key, M>> {
        let mut out: Vec<Event<E::Key, M>> = Vec::new();
        for flow_ev in self.tracker.finish() {
            out.extend(map_flow_event_with_details::<E::Key, M>(flow_ev, None, None));
        }
        for slot in &mut self.slots {
            out.extend(slot.finish());
        }
        out
    }

    /// Borrow the underlying tracker for introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()> {
        &self.tracker
    }

    /// Mutable borrow of the underlying tracker.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
        &mut self.tracker
    }
}

/// Builder for [`Driver<E, M>`].
pub struct DriverBuilder<E, M>
where
    E: FlowExtractor,
    M: Send + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_packet_details: bool,
    slots: Vec<Box<dyn DriverSlot<E::Key, M>>>,
    _marker: PhantomData<M>,
}

impl<E, M> DriverBuilder<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Override the central tracker's config.
    pub fn config(mut self, c: FlowTrackerConfig) -> Self {
        self.config = c;
        self
    }

    /// Enable strict-monotonic timestamp clamping on every slot's
    /// inner driver. Default `false`. Recommended `true` for
    /// offline pcap replay where timestamps may be slightly
    /// out-of-order due to capture interleaving.
    ///
    /// Mirror of [`crate::FlowSessionDriver::with_monotonic_timestamps`].
    pub fn monotonic_timestamps(mut self, on: bool) -> Self {
        self.monotonic_timestamps = on;
        self
    }

    /// Opt into per-packet enrichment: when set, every
    /// [`Event::FlowPacket`] carries
    /// `tcp: Option<crate::TcpInfo>` + `frame: Option<Vec<u8>>`
    /// populated from a fresh extraction of the packet view.
    ///
    /// Costs (default `false` — enrichment is opt-in):
    /// - One extra `extract` call per packet (for `tcp`).
    /// - One memcpy of the full frame per packet (for `frame`).
    ///
    /// Plan 108 absorbed into plan 116.
    pub fn emit_packet_details(mut self, on: bool) -> Self {
        self.emit_packet_details = on;
        self
    }

    /// Register a session parser bound to a fixed port set.
    /// The parser fires on flows whose src OR dst port is in
    /// `ports`. Emitted messages are lifted to `M` via `lift`.
    pub fn session_on_ports<P, I, F>(mut self, parser: P, ports: I, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let slot = ConcreteSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            Some(port_set),
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Register a session parser that fires on every flow
    /// regardless of port. Emitted messages are lifted to `M`
    /// via `lift`.
    pub fn session_broadcast<P, F>(mut self, parser: P, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        let slot = ConcreteSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            None,
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Register a datagram (UDP) parser bound to a fixed port
    /// set. Mirror of [`Self::session_on_ports`].
    pub fn datagram_on_ports<D, I, F>(mut self, parser: D, ports: I, lift: F) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(D::Message) -> M + Send + 'static,
    {
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        let slot = ConcreteDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            Some(port_set),
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Register a datagram (UDP) parser that fires on every
    /// flow regardless of port. Mirror of
    /// [`Self::session_broadcast`].
    pub fn datagram_broadcast<D, F>(mut self, parser: D, lift: F) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        F: Fn(D::Message) -> M + Send + 'static,
    {
        let slot = ConcreteDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            None,
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Register a session parser that fires when a payload
    /// signature returns
    /// [`Match`](crate::detect::signatures::SignatureMatch::Match).
    /// Probes the first [`DEFAULT_PROBE_PACKETS`] packets per
    /// flow; after a `Match`, the parser is pinned and every
    /// subsequent packet on that flow goes directly to the
    /// inner driver (O(1) dispatch).
    pub fn session_heuristic<P, F>(self, parser: P, signature: SignatureFn, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        self.session_heuristic_with_budget(parser, signature, DEFAULT_PROBE_PACKETS, lift)
    }

    /// [`Self::session_heuristic`] with an explicit probing
    /// budget. Typical values are 2–8; 4 is the shipping default.
    pub fn session_heuristic_with_budget<P, F>(
        mut self,
        parser: P,
        signature: SignatureFn,
        max_probe_packets: u8,
        lift: F,
    ) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        let slot = HeuristicSessionSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            signature,
            max_probe_packets,
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Datagram-side equivalent of [`Self::session_heuristic`].
    /// Each UDP packet is its own probe — no per-side
    /// buffering; the signature runs on the raw payload.
    pub fn datagram_heuristic<D, F>(self, parser: D, signature: SignatureFn, lift: F) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        F: Fn(D::Message) -> M + Send + 'static,
    {
        self.datagram_heuristic_with_budget(parser, signature, DEFAULT_PROBE_PACKETS, lift)
    }

    /// [`Self::datagram_heuristic`] with an explicit probing
    /// budget.
    pub fn datagram_heuristic_with_budget<D, F>(
        mut self,
        parser: D,
        signature: SignatureFn,
        max_probe_packets: u8,
        lift: F,
    ) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        F: Fn(D::Message) -> M + Send + 'static,
    {
        let slot = HeuristicDatagramSlot::new(
            self.extractor.clone(),
            parser,
            self.config.clone(),
            signature,
            max_probe_packets,
            self.monotonic_timestamps,
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> Driver<E, M> {
        Driver {
            tracker: FlowTracker::with_config(self.extractor.clone(), self.config),
            extractor: self.extractor,
            emit_packet_details: self.emit_packet_details,
            slots: self.slots,
            _marker: PhantomData,
        }
    }
}

/// Adapt a tracker-emitted [`FlowEvent`] into the unified
/// [`Event`] shape, populating `Event::FlowPacket`'s `tcp` /
/// `frame` fields from the pre-extracted enrichment if it was
/// produced this `track()` call.
///
/// Some variants split (`Ended` ←→ `FlowEnded`); `StateChange`
/// is dropped (no equivalent in the new shape — `FlowEstablished`
/// is the only state-transition event the new type ships).
fn map_flow_event_with_details<K, M>(
    ev: FlowEvent<K>,
    tcp: Option<TcpInfo>,
    frame: Option<Vec<u8>>,
) -> Option<Event<K, M>> {
    match ev {
        FlowEvent::Started { key, ts, l4, .. } => Some(Event::FlowStarted { key, ts, l4 }),
        FlowEvent::Established { key, ts, l4 } => {
            Some(Event::FlowEstablished { key, ts, l4 })
        }
        FlowEvent::Packet {
            key,
            side,
            len,
            ts,
        } => Some(Event::FlowPacket {
            key,
            side,
            len,
            ts,
            tcp,
            frame,
        }),
        FlowEvent::Ended {
            key,
            reason,
            stats,
            history,
            l4,
        } => {
            let ts = stats.last_seen;
            Some(Event::FlowEnded {
                key,
                reason,
                stats,
                history,
                l4,
                ts,
            })
        }
        FlowEvent::Tick { key, stats, ts } => Some(Event::FlowTick { key, stats, ts }),
        FlowEvent::FlowAnomaly { key, kind, ts } => Some(Event::FlowAnomaly { key, kind, ts }),
        FlowEvent::TrackerAnomaly { kind, ts } => Some(Event::TrackerAnomaly { kind, ts }),
        // StateChange has no unified-Event analog. Plan 116
        // intentionally drops it; the `FlowEstablished` variant
        // is the only transition the new type surfaces.
        FlowEvent::StateChange { .. } => None,
    }
}
