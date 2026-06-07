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

pub use event::Event;

use std::hash::Hash;
use std::marker::PhantomData;

use crate::PacketView;
use crate::Timestamp;
use crate::event::FlowEvent;
use crate::extractor::FlowExtractor;
use crate::session::SessionParser;
use crate::tracker::{FlowTracker, FlowTrackerConfig};

use erased::{ConcreteSlot, DriverSlot};

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

        // Central tracker emits flow-lifecycle events.
        for flow_ev in self.tracker.track(view).into_iter() {
            out.extend(map_flow_event::<E::Key, M>(flow_ev));
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
            out.extend(map_flow_event::<E::Key, M>(flow_ev));
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
            out.extend(map_flow_event::<E::Key, M>(flow_ev));
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
            lift,
        );
        self.slots.push(Box::new(slot));
        self
    }

    /// Finalize the builder.
    pub fn build(self) -> Driver<E, M> {
        Driver {
            tracker: FlowTracker::with_config(self.extractor, self.config),
            slots: self.slots,
            _marker: PhantomData,
        }
    }
}

/// Adapt a tracker-emitted [`FlowEvent`] into the unified
/// [`Event`] shape. Some variants split (`Ended` ←→ `FlowEnded`);
/// `StateChange` is dropped (no equivalent in the new shape —
/// `FlowEstablished` is the only state-transition event the new
/// type ships).
fn map_flow_event<K, M>(ev: FlowEvent<K>) -> Option<Event<K, M>> {
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
