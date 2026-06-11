//! Internal slot impls for [`super::typed::Driver`].
//!
//! Each slot owns its inner [`crate::FlowSessionDriver`] /
//! [`crate::FlowDatagramDriver`], a persistent `SessionEvent`
//! scratch buffer (for zero-alloc dispatch), and an
//! `Arc<SegQueue<SlotMessage<M, K>>>` that the matching
//! [`super::SlotHandle`] drains. The slot writes typed
//! `SlotMessage<M, K>` into the queue and flow-lifecycle /
//! parser-close events into the caller's `Event<K>` Vec.

use std::hash::Hash;
use std::marker::PhantomData;
use std::sync::Arc;

use crossbeam_queue::SegQueue;

use crate::PacketView;
use crate::Timestamp;
use crate::datagram_driver::FlowDatagramDriver;
use crate::extractor::FlowExtractor;
use crate::session::{DatagramParser, SessionEvent, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;

use super::slot::{SlotHandle, SlotMessage};
use super::typed::Event;

/// Type-erased slot trait used by the typed driver. The slot
/// emits flow-lifecycle / parser-close events into the
/// caller's `&mut Vec<Event<K>>`; typed parser messages flow
/// into the slot's private `SegQueue` shared with the
/// [`SlotHandle`] via `Arc`.
///
/// The driver itself remains single-threaded (the central
/// `FlowTracker` is `!Send`); only the **handles** the builder
/// returns are `Send + Sync` for cross-thread drain.
pub(super) trait ErasedSlot<K> {
    fn track_into(
        &mut self,
        view: PacketView<'_>,
        ts: Timestamp,
        lifecycle_out: &mut Vec<Event<K>>,
    );
    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<K>>);
    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<K>>);
    /// Tear down the slot's per-flow state, draining any
    /// buffered bytes through the parser before removal.
    /// Typed messages flushed by the parser's `fin_*` land in
    /// the slot queue; the slot's `ParserClosed` event lands in
    /// `lifecycle_out`. No-op if the slot has no state for the
    /// flow.
    fn force_close_into(&mut self, key: &K, now: Timestamp, lifecycle_out: &mut Vec<Event<K>>);
}

/// Concrete session-parser slot.
pub(super) struct TypedConcreteSlot<E, P>
where
    E: FlowExtractor,
    P: SessionParser + Sync,
    P::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    driver: FlowSessionDriver<E, P, ()>,
    parser_kind: &'static str,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
    msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, P::Message>>,
}

impl<E, P> TypedConcreteSlot<E, P>
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
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
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
            ports,
            monotonic_timestamps,
            msg_buf,
        );
        (slot, handle)
    }

    /// Construct the slot around a pre-allocated queue. Used by
    /// the deferred-builder path: the handle is returned at
    /// registration time (sharing the queue via `Arc::clone`),
    /// the slot is materialised here at `build_with` time.
    pub(super) fn with_queue(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
        monotonic_timestamps: bool,
        msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>>,
    ) -> Self
    where
        E::Key: Send + Sync + 'static,
        P::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowSessionDriver::with_config(extractor, parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            parser_kind,
            ports,
            msg_buf,
            session_scratch: Vec::new(),
        }
    }
}

impl<E, P> ErasedSlot<E::Key> for TypedConcreteSlot<E, P>
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
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        for ev in self.session_scratch.drain(..) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.sweep(now) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.finish() {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn force_close_into(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.force_close(key, now) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }
}

/// Concrete datagram-parser slot.
pub(super) struct TypedConcreteDatagramSlot<E, D>
where
    E: FlowExtractor,
    D: DatagramParser + Sync,
    D::Message: Send + Sync + 'static,
    E::Key: Send + Sync + 'static,
{
    driver: FlowDatagramDriver<E, D, ()>,
    parser_kind: &'static str,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
    msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, D::Message>>,
    _marker: PhantomData<D>,
}

impl<E, D> TypedConcreteDatagramSlot<E, D>
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
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
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
            ports,
            monotonic_timestamps,
            msg_buf,
        );
        (slot, handle)
    }

    pub(super) fn with_queue(
        extractor: E,
        parser: D,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
        monotonic_timestamps: bool,
        msg_buf: Arc<SegQueue<SlotMessage<D::Message, E::Key>>>,
    ) -> Self
    where
        E::Key: Send + Sync + 'static,
        D::Message: Send + Sync + 'static,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowDatagramDriver::with_config(extractor, parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            parser_kind,
            ports,
            msg_buf,
            session_scratch: Vec::new(),
            _marker: PhantomData,
        }
    }
}

impl<E, D> ErasedSlot<E::Key> for TypedConcreteDatagramSlot<E, D>
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
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        for ev in self.session_scratch.drain(..) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.sweep(now) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.finish() {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }

    fn force_close_into(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.force_close(key, now) {
            route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
        }
    }
}

/// Dispatch one inner-driver `SessionEvent`:
/// - `Application` → typed message pushed onto the slot queue.
/// - `Closed` → `ParserClosed` lifecycle event.
/// - `Started` / `FlowTick` / anomalies → suppressed (the
///   central tracker is the source of truth for those at the
///   `Driver<E>` layer; per-slot duplicates would confuse
///   consumers).
fn route_session_event<K, M>(
    ev: SessionEvent<K, M>,
    parser_kind: &'static str,
    buf: &SegQueue<SlotMessage<M, K>>,
    lifecycle_out: &mut Vec<Event<K>>,
) {
    match ev {
        SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind: _,
        } => {
            buf.push(SlotMessage {
                key,
                side,
                message,
                ts,
            });
        }
        SessionEvent::Closed {
            key, reason, stats, ..
        } => {
            lifecycle_out.push(Event::ParserClosed {
                key,
                parser_kind,
                reason,
                ts: stats.last_seen,
            });
        }
        SessionEvent::Started { .. }
        | SessionEvent::FlowAnomaly { .. }
        | SessionEvent::TrackerAnomaly { .. }
        | SessionEvent::FlowTick { .. } => {
            // Suppressed; the central tracker is authoritative.
        }
    }
}

/// Crude port-filter (shared with the legacy slot impls in
/// `erased.rs`).
fn view_matches_ports(view: PacketView<'_>, ports: &[u16]) -> bool {
    use crate::extract::parse::{self, ParsedL4};
    let Some(parsed) = parse::parse_eth(view.frame) else {
        return false;
    };
    let (sport, dport) = match parsed.l4 {
        Some(ParsedL4::Tcp(t)) => (t.src_port, t.dst_port),
        Some(ParsedL4::Udp(u)) => (u.src_port, u.dst_port),
        _ => return false,
    };
    ports.contains(&sport) || ports.contains(&dport)
}

/// Crate-internal re-export used by the heuristic slots (so
/// they don't have to re-implement the routing logic).
pub(super) fn route_session_event_pub<K, M>(
    ev: SessionEvent<K, M>,
    parser_kind: &'static str,
    buf: &SegQueue<SlotMessage<M, K>>,
    lifecycle_out: &mut Vec<Event<K>>,
) {
    route_session_event(ev, parser_kind, buf, lifecycle_out);
}

// ── Broadcast variant — Plan 150 (0.13) ──────────────────────

/// Broadcast-routed session-parser slot. Fan-outs every typed
/// message to every clone of the returned [`super::BroadcastSlotHandle`].
///
/// Used by [`super::DriverBuilder::session_on_ports_broadcast_each`].
pub(super) struct TypedBroadcastSlot<E, P>
where
    E: FlowExtractor,
    P: SessionParser + Sync,
    P::Message: Send + Sync + Clone + 'static,
    E::Key: Send + Sync + Clone + 'static,
{
    driver: FlowSessionDriver<E, P, ()>,
    parser_kind: &'static str,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
    broadcast: std::sync::Arc<super::broadcast::BroadcastInner<P::Message, E::Key>>,
    session_scratch: Vec<SessionEvent<E::Key, P::Message>>,
}

impl<E, P> TypedBroadcastSlot<E, P>
where
    E: FlowExtractor + Clone,
    P: SessionParser + Clone + Sync,
    P::Message: Send + Sync + Clone + 'static,
    E::Key: Send + Sync + Clone + 'static,
{
    pub(super) fn new(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
        monotonic_timestamps: bool,
    ) -> (Self, super::BroadcastSlotHandle<P::Message, E::Key>) {
        let parser_kind = parser.parser_kind();
        let broadcast = super::broadcast::BroadcastInner::new();
        let handle = super::BroadcastSlotHandle::new(std::sync::Arc::clone(&broadcast), parser_kind);
        let driver = FlowSessionDriver::with_config(extractor, parser, config)
            .with_monotonic_timestamps(monotonic_timestamps);
        let slot = Self {
            driver,
            parser_kind,
            ports,
            broadcast,
            session_scratch: Vec::new(),
        };
        (slot, handle)
    }
}

impl<E, P> ErasedSlot<E::Key> for TypedBroadcastSlot<E, P>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Send + Sync + 'static,
    P::Message: Send + Sync + Clone + 'static,
{
    fn track_into(
        &mut self,
        view: PacketView<'_>,
        _ts: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        for ev in self.session_scratch.drain(..) {
            route_broadcast_event(ev, parser_kind, &self.broadcast, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.sweep(now) {
            route_broadcast_event(ev, parser_kind, &self.broadcast, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.finish() {
            route_broadcast_event(ev, parser_kind, &self.broadcast, lifecycle_out);
        }
    }

    fn force_close_into(
        &mut self,
        key: &E::Key,
        now: Timestamp,
        lifecycle_out: &mut Vec<Event<E::Key>>,
    ) {
        let parser_kind = self.parser_kind;
        for ev in self.driver.force_close(key, now) {
            route_broadcast_event(ev, parser_kind, &self.broadcast, lifecycle_out);
        }
    }
}

/// Broadcast-variant route — fans out to every subscriber via
/// `BroadcastInner::push` instead of pushing to a single
/// `SegQueue`.
fn route_broadcast_event<K, M>(
    ev: SessionEvent<K, M>,
    parser_kind: &'static str,
    broadcast: &super::broadcast::BroadcastInner<M, K>,
    lifecycle_out: &mut Vec<Event<K>>,
) where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    match ev {
        SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind: _,
        } => {
            broadcast.push(SlotMessage {
                key,
                side,
                message,
                ts,
            });
        }
        SessionEvent::Closed {
            key, reason, stats, ..
        } => {
            lifecycle_out.push(Event::ParserClosed {
                key,
                parser_kind,
                reason,
                ts: stats.last_seen,
            });
        }
        SessionEvent::Started { .. }
        | SessionEvent::FlowAnomaly { .. }
        | SessionEvent::TrackerAnomaly { .. }
        | SessionEvent::FlowTick { .. } => {
            // Suppressed; the central tracker is authoritative.
        }
    }
}
