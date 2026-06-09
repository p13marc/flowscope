//! Internal slot impls for [`super::typed::Driver`].
//!
//! Each slot owns its inner [`crate::FlowSessionDriver`] /
//! [`crate::FlowDatagramDriver`], a persistent `SessionEvent`
//! scratch buffer (for zero-alloc dispatch), and a
//! `Rc<RefCell<SlotBuf<M, K>>>` that the matching
//! [`super::SlotHandle`] drains. The slot writes typed
//! `SlotMessage<M, K>` into the buf and flow-lifecycle /
//! parser-close events into the caller's `Event<K>` Vec.

use std::cell::RefCell;
use std::hash::Hash;
use std::marker::PhantomData;
use std::rc::Rc;

use crate::PacketView;
use crate::Timestamp;
use crate::datagram_driver::FlowDatagramDriver;
use crate::extractor::FlowExtractor;
use crate::session::{DatagramParser, SessionEvent, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;

use super::slot::{SlotBuf, SlotHandle, SlotMessage};
use super::typed::Event;

/// Type-erased slot trait used by the typed driver. The slot
/// emits flow-lifecycle / parser-close events into the
/// caller's `&mut Vec<Event<K>>`; typed parser messages flow
/// into the slot's private `SlotBuf` via shared `Rc<RefCell>`.
///
/// **Not `Send`** — the typed driver is single-threaded by
/// design. `Rc<RefCell>` over the slot buf is the cheap path;
/// netring's pattern is to drain inside the event loop and
/// post via channels for cross-task delivery.
pub(super) trait ErasedSlot<K> {
    fn track_into(
        &mut self,
        view: PacketView<'_>,
        ts: Timestamp,
        lifecycle_out: &mut Vec<Event<K>>,
    );
    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<K>>);
    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<K>>);
}

/// Concrete session-parser slot.
pub(super) struct TypedConcreteSlot<E, P>
where
    E: FlowExtractor,
    P: SessionParser,
{
    driver: FlowSessionDriver<E, P, ()>,
    parser_kind: &'static str,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
    msg_buf: Rc<RefCell<SlotBuf<P::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, P::Message>>,
}

impl<E, P> TypedConcreteSlot<E, P>
where
    E: FlowExtractor + Clone,
    P: SessionParser + Clone,
{
    pub(super) fn new(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
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
            driver: FlowSessionDriver::with_config(extractor, parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            parser_kind,
            ports,
            msg_buf,
            session_scratch: Vec::new(),
        };
        (slot, handle)
    }
}

impl<E, P> ErasedSlot<E::Key> for TypedConcreteSlot<E, P>
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
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.session_scratch.drain(..) {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.sweep(now) {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.finish() {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }
}

/// Concrete datagram-parser slot.
pub(super) struct TypedConcreteDatagramSlot<E, D>
where
    E: FlowExtractor,
    D: DatagramParser,
{
    driver: FlowDatagramDriver<E, D, ()>,
    parser_kind: &'static str,
    ports: Option<smallvec::SmallVec<[u16; 4]>>,
    msg_buf: Rc<RefCell<SlotBuf<D::Message, E::Key>>>,
    session_scratch: Vec<SessionEvent<E::Key, D::Message>>,
    _marker: PhantomData<D>,
}

impl<E, D> TypedConcreteDatagramSlot<E, D>
where
    E: FlowExtractor + Clone,
    D: DatagramParser + Clone,
{
    pub(super) fn new(
        extractor: E,
        parser: D,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
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
            driver: FlowDatagramDriver::with_config(extractor, parser, config)
                .with_monotonic_timestamps(monotonic_timestamps),
            parser_kind,
            ports,
            msg_buf,
            session_scratch: Vec::new(),
            _marker: PhantomData,
        };
        (slot, handle)
    }
}

impl<E, D> ErasedSlot<E::Key> for TypedConcreteDatagramSlot<E, D>
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
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return;
        }
        let parser_kind = self.parser_kind;
        self.session_scratch.clear();
        self.driver.track_into(view, &mut self.session_scratch);
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.session_scratch.drain(..) {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn sweep_into(&mut self, now: Timestamp, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.sweep(now) {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }

    fn finish_into(&mut self, lifecycle_out: &mut Vec<Event<E::Key>>) {
        let parser_kind = self.parser_kind;
        let mut buf = self.msg_buf.borrow_mut();
        for ev in self.driver.finish() {
            route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
        }
    }
}

/// Dispatch one inner-driver `SessionEvent`:
/// - `Application` → typed message lands in the slot buf.
/// - `Closed` → `ParserClosed` lifecycle event.
/// - `Started` / `FlowTick` / anomalies → suppressed (the
///   central tracker is the source of truth for those at the
///   `Driver<E>` layer; per-slot duplicates would confuse
///   consumers).
fn route_session_event<K, M>(
    ev: SessionEvent<K, M>,
    parser_kind: &'static str,
    buf: &mut SlotBuf<M, K>,
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
            buf.queue.push(SlotMessage {
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
    buf: &mut SlotBuf<M, K>,
    lifecycle_out: &mut Vec<Event<K>>,
) {
    route_session_event(ev, parser_kind, buf, lifecycle_out);
}
