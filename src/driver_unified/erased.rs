//! Type-erased session-parser slots for the unified
//! [`super::Driver`].
//!
//! A [`Driver<E, M>`](super::Driver) registers N parsers, each
//! producing a per-parser `Message` type. The composite `M` is
//! the union; per-parser lifting closures map each
//! `P::Message → M`. To store the slots heterogeneously, we
//! erase the parser type behind a `dyn DriverSlot<K, M>` trait.

use std::hash::Hash;
use std::marker::PhantomData;

use crate::PacketView;
use crate::Timestamp;
use crate::datagram_driver::FlowDatagramDriver;
use crate::extractor::FlowExtractor;
use crate::session::{DatagramParser, SessionEvent, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;

use super::Event;

/// One erased slot in the [`super::Driver`]'s session-parser
/// stack. Hides the per-parser concrete type behind a `dyn`
/// boundary so the driver can hold a heterogeneous `Vec`.
pub(super) trait DriverSlot<K, M>: Send {
    fn track(&mut self, view: PacketView<'_>, ts: Timestamp) -> Vec<Event<K, M>>;
    fn sweep(&mut self, now: Timestamp) -> Vec<Event<K, M>>;
    fn finish(&mut self) -> Vec<Event<K, M>>;
}

/// Concrete slot wrapping one `FlowSessionDriver<E, P, ()>` +
/// a lift closure. The trait impl below converts the per-parser
/// `SessionEvent<E::Key, P::Message>` stream into the unified
/// [`Event<E::Key, M>`] stream.
pub(super) struct ConcreteSlot<E, P, M, F>
where
    E: FlowExtractor,
    P: SessionParser,
{
    pub(super) driver: FlowSessionDriver<E, P, ()>,
    pub(super) lift: F,
    pub(super) parser_kind: &'static str,
    /// Optional port filter. `None` = broadcast (every packet).
    /// `Some(set)` = the parser fires only when src or dst port
    /// is in the set.
    pub(super) ports: Option<smallvec::SmallVec<[u16; 4]>>,
    pub(super) _marker: PhantomData<M>,
}

impl<E, P, M, F> ConcreteSlot<E, P, M, F>
where
    E: FlowExtractor,
    P: SessionParser + Clone,
{
    pub(super) fn new(
        extractor: E,
        parser: P,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
        lift: F,
    ) -> Self
    where
        E: Clone,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowSessionDriver::with_config(extractor, parser, config),
            lift,
            parser_kind,
            ports,
            _marker: PhantomData,
        }
    }
}

impl<E, P, M, F> DriverSlot<E::Key, M> for ConcreteSlot<E, P, M, F>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Send + 'static,
    P::Message: Send + 'static,
    F: Fn(P::Message) -> M + Send + 'static,
    M: Send + 'static,
{
    fn track(&mut self, view: PacketView<'_>, ts: Timestamp) -> Vec<Event<E::Key, M>> {
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return Vec::new();
        }
        let parser_kind = self.parser_kind;
        self.driver
            .track(view)
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, ts, parser_kind))
            .collect()
    }

    fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key, M>> {
        let parser_kind = self.parser_kind;
        self.driver
            .sweep(now)
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, now, parser_kind))
            .collect()
    }

    fn finish(&mut self) -> Vec<Event<E::Key, M>> {
        let parser_kind = self.parser_kind;
        self.driver
            .finish()
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, Timestamp::MAX, parser_kind))
            .collect()
    }
}

/// Concrete datagram slot wrapping one
/// `FlowDatagramDriver<E, D, ()>` + a lift closure. UDP
/// equivalent of [`ConcreteSlot`].
pub(super) struct ConcreteDatagramSlot<E, D, M, F>
where
    E: FlowExtractor,
    D: DatagramParser,
{
    pub(super) driver: FlowDatagramDriver<E, D, ()>,
    pub(super) lift: F,
    pub(super) parser_kind: &'static str,
    pub(super) ports: Option<smallvec::SmallVec<[u16; 4]>>,
    pub(super) _marker: PhantomData<M>,
}

impl<E, D, M, F> ConcreteDatagramSlot<E, D, M, F>
where
    E: FlowExtractor,
    D: DatagramParser + Clone,
{
    pub(super) fn new(
        extractor: E,
        parser: D,
        config: FlowTrackerConfig,
        ports: Option<smallvec::SmallVec<[u16; 4]>>,
        lift: F,
    ) -> Self
    where
        E: Clone,
    {
        let parser_kind = parser.parser_kind();
        Self {
            driver: FlowDatagramDriver::with_config(extractor, parser, config),
            lift,
            parser_kind,
            ports,
            _marker: PhantomData,
        }
    }
}

impl<E, D, M, F> DriverSlot<E::Key, M> for ConcreteDatagramSlot<E, D, M, F>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
    D: DatagramParser + Send + 'static,
    D::Message: Send + 'static,
    F: Fn(D::Message) -> M + Send + 'static,
    M: Send + 'static,
{
    fn track(&mut self, view: PacketView<'_>, ts: Timestamp) -> Vec<Event<E::Key, M>> {
        if let Some(ports) = &self.ports
            && !view_matches_ports(view, ports)
        {
            return Vec::new();
        }
        let parser_kind = self.parser_kind;
        self.driver
            .track(view)
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, ts, parser_kind))
            .collect()
    }

    fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key, M>> {
        let parser_kind = self.parser_kind;
        self.driver
            .sweep(now)
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, now, parser_kind))
            .collect()
    }

    fn finish(&mut self) -> Vec<Event<E::Key, M>> {
        let parser_kind = self.parser_kind;
        self.driver
            .finish()
            .into_iter()
            .filter_map(|e| lift_event(e, &self.lift, Timestamp::MAX, parser_kind))
            .collect()
    }
}

/// Crude port-filter: parses just enough of the frame to extract
/// the L4 src/dst ports. Returns `false` if the frame can't be
/// parsed — non-matching frames are silently dropped.
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

/// Public-to-the-driver_unified-module wrapper around
/// [`lift_event`], for slot impls in sibling files
/// (`heuristic.rs`).
pub(super) fn lift_event_pub<K, A, B, F>(
    ev: SessionEvent<K, A>,
    lift: &F,
    fallback_ts: Timestamp,
    slot_kind: &'static str,
) -> Option<Event<K, B>>
where
    F: Fn(A) -> B,
{
    lift_event(ev, lift, fallback_ts, slot_kind)
}

/// Map one [`SessionEvent<K, A>`] into the slot-emitted subset
/// of [`Event<K, B>`].
///
/// Slots in the unified `Driver` only emit parser-sourced
/// variants ([`Event::Message`] and [`Event::ParserClosed`]).
/// Flow lifecycle ([`Event::FlowStarted`] etc.) comes from the
/// `Driver`'s own central tracker — slots filter out
/// `SessionEvent::Started` / `FlowAnomaly` / `TrackerAnomaly` /
/// `FlowTick` to avoid duplicates.
fn lift_event<K, A, B, F>(
    ev: SessionEvent<K, A>,
    lift: &F,
    fallback_ts: Timestamp,
    slot_kind: &'static str,
) -> Option<Event<K, B>>
where
    F: Fn(A) -> B,
{
    match ev {
        SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } => Some(Event::Message {
            key,
            side,
            message: lift(message),
            ts,
            parser_kind,
        }),
        SessionEvent::Closed {
            key,
            reason,
            stats,
            l4: _,
        } => Some(Event::ParserClosed {
            key,
            parser_kind: slot_kind,
            reason,
            ts: if stats.last_seen == Timestamp::default() {
                fallback_ts
            } else {
                stats.last_seen
            },
        }),
        // Suppress: the central Driver tracker is authoritative
        // for flow lifecycle. Slot-side duplicates would confuse
        // consumers.
        SessionEvent::Started { .. }
        | SessionEvent::FlowAnomaly { .. }
        | SessionEvent::TrackerAnomaly { .. }
        | SessionEvent::FlowTick { .. } => None,
    }
}
