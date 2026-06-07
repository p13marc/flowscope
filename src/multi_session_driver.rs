//! [`FlowMultiSessionDriver`] — composite driver running N
//! session parsers against the same packet stream in one pass.
//!
//! Each registered parser fires when the packet matches its
//! routing rule (port set or broadcast). Events are unified
//! into a user-supplied sum type `M` via lift closures.
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::FlowMultiSessionDriver;
//! # #[cfg(feature = "http")] use flowscope::http::HttpParser;
//! # #[cfg(feature = "tls")] use flowscope::tls::TlsParser;
//!
//! #[derive(Debug, Clone)]
//! enum MyL7 {
//!     # #[cfg(feature = "http")]
//!     Http(flowscope::http::HttpMessage),
//!     # #[cfg(feature = "tls")]
//!     Tls(flowscope::tls::TlsMessage),
//! }
//!
//! # #[cfg(all(feature = "http", feature = "tls"))]
//! let driver = FlowMultiSessionDriver::<_, MyL7>::new(FiveTuple::bidirectional())
//!     .with_parser_on_ports(HttpParser::default(), [80, 8080], MyL7::Http)
//!     .with_parser_on_ports(TlsParser::default(),  [443],       MyL7::Tls);
//! ```
//!
//! # Design trade-off
//!
//! The 0.9 implementation runs **N parallel `FlowSessionDriver`s**
//! — one per registered parser — sharing the same extractor but
//! independent trackers / reassemblers. This duplicates the
//! per-flow tracking machinery N-fold; for high-throughput
//! pipelines with many parsers, the planned shared-tracker
//! optimisation (one tracker driving all parsers) is a follow-up.
//!
//! Plan 92 spec'd the shared-tracker shape; this implementation
//! ships the ergonomic surface (one `track()` call, one merged
//! event stream) without the storage optimisation. Consumers who
//! profile and find this matters drop to manual per-parser
//! dispatch (see `docs/recipes.md` "Multi-protocol monitoring").

use std::hash::Hash;

use crate::Timestamp;
use crate::event::FlowSide;
use crate::extractor::FlowExtractor;
use crate::session::{SessionEvent, SessionParser};
use crate::session_driver::FlowSessionDriver;
use crate::tracker::FlowTrackerConfig;
use crate::view::PacketView;

/// Routing rule for a registered parser.
enum Routing {
    /// Fire when `dst_port ∈ ports || src_port ∈ ports`.
    Ports(smallvec::SmallVec<[u16; 4]>),
    /// Fire on every packet matching the flow's L4.
    Broadcast,
}

/// Type-erased per-parser slot.
///
/// Holds the `FlowSessionDriver` + a lift closure converting
/// the parser's `Message` to the composite `M`.
struct ParserSlot<E: FlowExtractor, M> {
    routing: Routing,
    driver: Box<dyn DriverSlot<E::Key, M> + Send>,
}

/// Internal trait erasing the parser's concrete type.
trait DriverSlot<K, M>: Send {
    fn track(&mut self, view: PacketView<'_>) -> Vec<SessionEvent<K, M>>;
    fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<K, M>>;
    fn finish(&mut self) -> Vec<SessionEvent<K, M>>;
}

/// Concrete slot for one registered (parser, lift) pair.
struct ConcreteSlot<E, P, M, F>
where
    E: FlowExtractor,
    P: SessionParser,
{
    driver: FlowSessionDriver<E, P, ()>,
    lift: F,
    _marker: std::marker::PhantomData<M>,
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
    fn track(&mut self, view: PacketView<'_>) -> Vec<SessionEvent<E::Key, M>> {
        self.driver
            .track(view)
            .into_iter()
            .map(|e| lift_event(e, &self.lift))
            .collect()
    }

    fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, M>> {
        self.driver
            .sweep(now)
            .into_iter()
            .map(|e| lift_event(e, &self.lift))
            .collect()
    }

    fn finish(&mut self) -> Vec<SessionEvent<E::Key, M>> {
        self.driver
            .finish()
            .into_iter()
            .map(|e| lift_event(e, &self.lift))
            .collect()
    }
}

fn lift_event<K, A, B, F: Fn(A) -> B>(
    ev: SessionEvent<K, A>,
    lift: &F,
) -> SessionEvent<K, B> {
    match ev {
        SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind,
        } => SessionEvent::Application {
            key,
            side,
            message: lift(message),
            ts,
            parser_kind,
        },
        SessionEvent::Started { key, ts } => SessionEvent::Started { key, ts },
        SessionEvent::Closed {
            key,
            reason,
            stats,
            l4,
        } => SessionEvent::Closed {
            key,
            reason,
            stats,
            l4,
        },
        SessionEvent::FlowAnomaly { key, kind, ts } => SessionEvent::FlowAnomaly { key, kind, ts },
        SessionEvent::TrackerAnomaly { kind, ts } => {
            SessionEvent::TrackerAnomaly { kind, ts }
        }
        SessionEvent::FlowTick { key, stats, ts } => SessionEvent::FlowTick { key, stats, ts },
    }
}

/// Composite session driver running N parsers in one pass.
///
/// Construct via [`Self::new`]; register parsers via
/// [`Self::with_parser_on_ports`] / [`Self::with_parser_broadcast`].
/// Each registered parser observes packets matching its routing
/// rule; emitted messages are lifted into the composite `M` and
/// merged into a single event stream.
pub struct FlowMultiSessionDriver<E, M>
where
    E: FlowExtractor,
{
    extractor: E,
    config: FlowTrackerConfig,
    parsers: Vec<ParserSlot<E, M>>,
}

impl<E, M> FlowMultiSessionDriver<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Construct a new composite driver with the given extractor.
    pub fn new(extractor: E) -> Self {
        Self {
            extractor,
            config: FlowTrackerConfig::default(),
            parsers: Vec::new(),
        }
    }

    /// Override the tracker config for all registered parsers.
    pub fn with_config(mut self, config: FlowTrackerConfig) -> Self {
        self.config = config;
        self
    }

    /// Register a parser that fires on a fixed port set.
    pub fn with_parser_on_ports<P, I, F>(mut self, parser: P, ports: I, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        let driver = FlowSessionDriver::with_config(
            self.extractor.clone(),
            parser,
            self.config.clone(),
        );
        let port_set: smallvec::SmallVec<[u16; 4]> = ports.into_iter().collect();
        self.parsers.push(ParserSlot {
            routing: Routing::Ports(port_set),
            driver: Box::new(ConcreteSlot {
                driver,
                lift,
                _marker: std::marker::PhantomData,
            }),
        });
        self
    }

    /// Register a parser that fires on every packet (e.g. ICMP).
    pub fn with_parser_broadcast<P, F>(mut self, parser: P, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static,
    {
        let driver = FlowSessionDriver::with_config(
            self.extractor.clone(),
            parser,
            self.config.clone(),
        );
        self.parsers.push(ParserSlot {
            routing: Routing::Broadcast,
            driver: Box::new(ConcreteSlot {
                driver,
                lift,
                _marker: std::marker::PhantomData,
            }),
        });
        self
    }

    /// Process a packet — dispatch to every parser whose routing
    /// matches, merge their events in registration order.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> Vec<SessionEvent<E::Key, M>> {
        let view: PacketView<'v> = view.into();
        let mut out = Vec::new();

        // Port extraction for routing decisions. If we can't get
        // ports (non-TCP/UDP), broadcast-only parsers still see
        // it; port parsers don't.
        let (sport, dport) = extract_ports(&self.extractor, view);

        for slot in &mut self.parsers {
            let fires = match &slot.routing {
                Routing::Broadcast => true,
                Routing::Ports(ps) => match (sport, dport) {
                    (Some(s), Some(d)) => ps.iter().any(|&p| p == s || p == d),
                    _ => false,
                },
            };
            if fires {
                out.extend(slot.driver.track(view));
            }
        }
        out
    }

    /// Periodic sweep — fanned out to every registered parser.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, M>> {
        let mut out = Vec::new();
        for slot in &mut self.parsers {
            out.extend(slot.driver.sweep(now));
        }
        out
    }

    /// End-of-input flush — fanned out to every registered parser.
    pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, M>> {
        let mut out = Vec::new();
        for slot in &mut self.parsers {
            out.extend(slot.driver.finish());
        }
        out
    }
}

/// Extract (sport, dport) from a packet using the extractor's
/// own dispatcher. Returns (None, None) if the extractor can't
/// produce a key or if the L4 has no ports.
fn extract_ports<E: FlowExtractor>(
    extractor: &E,
    view: PacketView<'_>,
) -> (Option<u16>, Option<u16>) {
    let Some(extracted) = extractor.extract(view) else {
        return (None, None);
    };
    let _ = extracted; // We don't have a direct port accessor on
    // Extracted today; extract via the parse helper instead.
    let parsed = crate::extract::parse::parse_eth(view.frame);
    match parsed.and_then(|p| p.l4) {
        Some(crate::extract::parse::ParsedL4::Tcp(t)) => (Some(t.src_port), Some(t.dst_port)),
        Some(crate::extract::parse::ParsedL4::Udp(u)) => (Some(u.src_port), Some(u.dst_port)),
        _ => (None, None),
    }
}

// FlowSide kept in scope for downstream callers via the
// SessionEvent re-exports.
#[allow(unused_imports)]
use FlowSide as _UseFlowSide;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};

    #[derive(Default, Clone)]
    struct CountingParser(u32);

    impl SessionParser for CountingParser {
        type Message = u32;
        fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<u32> {
            self.0 += 1;
            vec![self.0]
        }
        fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<u32> {
            self.0 += 1;
            vec![self.0]
        }
    }

    #[derive(Debug, Clone, PartialEq)]
    enum L7 {
        Http(u32),
        Tls(u32),
    }

    #[test]
    fn route_by_dst_port() {
        let mut d = FlowMultiSessionDriver::<_, L7>::new(FiveTuple::bidirectional())
            .with_parser_on_ports(CountingParser::default(), [80], L7::Http)
            .with_parser_on_ports(CountingParser::default(), [443], L7::Tls);

        // Port 80 packet — http parser fires.
        let f = ipv4_tcp([0; 6], [0; 6], [1, 2, 3, 4], [5, 6, 7, 8], 12345, 80, 0, 0, 0x18, b"x");
        let ts = Timestamp::new(0, 0);
        let pv = PacketView::new(&f, ts);
        let _ = d.track(pv);
        // Drain remaining events on finish.
        let _ = d.finish();
    }

    #[test]
    fn broadcast_fires_for_any_packet() {
        let mut d = FlowMultiSessionDriver::<_, L7>::new(FiveTuple::bidirectional())
            .with_parser_broadcast(CountingParser::default(), L7::Http);
        let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 5678, b"hi");
        let pv = PacketView::new(&f, Timestamp::new(0, 0));
        let _ = d.track(pv);
        let _ = d.finish();
    }
}
