//! Parser stubs intended for downstream test crates that need a
//! `SessionParser` / `DatagramParser` impl but don't care about
//! the produced messages.
//!
//! Gated behind the `test-helpers` Cargo feature (alongside
//! `extract::parse::test_frames`). Not for production use.
//!
//! Future trait-shape evolution (new defaulted methods, signature
//! tweaks) absorbs into these stubs once instead of forcing every
//! downstream test crate to update its own copy.

use crate::{DatagramParser, FlowSide, SessionParser, Timestamp};

/// A `SessionParser` that produces no messages. Use when test code
/// needs to exercise the driver / stream wiring without caring
/// about parsed output.
#[derive(Debug, Default, Clone)]
pub struct NoopSessionParser;

impl SessionParser for NoopSessionParser {
    type Message = ();
    fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
    fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
}

/// A `DatagramParser` that produces no messages. Mirror of
/// [`NoopSessionParser`].
#[derive(Debug, Default, Clone)]
pub struct NoopDatagramParser;

impl DatagramParser for NoopDatagramParser {
    type Message = ();
    fn parse(&mut self, _payload: &[u8], _side: FlowSide, _ts: Timestamp, _out: &mut Vec<()>) {}
}

/// A `SessionParser` that echoes each fed chunk as a side-tagged
/// `Vec<u8>` message. Use when test code wants to inspect the
/// reassembled byte stream.
#[derive(Debug, Default, Clone)]
pub struct EchoSessionParser;

impl SessionParser for EchoSessionParser {
    type Message = (FlowSide, Vec<u8>);
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push((FlowSide::Initiator, bytes.to_vec()));
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        out.push((FlowSide::Responder, bytes.to_vec()));
    }
}

/// A `SessionParser` that emits one empty message on the first
/// `feed_initiator` call and reports `is_done() == true`
/// thereafter. Use for testing the plan-80
/// [`crate::SessionParser::is_done`] /
/// [`crate::EndReason::ParserDone`] wiring.
#[derive(Debug, Default, Clone)]
pub struct OneShotSessionParser {
    done: bool,
}

impl SessionParser for OneShotSessionParser {
    type Message = ();
    fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp, out: &mut Vec<()>) {
        self.done = true;
        out.push(());
    }
    fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
    fn is_done(&self) -> bool {
        self.done
    }
    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Other("one-shot-session")
    }
}

/// Datagram mirror of [`OneShotSessionParser`].
#[derive(Debug, Default, Clone)]
pub struct OneShotDatagramParser {
    done: bool,
}

impl DatagramParser for OneShotDatagramParser {
    type Message = ();
    fn parse(&mut self, _payload: &[u8], _side: FlowSide, _ts: Timestamp, out: &mut Vec<()>) {
        self.done = true;
        out.push(());
    }
    fn is_done(&self) -> bool {
        self.done
    }
    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Other("one-shot-datagram")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_session_compiles() {
        let mut p = NoopSessionParser;
        let mut out = Vec::new();
        p.feed_initiator(b"hi", Timestamp::default(), &mut out);
        assert!(out.is_empty());
        p.feed_responder(b"hi", Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn noop_datagram_compiles() {
        let mut p = NoopDatagramParser;
        let mut out = Vec::new();
        p.parse(b"hi", FlowSide::Initiator, Timestamp::default(), &mut out);
        assert!(out.is_empty());
    }

    #[test]
    fn echo_session_emits_chunks() {
        let mut p = EchoSessionParser;
        let mut m = Vec::new();
        p.feed_initiator(b"hello", Timestamp::default(), &mut m);
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, FlowSide::Initiator);
        assert_eq!(m[0].1, b"hello");
    }
}

// ── Plan 153 (0.13) — synthetic event constructors ────────────

/// Synthetic event constructors for downstream test crates.
///
/// Each function takes minimal-required fields; the rest are
/// filled with sensible defaults (`Default::default()` for
/// `FlowStats`, `None` for optional `L4Proto`, `Initiator` for
/// `FlowSide`). Saves the `#[doc(hidden)] pub fn new` escape
/// hatch dance — downstream tests can write
/// `events::started(key, ts)` instead of multi-line field-init.
///
/// Plan 153 (0.13).
pub mod events {
    use crate::{
        Timestamp,
        event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats},
        extractor::{L4Proto, Orientation},
    };

    /// `FlowEvent::Started` with `l4 = None`, `Initiator` side and
    /// `Forward` orientation.
    pub fn started<K>(key: K, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::Started {
            key,
            side: FlowSide::Initiator,
            orientation: Orientation::Forward,
            ts,
            l4: None,
        }
    }

    /// `FlowEvent::Started` with explicit L4.
    pub fn started_with_l4<K>(key: K, l4: L4Proto, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::Started {
            key,
            side: FlowSide::Initiator,
            orientation: Orientation::Forward,
            ts,
            l4: Some(l4),
        }
    }

    /// `FlowEvent::Established` with `l4 = None`.
    pub fn established<K>(key: K, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::Established { key, ts, l4: None }
    }

    /// `FlowEvent::Ended` with `EndReason::IdleTimeout` and
    /// empty stats. `last_seen` set to `ts`.
    pub fn ended<K>(key: K, ts: Timestamp) -> FlowEvent<K> {
        let stats = FlowStats {
            last_seen: ts,
            ..FlowStats::default()
        };
        FlowEvent::Ended {
            key,
            reason: EndReason::IdleTimeout,
            stats,
            history: Default::default(),
            l4: None,
        }
    }

    /// `FlowEvent::Ended` with caller-supplied reason + stats.
    pub fn ended_with<K>(key: K, reason: EndReason, stats: FlowStats) -> FlowEvent<K> {
        FlowEvent::Ended {
            key,
            reason,
            stats,
            history: Default::default(),
            l4: None,
        }
    }

    /// `FlowEvent::Tick` with empty stats.
    pub fn tick<K>(key: K, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::Tick {
            key,
            stats: FlowStats::default(),
            ts,
        }
    }

    /// `FlowEvent::FlowAnomaly`.
    pub fn flow_anomaly<K>(key: K, kind: AnomalyKind, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::FlowAnomaly { key, kind, ts }
    }

    /// `FlowEvent::TrackerAnomaly`.
    pub fn tracker_anomaly<K>(kind: AnomalyKind, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::TrackerAnomaly { kind, ts }
    }

    /// `FlowEvent::Packet` with default `Initiator` side / `Forward`
    /// orientation.
    pub fn packet<K>(key: K, len: usize, ts: Timestamp) -> FlowEvent<K> {
        FlowEvent::Packet {
            key,
            side: FlowSide::Initiator,
            orientation: Orientation::Forward,
            len,
            ts,
        }
    }

    /// `FlowEvent::Packet` with explicit side. Orientation is derived
    /// to be self-consistent (`Initiator` → `Forward`,
    /// `Responder` → `Reverse`).
    pub fn packet_side<K>(key: K, side: FlowSide, len: usize, ts: Timestamp) -> FlowEvent<K> {
        let orientation = match side {
            FlowSide::Initiator => Orientation::Forward,
            FlowSide::Responder => Orientation::Reverse,
        };
        FlowEvent::Packet {
            key,
            side,
            orientation,
            len,
            ts,
        }
    }

    /// Typed `driver::Event<K>` constructors.
    #[cfg(all(feature = "extractors", feature = "reassembler", feature = "session"))]
    pub mod driver {
        use crate::{
            Timestamp,
            driver::Event,
            event::{AnomalyKind, EndReason, FlowSide, FlowStats},
            extractor::{L4Proto, Orientation, TcpInfo},
        };

        /// `Event::Started` with `l4 = None` and `Forward` orientation.
        pub fn flow_started<K>(key: K, ts: Timestamp) -> Event<K> {
            Event::Started {
                key,
                orientation: Orientation::Forward,
                ts,
                l4: None,
            }
        }

        /// `Event::Started` with explicit L4.
        pub fn flow_started_with_l4<K>(key: K, l4: L4Proto, ts: Timestamp) -> Event<K> {
            Event::Started {
                key,
                orientation: Orientation::Forward,
                ts,
                l4: Some(l4),
            }
        }

        /// `Event::Established` with `l4 = None`.
        pub fn flow_established<K>(key: K, ts: Timestamp) -> Event<K> {
            Event::Established { key, ts, l4: None }
        }

        /// `Event::Ended` with `EndReason::IdleTimeout` and
        /// empty stats.
        pub fn flow_ended<K>(key: K, ts: Timestamp) -> Event<K> {
            Event::Ended {
                key,
                reason: EndReason::IdleTimeout,
                stats: FlowStats::default(),
                history: Default::default(),
                l4: None,
                ts,
            }
        }

        /// `Event::Packet` with `Initiator` side / `Forward`
        /// orientation and no tcp info.
        pub fn flow_packet<K>(key: K, len: usize, ts: Timestamp) -> Event<K> {
            Event::Packet {
                key,
                side: FlowSide::Initiator,
                orientation: Orientation::Forward,
                len,
                ts,
                tcp: None,
            }
        }

        /// `Event::Packet` with explicit fields. Orientation is
        /// derived to be self-consistent with `side` (`Initiator` →
        /// `Forward`, `Responder` → `Reverse`).
        pub fn flow_packet_full<K>(
            key: K,
            side: FlowSide,
            len: usize,
            tcp: Option<TcpInfo>,
            ts: Timestamp,
        ) -> Event<K> {
            let orientation = match side {
                FlowSide::Initiator => Orientation::Forward,
                FlowSide::Responder => Orientation::Reverse,
            };
            Event::Packet {
                key,
                side,
                orientation,
                len,
                ts,
                tcp,
            }
        }

        /// `Event::Tick`.
        pub fn flow_tick<K>(key: K, ts: Timestamp) -> Event<K> {
            Event::Tick {
                key,
                stats: FlowStats::default(),
                ts,
            }
        }

        /// `Event::ParserClosed` with `EndReason::ParserDone`.
        pub fn parser_closed<K>(key: K, parser_kind: crate::ParserKind, ts: Timestamp) -> Event<K> {
            Event::ParserClosed {
                key,
                parser_kind,
                reason: EndReason::ParserDone,
                ts,
            }
        }

        /// `Event::FlowAnomaly`.
        pub fn flow_anomaly<K>(key: K, kind: AnomalyKind, ts: Timestamp) -> Event<K> {
            Event::FlowAnomaly { key, kind, ts }
        }

        /// `Event::TrackerAnomaly`.
        pub fn tracker_anomaly<K>(kind: AnomalyKind, ts: Timestamp) -> Event<K> {
            Event::TrackerAnomaly { kind, ts }
        }
    }
}
