//! Sync companion to netring's async `session_stream`. Bundles a
//! [`FlowTracker`] + per-(flow, side) [`BufferedReassembler`] + per-
//! flow [`SessionParser`] and yields [`SessionEvent`]s.
//!
//! Use this when you want typed L7 messages from a synchronous loop
//! (offline pcap replay, embedded use, non-tokio CLI tools). The
//! async equivalent lives in
//! `netring::FlowStream::session_stream(parser)`.
//!
//! # Example
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::pcap::PcapFlowSource;
//! use flowscope::{FlowSessionDriver, SessionEvent, SessionParser};
//!
//! #[derive(Default, Clone)]
//! struct EchoParser;
//! impl SessionParser for EchoParser {
//!     type Message = Vec<u8>;
//!     fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
//!         vec![bytes.to_vec()]
//!     }
//!     fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Vec<u8>> {
//!         vec![bytes.to_vec()]
//!     }
//! }
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let mut driver = FlowSessionDriver::<_, EchoParser>::new(FiveTuple::bidirectional());
//! for view in PcapFlowSource::open("trace.pcap")?.views() {
//!     for ev in driver.track(view?.as_view()) {
//!         match ev {
//!             SessionEvent::Application { message, .. } => println!("{} bytes", message.len()),
//!             _ => {}
//!         }
//!     }
//! }
//! # Ok(()) }
//! ```

use std::collections::HashMap;
use std::hash::Hash;

use ahash::RandomState;

use crate::event::{EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::reassembler::{
    BufferedReassembler, BufferedReassemblerFactory, Reassembler, ReassemblerFactory,
};
use crate::session::{SessionEvent, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;
use crate::Timestamp;

/// Sync session-event driver. Owns a tracker, per-(flow, side)
/// reassemblers, and per-flow [`SessionParser`] instances.
///
/// `E` — the flow extractor.
/// `P` — the session parser; the helper requires `Default + Clone`
/// so each new flow gets a fresh per-flow instance via clone.
/// `S` — optional per-flow user state stored on the tracker.
pub struct FlowSessionDriver<E, P, S = ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Default + Clone + Send + 'static,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    factory: BufferedReassemblerFactory,
    reassemblers: HashMap<(E::Key, FlowSide), BufferedReassembler, RandomState>,
    parser_factory: P,
    parsers: HashMap<E::Key, P, RandomState>,
}

impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Default + Clone + Send + 'static,
    S: Default + Send + 'static,
{
    /// Construct with default tracker config and `S::default()`
    /// per-flow state.
    pub fn new(extractor: E) -> Self {
        Self::with_config(extractor, FlowTrackerConfig::default())
    }

    /// Construct with explicit tracker config. Honours
    /// `config.max_reassembler_buffer` and `config.overflow_policy`
    /// when building per-flow reassemblers.
    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self {
        let factory = match config.max_reassembler_buffer {
            Some(cap) => BufferedReassemblerFactory::default()
                .with_max_buffer(cap)
                .with_overflow_policy(config.overflow_policy),
            None => BufferedReassemblerFactory::default(),
        };
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            factory,
            reassemblers: HashMap::with_hasher(RandomState::new()),
            parser_factory: P::default(),
            parsers: HashMap::with_hasher(RandomState::new()),
        }
    }
}

impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Default + Clone + Send + 'static,
    S: Send + 'static,
{
    /// Drive one packet. Returns zero or more [`SessionEvent`]s.
    pub fn track(
        &mut self,
        view: PacketView<'_>,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let factory = &mut self.factory;
        let reassemblers = &mut self.reassemblers;
        let flow_events = self
            .tracker
            .track_with_payload(view, |key, side, seq, payload| {
                let r = reassemblers
                    .entry((key.clone(), side))
                    .or_insert_with(|| factory.new_reassembler(key, side));
                r.segment(seq, payload);
            });
        self.translate_events(flow_events.into_vec())
    }

    /// Run the idle-timeout sweep. Returns any resulting `Closed`
    /// events.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>> {
        let flow_events = self.tracker.sweep(now);
        self.translate_events(flow_events)
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        &self.tracker
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        &mut self.tracker
    }

    /// Map a tick's `FlowEvent`s to `SessionEvent`s, draining
    /// reassemblers and feeding the per-flow parser as we go.
    fn translate_events(
        &mut self,
        flow_events: Vec<FlowEvent<E::Key>>,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut out: Vec<SessionEvent<E::Key, P::Message>> = Vec::new();
        for ev in flow_events {
            match ev {
                FlowEvent::Started { key, ts, .. } => {
                    self.parsers
                        .entry(key.clone())
                        .or_insert_with(|| self.parser_factory.clone());
                    out.push(SessionEvent::Started { key, ts });
                }
                FlowEvent::Packet { key, ts, .. } => {
                    self.drain_into_parser(&key, ts, &mut out);
                }
                FlowEvent::Ended {
                    key,
                    reason,
                    stats,
                    ..
                } => {
                    // Final drain + fin/rst handlers, then close.
                    let ts = stats.last_seen;
                    self.drain_into_parser(&key, ts, &mut out);
                    if let Some(mut parser) = self.parsers.remove(&key) {
                        match reason {
                            EndReason::Fin | EndReason::IdleTimeout => {
                                for m in parser.fin_initiator() {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Initiator,
                                        message: m,
                                        ts,
                                    });
                                }
                                for m in parser.fin_responder() {
                                    out.push(SessionEvent::Application {
                                        key: key.clone(),
                                        side: FlowSide::Responder,
                                        message: m,
                                        ts,
                                    });
                                }
                            }
                            EndReason::Rst
                            | EndReason::Evicted
                            | EndReason::BufferOverflow => {
                                parser.rst_initiator();
                                parser.rst_responder();
                            }
                        }
                    }
                    // Drop both side reassemblers.
                    self.reassemblers.remove(&(key.clone(), FlowSide::Initiator));
                    self.reassemblers.remove(&(key.clone(), FlowSide::Responder));
                    out.push(SessionEvent::Closed { key, reason, stats });
                }
                FlowEvent::Established { .. }
                | FlowEvent::StateChange { .. }
                | FlowEvent::Anomaly { .. } => {
                    // Not surfaced to SessionEvent today. Anomalies could
                    // be added later if there's demand.
                }
            }
        }
        out
    }

    fn drain_into_parser(
        &mut self,
        key: &E::Key,
        ts: Timestamp,
        out: &mut Vec<SessionEvent<E::Key, P::Message>>,
    ) {
        let parser = match self.parsers.get_mut(key) {
            Some(p) => p,
            None => return,
        };
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            let drained = match self.reassemblers.get_mut(&(key.clone(), side)) {
                Some(r) => r.take(),
                None => continue,
            };
            if drained.is_empty() {
                continue;
            }
            let messages = match side {
                FlowSide::Initiator => parser.feed_initiator(&drained),
                FlowSide::Responder => parser.feed_responder(&drained),
            };
            for m in messages {
                out.push(SessionEvent::Application {
                    key: key.clone(),
                    side,
                    message: m,
                    ts,
                });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{FiveTuple, parse::test_frames::ipv4_tcp};

    fn view(frame: &[u8], sec: u32) -> PacketView<'_> {
        PacketView::new(frame, Timestamp::new(sec, 0))
    }

    /// Tiny line-oriented parser: emits one Vec<u8> per newline-terminated frame.
    #[derive(Default, Clone)]
    struct LineParser {
        init: Vec<u8>,
        resp: Vec<u8>,
    }

    impl SessionParser for LineParser {
        type Message = (FlowSide, Vec<u8>);

        fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
            drain(&mut self.init, bytes, FlowSide::Initiator)
        }
        fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
            drain(&mut self.resp, bytes, FlowSide::Responder)
        }
    }

    fn drain(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide) -> Vec<(FlowSide, Vec<u8>)> {
        buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
            let line = buf[..nl].to_vec();
            out.push((side, line));
            buf.drain(..=nl);
        }
        out
    }

    fn build_3whs() -> [Vec<u8>; 3] {
        let mac = [0u8; 6];
        let ip_a = [10, 0, 0, 1];
        let ip_b = [10, 0, 0, 2];
        [
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1000, 0, 0x02, b""),
            ipv4_tcp(mac, mac, ip_b, ip_a, 80, 1234, 5000, 1001, 0x12, b""),
            ipv4_tcp(mac, mac, ip_a, ip_b, 1234, 80, 1001, 5001, 0x10, b""),
        ]
    }

    #[test]
    fn started_event_emitted_on_first_packet() {
        let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
        let frames = build_3whs();
        let mut events = Vec::new();
        for f in &frames {
            events.extend(d.track(view(f, 0)));
        }
        let starts = events
            .iter()
            .filter(|e| matches!(e, SessionEvent::Started { .. }))
            .count();
        assert_eq!(starts, 1);
    }

    #[test]
    fn application_events_for_parsed_messages() {
        let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        // Initiator data — two complete lines.
        let mac = [0u8; 6];
        let data = ipv4_tcp(
            mac, mac,
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 1001, 5001, 0x18,
            b"hello\nworld\n",
        );
        events.extend(d.track(view(&data, 0)));
        let lines: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::Application { side, message: (s, m), .. } => {
                    assert_eq!(s, side);
                    Some(m.clone())
                }
                _ => None,
            })
            .collect();
        assert_eq!(lines, vec![b"hello".to_vec(), b"world".to_vec()]);
    }

    #[test]
    fn closed_event_carries_stats_on_rst() {
        let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let rst = ipv4_tcp(
            mac, mac,
            [10, 0, 0, 1], [10, 0, 0, 2],
            1234, 80, 1001, 5001, 0x04, b"",
        );
        events.extend(d.track(view(&rst, 0)));
        let closed = events
            .into_iter()
            .find(|e| matches!(e, SessionEvent::Closed { .. }))
            .expect("expected Closed");
        match closed {
            SessionEvent::Closed { reason, stats, .. } => {
                assert_eq!(reason, EndReason::Rst);
                // Three packets in 3WHS + one RST.
                assert_eq!(stats.packets_initiator + stats.packets_responder, 4);
            }
            _ => unreachable!(),
        }
    }
}
