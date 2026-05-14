//! Sync companion to netring's async `session_stream`. Wraps a
//! [`FlowDriver`] and adds per-flow [`SessionParser`] dispatch,
//! yielding [`SessionEvent`]s.
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

use crate::Timestamp;
use crate::driver::FlowDriver;
use crate::event::{EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::reassembler::BufferedReassemblerFactory;
use crate::session::{SessionEvent, SessionParser};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

/// Sync session-event driver. Wraps a [`FlowDriver`] with
/// [`BufferedReassemblerFactory`] and adds per-flow
/// [`SessionParser`] dispatch.
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
    driver: FlowDriver<E, BufferedReassemblerFactory, S>,
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
            driver: FlowDriver::with_config(extractor, factory, config),
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
    /// Opt in to forwarding [`SessionEvent::Anomaly`]s through the
    /// stream. Default: `false`. Mirrors
    /// [`FlowDriver::with_emit_anomalies`].
    ///
    /// Anomalies are coalesced per (flow, side, kind) per tick by
    /// the underlying [`FlowDriver`].
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.driver = self.driver.with_emit_anomalies(enable);
        self
    }

    /// Drive one packet. Returns zero or more [`SessionEvent`]s.
    pub fn track(&mut self, view: PacketView<'_>) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut flow_events = self.driver.track_pending(view);
        let out = self.translate_events(&flow_events);
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Run the idle-timeout sweep. Returns any resulting `Closed`
    /// events plus anomalies emitted during the sweep.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut flow_events = self.driver.sweep_pending(now);
        let out = self.translate_events(&flow_events);
        self.driver.finalize(flow_events.as_mut_slice());
        out
    }

    /// Borrow the inner tracker (for stats, introspection).
    pub fn tracker(&self) -> &FlowTracker<E, S> {
        self.driver.tracker()
    }

    /// Borrow the inner tracker mutably.
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> {
        self.driver.tracker_mut()
    }

    /// Map a tick's `FlowEvent`s to `SessionEvent`s, draining
    /// reassembler buffers and feeding the per-flow parser as we go.
    ///
    /// Called between `track_pending` / `sweep_pending` and
    /// `finalize` — reassemblers for ended flows are still
    /// accessible here, so FIN-with-payload bytes are captured.
    fn translate_events(
        &mut self,
        flow_events: &[FlowEvent<E::Key>],
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        let mut out: Vec<SessionEvent<E::Key, P::Message>> = Vec::new();
        for ev in flow_events {
            match ev {
                FlowEvent::Started { key, ts, .. } => {
                    self.parsers
                        .entry(key.clone())
                        .or_insert_with(|| self.parser_factory.clone());
                    out.push(SessionEvent::Started {
                        key: key.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::Packet { key, ts, .. } => {
                    self.drain_into_parser(key, *ts, &mut out);
                }
                FlowEvent::Ended {
                    key,
                    reason,
                    stats,
                    ..
                } => {
                    // Final drain (captures FIN-with-payload bytes
                    // before the reassembler is dropped in finalize),
                    // then call the parser's fin/rst hook.
                    let ts = stats.last_seen;
                    self.drain_into_parser(key, ts, &mut out);
                    if let Some(mut parser) = self.parsers.remove(key) {
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
                            EndReason::Rst | EndReason::Evicted | EndReason::BufferOverflow => {
                                parser.rst_initiator();
                                parser.rst_responder();
                            }
                        }
                    }
                    out.push(SessionEvent::Closed {
                        key: key.clone(),
                        reason: *reason,
                        stats: stats.clone(),
                    });
                }
                FlowEvent::Anomaly { key, kind, ts } => {
                    out.push(SessionEvent::Anomaly {
                        key: key.clone(),
                        kind: kind.clone(),
                        ts: *ts,
                    });
                }
                FlowEvent::Established { .. } | FlowEvent::StateChange { .. } => {
                    // TCP-machine internal transitions; not surfaced
                    // to SessionEvent.
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
            let drained = self.driver.drain_buffer(key, side);
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
    use crate::AnomalyKind;
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
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            b"hello\nworld\n",
        );
        events.extend(d.track(view(&data, 0)));
        let lines: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                SessionEvent::Application {
                    side,
                    message: (s, m),
                    ..
                } => {
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
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x04,
            b"",
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

    #[test]
    fn fin_with_payload_drains_before_close() {
        // FIN packet carries payload — bytes must reach the parser
        // before the Closed event fires (the FlowDriver finalize
        // path drops the reassembler; FlowSessionDriver drains it
        // first via the track_pending -> drain -> finalize split).
        let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let fin_with_data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x19, // FIN + ACK + PSH
            b"goodbye\n",
        );
        events.extend(d.track(view(&fin_with_data, 0)));
        let goodbye = events.iter().find_map(|e| match e {
            SessionEvent::Application {
                message: (_, m), ..
            } if m.as_slice() == b"goodbye" => Some(()),
            _ => None,
        });
        assert!(
            goodbye.is_some(),
            "FIN-with-payload bytes lost; events: {:?}",
            events
                .iter()
                .filter(|e| matches!(e, SessionEvent::Application { .. }))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn anomaly_event_forwarded_when_emit_anomalies_on() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(64),
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::<_, LineParser>::with_config(FiveTuple::bidirectional(), cfg)
                .with_emit_anomalies(true);

        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let big = vec![b'A'; 200];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            &big,
        );
        events.extend(d.track(view(&data, 0)));

        let buffer_overflow = events.iter().find(|e| {
            matches!(
                e,
                SessionEvent::Anomaly {
                    kind: AnomalyKind::BufferOverflow { .. },
                    ..
                }
            )
        });
        assert!(
            buffer_overflow.is_some(),
            "expected a BufferOverflow anomaly forwarded"
        );
    }

    #[test]
    fn no_anomaly_events_by_default() {
        let cfg = FlowTrackerConfig {
            max_reassembler_buffer: Some(64),
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::<_, LineParser>::with_config(FiveTuple::bidirectional(), cfg);
        let mut events = Vec::new();
        for f in build_3whs() {
            events.extend(d.track(view(&f, 0)));
        }
        let mac = [0u8; 6];
        let big = vec![b'A'; 200];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            &big,
        );
        events.extend(d.track(view(&data, 0)));
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, SessionEvent::Anomaly { .. })),
            "expected no anomaly events when emit_anomalies is off"
        );
    }

    #[test]
    fn eviction_pressure_anomaly_has_no_key() {
        let cfg = FlowTrackerConfig {
            max_flows: 2,
            ..FlowTrackerConfig::default()
        };
        let mut d =
            FlowSessionDriver::<_, LineParser>::with_config(FiveTuple::bidirectional(), cfg)
                .with_emit_anomalies(true);
        let mut events = Vec::new();
        for src_port in [1234u16, 1235, 1236] {
            let frame = ipv4_tcp(
                [0; 6],
                [0; 6],
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                src_port,
                80,
                0,
                0,
                0x02,
                b"",
            );
            events.extend(d.track(view(&frame, 0)));
        }
        let pressure = events.iter().find(|e| {
            matches!(
                e,
                SessionEvent::Anomaly {
                    kind: AnomalyKind::FlowTableEvictionPressure { .. },
                    ..
                }
            )
        });
        let pressure = pressure.expect("expected an eviction-pressure anomaly");
        match pressure {
            SessionEvent::Anomaly {
                key,
                kind:
                    AnomalyKind::FlowTableEvictionPressure {
                        evicted_in_tick, ..
                    },
                ..
            } => {
                assert!(key.is_none());
                assert_eq!(*evicted_in_tick, 1);
            }
            _ => unreachable!(),
        }
    }
}
