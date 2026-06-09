//! Plan 116 PR 3 — unified `flowscope::driver_unified::Pipeline`
//! wrapper around `Driver<E, M>`.

#![cfg(all(feature = "test-helpers", feature = "extractors", feature = "session"))]

use flowscope::driver_unified::{Event, Pipeline};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::{DatagramParser, FlowSide, OwnedPacketView, SessionParser, Timestamp};

#[derive(Default, Clone)]
struct CountParser;

impl SessionParser for CountParser {
    type Message = (FlowSide, usize);

    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push((FlowSide::Initiator, b.len()));
        }
    }

    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push((FlowSide::Responder, b.len()));
        }
    }

    fn parser_kind(&self) -> &'static str {
        "count"
    }
}

#[derive(Default, Clone)]
struct UdpEcho;

impl DatagramParser for UdpEcho {
    type Message = usize;
    fn parse(&mut self, b: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<usize>) {
        if !b.is_empty() {
            out.push(b.len());
        }
    }
    fn parser_kind(&self) -> &'static str {
        "udp"
    }
}

#[derive(Debug, Clone)]
enum Msg {
    Tcp(FlowSide, usize),
    Udp(usize),
}

impl Msg {
    /// Force a read of every variant field so they aren't
    /// flagged dead by the compiler.
    fn payload_len(&self) -> usize {
        match self {
            Msg::Tcp(side, n) => {
                debug_assert!(matches!(side, FlowSide::Initiator | FlowSide::Responder));
                *n
            }
            Msg::Udp(n) => *n,
        }
    }
}

fn owned_view(frame: Vec<u8>, sec: u32) -> OwnedPacketView {
    OwnedPacketView {
        frame,
        timestamp: Timestamp::new(sec, 0),
    }
}

#[test]
fn pipeline_builder_compiles_and_no_op_yields_nothing() {
    let mut p = Pipeline::<_, Msg>::builder(FiveTuple::bidirectional()).build();
    let events: Vec<_> = p.run_iter(std::iter::empty()).collect();
    assert!(events.is_empty());
}

#[test]
fn pipeline_run_iter_dispatches_to_session_and_datagram() {
    let mut p = Pipeline::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser, |(s, n)| Msg::Tcp(s, n))
        .datagram_broadcast(UdpEcho, Msg::Udp)
        .build();

    let tcp = owned_view(
        ipv4_tcp(
            [1; 6],
            [2; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            33000,
            80,
            0,
            0,
            0x18,
            b"hi",
        ),
        0,
    );
    let udp = owned_view(ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 5353, 53, b"yo"), 1);

    let events: Vec<_> = p
        .run_iter(vec![tcp, udp])
        .collect::<flowscope::Result<Vec<_>>>()
        .unwrap();

    let tcp_msgs = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::Message {
                    message: Msg::Tcp(..),
                    ..
                }
            )
        })
        .count();
    let udp_msgs = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::Message {
                    message: Msg::Udp(_),
                    ..
                }
            )
        })
        .count();
    let flow_started = events
        .iter()
        .filter(|e| matches!(e, Event::FlowStarted { .. }))
        .count();
    assert!(tcp_msgs > 0, "no TCP messages emitted");
    assert!(udp_msgs > 0, "no UDP messages emitted");
    assert!(flow_started >= 2, "expected ≥2 FlowStarted (one per flow)");
    // Read the inner payload through payload_len so the variant
    // fields aren't dead-code.
    let total_bytes: usize = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(message.payload_len()),
            _ => None,
        })
        .sum();
    assert!(total_bytes > 0);
}

#[test]
fn pipeline_session_heuristic_proxies_through_to_driver() {
    use flowscope::detect::signatures::SignatureMatch;

    fn always_match(_b: &[u8]) -> SignatureMatch {
        SignatureMatch::Match
    }

    let mut p = Pipeline::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_heuristic(CountParser, always_match, |(s, n)| Msg::Tcp(s, n))
        .build();

    let tcp = owned_view(
        ipv4_tcp(
            [1; 6],
            [2; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            33000,
            9999,
            0,
            0,
            0x18,
            b"x",
        ),
        0,
    );
    let events: Vec<_> = p
        .run_iter(vec![tcp])
        .collect::<flowscope::Result<Vec<_>>>()
        .unwrap();
    let tcp_msgs = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::Message {
                    message: Msg::Tcp(..),
                    ..
                }
            )
        })
        .count();
    assert!(tcp_msgs > 0, "session_heuristic proxy didn't dispatch");
}

#[test]
fn pipeline_datagram_heuristic_proxies_through_to_driver() {
    use flowscope::detect::signatures::SignatureMatch;

    fn always_match(_b: &[u8]) -> SignatureMatch {
        SignatureMatch::Match
    }

    let mut p = Pipeline::<_, Msg>::builder(FiveTuple::bidirectional())
        .datagram_heuristic(UdpEcho, always_match, Msg::Udp)
        .build();

    let udp = owned_view(
        ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, b"yo"),
        0,
    );
    let events: Vec<_> = p
        .run_iter(vec![udp])
        .collect::<flowscope::Result<Vec<_>>>()
        .unwrap();
    let udp_msgs = events
        .iter()
        .filter(|e| {
            matches!(
                e,
                Event::Message {
                    message: Msg::Udp(_),
                    ..
                }
            )
        })
        .count();
    assert!(udp_msgs > 0, "datagram_heuristic proxy didn't dispatch");
}

#[test]
fn pipeline_reset_clears_flow_state() {
    let mut p = Pipeline::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser, |(s, n)| Msg::Tcp(s, n))
        .build();

    let tcp = owned_view(
        ipv4_tcp(
            [1; 6],
            [2; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            33000,
            80,
            0,
            0,
            0x18,
            b"a",
        ),
        0,
    );

    let first: Vec<_> = p
        .run_iter(vec![tcp.clone()])
        .collect::<flowscope::Result<Vec<_>>>()
        .unwrap();
    let started_first = first
        .iter()
        .filter(|e| matches!(e, Event::FlowStarted { .. }))
        .count();
    assert_eq!(started_first, 1);

    p.reset();

    let second: Vec<_> = p
        .run_iter(vec![tcp])
        .collect::<flowscope::Result<Vec<_>>>()
        .unwrap();
    let started_second = second
        .iter()
        .filter(|e| matches!(e, Event::FlowStarted { .. }))
        .count();
    // Same flow re-tracked from clean state → 1 FlowStarted again.
    assert_eq!(started_second, 1, "reset didn't clear flow state");
}
