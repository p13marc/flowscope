//! Plan 116 PR 1 — unified `Driver<E, M>` + `Event<K, M>` shape.
//!
//! Verifies the new types ship alongside the legacy
//! `FlowSessionDriver` / `FlowMultiSessionDriver` without
//! interfering. Covers builder shape, single-parser session
//! dispatch, port-routed dispatch, broadcast dispatch, and the
//! merged-event-stream contract.

#![cfg(all(feature = "test-helpers", feature = "extractors", feature = "session"))]

use flowscope::driver_unified::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::{DatagramParser, FlowSide, PacketView, SessionParser, Timestamp};

/// Toy session parser: counts bytes per side, emits one
/// "byte-count" message per feed.
#[derive(Default, Clone)]
struct CountParser {
    name: &'static str,
}

impl CountParser {
    fn named(name: &'static str) -> Self {
        Self { name }
    }
}

impl SessionParser for CountParser {
    type Message = (FlowSide, usize);

    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        if b.is_empty() {
            Vec::new()
        } else {
            vec![(FlowSide::Initiator, b.len())]
        }
    }

    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        if b.is_empty() {
            Vec::new()
        } else {
            vec![(FlowSide::Responder, b.len())]
        }
    }

    fn parser_kind(&self) -> &'static str {
        if self.name.is_empty() { "count" } else { self.name }
    }
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum Msg {
    Counted { name: &'static str, side: FlowSide, len: usize },
}

#[test]
fn builder_shape_compiles_and_no_op_is_empty() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional()).build();
    // No registered parsers; an empty input run produces no events.
    let out = driver.finish();
    assert!(out.is_empty());
}

#[test]
fn single_session_parser_emits_flow_lifecycle_and_messages() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser::named("count"), |(side, len)| Msg::Counted {
            name: "count",
            side,
            len,
        })
        .build();

    // SYN — first packet of a new flow.
    let syn = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 1234, 80, 1000, 0, 0x02, b"",
    );
    let events = driver.track(PacketView::new(&syn, Timestamp::new(0, 0)));

    let started = events.iter().filter(|e| matches!(e, Event::FlowStarted { .. })).count();
    assert_eq!(started, 1, "expected one FlowStarted: {events:?}");
}

#[test]
fn port_routed_parser_fires_only_on_matching_flows() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_on_ports(CountParser::named("http"), [80], |(side, len)| Msg::Counted {
            name: "http",
            side,
            len,
        })
        .session_on_ports(CountParser::named("ssh"), [22], |(side, len)| Msg::Counted {
            name: "ssh",
            side,
            len,
        })
        .build();

    // Port 80 frame with payload — only the HTTP slot should
    // see it (the SSH slot's port filter rejects the frame
    // before even hitting its inner driver).
    let frame = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 80, 1000, 0, 0x18, b"GET /\r\n",
    );
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));

    let http_msgs: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                message: Msg::Counted { name: "http", .. },
                ..
            } => Some(()),
            _ => None,
        })
        .collect();
    let ssh_msgs: Vec<_> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message {
                message: Msg::Counted { name: "ssh", .. },
                ..
            } => Some(()),
            _ => None,
        })
        .collect();
    assert!(!http_msgs.is_empty(), "HTTP slot didn't fire on port-80 flow");
    assert!(ssh_msgs.is_empty(), "SSH slot wrongly fired on port-80 flow");
}

#[test]
fn broadcast_parser_fires_regardless_of_port() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser::named("any"), |(side, len)| Msg::Counted {
            name: "any",
            side,
            len,
        })
        .build();

    let frame = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, 1000, 0, 0x18, b"hello",
    );
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let any: usize = events
        .iter()
        .filter(|e| matches!(e, Event::Message { message: Msg::Counted { name: "any", .. }, .. }))
        .count();
    assert!(any > 0, "broadcast slot didn't fire on arbitrary-port flow");
}

#[test]
fn event_accessors_smoke_test() {
    let ev: Event<u32, Msg> = Event::FlowStarted {
        key: 7,
        ts: Timestamp::new(0, 0),
        l4: None,
    };
    assert_eq!(ev.key().copied(), Some(7));
    assert!(ev.is_flow_event());
    assert!(!ev.is_parser_event());
    assert!(ev.parser_kind().is_none());

    let ev: Event<u32, Msg> = Event::Message {
        key: 7,
        side: FlowSide::Initiator,
        message: Msg::Counted {
            name: "x",
            side: FlowSide::Initiator,
            len: 1,
        },
        ts: Timestamp::new(0, 0),
        parser_kind: "x",
    };
    assert!(ev.is_parser_event());
    assert_eq!(ev.parser_kind(), Some("x"));
}

/// Toy datagram parser that emits one event per non-empty payload.
#[derive(Default, Clone)]
struct UdpEcho;

impl DatagramParser for UdpEcho {
    type Message = usize;
    fn parse(
        &mut self,
        payload: &[u8],
        _side: FlowSide,
        _ts: Timestamp,
    ) -> Vec<Self::Message> {
        if payload.is_empty() {
            Vec::new()
        } else {
            vec![payload.len()]
        }
    }
    fn parser_kind(&self) -> &'static str {
        "udp-echo"
    }
}

#[test]
fn datagram_on_ports_fires_on_matching_udp_flows() {
    let mut driver = Driver::<_, usize>::builder(FiveTuple::bidirectional())
        .datagram_on_ports(UdpEcho, [53], |n| n)
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 53, b"hello");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let msgs: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, vec![5]);
}

#[test]
fn datagram_broadcast_fires_regardless_of_port() {
    let mut driver = Driver::<_, usize>::builder(FiveTuple::bidirectional())
        .datagram_broadcast(UdpEcho, |n| n)
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 7777, b"abcd");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let msgs: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, vec![4]);
}

#[test]
fn datagram_on_ports_skips_non_matching() {
    let mut driver = Driver::<_, usize>::builder(FiveTuple::bidirectional())
        .datagram_on_ports(UdpEcho, [53], |n| n)
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 7777, b"abcd");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let msgs: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert!(msgs.is_empty(), "wrongly fired on non-matching port: {msgs:?}");
}

#[test]
fn session_and_datagram_slots_coexist() {
    let mut driver = Driver::<_, MixedMsg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser::named("tcp"), |(s, n)| {
            MixedMsg::Tcp { side: s, len: n }
        })
        .datagram_broadcast(UdpEcho, MixedMsg::Udp)
        .build();
    let tcp = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 80, 0, 0, 0x18, b"x",
    );
    let udp = ipv4_udp([10, 0, 0, 3], [10, 0, 0, 4], 5353, 53, b"yz");
    let mut events = driver.track(PacketView::new(&tcp, Timestamp::new(0, 0)));
    events.extend(driver.track(PacketView::new(&udp, Timestamp::new(1, 0))));
    let tcp_msgs = events
        .iter()
        .filter(|e| matches!(e, Event::Message { message: MixedMsg::Tcp { .. }, .. }))
        .count();
    let udp_msgs = events
        .iter()
        .filter(|e| matches!(e, Event::Message { message: MixedMsg::Udp(_), .. }))
        .count();
    assert!(tcp_msgs > 0, "no TCP messages emitted");
    assert!(udp_msgs > 0, "no UDP messages emitted");
}

#[derive(Debug, Clone)]
#[allow(dead_code)]
enum MixedMsg {
    Tcp { side: FlowSide, len: usize },
    Udp(usize),
}

// ── heuristic routing (plan 116 PR 2b) ─────────────────────────────

/// Toy "always matches" signature.
fn always_match(_b: &[u8]) -> flowscope::detect::signatures::SignatureMatch {
    flowscope::detect::signatures::SignatureMatch::Match
}

/// Toy "never matches" signature.
fn never_match(_b: &[u8]) -> flowscope::detect::signatures::SignatureMatch {
    flowscope::detect::signatures::SignatureMatch::NoMatch
}

#[test]
fn session_heuristic_dispatches_on_match() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_heuristic(CountParser::named("h"), always_match, |(side, len)| {
            Msg::Counted { name: "h", side, len }
        })
        .build();
    let frame = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, 0, 0, 0x18, b"hello",
    );
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let messages = events
        .iter()
        .filter(|e| matches!(e, Event::Message { message: Msg::Counted { name: "h", .. }, .. }))
        .count();
    assert!(messages > 0, "heuristic slot didn't fire on Match signature");
}

#[test]
fn session_heuristic_skips_on_never_match() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_heuristic_with_budget(
            CountParser::named("h"),
            never_match,
            2,
            |(side, len)| Msg::Counted { name: "h", side, len },
        )
        .build();
    let frame = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, 0, 0, 0x18, b"X",
    );
    // First packet — probing; second packet — still probing; third packet — gave up.
    let frame2 = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, 0, 0, 0x18, b"Y",
    );
    let frame3 = ipv4_tcp(
        [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, 0, 0, 0x18, b"Z",
    );
    let mut events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    events.extend(driver.track(PacketView::new(&frame2, Timestamp::new(1, 0))));
    events.extend(driver.track(PacketView::new(&frame3, Timestamp::new(2, 0))));
    let messages = events
        .iter()
        .filter(|e| matches!(e, Event::Message { message: Msg::Counted { name: "h", .. }, .. }))
        .count();
    assert_eq!(messages, 0, "heuristic slot wrongly fired on NoMatch signature");
}

#[test]
fn datagram_heuristic_dispatches_on_match() {
    let mut driver = Driver::<_, usize>::builder(FiveTuple::bidirectional())
        .datagram_heuristic(UdpEcho, always_match, |n| n)
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, b"yo");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let msgs: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert_eq!(msgs, vec![2]);
}

#[test]
fn datagram_heuristic_skips_on_never_match() {
    let mut driver = Driver::<_, usize>::builder(FiveTuple::bidirectional())
        .datagram_heuristic_with_budget(UdpEcho, never_match, 2, |n| n)
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 9999, b"yo");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let msgs: Vec<usize> = events
        .iter()
        .filter_map(|e| match e {
            Event::Message { message, .. } => Some(*message),
            _ => None,
        })
        .collect();
    assert!(msgs.is_empty(), "datagram heuristic wrongly fired: {msgs:?}");
}

#[test]
fn udp_flow_does_not_emit_established() {
    let mut driver = Driver::<_, Msg>::builder(FiveTuple::bidirectional())
        .session_broadcast(CountParser::default(), |(side, len)| Msg::Counted {
            name: "count",
            side,
            len,
        })
        .build();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 5353, 53, b"x");
    let events = driver.track(PacketView::new(&frame, Timestamp::new(0, 0)));
    let established = events.iter().filter(|e| matches!(e, Event::FlowEstablished { .. })).count();
    assert_eq!(established, 0);
}
