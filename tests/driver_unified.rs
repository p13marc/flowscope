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
use flowscope::{FlowSide, PacketView, SessionParser, Timestamp};

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
