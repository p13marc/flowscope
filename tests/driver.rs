//! Plan 121 — `flowscope::driver::Driver<E>`
//! integration tests.
//!
//! The typed driver emits flow-lifecycle [`Event<K>`] only;
//! per-parser typed messages flow through `SlotHandle<M, K>`
//! returned at registration time. Verify both event streams,
//! port + heuristic routing, and capacity reuse.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::driver::SlotMessage;
use flowscope::driver::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::{DatagramParser, FlowSide, PacketView, SessionParser, Timestamp};

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
    type Message = Vec<u8>;
    fn parse(&mut self, b: &[u8], _: FlowSide, _: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push(b.to_vec());
        }
    }
    fn parser_kind(&self) -> &'static str {
        "udp-echo"
    }
}

fn tcp_packet(sport: u16, dport: u16, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        dport,
        1000,
        0,
        0x18,
        payload,
    )
}

#[test]
fn driver_with_no_slots_emits_lifecycle_only() {
    let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
    let frame = tcp_packet(33000, 80, b"data");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));

    let mut events = Vec::new();
    driver.track_into(view, &mut events);

    // Expect FlowStarted + FlowPacket (no Established for the
    // single packet — that takes a 3WHS).
    let started = events
        .iter()
        .filter(|e| matches!(e, Event::FlowStarted { .. }))
        .count();
    let packets = events
        .iter()
        .filter(|e| matches!(e, Event::FlowPacket { .. }))
        .count();
    assert_eq!(started, 1);
    assert_eq!(packets, 1);
}

#[test]
fn session_slot_drains_typed_messages() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut count_slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();

    let frame = tcp_packet(33000, 80, b"hello world");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));

    let mut events = Vec::new();
    driver.track_into(view, &mut events);

    // Lifecycle should have FlowStarted + FlowPacket — but NO
    // Message variant (it doesn't exist on Event<K>).
    assert!(
        events
            .iter()
            .any(|e| matches!(e, Event::FlowStarted { .. }))
    );
    assert!(events.iter().any(|e| matches!(e, Event::FlowPacket { .. })));

    // Typed messages drain from the slot handle.
    let mut msgs: Vec<SlotMessage<(FlowSide, usize), _>> = Vec::new();
    let n = count_slot.drain(&mut msgs);
    assert_eq!(n, 1, "expected 1 message from the count parser");
    assert_eq!(msgs[0].message.0, FlowSide::Initiator);
    assert_eq!(msgs[0].message.1, b"hello world".len());

    // Slot is empty after drain.
    assert_eq!(count_slot.pending(), 0);
}

#[test]
fn session_slot_port_filter_drops_non_matching() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();

    // Port 9999 — doesn't match the [80] filter.
    let frame = tcp_packet(33000, 9999, b"some bytes");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));

    let mut events = Vec::new();
    driver.track_into(view, &mut events);

    let mut msgs = Vec::new();
    let n = http_slot.drain(&mut msgs);
    assert_eq!(n, 0, "port-filtered slot should not emit");
}

#[test]
fn datagram_slot_drains_typed_messages() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut udp_slot = builder.datagram_on_ports(UdpEcho, [53]);
    let mut driver = builder.build();

    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 53, b"query");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));

    let mut events = Vec::new();
    driver.track_into(view, &mut events);

    let mut msgs: Vec<SlotMessage<Vec<u8>, _>> = Vec::new();
    let n = udp_slot.drain(&mut msgs);
    assert_eq!(n, 1);
    assert_eq!(msgs[0].message, b"query");
}

#[test]
fn two_slots_drain_independently() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut tcp_slot = builder.session_on_ports(CountParser, [80]);
    let mut udp_slot = builder.datagram_on_ports(UdpEcho, [53]);
    let mut driver = builder.build();

    let tcp_frame = tcp_packet(33000, 80, b"hi");
    let udp_frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 33000, 53, b"ye");

    let mut events = Vec::new();
    driver.track_into(
        PacketView::new(&tcp_frame, Timestamp::new(0, 0)),
        &mut events,
    );
    driver.track_into(
        PacketView::new(&udp_frame, Timestamp::new(1, 0)),
        &mut events,
    );

    let mut tcp_msgs = Vec::new();
    let mut udp_msgs = Vec::new();
    tcp_slot.drain(&mut tcp_msgs);
    udp_slot.drain(&mut udp_msgs);

    assert_eq!(tcp_msgs.len(), 1);
    assert_eq!(udp_msgs.len(), 1);
    assert_eq!(tcp_msgs[0].message.1, b"hi".len());
    assert_eq!(udp_msgs[0].message, b"ye");
}

#[test]
fn slot_handle_capacity_is_reused() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();

    let frame = tcp_packet(33000, 80, b"a");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));

    // Warmup
    let mut events = Vec::new();
    let mut msgs = Vec::with_capacity(8);
    for _ in 0..16 {
        events.clear();
        driver.track_into(view, &mut events);
        msgs.clear();
        slot.drain(&mut msgs);
    }
    let cap_after_warmup = msgs.capacity();

    // Reuse across many calls.
    for _ in 0..1000 {
        events.clear();
        driver.track_into(view, &mut events);
        msgs.clear();
        slot.drain(&mut msgs);
    }
    // Capacity should not have shrunk.
    assert!(
        msgs.capacity() >= cap_after_warmup,
        "drain shrunk capacity: {} → {}",
        cap_after_warmup,
        msgs.capacity()
    );
}

#[test]
fn session_broadcast_sees_every_flow() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_broadcast(CountParser);
    let mut driver = builder.build();

    // Two different flows on two different ports.
    let a = tcp_packet(33000, 80, b"a");
    let b = tcp_packet(33001, 443, b"b");

    let mut events = Vec::new();
    driver.track_into(PacketView::new(&a, Timestamp::new(0, 0)), &mut events);
    driver.track_into(PacketView::new(&b, Timestamp::new(0, 0)), &mut events);

    let mut msgs = Vec::new();
    slot.drain(&mut msgs);
    assert_eq!(msgs.len(), 2, "broadcast should fire on every flow");
}

#[test]
fn parser_kind_is_propagated_to_handle() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let slot = builder.session_broadcast(CountParser);
    let _driver = builder.build();

    assert_eq!(slot.parser_kind(), "count");
}
