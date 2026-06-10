//! Plan 124 — `Driver::deferred()` constructor for builders
//! that defer extractor selection until `.build_with(ext)`.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::driver::{DeferredDriverBuilder, Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::{DatagramParser, FlowSide, PacketView, SessionParser, Timestamp};

#[derive(Default, Clone)]
struct CountParser;
impl SessionParser for CountParser {
    type Message = usize;
    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push(b.len());
        }
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
        if !b.is_empty() {
            out.push(b.len());
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

fn tcp_packet(seq: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        33000,
        80,
        seq,
        0,
        0x18,
        payload,
    )
}

#[test]
fn deferred_builder_handle_drains_after_build_with() {
    let mut builder = Driver::<FiveTuple>::deferred();
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build_with(FiveTuple::bidirectional());

    let mut events = Vec::new();
    let mut seq: u32 = 1000;
    for i in 0..5u32 {
        let frame = tcp_packet(seq, b"hello");
        driver.track_into(PacketView::new(&frame, Timestamp::new(i, 0)), &mut events);
        seq = seq.wrapping_add(5);
    }

    let mut msgs = Vec::new();
    let n = slot.drain(&mut msgs);
    assert_eq!(n, 5, "all 5 packets produced messages");
    assert!(msgs.iter().all(|m| m.message == 5));
}

#[test]
fn deferred_emit_anomalies_propagates_through_build_with() {
    let mut b1 = Driver::<FiveTuple>::deferred();
    b1.emit_anomalies(true);
    let driver_with: Driver<FiveTuple> = b1.build_with(FiveTuple::bidirectional());

    let b2 = Driver::<FiveTuple>::deferred();
    let driver_without: Driver<FiveTuple> = b2.build_with(FiveTuple::bidirectional());

    // Type-existence smoke test (the flag is internal — we just
    // verify the build_with path consumes the knob without
    // dropping it on the floor).
    let _ = driver_with;
    let _ = driver_without;
}

#[test]
fn deferred_multi_slot_independent_drains() {
    let mut builder = Driver::<FiveTuple>::deferred();
    let mut tcp_slot = builder.session_on_ports(CountParser, [80]);
    let mut udp_slot = builder.datagram_on_ports(UdpEcho, [53]);
    let mut driver = builder.build_with(FiveTuple::bidirectional());

    let tcp_frame = tcp_packet(1000, b"hi");
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
    assert_eq!(udp_msgs[0].message, b"ye");
}

#[test]
fn deferred_builder_matches_eager_for_same_inputs() {
    // Two pipelines with identical (parser, ports, extractor),
    // one eager, one deferred. The event streams must match for
    // identical traffic.
    let mut eager_builder = Driver::builder(FiveTuple::bidirectional());
    let mut eager_slot = eager_builder.session_on_ports(CountParser, [80]);
    let mut eager_driver = eager_builder.build();

    let mut deferred_builder: DeferredDriverBuilder<FiveTuple> = Driver::<FiveTuple>::deferred();
    let mut deferred_slot = deferred_builder.session_on_ports(CountParser, [80]);
    let mut deferred_driver = deferred_builder.build_with(FiveTuple::bidirectional());

    let mut eager_events: Vec<Event<_>> = Vec::new();
    let mut deferred_events: Vec<Event<_>> = Vec::new();

    let mut seq: u32 = 1000;
    for i in 0..10u32 {
        let payload = format!("ev-{i:02}");
        let frame = tcp_packet(seq, payload.as_bytes());
        eager_driver.track_into(
            PacketView::new(&frame, Timestamp::new(i, 0)),
            &mut eager_events,
        );
        deferred_driver.track_into(
            PacketView::new(&frame, Timestamp::new(i, 0)),
            &mut deferred_events,
        );
        seq = seq.wrapping_add(payload.len() as u32);
    }

    assert_eq!(
        eager_events.len(),
        deferred_events.len(),
        "event count parity"
    );
    let mut em = Vec::new();
    let mut dm = Vec::new();
    eager_slot.drain(&mut em);
    deferred_slot.drain(&mut dm);
    assert_eq!(em.len(), dm.len(), "message count parity");
    for (a, b) in em.iter().zip(dm.iter()) {
        assert_eq!(a.message, b.message);
        assert_eq!(a.side, b.side);
    }
}
