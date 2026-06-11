//! Plan 150 (0.13) — `BroadcastSlotHandle<M, K>` fan-out semantics.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::driver::{BroadcastSlotHandle, Driver};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{PacketView, SessionParser, Timestamp};
use static_assertions::assert_impl_all;

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

fn tcp_packet(sport: u16, dport: u16, seq: u32, payload: &[u8]) -> Vec<u8> {
    ipv4_tcp(
        [1; 6],
        [2; 6],
        [10, 0, 0, 1],
        [10, 0, 0, 2],
        sport,
        dport,
        seq,
        0,
        0x18,
        payload,
    )
}

assert_impl_all!(BroadcastSlotHandle<usize, flowscope::extract::FiveTupleKey>: Send, Sync);

#[test]
fn broadcast_two_subscribers_both_see_every_message() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut sub_a = builder.session_on_ports_broadcast_each(CountParser, [80]);
    let mut sub_b = sub_a.clone();
    let mut driver = builder.build();

    let mut events = Vec::new();
    let mut seq: u32 = 1000;
    for i in 0..10u32 {
        let frame = tcp_packet(33000, 80, seq, b"abc");
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
        seq = seq.wrapping_add(3);
    }

    let mut out_a = Vec::new();
    let mut out_b = Vec::new();
    sub_a.drain(&mut out_a);
    sub_b.drain(&mut out_b);
    assert_eq!(out_a.len(), 10, "subscriber A saw all 10 messages");
    assert_eq!(out_b.len(), 10, "subscriber B saw all 10 messages");
}

#[test]
fn broadcast_subscriber_dropped_is_pruned() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut sub_a = builder.session_on_ports_broadcast_each(CountParser, [80]);
    {
        let _sub_b = sub_a.clone();
        assert_eq!(sub_a.subscribers(), 2);
    }

    // After sub_b drops, the next push prunes it.
    let mut driver = builder.build();
    let mut events = Vec::new();
    let frame = tcp_packet(33000, 80, 1000, b"x");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));
    driver.track_into(view, &mut events);

    // sub_b's Weak no longer upgrades — subscribers() observes 1.
    assert_eq!(sub_a.subscribers(), 1);
    let mut out = Vec::new();
    sub_a.drain(&mut out);
    assert_eq!(out.len(), 1);
}

#[test]
fn broadcast_zero_subscribers_is_noop() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let sub = builder.session_on_ports_broadcast_each(CountParser, [80]);
    drop(sub); // No subscribers remain.

    let mut driver = builder.build();
    let mut events = Vec::new();
    for i in 0..5u32 {
        let frame = tcp_packet(33000, 80, 1000 + i, b"x");
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
    }
    // No subscriber crash — driver still tracks flow lifecycle.
    assert!(!events.is_empty(), "lifecycle events still emitted");
}

#[test]
fn broadcast_clone_produces_distinct_queue() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut sub_a = builder.session_on_ports_broadcast_each(CountParser, [80]);
    let mut sub_b = sub_a.clone();
    let mut driver = builder.build();

    let mut events = Vec::new();
    let frame = tcp_packet(33000, 80, 1000, b"x");
    let view = PacketView::new(&frame, Timestamp::new(0, 0));
    driver.track_into(view, &mut events);

    // sub_a drains; sub_b still has its message.
    let mut out_a = Vec::new();
    sub_a.drain(&mut out_a);
    assert_eq!(out_a.len(), 1);
    assert_eq!(sub_b.pending(), 1, "sub_b queue independent of sub_a");
    let mut out_b = Vec::new();
    sub_b.drain(&mut out_b);
    assert_eq!(out_b.len(), 1);
}

#[test]
fn broadcast_drain_n_caps_per_subscriber() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut sub = builder.session_on_ports_broadcast_each(CountParser, [80]);
    let mut driver = builder.build();

    let mut events = Vec::new();
    let mut seq: u32 = 2000;
    for i in 0..20u32 {
        let frame = tcp_packet(33000, 80, seq, b"x");
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
        seq = seq.wrapping_add(1);
    }

    let mut out = Vec::new();
    let drained = sub.drain_n(&mut out, 5);
    assert_eq!(drained, 5);
    assert_eq!(sub.pending(), 15);
}
