//! Plan 150 (0.13) — `BroadcastSlotHandle<M, K>` fan-out semantics.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use flowscope::{
    PacketView, SessionParser, Timestamp,
    driver::{BroadcastSlotHandle, Driver, SlotDrain},
    extract::{FiveTuple, FiveTupleKey, parse::test_frames::ipv4_tcp},
};
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

/// #101: one generic drain loop works over both the competitive
/// `SlotHandle` and the fan-out `BroadcastSlotHandle` via the shared
/// `SlotDrain` trait.
#[test]
fn slot_drain_trait_is_generic_over_both_handles() {
    fn pump<S: SlotDrain<usize, FiveTupleKey>>(slot: &mut S) -> (usize, &'static str) {
        let mut out = Vec::new();
        let n = slot.drain(&mut out);
        assert_eq!(n, out.len());
        (n, slot.parser_kind())
    }

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut plain = builder.session_on_ports(CountParser, [80]);
    let mut bcast = builder.session_on_ports_broadcast_each(CountParser, [443]);
    let mut driver = builder.build();

    let mut events = Vec::new();
    for (i, dport) in [80u16, 443].into_iter().enumerate() {
        let frame = tcp_packet(33000 + i as u16, dport, 1000, b"abcd");
        let view = PacketView::new(&frame, Timestamp::new(i as u32, 0));
        driver.track_into(view, &mut events);
    }

    // Same trait, two delivery modes, one loop.
    assert_eq!(plain.pending(), 1);
    assert_eq!(bcast.pending(), 1);
    let (n_plain, kind_plain) = pump(&mut plain);
    let (n_bcast, kind_bcast) = pump(&mut bcast);
    assert_eq!(n_plain, 1);
    assert_eq!(n_bcast, 1);
    assert_eq!(kind_plain, "count");
    assert_eq!(kind_bcast, "count");
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
