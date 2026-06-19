//! Plan 122 — `SlotHandle<M, K>` is `Send + Sync`.
//!
//! Verifies the cross-thread handle contract: drain on a
//! different thread than the driver runs on; competitive-
//! consumer clone semantics; FiveTupleKey + DNS Message
//! handles compile as Send.

#![cfg(all(
    feature = "test-helpers",
    feature = "extractors",
    feature = "session",
    feature = "reassembler",
))]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::Duration,
};

use flowscope::{
    PacketView, SessionParser, Timestamp,
    driver::{Driver, SlotHandle, SlotMessage},
    extract::{FiveTuple, FiveTupleKey, parse::test_frames::ipv4_tcp},
};

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

// ── Compile-time Send + Sync assertions ───────────────────────

static_assertions::assert_impl_all!(
    SlotHandle<usize, FiveTupleKey>: Send, Sync
);
static_assertions::assert_impl_all!(
    SlotMessage<usize, FiveTupleKey>: Send, Sync
);

#[test]
fn slot_handle_send_sync_at_runtime() {
    // The static_assertions above already prove it at compile
    // time; this test exists so a regression shows up in test
    // output as a failed assertion rather than just a compile
    // error somewhere else.
    fn assert_send<T: Send>() {}
    fn assert_sync<T: Sync>() {}
    assert_send::<SlotHandle<usize, FiveTupleKey>>();
    assert_sync::<SlotHandle<usize, FiveTupleKey>>();
}

// ── Cross-thread drain ────────────────────────────────────────

#[test]
fn cross_thread_drain_basic() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();

    // Move a clone of the handle to a worker thread. Drain in a
    // tight loop until we've collected N messages.
    let drainer_handle = slot.clone();
    let done = Arc::new(AtomicBool::new(false));
    let done_clone = Arc::clone(&done);

    let worker = thread::spawn(move || {
        let mut h = drainer_handle;
        let mut acc: Vec<SlotMessage<usize, FiveTupleKey>> = Vec::new();
        let mut buf = Vec::new();
        while !done_clone.load(Ordering::Acquire) || h.pending() > 0 {
            h.drain(&mut buf);
            acc.append(&mut buf);
            thread::sleep(Duration::from_micros(10));
        }
        // Final drain after producer signals stop.
        h.drain(&mut buf);
        acc.append(&mut buf);
        acc
    });

    // Push some packets through the driver from the main thread.
    // Increment seq by payload length so each packet is fresh
    // data, not a retransmit.
    let mut events = Vec::new();
    let mut seq: u32 = 1000;
    for i in 0..50u32 {
        let payload = format!("packet-{i:02}");
        let frame = tcp_packet(33000, 80, seq, payload.as_bytes());
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
        seq = seq.wrapping_add(payload.len() as u32);
    }
    done.store(true, Ordering::Release);
    let collected = worker.join().expect("worker panicked");

    // We also drain locally to make sure no message escaped both
    // consumers (it shouldn't — competitive consumer).
    let mut local = Vec::new();
    slot.drain(&mut local);

    assert_eq!(
        collected.len() + local.len(),
        50,
        "every payload should be observed exactly once across both consumers"
    );
}

#[test]
fn competitive_consumer_clone_does_not_duplicate() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot_a = builder.session_on_ports(CountParser, [80]);
    let mut slot_b = slot_a.clone();
    let mut driver = builder.build();

    let mut events = Vec::new();
    let mut seq: u32 = 1000;
    for i in 0..100u32 {
        let frame = tcp_packet(33000, 80, seq, b"x");
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
        seq = seq.wrapping_add(1);
    }

    let mut a = Vec::new();
    let mut b = Vec::new();
    slot_a.drain(&mut a);
    slot_b.drain(&mut b);
    assert_eq!(
        a.len() + b.len(),
        100,
        "messages distributed between competitive consumers, not duplicated"
    );
}

// Plan 156 (0.13) — `Driver<E>` itself is Send + Sync.
#[test]
fn driver_is_send_and_sync() {
    fn assert_send_sync<T: Send + Sync>() {}
    assert_send_sync::<Driver<FiveTuple>>();
}

#[test]
fn driver_survives_thread_spawn_and_back() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();

    let mut events = Vec::new();
    let handle = thread::spawn(move || {
        let mut seq: u32 = 1000;
        for i in 0..10u32 {
            let frame = tcp_packet(33000, 80, seq, b"y");
            let view = PacketView::new(&frame, Timestamp::new(i, 0));
            driver.track_into(view, &mut events);
            seq = seq.wrapping_add(1);
        }
        (driver, events)
    });

    let (_driver, events) = handle.join().expect("worker thread panicked");
    assert!(
        !events.is_empty(),
        "driver produced events on worker thread"
    );

    let mut msgs = Vec::new();
    let drained = slot.drain(&mut msgs);
    assert_eq!(drained, 10, "10 messages drained on main thread");
}

// Plan 149 (0.13) — bounded drain.

fn fill_slot(
    _slot: &mut SlotHandle<usize, FiveTupleKey>,
    driver: &mut Driver<FiveTuple>,
    count: u32,
) {
    let mut events = Vec::new();
    let mut seq: u32 = 2000;
    for i in 0..count {
        let frame = tcp_packet(33000, 80, seq, b"z");
        let view = PacketView::new(&frame, Timestamp::new(i, 0));
        driver.track_into(view, &mut events);
        seq = seq.wrapping_add(1);
    }
}

#[test]
fn drain_n_respects_max_when_queue_larger() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();
    fill_slot(&mut slot, &mut driver, 100);

    let mut out = Vec::new();
    let drained = slot.drain_n(&mut out, 10);
    assert_eq!(drained, 10);
    assert_eq!(out.len(), 10);
    assert_eq!(slot.pending(), 90);
}

#[test]
fn drain_n_returns_actual_count_when_queue_smaller() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();
    fill_slot(&mut slot, &mut driver, 5);

    let mut out = Vec::new();
    let drained = slot.drain_n(&mut out, 100);
    assert_eq!(drained, 5);
    assert_eq!(out.len(), 5);
}

#[test]
fn drain_n_with_empty_queue_returns_zero() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot: SlotHandle<usize, FiveTupleKey> = builder.session_on_ports(CountParser, [80]);
    let _driver = builder.build();

    let mut out = Vec::new();
    let drained = slot.drain_n(&mut out, 100);
    assert_eq!(drained, 0);
    assert!(out.is_empty());
}

#[test]
fn drain_n_max_zero_is_no_op() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();
    fill_slot(&mut slot, &mut driver, 50);

    let mut out = Vec::new();
    let drained = slot.drain_n(&mut out, 0);
    assert_eq!(drained, 0);
    assert_eq!(slot.pending(), 50);
}

#[test]
fn drain_n_max_usize_drains_everything() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();
    fill_slot(&mut slot, &mut driver, 25);

    let mut out = Vec::new();
    let drained = slot.drain_n(&mut out, usize::MAX);
    assert_eq!(drained, 25);
    assert_eq!(slot.pending(), 0);
}

#[test]
fn drain_n_drains_in_two_batches() {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut slot = builder.session_on_ports(CountParser, [80]);
    let mut driver = builder.build();
    fill_slot(&mut slot, &mut driver, 30);

    let mut out_a = Vec::new();
    let drained_a = slot.drain_n(&mut out_a, 10);
    assert_eq!(drained_a, 10);
    assert_eq!(slot.pending(), 20);

    let mut out_b = Vec::new();
    let drained_b = slot.drain_n(&mut out_b, 20);
    assert_eq!(drained_b, 20);
    assert_eq!(slot.pending(), 0);
}
