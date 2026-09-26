//! Measured allocation gate (issue #192): in-order TCP through the
//! session engines allocates nothing per packet once a flow is
//! established — no reassembly buffer, no scratch growth, no event
//! container. A parser that produces no messages is used so only the
//! engine is measured.

#![cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    feature = "test-helpers"
))]

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use flowscope::driver::Driver;
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::session::SessionDriver;
use flowscope::{PacketView, SessionParser, Timestamp};

struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static BLOCKS: Cell<u64> = const { Cell::new(0) };
}

fn note() {
    if ON.try_with(|c| c.get()).unwrap_or(false) {
        let _ = BLOCKS.try_with(|b| b.set(b.get() + 1));
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        note();
        unsafe { System.alloc(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, n: usize) -> *mut u8 {
        note();
        unsafe { System.realloc(p, l, n) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn counted<F: FnOnce()>(f: F) -> u64 {
    BLOCKS.with(|b| b.set(0));
    ON.with(|c| c.set(true));
    f();
    ON.with(|c| c.set(false));
    BLOCKS.with(|b| b.get())
}

#[derive(Clone, Default)]
struct Silent;

impl SessionParser for Silent {
    type Message = ();
    fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
    fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
}

/// Handshake, then `n` request/response segment pairs, in order.
fn conversation(n: usize) -> Vec<(Timestamp, Vec<u8>)> {
    let m = [0u8; 6];
    let (c, s) = ([10, 0, 0, 1], [10, 0, 0, 2]);
    let (mut cseq, mut sseq) = (1000u32, 5000u32);
    let mut v = vec![
        ipv4_tcp(m, m, c, s, 40_000, 80, cseq, 0, 0x02, b""),
        ipv4_tcp(m, m, s, c, 80, 40_000, sseq, cseq + 1, 0x12, b""),
    ];
    cseq += 1;
    sseq += 1;
    v.push(ipv4_tcp(m, m, c, s, 40_000, 80, cseq, sseq, 0x10, b""));
    let req = [b'q'; 200];
    let resp = [b'r'; 1200];
    for _ in 0..n {
        v.push(ipv4_tcp(m, m, c, s, 40_000, 80, cseq, sseq, 0x18, &req));
        cseq += req.len() as u32;
        v.push(ipv4_tcp(m, m, s, c, 80, 40_000, sseq, cseq, 0x18, &resp));
        sseq += resp.len() as u32;
    }
    v.into_iter()
        .enumerate()
        .map(|(i, f)| {
            let us = i as u64 * 50;
            (
                Timestamp::new(1 + (us / 1_000_000) as u32, (us % 1_000_000) as u32 * 1000),
                f,
            )
        })
        .collect()
}

#[test]
fn typed_driver_in_order_tcp_allocates_nothing_per_packet() {
    let frames = conversation(1_100);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let _slot = b.session_on_ports(Silent, [80]);
    let mut d = b.build();
    let mut events = Vec::with_capacity(64);
    let (warm, steady) = frames.split_at(203);
    for (ts, f) in warm {
        events.clear();
        d.track_into(PacketView::new(f, *ts), &mut events);
    }
    let blocks = counted(|| {
        for (ts, f) in steady {
            events.clear();
            d.track_into(PacketView::new(f, *ts), &mut events);
        }
    });
    assert_eq!(blocks, 0, "{} packets", steady.len());
}

#[test]
fn session_driver_in_order_tcp_allocates_nothing_per_packet() {
    let frames = conversation(1_100);
    let mut d = SessionDriver::new(FiveTuple::bidirectional(), Silent);
    let mut out = Vec::with_capacity(64);
    let (warm, steady) = frames.split_at(203);
    for (ts, f) in warm {
        out.clear();
        d.track_into(PacketView::new(f, *ts), &mut out);
    }
    let blocks = counted(|| {
        for (ts, f) in steady {
            out.clear();
            d.track_into(PacketView::new(f, *ts), &mut out);
        }
    });
    assert_eq!(blocks, 0, "{} packets", steady.len());
}

#[test]
fn the_counter_counts() {
    let n = counted(|| {
        let v: Vec<u8> = Vec::with_capacity(10);
        std::hint::black_box(v);
    });
    assert_eq!(n, 1);
}

/// A sweep that ends nothing (every flow still fresh) allocates
/// nothing either.
#[test]
fn quiet_sweep_allocates_nothing() {
    let frames = conversation(50);
    let mut b = Driver::builder(FiveTuple::bidirectional());
    let _slot = b.session_on_ports(Silent, [80]);
    let mut d = b.build();
    let mut events = Vec::with_capacity(64);
    for (ts, f) in &frames {
        events.clear();
        d.track_into(PacketView::new(f, *ts), &mut events);
    }
    let now = frames.last().unwrap().0;
    events.clear();
    d.sweep_into(now, &mut events); // warm the sweep path once
    let blocks = counted(|| {
        for _ in 0..100 {
            events.clear();
            d.sweep_into(now, &mut events);
        }
    });
    assert_eq!(blocks, 0);
}
