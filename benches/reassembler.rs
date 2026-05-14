//! `BufferedReassembler::segment` throughput benchmarks.
//!
//! Run with:
//!
//!     cargo bench --bench reassembler --features reassembler

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use flowscope::{BufferedReassembler, OverflowPolicy, Reassembler};

fn bench_in_order_1500_uncapped(c: &mut Criterion) {
    let payload = vec![0u8; 1500];
    c.bench_function("reassembler/in_order_1500_uncapped", |b| {
        let mut r = BufferedReassembler::new();
        let mut seq = 0u32;
        b.iter(|| {
            r.segment(seq, &payload);
            seq = seq.wrapping_add(payload.len() as u32);
            // Drain periodically to keep the buffer bounded without
            // forcing reallocation on every iteration.
            if r.buffered_len() > 1_000_000 {
                black_box(r.take());
            }
        })
    });
}

fn bench_in_order_1500_capped_1m(c: &mut Criterion) {
    let payload = vec![0u8; 1500];
    c.bench_function("reassembler/in_order_1500_capped_1m", |b| {
        let mut r = BufferedReassembler::new().with_max_buffer(1 << 20);
        let mut seq = 0u32;
        b.iter(|| {
            r.segment(seq, &payload);
            seq = seq.wrapping_add(payload.len() as u32);
            if r.buffered_len() > (1 << 19) {
                black_box(r.take());
            }
        })
    });
}

fn bench_sliding_window_overflow(c: &mut Criterion) {
    // Cap = 100; every 1500-byte segment overflows. Exercises the
    // rotation path under SlidingWindow.
    let payload = vec![0u8; 1500];
    c.bench_function("reassembler/sliding_window_overflow", |b| {
        let mut r = BufferedReassembler::new().with_max_buffer(100);
        let mut seq = 0u32;
        b.iter(|| {
            r.segment(seq, &payload);
            seq = seq.wrapping_add(payload.len() as u32);
        })
    });
}

fn bench_ooo_drops(c: &mut Criterion) {
    let payload = vec![0u8; 1500];
    c.bench_function("reassembler/ooo_drops", |b| {
        let mut r = BufferedReassembler::new();
        // Prime with one in-order segment to set expected_seq.
        r.segment(0, &payload);
        b.iter(|| {
            // Always OOO — seq is far from expected.
            r.segment(1_000_000, &payload);
            black_box(r.dropped_segments());
        })
    });
}

fn bench_drop_flow_idle(c: &mut Criterion) {
    // Drop-flow + post-poison no-op path: hot-path cost for
    // already-poisoned reassemblers.
    let payload = vec![0u8; 1500];
    c.bench_function("reassembler/drop_flow_poisoned", |b| {
        let mut r = BufferedReassembler::new()
            .with_max_buffer(100)
            .with_overflow_policy(OverflowPolicy::DropFlow);
        // Trigger the poison once up-front.
        r.segment(0, &payload);
        assert!(r.is_poisoned());
        let mut seq = 1500u32;
        b.iter(|| {
            r.segment(seq, &payload);
            seq = seq.wrapping_add(payload.len() as u32);
        })
    });
}

criterion_group!(
    benches,
    bench_in_order_1500_uncapped,
    bench_in_order_1500_capped_1m,
    bench_sliding_window_overflow,
    bench_ooo_drops,
    bench_drop_flow_idle,
);
criterion_main!(benches);
