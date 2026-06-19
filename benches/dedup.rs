//! `Dedup::keep` throughput benchmarks.
//!
//! Run with:
//!
//!     cargo bench --bench dedup --features tracker

use criterion::{black_box, criterion_group, criterion_main, Criterion, Throughput};
use flowscope::{Dedup, PacketView, Timestamp};

fn bench_unique_1500(c: &mut Criterion) {
    let mut group = c.benchmark_group("dedup");
    group.throughput(Throughput::Elements(1));
    group.bench_function("unique_1500", |b| {
        let mut d = Dedup::loopback();
        // Pre-build a pool of distinct frames so each iter sees a
        // new hash (no false dedupes).
        let frames: Vec<Vec<u8>> = (0..1024)
            .map(|i| {
                let mut v = vec![0u8; 1500];
                v[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                v
            })
            .collect();
        let mut i = 0usize;
        b.iter(|| {
            let v = PacketView::new(&frames[i % frames.len()], Timestamp::default());
            black_box(d.keep(v));
            i = i.wrapping_add(1);
        })
    });
    group.bench_function("unique_64", |b| {
        let mut d = Dedup::loopback();
        let frames: Vec<Vec<u8>> = (0..1024)
            .map(|i| {
                let mut v = vec![0u8; 64];
                v[0..4].copy_from_slice(&(i as u32).to_be_bytes());
                v
            })
            .collect();
        let mut i = 0usize;
        b.iter(|| {
            let v = PacketView::new(&frames[i % frames.len()], Timestamp::default());
            black_box(d.keep(v));
            i = i.wrapping_add(1);
        })
    });
    group.bench_function("duplicate_1500", |b| {
        let mut d = Dedup::loopback();
        let frame = vec![0u8; 1500];
        b.iter(|| {
            let v = PacketView::new(&frame, Timestamp::default());
            black_box(d.keep(v));
        })
    });
    group.finish();
}

criterion_group!(benches, bench_unique_1500);
criterion_main!(benches);
