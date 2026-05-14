//! `FlowTracker::track` throughput benchmarks.
//!
//! Validates Plan 41's hot-cache claims: monoflow should be
//! substantially faster than multiflow round-robin because the
//! same key reappears every call and the hot-cache short-circuits
//! the hashmap lookup.
//!
//! Run with:
//!
//!     cargo bench --bench tracker --features tracker,extractors,test-helpers

use criterion::{BenchmarkId, Criterion, Throughput, black_box, criterion_group, criterion_main};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{FlowTracker, PacketView, Timestamp};

fn bench_monoflow(c: &mut Criterion) {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let frame = ipv4_tcp(
        [0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1000, 0, 0x18, b"x",
    );
    let mut group = c.benchmark_group("tracker");
    group.throughput(Throughput::Elements(1));
    group.bench_function("monoflow", |b| {
        b.iter(|| {
            let v = PacketView::new(&frame, Timestamp::default());
            black_box(t.track(v));
        })
    });
    group.finish();
}

fn bench_n_flows(c: &mut Criterion) {
    let mut group = c.benchmark_group("tracker/n_flows");
    group.throughput(Throughput::Elements(1));
    for &n in &[10usize, 100, 1_000, 10_000] {
        // Pre-build N distinct frames keyed by varying source port.
        let frames: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                ipv4_tcp(
                    [0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
                    1024 + (i as u16), 80, 1000, 0, 0x18, b"x",
                )
            })
            .collect();
        group.bench_with_input(BenchmarkId::from_parameter(n), &frames, |b, fs| {
            let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
            let mut i = 0usize;
            b.iter(|| {
                let v = PacketView::new(&fs[i % fs.len()], Timestamp::default());
                black_box(t.track(v));
                i = i.wrapping_add(1);
            });
        });
    }
    group.finish();
}

criterion_group!(benches, bench_monoflow, bench_n_flows);
criterion_main!(benches);
