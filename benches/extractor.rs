//! `FlowExtractor` throughput benchmarks.
//!
//! Run with:
//!
//!     cargo bench --bench extractor --features extractors,test-helpers

use criterion::{Criterion, black_box, criterion_group, criterion_main};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::extractor::FlowExtractor;
use flowscope::{PacketView, Timestamp};

fn bench_five_tuple_ipv4_tcp(c: &mut Criterion) {
    let extractor = FiveTuple::bidirectional();
    let frame = ipv4_tcp(
        [0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1000, 0, 0x18, b"GET / HTTP/1.1\r\n\r\n",
    );
    c.bench_function("extractor/five_tuple_ipv4_tcp", |b| {
        b.iter(|| {
            let v = PacketView::new(&frame, Timestamp::default());
            black_box(extractor.extract(v))
        })
    });
}

fn bench_five_tuple_ipv4_udp(c: &mut Criterion) {
    let extractor = FiveTuple::bidirectional();
    let frame = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1234, 53, b"query");
    c.bench_function("extractor/five_tuple_ipv4_udp", |b| {
        b.iter(|| {
            let v = PacketView::new(&frame, Timestamp::default());
            black_box(extractor.extract(v))
        })
    });
}

criterion_group!(benches, bench_five_tuple_ipv4_tcp, bench_five_tuple_ipv4_udp);
criterion_main!(benches);
