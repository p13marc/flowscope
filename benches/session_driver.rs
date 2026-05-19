//! `FlowSessionDriver` end-to-end throughput.
//!
//! Run with:
//!
//!     cargo bench --bench session_driver \
//!         --features session,reassembler,extractors,test-helpers

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{FlowSessionDriver, FlowSide, PacketView, SessionParser, Timestamp};

/// No-op parser: returns no messages, just measures the driver's
/// per-packet overhead.
#[derive(Default, Clone)]
struct NoopParser;
impl SessionParser for NoopParser {
    type Message = ();
    fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
    fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
}

fn bench_passthrough(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_driver");
    group.throughput(Throughput::Elements(1));
    group.bench_function("passthrough", |b| {
        let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(), NoopParser);
        // 3WHS first so the flow is established before benchmarking.
        let mac = [0u8; 6];
        let syn = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1000,
            0,
            0x02,
            b"",
        );
        let synack = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 2],
            [10, 0, 0, 1],
            80,
            1234,
            5000,
            1001,
            0x12,
            b"",
        );
        let ack = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x10,
            b"",
        );
        for f in &[syn, synack, ack] {
            d.track(PacketView::new(f, Timestamp::default()));
        }
        let payload = vec![b'A'; 1400];
        let data = ipv4_tcp(
            mac,
            mac,
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            1001,
            5001,
            0x18,
            &payload,
        );
        // Benchmark: feed a data segment in a loop, advancing seq.
        let mut seq = 1001u32;
        b.iter(|| {
            let frame = ipv4_tcp(
                mac,
                mac,
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                1234,
                80,
                seq,
                5001,
                0x18,
                &payload,
            );
            black_box(d.track(PacketView::new(&frame, Timestamp::default())));
            seq = seq.wrapping_add(payload.len() as u32);
        });
        // Reference to silence unused-variable warnings.
        let _ = (data, FlowSide::Initiator);
    });
    group.finish();
}

criterion_group!(benches, bench_passthrough);
criterion_main!(benches);
