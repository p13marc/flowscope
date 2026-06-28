//! Typed `Driver<E>` session-slot end-to-end throughput.
//!
//! Benchmarks the same TCP session-dispatch path that the (now
//! crate-private) `FlowSessionDriver` engine drives, via the
//! public typed [`flowscope::driver::Driver`] with a single
//! session slot.
//!
//! Run with:
//!
//!     cargo bench --bench session_driver \
//!         --features session,reassembler,extractors,test-helpers

use criterion::{Criterion, Throughput, black_box, criterion_group, criterion_main};
use flowscope::{
    FlowSide, PacketView, SessionParser, Timestamp,
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey, parse::test_frames::ipv4_tcp},
};

/// No-op parser: returns no messages, just measures the driver's
/// per-packet overhead.
#[derive(Default, Clone)]
struct NoopParser;
impl SessionParser for NoopParser {
    type Message = ();
    fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
    fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp, _out: &mut Vec<()>) {}
}

fn bench_passthrough(c: &mut Criterion) {
    let mut group = c.benchmark_group("session_driver");
    group.throughput(Throughput::Elements(1));
    group.bench_function("passthrough", |b| {
        let mut builder = Driver::builder(FiveTuple::bidirectional());
        let mut slot = builder.session_on_ports(NoopParser, [80]);
        let mut d = builder.build();

        let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
        let mut msgs: Vec<SlotMessage<(), FiveTupleKey>> = Vec::new();

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
            d.track_into(PacketView::new(f, Timestamp::default()), &mut events);
            events.clear();
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
            events.clear();
            d.track_into(PacketView::new(&frame, Timestamp::default()), &mut events);
            slot.drain(&mut msgs);
            black_box((&events, &msgs));
            msgs.clear();
            seq = seq.wrapping_add(payload.len() as u32);
        });
        // Reference to silence unused-variable warnings.
        let _ = (data, FlowSide::Initiator);
    });
    group.finish();
}

criterion_group!(benches, bench_passthrough);
criterion_main!(benches);
