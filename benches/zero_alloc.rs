//! Plan-118 Phase 0 — allocation-counting bench harness.
//!
//! Five measurements ground every subsequent phase in measured
//! (not estimated) numbers. Each bench prints `allocs/iter` and
//! `bytes/iter` outside Criterion's timing.
//!
//! Run with:
//!
//! ```sh
//! cargo bench --bench zero_alloc \
//!   --features "session,reassembler,extractors,http,dns,tls,test-helpers"
//! ```

#![allow(unused_imports)]

#[path = "support/counting_allocator.rs"]
mod counting_allocator;

use counting_allocator::CountingAllocator;
use criterion::{black_box, criterion_group, criterion_main, Criterion};

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

use flowscope::{
    extract::{
        parse::test_frames::{ipv4_tcp, ipv4_udp},
        FiveTuple,
    },
    PacketView, Timestamp,
};

const N_PACKETS: usize = 10_000;

fn synth_tcp_stream() -> Vec<Vec<u8>> {
    (0..N_PACKETS as u16)
        .map(|i| {
            let sport = 40000 + (i % 1000);
            ipv4_tcp(
                [1; 6],
                [2; 6],
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                sport,
                80,
                u32::from(i),
                0,
                0x18,
                b"x",
            )
        })
        .collect()
}

#[cfg(all(
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    feature = "http"
))]
fn bench_track_into_with_slots_steady_state(c: &mut Criterion) {
    use flowscope::{
        driver::{Driver, Event},
        extract::FiveTupleKey,
        http::HttpParser,
    };

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let _s1 = builder.session_on_ports(HttpParser::default(), [80]);
    let _s2 = builder.session_on_ports(HttpParser::default(), [8080]);
    let _s3 = builder.session_on_ports(HttpParser::default(), [443]);
    let _s4 = builder.session_on_ports(HttpParser::default(), [8443]);
    let _s5 = builder.session_on_ports(HttpParser::default(), [3000]);
    let mut driver = builder.build();

    let frames = synth_tcp_stream();
    let mut scratch: Vec<Event<FiveTupleKey>> = Vec::with_capacity(8);

    for frame in frames.iter().take(128) {
        let v = PacketView::new(frame, Timestamp::default());
        scratch.clear();
        driver.track_into(v, &mut scratch);
        black_box(&scratch);
    }

    c.bench_function("track_into_5_slots_steady_state", |b| {
        b.iter(|| {
            for frame in &frames {
                let v = PacketView::new(frame, Timestamp::default());
                scratch.clear();
                driver.track_into(v, &mut scratch);
                black_box(&scratch);
            }
        })
    });

    CountingAllocator::reset();
    for frame in &frames {
        let v = PacketView::new(frame, Timestamp::default());
        scratch.clear();
        driver.track_into(v, &mut scratch);
        black_box(&scratch);
    }
    println!(
        "track_into_5_slots:       {:.3} allocs/pkt, {} bytes/pkt over {} pkts",
        CountingAllocator::allocs_per(N_PACKETS),
        CountingAllocator::bytes() / N_PACKETS,
        N_PACKETS,
    );
}

#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
fn bench_track_into_steady_state(c: &mut Criterion) {
    use flowscope::{
        driver::{Driver, Event},
        extract::FiveTupleKey,
    };

    let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
    let frames = synth_tcp_stream();
    let mut scratch: Vec<Event<FiveTupleKey>> = Vec::with_capacity(8);

    for frame in frames.iter().take(64) {
        let v = PacketView::new(frame, Timestamp::default());
        scratch.clear();
        driver.track_into(v, &mut scratch);
        black_box(&scratch);
    }

    c.bench_function("track_into_steady_state", |b| {
        b.iter(|| {
            for frame in &frames {
                let v = PacketView::new(frame, Timestamp::default());
                scratch.clear();
                driver.track_into(v, &mut scratch);
                black_box(&scratch);
            }
        })
    });

    CountingAllocator::reset();
    for frame in &frames {
        let v = PacketView::new(frame, Timestamp::default());
        scratch.clear();
        driver.track_into(v, &mut scratch);
        black_box(&scratch);
    }
    println!(
        "track_into_steady_state: {:.3} allocs/pkt, {} bytes/pkt over {} pkts",
        CountingAllocator::allocs_per(N_PACKETS),
        CountingAllocator::bytes() / N_PACKETS,
        N_PACKETS,
    );

    CountingAllocator::reset();
    for frame in &frames {
        let v = PacketView::new(frame, Timestamp::default());
        let _ = black_box(driver.track(v));
    }
    println!(
        "track legacy wrapper:    {:.3} allocs/pkt, {} bytes/pkt over {} pkts",
        CountingAllocator::allocs_per(N_PACKETS),
        CountingAllocator::bytes() / N_PACKETS,
        N_PACKETS,
    );
}

#[cfg(all(feature = "session", feature = "http"))]
fn bench_parser_feed_steady_state(c: &mut Criterion) {
    use flowscope::{
        http::{HttpMessage, HttpParser},
        SessionParser,
    };

    let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n";
    let mut parser = HttpParser::default();
    let mut scratch: Vec<HttpMessage> = Vec::with_capacity(4);

    for _ in 0..32 {
        scratch.clear();
        parser.feed_initiator(req, Timestamp::default(), &mut scratch);
    }

    c.bench_function("parser_feed_steady_state", |b| {
        b.iter(|| {
            scratch.clear();
            parser.feed_initiator(black_box(req), Timestamp::default(), &mut scratch);
            black_box(&scratch);
        })
    });

    CountingAllocator::reset();
    for _ in 0..N_PACKETS {
        scratch.clear();
        parser.feed_initiator(req, Timestamp::default(), &mut scratch);
        black_box(&scratch);
    }
    println!(
        "parser_feed_steady_state: {:.3} allocs/call, {} bytes/call over {} calls",
        CountingAllocator::allocs_per(N_PACKETS),
        CountingAllocator::bytes() / N_PACKETS,
        N_PACKETS,
    );
}

#[cfg(feature = "http")]
fn bench_http_request_parse(c: &mut Criterion) {
    use flowscope::{
        http::{HttpMessage, HttpParser},
        SessionParser,
    };

    let req = b"GET /api/v1/users?id=42 HTTP/1.1\r\n\
                 Host: api.example.com\r\n\
                 User-Agent: Mozilla/5.0 (X11; Linux x86_64) bench\r\n\
                 Accept: application/json\r\n\
                 Accept-Language: en-US,en;q=0.9\r\n\
                 Accept-Encoding: gzip, deflate, br\r\n\
                 Cookie: session=abc123; theme=dark\r\n\
                 Referer: https://example.com/dashboard\r\n\
                 Content-Type: application/x-www-form-urlencoded\r\n\
                 Content-Length: 0\r\n\r\n";

    c.bench_function("http_request_parse", |b| {
        b.iter(|| {
            let mut parser = HttpParser::default();
            let mut msgs: Vec<HttpMessage> = Vec::new();
            parser.feed_initiator(black_box(req), Timestamp::default(), &mut msgs);
            black_box(&msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = HttpParser::default();
        let mut msgs: Vec<HttpMessage> = Vec::new();
        parser.feed_initiator(req, Timestamp::default(), &mut msgs);
        black_box(&msgs);
    }
    println!(
        "http_request_parse: {:.3} allocs/parse, {} bytes/parse over {} parses",
        CountingAllocator::allocs_per(N),
        CountingAllocator::bytes() / N,
        N,
    );
}

#[cfg(feature = "dns")]
fn bench_dns_response_5_txt(c: &mut Criterion) {
    use flowscope::{
        dns::{DnsMessage, DnsUdpParser},
        DatagramParser, FlowSide,
    };

    let mut pkt = vec![
        0, 0, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0, 7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3,
        b'c', b'o', b'm', 0, 0, 16, 0, 1,
    ];
    for s in &[
        b"v=spf1 -all" as &[u8],
        b"google-site-verification=xxx",
        b"foo",
        b"bar",
        b"baz",
    ] {
        pkt.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0x0e, 0x10]);
        let rdlen = 1 + s.len();
        pkt.extend_from_slice(&[(rdlen >> 8) as u8, rdlen as u8]);
        pkt.push(s.len() as u8);
        pkt.extend_from_slice(s);
    }

    c.bench_function("dns_response_5_txt", |b| {
        b.iter(|| {
            let mut parser = DnsUdpParser::default();
            let mut msgs: Vec<DnsMessage> = Vec::new();
            parser.parse(
                black_box(&pkt),
                FlowSide::Responder,
                Timestamp::default(),
                &mut msgs,
            );
            black_box(&msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = DnsUdpParser::default();
        let mut msgs: Vec<DnsMessage> = Vec::new();
        parser.parse(&pkt, FlowSide::Responder, Timestamp::default(), &mut msgs);
        black_box(&msgs);
    }
    println!(
        "dns_response_5_txt: {:.3} allocs/parse, {} bytes/parse over {} parses",
        CountingAllocator::allocs_per(N),
        CountingAllocator::bytes() / N,
        N,
    );
}

#[cfg(feature = "tls")]
fn bench_tls_client_hello(c: &mut Criterion) {
    use flowscope::{
        tls::{TlsMessage, TlsParser},
        SessionParser,
    };

    let hello: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x35, 0x01, 0x00, 0x00, 0x31, 0x03, 0x03, 0, 1, 2, 3, 4, 5, 6, 7,
        8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30,
        31, 0x00, 0x00, 0x02, 0xc0, 0x2c, 0x01, 0x00, 0x00, 0x06, 0x00, 0x2b, 0x00, 0x02, 0x03,
        0x04,
    ];

    c.bench_function("tls_client_hello", |b| {
        b.iter(|| {
            let mut parser = TlsParser::default();
            let mut msgs: Vec<TlsMessage> = Vec::new();
            parser.feed_initiator(black_box(hello), Timestamp::default(), &mut msgs);
            black_box(&msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = TlsParser::default();
        let mut msgs: Vec<TlsMessage> = Vec::new();
        parser.feed_initiator(hello, Timestamp::default(), &mut msgs);
        black_box(&msgs);
    }
    println!(
        "tls_client_hello: {:.3} allocs/parse, {} bytes/parse over {} parses",
        CountingAllocator::allocs_per(N),
        CountingAllocator::bytes() / N,
        N,
    );
}

#[cfg(all(
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    feature = "http"
))]
criterion_group!(
    driver_benches,
    bench_track_into_steady_state,
    bench_track_into_with_slots_steady_state
);

#[cfg(all(
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    not(feature = "http")
))]
criterion_group!(driver_benches, bench_track_into_steady_state);

#[cfg(all(feature = "session", feature = "http"))]
criterion_group!(
    parser_benches,
    bench_parser_feed_steady_state,
    bench_http_request_parse
);

#[cfg(feature = "dns")]
criterion_group!(dns_benches, bench_dns_response_5_txt);

#[cfg(feature = "tls")]
criterion_group!(tls_benches, bench_tls_client_hello);

#[cfg(all(
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    feature = "http",
    feature = "dns",
    feature = "tls",
))]
criterion_main!(driver_benches, parser_benches, dns_benches, tls_benches);

#[cfg(not(all(
    feature = "session",
    feature = "reassembler",
    feature = "extractors",
    feature = "http",
    feature = "dns",
    feature = "tls",
)))]
fn main() {
    eprintln!(
        "zero_alloc bench requires features: \
         session, reassembler, extractors, http, dns, tls."
    );
}
