//! Plan-118 Phase 0 — allocation-counting bench harness.
//!
//! Five measurements ground every subsequent phase in measured
//! (not estimated) numbers. Each bench prints `allocs/iter` and
//! `bytes/iter` outside Criterion's timing, so the gate numbers
//! land in the bench stdout regardless of timing variance.
//!
//! Run with:
//!
//! ```sh
//! cargo bench --bench zero_alloc \
//!   --features "session,reassembler,extractors,http,dns,tls,icmp,test-helpers"
//! ```
//!
//! Five rows are reported (see plan 118 Baseline numbers table):
//!
//! | Row | What | Phase that lands the target |
//! |-----|------|-----------------------------|
//! | `track_into_steady_state` | 5-slot Driver, no L7 traffic | 119 |
//! | `parser_feed_steady_state` | HttpParser feed loop | 119 |
//! | `http_request_parse` | one HTTP/1.1 GET | 120 |
//! | `dns_response_5_txt` | one DNS response w/ 5 TXT | 120 |
//! | `tls_client_hello` | one TLS 1.3 ClientHello | 120 |
//! | `typed_slot_dispatch` | parsed L7 messages dispatched | 121 |
//! | `emit_packet_details_mode` | track_into with frame enrich | 118-P4 |

#![allow(unused_imports)]

#[path = "support/counting_allocator.rs"]
mod counting_allocator;

use counting_allocator::CountingAllocator;
use criterion::{Criterion, black_box, criterion_group, criterion_main};

#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;

use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::{ipv4_tcp, ipv4_udp};
use flowscope::{PacketView, Timestamp};

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

#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
fn bench_track_into_steady_state(c: &mut Criterion) {
    use flowscope::driver_unified::Driver;

    let mut driver = Driver::<_, ()>::builder(FiveTuple::bidirectional()).build();
    let frames = synth_tcp_stream();

    // Warmup — let internal Vec capacities grow once.
    for frame in frames.iter().take(64) {
        let v = PacketView::new(frame, Timestamp::default());
        black_box(driver.track(v));
    }

    c.bench_function("track_steady_state", |b| {
        b.iter(|| {
            for frame in &frames {
                let v = PacketView::new(frame, Timestamp::default());
                black_box(driver.track(v));
            }
        })
    });

    // Outside-Criterion alloc count: one full N_PACKETS sweep.
    CountingAllocator::reset();
    for frame in &frames {
        let v = PacketView::new(frame, Timestamp::default());
        let _ = black_box(driver.track(v));
    }
    println!(
        "track_steady_state: {:.3} allocs/pkt, {} bytes/pkt over {} pkts",
        CountingAllocator::allocs_per(N_PACKETS),
        CountingAllocator::bytes() / N_PACKETS,
        N_PACKETS,
    );
}

#[cfg(all(feature = "session", feature = "http"))]
fn bench_parser_feed_steady_state(c: &mut Criterion) {
    use flowscope::SessionParser;
    use flowscope::http::HttpParser;

    let req = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: bench\r\nAccept: */*\r\n\r\n";
    let mut parser = HttpParser::default();

    // Warmup — parser's internal Vec capacity stabilises.
    for _ in 0..32 {
        let _ = parser.feed_initiator(req, Timestamp::default());
    }

    c.bench_function("parser_feed_steady_state", |b| {
        b.iter(|| {
            let msgs = parser.feed_initiator(black_box(req), Timestamp::default());
            black_box(msgs);
        })
    });

    CountingAllocator::reset();
    for _ in 0..N_PACKETS {
        let _ = black_box(parser.feed_initiator(req, Timestamp::default()));
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
    use flowscope::SessionParser;
    use flowscope::http::HttpParser;

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
            let msgs = parser.feed_initiator(black_box(req), Timestamp::default());
            black_box(msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = HttpParser::default();
        let _ = black_box(parser.feed_initiator(req, Timestamp::default()));
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
    use flowscope::DatagramParser;
    use flowscope::FlowSide;
    use flowscope::dns::DnsUdpParser;

    // Synthesize a tiny DNS response with 5 TXT records.
    // Header: id=0, flags=0x8180, q=1, an=5, ns=0, ar=0.
    let mut pkt = vec![
        0, 0, 0x81, 0x80, 0, 1, 0, 5, 0, 0, 0, 0,
        // Question: example.com TXT IN
        7, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
        3, b'c', b'o', b'm', 0,
        0, 16, 0, 1,
    ];
    // 5 TXT answers, each pointing back to the question name (compression).
    for s in &[b"v=spf1 -all" as &[u8], b"google-site-verification=xxx", b"foo", b"bar", b"baz"] {
        pkt.extend_from_slice(&[0xc0, 12, 0, 16, 0, 1, 0, 0, 0x0e, 0x10]);
        let rdlen = 1 + s.len();
        pkt.extend_from_slice(&[(rdlen >> 8) as u8, rdlen as u8]);
        pkt.push(s.len() as u8);
        pkt.extend_from_slice(s);
    }

    c.bench_function("dns_response_5_txt", |b| {
        b.iter(|| {
            let mut parser = DnsUdpParser::default();
            let msgs = parser.parse(
                black_box(&pkt),
                FlowSide::Responder,
                Timestamp::default(),
            );
            black_box(msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = DnsUdpParser::default();
        let _ = black_box(parser.parse(
            &pkt,
            FlowSide::Responder,
            Timestamp::default(),
        ));
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
    use flowscope::SessionParser;
    use flowscope::tls::TlsParser;

    // Minimal TLS 1.2 ClientHello captured from a real handshake.
    // Pre-baked to keep the bench independent of network resources.
    let hello: &[u8] = &[
        0x16, 0x03, 0x01, 0x00, 0x35, // record header
        0x01, 0x00, 0x00, 0x31, // handshake header
        0x03, 0x03, // legacy_version
        // 32-byte random
        0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31,
        0x00, // session_id_length = 0
        0x00, 0x02, 0xc0, 0x2c, // cipher_suites length=2, one cipher
        0x01, 0x00, // compression_methods length=1, value=null
        0x00, 0x06, // extensions length=6
        0x00, 0x2b, 0x00, 0x02, 0x03, 0x04, // supported_versions ext (TLS 1.3)
    ];

    c.bench_function("tls_client_hello", |b| {
        b.iter(|| {
            let mut parser = TlsParser::default();
            let msgs = parser.feed_initiator(black_box(hello), Timestamp::default());
            black_box(msgs);
        })
    });

    CountingAllocator::reset();
    const N: usize = 1000;
    for _ in 0..N {
        let mut parser = TlsParser::default();
        let _ = black_box(parser.feed_initiator(hello, Timestamp::default()));
    }
    println!(
        "tls_client_hello: {:.3} allocs/parse, {} bytes/parse over {} parses",
        CountingAllocator::allocs_per(N),
        CountingAllocator::bytes() / N,
        N,
    );
}

// ── Criterion plumbing ──────────────────────────────────────────────────

#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
criterion_group!(
    name = driver_benches;
    config = Criterion::default();
    targets = bench_track_into_steady_state,
);

#[cfg(all(feature = "session", feature = "http"))]
criterion_group!(
    name = parser_benches;
    config = Criterion::default();
    targets = bench_parser_feed_steady_state, bench_http_request_parse,
);

#[cfg(feature = "dns")]
criterion_group!(
    name = dns_benches;
    config = Criterion::default();
    targets = bench_dns_response_5_txt,
);

#[cfg(feature = "tls")]
criterion_group!(
    name = tls_benches;
    config = Criterion::default();
    targets = bench_tls_client_hello,
);

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
         session, reassembler, extractors, http, dns, tls. \
         Re-run with `--features <list>` or `--all-features`."
    );
}
