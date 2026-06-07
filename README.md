# flowscope

[![crates.io](https://img.shields.io/crates/v/flowscope.svg)](https://crates.io/crates/flowscope)
[![docs.rs](https://img.shields.io/docsrs/flowscope)](https://docs.rs/flowscope)
[![CI](https://github.com/p13marc/flowscope/actions/workflows/ci.yml/badge.svg)](https://github.com/p13marc/flowscope/actions)

Passive flow & session tracking for packet capture.

`flowscope` is a runtime-free, cross-platform Rust library for **observing**
what's happening on the wire. It pairs with any source of `&[u8]` frames:
[`netring`](https://crates.io/crates/netring) (Linux AF_PACKET / AF_XDP),
pcap files, tun/tap, eBPF, embedded — anywhere bytes show up.

No tokio, no futures, no async runtime in the core. (For tokio integration,
see `netring`'s `AsyncCapture::flow_stream` etc., which consume this crate's
traits.)

## What's here

```
PacketView   →   FlowExtractor   →   FlowTracker   →   Reassembler   →   SessionParser / DatagramParser
   ↑                                                                              ↓
   anything                                                              typed L7 messages
```

Core (always on):

- `FlowExtractor` trait + built-in extractors (5-tuple, IP-pair, MAC-pair) +
  decap combinators (VLAN, MPLS, VXLAN, GTP-U, GRE) + `AutoDetectEncap`
  combinator + `FlowLabel` IPv6 augmentation.
- `FlowTracker` — bidirectional flow accounting, TCP state machine, idle
  timeouts, LRU eviction.
- `Reassembler` — sync per-(flow, side) hook for TCP byte streams.
- `SessionParser` / `DatagramParser` — typed L7 message parsing per flow.

Protocol parsers + analysis modules (each behind its own feature):

| Feature | What you get |
|---------|--------------|
| `http`  | HTTP/1.x request/response parsing via `HttpParser` (`SessionParser`); `HttpExchangeParser` aggregates a request/response pair into one `HttpExchange` event (0.10) |
| `tls`   | TLS handshake observer (ClientHello/ServerHello/Alert) via `TlsParser` (`SessionParser`) — passive only, no decryption; `TlsHandshakeParser` aggregates a handshake into one event |
| `ja3`   | [JA3](https://github.com/salesforce/ja3) client fingerprinting (sub-feature of `tls`) |
| `ja4`   | [JA4](https://github.com/FoxIO-LLC/ja4) client fingerprinting (sub-feature of `tls`) |
| `dns`   | DNS message parser, per-flow query/response correlator. UDP via `DnsUdpParser` (`DatagramParser`); TCP via `DnsTcpParser` (`SessionParser`, RFC 1035 §4.2.2 length-framed); `DnsExchangeParser` aggregates query+response into one `DnsExchange` event (0.10) |
| `icmp`  | ICMPv4/v6 message parser (`IcmpParser` — `DatagramParser`) |
| `pcap`  | pcap file source for offline replay |
| `emit`  | `flowscope::emit` — `FlowEventCsvWriter` + `ZeekConnLogWriter` (RFC-4180 quoting, `conn.log` headers) (0.10) |
| `emit-ndjson` | adds `FlowEventNdjsonWriter` to `emit`; pulls in `serde_json` (0.10) |
| `aggregate` | `flowscope::aggregate` — `Histogram` + `Percentile` (t-digest) for SLO baselining (0.10) |
| `l7`    | Umbrella: `http` + `tls` + `dns` + `icmp` |
| `full`  | All of the above (incl. `ja3`, `ja4`, `pcap`, `serde`, observability, `emit`, `emit-ndjson`, `aggregate`) |

Plus always-on modules that don't need a feature flag:

- **`flowscope::correlate`** — cross-flow correlation primitives:
  `TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`,
  `BurstDetector`, `TopK`, `Ewma`, `SequencePattern`.
- **`flowscope::detect`** — `shannon_entropy`, `is_high_entropy`,
  `is_base64ish`, `is_hex_string`, `hamming_distance`,
  `ngram_distribution`, plus `detect::signatures` (10
  magic-byte recognizers + registry).
- **`flowscope::well_known`** — curated `(L4Proto, port)` →
  short-label table (~70 entries) for protocol-by-port labelling.
- **`flowscope::layers`** — zero-copy per-packet layered view
  (Ethernet/VLAN/MPLS/IPv4/IPv6/ARP/TCP/UDP/ICMPv4/ICMPv6/
  GRE/VXLAN/GTP-U) with `LayerParser` + `LayerStack` zero-alloc
  fast path.

## Quick start

```toml
[dependencies]
flowscope = { version = "0.9", features = ["full"] }
```

MSRV is Rust 1.88.

One import, one builder chain, one iterator — the high-level
`Pipeline` entry point introduced in 0.9.0:

```rust,no_run
use flowscope::prelude::*;
use flowscope::http::HttpParser;

# fn main() -> flowscope::Result<()> {
let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
    .session(HttpParser::default())
    .build();

for event in pipeline.run_pcap("trace.pcap")? {
    if let Event::Tcp(SessionEvent::Application { message, .. }) = event? {
        println!("{message:?}");
    }
}
# Ok(()) }
```

`Pipeline` bundles the common driver setup with sensible defaults
(anomalies emitted, monotonic timestamps for offline replay).
For per-flow user state, custom drainers, or multiple parsers
per L4, drop to `FlowSessionDriver` / `FlowDatagramDriver`
directly.

### Per-packet introspection

The 0.9 `flowscope::layers` module exposes a zero-copy view of a
frame with both direct accessors and a dynamic walk:

```rust,no_run
use flowscope::PacketView;
use flowscope::layers::LayerKind;

# fn ex(pv: PacketView<'_>) -> flowscope::Result<()> {
let layers = pv.layers()?;

// Direct accessors — the common case.
if let Some(tcp) = layers.tcp() {
    println!("seq={} window={}", tcp.seq(), tcp.window());
}
if let Some(vlan) = layers.vlan() {
    println!("vid={}", vlan.vid());
}

// Dynamic walk — "show me everything".
for layer in layers.iter() {
    println!("{} ({}B)", layer.kind(), layer.bytes().len());
}
# Ok(()) }
```

### Custom protocols

For an end-to-end example of writing a `SessionParser` for your own
wire format — including the synchronous offline pcap path via
[`FlowSessionDriver`](https://docs.rs/flowscope/latest/flowscope/session_driver/struct.FlowSessionDriver.html) —
see `examples/length_prefixed_pcap.rs`. The example demonstrates a
length-prefixed binary protocol (PSMSG-shaped) with two
variable-length markers and is paired with a deterministic pcap
fixture under `tests/fixtures/length_prefixed/`.

## Tokio integration

`flowscope` itself is runtime-free. To consume a live capture into a stream
of `FlowEvent` / `SessionEvent` via tokio, use [`netring`](https://crates.io/crates/netring):

```rust,no_run
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::http::HttpParser;
use futures::StreamExt;

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let mut s = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());
while let Some(evt) = s.next().await { /* ... */ }
# Ok(()) }
```

## Status

0.10.0 (in progress) — DX polish + structured-output cycle on
top of the 0.9 surface. Modules: `flowscope::emit` (CSV /
NDJSON / Zeek `conn.log` writers), `flowscope::aggregate`
(Histogram / Percentile), `flowscope::detect` (entropy
primitives + 10-protocol signature recognizers),
`flowscope::well_known` (curated `(proto, port) → label`
table), `correlate` extensions (`TimeBucketedSet` /
`BurstDetector` / `TopK` / `Ewma`), parser ergonomics
(`AccumulatingSessionParser` / `PerDatagramParser` /
`BufferedFrameDrain`), exchange aggregators
(`HttpExchangeParser` / `DnsExchangeParser`), rustdoc
landing pages on every L7 module + 9 new HTTP accessors,
and a quick-win helper sweep across `Timestamp` /
`FlowStats` / `EndReason` / `LayerKind` / `Layer` /
`LayerStack` / `KeyIndexed`. Centerpiece — driver+event
unification (`Driver<E, M>` + `Event<K, M>` replacing the
6-driver / 4-event surface) — still in flight.

0.9.0 (also in flight) — biggest release since 0.1:
high-level `Pipeline` entry point, public
`flowscope::layers` per-packet view (with tunnel walking
+ zero-alloc fast path), unified `flowscope::Error`,
`flowscope::correlate` cross-flow primitives,
`FlowMultiSessionDriver` composite driver,
`SegmentBufferReassembler` OOO TCP hole-fill, JA4 TLS
fingerprint + `TlsHandshakeParser` aggregator,
`FlowTracker::with_auto_sweep` for live/offline parity,
`flowscope::prelude`, MSRV bumped to 1.88.

0.8.0 was the last point release: serde wire-format lock,
ICMP correlation helpers, programmatic flow termination,
per-flow snapshot iterator, multi-protocol monitor recipe.

Core flow APIs (`FlowExtractor`, `FlowTracker`, `Reassembler`,
`SessionParser`, `DatagramParser`) are settled; public structs
and enums are `#[non_exhaustive]` so future variants and fields
are additive. See [`CHANGELOG.md`](CHANGELOG.md) for the
release history.

See [`docs/getting-started.md`](docs/getting-started.md) for a
hello-world,
[`docs/concepts.md`](docs/concepts.md) for the conceptual model,
[`docs/recipes.md`](docs/recipes.md) for worked patterns,
[`docs/observability.md`](docs/observability.md) for metrics +
tracing, [`examples/README.md`](examples/README.md) for a
catalog of 25+ runnable examples (port-scan detection, IoC
extraction, Zeek-style conn.log, TLS handshake inventory,
per-packet inspection, NDJSON export, custom protocols, …),
and [`CHANGELOG.md`](CHANGELOG.md) for the per-release feature
list and migration recipes.

## License

MIT OR Apache-2.0, your choice.
