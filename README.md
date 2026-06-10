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
| `http`  | HTTP/1.x request/response parsing via `HttpParser` (`SessionParser`); `HttpExchangeParser` aggregates a request/response pair into one `HttpExchange` event |
| `tls`   | TLS handshake observer (ClientHello/ServerHello/Alert) via `TlsParser` (`SessionParser`) — passive only, no decryption; `TlsHandshakeParser` aggregates a handshake into one event |
| `tls-fingerprints` | [JA3](https://github.com/salesforce/ja3) + [JA4](https://github.com/FoxIO-LLC/ja4) client TLS fingerprinting (sub-feature of `tls`) |
| `dns`   | DNS message parser, per-flow query/response correlator. UDP via `DnsUdpParser` (`DatagramParser`); TCP via `DnsTcpParser` (`SessionParser`, RFC 1035 §4.2.2 length-framed); `DnsExchangeParser` aggregates query+response into one `DnsExchange` event |
| `icmp`  | ICMPv4/v6 message parser (`IcmpParser` — `DatagramParser`) |
| `pcap`  | pcap file source for offline replay |
| `emit`  | `flowscope::emit` — `FlowEventCsvWriter` + `ZeekConnLogWriter` (RFC-4180 quoting, `conn.log` headers) |
| `emit-ndjson` | adds `FlowEventNdjsonWriter` to `emit`; pulls in `serde_json` |
| `emit-eve` | adds `EveJsonWriter` — Suricata 7.x EVE JSON for Filebeat / Splunk / Tenzir / ECS pipelines (0.12) |
| `chrono` | `From<DateTime<Utc>>` + `TryFrom<Timestamp>` for `chrono::DateTime<Utc>` interop on `Timestamp` (0.12) |
| `aggregate` | `flowscope::aggregate` — `Histogram` + `Percentile` (t-digest) for SLO baselining |
| `l7`    | Umbrella: `http` + `tls` + `dns` + `icmp` |
| `full`  | All of the above (incl. `tls-fingerprints`, `pcap`, `serde`, observability, `emit`, `emit-ndjson`, `emit-eve`, `aggregate`, `chrono`) |

Plus always-on modules that don't need a feature flag:

- **`flowscope::driver`** — typed `Driver<E>` with per-parser
  `SlotHandle<M, K>` drain handles. **`Send + Sync` since 0.12**
  — drain from a tokio task on a separate thread while the
  driver runs on a dedicated capture thread.
- **`flowscope::AnomalyFields`** (0.12) — structured key + anomaly
  accessors (`src_ip` / `dest_port` / `proto_str` / `anomaly_type` …)
  consumed by `EveJsonWriter`. Impl on `FiveTupleKey`, `L4Proto`,
  `AnomalyKind` ships out of the box; custom keys opt in.
- **`flowscope::correlate`** — cross-flow correlation primitives:
  `TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`,
  `BurstDetector`, `TopK`, `Ewma`, `SequencePattern`. All bucketed
  types ship `new_unbounded` convenience constructors (0.12).
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
flowscope = { version = "0.12", features = ["full"] }
```

MSRV is Rust 1.88.

One builder chain, one typed slot handle per protocol. The
`Driver<E>` shape introduced in 0.11 + slot handles that are
`Send + Sync` since 0.12:

```rust,no_run
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::PacketView;

# fn main() -> flowscope::Result<()> {
let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http: flowscope::driver::SlotHandle<HttpMessage, FiveTupleKey> =
    builder.session_on_ports(HttpParser::default(), [80, 8080]);
let mut driver = builder.build();

let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
let mut msgs:   Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

for owned in PcapFlowSource::open("trace.pcap")?.views() {
    let owned = owned?;
    events.clear();
    msgs.clear();
    driver.track_into(PacketView::from(&owned), &mut events);
    http.drain(&mut msgs);
    for m in &msgs {
        println!("{:?} {:?}", m.side, m.message);
    }
}
# Ok(()) }
```

Per packet: `driver.track_into` appends flow-lifecycle events
into your `events` Vec; `http.drain` appends parsed messages
into your `msgs` Vec. Zero allocation at the surface in steady
state.

For per-flow user state on the central tracker, drop to
`FlowDriver`. For raw sync session/datagram primitives, see
`FlowSessionDriver` / `FlowDatagramDriver`. For deferred
extractor selection (consumer-built monitor chains), use
`Driver::deferred()` → `.build_with(ext)` (0.12).

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

0.12.0 — Cross-thread + structured-output cycle.

- **`SlotHandle<M, K>` is `Send + Sync`** — pre-1.0 break.
  Backing storage moved from `Rc<RefCell<Vec<…>>>` to
  `Arc<crossbeam_queue::SegQueue<…>>` (lock-free MPMC).
  Move handles to a tokio task, share via `Arc` with multiple
  drainers, drain from a worker thread. Bench gate holds:
  `track_into_5_slots: 0.000 allocs/pkt` in steady state.
- **`flowscope::emit::EveJsonWriter`** behind `emit-eve` —
  Suricata 7.x EVE JSON for Filebeat / Splunk / Tenzir / ECS
  pipelines. Three event types: `flow` / `anomaly` / `stats`.
- **`Driver::deferred()`** + `DeferredDriverBuilder::build_with(ext)`
  — late extractor selection for consumer-built monitor chains.
  Compile-time guarantee preserved (no panicking `build()`).
- **`flowscope::AnomalyFields` trait** — structured field
  access on flow keys / anomaly kinds. Shipped impls on
  `FiveTupleKey`, `L4Proto`, `AnomalyKind`; custom keys opt in.
- **`Timestamp::write_iso8601` / `to_iso8601`** — alloc-free
  RFC 3339 / ISO 8601 rendering. Optional `chrono` feature
  adds `From<DateTime<Utc>>` + `TryFrom<Timestamp>` interop.
- **`correlate::*::new_unbounded` ctors** on
  `TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`.

0.11.0 — Zero-allocation cycle. Collapsed the closed-`M`
`Driver<E, M>` shape into the typed-slot-drain shape:
`Driver<E>` emits flow-lifecycle `Event<K>` only; per-parser
typed messages flow through `SlotHandle<M, K>` returned at
registration time. `Driver::track_into` with 5 HTTP slots:
**0.000 allocs/packet** in steady state. HTTP/1.1 GET parse:
**28 → 7 allocs**. Parser API break:
`SessionParser`/`DatagramParser` take `&mut Vec<Self::Message>`.

0.10.0 — DX polish + structured-output cycle. Modules:
`flowscope::emit` (CSV / NDJSON / Zeek `conn.log`),
`flowscope::aggregate` (Histogram / Percentile),
`flowscope::detect` (entropy + 10 signature recognizers),
`flowscope::well_known` (curated `(proto, port) → label`),
`correlate` extensions, parser ergonomics
(`AccumulatingSessionParser` / `PerDatagramParser` /
`BufferedFrameDrain`), exchange aggregators
(`HttpExchangeParser` / `DnsExchangeParser`).

Core flow APIs (`FlowExtractor`, `FlowTracker`, `Reassembler`,
`SessionParser`, `DatagramParser`) are settled; public structs
and enums are `#[non_exhaustive]` so future variants and fields
are additive. See [`CHANGELOG.md`](CHANGELOG.md) for the
release history and
[`docs/migration-0.11-to-0.12.md`](docs/migration-0.11-to-0.12.md)
for the 0.11 → 0.12 cheat sheet.

See [`docs/getting-started.md`](docs/getting-started.md) for a
hello-world,
[`docs/concepts.md`](docs/concepts.md) for the conceptual model,
[`docs/recipes.md`](docs/recipes.md) for worked patterns,
[`docs/observability.md`](docs/observability.md) for metrics +
tracing, [`docs/eve-format.md`](docs/eve-format.md) for the
Suricata EVE schema mapping (0.12),
[`examples/README.md`](examples/README.md) for a catalog of
runnable examples (port-scan detection, IoC extraction,
Zeek-style conn.log, EVE JSON, TLS handshake inventory,
per-packet inspection, NDJSON export, custom protocols, …),
and [`CHANGELOG.md`](CHANGELOG.md) for the per-release feature
list and migration recipes.

## License

MIT OR Apache-2.0, your choice.
