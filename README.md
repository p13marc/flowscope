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
| `chrono` | Infallible `From` interop in both directions between `Timestamp` and `chrono::DateTime<Utc>` (0.12) |
| `file-hash` | `flowscope::detect::file::{Sha256Sink, Md5Sink, FileType}` — streaming hashes + magic-byte MIME classification (0.12) |
| `aggregate` | `flowscope::aggregate` — `Histogram` + `Percentile` (t-digest) for SLO baselining |
| `l7`    | Umbrella: `http` + `tls` + `dns` + `icmp` |
| `full`  | All of the above (incl. `tls-fingerprints`, `pcap`, `serde`, observability, `emit`, `emit-ndjson`, `emit-eve`, `aggregate`, `chrono`, `file-hash`) |

Plus always-on modules that don't need a feature flag:

- **`flowscope::driver`** — typed `Driver<E>` with per-parser
  `SlotHandle<M, K>` drain handles. The handle has been
  `Send + Sync` since 0.12; **the whole `Driver<E>` is
  `Send + Sync` since 0.13** — `tokio::spawn(driver_task)` on
  the default multi-thread runtime just works. The 0.12
  CHANGELOG claimed `Driver<E>` was `!Send` because of
  `Rc<RefCell>` interior mutability; that was incorrect, the
  real `!Send` source was a missing `+ Send` bound on the
  internal slot trait object. Fixed structurally in 0.13 — no
  `unsafe`, no opt-in knob, no runtime overhead.
- **`flowscope::driver::BroadcastSlotHandle<M, K>`** (0.13) —
  fan-out sibling of `SlotHandle`. `Clone` produces a fresh
  subscriber that sees **every** message (not a competitive
  consumer). Register via
  `DriverBuilder::session_on_ports_broadcast_each`. Backed by
  `Arc<BroadcastInner>` with a `Mutex<Vec<Weak<SegQueue<…>>>>`
  subscriber list; dead subscribers prune lazily on push. Use
  when multiple downstream consumers each need their own copy
  of every message (logger + metrics + sink).
- **`flowscope::OwnedAnomaly` + `flowscope::DetectorScore`** (0.13) —
  canonical owned detector-output value (`kind` slug +
  `Severity` + `Timestamp` + flattened 5-tuple + `SmallVec`-
  backed observations + metrics) plus a small output-side
  trait every shipped detector score (`ScanScore<K>`,
  `BeaconScore<K>`, `DgaScore`) implements. Uniform routing
  through `EveJsonWriter::write_owned_anomaly` (Suricata EVE
  with `anomaly.labels` + `anomaly.metrics` shapes) and
  `FlowEventNdjsonWriter::write_owned_anomaly`. New
  `EveOptions::custom_anomaly_type` field (default
  `"applayer"`) for non-bridged emissions.
- **`flowscope::correlate::FlowStateMap<T, K>`** (0.13) —
  per-flow typed state. Auto-evicts on `FlowEvent::Ended`;
  TTL sweep. Defaults `K` to `FiveTupleKey`. Layered over
  `KeyIndexed<K, T>`.
- **`flowscope::KeyFields` + `flowscope::AnomalyFields`** (0.12) —
  structured key (`src_ip` / `dest_port` / `proto_str` / …) and
  anomaly classification (`anomaly_type` / `anomaly_event`)
  accessors consumed by every emit writer (CSV / NDJSON / Zeek /
  EVE). Impls on `FiveTupleKey` + `L4Proto` (KeyFields) and
  `AnomalyKind` (AnomalyFields) ship out of the box; custom
  keys opt in.
- **`flowscope::detect::patterns`** (0.12) — three named
  detectors: `BeaconDetector<K>` (CV-composite, RITA-style),
  `PortScanDetector<K>` (Threshold Random Walk, Jung 2004),
  `DgaScorer` (bigram log-likelihood with embedded English
  baseline). Always-on; no Cargo feature gate.
- **`flowscope::detect::file`** (0.12, `file-hash` feature) —
  `Sha256Sink` + `Md5Sink` streaming-hash sinks for
  reassembled payload windows, with `FileType` magic-byte
  classification (16 formats: PE / ELF / Mach-O / PDF / PNG /
  JPEG / GIF / WebP / ZIP / Gzip / Bzip2 / Xz / MP4 / MP3 /
  SQLite3 / Unknown). Bridges flowscope into DFIR / IR
  pipelines (VirusTotal hash matching, Suricata
  `file_md5` ergonomics) without storing file bytes.
- **TLS ECH signal extraction** (0.12) — `TlsClientHello` gains
  `ech_present` / `ech_config_id` / `sni_is_outer` when
  extension `0xfe0d` is observed; `TlsHandshake` aggregates an
  `EchOutcome` (NotOffered / Accepted / Rejected / Unknown).
  Outer SNI marked as cover-domain so downstream pipelines
  don't silently mis-attribute target identity.
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
flowscope = { version = "0.14", features = ["full"] }
```

MSRV is Rust 1.88.

One builder chain, one typed slot handle per protocol. The
`Driver<E>` shape introduced in 0.11; the whole driver +
slot handles are `Send + Sync` since 0.13:

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

0.14.0 — netring-0.22 adoption cycle: operations-layer
ergonomics. ICMP error → live-flow join, generic bandwidth-by-
app primitives, site-custom port labels, per-flow inspection
patterns, and a discoverability sweep across the prelude +
docs.

Headlines (0.14):

- **`FlowTracker<FiveTuple, S>::lookup_inner(&IcmpInner)`**
  (plan 161). Joins an ICMP error's embedded inner 5-tuple
  back to a live flow with one method call. Direction-
  agnostic via `FiveTupleKey::from_inner_canonical`. Replaces
  the hand-rolled `HashMap<FlowKey, FlowStats>` mirror cache
  every L4 monitor was rebuilding. The wishlist's claim that
  `FlowTracker` was "mutate-only" was verified wrong — the
  read API (`get`, `snapshot_stats`, `flows`, `iter_active`)
  already existed.
- **`DestUnreachableKind`** (plan 162) — unified v4/v6
  vocabulary for the ~17 ICMPv4 + ~8 ICMPv6 Destination
  Unreachable codes. Plus `IcmpType::dest_unreachable_kind`
  accessor. Re-exported at the crate root and in the
  prelude. Promotes `icmp::types` from private to `pub mod`
  (rustdoc + IDE autocomplete bait-and-switch fix; absorbs
  wishlist plan 166).
- **`flowscope::correlate::RollingRate<K, V>`** (plan 164) —
  per-key per-second rate over a sliding window. Sibling to
  `TimeBucketedCounter` but generic over the value type (`V
  = u64` for bytes/sec, `V = f64` for latency-sum). Bucket-
  reuse zero-alloc per `record` call. Plus the `RateValue`
  trait.
- **`flowscope::well_known::LabelTable`** (plan 165) — site-
  custom port label extensibility. `Send + Sync + Clone`.
  Plus `FiveTupleKey::protocol_label_with` / `app_label_with`
  companions.
- **`L4Proto::canonical_name`** + **`FiveTupleKey::app_label`**
  (plan 163) — lowercase always-Some siblings to the
  uppercase `proto_str` (EVE/Suricata) and `Option`-returning
  `protocol_label`. Removes the `is_tcp: bool` workaround
  from bandwidth-by-app reports.
- **`KeyIndexed::drain_expired`** + **`drain_expired_into`**
  (plan 160) — returns expired entries as owned `(K, V)`
  pairs for inspection. Sibling to `evict_expired` (which
  discards).
- **`FlowStats` per-side accessors** (plan 168) —
  `bytes_for(side)` / `pkts_for(side)` /
  `mean_pkt_size_for(side)` / `direction_skew()`.
- **Discoverability sweep** (plan 167) — prelude expanded
  with ~13 `correlate` + ICMP + `well_known` re-exports;
  new [`docs/discoverability.md`](docs/discoverability.md)
  one-page tour grouped by use case.

Pre-release polish (plans 170-174):

- **`IcmpType::mtu_signal()`** + **`MtuSignalKind`** (plan 170)
  — unified v4 `FragmentationNeeded` + v6 `PacketTooBig`
  signal with preserved next-hop MTU. Sibling to
  `DestUnreachableKind` for non-DU classification.
- **`RollingRate` completeness** (plan 171) — `sum(k, now)`,
  `top_k(n, now)`, `clear()`, `len(now)`. Built-in sorted
  top-N — no manual `snapshot().collect().sort()` dance.
- **`LabelTable` completeness** (plan 172) — `remove`,
  `contains`, `len`, `is_empty`. Plus the only **breaking**
  removal in 0.14: `override_count` → `len` (rename to
  idiomatic name; method shipped on master hours ago, never
  on crates.io).
- **`FlowStats::throughput_bps*`** (plan 173) — overall +
  per-side lifetime-average throughput with safe-divide
  built in (zero-duration flows return `0.0`, not NaN).
- **DX sweep** (plan 174) — three runnable examples for the
  0.14 surface (`bandwidth_by_app`, `icmp_explained_drops`,
  `direction_skew_anomaly`); rustdoc "see also" cross-links
  across sibling primitives.

See [`docs/migration-0.13-to-0.14.md`](docs/migration-0.13-to-0.14.md)
for the 0.13 → 0.14 cheat sheet.

0.13.0 — netring-0.21 adoption cycle: fully `Send + Sync`
driver + canonical anomaly value type + broadcast delivery +
bounded back-pressure + per-flow typed state.

Headlines (0.13):

- **`Driver<E>: Send + Sync` unconditionally** (plan 156).
  `tokio::spawn(driver_task)` on the default multi-thread
  runtime just works. The 0.12 CHANGELOG misattributed the
  `!Send` source to `Rc<RefCell>` interior mutability; the
  real cause was a missing `+ Send` bound on a trait object.
  Fixed structurally — no `unsafe`, no opt-in knob, no
  runtime overhead. See `docs/migration-0.12-to-0.13.md`.
- **`flowscope::OwnedAnomaly` + `DetectorScore` trait** (plan 147).
  Canonical owned detector-output value with
  `SmallVec<[..; 4]>`-backed observations + metrics (zero-
  alloc typical case). Every shipped detector score
  (`ScanScore<K>` / `BeaconScore<K>` / `DgaScore`) gets an
  `into_anomaly(ts)` method + `DetectorScore` impl. Routes
  through `EveJsonWriter::write_owned_anomaly` (with
  `anomaly.labels` + `anomaly.metrics` sub-objects) +
  `FlowEventNdjsonWriter::write_owned_anomaly`.
- **`BroadcastSlotHandle<M, K>`** (plan 150) — fan-out
  sibling of `SlotHandle`. Each `Clone` is a separate
  subscriber that sees every message (vs the competitive-
  consumer MPMC semantics of `SlotHandle::clone`). Register
  via `DriverBuilder::session_on_ports_broadcast_each`.
- **`SlotHandle::drain_n(out, max) -> usize`** (plan 149) —
  bounded back-pressure for shard run-loops. `max = 0`
  is a no-op; `max = usize::MAX` is identical to `drain`.
- **`PcapFlowSource::with_speed_factor(f64)`** (plan 152) —
  time-realistic pcap replay. `1.0` = original timing;
  `f64::INFINITY` = unpaced (default). Tokio caveat
  documented (uses `std::thread::sleep`).
- **`flowscope::correlate::FlowStateMap<T, K>`** (plan 154) —
  per-flow typed state with auto-evict on `FlowEvent::Ended`
  + TTL sweep. Plus `KeyIndexed::get_mut`. Plus a fix:
  `KeyIndexed::new_unbounded` now uses
  `lru::LruCache::unbounded()` instead of `new(usize::MAX)`
  (the latter caused a hashbrown overflow — a 0.12
  regression caught while implementing plan 154).
- **`flowscope::test_helpers::events`** (plan 153) —
  synthetic `FlowEvent` + `driver::Event` constructors.
- **Sharded-driver example + recipe** (plan 155) —
  `examples/00-getting-started/sharded_capture.rs` +
  [`docs/sharded.md`](docs/sharded.md).

0.12.0 — Cross-thread + structured-output + pre-1.0 debt
retirement + named-detector / TLS-modernisation / DFIR-sinks
cycle.

Headlines (0.12):

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
- **`KeyFields` / `AnomalyFields` trait split** (plan 130) —
  pre-1.0 break. The previous monolithic `AnomalyFields` trait
  conflated 5-tuple key accessors with anomaly classification;
  split along the natural cleavage so the type system reflects
  what's a key property vs an anomaly property. Emit writers
  are now generic over `K: KeyFields`.
- **`flowscope::detect::patterns`** — three named detectors:
  `BeaconDetector` / `PortScanDetector` / `DgaScorer`. Always-on.
- **TLS ECH signal extraction** — outer SNI flagged + ECH
  outcome aggregated; no silent target mis-attribution.
- **`file-hash` feature** — `Sha256Sink` + `Md5Sink` + 16-format
  MIME classifier for DFIR / IR pipelines.
- **`Timestamp::write_iso8601` / `to_iso8601`** — alloc-free
  RFC 3339 / ISO 8601 rendering. Optional `chrono` feature
  adds infallible `From` interop in both directions.
- **Pre-1.0 feature pruning** (plan 131) — `ja3` + `ja4`
  collapsed into `tls-fingerprints`; `tracing-messages` deleted
  (per-message tracing is now always-on under `tracing`;
  filter at runtime via `EnvFilter`).
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
release history,
[`docs/migration-0.12-to-0.13.md`](docs/migration-0.12-to-0.13.md)
for the 0.12 → 0.13 cheat sheet, and
[`docs/migration-0.11-to-0.12.md`](docs/migration-0.11-to-0.12.md)
for the prior cycle.

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
