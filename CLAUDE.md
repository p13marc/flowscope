# CLAUDE.md

## Project Overview

`flowscope` is a passive flow & session tracking library for packet
capture pipelines. Single crate with feature-gated modules. Runtime-
free, cross-platform — no tokio, no futures, no Linux-specific code in
the core.

- Edition 2024, MSRV 1.88 (bumped from 1.85 in plan 99 for
  let-chains)
- Single Cargo package; modules `http` / `tls` (+ `ja3`) / `dns` /
  `pcap` are opt-in via Cargo features. Observability hooks
  (`metrics`, `tracing`) are opt-in too.
- Pairs with [`netring`](https://crates.io/crates/netring) for live
  Linux capture; with `pcap` files for offline replay; with any other
  source of `&[u8]` frames (tun-tap, eBPF userspace, embedded, etc.)
- Pre-1.0 API; trait shape (`SessionParser` / `DatagramParser`) is
  stable since 0.1.0. Public structs are `#[non_exhaustive]` since
  0.2.0 — additive fields/variants are unconditionally non-breaking.

## Implementation Status

**0.9.0 cycle** (in progress at 2026-06). Plan-of-record in
`plans/INDEX.md`. Shipped so far:

- **Plan 96** — unified `flowscope::Error` (5 module enums
  collapsed; source-chain preserved; `(module, code)` matching).
- **Plan 94 Tier 3** — public `flowscope::layers` per-packet
  view (zero-copy, Layers/Layer/LayerKind + Eth/VLAN/MPLS/
  IPv4/IPv6/ARP/TCP/UDP/ICMPv4/ICMPv6 slices, dynamic walk +
  direct accessors, `PacketView::layers()`; tunnel walking for
  VXLAN/GTP-U/GRE/IP-in-IP via `Layers::has_tunnel()` /
  `Layers::truncated()`).
- **Plan 94 Tier 1** — `flowscope::Pipeline` high-level entry
  point + `flowscope::prelude` (one-import API) + `.reset()`
  + `.run_iter()` over `OwnedPacketView`.
- **Plan 75** — `FlowTracker::with_auto_sweep(interval)` for
  live/offline parity.
- **Plan 99** — MSRV 1.85 → 1.88 + let-chain idiom sweep.
- **Plan 81** — `flowscope::correlate` module
  (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`).
- **Plan 97** — TLS modernization: `ja4` feature (FoxIO v1
  client fingerprint) + `TlsHandshakeParser` aggregator
  (one `TlsHandshake` event per handshake with
  SNI / ALPN / JA3 / JA4 / version / cipher /
  `resumption_attempted` / `HandshakeOutcome`).
- **Plan 92** — `FlowMultiSessionDriver<E, M>` composite
  driver (port-set + broadcast routing; user-supplied sum-type
  lifting).
- **Plan 74** — `SegmentBufferReassembler` with OOO hole-fill
  (BTreeMap-backed pending queue; deadline expiry; strict
  RFC 5722 overlap).

- **Plan 94 Tier 2** — driver builders: additive
  `Driver::builder(extractor)` chainable entry on
  `FlowSessionDriver` + `FlowDatagramDriver`. Constructor
  deletion deferred to a follow-up cycle.
- **Plan 94 Tier 3 fast path** — `LayerParser` + `LayerStack`
  zero-allocation parsing (gopacket `DecodingLayerParser`
  shape) with caller-owned scratch + `.only(kinds)` mask.

The 0.9 cycle is complete; all eight implementation plans
shipped. The plan-of-record umbrella (93) lingers as the
durable audit; the implementation plans (74, 75, 81, 92, 94,
96, 97, 99) are retired per project convention.

Test counts: 508 passing, zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings.

(0.5.0 historical: TCP rich diagnostics, periodic ticks,
parser identity. 0.8.0 historical: serde wire-format lock,
ICMP correlation, programmatic flow termination, snapshot
iterator, multi-protocol monitor recipe. See CHANGELOG.md.)

### Modules

```
src/
├── lib.rs                       # re-exports + feature wiring
├── error.rs                     # flowscope::Error / ErrorKind / Module / ErrorCode (plan 96, 0.9.0)
├── prelude.rs                   # flowscope::prelude::* (plan 94, 0.9.0)
├── pipeline.rs                  # Pipeline + PipelineBuilder + Event + EventKind (plan 94 Tier 1, 0.9.0)
├── timestamp.rs                 # Timestamp (also re-exported by netring)
├── view.rs                      # PacketView<'a> = (frame: &[u8], ts) + .layers() (plan 94, 0.9.0)
├── extractor.rs                 # FlowExtractor trait + Extracted/Orientation
├── layers/                      # Per-packet layered view (plan 94 Tier 3, 0.9.0)
│   ├── mod.rs                   # Layers + Layer + accessors + tunnel walk + dynamic walk
│   ├── kind.rs                  # LayerKind enum + .layer_number()
│   ├── eth.rs                   # EthernetSlice + VlanSlice + MplsSlice
│   ├── ip.rs                    # Ipv4Slice + Ipv6Slice + ArpSlice
│   ├── transport.rs             # TcpSlice + UdpSlice + Icmpv4Slice + Icmpv6Slice + TcpFlagsView + TcpOption
│   └── tunnel.rs                # GreSlice + VxlanSlice + GtpUSlice
├── correlate/                   # flowscope::correlate (plan 81, 0.9.0)
│   ├── mod.rs                   # public re-exports
│   ├── bucketed.rs              # TimeBucketedCounter<K>
│   ├── indexed.rs               # KeyIndexed<K, V>
│   └── sequence.rs              # SequencePattern + KeylessSequencePattern
├── driver_builder.rs            # Driver::builder(ext) entry (plan 94 Tier 2, 0.9.0)
├── layers/fast.rs               # LayerParser + LayerStack zero-alloc (plan 94 Tier 3 fast path, 0.9.0)
├── multi_session_driver.rs      # FlowMultiSessionDriver<E, M> (plan 92, 0.9.0)
├── segment_reassembler.rs       # SegmentBufferReassembler OOO hole-fill (plan 74, 0.9.0)
├── extract/                     # built-in extractors (extractors feature)
│   ├── parse.rs                 # internal etherparse wrappers
│   ├── five_tuple.rs            # FiveTuple { proto, a, b }
│   ├── ip_pair.rs               # IpPair (proto-agnostic, useful for ICMP)
│   ├── mac_pair.rs              # MacPair (L2 only)
│   ├── encap_vlan.rs            # StripVlan<E>
│   ├── encap_mpls.rs            # StripMpls<E>
│   ├── encap_vxlan.rs           # InnerVxlan<E>
│   ├── encap_gtp.rs             # InnerGtpU<E>
│   ├── encap_gre.rs             # InnerGre<E>            (plan 50.1)
│   ├── auto_detect.rs           # AutoDetectEncap<E>     (plan 50.3)
│   └── flow_label.rs            # FlowLabel<E>           (plan 50.2)
├── event.rs                     # FlowEvent / FlowSide / EndReason / FlowStats
│                                # AnomalyKind / OverflowPolicy   (0.2.0)
├── history.rs                   # HistoryString (Zeek-style ShAdaFf)
├── tcp_state.rs                 # TCP state machine (transitions + idle policy)
├── tracker.rs                   # FlowTracker<E, S>     (manual_tick alias added in 50.4)
│                                # hot-cache fast path   (plan 41, 0.2.0)
│                                # snapshot_stats / snapshot_history / forget (0.2.0)
├── reassembler.rs               # Reassembler trait + BufferedReassembler
│                                # buffer cap + OverflowPolicy (plan 42 §1, 0.2.0)
├── driver.rs                    # FlowDriver<E, F, S = ()> (sync wrapper)
│                                # diagnostics patch + BufferOverflow synthesis +
│                                # with_emit_anomalies      (plan 42 §2/§3, 0.2.0)
├── session.rs                   # SessionParser / DatagramParser traits + factories + SessionEvent
├── session_driver.rs            # FlowSessionDriver — sync mirror of session_stream (plan 25, 0.2.0)
│                                # Refactored to wrap FlowDriver (plan 51, 0.3.0)
├── datagram_driver.rs           # FlowDatagramDriver — sync UDP mirror (plan 57, 0.3.0)
├── dedup.rs                     # Dedup — content-hash + window dedup (plan 49, 0.3.0)
├── obs.rs                       # metrics / tracing hooks (plan 40, 0.2.0)
│                                # tracing-messages sub-feature (plan 56, 0.3.0)
├── http/                        # `http` feature
│   ├── parser.rs                # internal step() machine (httparse-based)
│   ├── session.rs               # HttpParser (SessionParser, plan 31, the only public shape since 0.9.0)
│   └── types.rs                 # HttpRequest / HttpResponse / HttpConfig
├── tls/                         # `tls` feature
│   ├── parser.rs                # internal step() machine (tls-parser-based)
│   ├── session.rs               # TlsParser (SessionParser, the only public shape since 0.9.0)
│   ├── handshake.rs             # TlsHandshakeParser aggregator (plan 97, 0.9.0)
│   ├── fingerprint.rs           # JA3 (gated by `ja3` feature)
│   ├── ja4.rs                   # JA4 (gated by `ja4` feature, plan 97, 0.9.0)
│   └── types.rs                 # TlsClientHello / TlsServerHello / TlsAlert / TlsConfig
├── dns/                         # `dns` feature
│   ├── parser.rs                # parse_message / parse_message_at (simple-dns-based)
│   ├── correlator.rs            # Correlator<S> — query/response matching
│   ├── datagram.rs              # DnsUdpParser (DatagramParser; correlating, plan 37)
│   ├── session.rs               # DnsTcpParser (SessionParser, RFC 1035 §4.2.2 framing)
│   └── types.rs                 # DnsQuery / DnsResponse / DnsRdata / DnsConfig
├── icmp/                        # `icmp` feature
│   ├── parser.rs                # parse_v4 / parse_v6 stateless decoders
│   ├── datagram.rs              # IcmpParser (DatagramParser, plan 76, 0.7.0)
│   └── types.rs                 # IcmpMessage / IcmpType variants
└── pcap/                        # `pcap` feature
    └── source.rs                # PcapFlowSource — offline replay
```

The legacy `HttpFactory` / `TlsFactory` callback-handler shape
(`factory.rs` modules) was removed in 0.9.0 — the
`SessionParser` typed-stream shape is the only public surface.

### Tests

- `tests/parser_proptest.rs` — 11 splitting-invariance / no-panic
  proptests across all four parsers (HTTP / TLS / DNS-UDP / DNS-TCP).
  Run with `PROPTEST_CASES=10000` for stress testing.
- `tests/proptest_invariants.rs` — tracker-level proptests
  (FiveTuple canonicalization, TCP state machine).
- `tests/{http,tls,dns}_parser.rs` — fixture-based unit tests per parser
  (TLS rewritten on 0.9 to drive the SessionParser shape after the
  callback-factory removal).
- `tests/{http,pcap}_pcap.rs`, `tests/pcap_integration.rs`,
  `tests/pcap_fixtures.rs` — pcap-driven integration tests.
- `tests/length_prefixed_example.rs` — sync `FlowSessionDriver` +
  custom protocol parser, paired with
  `tests/fixtures/length_prefixed/sample.pcap` (0.2.0).
- `tests/metrics_integration.rs` — DebuggingRecorder snapshot test
  for the `metrics` feature (0.2.0).
- `tests/round_trip.rs` — synthesize→pcap→PcapFlowSource→
  FlowSessionDriver→assert byte-equality regression test. Three
  hand-written variants plus a proptest (0.3.0).
- `tests/pipeline.rs` — `Pipeline` builder + `run_pcap` /
  `run_iter` / `reset` integration (plan 94 Tier 1, 0.9.0).
- `tests/layers.rs` + `tests/layers_extended.rs` — Tier 3
  per-packet view (direct slices, dynamic walk, tunnel walking,
  ARP/MPLS/ICMP).
- `tests/auto_sweep.rs` — `FlowTracker::with_auto_sweep` (plan
  75, 0.9.0).
- `tests/error_chain.rs` — unified `flowscope::Error` source
  chain across pcap I/O, ICMP, DNS (plan 96, 0.9.0).
- `benches/{extractor,tracker,reassembler,session_driver,dedup}.rs`
  — criterion benchmark harness (0.3.0). Run with
  `cargo bench --all-features`; baselines in
  `docs/performance.md`.

## Build & Test

```bash
# Default features
cargo test

# All features (incl. ja3, dns, pcap, metrics, tracing)
cargo test --all-features

# Just one module
cargo test --features http
cargo test --features dns

# Stress proptests
PROPTEST_CASES=10000 cargo test --features http,tls,dns --test parser_proptest

# Lint
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --all-features --no-deps
```

## Architecture

### Three layers, one trait per layer

1. **Extractor** (`FlowExtractor`) — turns a frame into a flow key +
   metadata. User-pluggable. Built-in extractors (5-tuple etc.) and
   decap combinators wrap each other (`StripVlan(InnerVxlan(FiveTuple))`).
2. **Tracker** (`FlowTracker<E, S>`) — bidirectional flow accounting
   on top of an extractor. TCP state machine with Suricata-style idle
   timeouts and LRU eviction. Emits `FlowEvent` lifecycle. Hot-cache
   fast path for monoflow workloads (0.2.0).
3. **Reassembler** / **SessionParser** / **DatagramParser** — three
   API shapes for consuming TCP / UDP payloads. Pick by use case
   ([recipes.md](docs/recipes.md) walks through the
   decision tree).

### One L7 API shape — sync / async parity

Every shipped L7 parser exposes the typed-stream shape only
(`SessionParser` for TCP, `DatagramParser` for UDP). The legacy
`*Factory<H>` callback-handler shape that shipped through 0.8
was removed in 0.9.

- **`SessionParser` / `DatagramParser`** — typed message stream.
  `feed_initiator` / `feed_responder` / `parse` return
  `Vec<Self::Message>`; both traits have a defaulted `on_tick`.
- A consumer who wants callback ergonomics writes
  `for ev in driver.track(...) { match ev { … } }` and
  dispatches inside the `SessionEvent::Application` arm.

Two driver helpers:

- Sync, no runtime: **`FlowSessionDriver<E, P, S = ()>`** in
  flowscope (0.2.0; `S` restored in 0.5 — see plan 38). The 0.9
  release adds `FlowSessionDriver::builder(ext)` chainable
  construction alongside the existing constructors.
- Async tokio: **`flow_stream(...).session_stream(parser)`** in
  netring.

Both produce the same `SessionEvent`s for the same wire bytes.

For the highest-level convenience, the 0.9 `flowscope::Pipeline`
wraps both `FlowSessionDriver` + `FlowDatagramDriver` behind one
builder chain — see `docs/getting-started.md`.

### Reassembly observability (0.2.0)

`BufferedReassembler` ships an optional per-side cap with two
overflow policies:

- `OverflowPolicy::SlidingWindow` (default): drop oldest bytes;
  flow stays alive; parser must resync.
- `OverflowPolicy::DropFlow`: poison the reassembler; the driver
  synthesises an `Ended { reason: BufferOverflow }` event for the
  flow on the next tick.

`FlowStats` carries per-side reassembly diagnostics
(`reassembly_dropped_ooo_*`, `reassembly_bytes_dropped_oversize_*`)
on every `Ended` event. For live signal, `FlowDriver::with_emit_anomalies(true)`
emits `FlowEvent::FlowAnomaly { key, kind: AnomalyKind::… }` and
`FlowEvent::TrackerAnomaly { kind, .. }` events inline,
coalesced per (flow, side, kind) per tick.

### Observability features (0.2.0)

`metrics` and `tracing` Cargo features wire the tracker and driver
into the standard observability ecosystem. Both zero-cost when off
(every entry point compile-time stubbed). Metric vocabulary in
[docs/observability.md](docs/observability.md).

### Design constraints

- **Runtime-free in core.** Tokio is forbidden in `flowscope`'s deps.
  Async lives in `netring` (which depends on flowscope, not the other
  way around). This is a hard project rule; PRs adding tokio to
  flowscope are wrong-shaped.
- **No `unsafe` outside well-justified zero-copy spots.** Buffer
  handling uses `Bytes` / `Vec<u8>` with safe slicing.
- **Deterministic state machines.** No background threads, no global
  state. Every parser holds its state and returns messages
  synchronously.
- **Bounded memory.** Tracker has `max_flows`; reassemblers have
  optional `max_buffer`; correlator has `max_pending`. No unbounded
  growth.
- **`#[non_exhaustive]` on every public struct/enum that may grow.**
  Added project-wide in 0.2.0. Construct via `::default()` and mutate;
  do not rely on struct-literal construction from outside the crate.
  All future additions are additive.
- **Single vocabulary across event stream and metrics.** `AnomalyKind`
  is the source of truth for both `FlowEvent::FlowAnomaly` /
  `TrackerAnomaly` carriers and the
  `flowscope_anomalies_total` metric labels. Adding a variant
  requires adding the corresponding metric label arm in
  `src/obs.rs::anomaly_label`.
- **Trait stability lock.** `SessionParser` / `DatagramParser` shape
  was committed in 0.1.0. `Reassembler` grew default-zero diagnostic
  methods in 0.2.0 (purely additive). Future additions stay additive;
  breaking changes need a major bump.

## Docs vs plans

The repo separates **reference docs** from **forward-looking
plans**:

- **`docs/`** — published as part of the crates.io package.
  Reference material for users of the library: how to pick an
  API, what metrics fire, what the architecture looks like,
  design rationale, consumer-feedback records.
- **`plans/`** — in-repo only (excluded from the published
  package via `Cargo.toml`'s `exclude` field). Forward-looking
  work items only — concrete plans for features that haven't
  shipped yet.

**Convention**: when an implementation plan ships, **delete the
plan file** in the same PR series. `git log` is the historical
record; `plans/` is the working backlog.

### `docs/` (published reference)

- `getting-started.md` — install + three minimal pipelines.
- `concepts.md` — the four layers + event model.
- `recipes.md` — picking an API, custom parsers, multi-protocol
  monitoring, cross-protocol correlation, structured output.
- `observability.md` — metric vocabulary, cardinality, tracing
  targets, severity routing.
- `performance.md` — criterion bench methodology and baseline
  numbers (0.3.0 snapshot).
- `design.md` — why flowscope is shaped the way it is
  (runtime-free, run-to-completion threading, layered traits,
  locked serde format).

Per-cycle upstream-feedback documents, per-cycle plan-of-record
syntheses, design proposals, and audit reports are retired once
their plans ship — `CHANGELOG.md` entries are the durable
record, and `plans/INDEX.md` carries the surviving deferral /
RFC notes.

### `plans/` (active backlog)

- `INDEX.md` — backlog index, project conventions, and the
  "Considered but not in the backlog" footnote listing known
  capability gaps without active plans.
- `21-flow-protolens.md` — protolens bridge sister crate (STALE
  pre-consolidation draft, pending real consumer ask).
- `74-rfc-ooo-reassembly.md` — RFC for OOO TCP reassembly
  (`SegmentBufferReassembler`); implementation deferred pending
  consumer + maintainer agreement.
- `75-rfc-tracker-auto-sweep.md` — RFC for
  `FlowTracker::with_auto_sweep(interval)`.
- `81-rfc-correlate-module.md` — RFC for `flowscope::correlate`
  (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`).
- `92-rfc-multi-parser-driver.md` — RFC for
  `FlowMultiSessionDriver` composite parser driver.

Plan numbers 00–04, 12, 20, 22–25, 30–61, 70–73 (everything
except 21 and 74, which are parked) are retired (implementation
shipped, file removed). See [`plans/INDEX.md`](plans/INDEX.md)
for the numbering scheme used by new plans.

## Pre-publish checklist

For the next `cargo publish` of flowscope:

1. Bump `Cargo.toml` `version` if user-facing changes have landed.
2. Update `CHANGELOG.md` with the new release section.
3. `cargo test --all-features` clean.
4. `cargo clippy --all-features --all-targets -- -D warnings` clean.
5. `cargo fmt --check` clean.
6. `cargo doc --all-features --no-deps` zero warnings.
7. `cargo machete` no unused deps.
8. `cargo publish --dry-run` packages and verifies.
9. `cargo publish`.
10. Tag the release in git: `git tag 0.x.y && git push origin 0.x.y`
    (no `v` prefix — matches the 0.1.0 / 0.2.0 / 0.3.0 / 0.4.0 /
    0.5.0 tags).

## Intra-doc links for re-exporters

See `docs/recipes.md` → "Re-exporting flowscope types" for
the recipe. The source of truth lives in `docs/` so downstream
re-exporters find it on docs.rs; keeping a copy here would just
drift.

## Relationship to netring

netring (the published Linux-capture crate) has flowscope as a
non-optional dep. Specifically:

- `netring` re-exports `flowscope::Timestamp` and `flowscope::PacketView`
  unconditionally — they're fundamental types every netring user
  may touch.
- `netring`'s `parse` / `flow` features turn on flowscope's
  `extractors` / `tracker` / `reassembler` / `session` features.
- The async stream adapters (`flow_stream`, `session_stream`,
  `datagram_stream`, `flow_broadcast`, `conversation`) live in
  netring because they depend on tokio + `AsyncCapture`. They
  consume flowscope's traits.
- The 0.2.0 `FlowEvent::key()` signature change (`&K` → `Option<&K>`)
  needs a matching netring update if netring's adapters call
  `event.key()`.
- `FlowEvent::FlowAnomaly` / `TrackerAnomaly` and
  `EndReason::BufferOverflow` flow through
  the async adapters verbatim — no netring changes needed for those.

If you add a new public API in flowscope, consider whether netring
needs a corresponding re-export under `netring::flow::*`.

## Key files

- `README.md` — front page (also published as the crates.io readme).
- `CHANGELOG.md` — release history.
- `docs/` — published reference docs (see [Docs vs plans](#docs-vs-plans)
  for the full inventory).
- `Cargo.toml` — package manifest. `exclude = ["plans/"]` keeps
  the backlog out of the published package; `docs/` IS published.
- `src/lib.rs` — top-level rustdoc + feature/module wiring.
- `src/session.rs` — the strategic 1.0 abstraction
  (`SessionParser` / `DatagramParser`).
- `src/session_driver.rs` — `FlowSessionDriver`, the sync mirror of
  netring's `session_stream`.
- `src/datagram_driver.rs` — `FlowDatagramDriver`, the sync mirror
  of netring's `datagram_stream`.
- `src/dedup.rs` — content-hash dedup primitive.
- `src/obs.rs` — metrics + tracing hooks; metric-name constants
  exported here.
