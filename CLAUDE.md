# CLAUDE.md

## Project Overview

`flowscope` is a passive flow & session tracking library for packet
capture pipelines. Single crate with feature-gated modules. Runtime-
free, cross-platform — no tokio, no futures, no Linux-specific code in
the core.

- Edition 2024, MSRV 1.88 (bumped from 1.85 in plan 99 for
  let-chains)
- Single Cargo package; modules `http` / `tls` (+ `tls-fingerprints`) / `dns` /
  `pcap` are opt-in via Cargo features. Observability hooks
  (`metrics`, `tracing`) are opt-in too.
- Pairs with [`netring`](https://crates.io/crates/netring) for live
  Linux capture; with `pcap` files for offline replay; with any other
  source of `&[u8]` frames (tun-tap, eBPF userspace, embedded, etc.)
- Pre-1.0 API; trait shape (`SessionParser` / `DatagramParser`) is
  stable since 0.1.0. Public structs are `#[non_exhaustive]` since
  0.2.0 — additive fields/variants are unconditionally non-breaking.

## Implementation Status

**0.14.0 cycle** (netring 0.22 adoption — operations-layer
ergonomics: ICMP error correlation + bandwidth-by-app
primitives + site-custom labels + discoverability,
shipped 2026-06-12).

Plans 160 / 161 / 162 / 163 / 164 / 165 / 167 / 168.
Triggered by the netring 0.22 adoption wishlist (wishlist
file retired after cycle completion; durable record in
`CHANGELOG.md` and `git log`).

Headlines:

- **Plan 161 — `FlowTracker<FiveTuple, S>::lookup_inner`**.
  Specialised impl block (not generic — `IcmpInner` is
  FiveTupleKey-shaped) that joins an ICMP error's embedded
  inner 5-tuple back to a live flow. Plus
  `FiveTupleKey::from_inner_canonical` + `from_inner_literal`
  public constructors (the canonicalisation logic was private
  inside `extract_from_parsed` pre-0.14). The wishlist's
  caveat claiming `FlowTracker` was "mutate-only" was
  verified wrong — `FlowTracker<E, S>` already exposes `get`,
  `snapshot_stats`, `flows`, `iter_active`. No refactor; the
  specialised impl calls them directly.
- **Plan 162 — `DestUnreachableKind`** unified v4/v6 vocabulary
  for the ~17 ICMPv4 + ~8 ICMPv6 Destination Unreachable
  codes. Maps down to 7 operationally-distinguishable
  variants (Host / Port / Network / Protocol /
  AdministrativelyProhibited / FragmentationNeeded / Other).
  Plus `IcmpType::dest_unreachable_kind` + `as_str` (stable
  metric-label slug). Plus the wishlist's plan 166 absorbed:
  `icmp::types` was promoted from private to `pub mod` so
  `flowscope::icmp::types::Icmpv6DestUnreachCode` resolves
  (was a rustdoc + autocomplete bait-and-switch).
  `DestUnreachableKind` re-exported at the crate root and in
  the prelude.
- **Plan 164 — `flowscope::correlate::RollingRate<K, V>`**.
  Per-key per-second rate over a sliding window. Sibling to
  `TimeBucketedCounter` but generic over `V` (bytes/sec,
  request count, latency-sum). Same bucket-reuse zero-alloc
  discipline. Plus the small sealed-style `RateValue` trait
  implemented for `u64` / `u32` / `i64` / `i32` / `f64` /
  `f32` (custom newtype wrappers can implement it for
  semantic distinction). Drops the wishlist's incorrect
  `V: From<u64> + Into<f64>` bound (doesn't hold for `u64`).
- **Plan 165 — `flowscope::well_known::LabelTable`**. Site-
  custom port label extensibility. `new()` inherits the
  built-in ~80-entry table; `standalone()` is whitelist-only.
  `Send + Sync + Clone`. Labels are `&'static str` (use
  `Box::leak` for runtime-loaded strings). Plus
  `FiveTupleKey::protocol_label_with` / `app_label_with`
  companions.
- **Plan 163 — `L4Proto::canonical_name`** lowercase always-
  Some sibling to the existing uppercase `proto_str` (which
  is EVE/Suricata schema-shaped + `Option`). Plus
  `FiveTupleKey::app_label` always-Some companion to
  `protocol_label()` with L4 fallback. Removes the
  `is_tcp: bool` workaround from netring's bandwidth-by-app
  primitive.
- **Plan 160 — `KeyIndexed::drain_expired` + `drain_expired_into`**.
  Returns expired entries as owned `(K, V)` pairs for
  inspection. Sibling to `evict_expired` (which discards).
  Honest allocation contract: ships `Vec<(K, V)>` return +
  reusable-`&mut Vec` variant rather than the wishlist's
  misleading `impl Iterator + '_` (the `lru::LruCache` has
  no `drain()`, so a Vec is unavoidable).
- **Plan 168 — `FlowStats` per-`FlowSide` accessors**.
  `bytes_for` / `pkts_for` / `mean_pkt_size_for` /
  `direction_skew` methods. `direction_skew` is
  `(bytes_init - bytes_resp) / total_bytes`, clamped to
  `[-1, 1]` — positive = initiator-heavy (uploads), negative
  = responder-heavy (downloads).
- **Plan 167 — discoverability sweep**. Pure DX. Prelude
  expanded with `TimeBucketedCounter`, `TimeBucketedSet`,
  `KeyIndexed`, `BurstDetector`, `Ewma`, `TopK`, `RollingRate`,
  `FlowStateMap`, `IcmpType`, `IcmpMessage`, `IcmpInner`,
  `DestUnreachableKind`, `LabelTable` (~13 new exports). New
  `docs/discoverability.md` one-page tour grouped by use
  case ("count things per key over time" / "react to ICMP
  errors" / "emit structured anomalies" / …).

Pre-release polish extension (plans 170-174, scope-extended
after the audit pass per user instruction "do not defer
features if you think they have values"):

- **Plan 170 — `IcmpType::mtu_signal()` + `MtuSignalKind`.**
  Reverses wishlist §13's defer-to-0.15. Unified v4
  `FragmentationNeeded` + v6 `PacketTooBig` signal with
  preserved next-hop MTU (`Option<u16>` for v4 RFC 1191,
  `u32` for v6). Sibling to `DestUnreachableKind`. Re-exported
  at crate root + in prelude.
- **Plan 171 — `RollingRate` completeness.** Adds `sum(k, now)
  -> V` (raw window sum without per-sec divide),
  `top_k(n, now) -> Vec<(K, f64)>` (sorted top-N built-in),
  `clear()` (reset), `len(now)` (in-window key count). `is_empty`
  doc clarified as storage-state vs `len`'s in-window-state.
  `with_capacity` LRU variant deferred — storage shape
  (`VecDeque<(Timestamp, HashMap<K, V>)>`) is per-time-bucket
  not per-key, ~80 LoC of cross-bucket bookkeeping to bound;
  `evict_expired` already bounds memory to "K cardinality per
  window".
- **Plan 172 — `LabelTable` completeness + `override_count`
  removal.** `remove`, `contains`, `len`, `is_empty`. **Only
  breaking change in 0.14**: `override_count` removed in
  favor of idiomatic `len()`. Safe — method shipped on master
  ~hours ago, never on crates.io.
- **Plan 173 — `FlowStats::throughput_bps*` accessors.**
  Lifetime-average overall + per-side throughput with
  safe-divide built in. Replaces the `as f64 /
  duration_secs().max(EPSILON)` pattern at every monitor call
  site. Zero-duration flows return `0.0`, not NaN.
- **Plan 174 — DX sweep.** Three runnable examples under
  `examples/04-observability/`: `bandwidth_by_app.rs`
  (RollingRate + top_k + LabelTable + app_label_with),
  `icmp_explained_drops.rs` (lookup_inner +
  DestUnreachableKind + MtuSignalKind), `direction_skew_anomaly.rs`
  (direction_skew + bytes_for + throughput_bps_for). Plus
  rustdoc "see also" cross-links across sibling primitives
  (`RollingRate` ↔ `TimeBucketedCounter`/`TopK`/`Ewma`;
  `DestUnreachableKind` ↔ `MtuSignalKind`; `app_label` ↔
  `app_label_with`; `evict_expired` ↔ `drain_expired`).

Test count after the polish round: **920 passing** (up from
884 mid-cycle, +36 polish; up from 809 at 0.13.0 release,
+111 cycle-wide). Zero clippy warnings under `--all-features
--all-targets -D warnings`, zero rustdoc warnings. All 13 CI
feature-matrix combinations build clean.

New module registered: `src/correlate/rolling_rate.rs`.

**0.13.0 cycle** (netring 0.21 adoption — Send+Sync driver +
canonical anomaly value + broadcast + DX, shipped 2026-06).

Plans 147 / 149 / 150 / 152 / 153 / 154 / 155 / 156. Triggered
by the netring 0.21 adoption wishlist (wishlist file retired
after cycle release).

Headlines:

- **Plan 156 structural fix (no `unsafe`)** — `Driver<E>` is
  `Send + Sync` unconditionally. The 0.12 CHANGELOG + doc
  comments claimed it was `!Send` because `FlowTracker` held
  `Rc<RefCell>` state, but that was incorrect — direct grep
  found zero `Rc<RefCell>` in tree. The real cause was a
  missing `+ Send` bound on the `Vec<Box<dyn ErasedSlot<_>>>`
  trait object. Fixed structurally: 1-line trait-object bound
  + `P: Send + Sync` audit at builder registration sites.
  Effort dropped from the wishlist's 3-4 days (unsafe newtype
  + Miri audit) to ~3 hours. Stale doc comments cleaned up at
  5 sites (`src/driver/{slot,mod}.rs` + 0.12 retired plans).
- **Plan 147** — `flowscope::OwnedAnomaly` canonical detector-
  output value (six fields + `SmallVec<[..; 4]>` for
  observations + metrics; zero-alloc typical case) +
  `flowscope::DetectorScore` trait (`name()` +
  `into_anomaly(ts)`) implemented on `ScanScore<K>`,
  `BeaconScore<K>`, `DgaScore`. Per-score `into_anomaly`
  inherent methods on each. `EveJsonWriter::write_owned_anomaly`
  + `FlowEventNdjsonWriter::write_owned_anomaly`. New
  `EveOptions::custom_anomaly_type` field (default
  `"applayer"`). Absorbs wishlist 147 + 148 + 151 into one
  coherent ship.
- **Plan 149** — `SlotHandle::drain_n(out, max) -> usize` for
  bounded back-pressure. `swap`/`SlotBuf` micro-optimisation
  variants deferred to 0.14 (SegQueue::pop is ~10ns; downstream
  emit dwarfs it).
- **Plan 150** — `flowscope::driver::BroadcastSlotHandle<M, K>`
  fan-out delivery + `DriverBuilder::session_on_ports_broadcast_each`.
  `Arc<BroadcastInner>` holds `Mutex<Vec<Weak<SegQueue<...>>>>`.
  Each `Clone` is a separate subscriber; push fans out to all
  live queues; dead `Weak`s prune inline. New `M: Clone` bound
  on the broadcast variant (every shipped parser message
  already derives `Clone`).
- **Plan 152** — `PcapFlowSource::with_speed_factor(f64)` for
  time-realistic replay. Tokio-blocking caveat documented.
  `replay_at_wall_clock` from the wishlist dropped — low value.
- **Plan 153** — `flowscope::test_helpers::events` synthetic-
  event constructors (under existing `test-helpers` feature).
  Includes a `::driver` sub-module for the typed `Event<K>`.
- **Plan 154** — `flowscope::correlate::FlowStateMap<T, K>`
  per-flow typed state, layered over `KeyIndexed<K, T>`
  (~80 LoC instead of the originally-proposed 200). Plus
  `KeyIndexed::get_mut` (mutable TTL-aware lookup) and a fix:
  `KeyIndexed::new_unbounded` now uses `lru::LruCache::unbounded()`
  instead of `LruCache::new(usize::MAX)` (the latter caused
  hashbrown capacity overflow — a regression I caught during
  154 implementation, was shipped in 0.12).
- **Plan 155** — `examples/00-getting-started/sharded_capture.rs`
  + `docs/sharded.md` recipe. Built on 156's Send+Sync driver.

Test count after the 0.13 cycle: **809 passing** (up from 772 at
0.12.0 release, +37 new), zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings. New modules registered: `src/anomaly.rs`,
`src/correlate/flow_state_map.rs`, `src/driver/broadcast.rs`.

**0.12.0 cycle** (cross-thread + structured-output + pre-1.0
debt retirement cycle, shipped 2026-06).

- **Base** (shipped first): plans 122 / 123 / 124 / 126 / 127 +
  Phase 7 small wins. Triggered by the netring 0.21 dependency
  wishlist (per-CPU sharded capture; multi-thread tokio runtime
  ask; SIEM EVE-format ingest).
- **Expanded scope** (post-strategic-review audit): plans 130 /
  131 / 132 / 143 / 144 / 146 — pre-1.0 API debt retirement
  (trait shape cleanup, error/features pruning, doc overhaul)
  + named detectors (Beacon / PortScan / DGA) + TLS
  modernisation (ECH) + DFIR / IR sinks (file hashes).

Headlines (base):

Headlines:

- **Plan 122 pre-1.0 break** — `SlotHandle<M, K>` transitions
  from `!Send + !Sync` to `Send + Sync`. Backing storage moved
  from `Rc<RefCell<Vec<SlotMessage>>>` to
  `Arc<crossbeam_queue::SegQueue<SlotMessage>>` (lock-free
  MPMC). New always-on dep `crossbeam-queue = "0.3"`. Generic
  bounds tightened from `M: 'static, K: 'static` to
  `M: Send + 'static, K: Send + 'static` — every shipped
  parser already meets this. Bench gate
  `track_into_5_slots_steady_state` confirmed at **0.000
  allocs/pkt** post-change. **0.13 update (plan 156):** the
  whole `Driver<E>` is now also `Send + Sync` — the 0.12 doc
  claim about `Rc<RefCell>` was incorrect; the actual `!Send`
  source was a missing `+ Send` bound on the slot trait
  object. Fixed structurally with no `unsafe`.
- **Plan 123** — `flowscope::emit::EveJsonWriter` behind
  `emit-eve` feature. Suricata 7.x EVE schema:
  `event_type: "flow"` for `Ended`, `"anomaly"` for
  `FlowAnomaly` / `TrackerAnomaly`, `"stats"` for `Tick`
  (off by default). Every record carries a `flow_hash` field
  (FNV-1a over `(proto, sorted endpoints)`, direction-
  invariant). Schema-compatible with Filebeat's Suricata
  module, Splunk Suricata TA, Tenzir's `read_suricata`, ECS-
  converting pipelines. See `docs/eve-format.md`.
- **Plan 124** — `Driver::<E>::deferred()` returns
  `DeferredDriverBuilder<E>`, a mirror of `DriverBuilder<E>`
  minus `build()` plus `build_with(ext)`. For consumer-built
  monitor chains (netring's `MonitorBuilder`) that need to
  register protocol parsers *before* the extractor instance
  is known. Compile-time guarantee preserved by type-system
  separation — no panicking `build()`.
- **Plan 126** — `flowscope::AnomalyFields` trait. Structured
  field accessors (`src_ip` / `src_port` / `dest_ip` /
  `dest_port` / `proto_str` / `app_proto_str` /
  `anomaly_type` / `anomaly_event`) used by `EveJsonWriter`
  and consumable by any future field-aware emitter. Shipped
  impls on `FiveTupleKey`, `L4Proto`, `AnomalyKind`. All 8
  methods default to `None` — partial impls work for custom
  keys.
- **Plan 127** — `Timestamp::write_iso8601<W: fmt::Write>`
  (alloc-free) + `to_iso8601() -> String`. Pure Howard
  Hinnant `civil_from_days` — no chrono dep required.
  Optional `chrono` feature adds `From<DateTime<Utc>>` for
  `Timestamp` and `TryFrom<Timestamp>` for `DateTime<Utc>`
  with `ChronoOutOfRange` error.
- **Phase 7 small wins** —
  `TimeBucketedCounter::new_unbounded(window, bucket)`,
  `TimeBucketedSet::new_unbounded(window, bucket)`,
  `KeyIndexed::new_unbounded(ttl)`. 3 trivial delegates,
  retire netring's duplicated `correlate` module.

Headlines (expanded):

- **Plan 130** — pre-1.0 trait shape cleanup. Split
  `AnomalyFields` into `KeyFields` (5-tuple accessors) +
  `AnomalyFields` (anomaly classification). Emit writers
  (CSV / NDJSON / Zeek / EVE) become generic over
  `K: KeyFields`. `Event::tcp()` cross-variant accessor.
  `From<Timestamp> for chrono::DateTime<Utc>` (infallible —
  `ChronoOutOfRange` deleted). `DriverBuilder` Send-bound
  parity with `DeferredDriverBuilder`.
  `TopK::new_unbounded()` + `BurstDetector::new_unbounded()`
  complete the `correlate::*::new_unbounded` family.
- **Plan 131** — `Error::Module::Pipeline` removed (was dead
  code since 0.11). Five new variants added (Driver / Emit /
  Detect / Aggregate / Correlate). `ja3` + `ja4` features
  collapsed into `tls-fingerprints`. `tracing-messages`
  deleted — per-message emission is always-on under
  `tracing`; filter at runtime via `EnvFilter`.
- **Plan 132** — doc overhaul. Migration recipes for plans
  130 / 131 appended to `docs/migration-0.11-to-0.12.md`
  §7-§12.
- **Plan 143** — `flowscope::detect::patterns` module:
  `BeaconDetector<K>` (RITA-style composite CV score),
  `PortScanDetector<K>` (Threshold Random Walk, Jung 2004),
  `DgaScorer` (bigram log-likelihood with embedded English
  baseline corpus compiled at first use). Always-on; no
  Cargo feature gate. Examples:
  `examples/03-detection/{c2_beacon_finder,dga_finder}.rs`.
- **Plan 144** — TLS ECH (Encrypted Client Hello) signal
  extraction. `TlsClientHello` gains `ech_present` /
  `ech_config_id` / `sni_is_outer`; `TlsServerHello` gains
  `ech_retry_configs`; `TlsHandshake` gains `EchOutcome`
  (NotOffered / Accepted / Rejected / Unknown) +
  `ech_config_id`. Required `TlsClientHello` /
  `TlsServerHello` to become `#[non_exhaustive]` + derive
  `Default`; `TlsVersion` derives `Default` with `Tls1_3`
  as the `#[default]` variant. Reference:
  `draft-ietf-tls-esni-22`.
- **Plan 146** — `flowscope::detect::file` module behind the
  new `file-hash` Cargo feature: `Sha256Sink` + `Md5Sink`
  streaming hash sinks for reassembled payload windows,
  plus a 16-format `FileType` magic-byte classifier
  (`Pe` / `Elf` / `MachO` / `Pdf` / `Png` / `Jpeg` / `Gif` /
  `Webp` / `Zip` / `Gzip` / `Bzip2` / `Xz` / `Mp4` / `Mp3` /
  `Sqlite3` / `Unknown`). With `tls-fingerprints` enabled,
  adds zero new transitive deps.

Test count after the 0.12 cycle: 772 passing, zero clippy
warnings under `--all-features --all-targets -D warnings`,
zero rustdoc warnings. EVE example
(`examples/05-export/eve_writer.rs`) verified end-to-end
against `tests/data/mixed_short.pcap`.

CI feature matrix changes: base added `chrono` + `emit-eve`;
expanded collapsed `ja3` + `ja4` into a single `tls-fingerprints`
entry and deleted `tracing-messages`
(no CI matrix entry). Cross-`SlotHandle` Send+Sync compile
assertions in `tests/driver_send.rs` (via `static_assertions`).
Migration recipes: `docs/migration-0.11-to-0.12.md`.

**0.11.0 cycle** (zero-allocation cycle, shipped 2026-06).
Plans 118 / 119 / 120 / 121. Triggered by the netring 0.19
dependency audit; collapses the closed-`M` sum-type `Driver<E,
M>` shape into a typed-slot-drain shape and deletes every 0.9-
era legacy driver type.

Headlines:

- **Plan 121 architectural keystone** — `flowscope::driver`
  becomes the typed-slot shape: `Driver<E>` emits flow-lifecycle
  `Event<K>` only; per-parser typed messages flow through
  `SlotHandle<P::Message, E::Key>` returned by the builder at
  registration time. No closed-`M` sum type, no lift closures,
  zero per-message Box. `flowscope::driver_unified` was renamed
  to `flowscope::driver` at the crate root; the old
  `flowscope::driver` (`FlowDriver`) moved to
  `flowscope::flow_driver`. Public driver-shaped types: 6
  (down from 14 in 0.9).
- **Plan 119** — `Driver::track_into(view, &mut Vec<Event>)` +
  parser API break: `SessionParser` and `DatagramParser` take
  `&mut Vec<Self::Message>` (same idiom as `httparse::Request::parse`).
  Eliminates the per-packet `Vec::new()` at every dispatch
  layer. Bench gate row `track_into` with **5 HTTP slots**:
  **0.000 allocs/packet** in steady state.
- **Plan 120** — HTTP / DNS / TLS payload-type Bytes audit.
  HTTP/1.1 GET parse: **28 → 7 allocs** (-75%) by sharing one
  Arc-backed Bytes for the whole header region and slicing
  zero-copy.
- **Plan 118 §4 small wins** — `Event::FlowPacket::frame`
  field deleted (was `view.frame.to_vec()` clone per packet =
  1.5 GB/sec at 1 Mpps). `parser_kinds::TLS_HANDSHAKE`
  constant added.

Public surface after the cycle: `Driver<E>`, `DriverBuilder<E>`,
`Event<K>`, `SlotHandle<M, K>`, `SlotMessage<M, K>` for the
typed driver; `FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver` kept as raw sync primitives.

The typed `Driver<E>` is `Send + Sync` since 0.13 (plan 156 —
strictly structural; no `unsafe`). `SlotHandle<M, K>` is
`Send + Sync` since 0.12. Move the driver to a tokio task on
a worker core, share a handle via `Arc` with multiple drainers,
the driver runs on the capture thread, or share via `Arc` with
multiple drainers (competitive-consumer semantics — each clone
pops from the same `SegQueue`).

**0.10.0 cycle** (shipped 2026-06). Plan-of-record in
`plans/INDEX.md`. Triggered by the 0.9 examples-writing
postmortem (plan 100). Shipped:

- **Plan 110 sub-B** — quick-win helper sweep. New methods on
  `Timestamp` (`to_unix_f64` / `from_unix_f64` / `relative_to`
  / `from_system_time`), `FlowStats` (rollup helpers),
  `EndReason::as_str()`, `LayerKind::is_l2 / l3 / l4 / tunnel`,
  `Layer<'_>::Display`, `LayerStack::depth / iter_kinds`,
  `KeyIndexed::peek`.
- **Plan 102 sub-D** — `flowscope::well_known` curated
  `(L4Proto, port) → label` table (~70 entries) + accessors on
  `FiveTupleKey` (`well_known_port` / `protocol_label`).
- **Plan 101** — `flowscope::emit` structured event sinks:
  `FlowEventCsvWriter` (RFC-4180 quoting), `ZeekConnLogWriter`
  (tab-separated, `#fields`/`#types`/`#close` headers, UID
  generation) behind `emit`; `FlowEventNdjsonWriter` behind
  `emit-ndjson` (pulls `serde_json`). Plus
  `EndReason::as_zeek_state()`.
- **Plan 102 sub-C** — `flowscope::detect` (Shannon entropy +
  5 light primitives + `NgramDist`).
- **Plan 102 sub-B** — `flowscope::aggregate` (Histogram +
  Percentile / t-digest) behind `aggregate` feature.
- **Plan 110 sub-A** — rustdoc landing pages on
  `flowscope::http` / `tls` / `dns` / `icmp` with curated
  convenience-accessor tables. Plus 9 new HTTP accessors
  (`HttpRequest::referer/accept/content_type/content_length`;
  `HttpResponse::status_class/is_success/is_redirect/
  is_client_error/is_server_error`).
- **Plan 113 sub-A** — `flowscope::detect::signatures` (10
  pure-function magic-byte recognizers + `registry()`).
- **Plan 102 sub-A** — `correlate` extensions (`TimeBucketedSet`
  / `BurstDetector` / `BurstHit` / `TopK` / `Ewma`).
- **Plan 106** — parser ergonomics (`BufferedFrameDrain` +
  `AccumulatingSessionParser` + `PerDatagramParser` +
  `FrameDrainError`).
- **Plan 107** — exchange aggregators (`HttpExchangeParser` +
  `HttpExchange` + `HttpOutcome`; `DnsExchangeParser` +
  `DnsExchange` + `DnsOutcome`).
- **Plan 116 PR 1–4 (partial)** — unified
  `flowscope::driver_unified::{Driver, Event, DriverBuilder,
  Pipeline, PipelineBuilder}`. One `Driver<E, M>` with
  session + datagram + heuristic routing under one
  `Event<K, M>` stream. Includes plan 113 sub-B (heuristic
  routing — `session_heuristic` / `datagram_heuristic` with
  per-flow Probing/Pinned/GaveUp state, `PROBE_BUFFER_CAP`
  64 B, `DEFAULT_PROBE_PACKETS` 4) and a
  `examples/unified_driver_demo.rs` showcase. The 0.9-era
  `FlowSessionDriver` / `FlowDatagramDriver` /
  `FlowMultiSessionDriver` / `Pipeline` (legacy) types stay
  shipped in 0.10 for migration; PR 5 (deletion sweep) is
  deferred to the next major release.

The 0.10 cycle's user-priority plan (116) is substantially
complete. Plan 113 is fully complete (sub-A + sub-B both
landed). Plans 101, 102, 106, 107, 110 are fully complete.

Test count after 0.10 work-in-progress: ~430 passing, zero
clippy warnings under `--all-features --all-targets -D
warnings`, zero rustdoc warnings.

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
├── anomaly_fields.rs            # AnomalyFields trait (plan 126, 0.12.0)
├── anomaly.rs                   # OwnedAnomaly value + DetectorScore trait (plan 147, 0.13.0)
├── timestamp.rs                 # Timestamp + write_iso8601 + to_iso8601 + chrono interop (plan 127, 0.12.0)
├── view.rs                      # PacketView<'a> #[non_exhaustive] = (frame, ts, rx_metadata) + .layers() + .with_rx_metadata (issue #2, 0.17)
├── rx_metadata.rs               # RxMetadata + RxHash + RssHashType + VlanTag + VlanProto + ChecksumStatus (issue #2, 0.17)
├── mac_addr.rs                  # MacAddr #[repr(transparent)] newtype + Display + FromStr + predicates (issue #1, 0.17)
├── extractor.rs                 # FlowExtractor trait + Extracted/Orientation + AnomalyFields for L4Proto (0.12.0)
├── layers/                      # Per-packet layered view (plan 94 Tier 3, 0.9.0)
│   ├── mod.rs                   # Layers + Layer + accessors + tunnel walk + dynamic walk
│   ├── kind.rs                  # LayerKind enum + .layer_number()
│   ├── eth.rs                   # EthernetSlice + VlanSlice + MplsSlice
│   ├── ip.rs                    # Ipv4Slice + Ipv6Slice + ArpSlice
│   ├── transport.rs             # TcpSlice + UdpSlice + Icmpv4Slice + Icmpv6Slice + TcpFlagsView + TcpOption
│   └── tunnel.rs                # GreSlice + VxlanSlice + GtpUSlice
├── correlate/                   # flowscope::correlate (plan 81, 0.9.0; extended in plan 102 sub-A, 0.10)
│   ├── mod.rs                   # public re-exports
│   ├── bucketed.rs              # TimeBucketedCounter<K>
│   ├── burst.rs                 # BurstDetector<K, E> + BurstHit<K>             (plan 102 sub-A, 0.10)
│   ├── ewma.rs                  # Ewma<K>                                       (plan 102 sub-A, 0.10)
│   ├── flow_state_map.rs        # FlowStateMap<T, K> per-flow typed state       (plan 154, 0.13.0)
│   ├── indexed.rs               # KeyIndexed<K, V>  (.peek 0.10; .get_mut + new_unbounded fix plan 154, 0.13.0; .drain_expired + .drain_expired_into plan 160, 0.14.0)
│   ├── neighbor_table.rs        # NeighborTable<L3, L4> + NeighborBinding + NeighborEvent + ArpTable alias (issue #1, 0.17)
│   ├── rolling_rate.rs          # RollingRate<K, V> + RateValue trait — per-key per-second rate (plan 164, 0.14.0)
│   ├── sequence.rs              # SequencePattern + KeylessSequencePattern
│   ├── set.rs                   # TimeBucketedSet<K, V>                         (plan 102 sub-A, 0.10)
│   └── topk.rs                  # TopK<K> (Misra-Gries)                         (plan 102 sub-A, 0.10)
├── detect/                      # flowscope::detect (plan 102 sub-C, 0.10)
│   ├── mod.rs                   # shannon_entropy + 5 light primitives + NgramDist
│   ├── signatures.rs            # 10 magic-byte recognizers + registry          (plan 113 sub-A, 0.10)
│   ├── patterns/                # Named detectors (plan 143, 0.12.0; always-on)
│   │   ├── mod.rs               # public re-exports
│   │   ├── beacon.rs            # BeaconDetector<K> — RITA CV composite score
│   │   ├── portscan.rs          # PortScanDetector<K> — TRW (Jung 2004)
│   │   └── dga.rs               # DgaScorer — bigram log-likelihood + embedded baseline
│   ├── fingerprint.rs           # FingerprintBuilder + FlowFingerprint (issue #4, 0.17; `fingerprint` feature)
│   └── file/                    # File hash sinks (plan 146, 0.12.0; `file-hash` feature)
│       ├── mod.rs               # FileHashSink trait + re-exports
│       ├── types.rs             # FileHashEvent + FileType + magic-byte classify
│       ├── sha256.rs            # Sha256Sink (sha2 crate)
│       └── md5.rs               # Md5Sink (md-5 crate)
├── aggregate/                   # flowscope::aggregate (plan 102 sub-B, 0.10; `aggregate` feature)
│   ├── mod.rs                   # public re-exports
│   ├── histogram.rs             # Histogram + HistogramError
│   └── percentile.rs            # Percentile (wraps `tdigest` crate)
├── emit/                        # flowscope::emit (plan 101, 0.10; `emit` / `emit-ndjson` / `emit-eve` features)
│   ├── mod.rs                   # public re-exports
│   ├── csv.rs                   # FlowEventCsvWriter + CsvOptions
│   ├── eve.rs                   # EveJsonWriter + EveOptions + flow_hash (plan 123, 0.12.0; .write_owned_anomaly + .custom_anomaly_type plan 147, 0.13.0)
│   ├── ndjson.rs                # FlowEventNdjsonWriter + NdjsonOptions (gated on `emit-ndjson`; .write_owned_anomaly plan 147, 0.13.0)
│   └── zeek.rs                  # ZeekConnLogWriter + ZeekOptions
├── well_known/                  # flowscope::well_known (plan 102 sub-D, 0.10)
│   └── mod.rs                   # protocol_label / entries / curated table + LabelTable site-custom overrides (plan 165, 0.14.0)
├── layers/fast.rs               # LayerParser + LayerStack zero-alloc (plan 94 Tier 3 fast path, 0.9.0)
├── driver/                      # flowscope::driver — typed Driver<E> + SlotHandle<M, K> (plan 121, 0.11.0; Send+Sync since plan 156, 0.13.0)
│   ├── mod.rs                   # public re-exports (Driver / DriverBuilder / DeferredDriverBuilder / Event / SlotHandle / SlotMessage / BroadcastSlotHandle)
│   ├── broadcast.rs             # BroadcastSlotHandle<M, K> + BroadcastInner — fan-out delivery (plan 150, 0.13.0)
│   ├── slot.rs                  # SlotHandle<M, K> + SlotMessage<M, K> — Arc<crossbeam_queue::SegQueue> backing (Send + Sync, plan 122, 0.12.0; .drain_n added plan 149, 0.13.0)
│   ├── typed.rs                 # Driver<E> + DriverBuilder<E> + DeferredDriverBuilder<E> + Event<K> + map_flow_event (plan 124, 0.12.0; .session_on_ports_broadcast_each added plan 150, 0.13.0)
│   ├── typed_slot.rs            # TypedConcreteSlot + TypedConcreteDatagramSlot + TypedBroadcastSlot (plan 150 broadcast variant, 0.13.0)
│   └── typed_slot_heuristic.rs  # TypedHeuristicSessionSlot + TypedHeuristicDatagramSlot (FlowDetection FSM)
├── segment_reassembler.rs       # SegmentBufferReassembler OOO hole-fill (plan 74, 0.9.0)
├── extract/                     # built-in extractors (extractors feature)
│   ├── parse.rs                 # internal etherparse wrappers
│   ├── five_tuple.rs            # FiveTuple { proto, a, b }
│   ├── ip_pair.rs               # IpPair (proto-agnostic, useful for ICMP)
│   ├── mac_pair.rs              # MacPair (L2 only; MacAddr-typed since issue #1, 0.17)
│   ├── encap_vlan.rs            # StripVlan<E>
│   ├── encap_mpls.rs            # StripMpls<E>
│   ├── encap_vxlan.rs           # InnerVxlan<E>
│   ├── encap_gtp.rs             # InnerGtpU<E>
│   ├── encap_gre.rs             # InnerGre<E>            (plan 50.1)
│   ├── auto_detect.rs           # AutoDetectEncap<E>     (plan 50.3)
│   ├── flow_label.rs            # FlowLabel<E>           (plan 50.2)
│   └── tagged.rs                # Tagged<E, T> + TaggedKey + Tagger trait — per-packet tag prefix (issue #5, 0.17)
├── event.rs                     # FlowEvent / FlowSide / EndReason / FlowStats
│                                # AnomalyKind / OverflowPolicy   (0.2.0)
│                                # FlowStats::{bytes_for,pkts_for,mean_pkt_size_for,direction_skew} (plan 168, 0.14.0)
│                                # FlowStats::throughput_bps{,_pps,_for,_pps_for} safe-divide accessors (plan 173, 0.14.0)
├── history.rs                   # HistoryString (Zeek-style ShAdaFf)
├── tcp_state.rs                 # TCP state machine (transitions + idle policy)
├── tracker.rs                   # FlowTracker<E, S>     (manual_tick alias added in 50.4)
│                                # hot-cache fast path   (plan 41, 0.2.0)
│                                # snapshot_stats / snapshot_history / forget (0.2.0)
│                                # specialised impl<S> FlowTracker<FiveTuple, S>: lookup_inner + stats_for_inner (plan 161, 0.14.0)
├── reassembler.rs               # Reassembler trait + BufferedReassembler
│                                # buffer cap + OverflowPolicy (plan 42 §1, 0.2.0)
├── driver.rs                    # FlowDriver<E, F, S = ()> (sync wrapper)
│                                # diagnostics patch + BufferOverflow synthesis +
│                                # with_emit_anomalies      (plan 42 §2/§3, 0.2.0)
├── session.rs                   # SessionParser / DatagramParser traits + factories + SessionEvent
│                                # + AccumulatingSessionParser / PerDatagramParser /
│                                #   BufferedFrameDrain / FrameDrainError (plan 106, 0.10)
├── session_driver.rs            # FlowSessionDriver — sync mirror of session_stream (plan 25, 0.2.0)
│                                # Refactored to wrap FlowDriver (plan 51, 0.3.0)
├── datagram_driver.rs           # FlowDatagramDriver — sync UDP mirror (plan 57, 0.3.0)
├── dedup.rs                     # Dedup — content-hash + window dedup (plan 49, 0.3.0)
├── obs.rs                       # metrics / tracing hooks (plan 40, 0.2.0)
│                                # (former tracing-messages sub-feature removed in 0.12, plan 131 — always-on under `tracing`)
├── http/                        # `http` feature
│   ├── exchange.rs              # HttpExchangeParser + HttpExchange + HttpOutcome (plan 107, 0.10)
│   ├── parser.rs                # internal step() machine (httparse-based)
│   ├── session.rs               # HttpParser (SessionParser, plan 31, the only public shape since 0.9.0)
│   └── types.rs                 # HttpRequest / HttpResponse / HttpConfig
│                                # + 9 new accessors                              (plan 110 sub-A, 0.10)
├── tls/                         # `tls` feature
│   ├── parser.rs                # internal step() machine (tls-parser-based)
│   ├── session.rs               # TlsParser (SessionParser, the only public shape since 0.9.0)
│   ├── handshake.rs             # TlsHandshakeParser aggregator (plan 97, 0.9.0)
│   ├── fingerprint.rs           # JA3 (gated by `tls-fingerprints` feature; was `ja3` pre-0.12)
│   ├── ja4.rs                   # JA4 (gated by `tls-fingerprints` feature; was `ja4`; plan 97, 0.9.0)
│   └── types.rs                 # TlsClientHello / TlsServerHello / TlsAlert / TlsConfig
├── dns/                         # `dns` feature
│   ├── parser.rs                # parse_message / parse_message_at (simple-dns-based)
│   ├── correlator.rs            # Correlator<S> — query/response matching
│   ├── datagram.rs              # DnsUdpParser (DatagramParser; correlating, plan 37)
│   ├── exchange.rs              # DnsExchangeParser + DnsExchange + DnsOutcome   (plan 107, 0.10)
│   ├── session.rs               # DnsTcpParser (SessionParser, RFC 1035 §4.2.2 framing)
│   └── types.rs                 # DnsQuery / DnsResponse / DnsRdata / DnsConfig
├── icmp/                        # `icmp` feature (`mod types` promoted to `pub mod` in plan 162, 0.14.0)
│   ├── parser.rs                # parse_v4 / parse_v6 stateless decoders
│   ├── datagram.rs              # IcmpParser (DatagramParser, plan 76, 0.7.0)
│   └── types.rs                 # IcmpMessage / IcmpType variants + DestUnreachableKind + IcmpType::dest_unreachable_kind (plan 162, 0.14.0) + MtuSignalKind + IcmpType::mtu_signal (plan 170, 0.14.0)
├── arp/                         # `arp` feature (issue #1, 0.17)
│   ├── mod.rs                   # public re-exports + module doc
│   ├── parser.rs                # arp::parse(payload) + arp::parse_frame(frame) + ArpParser marker
│   └── types.rs                 # ArpMessage + ArpOp + is_gratuitous + is_likely_spoof
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
- `tests/driver.rs` — typed `Driver<E>` + `SlotHandle` /
  port routing / heuristic / broadcast / force_close
  (plan 121, 0.11.0).
- `tests/driver_send.rs` — `static_assertions::assert_impl_all!`
  on `SlotHandle: Send + Sync` + cross-thread drain +
  competitive-consumer clone semantics (plan 122, 0.12.0).
- `tests/driver_deferred.rs` — `Driver::deferred()` +
  `DeferredDriverBuilder::build_with(ext)` equivalence with
  the eager path + every builder knob propagates (plan 124,
  0.12.0).
- `tests/anomaly_fields.rs` — `AnomalyFields` impls on
  `FiveTupleKey` / `L4Proto` / `AnomalyKind` (plan 126,
  0.12.0).
- `tests/layers.rs` + `tests/layers_extended.rs` — Tier 3
  per-packet view (direct slices, dynamic walk, tunnel walking,
  ARP/MPLS/ICMP).
- `tests/auto_sweep.rs` — `FlowTracker::with_auto_sweep` (plan
  75, 0.9.0).
- `tests/error_chain.rs` — unified `flowscope::Error` source
  chain across pcap I/O, ICMP, DNS (plan 96, 0.9.0).
- `tests/quick_wins.rs` — Timestamp/FlowStats/EndReason/
  LayerKind/Layer/LayerStack/KeyIndexed helpers (plan 110
  sub-B, 0.10).
- `tests/well_known.rs` — `FiveTupleKey` `well_known_port` /
  `protocol_label` (plan 102 sub-D, 0.10).
- `tests/emit_csv.rs`, `tests/emit_ndjson.rs`,
  `tests/emit_zeek.rs` — three writers in `flowscope::emit`
  (plan 101, 0.10).
- `tests/emit_eve.rs` — Suricata EVE JSON writer:
  flow / anomaly / stats event_types + flow_hash
  determinism + direction-invariance + severity mapping
  + every-line-is-valid-JSON (plan 123, 0.12.0).
- `tests/parser_helpers.rs` — `BufferedFrameDrain` /
  `AccumulatingSessionParser` / `PerDatagramParser` (plan
  106, 0.10).
- `tests/http_exchange.rs`, `tests/dns_exchange.rs` —
  exchange aggregators (plan 107, 0.10).
- `benches/{extractor,tracker,reassembler,session_driver,dedup}.rs`
  — criterion benchmark harness (0.3.0). Run with
  `cargo bench --all-features`; baselines in
  `docs/performance.md`.

## Build & Test

```bash
# Default features
cargo test

# All features (incl. tls-fingerprints, dns, pcap, metrics, tracing)
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

- `INDEX.md` — backlog index, project conventions, deferred
  items list (capability gaps without active plans), and the
  numbering scheme.
- `169-cycle-0-14-umbrella.md` — 0.14 cycle umbrella; retired
  once `0.14.0` ships to crates.io.

Shipped cycle wishlists / umbrellas / per-plan files are
deleted after the cycle releases — the durable record is in
`CHANGELOG.md`, the `docs/migration-*.md` series, and
`git log`. See [`plans/INDEX.md`](plans/INDEX.md) for the
numbering scheme used by new plans.

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
