# Changelog

## Unreleased — API ergonomics

Driven by the audit in
[`plans/API-ERGONOMICS-REVIEW.md`](plans/API-ERGONOMICS-REVIEW.md).
Pre-1.0 breaking changes; `netring` and other consumers update in
lockstep.

### Breaking

- **Drivers lose the `S` per-flow-user-state type parameter.**
  `FlowDriver<E, F, S>` → `FlowDriver<E, F>`,
  `FlowSessionDriver<E, P, S>` → `FlowSessionDriver<E, P>`,
  `FlowDatagramDriver<E, P, S>` → `FlowDatagramDriver<E, P>`. The
  drivers always run their tracker with `S = ()`; per-flow user
  state remains on `FlowTracker<E, S>` for code that builds the
  tracker directly. This removes the `<_, ()>` /
  `<FiveTuple, _, ()>` annotation that type-parameter-default
  inference forced on every construction site.
  *Migration:* delete the trailing `, ()` from any explicit driver
  type; for per-flow user state, use `FlowTracker` directly.
- **`FlowSessionDriver` / `FlowDatagramDriver` constructors take the
  parser by value.** `new(extractor)` → `new(extractor, parser)`;
  `with_config(extractor, config)` → `with_config(extractor,
  parser, config)`. The parser bound relaxes from `Default + Clone`
  to just `Clone`, so non-`Default` (config-built) parsers now
  work.
  *Migration:* `FlowSessionDriver::<_, P>::new(ext)` →
  `FlowSessionDriver::new(ext, P::default())`.

### Added

- **`finish()` on all three drivers** — `FlowDriver::finish()`,
  `FlowSessionDriver::finish()`, `FlowDatagramDriver::finish()`.
  Sweeps every still-open flow to its end; call once when input is
  exhausted. Equivalent to `sweep(Timestamp::MAX)` — replaces the
  ad-hoc "sweep with a far-future timestamp" pattern.
- **`Timestamp::MAX`** — the maximum representable timestamp
  (`u32::MAX` seconds), for forcing an end-of-input flush.
- **`track()` accepts `impl Into<PacketView>`** on `FlowTracker`,
  `FlowDriver`, `FlowSessionDriver`, and `FlowDatagramDriver`, plus a
  new `impl From<&OwnedPacketView> for PacketView`. A pcap
  `&OwnedPacketView` can be passed straight to `track()` — no
  `.as_view()`. Existing `track(packet_view)` calls are unaffected
  (`Into` is reflexive); `OwnedPacketView::as_view()` is retained.

## 0.3.0 — Production hardening

Eleven sub-plans driven by external feedback from the `des-rs`
team ([`docs/feedback-2026-05-14-des-rs.md`](docs/feedback-2026-05-14-des-rs.md))
plus four planning-review additions. The plans themselves have
been pruned from `plans/` (shipped → deleted convention); the
implementation is in `git log` under the `plan NN:` commit
prefixes.

### Highlights

- **Live `FlowStats` snapshots** (Plan 46)
  via `FlowDriver::snapshot_flow_stats()` and
  `FlowSessionDriver::snapshot_flow_stats()`. Lazy iterator
  returning `(K, FlowStats)` with reassembler diagnostics
  patched in. Use `.collect::<Vec<_>>()` for the snapshot-
  everything case; `.take(1)` / `.filter()` consumers pay
  nothing for the rest.
- **Reassembler high-watermark** on `FlowStats` (peak buffer
  occupancy per side). Useful for tuning
  `max_reassembler_buffer`. New
  `flowscope_reassembler_high_watermark_bytes` metric (histogram).
- **Per-key idle timeouts** (Plan 47)
  via `FlowTracker::set_idle_timeout_fn(F)` and the matching
  `with_idle_timeout_fn(F)` builders on both drivers. Plus
  `FiveTupleKey::either_port(u16) -> bool` helper for the
  canonical port-based override case.
- **Monotonic timestamps** (opt-in,
  Plan 48) via
  `with_monotonic_timestamps(true)`. Clamps NIC timestamps to a
  running max — useful when downstream consumers want a strictly
  non-decreasing timeline.
- **Sync-side dedup** (Plan 49)
  via the new `flowscope::Dedup` primitive and
  `with_dedup(Dedup::loopback())` builder on both drivers.
  Content-hash + length + time-window match; ~1.2 µs per
  1500-byte frame.
- **`FlowDatagramDriver`** (Plan 57)
  — sync mirror of netring's `datagram_stream` for UDP-based
  `DatagramParser`s.
- **`SessionEvent::Anomaly`** forwarding
  (Plan 51) +
  `FlowSessionDriver::with_emit_anomalies(true)`. Plus an
  internal refactor: `FlowSessionDriver` now wraps `FlowDriver`
  for single source of truth on anomaly / overflow synthesis.
- **Parser fallibility** (Plan 55)
  via `SessionParser::is_poisoned()` / `poison_reason()` (mirror
  on `DatagramParser`). On poison, the driver synthesises
  `Ended { reason: ParseError }` plus optional
  `Anomaly { kind: SessionParseError, .. }`.
- **`tracing-messages` sub-feature** (Plan 56)
  — emit `tracing::trace!` per `SessionEvent::Application`.
  Off by default; targets `flowscope.message`.
- **Criterion benchmark harness** (Plan 54)
  under `benches/` with five groups (extractor, tracker,
  reassembler, session_driver, dedup). Documented baselines in
  [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md). Plan 41's
  hot-cache claim verified at ~1.4× monoflow vs 10k-flow
  round-robin.
- **Round-trip CI fixture** (Plan 52)
  — `tests/round_trip.rs` exercises
  synthesize→pcap→PcapFlowSource→FlowSessionDriver→assert
  byte-equality across hand-written + proptest cases.
- **SessionParser author guide**
  (Plan 53) — new
  walkthrough section in `docs/SESSION_GUIDE.md` covering the
  trait contract, partial-buffer pattern, resync strategies,
  and testing approach.

### Breaking changes

Pre-1.0 release; these are minor breaks that pay off in
long-term API quality:

- **`SessionEvent` is now `#[non_exhaustive]`** with a new
  `Anomaly` variant. External `match` blocks need a wildcard
  arm.
- **`EndReason` is now `#[non_exhaustive]`** with a new
  `ParseError` variant. External `match` blocks over
  `EndReason` need a new arm (treat it like `Rst` for
  cleanup semantics).
- **`SessionParser::Message` and `DatagramParser::Message`**
  gain a `Debug` trait bound (was just `Send + 'static`). All
  four shipped parsers + the example parser already derive
  `Debug`; external impls add one derive line.
- **`Reassembler` trait gains a `high_watermark()` method**
  with a default-zero impl. Existing impls compile unchanged;
  custom reassemblers can override to surface their own peak.
- **`SessionParser` / `DatagramParser` gain `is_poisoned()` +
  `poison_reason()`** methods with default impls (`false` /
  `None`). Existing impls compile unchanged.

Internal-only:
- **`FlowSessionDriver` is rewired** to wrap `FlowDriver`
  internally. Public signature unchanged; consumers using the
  type alias / generic shape need a recompile.
- **`FlowDriver::track` split into `track_pending` +
  `finalize`** for callers that need access to reassemblers
  between segment dispatch and Ended-event finalization. The
  high-level `track` and `sweep` methods keep the existing
  one-shot semantics.

### New API

- `flowscope::FlowDatagramDriver<E, P, S>` — sync UDP driver.
- `flowscope::Dedup` — content-hash dedup primitive.
- `flowscope::IdleTimeoutFn<K>` — predicate type alias for
  per-key idle-timeout overrides.
- `FlowTracker::all_flow_stats()` — borrow-iterator over live
  FlowStats.
- `FlowTracker::set_idle_timeout_fn` / `clear_idle_timeout_fn`.
- `FlowDriver::snapshot_flow_stats()` / `with_idle_timeout_fn`
  / `with_dedup` / `with_monotonic_timestamps` /
  `track_pending` / `sweep_pending` / `finalize` /
  `reassembler` / `drain_buffer` / `emits_anomalies` / `dedup`.
- `FlowSessionDriver::snapshot_flow_stats` /
  `with_idle_timeout_fn` / `with_dedup` /
  `with_monotonic_timestamps` / `dedup`.
- `FiveTupleKey::either_port(u16) -> bool`.
- `BufferedReassembler::high_watermark()` /
  `Reassembler::high_watermark()` trait method.
- `Timestamp::saturating_sub(other) -> Duration`.
- `EndReason::ParseError`.
- `AnomalyKind::SessionParseError { side, reason }`.
- `flowscope::obs::METRIC_REASSEMBLER_HIGH_WATERMARK`.

### Migration

Most consumers need only a recompile. The exhaustive-match
fixes:

```diff
- match reason {
-     EndReason::Fin => ...,
-     EndReason::Rst => ...,
-     EndReason::IdleTimeout => ...,
-     EndReason::Evicted => ...,
-     EndReason::BufferOverflow => ...,
- }
+ match reason {
+     EndReason::Fin => ...,
+     EndReason::Rst => ...,
+     EndReason::IdleTimeout => ...,
+     EndReason::Evicted => ...,
+     EndReason::BufferOverflow => ...,
+     EndReason::ParseError => ..., // treat like Rst
+     _ => ..., // future variants land in 0.4.0+
+ }

- match event {
-     SessionEvent::Started { .. } => ...,
-     SessionEvent::Application { .. } => ...,
-     SessionEvent::Closed { .. } => ...,
- }
+ match event {
+     SessionEvent::Started { .. } => ...,
+     SessionEvent::Application { .. } => ...,
+     SessionEvent::Closed { .. } => ...,
+     SessionEvent::Anomaly { .. } => ..., // new in 0.3.0
+     _ => ..., // forward-compatible
+ }
```

For external `SessionParser` / `DatagramParser` impls whose
`Message` type didn't derive `Debug`:

```diff
- #[derive(Clone)]
+ #[derive(Debug, Clone)]
  struct MyMessage { ... }
```

## 0.2.0 — Reassembly observability + metrics/tracing hooks

This minor release ships the bundle described in
Plan 42:
optional buffer caps on `BufferedReassembler`, end-of-flow reassembly
diagnostics on `FlowStats`, and a live `FlowEvent::Anomaly` stream.
It also adds opt-in `metrics` + `tracing` features (Plan 40)
that share the same `AnomalyKind` vocabulary, plus a hot-cache
fast-path on `FlowTracker` (Plan 41).
The motivating consumer is [`des-rs`](https://github.com/p13marc/des-rs)'s
`tools/des-capture`, which can now drop its hand-rolled
`TcpStreamTracker` in favour of flowscope.

### Highlights

- **`BufferedReassembler::with_max_buffer(n)`** — optional per-side
  byte cap, paired with **`with_overflow_policy(...)`** to choose:
  - `OverflowPolicy::SlidingWindow` (default) — drop oldest bytes
    from the buffer; flow stays alive; parser sees a gap and must
    resync. Best for stream-shaped / append-only protocols.
  - `OverflowPolicy::DropFlow` — poison the reassembler; the driver
    synthesises an `Ended { reason: EndReason::BufferOverflow }`
    event on the next tick. Best for framed binary protocols (DES
    PSMSG, TLS records, length-prefixed wire formats).
- **Reassembly diagnostics on `FlowStats`** — four new fields
  (`reassembly_dropped_ooo_initiator/responder`,
  `reassembly_bytes_dropped_oversize_initiator/responder`) populated
  by `FlowDriver` when each flow ends.
- **Live `FlowEvent::Anomaly`** — opt-in via
  `FlowDriver::with_emit_anomalies(true)`. Emits one `AnomalyKind`
  per (flow, side, kind) per tick:
  - `BufferOverflow { side, bytes, policy }`
  - `OutOfOrderSegment { side, count }`
  - `FlowTableEvictionPressure { evicted_in_tick, evicted_total }` —
    tracker-global signal that `max_flows` is the bottleneck.

### Breaking changes

- **`#[non_exhaustive]`** applied project-wide to every public
  struct/enum that's likely to grow over time. From now on, additive
  changes are unconditionally non-breaking.
  Affected types: `FlowStats`, `FlowTrackerConfig`, `AnomalyKind`,
  `OverflowPolicy`. Construct via `::default()` and mutate; do not
  rely on struct-literal construction from outside the crate.
- **`FlowEvent::key()`** now returns `Option<&K>` (was `&K`).
  `None` is reserved for tracker-global anomalies (e.g.
  `FlowTableEvictionPressure`); per-flow events still return
  `Some(key)`. Migrate via `event.key().expect("non-anomaly")` or
  pattern-match.
- **`EndReason`** gained a new `BufferOverflow` variant. Any
  exhaustive `match EndReason { ... }` needs a new arm. Treat it
  like `Rst` for cleanup semantics (the driver does).
- **`Reassembler` trait** gained three default-zero diagnostic
  methods (`dropped_segments`, `bytes_dropped_oversize`,
  `is_poisoned`). Existing impls compile unchanged; surface real
  counts by overriding.

### Observability hooks (Plan 40)

- New optional `metrics` Cargo feature: counters, gauges, and
  histograms wired through `FlowTracker` and `FlowDriver`. Metric
  vocabulary documented in [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).
- New optional `tracing` Cargo feature: structured events at flow
  lifecycle transitions and on every emitted anomaly.
- Both features are zero-cost when off (compile-time stubbed).
- Public metric-name constants exported from `flowscope::obs`
  (`METRIC_FLOWS_CREATED`, `METRIC_ANOMALIES`, …).

### Sync session driver + worked example (Plan 25)

- **`FlowSessionDriver<E, P, S>`** — the sync mirror of netring's
  async `session_stream`. Bundles `FlowTracker` + per-(flow, side)
  `BufferedReassembler` + per-flow `SessionParser` and yields
  `SessionEvent`s without a runtime dependency. Honours
  `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`
  automatically.
- **`examples/length_prefixed_pcap.rs`** — end-to-end example of
  writing a custom `SessionParser` for a length-prefixed binary
  protocol (PSMSG-shaped). Demonstrates partial-header / partial-body
  buffering and pairs with a deterministic pcap fixture under
  `tests/fixtures/length_prefixed/`.
- New integration test `tests/length_prefixed_example.rs` verifies
  the parser against the fixture and against byte-by-byte sliced
  input.

### Performance (Plan 41)

- `FlowTracker` gains a "last flow seen" hot-cache that skips the
  hash lookup when consecutive packets share a key. Estimated 2x
  throughput on monoflow workloads (single iperf3 / HTTP/2 stream),
  small win on heterogeneous traffic. No API impact.

### New API

- `flowscope::OverflowPolicy` (`SlidingWindow`, `DropFlow`).
- `flowscope::AnomalyKind` (non_exhaustive).
- `BufferedReassembler::with_max_buffer` /
  `with_overflow_policy` / `bytes_dropped_oversize` / `is_poisoned`.
- `BufferedReassemblerFactory::with_max_buffer` /
  `with_overflow_policy`.
- `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`.
- `FlowTracker::snapshot_stats(&K)` /
  `snapshot_history(&K)` / `forget(&K)` — accessors used by the
  driver to synthesise `BufferOverflow` end events.
- `FlowDriver::with_emit_anomalies(bool)`.
- `FlowEvent::Anomaly { key, kind, ts }`.
- `FlowSessionDriver<E, P, S>` — sync session driver that bundles
  `FlowTracker` + per-(flow, side) reassembler + per-flow
  `SessionParser`. The sync mirror of netring's `session_stream`.
- `flowscope::obs` module — `metrics` / `tracing` hook surface plus
  the public metric-name constants.

### Migration

Most consumers need only:

```diff
- let cfg = FlowTrackerConfig { max_flows: 100, ..Default::default() };
+ let mut cfg = FlowTrackerConfig::default();
+ cfg.max_flows = 100;
```

(Within the same crate, struct-literal syntax with `..Default::default()`
keeps working — `non_exhaustive` only restricts external constructors.)

If you destructure or pattern-match `FlowEvent::Ended { stats: FlowStats { ... } }`,
add `..` to the inner pattern:

```diff
- FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, ... } } => ...
+ FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, .. } } => ...
```

If you call `event.key()` and treat the return as a borrow:

```diff
- let k: &K = event.key();
+ let k: Option<&K> = event.key();
```

---

## 0.1.0 — Initial release

`flowscope` is a passive flow & session tracking library extracted
from the previous `netring-flow{,-http,-tls,-dns,-pcap}` workspace
into a single, publishable crate with feature-gated modules. The
core layers (extractor → tracker → reassembler → session/datagram
parsers) are runtime-free and cross-platform; protocol parsers are
opt-in via Cargo features.

### Core

- `PacketView` / `Timestamp` — abstract input.
- `FlowExtractor` trait + built-in extractors: `FiveTuple`, `IpPair`,
  `MacPair`. Decap combinators: `StripVlan`, `StripMpls`, `InnerVxlan`,
  `InnerGtpU`, `InnerGre`. Combinator: `AutoDetectEncap` (tries
  plain → VLAN → MPLS → VXLAN → GTP-U → GRE in order). Key
  augmentation: `FlowLabel<E>` (IPv6 flow label).
- `FlowTracker<E, S>` — bidirectional flow accounting, TCP state
  machine (`SynSent → Established → FinWait → Closed` + `Reset`),
  per-protocol idle timeouts (Suricata defaults), LRU eviction.
  `manual_tick(now)` alias for `sweep`.
- `FlowEvent<K>` — `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with `EndReason`, `FlowStats`, `HistoryString`).
- `Reassembler` / `ReassemblerFactory<K>` — sync per-(flow, side) TCP-
  segment hook; `BufferedReassembler` built-in.
- `FlowDriver<E, F, S>` — sync wrapper combining tracker + reassembler.
- `SessionParser` / `DatagramParser` (with `*Factory<K>` companions
  and blanket impls for `Default + Clone` parsers) — typed L7 message
  parsing per flow. Trait shape stable for the 1.0 lock; future
  additions will be additive.
- `SessionEvent<K, M>` — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.

### Protocol parsers (each behind its own feature)

- **`http`** — HTTP/1.0 / HTTP/1.1 via `httparse`. Both
  `HttpFactory` (callback-style) and `HttpParser` (`SessionParser`)
  ship side by side. Pipelined messages, split segments, and
  Connection: close bodies handled.
- **`tls`** — passive TLS handshake observer. `TlsFactory`
  (callback) and `TlsParser` (`SessionParser`) emit ClientHello /
  ServerHello / Alert events. Records past ChangeCipherSpec are
  silently skipped (encrypted). Optional `ja3` sub-feature for JA3
  fingerprinting (GREASE stripped per RFC 8701).
- **`dns`** — DNS message parser. UDP path: `DnsUdpObserver`
  (callback-style tap on top of any `FlowExtractor`) and
  `DnsUdpParser` (`DatagramParser`). TCP path: `DnsTcpParser`
  (`SessionParser`, RFC 1035 §4.2.2 length-prefixed framing).
  Per-flow query/response correlator with 16-bit transaction ID
  scoping, oldest-first eviction on overflow, sweep for unanswered
  timeouts.
- **`pcap`** — `PcapFlowSource` for offline replay; produces views &
  flow events from any `.pcap` file.

### Tokio integration

For an async stream over flow / session / datagram events, see
[`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`,
`.session_stream`, `.datagram_stream`, and `.broadcast`. The traits
they consume live in this crate; the Stream impls live in `netring`.

### Tests

- 167 unit tests + 11 parser proptests (splitting invariance and
  no-panic across HTTP / TLS / DNS-UDP / DNS-TCP) + tracker
  proptests (FiveTuple canonicalization, TCP state-machine
  invariants).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo doc --all-features --no-deps` clean.

### Documentation

- [`docs/SESSION_GUIDE.md`](docs/SESSION_GUIDE.md) — decision-flow
  for picking between `FlowEvent`, `Reassembler`, `*Factory<H>`,
  `SessionParser`, `DatagramParser`, and `Conversation<K>`. Includes
  migration recipes from callback-style factories to the typed-stream
  parser API.

### Notes

- This crate replaces `netring-flow`, `netring-flow-http`,
  `netring-flow-tls`, `netring-flow-dns`, and `netring-flow-pcap`
  (none of which were ever published to crates.io). Migration:
  rename your dep to `flowscope` and update import paths from
  `netring_flow_http::X` → `flowscope::http::X` (and similarly for
  `tls` / `dns` / `pcap`). Trait names and types are unchanged.
- Out of scope for v0.1.0:
  - HTTP/2, HTTP/3 (no plan yet).
  - DoH / DoT / DoQ (no plan yet).
  - NetFlow / IPFIX export (plan 32, deferred).
  - Observability (`metrics` / `tracing` integration; plan 40,
    deferred).
  - Zero-copy reassembly (plan 41, deferred — needs profiling-guided
    redesign).
  - IPv6 fragment reassembly (plan 50.5, deferred).
  - `protolens` companion (plan 21, on demand).
  - CLI tooling (`flow-summary`, `flow-replay`; plan 60, would need
    workspace conversion).
