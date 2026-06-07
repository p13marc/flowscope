# Plan 116 — driver + event unification

## Summary

Collapse the 6 driver types (`FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver`, `FlowMultiSessionDriver`, plus the
proposed `FlowMultiDriver` and `Pipeline`-as-separate-thing)
into one `Driver<E, M>`. Collapse the 4 event types
(`FlowEvent`, `SessionEvent`, planned `MultiEvent`, planned
`Event` on Pipeline) into one `Event<K, M>`. Rewrite `Pipeline`
as a one-screen wrapper over `Driver`.

This is the centerpiece API redesign for the 0.10 cycle —
identified by plan 115's strategic review. Replaces plan 109
(cross-L4 driver) and absorbs plan 108 (packet enrichment) as
sub-tasks.

After 116: **1 driver type, 1 event type, 1 builder**.
Consumers learn three names — `FlowTracker` (raw),
`Driver<E, M>` (orchestrated), `Pipeline<E, M>` (sourced) —
instead of fourteen.

## Status

**Ready to implement.** Targets 0.10.0. The centerpiece of the
cycle; lands as a phased PR series (~5 PRs) so individual
reviews stay tractable.

## Prerequisites

- **Plan 96** — `flowscope::Error` (shipped 0.9).
- **Plan 106** — parser ergonomics
  (`AccumulatingSessionParser` + fallible variants). Plan 116
  consumes the fallible API in its dispatch path.
- **Plan 111** — quick wins (`Timestamp` / `FlowStats` /
  `EndReason::as_str` / etc.). The new `Event` shape uses
  several of these.
- Plan 113 (signatures) lands independently; plan 114
  (heuristic routing) builds on 116 not 109.

## Out of scope

- **Unifying `SessionParser` / `DatagramParser` traits.**
  Stable since 0.1.0; deferred to 1.0 per plan 115's
  recommendation.
- **`FlowTracker` internals.** Unchanged. `Driver` uses it as
  the underlying primitive.
- **Reassembler trait or implementations.** Unchanged.
- **Extractor trait or combinators.** Unchanged.
- **Async story.** flowscope stays sync.
- **`#[derive(Driver)]` macro or other declarative builders.**
  Defer to post-1.0.

---

## API after 116

### `Driver<E, M>`

```rust
// src/driver/mod.rs

pub struct Driver<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{ /* … */ }

impl<E, M> Driver<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Construct a builder. The only public way to start.
    pub fn builder(extractor: E) -> DriverBuilder<E, M>;

    /// Process a packet. Returns the merged event stream.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>)
        -> Vec<Event<E::Key, M>>;

    /// Periodic sweep. Idle-timeout `Ended` events + parser
    /// `on_tick` outputs.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<Event<E::Key, M>>;

    /// End-of-input flush.
    pub fn finish(&mut self) -> Vec<Event<E::Key, M>>;

    /// Borrow the underlying tracker for introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()>;
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()>;
}
```

### `DriverBuilder<E, M>`

```rust
pub struct DriverBuilder<E, M>
where
    E: FlowExtractor,
    M: Send + 'static,
{ /* … */ }

impl<E, M> DriverBuilder<E, M> {
    /// Tracker config override.
    pub fn config(self, c: FlowTrackerConfig) -> Self;

    /// Emit anomaly events inline.
    pub fn emit_anomalies(self, on: bool) -> Self;

    /// Strictly non-decreasing timestamps.
    pub fn monotonic_timestamps(self, on: bool) -> Self;

    /// Per-key idle-timeout override.
    pub fn idle_timeout_fn<F>(self, f: F) -> Self
    where F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + 'static;

    /// Content-hash dedup.
    pub fn dedup(self, dedup: Dedup) -> Self;

    /// **Plan 108 absorbed:** emit per-packet TCP info + frame
    /// bytes on `Event::FlowPacket`.
    pub fn emit_packet_details(self, on: bool) -> Self;

    // ── Session (TCP) parser registration ─────────────────

    pub fn session_on_ports<P, I, F>(self, parser: P, ports: I, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(P::Message) -> M + Send + 'static;

    pub fn session_broadcast<P, F>(self, parser: P, lift: F) -> Self where /* … */;

    /// **Plan 114:** heuristic routing — signature-based dispatch.
    pub fn session_heuristic<P, F>(
        self, parser: P,
        signature: detect::signatures::SignatureFn,
        lift: F,
    ) -> Self where /* … */;

    pub fn session_heuristic_with_budget<P, F>(
        self, parser: P,
        signature: detect::signatures::SignatureFn,
        max_probe_packets: u8,
        lift: F,
    ) -> Self where /* … */;

    // ── Datagram (UDP) parser registration ────────────────

    pub fn datagram_on_ports<P, I, F>(self, parser: P, ports: I, lift: F) -> Self where /* … */;
    pub fn datagram_broadcast<P, F>(self, parser: P, lift: F) -> Self where /* … */;
    pub fn datagram_heuristic<P, F>(self, parser: P, signature: SignatureFn, lift: F) -> Self where /* … */;

    pub fn build(self) -> Driver<E, M>;
}
```

### `Event<K, M>`

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event<K, M> {
    /// First packet of a new flow.
    FlowStarted {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP flow reached `Established` state (3-way handshake
    /// complete). Not emitted for UDP/ICMP flows.
    FlowEstablished {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// Per-packet event. The `tcp` and `frame` fields are
    /// populated only when `emit_packet_details(true)` was
    /// called on the builder (plan 108 absorbed).
    FlowPacket {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        tcp: Option<TcpInfo>,
        frame: Option<Bytes>,
    },

    /// Flow ended (FIN / RST / idle / eviction).
    FlowEnded {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
    },

    /// Periodic `FlowStats` snapshot — emitted when
    /// `flow_tick_interval` is set.
    FlowTick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },

    /// L7 message emitted by a registered parser.
    /// `parser_kind` distinguishes which parser emitted it.
    Message {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        parser_kind: &'static str,
    },

    /// Parser-level close — a session parser drained its
    /// `fin_*` accumulator. Distinct from `FlowEnded` (which
    /// fires once per flow); this fires per (parser, flow).
    /// UDP parsers don't emit this.
    ParserClosed {
        key: K,
        parser_kind: &'static str,
        reason: EndReason,
        ts: Timestamp,
    },

    /// Live per-flow anomaly. Emitted only when
    /// `emit_anomalies(true)` is set.
    FlowAnomaly {
        key: K,
        kind: AnomalyKind,
        ts: Timestamp,
    },

    /// Live tracker-global anomaly.
    TrackerAnomaly {
        kind: AnomalyKind,
        ts: Timestamp,
    },
}

impl<K, M> Event<K, M> {
    pub fn key(&self) -> Option<&K>;
    pub fn timestamp(&self) -> Timestamp;
    pub fn parser_kind(&self) -> Option<&'static str>;
    pub fn anomaly_kind(&self) -> Option<&AnomalyKind>;

    /// Convenience: is this any of the flow-lifecycle variants?
    pub fn is_flow_event(&self) -> bool;
    /// Convenience: is this a Message or ParserClosed?
    pub fn is_parser_event(&self) -> bool;
}
```

### `Pipeline<E, M>`

```rust
// src/pipeline.rs

pub struct Pipeline<E, M>
where E: FlowExtractor, M: Send + 'static,
{
    driver: Driver<E, M>,
}

impl<E, M> Pipeline<E, M> {
    pub fn builder(extractor: E) -> PipelineBuilder<E, M> { … }

    pub fn run_pcap(&mut self, path: impl AsRef<Path>)
        -> Result<PipelineIter<'_, E, M>> { … }

    pub fn run_iter<I>(&mut self, iter: I) -> PipelineIter<'_, E, M>
    where I: IntoIterator<Item = OwnedPacketView> + 'static { … }

    pub fn reset(&mut self) { … }
    pub fn driver(&self) -> &Driver<E, M>;
    pub fn driver_mut(&mut self) -> &mut Driver<E, M>;
}

pub struct PipelineBuilder<E, M> {
    inner: DriverBuilder<E, M>,
    pcap_options: PcapOptions,
    monotonic_timestamps: bool,  // default true for offline replay
}

impl<E, M> PipelineBuilder<E, M> {
    // Proxy every Driver builder method through directly.
    pub fn session_on_ports<P, I, F>(mut self, parser: P, ports: I, lift: F) -> Self { … }
    pub fn datagram_on_ports<P, I, F>(...) -> Self { … }
    pub fn session_heuristic<P, F>(...) -> Self { … }
    // ... all 8 registration methods proxied ...

    pub fn config(self, c: FlowTrackerConfig) -> Self { … }
    pub fn emit_anomalies(self, on: bool) -> Self { … }
    // ... etc ...

    pub fn build(self) -> Pipeline<E, M> { … }
}
```

`Pipeline` IS `Driver` + source. The builder transparently
proxies — users learn one API, use it at both tiers.

---

## Migration: before / after

### Single-parser TCP (was `FlowSessionDriver`)

```rust
// 0.9
let mut driver = FlowSessionDriver::new(ext, HttpParser::default());
for ev in driver.track(view) {
    match ev {
        SessionEvent::Application { message, .. } => …,
        SessionEvent::Started { .. } => …,
        SessionEvent::Closed { .. } => …,
        _ => {}
    }
}

// 0.10
let mut driver = Driver::<_, HttpMessage>::builder(ext)
    .session_broadcast(HttpParser::default(), identity)
    .build();
for ev in driver.track(view) {
    match ev {
        Event::Message { message, .. } => …,
        Event::FlowStarted { .. } => …,
        Event::ParserClosed { .. } | Event::FlowEnded { .. } => …,
        _ => {}
    }
}
```

### Single-parser UDP (was `FlowDatagramDriver`)

```rust
// 0.10
let mut driver = Driver::<_, DnsMessage>::builder(ext)
    .datagram_on_ports(DnsUdpParser::default(), [53], identity)
    .build();
```

### Multi-parser TCP+UDP (was `FlowMultiSessionDriver` + a parallel UDP driver)

```rust
// 0.10
let mut driver = Driver::<_, MyL7>::builder(ext)
    .session_on_ports(HttpParser::default(),  [80, 8080], MyL7::Http)
    .session_on_ports(TlsParser::default(),   [443],       MyL7::Tls)
    .datagram_on_ports(DnsUdpParser::default(), [53],       MyL7::Dns)
    .build();
```

### Pipeline for the hello-world case

```rust
// 0.9 (Pipeline shipped)
let mut pipeline = Pipeline::builder(ext)
    .session(HttpParser::default())
    .build();
for ev in pipeline.run_pcap("trace.pcap")? {
    match ev? {
        Event::Tcp(SessionEvent::Application { message, .. }) => …,
        Event::Flow(FlowEvent::Started { .. }) => …,
        _ => {}
    }
}

// 0.10
let mut pipeline = Pipeline::<_, HttpMessage>::builder(ext)
    .session_broadcast(HttpParser::default(), identity)
    .build();
for ev in pipeline.run_pcap("trace.pcap")? {
    match ev? {
        Event::Message { message, .. } => …,
        Event::FlowStarted { .. } => …,
        _ => {}
    }
}
```

The migration recipe ships in the CHANGELOG with a complete
mapping table.

---

## Files

```
src/driver/mod.rs              # NEW — unified Driver + DriverBuilder
src/driver/dispatch.rs         # NEW — internal session/datagram dispatch
src/driver/erased.rs           # NEW — ErasedSessionParser + LiftingErased…
src/event.rs                   # REWRITE — single Event<K, M>
src/pipeline.rs                # REWRITE — thin wrapper over Driver
src/lib.rs                     # remove old re-exports, add new ones
src/prelude.rs                 # update re-exports
src/session_driver.rs          # DELETED
src/datagram_driver.rs         # DELETED
src/driver.rs (old)            # DELETED (replaced by src/driver/mod.rs)
src/driver_builder.rs          # DELETED (absorbed into Driver's builder)
src/multi_session_driver.rs    # DELETED
plans/108-packet-event-enrichment.md   # DELETED (absorbed)
plans/109-cross-l4-multi-driver.md     # DELETED (subsumed)

tests/driver.rs                # NEW — unified driver coverage
tests/migration_check.rs       # NEW — old patterns commented out, new patterns asserted
tests/* (old)                  # MIGRATE: every existing test that named a deleted type

examples/*                     # MIGRATE: 29 examples to the new shape

docs/getting-started.md        # rewrite first example
docs/recipes.md                # sweep
docs/concepts.md               # rewrite Driver section + three-tier diagram
CHANGELOG.md                   # 0.10 breaking section + migration mapping
```

## Implementation steps — 5-PR series

### PR 1 — New types alongside old (zero deletions)

1. Add `src/driver/mod.rs` with the new `Driver<E, M>` +
   `DriverBuilder<E, M>` types.
2. Add the new `Event<K, M>` enum in a NEW file
   `src/event_new.rs` (temporary) — DOES NOT delete the old
   `FlowEvent` / `SessionEvent` yet.
3. Add internal `ErasedSessionParser` + `LiftingErasedSessionParser`
   machinery in `src/driver/erased.rs`.
4. Add session-parser dispatch (port-routed + broadcast) in
   `src/driver/dispatch.rs`.
5. Wire `src/lib.rs` to expose both old + new APIs in parallel.
   Old types remain re-exported (the compiler doesn't know
   anything broke yet).
6. Unit tests for the new types in `tests/driver.rs` —
   independent of the old types.

PR 1 is purely additive: nothing breaks. Reviewers compare
new code against the existing code side-by-side.

### PR 2 — Datagram dispatch + heuristic routing

7. Add datagram-parser dispatch.
8. Add heuristic-routing variant (`Routing::Heuristic`) and
   per-flow `FlowDetection` state — absorbing plan 114
   directly into the unified driver.
9. Extend `tests/driver.rs` with the new shapes.

### PR 3 — Migrate internal callers

10. Migrate `src/pipeline.rs` to use `Driver` internally;
    rename the existing `Pipeline::Event` enum to the new
    `Event<K, M>`. Pipeline becomes a thin wrapper.
11. Migrate internal `src/pcap/source.rs::sessions` /
    `datagrams` to use `Driver`.
12. Old `FlowSessionDriver` / `FlowDatagramDriver` /
    `FlowMultiSessionDriver` still exist but are
    `#[deprecated]`-flagged with a message pointing at
    `Driver`.

### PR 4 — Migrate every test + example

13. Sweep `tests/` — every test that named a deleted type
    rewrites against the new shape. (~25 test files.)
14. Sweep `examples/` — 29 example files. Largely mechanical;
    the worked example diffs in plan 115 cover the shape.
15. Sweep `docs/recipes.md` + `docs/concepts.md` + `docs/getting-
    started.md`.

### PR 5 — Delete the old types + ship CHANGELOG

16. Delete `src/session_driver.rs`, `src/datagram_driver.rs`,
    `src/driver.rs` (old), `src/driver_builder.rs`,
    `src/multi_session_driver.rs`. Move the new
    `src/driver/` contents into final location.
17. Delete `src/event_new.rs` (was temp); move content into
    `src/event.rs` replacing the old `FlowEvent` /
    `SessionEvent`.
18. Update `src/lib.rs` re-exports — old names gone; new
    `Driver`, `DriverBuilder`, `Event` are the public surface.
19. Update `src/prelude.rs`.
20. Delete `plans/108-packet-event-enrichment.md` +
    `plans/109-cross-l4-multi-driver.md` (subsumed by 116).
21. CHANGELOG entry under 0.10.0 "Breaking" — full migration
    mapping table.

## Tests

### `tests/driver.rs` (new — replaces multi-session/pipeline tests)

A consolidated test suite:

```rust
- builder type-check: no parser registered builds a no-op driver.
- single TCP parser on ports: HTTP-only smoke test.
- single UDP parser on ports: DNS-only smoke test.
- both: HTTP + DNS in one driver, output ordering correct.
- heuristic routing: HTTP on port 9999 caught by signature.
- packet enrichment: emit_packet_details(true) populates tcp + frame.
- shared tracker: 100k-flow workload produces one FlowStarted per flow
  (not N per parser).
- ParserClosed fires per (parser, flow) on FlowEnded.
- migration regression: equivalent inputs through old vs new produce
  matching event sequences (run during PR 1 + 2; remove in PR 5).
```

### Property tests

Splitting invariance: same packet stream chunked at arbitrary
boundaries produces the same `Event` sequence.

## Acceptance criteria

- `Driver<E, M>` ships; `DriverBuilder<E, M>` ships;
  `Event<K, M>` ships.
- `FlowSessionDriver`, `FlowDatagramDriver`, `FlowDriver`,
  `FlowMultiSessionDriver`, `FlowSessionDriverBuilder`,
  `FlowDatagramDriverBuilder` are deleted.
- `FlowEvent` and `SessionEvent` are deleted; merged into
  `Event<K, M>`.
- `Pipeline<E, M>` rewritten as Driver-wrapper; works against
  pcap + iter sources as before.
- 29 examples + ~25 tests migrated; all green.
- CHANGELOG mapping table ships:
  - `FlowSessionDriver` → `Driver` (single-parser case)
  - `FlowMultiSessionDriver` → `Driver` (multi-parser case)
  - `FlowEvent::*` → `Event::Flow*`
  - `SessionEvent::Application` → `Event::Message`
  - `SessionEvent::Closed` → `Event::ParserClosed`
- Public type count: 1 driver type, 1 event type, 1 builder
  (+ Pipeline + PipelineBuilder = 2 + 2). Down from 6 + 4 + 4.
- `cargo test --all-features` clean across all 5 PRs.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `netring` updated in lockstep; the 0.10 release of flowscope
  ships paired with the matching `netring` release.

## Risks

- **Migration burden — internal.** ~50 file edits, mostly
  mechanical, but cross-cutting. Mitigated by the 5-PR series:
  each step is independently reviewable.
- **Migration burden — external.** Every shipped consumer
  rewrites their match arms. Mitigation: complete mapping
  table in CHANGELOG; `#[deprecated]`-with-pointer in PR 3
  warns at compile time.
- **Generic specialisation cost.** `Driver<E, M>` with N
  registered parsers generates one specialisation per
  (extractor, message type). For consumers using one user
  enum across all parsers, that's one specialisation total.
  No worse than today's `FlowMultiSessionDriver<E, M>`.
- **Performance regression risk.** The unified dispatch path
  may add per-packet overhead vs the specialised drivers.
  Mitigation: `benches/` measures the per-packet cost
  baseline (existing single-parser driver throughput) vs the
  new unified driver throughput in PR 1's bench updates. If
  regression > 5 %, optimise via inlined static dispatch for
  the N=1 case before PR 5.
- **API discoverability after the collapse.** Fewer types
  means each carries more weight. Mitigation: rustdoc landing
  page (plan 110) extended to cover `Driver` exhaustively.
- **netring sync.** netring's `flow_stream` / `session_stream`
  / `datagram_stream` adapters need full rewrite. Same as plan
  94 in 0.9. Coordinated release window required.

## Effort

| PR | Description | LoC | Hours |
|----|-------------|-----|-------|
| 1 | New types + erasure + session dispatch + tests | ~720 | 14 |
| 2 | Datagram dispatch + heuristic routing | ~380 | 8 |
| 3 | Migrate internals + Pipeline rewrite | ~310 net | 8 |
| 4 | Migrate tests + examples + docs | ~120 net | 10 |
| 5 | Delete old types + finalize | ~−1,800 net | 6 |
| Benchmarks + regression check | ~150 | 4 |
| CHANGELOG migration table | ~180 | 2 |
| **Total** | | **~700 LoC net** | **~52 hours** |

Comparable in scope to plan 94 in 0.9 cycle (~62 hours).

## Provenance

Plan 115 (strategic review):

> Collapse the drivers — ONE `Driver<E, M>`. […] After the
> redesign: 14 driver/event/builder types drops to ~6. […]
> The mental model shrinks to: `FlowTracker` (raw), `Driver`
> (orchestrated), `Pipeline` (sourced). Three levels, three
> names.

User question, 2026-06-07:

> *"review our code. review all our plans. You are allow to
> completely redesign flowscope if needed. Take your time.
> Our API should be right."*

Industry alignment (also in plan 115):

- Most packet libraries don't have a driver concept;
  flowscope's driver layer adds value (orchestration,
  dispatch, lifecycle), but six driver types is an
  anti-pattern.
- Closest precedents: Cap'n Proto's `MessageReader<T>` (one
  generic over what's inside), OpenTelemetry's `Tracer<T>`,
  tower's `Service<R>`. Each library converged on **one
  generic over what flows through it**, not specialised
  variants per data shape.

Plan 116 brings flowscope's driver layer to that shape.
