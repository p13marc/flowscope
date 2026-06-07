# Plan 109 — `FlowMultiDriver<E, M>` — cross-L4 composite driver

## Summary

Replace `FlowMultiSessionDriver` (TCP-only, N-tracker
implementation) with a unified `FlowMultiDriver<E, M>` that:

1. **Spans both L4s.** Register TCP `SessionParser`s and UDP
   `DatagramParser`s into one driver; routing decides which
   parser sees which packet.
2. **Shares one tracker across all registered parsers.** Flow
   lifecycle (Started / Ended / anomalies) emits once per
   event, not N times. Plan 92 deferred this as a follow-up;
   plan 109 ships it.
3. **Emits a unified event stream** via a `MultiEvent<K, M>`
   sum type that separates flow-level from parser-level
   events, so consumers don't have to dedup Started/Closed
   events across parsers.

This is theme 6 in
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md)
— the highest-priority pain point surfaced by the
example-writing pass. The `extract_iocs.rs` example needed
HTTP + TLS + DNS together and ran three parallel drivers
because the existing `FlowMultiSessionDriver` is TCP-only.

`FlowMultiSessionDriver` is removed; `FlowMultiDriver` is the
single composite shape for 0.10 forward.

## Status

**Ready to implement.** Targets 0.10.0. Sibling to plans 108
(packet enrichment) and 106 (parser ergonomics) — they touch
overlapping internals; landing order spelled out below.

## Prerequisites

- **Plan 92** — `FlowMultiSessionDriver` shipped in 0.9.0 as a
  thin wrapper over N `FlowSessionDriver` instances. Its
  ergonomic API (`with_parser_on_ports` + `with_parser_broadcast`)
  is the surface plan 109 keeps; only the implementation
  changes (and the surface grows to cover UDP).
- **Plan 96** — unified `flowscope::Error`. `MultiEvent`'s
  error paths return `flowscope::Error`.
- **Plan 94** — `Pipeline` + driver builders. The new
  `FlowMultiDriver` follows the same builder pattern. The
  high-level `Pipeline` will eventually be re-implemented atop
  `FlowMultiDriver` for the single-protocol case (post-0.10
  cleanup — out of scope here).
- No work in `netring` is required for the initial landing;
  netring will gain a `multi_stream` adapter in a follow-up
  release once the sync surface stabilises.

## Out of scope

- **Single-protocol `Pipeline` rewrite atop `FlowMultiDriver`.**
  Tempting but distinct. Pipeline stays. A future plan
  (post-0.10) may collapse them once `FlowMultiDriver` has
  shipped against real workloads.
- **`netring::multi_stream` async adapter.** Sibling release.
- **Dynamic parser registration after `build()`.** The driver
  is configured at build time; adding parsers at runtime
  requires `Box<dyn>` everywhere and is out of scope.
- **Per-parser `S` user state.** Plan 92 already locked
  "no per-parser state on the composite." Same decision here.
- **Cross-parser reassembler state sharing.** Each TCP parser
  keeps its own reassembler. Sharing is a deferred perf
  optimisation if a profile shows it matters.
- **Pluggable routing predicates.** Plan 92 Q2 locked
  port-set + broadcast as the only routing modes; predicate
  routing stays deferred. If a consumer reaches for it, that's
  a separate plan.
- **AnyL7Message convenience preset.** Plan 92 deferred the
  built-in `AnyL7Message` sum type; that stays deferred. A
  follow-up may add it as `flowscope::well_known::AnyL7` once
  the built-in parser set is fully proven.

---

## The use case

### Today: parallel drivers per L4 + per parser

`extract_iocs.rs` was the test case:

```rust
// Today (0.9): three drivers running in parallel.
let mut http_driver  = FlowSessionDriver::new(ext.clone(), HttpParser::default());
let mut tls_driver   = FlowSessionDriver::new(ext.clone(), TlsHandshakeParser::default());
let mut dns_driver   = FlowDatagramDriver::new(ext.clone(), DnsUdpParser::default());
let mut flow_tracker = FlowTracker::<FiveTuple>::new(ext.clone());

for owned in source.views() {
    let owned = owned?;
    for ev in flow_tracker.track(&owned) { collect_ips(&mut iocs, ev); }
    for ev in http_driver.track(&owned)  { handle_http(&mut iocs, ev); }
    for ev in tls_driver.track(&owned)   { handle_tls(&mut iocs, ev); }
    for ev in dns_driver.track(&owned)   { handle_dns(&mut iocs, ev); }
}
```

Three separate trackers. Three separate flow event streams.
Three sets of Started/Ended for the same flow. Memory cost is
**3× the per-flow tracker state**; CPU cost is 3× the
extractor + tracker dispatch.

### After plan 109: one driver, one tracker

```rust
// 0.10: one driver, one tracker shared across all parsers.
let mut driver = FlowMultiDriver::<_, MyL7>::builder(ext)
    .session_on_ports(HttpParser::default(),         [80, 8080], MyL7::Http)
    .session_on_ports(TlsHandshakeParser::default(), [443],       MyL7::Tls)
    .datagram_on_ports(DnsUdpParser::default(),      [53],        MyL7::Dns)
    .build();

for owned in source.views() {
    for ev in driver.track(&owned?) {
        match ev {
            MultiEvent::Flow(FlowEvent::Started { key, .. }) => collect_ips(&mut iocs, key),
            MultiEvent::Message { parser_kind: "http", message: MyL7::Http(m), .. } => …,
            MultiEvent::Message { parser_kind: "tls-handshake", message: MyL7::Tls(m), .. } => …,
            MultiEvent::Message { parser_kind: "dns-udp", message: MyL7::Dns(m), .. } => …,
            _ => {}
        }
    }
}
```

Single shared tracker — flow lifecycle emits once. The
`MultiEvent::Message { parser_kind, message, … }` arm
demuxes by parser. The example's lift closures are clear and
type-safe.

### Concrete savings on `extract_iocs.rs`

| | Today | Plan 109 |
|---|---|---|
| Driver instances | 3 | 1 |
| Tracker instances | 3 | 1 |
| Extractor `extract()` calls per packet | 3 | 1 |
| Flow events per flow | 3× (one per driver) | 1× |
| `FlowEvent::Started` for IPs accounting | from a fourth bare `FlowTracker` | from the driver itself |
| LoC at the consumer site | ~30 (init + dispatch) | ~10 |

The throughput win at scale: ~2-3× on multi-protocol monitoring
workloads (untested, ballpark based on parsed-packet
benchmarks for the per-driver code paths).

---

## API

### Builder

```rust
pub struct FlowMultiDriverBuilder<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{ /* … */ }

impl<E, M> FlowMultiDriverBuilder<E, M> {
    /// Construct a builder. Defaults: anomalies off, monotonic
    /// timestamps on (matches `Pipeline`'s offline-replay
    /// defaults).
    pub fn new(extractor: E) -> Self;

    /// Override the shared tracker's config.
    pub fn config(self, config: FlowTrackerConfig) -> Self;

    /// Emit `FlowAnomaly` / `TrackerAnomaly` events inline.
    /// Default: `false` (matches `FlowSessionDriver` default).
    pub fn emit_anomalies(self, on: bool) -> Self;

    /// Assume the packet stream is in monotonic timestamp order.
    /// Default: `true`.
    pub fn monotonic_timestamps(self, on: bool) -> Self;

    /// Apply content-hash dedup before extraction.
    pub fn dedup(self, dedup: Dedup) -> Self;

    // ── Session (TCP) parser registration ────────────────────

    /// Register a `SessionParser` for TCP traffic on the given
    /// port set. Fires when `dst_port ∈ ports || src_port ∈ ports`.
    pub fn session_on_ports<P, I, F>(self, parser: P, ports: I, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(P::Message) -> M + Send + 'static;

    /// Register a `SessionParser` that fires on every TCP
    /// packet (e.g. a custom protocol with no canonical port).
    pub fn session_broadcast<P, F>(self, parser: P, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    // ── Datagram (UDP) parser registration ───────────────────

    /// Register a `DatagramParser` for UDP traffic on the
    /// given port set.
    pub fn datagram_on_ports<P, I, F>(self, parser: P, ports: I, lift: F) -> Self
    where
        P: DatagramParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16>,
        F: Fn(P::Message) -> M + Send + 'static;

    /// Register a `DatagramParser` that fires on every UDP
    /// packet (e.g. tunnel parsers, or per-packet broadcasts).
    pub fn datagram_broadcast<P, F>(self, parser: P, lift: F) -> Self
    where
        P: DatagramParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    /// Build the driver.
    pub fn build(self) -> FlowMultiDriver<E, M>;
}
```

### Driver

```rust
pub struct FlowMultiDriver<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{ /* … */ }

impl<E, M> FlowMultiDriver<E, M> {
    /// Construct a builder. The only public way to make one.
    pub fn builder(extractor: E) -> FlowMultiDriverBuilder<E, M>;

    /// Process a packet. Returns a `Vec<MultiEvent<K, M>>` —
    /// flow events from the shared tracker plus parser-emitted
    /// messages from every parser whose routing rule matched.
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>)
        -> Vec<MultiEvent<E::Key, M>>;

    /// Periodic sweep — drains parser `on_tick`s + tracker
    /// idle-timeouts. Returns the merged event stream.
    pub fn sweep(&mut self, now: Timestamp) -> Vec<MultiEvent<E::Key, M>>;

    /// End-of-input flush — drains every still-open flow's
    /// `fin_*` methods on every applicable parser.
    pub fn finish(&mut self) -> Vec<MultiEvent<E::Key, M>>;

    /// Borrow the shared tracker (for introspection / snapshot).
    pub fn tracker(&self) -> &FlowTracker<E, ()>;

    /// Mutable borrow for runtime reconfiguration
    /// (e.g. `tracker_mut().set_idle_timeout_fn(…)`).
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()>;
}
```

### Event type

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum MultiEvent<K, M> {
    /// Flow lifecycle from the shared tracker — emitted ONCE
    /// per event (not N times). `Started`, `Established`,
    /// `Packet`, `Ended`, `Tick`, `FlowAnomaly`,
    /// `TrackerAnomaly`.
    Flow(FlowEvent<K>),

    /// L7 message emitted by a registered parser.
    ///
    /// `parser_kind` is the value returned by the originating
    /// parser's `SessionParser::parser_kind()` /
    /// `DatagramParser::parser_kind()` — use the
    /// `flowscope::parser_kinds::*` constants for typo-safe
    /// match arms.
    Message {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        parser_kind: &'static str,
    },

    /// Parser-level close — a `SessionParser` drained its
    /// `fin_*` / `rst_*` accumulator. Distinct from the
    /// flow-level `FlowEvent::Ended` (which fires once per
    /// flow); this fires per (parser, flow).
    ///
    /// UDP parsers don't emit this — they have no close
    /// semantics.
    ParserClosed {
        key: K,
        parser_kind: &'static str,
        reason: EndReason,
        ts: Timestamp,
    },
}

impl<K, M> MultiEvent<K, M> {
    pub fn key(&self) -> Option<&K>;
    pub fn timestamp(&self) -> Timestamp;
    pub fn parser_kind(&self) -> Option<&'static str>;
}
```

### Migration: `FlowMultiSessionDriver` → `FlowMultiDriver`

```diff
- use flowscope::FlowMultiSessionDriver;
+ use flowscope::FlowMultiDriver;

- let mut driver = FlowMultiSessionDriver::<_, MyL7>::new(extractor)
-     .with_parser_on_ports(HttpParser::default(), [80, 8080], MyL7::Http)
-     .with_parser_broadcast(MyTcpParser::default(), MyL7::Other);
+ let mut driver = FlowMultiDriver::<_, MyL7>::builder(extractor)
+     .session_on_ports(HttpParser::default(), [80, 8080], MyL7::Http)
+     .session_broadcast(MyTcpParser::default(), MyL7::Other)
+     .build();

  for owned in source.views() {
      for ev in driver.track(&owned?) {
-         match ev {
-             SessionEvent::Application { message, .. } => …,
-             _ => {}
-         }
+         match ev {
+             MultiEvent::Message { message, .. } => …,
+             MultiEvent::Flow(FlowEvent::Started { .. }) => …,
+             _ => {}
+         }
      }
  }
```

Renames + a `.build()` call. The new variant-split of `Flow` /
`Message` / `ParserClosed` is more discoverable than the union
in `SessionEvent`.

---

## Internal architecture

### Storage

```rust
pub struct FlowMultiDriver<E, M>
where E: FlowExtractor, M: Send + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    dedup: Option<Dedup>,

    /// Single shared tracker.
    tracker: FlowTracker<E, ()>,

    /// Per-session-parser slots. Each owns the parser template,
    /// its routing, its per-(flow, side) reassembler set, and
    /// its per-flow parser instances.
    session_slots: Vec<SessionSlot<E::Key, M>>,

    /// Per-datagram-parser slots.
    datagram_slots: Vec<DatagramSlot<E::Key, M>>,

    /// Hot-cache for the most recent packet's extracted
    /// `(key, l4, src_port, dst_port)` — avoids re-extracting
    /// for the routing decision after the tracker has already
    /// extracted for its own bookkeeping.
    last_extracted: Option<ExtractedHot<E::Key>>,
}

struct SessionSlot<K, M> {
    routing: Routing,
    /// Type-erased registered parser; vends instances per flow.
    factory: Box<dyn ParserFactory<K, M> + Send>,
    /// Per-(flow, side) reassemblers — each parser sees an
    /// independent byte stream.
    reassemblers: HashMap<(K, FlowSide), BufferedReassembler>,
    /// Per-flow parser instances. Cloned from the factory on
    /// first sight of a matching flow.
    instances: HashMap<K, Box<dyn ErasedSessionParser<Message = M>>>,
}

struct DatagramSlot<K, M> {
    routing: Routing,
    factory: Box<dyn DatagramFactory<K, M> + Send>,
    /// Per-flow parser instances (UDP needs less state than TCP
    /// but per-flow parsers can still carry state — e.g. DNS
    /// query/response correlator).
    instances: HashMap<K, Box<dyn ErasedDatagramParser<Message = M>>>,
}

enum Routing {
    /// Match TCP/UDP packets with src or dst port in this set.
    Ports(SmallVec<[u16; 4]>),
    /// Match every TCP (for SessionSlot) or UDP (for DatagramSlot) packet.
    Broadcast,
}
```

### Per-packet dispatch

```text
track(view):
  1. Optional dedup check — bail if duplicate.
  2. extractor.extract(view) once. Cache result in last_extracted.
  3. tracker.track(view) — emits FlowEvent(s); these go into the
     output as MultiEvent::Flow(_) verbatim.
  4. For each MultiEvent::Flow(FlowEvent::Ended { key, .. }), fire
     fin_* on every per-parser instance for that key and emit
     MultiEvent::ParserClosed for each.
  5. Determine packet L4 + ports from layers (cheap re-parse
     bypassed for the shared `last_extracted`).
  6. Route to TCP session slots:
     - For each session_slot whose routing matches: extract the
       TCP payload, feed into the per-(key, side) reassembler,
       drain into the per-key parser instance.
     - Each parser_kind's emitted messages become
       MultiEvent::Message { parser_kind, … } in the output.
  7. Route to UDP datagram slots:
     - For each datagram_slot whose routing matches: feed the
       payload into the per-key parser via parse(...).
     - Same lift-and-emit as session slots.
  8. Return the merged Vec<MultiEvent>.
```

The output is **per-packet ordered**: Flow events first (from
the tracker), then session parser messages (in registration
order), then datagram parser messages (in registration order),
then any synthesised `ParserClosed`s from step 4.

### Sweep + finish

`sweep(now)`:

```text
1. tracker.sweep(now) → MultiEvent::Flow(FlowEvent::Ended) for
   idle-timed-out flows.
2. For each Ended event, drain matching parser instances and
   emit MultiEvent::ParserClosed.
3. For each registered parser, drive `on_tick(now)` on every
   live instance and emit any returned messages.
```

`finish()`:

```text
1. tracker.finish() → drain all live flow events.
2. For each parser, fin_initiator + fin_responder on every
   live instance.
3. Drop all parser instances + reassemblers.
```

### Type-erasure boundary

`SessionParser` has an associated type `Message: Send + 'static`.
To store heterogeneous parsers in `Vec<SessionSlot>`, each slot
holds:

```rust
trait ErasedSessionParser: Send {
    type Message;  // = M (the outer composite's M)
    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn fin_initiator(&mut self) -> Vec<Self::Message>;
    fn fin_responder(&mut self) -> Vec<Self::Message>;
    fn on_tick(&mut self, now: Timestamp) -> Vec<Self::Message>;
    fn parser_kind(&self) -> &'static str;
}

struct LiftingErasedSessionParser<P, F>
where P: SessionParser, F: Fn(P::Message) -> M + Send,
{
    inner: P,
    lift: F,
}

impl<P, F> ErasedSessionParser for LiftingErasedSessionParser<P, F>
where P: SessionParser, F: Fn(P::Message) -> M + Send,
{
    type Message = M;
    fn feed_initiator(&mut self, b: &[u8], ts: Timestamp) -> Vec<M> {
        self.inner.feed_initiator(b, ts).into_iter().map(&self.lift).collect()
    }
    // … etc …
}
```

`Box<dyn ErasedSessionParser<Message = M>>` is the storable
form. Same shape for `DatagramSlot`.

### Memory profile

Per flow: one entry in the shared tracker (`FlowEntry<()>`,
small) plus one parser instance + one (init, resp) reassembler
pair per registered parser that the flow matched.

Compared to the existing `FlowMultiSessionDriver` (which
duplicates the tracker N times for N parsers): saves
`(N-1) × sizeof(FlowEntry) × num_active_flows`. For a 100k-flow
deployment with 3 parsers, that's typically 6-20 MiB saved.

Compared to a single-parser `FlowSessionDriver`: same per-flow
cost (one tracker entry + one parser instance + reassemblers).
The composite adds Vec-based dispatch overhead per packet
(~10 ns per packet per registered parser, dominated by the
routing check).

---

## Files

```
src/multi_driver.rs                  # FlowMultiDriver + builder + MultiEvent (NEW)
src/multi_session_driver.rs          # DELETED (subsumed; see migration recipe)
src/lib.rs                           # add multi_driver, remove multi_session_driver, re-export
tests/multi_driver.rs                # 2-, 3-, 4-parser integration tests (NEW)
tests/multi_driver_proptest.rs       # ordering + dedup + routing proptests (NEW)
examples/extract_iocs.rs             # MIGRATED from 4 drivers → 1 FlowMultiDriver
examples/multi_parser_pipeline.rs    # MIGRATED to FlowMultiDriver
docs/recipes.md                      # rewrite "Multi-protocol monitoring" → FlowMultiDriver
CHANGELOG.md                         # 0.10 entry + migration recipe
```

## Implementation steps

Land as ~5 PRs (to keep individual reviews tractable):

### PR 1 — Type-erasure scaffolding

1. Define `ErasedSessionParser` + `ErasedDatagramParser`
   internal traits.
2. Define `LiftingErasedSessionParser<P, F>` +
   `LiftingErasedDatagramParser<P, F>` adapters.
3. Define `SessionSlot<K, M>` + `DatagramSlot<K, M>` storage
   structs.
4. Unit tests for the type-erasure layer (feeding through the
   eraser + lift produces the expected `M`).

### PR 2 — `FlowMultiDriver` core + builder

5. Define `FlowMultiDriver<E, M>` and
   `FlowMultiDriverBuilder<E, M>`.
6. Implement the builder methods (`session_on_ports`,
   `datagram_on_ports`, `session_broadcast`,
   `datagram_broadcast`, `config`, `emit_anomalies`,
   `monotonic_timestamps`, `dedup`).
7. Define `MultiEvent<K, M>` enum + its public accessors.
8. Initial `track()` skeleton that:
   - Runs the tracker once.
   - Emits `MultiEvent::Flow(_)` for each tracker event.
   - Returns empty for parser dispatches.
9. Unit tests: empty driver (no parsers registered) just
   forwards tracker events.

### PR 3 — Session parser dispatch + per-flow state

10. Extract L4 + ports from packet (re-using
    `src/layers/parse.rs` machinery).
11. For each session slot whose routing matches:
    - Get or vend a per-flow parser instance.
    - Get or vend a per-(flow, side) reassembler.
    - Feed the TCP payload into the reassembler, then drain
      bytes into the parser via `feed_*`.
    - Lift emitted messages into `M` and append
      `MultiEvent::Message { parser_kind, … }`.
12. Implement `ParserClosed` synthesis: on each
    `FlowEvent::Ended` from the tracker, drive `fin_*` on every
    matching parser instance and emit
    `MultiEvent::ParserClosed`.
13. Implement `sweep()` for session parsers — drive `on_tick`
    on every live instance.

### PR 4 — Datagram parser dispatch

14. Same shape as PR 3 but for UDP via `parse()`. Simpler — no
    reassembler.
15. Datagram parsers don't get `ParserClosed` (UDP has no close
    semantics) — document this in the rustdoc.

### PR 5 — Migration + cleanup

16. Migrate `examples/extract_iocs.rs` to the new shape.
17. Migrate `examples/multi_parser_pipeline.rs`.
18. Delete `src/multi_session_driver.rs`. Remove the
    `FlowMultiSessionDriver` re-export from `src/lib.rs`.
19. Update `docs/recipes.md` → "Multi-protocol monitoring"
    section.
20. CHANGELOG migration recipe (`FlowMultiSessionDriver` →
    `FlowMultiDriver`).

## Tests

### `tests/multi_driver.rs` (new)

Three integration tests covering the key shapes:

1. **TCP + UDP same driver.** Register an HTTP `SessionParser`
   on port 80 + DNS `DatagramParser` on port 53. Run against
   a synthetic pcap with a TCP HTTP flow and a UDP DNS flow.
   Assert: 1 `Flow::Started` per flow, the right number of
   `Message`s with the right `parser_kind`, no duplicated
   flow events.

2. **Three TCP parsers + port routing.** Register HTTP on
   80/8080, TLS on 443, custom parser broadcast. Verify each
   parser fires exactly when expected; broadcast fires every
   TCP packet.

3. **Shared tracker semantics.** Run a 1k-flow workload with
   two registered parsers. Assert that
   `driver.tracker().snapshot_stats()` matches the
   single-parser `FlowSessionDriver` baseline (no
   double-counting).

### `tests/multi_driver_proptest.rs` (new)

Two property tests:

1. **Splitting invariance.** Same packet stream split at
   arbitrary boundaries between `track()` calls produces the
   same `MultiEvent` sequence.

2. **Event ordering deterministic.** Per packet, `MultiEvent::Flow`
   events arrive before `MultiEvent::Message` events; messages
   from session parsers arrive in registration order, then
   datagram parsers in registration order.

### Equivalence test against the old driver

A regression test that runs the same workload through:
- A `FlowMultiSessionDriver` (pre-deletion, in a temporary
  branch),
- A `FlowMultiDriver`,

and asserts the message sets match. Drop the comparison after
PR 5 lands; keep the cleaned-up version as a regression
fixture against future changes.

## Acceptance criteria

- `FlowMultiDriver<E, M>` lands with builder API exactly as
  specified above.
- `FlowMultiSessionDriver` is removed; `lib.rs` no longer
  re-exports it.
- `examples/extract_iocs.rs` rewritten to use the new driver —
  LoC down from ~150 to ~80, four drivers down to one.
- `examples/multi_parser_pipeline.rs` migrated.
- `docs/recipes.md` "Multi-protocol monitoring" section
  rewritten — `FlowMultiSessionDriver` mentions removed; the
  new builder is the canonical pattern.
- All five PRs land in order, each independently green.
- 7+ new integration / proptest tests cover the major shapes.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG migration recipe ships in 0.10.0.

## Risks

- **`Box<dyn>` dispatch cost.** Per-packet routing through a
  trait object adds ~5-15 ns per registered parser. For a
  three-parser deployment processing 100k packets/sec, that's
  ~5 µs/sec — negligible. For 10 M packets/sec it's 0.5 s/sec
  = 50 % overhead; that workload should drop to lower-level
  APIs anyway. Mitigation: criterion bench in `benches/` that
  records the per-parser-per-packet cost; document the
  trade-off in rustdoc.

- **Output-event ordering surprises.** With many registered
  parsers, a single packet can produce many `MultiEvent`s in
  the output Vec. Consumers iterating may see `Flow(Started)`
  immediately followed by 3 `Message`s, then `Flow(Established)`.
  The plan-92 decision was registration-order; plan 109 keeps
  it. Documented in rustdoc.

- **Memory churn from `Vec<MultiEvent>` per `track()`.** A
  hot-path driver allocates a Vec per packet. Mitigation:
  reuse a `SmallVec<[MultiEvent; 4]>` returned by-value to
  the caller; the inline capacity covers the no-parser-fired
  case (just one Flow event for the packet) without a heap
  allocation.

- **`ParserClosed` semantics for UDP.** UDP doesn't have
  close events; the driver only emits `ParserClosed` for
  session (TCP) parsers. Document explicitly so users
  matching on `ParserClosed` don't expect UDP entries.

- **Backward compatibility break.** Deleting
  `FlowMultiSessionDriver` is the only consumer-facing break.
  Migration is a name change + `.build()` call. CHANGELOG
  recipe + commit message capture the diff.

- **netring lockstep.** Async wrappers in netring depend on
  the sync surface; netring needs a coordinated update. Same
  pattern as plan 94 in 0.9.

## Effort

| Sub-PR | Description | LoC | Hours |
|--------|-------------|-----|-------|
| PR 1 | Type-erasure scaffolding + unit tests | ~280 | 5 |
| PR 2 | Driver + builder + MultiEvent + initial track() | ~360 | 8 |
| PR 3 | Session parser dispatch + per-flow state + sweep | ~340 | 8 |
| PR 4 | Datagram parser dispatch | ~190 | 4 |
| PR 5 | Examples + docs + CHANGELOG + delete old driver | ~−260 net | 5 |
| Tests | 3 integration + 2 proptests + benches | ~420 | 8 |
| **Total** | | **~1,330 LoC** | **~38 hours** |

Comparable to plan 94's Tier 2 driver-builder work in 0.9 — a
focused, contained refactor with a clear before/after shape.

## Provenance

Postmortem theme 6, from
[`100-examples-postmortem.md`](./100-examples-postmortem.md):

> Ran four drivers in parallel: `FlowSessionDriver<HttpParser>`,
> `FlowSessionDriver<TlsHandshakeParser>`,
> `FlowDatagramDriver<DnsUdpParser>`, plus a bare `FlowTracker`
> for IPs. Each takes its own extractor instance.
> `FlowMultiSessionDriver` solves this for TCP parsers but
> doesn't span L4 — no way to register a UDP parser into the
> same composite. So I had two composite drivers worth of
> ceremony.

User priority (2026-06-07):

> *"I think the most important one is '6. cross L4 dispatch
> needs N drivers'. You can make research on internet if
> needed. Take your time. I want to fix all of those for our
> next release"*

Architectural references:

- **Plan 92 (shipped 0.9.0)** — the additive
  `FlowMultiSessionDriver` this plan replaces. Plan 92's
  shared-tracker `α` design decision (per-parser reassembler)
  carries forward; the deferred shared-tracker optimisation
  lands here.
- **gopacket** — `LayerType`-based routing inspires the
  port + L4 routing model.
- **Suricata** — per-protocol parser registration with
  port hints + broadcast detection mode.
- **Zeek's DPM (Dynamic Protocol Detection)** — Zeek does
  content-sniffing routing. flowscope intentionally stays
  port-set + broadcast only (predicate routing deferred per
  plan 92 Q2).
