# Plan 121 — Typed slot drains + legacy driver deletion

## Summary

Two coupled changes that share the same refactor surface:

1. **Typed slot drain handles.** Replace the closed-`M`
   `Driver<E, M>` shape with `Driver<E>` + one
   `SlotHandle<P::Message>` per registered parser. Each slot
   holds its own typed `Vec<P::Message>` internally; the
   consumer drains via `SlotHandle::drain(&mut buf)`. The
   `lift: Fn(P::Message) -> M` closures disappear; netring's
   `Erased = Box<dyn Any>` workaround disappears; zero
   allocation per parsed L7 message in steady state.

2. **Legacy driver deletion (absorbs plan 117).** The current
   slot impls wrap `FlowSessionDriver` / `FlowDatagramDriver`.
   The typed-slot refactor inlines that logic directly into
   the slot, so `FlowSessionDriver` /
   `FlowDatagramDriver` / `FlowMultiSessionDriver` and the
   legacy `Pipeline` become dead code. Deleting them in the
   same release saves a future migration window and ~1000
   LOC.

After this plan: 5 public driver-shaped types
(`Driver`, `DriverBuilder`, `Event<K>`, `Pipeline`,
`PipelineBuilder`) plus `SlotHandle<M>`. Down from 14 in 0.9.

## Status

Not started. Blocked on plans 119 + 120.

## Prerequisites

- Plan 118 Phase 0 — bench gate.
- Plan 119 — `track_into` + `&mut Vec` parser API in place.
- Plan 120 — Bytes audit complete (so the migration guide
  doesn't have to cover three shape changes at once).

## Out of scope

- **Push-style `on::<M>(callback)` API.** Reanalysis
  Alternative A picked pull (drain). Push can ship as sugar
  over drain in a follow-up patch release if asked for; not
  in 0.11.
- **`ConcurrentSlotHandle<M>` (Arc<Mutex>) variant.** First
  draft of this plan proposed it for async-task-crossing
  netring uses. Dropped: netring's pattern is to drain inside
  the single-threaded event loop, then post messages to async
  consumers via its own channels. flowscope ships one shape;
  netring adapts.
- **`seq: u64` cross-slot ordering field.** First draft
  proposed it. Dropped: per-`track_into` drain provides
  packet-level ordering automatically. Multi-packet ordering
  is up to the consumer's drain cadence; if they need
  finer-grained ordering they merge-sort by the existing
  `Timestamp` (already on every event). One less field.
- **Compile-time typestate builder.** First draft proposed a
  tuple-typestate `Builder<E, (P1, P2, P3)>`. Dropped:
  `SlotId<M>` tokens (a `usize` + `PhantomData<M>`) achieve
  the same type safety with simpler error messages and
  cfg-feature-gated parser registration. The driver internally
  holds `Vec<Box<dyn ErasedSlot>>` — one indirect call per
  slot per packet; the math at 5 slots × 1 Mpps = 250µs/sec =
  0.025% of a core, acceptable.
- **`flowscope::driver_unified` namespace.** Becomes
  `flowscope::driver` at the crate root (was originally plan
  117's rename step).

## Files

### Renames + deletions (absorbs plan 117)

- `src/driver_unified/` → `src/driver/` (rename).
- `src/driver.rs` (legacy `FlowDriver`) — DELETE; renamed
  module takes its slot.
- `src/session_driver.rs` (`FlowSessionDriver`) — DELETE.
- `src/datagram_driver.rs` (`FlowDatagramDriver`) — DELETE.
- `src/multi_session_driver.rs` (`FlowMultiSessionDriver`) —
  DELETE.
- `src/driver_builder.rs` — DELETE (both builders).
- `src/pipeline.rs` (legacy `Pipeline<E, S, D>`) — DELETE.
- `src/event.rs` — collapse: drop `FlowEvent` /
  `SessionEvent`; `Event<K>` (from former
  driver_unified::event) moves here. Note the parameter swap:
  the new `Event` carries flow-lifecycle variants only; per-
  slot typed messages live on `SlotHandle`, not on `Event`.

### Slot infrastructure (new shape)

- `src/driver/mod.rs` — `Driver<E>` (no `M` parameter),
  `DriverBuilder<E>`, public surface.
- `src/driver/slot.rs` (new) — `SlotHandle<M>`, `SlotId<M>`,
  `SlotMessage<K, M>`, internal `ErasedSlot` trait.
- `src/driver/concrete_slot.rs` — `ConcreteSlot<E, P>` for
  session parsers; inlines the former
  `FlowSessionDriver::track_into` logic directly using
  `FlowTracker` + `BufferedReassemblerFactory`.
- `src/driver/concrete_datagram_slot.rs` — same for
  datagrams.
- `src/driver/heuristic.rs` — heuristic slots become typed
  too.
- `src/driver/pipeline.rs` — `Pipeline<E>` wrapper, simplified
  since no `M` needs threading.

### Public surface

- `src/lib.rs` — drop the legacy re-exports
  (`pub use driver::FlowDriver`, etc.); add new re-exports
  for `Driver`, `DriverBuilder`, `Event`, `Pipeline`,
  `PipelineBuilder`, `SlotHandle`, `SlotId`, `SlotMessage`.
- `src/prelude.rs` — swap legacy types for unified.

### Tests + examples (migration sweep)

- ~25 test files importing deleted types: rewrite imports.
- ~30 example files: rewrite imports + builder calls.
- `examples/00-getting-started/hello_pipeline.rs` (already on
  unified) — verify no change needed.
- `examples/00-getting-started/unified_driver_demo.rs` —
  rename to `driver_demo.rs` post-namespace-flatten.

### Docs

- `docs/getting-started.md` — rewrite hello-world.
- `docs/concepts.md` — drop the legacy/unified comparison
  diagram; clean three-tier diagram (`FlowTracker` /
  `Driver` / `Pipeline`).
- `docs/recipes.md` — drop the "Migrating to unified Driver"
  recipe (no longer needed); add "Typed slot drains" recipe
  with the multi-protocol monitoring example.
- `docs/migration-0.10-to-0.11.md` — typed-slot section:
  - 0.10 `Driver<_, MyL7>::builder(ext).session_on_ports(...,
    MyL7::Http).build()` → 0.11 `let (mut driver,
    http_slot) = Driver::builder(ext).session(parser).build();`
  - lift closures gone; `Event::Message { message: MyL7, .. }`
    in 0.10 → `http_slot.drain(&mut buf); for m in &buf { /*
    HttpMessage */ }` in 0.11.

### Cargo.toml

- No new deps; no dropped deps. (The first draft considered
  `frunk` for typestate; rejected.)

## API

### Driver<E>

```rust
pub struct Driver<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    // internals:
    central: FlowTracker<E, ()>,         // inlined from former FlowDriver
    extractor: E,
    slots: Vec<Box<dyn ErasedSlot<E::Key>>>,
    dedup: Option<Dedup>,
    emit_anomalies: bool,
    monotonic_timestamps: bool,
    last_ts: Option<Timestamp>,
}

impl<E> Driver<E> /* … */ {
    pub fn builder(extractor: E) -> DriverBuilder<E>;

    pub fn track_into<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        out: &mut Vec<Event<E::Key>>,
    );
    pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key>>);
    pub fn finish_into(&mut self, out: &mut Vec<Event<E::Key>>);

    /// Borrow the central tracker for introspection.
    pub fn tracker(&self) -> &FlowTracker<E, ()>;
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()>;
}
```

### Event<K> — no `M` parameter

```rust
#[non_exhaustive]
pub enum Event<K> {
    FlowStarted { key: K, ts: Timestamp, l4: Option<L4Proto> },
    FlowPacket  { key: K, ts: Timestamp, tcp: Option<TcpInfo> },
    FlowEnded   { key: K, reason: EndReason, stats: FlowStats, ts: Timestamp },
    FlowAnomaly { key: K, kind: AnomalyKind, ts: Timestamp, /* … */ },
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp, /* … */ },
    ParserClosed { key: K, parser_kind: &'static str, reason: EndReason, ts: Timestamp },
}
```

The 0.10 `Event::Message { message: M, .. }` variant disappears
— typed messages flow through `SlotHandle::drain` instead.

### Slot types

```rust
// src/driver/slot.rs

/// Token identifying a registered slot. Tied to a specific
/// driver instance and a specific message type at compile time.
#[derive(Debug, Clone, Copy)]
pub struct SlotId<M> {
    index: usize,
    _marker: PhantomData<fn() -> M>,
}

/// Drain handle for one registered parser's typed message
/// stream.
pub struct SlotHandle<M: Send + 'static> {
    inner: Rc<RefCell<SlotBuf<M>>>,
    parser_kind: &'static str,
}

impl<M: Send + 'static> SlotHandle<M> {
    /// Drain buffered messages into `out`, reusing `out`'s
    /// capacity. Returns the number drained.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M>>) -> usize;

    /// Buffered count right now. Cheap inspection.
    pub fn pending(&self) -> usize;

    pub fn parser_kind(&self) -> &'static str { self.parser_kind }
}

#[non_exhaustive]
pub struct SlotMessage<M> {
    pub key: FlowKey,     // type-erased over E::Key for uniformity
    pub side: FlowSide,
    pub message: M,
    pub ts: Timestamp,
}
```

`FlowKey` is a new type-erased wrapper (`enum FlowKey {
FiveTuple(...), IpPair(...), MacPair(...), ... }` — or a
`Box<dyn Any>` if we don't want a closed enum). Pragmatically,
since the bench gate measures "0 allocs per parsed L7 message in
steady state," we need this to not allocate. **Decision:**
parameterise `SlotHandle<M, K = E::Key>` over the key type too,
mirroring `Driver<E>`. Then `SlotMessage<M, K>` is fully typed,
no boxing.

Refined:

```rust
pub struct SlotHandle<M, K = ()> { /* … */ }
pub struct SlotMessage<M, K> {
    pub key: K,
    pub side: FlowSide,
    pub message: M,
    pub ts: Timestamp,
}
```

### DriverBuilder<E>

```rust
pub struct DriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    emit_packet_details: bool,
    dedup: Option<Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
    slots: Vec<SlotSpec<E::Key>>,
}

impl<E> DriverBuilder<E> /* … */ {
    pub fn session<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone;

    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone, I: IntoIterator<Item = u16>;

    pub fn session_heuristic<P>(&mut self, parser: P, sig: SignatureFn) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone;

    pub fn datagram<D>(&mut self, parser: D) -> SlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone;

    // … same for other registration knobs

    pub fn config(&mut self, c: FlowTrackerConfig) -> &mut Self;
    pub fn monotonic_timestamps(&mut self, on: bool) -> &mut Self;
    pub fn emit_anomalies(&mut self, on: bool) -> &mut Self;
    pub fn emit_packet_details(&mut self, on: bool) -> &mut Self;
    pub fn dedup(&mut self, d: Dedup) -> &mut Self;
    pub fn idle_timeout_fn<F>(&mut self, f: F) -> &mut Self
    where F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + 'static;

    pub fn build(self) -> Driver<E>;
}
```

Note the builder takes `&mut self` for slot-registration calls
(not `self`) — so each `session(parser)` call mutates the
builder in place and returns the typed `SlotHandle`, not a
re-shaped builder. Far simpler than the typestate-tuple
approach.

### Consumer usage

```rust
let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot = builder.session(HttpParser::default());
let mut dns_slot  = builder.datagram(DnsUdpParser::default());
builder
    .emit_anomalies(true)
    .monotonic_timestamps(true);
let mut driver = builder.build();

let mut flow_events: Vec<Event<_>> = Vec::new();
let mut http_msgs:  Vec<SlotMessage<HttpMessage, _>> = Vec::new();
let mut dns_msgs:   Vec<SlotMessage<DnsMessage, _>>  = Vec::new();

for view in views() {
    flow_events.clear();
    http_msgs.clear();
    dns_msgs.clear();

    driver.track_into(view, &mut flow_events);
    http_slot.drain(&mut http_msgs);
    dns_slot.drain(&mut dns_msgs);

    for ev in &flow_events { /* lifecycle */ }
    for m in &http_msgs   { /* typed HttpMessage */ }
    for m in &dns_msgs    { /* typed DnsMessage */ }
}
```

## Implementation steps

### Step 1 — Rename + collapse

1. `git mv src/driver_unified src/driver`.
2. Move `Event` from `src/driver/event.rs` → `src/event.rs`,
   stripped of the `<M>` parameter and the `Message`/
   `ParserClosed`-via-lift variants.
3. Delete the 6 legacy files (`src/driver.rs`,
   `src/session_driver.rs`, `src/datagram_driver.rs`,
   `src/multi_session_driver.rs`, `src/driver_builder.rs`,
   `src/pipeline.rs`).
4. `src/lib.rs` — swap re-exports; rustdoc-link sweep.
5. `src/prelude.rs` — swap.

### Step 2 — Slot infrastructure

6. Write `SlotHandle<M, K>`, `SlotId<M>`, `SlotMessage<M, K>`,
   `SlotBuf<M, K>`, internal `ErasedSlot<K>` trait.
7. Write `ConcreteSlot<E, P>` — replicates what
   `FlowSessionDriver::track_into` did internally but writes
   typed messages into its slot buffer instead of into a
   `SessionEvent` stream.
8. Write `ConcreteDatagramSlot<E, D>` — same shape.
9. Write `HeuristicSessionSlot<E, P>` and
   `HeuristicDatagramSlot<E, D>` (the FlowDetection FSM logic
   ports straight from the old heuristic.rs).

### Step 3 — Driver + Builder

10. Refactor `Driver<E>` to drop the `M` parameter, hold the
    typed `Vec<Box<dyn ErasedSlot<E::Key>>>`, route packets to
    every applicable slot.
11. Refactor `DriverBuilder<E>` to mutate-in-place and return
    `SlotHandle<P::Message, E::Key>` per registration call.

### Step 4 — Pipeline

12. Refactor `Pipeline<E>` to wrap `Driver<E>`. Its
    `PipelineBuilder<E>::session(parser)` etc. mirror the
    driver builder shape, returning slot handles to the
    consumer.
13. `Pipeline::run_iter` yields `Event<E::Key>` only;
    consumers also receive their slot handles up-front and
    drain them between iterator pulls.

### Step 5 — Migration sweep (the big one)

14. Migrate every test file. Two patterns:
    - **Pattern A** (parser-free, lifecycle-only): replace
      `FlowDriver` / `FlowSessionDriver` import + builder call
      with `Driver::builder(ext).build()`; match `Event<K>`
      variants.
    - **Pattern B** (with parsers): builder.session(parser) →
      get slot handle; loop calls `track_into` for lifecycle
      and `slot.drain` for messages.
15. Migrate every example.
16. Migrate `examples/00-getting-started/unified_driver_demo.rs`
    → `examples/00-getting-started/driver_demo.rs`; this
    becomes the canonical shape doc.

### Step 6 — Docs

17. Rewrite `docs/getting-started.md` hello-world to use the
    new shape.
18. Rewrite `docs/concepts.md` three-tier diagram.
19. Add typed-slot recipe to `docs/recipes.md`.
20. Write the typed-slot migration section in
    `docs/migration-0.10-to-0.11.md`.

### Step 7 — Bench + finalize

21. Run `cargo bench --bench zero_alloc`. Phase 3 row of the
    umbrella's Baseline table records the post-Phase-3
    number. Gate hit: 0 allocs per parsed L7 message in
    steady state.

## Tests

- `tests/typed_slot_drain.rs::slot_drain_basic` — single
  parser, drain pulls messages.
- `tests/typed_slot_drain.rs::slot_drain_capacity_reuse` —
  scratch capacity stable after warmup.
- `tests/typed_slot_drain.rs::two_slots_independent_drain` —
  HTTP + DNS slots, drained independently, no
  cross-contamination.
- `tests/typed_slot_drain.rs::port_filter_routes_only_matching`
  — session_on_ports([80]) only sees port-80 traffic.
- `tests/typed_slot_drain.rs::heuristic_promotes_then_pins` —
  promotion + pinning + GaveUp transitions all visible.
- `tests/driver_unified.rs::event_no_message_variant` —
  compile-fail proof that `Event` has no `Message` variant.
- `tests/legacy_types_gone.rs` (build-only test) — compile-
  fail proof that `flowscope::FlowSessionDriver` does not
  resolve.
- Bench (gates Phase 3 baseline row):
  - `benches/zero_alloc.rs::bench_typed_slot_dispatch` ≤ 0
    allocs/parsed-message.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 9 CI feature-matrix entries clean.
- `cargo doc --all-features --no-deps` zero warnings.
- Phase 3 bench gate row hits target.
- Every legacy type (`FlowDriver`, `FlowSessionDriver`,
  `FlowDatagramDriver`, `FlowMultiSessionDriver`,
  `FlowSessionDriverBuilder`, `FlowDatagramDriverBuilder`,
  legacy `Pipeline`) is gone from `src/`.
- `flowscope::Driver` / `flowscope::Event` /
  `flowscope::Pipeline` resolve at the crate root.
- All shipped tests + examples build + run.
- Public driver-shaped type count: 5 (Driver, DriverBuilder,
  Event, Pipeline, PipelineBuilder) + 3 slot types
  (SlotHandle, SlotId, SlotMessage) = 8. Down from 14 in
  0.9.
- Migration guide typed-slot section complete with a
  side-by-side before/after for the multi-protocol
  monitoring example.
- CHANGELOG 0.11.0 entry lists every deleted type + recipes.

## Risks

- **`Rc<RefCell<…>>` inside `SlotHandle` makes it `!Send`.**
  Mitigation: this matches netring's actual usage (drain
  inside the single-threaded event loop; post to async
  consumers via netring's channels). Document the
  single-thread expectation. Multi-thread cases ship a
  channel adapter in netring, not here.
- **`SlotHandle` lifetime tied to `Driver` lifetime.** If
  the Driver drops, the SlotHandle's `Rc<RefCell<...>>` is
  still alive but points to nothing useful. Mitigation: the
  `Rc` keeps the SlotBuf alive even after the Driver drops;
  drain returns nothing if there's no further input. Safe;
  document the behaviour.
- **The big migration sweep (Step 5) is the biggest single
  chunk of work in the cycle.** ~25 tests + ~30 examples ×
  ~10 LOC change average = ~500 LOC. Mitigation: pattern A
  / B template in the migration guide; sweep through with a
  small script if needed.
- **Internal slot refactor (Step 2) replicates
  `FlowSessionDriver` logic.** Risk of subtle behaviour
  drift. Mitigation: the new `ConcreteSlot` is a careful
  re-implementation; regression tests against the 0.10.1
  recorded snapshots for HTTP / DNS / TLS fixture pcaps
  catch any drift.
- **Public type-erased key in `SlotMessage`.** First draft
  proposed `FlowKey` (closed enum or `Box<dyn Any>`).
  Dropped: `SlotMessage<M, K>` is generic over `K = E::Key`.
  Each `Driver<E>` instance has one `K`, so per-driver type
  uniformity is preserved. Multi-extractor scenarios are
  rare and out of scope.
- **`Pipeline` builder ergonomics with slot handles.** The
  pipeline builder needs to thread slot handles back to the
  caller from inside its registration chain. Mitigation:
  same `&mut self`-returning shape as `DriverBuilder`; the
  builder is a temporary scaffold, not a long-lived value.

## Effort

~5 working days:
- 0.5d rename + delete + lib.rs re-exports.
- 1.0d slot infrastructure (SlotHandle, SlotBuf, ErasedSlot
  trait, ConcreteSlot, ConcreteDatagramSlot, heuristic
  slots).
- 0.5d Driver + DriverBuilder refactor.
- 0.5d Pipeline refactor.
- 1.5d test + example migration sweep.
- 0.5d docs + migration guide section.
- 0.5d bench + CI verification + buffer.

## Provenance

- `flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`
  §3.3 Alternative A (typed slot drains, picked over the
  TypeId-callback approach and the sum-type-macro approach).
- The simplification path here (drop typestate, drop seq,
  drop ConcurrentSlotHandle) comes from the consolidation
  pass — first-draft plan 122 had all three; second pass
  showed they were complexity without enough return.
- Plan 117 (legacy driver deletion, was queued for next
  major) is absorbed into this plan's Step 1 + Step 5
  because the slot refactor overlaps and a second migration
  window for consumers is worse than one wider one.
