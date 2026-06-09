# Plan 119 — Driver allocation elimination

## Summary

Drive the per-packet allocation count to zero on the `Driver`
dispatch path. Three coordinated changes:

1. **`Driver::track_into(view, &mut Vec<Event>)`** — additive
   on the public API; original allocation site.
2. **`DriverSlot::track_into(view, ts, &mut Vec<Event>)`** —
   internal trait change; every `.collect()` on the slot
   dispatch path is removed.
3. **`SessionParser::feed_*` / `DatagramParser::parse`** take
   `&mut Vec<Self::Message>` directly instead of returning a
   fresh Vec. Same idiom `httparse` uses for the same reason.

The three changes have to ship together because the buffer
flows top-down: caller's `Vec<Event>` → slot's `Vec<P::Message>`
(internal scratch) → parser writes into the scratch. Each step
without the next is wasted work.

After this plan: a `Driver` with 5 slots running 1 Mpps mixed
HTTP / DNS / non-L7 traffic does ≤ 0.5 allocations per packet
in steady state.

## Status

Not started. Blocked on plan 118 Phase 0 (benchmark gate).

## Prerequisites

- Plan 118 Phase 0 — bench harness landed; baseline numbers in
  the umbrella's Baseline table.

## Out of scope

- **Bytes audit on parsed-message types.** Plan 120.
- **Typed slot drain handles.** Plan 121.
- **Legacy driver deletion.** Plan 121.
- **`OutBuf<'_, M>` newtype wrapper.** Reanalysis report
  proposed this; on second pass, the bare `&mut Vec<M>` is
  simpler — same perf, fewer concepts, matches the `httparse`
  / `nom` (`many0_count`) / `quiche::recv` idiom that Rust
  ecosystem readers already know. KISS.
- **Static-dispatch the slot list.** Reanalysis §4.3 raised
  vtable indirection cost — but the math at 5 slots × 1 Mpps =
  250µs/s = 0.025% of a core. Not worth the typestate-tuple
  complexity. Stays `Vec<Box<dyn DriverSlot>>`.
- **Pipeline::run_iter / run_pcap.** Internal uses of `track`
  benefit transparently once `track_into` is wired underneath;
  no public API change here.

## Files

- `src/driver_unified/mod.rs` — add `Driver::track_into`,
  `Driver::sweep_into`, `Driver::finish_into`. Refactor
  `track` / `sweep` / `finish` into thin wrappers.
- `src/driver_unified/erased.rs` — change the `DriverSlot<K,
  M>` trait method shape; rewrite `ConcreteSlot` /
  `ConcreteDatagramSlot` impls; remove every `.collect()` and
  `Vec::new()` on the lifted-event path.
- `src/driver_unified/heuristic.rs` — same shape change for
  `HeuristicSessionSlot` and `HeuristicDatagramSlot`.
- `src/driver_unified/pipeline.rs` — `Pipeline::run_iter`
  reuses one scratch buffer across packets via the new
  `track_into`.
- `src/driver.rs` — `FlowDriver::track_into` (the central
  tracker driver). This is the bedrock the slot impls and the
  unified Driver both call into.
- `src/session_driver.rs` — `FlowSessionDriver::track_into`.
- `src/datagram_driver.rs` — `FlowDatagramDriver::track_into`.
- `src/tracker.rs` — `FlowTracker::track_into(&mut self, view,
  &mut Vec<FlowEvent<K>>)` plus the `track` / `sweep` / `finish`
  wrappers.
- `src/session.rs` — break `SessionParser::feed_initiator` /
  `feed_responder` / `fin_initiator` / `fin_responder` /
  `on_tick` to take `&mut Vec<Self::Message>`. Same for
  `DatagramParser::parse` and `on_tick`.
- All shipped parsers:
  - `src/http/parser.rs`, `src/http/session.rs`,
    `src/http/exchange.rs`
  - `src/tls/parser.rs`, `src/tls/session.rs`,
    `src/tls/handshake.rs`
  - `src/dns/parser.rs`, `src/dns/session.rs`,
    `src/dns/datagram.rs`, `src/dns/exchange.rs`
  - `src/icmp/parser.rs`, `src/icmp/datagram.rs`
- All parser-helper impls:
  - `src/session.rs` — `BufferedFrameDrain` /
    `AccumulatingSessionParser` / `PerDatagramParser`.
- All shipped tests with custom parsers:
  - `tests/length_prefixed_example.rs`
  - `tests/parser_helpers.rs`
  - `tests/driver_unified.rs`
  - `tests/pipeline_unified.rs`
  - `tests/pipeline.rs`
  - `tests/multi_session_driver.rs`
  - `tests/round_trip.rs`
  - `tests/auto_sweep.rs`
  - `tests/parser_proptest.rs`
- All examples with custom parsers:
  - `examples/06-custom-protocols/`
  - any other custom-parser sites the migration sweep catches.
- `docs/migration-0.10-to-0.11.md` — new file (or grow it if
  plan 120 lands first); covers the parser API shift.

## API

### Driver

```rust
impl<E, M> Driver<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Process one packet, appending events into `out`. Reuses
    /// `out`'s capacity across calls — zero allocation in
    /// steady state.
    pub fn track_into<'v>(
        &mut self,
        view: impl Into<PacketView<'v>>,
        out: &mut Vec<Event<E::Key, M>>,
    );

    pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<E::Key, M>>);
    pub fn finish_into(&mut self, out: &mut Vec<Event<E::Key, M>>);

    // Existing `track` / `sweep` / `finish` become thin wrappers
    // that allocate a fresh Vec; behaviour unchanged.
}
```

### Slot trait (`pub(super)`)

```rust
pub(super) trait DriverSlot<K, M>: Send {
    fn track_into(&mut self, view: PacketView<'_>, ts: Timestamp, out: &mut Vec<Event<K, M>>);
    fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<K, M>>);
    fn finish_into(&mut self, out: &mut Vec<Event<K, M>>);
}
```

### Parser traits (breaking)

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);
    fn fin_initiator(&mut self, _out: &mut Vec<Self::Message>) {}
    fn fin_responder(&mut self, _out: &mut Vec<Self::Message>) {}
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}
    fn on_tick(&mut self, _now: Timestamp, _out: &mut Vec<Self::Message>) {}

    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn is_done(&self) -> bool { false }
    fn parser_kind(&self) -> &'static str { "" }
}

pub trait DatagramParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    fn parse(
        &mut self,
        payload: &[u8],
        side: FlowSide,
        ts: Timestamp,
        out: &mut Vec<Self::Message>,
    );

    fn on_tick(&mut self, _now: Timestamp, _out: &mut Vec<Self::Message>) {}
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn parser_kind(&self) -> &'static str { "" }
}
```

### `FlowTracker::track_into` (internal-but-public)

```rust
impl<E, S> FlowTracker<E, S> { /* … */
    /// Append-only variant of [`track`]. Reuses caller's
    /// capacity. Same event semantics.
    pub fn track_into(&mut self, view: PacketView<'_>, out: &mut Vec<FlowEvent<E::Key>>);
    pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<FlowEvent<E::Key>>);
    pub fn finish_into(&mut self, out: &mut Vec<FlowEvent<E::Key>>);
}
```

## Implementation steps

### Step 1 — Tracker layer

1. Add `FlowTracker::track_into` / `sweep_into` / `finish_into`.
   The existing `track` etc. become wrappers that allocate a
   `Vec::with_capacity(8)` and call `_into`.
2. Same shape for `FlowDriver::track_into` /
   `FlowSessionDriver::track_into` /
   `FlowDatagramDriver::track_into`.

### Step 2 — Slot trait swap

3. Rewrite `DriverSlot::track_into` to take `&mut Vec<Event<K,
   M>>`. Compiler will error on every impl; that's the work
   list.
4. Migrate `ConcreteSlot::track_into`: replace
   `.filter_map(...).collect()` with a loop that calls
   `lift_event` and `out.push(...)`. The underlying
   `FlowSessionDriver::track_into` writes its events into a
   per-slot scratch `Vec<SessionEvent<K, P::Message>>` (kept
   as a struct field on `ConcreteSlot`, cleared each call).
5. Migrate `ConcreteDatagramSlot::track_into`: same shape.
6. Migrate `HeuristicSessionSlot::track_into` and
   `HeuristicDatagramSlot::track_into`: same shape; the
   heuristic FSM logic stays.

### Step 3 — Driver top layer

7. Add `Driver::track_into`. Bodywise:
   - For `emit_packet_details(true)` the existing
     `view.frame.to_vec()` clone stays for this plan (gets
     removed in Phase 4 of plan 118 — the field is deleted
     entirely there).
   - Call `self.central.track_into(view, out)` (writes
     flow-lifecycle events directly).
   - For each slot, `slot.track_into(view, ts, out)`.
8. Add `Driver::sweep_into` / `finish_into` with the same
   shape.
9. Update `Driver::track` etc. to be one-line wrappers.

### Step 4 — Parser trait break

10. Rewrite `SessionParser` + `DatagramParser` trait method
    signatures.
11. Migrate `HttpParser` + `HttpExchangeParser`. These already
    buffer messages internally; just switch the "drain into a
    fresh Vec to return" line to "push directly into `out`."
12. Migrate `TlsParser` + `TlsHandshakeParser`.
13. Migrate `DnsUdpParser` + `DnsTcpParser` +
    `DnsExchangeParser`.
14. Migrate `IcmpParser`.
15. Migrate the parser-helper types (`BufferedFrameDrain`,
    `AccumulatingSessionParser`, `PerDatagramParser`).

### Step 5 — Migrate every consumer of the old trait shape

16. `FlowSessionDriver` / `FlowDatagramDriver`: the per-slot
    `messages: Vec<_>` field that today receives the parser's
    return value now gets passed as `&mut messages` to
    `parser.feed_initiator(bytes, ts, &mut messages)`.
17. Every test with a custom parser: rewrite the parser impl
    to push into `out`. The pattern is mechanical; ~5 lines
    per parser, ~30 lines per test file.
18. Every example with a custom parser: same.

### Step 6 — Pipeline::run_iter

19. Hold a persistent `Vec<Event<_, M>>` scratch on the
    iterator state. Per-packet: `out.clear();
    driver.track_into(view, &mut out)`; yield events from `out`
    via a chained iterator drain.

### Step 7 — Bench

20. Re-run `cargo bench --bench zero_alloc`. Phase 1 row of
    the umbrella's Baseline table records the post-Phase-1
    number. Hit gate: ≤ 0.5 allocs/packet at 1 Mpps non-L7
    with 5 slots; ≤ 0.1 allocs/parser-call.

## Tests

- `tests/driver_unified.rs::track_into_reuses_buffer` — call
  `track_into` 1000× against the same fixture; assert scratch
  capacity is stable after the first 10 calls.
- `tests/driver_unified.rs::track_into_matches_track` — output
  equality vs. the legacy `track` path.
- `tests/driver_unified.rs::sweep_into_drains_idle_flows` —
  parity with existing sweep behaviour.
- `tests/pipeline_unified.rs::pipeline_run_iter_stable_memory`
  — long synthetic stream (100k packets); assert allocator
  count flatlines after warmup.
- Parser migration parity per shipped parser:
  - `tests/http_parser.rs::out_buf_path_matches_old_vec_path` —
    feed a recorded fixture, compare output to recorded
    snapshots.
  - Same for TLS / DNS / ICMP.
- Bench (gates Phase 1 row in plan 118 baseline table):
  - `benches/zero_alloc.rs::bench_track_into_steady_state`
    asserts ≤ 0.5 allocs/packet.
  - `benches/zero_alloc.rs::bench_parser_feed_steady_state`
    asserts ≤ 0.1 allocs/call.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 9 CI feature-matrix entries clean.
- `cargo doc --all-features --no-deps` zero warnings (rustdoc
  updated for the new method signatures).
- `cargo bench --bench zero_alloc` hits both Phase 1 gate
  rows.
- Migration-guide section "parser API change" complete with
  one-line before/after for each method.
- `CHANGELOG.md` 0.11.0 entry documents the parser trait break
  with a 5-line recipe.

## Risks

- **Third-party `SessionParser` impls break.** Mitigation:
  migration guide ships a sed-style recipe for the common
  case:
  - Before: `fn feed_initiator(&mut self, bytes: &[u8], ts:
    Timestamp) -> Vec<Self::Message> { let mut out =
    Vec::new(); /* ... */ out }`
  - After: `fn feed_initiator(&mut self, bytes: &[u8], ts:
    Timestamp, out: &mut Vec<Self::Message>) { /* same body,
    s/out.push/out.push/ */ }`
- **`is_done()` ordering vs. `feed_*` output.** Today the
  driver checks `is_done` after `feed_*` returns the Vec. Now
  the driver checks after `feed_*` returns void; output has
  already landed in `out`. Same semantics; no behaviour change.
- **Pipeline iterator semantics.** `run_iter` returning a
  per-packet substream that re-fills shared scratch could
  produce non-Send iterators if the scratch is not `Send`.
  Mitigation: scratch is `Vec<Event<_, M>>` which is `Send`
  whenever `M: Send`; same as today.
- **The `view.frame.to_vec()` line is still there** when
  `emit_packet_details(true)`. Plan 118 Phase 4 removes it
  entirely; this plan does not touch it. The Phase 1 bench
  measures with `emit_packet_details(false)` so this isn't a
  blocker.
- **A scratch buffer can grow unboundedly** if a single
  packet emits many events (pathological synthetic test).
  Mitigation: `Vec`'s growth is geometric; cap with
  `out.shrink_to(capacity_after_warmup)` if needed.
  Documented but unfixed unless a real consumer trips it.

## Effort

~5 working days:
- 0.5d Tracker / FlowDriver `track_into` plumbing.
- 1.0d Slot trait swap + ConcreteSlot /
  ConcreteDatagramSlot / Heuristic* migration.
- 0.5d Driver::track_into + sweep_into + finish_into.
- 0.5d Pipeline::run_iter rewrite.
- 1.0d parser trait break + migrate 5 shipped parsers + 3
  helper types.
- 1.0d migrate all custom parser tests + examples.
- 0.5d bench verification + migration-guide section.

## Provenance

- `flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`
  §3.1 (rejects original `&mut Vec`; this plan picks `&mut Vec`
  back up after second pass — the `OutBuf` newtype was the
  reanalysis's overcorrection. KISS.).
- Reanalysis §4.1 (slot-level `.collect()` allocations).
- Reanalysis §4.3 — rejected here. Static slot dispatch math:
  5 slots × 1 Mpps × ~50ns/indirect = 0.025% of a core. Not
  worth the typestate complexity.
- Reanalysis §3.2 — original audit's parser scratch reuse
  item, picked up wholesale.
