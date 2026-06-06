# Plan 81 — `flowscope::correlate` module

## Summary

A `flowscope::correlate` module shipping three building blocks
every consumer of real-time anomaly-correlation logic needs:

1. **`TimeBucketedCounter<K>`** — windowed rate counting per
   key, with automatic bucket eviction. Use case:
   *"host issued >N DNS queries in <T seconds"*.
2. **`KeyIndexed<K, V>`** — TTL'd LRU cache with monotonic-
   time semantics. Use case: *"DNS resolved foo.com → IPs Y at
   time T; was the subsequent TCP connection to Y within idle
   window of T?"*
3. **`SequencePattern<E>`** — generic FSM trait for event-
   sequence detection: *"event matching A → expect event matching
   B within K seconds → otherwise emit anomaly."*

This started as an RFC plan published in 0.7.0; for 0.9.0 the
design is locked and it promotes to an implementation plan.

The narrow `flowscope::dns::DnsResolutionCache` primitive (shipped
in 0.8.0, plan 85) consumes the `KeyIndexed` shape — when
`correlate` lands, `DnsResolutionCache` is re-implemented as a
domain-specific wrapper around `KeyIndexed<(IpAddr, IpAddr),
String>` for zero-cost type-narrowing while preserving the
existing API.

## Status

**Ready to implement.** Targets 0.9.0 release. Design questions
Q1–Q7 (below) are answered with locked picks; reviewer pushback
is welcome but no further blocking on consensus.

## Prerequisites

- Plan 49 (`Dedup` content-hash dedup primitive) — shipped in
  0.3.0. The `Dedup` shape (carrier-agnostic primitive,
  embeddable into any consumer pipeline) is the design
  precedent. The correlate primitives follow the same shape.
- Plan 71 (`flow_tick_interval` / `FlowEvent::Tick`) — shipped
  in 0.5.0. Tick events are the timing substrate
  `SequencePattern::on_tick` consumes.
- Plan 43 (`FlowAnomaly` / `TrackerAnomaly` split) — shipped in
  0.6.0. Correlation outputs that classify as anomalies use the
  established carrier shapes.
- Plan 85 (`DnsResolutionCache`) — shipped in 0.8.0. The
  domain-specific shape this plan generalises. Plan covers the
  re-implementation step as a wrapper around `KeyIndexed`.

## Out of scope

- Concrete anomaly *types* / heuristics (volumetric attack
  detection, port-scan detection, etc.). The module ships
  primitives; consumers compose them into detectors. Concrete
  detectors live in netring or downstream crates.
- Cross-host coordination. The primitives are per-process; a
  distributed consumer (multi-collector NMS) coordinates via
  external means (Prometheus, Kafka, etc.). The flowscope
  primitives are deliberately single-process.
- Built-in pre-baked `SequencePattern` implementations (e.g.
  `WithinWindow<E>`). Ship the trait + adapter in 0.9; the
  pre-baked patterns are a follow-up after 0.9 usage data.

---

## Why these three primitives?

The three are the irreducible substrate of pattern-matched
anomaly detection over event streams:

- **Counters** answer "how often" — rate-limited / threshold-
  based detectors.
- **TTL'd lookups** answer "what was true recently" — cross-
  protocol correlation, time-bounded joins.
- **Sequence patterns** answer "did A → B happen in order
  within T" — protocol-misbehaviour detectors, attack-pattern
  matchers.

These are also exactly what an event-driven anomaly engine like
[stalker](https://github.com/cloudflare/stalker),
[VAST](https://vast.io/),
[Suricata's flowint](https://docs.suricata.io/en/latest/rules/flow-keywords.html),
or [Zeek's table types](https://docs.zeek.org/en/master/script-reference/types.html#type-table)
expose at their core. flowscope's value-add is bounded
memory + zero allocations on the hot path + packet-clock
timing — same constraints as the rest of the crate.

### Why ship them in flowscope?

The author's case: every downstream that builds a real-time
correlator writes the same three primitives. Shipping once
beats N times. Counterargument: the primitives are
domain-generic — why does flowscope (a flow-tracking crate)
ship them? Because they share the `Timestamp` / `bounded
memory` / `runtime-free` constraints with the rest of the
crate, and the consumer-side correlation patterns naturally
feed off `FlowEvent` / `SessionEvent`. A standalone
`event-correlate` crate would have to re-derive the timing
model.

The decision is "ship inside flowscope under a feature gate"
unless reviewers object.

---

## Design questions

Each has an opinion attached; the RFC invites reviewer
disagreement before code lands.

### Q1: `TimeBucketedCounter` — fixed buckets or sliding window?

**Option A** (fixed buckets, ring-buffer of `HashMap`s): cheap
(~ns/bump), counts reset at bucket boundaries. A 99-bump
burst at second `T - 0.001s` reads as 1 at `T + 0.5s` if the
bucket width is 1s.

**Option B** (sliding window of timestamps per key): precise
to the timestamp, expensive (O(n) per query, unbounded memory
unless capped per key).

**Option C** (TDigest / exponential decay): smooths the cliff
but introduces estimation error.

**Locked decision:** Option A with a documented cliff. The
80% case for anomaly detection is rate thresholds on the order
of multiple buckets — a 99-bump burst at bucket boundary that
reads as 99-bumps-in-one-bucket-then-zero is operationally
fine. Consumers needing sub-bucket precision are out of scope
for the primitive; they roll their own.

### Q2: `KeyIndexed<K, V>` — wrap `lru` or hand-roll?

flowscope already depends on the `lru` crate
(`FlowTracker::flows: LruCache`). Wrapping that crate avoids a
second LRU implementation. The wrapping logic is:
- `insert(k, v, ts)` → `lru.put(k, (v, ts))`
- `get(k, now)` → `lru.get(k)` then filter on `now - ts <= ttl`
- `evict_expired(now)` → iterate; remove all where
  `now - ts > ttl`

Hand-rolling would buy us nothing: the `lru` crate is mature,
the per-entry timestamp is the only extra bookkeeping.

**Locked decision:** wrap `lru::LruCache<K, (V, Timestamp)>`.

### Q3: `SequencePattern` — trait-based or callback?

The author's proposal:

```rust
pub trait SequencePattern: Send + 'static {
    type Event;
    type Anomaly;
    fn observe(&mut self, evt: &Self::Event, now: Timestamp)
        -> SmallVec<[Self::Anomaly; 1]>;
    fn on_tick(&mut self, now: Timestamp)
        -> SmallVec<[Self::Anomaly; 4]>;
}
```

Trait-based, owns its own state, mirrors the `SessionParser`
shape. Pro: composes with existing flowscope patterns.

Alternative: a `SequencePattern` *struct* configured via a
state-table or DSL. Pro: declarative; consumer writes less
code. Con: design-heavy; the DSL is the hard part.

**Locked decision:** trait-based. Consumers either roll a
custom struct (full control) or pick a small set of pre-built
patterns flowscope ships (e.g. `WithinWindow<E>` for
"event-A-then-event-B within T"). The set of pre-built
patterns is a follow-up plan; the trait shape is the RFC
deliverable.

### Q4: How does `SequencePattern` ingest events?

The flowscope event types are `FlowEvent<K>` and
`SessionEvent<K, M>`. Both carry the flow key. A `SequencePattern`
needs to:

- Index its state per key (e.g. "track NS → NA sequence per
  source IP"), so the trait should make per-key state easy.
- Allow keyed lookup of "what state did we have for key K at
  time T".

**Option A:** `SequencePattern` owns a single state machine;
consumer wraps it with a `HashMap<K, SequencePattern>`.

**Option B:** `SequencePattern` is inherently keyed:
`fn observe(&mut self, key: &K, evt: &E, now: Timestamp)`.

**Locked decision:** Option B. The keying is so universal that
making it explicit on the trait saves the per-consumer
boilerplate. Cost: less flexible for keyless patterns
(global-state detectors). Mitigation: a `KeylessSequencePattern`
sub-trait blanket-implements `SequencePattern` for `K = ()`.

### Q5: `Anomaly` output — typed or string?

The author proposes `type Anomaly` (associated type). Pro:
consumer-defined; full type information at the call site. Con:
no built-in routing of "anomalies from any pattern" because
each pattern has its own `Anomaly` type.

**Alternative:** ship a `flowscope::CorrelationAnomaly` enum
that all built-in patterns produce; consumers writing custom
patterns either map into it or expose their own type.

**Locked decision:** the associated type. Built-in patterns
(when shipped) all converge on a single concrete type for
ergonomics; custom patterns use whatever fits.

### Q6: Composition with `FlowEvent` / `SessionEvent`

How does the consumer wire a `SequencePattern` into their
event loop? Two shapes:

**A.** Consumer is responsible: walk
`driver.track(view)`; for each event, call `pattern.observe(key,
&event, ts)`; drain `pattern.on_tick(now)` on every sweep.

**B.** flowscope ships a `CorrelatedStream<S, P>` driver that
sits *atop* a `FlowSessionDriver` and merges the pattern's
anomalies into the event stream as a new `SessionEvent` variant.

**Locked decision:** A. Consumer-owned composition keeps the
driver simple and lets the consumer mix multiple patterns
over the same event stream. The wrapper-driver approach
(option B) can be a downstream's `netring::CorrelatedStream`
if it turns out to be wanted.

### Q7: Memory bounds

All three primitives need hard limits. For
`TimeBucketedCounter`: cap on total keys (LRU evict the
oldest). For `KeyIndexed`: explicit capacity argument. For
`SequencePattern`: caller's responsibility (the trait owns the
state).

Open: should `TimeBucketedCounter` expose
`AnomalyKind::CorrelationTableEvictionPressure`? Consistent
with the existing `FlowTableEvictionPressure`. Likely yes;
defer to the implementation plan.

---

## Proposed API shape

The RFC pins one minimum shape so the discussion has something
concrete to react to. Variants are explicitly invited.

### `src/correlate/mod.rs` (new module, feature `correlate`)

```rust
//! Real-time event-correlation primitives.

mod time_bucketed_counter;
mod key_indexed;
mod sequence_pattern;

pub use time_bucketed_counter::TimeBucketedCounter;
pub use key_indexed::KeyIndexed;
pub use sequence_pattern::{SequencePattern, KeylessSequencePattern};
```

### `TimeBucketedCounter`

```rust
pub struct TimeBucketedCounter<K> {
    window: Duration,
    bucket_width: Duration,
    capacity: usize,
    buckets: VecDeque<(Timestamp, HashMap<K, u64>)>,
}

impl<K: Hash + Eq + Clone> TimeBucketedCounter<K> {
    /// `window` = total observation window; `bucket_width` =
    /// bucket granularity; `capacity` = max distinct keys held
    /// (LRU eviction at this cap).
    pub fn new(window: Duration, bucket_width: Duration, capacity: usize) -> Self;

    pub fn bump(&mut self, key: K, now: Timestamp);
    pub fn count(&self, key: &K, now: Timestamp) -> u64;
    pub fn entries_above(&self, threshold: u64, now: Timestamp)
        -> impl Iterator<Item = (&K, u64)>;

    /// Drop buckets older than `now - window`.
    pub fn evict_expired(&mut self, now: Timestamp);
}
```

### `KeyIndexed`

```rust
pub struct KeyIndexed<K, V> {
    ttl: Duration,
    inner: lru::LruCache<K, (V, Timestamp)>,
}

impl<K: Hash + Eq, V> KeyIndexed<K, V> {
    pub fn new(ttl: Duration, capacity: usize) -> Self;

    pub fn insert(&mut self, k: K, v: V, ts: Timestamp);
    pub fn get(&mut self, k: &K, now: Timestamp) -> Option<&V>;
    pub fn evict_expired(&mut self, now: Timestamp);
}
```

### `SequencePattern`

```rust
pub trait SequencePattern: Send + 'static {
    type Key: Hash + Eq + Clone + Send + 'static;
    type Event;
    type Anomaly;

    fn observe(&mut self, key: &Self::Key, evt: &Self::Event, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 1]>;

    fn on_tick(&mut self, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 4]>;
}

/// Blanket adapter for keyless patterns. Implement
/// `KeylessSequencePattern` instead and get `SequencePattern<Key = ()>`
/// for free.
pub trait KeylessSequencePattern: Send + 'static {
    type Event;
    type Anomaly;

    fn observe(&mut self, evt: &Self::Event, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 1]>;

    fn on_tick(&mut self, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 4]>;
}

impl<T: KeylessSequencePattern> SequencePattern for T {
    type Key = ();
    type Event = T::Event;
    type Anomaly = T::Anomaly;
    fn observe(&mut self, _key: &(), evt: &T::Event, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 1]> {
        KeylessSequencePattern::observe(self, evt, now)
    }
    fn on_tick(&mut self, now: Timestamp)
        -> smallvec::SmallVec<[Self::Anomaly; 4]> {
        KeylessSequencePattern::on_tick(self, now)
    }
}
```

---

## What would need to change in netring

If this lands as proposed, netring's anomaly examples reduce
to ~30 LoC of pattern composition vs. ~300 LoC of
hand-rolled state. The author's roadmap document outlines this
expectation. Concrete migration is netring-side and not in
this RFC's scope; the RFC's success criterion is that the
primitives are general enough for *both* netring's anticipated
anomaly patterns and at least one other consumer's (simple-nms's
or des-rs's) without modification.

## Constraints

### Memory bounded

Every primitive caps memory explicitly. `TimeBucketedCounter`
caps per-bucket map size (LRU-evict at cap); `KeyIndexed` is
LRU at construction-time capacity; `SequencePattern` defers
to the impl.

### Time bounded

All primitives use `Timestamp` (packet clock or wall clock —
the type itself is opaque). The internal logic is monotonic
under the assumption that callers feed monotonic timestamps;
out-of-order timestamps either evict prematurely or lose
counts (documented).

### Composes with `Send + 'static`

All primitives are `Send + 'static` so they cross task
boundaries cleanly (consumers compose them inside tokio tasks
in netring; sync consumers in flowscope itself).

### Stays inside the `correlate` feature

The module ships behind a `correlate` Cargo feature so consumers
who only want `FlowTracker` don't compile the LRU wrapper / FSM
machinery.

---

## Acceptance criteria

- All three primitives compile under `--features correlate` and
  carry round-trip tests for the documented semantics.
- `DnsResolutionCache` (plan 85) is re-implemented as a
  domain-specific wrapper around `KeyIndexed<(IpAddr, IpAddr),
  String>`. The public API is unchanged; the migration is
  internal-only.
- `TimeBucketedCounter` and `KeyIndexed` both ship LRU
  capacity caps with eviction-pressure anomaly variants on
  `AnomalyKind` (`CorrelationTableEvictionPressure`).
- One pre-built `SequencePattern` impl ships in the same
  release: `WithinWindow<E>` for the "event-A-then-event-B
  within T" pattern.
- `docs/recipes.md` gains a "Building anomaly detectors with
  correlate" section consuming the three primitives.
- `cargo bench --features correlate` shows the three primitives'
  hot-path costs; baseline numbers land in `docs/performance.md`.

## Effort

- `TimeBucketedCounter`: ~150 LoC + tests, 4 hours.
- `KeyIndexed`: ~80 LoC + tests, 2 hours.
- `SequencePattern` trait + `KeylessSequencePattern` blanket
  adapter: ~100 LoC + tests, 3 hours.
- `WithinWindow<E>` pre-built pattern: ~120 LoC + tests, 4 hours.
- `DnsResolutionCache` re-implementation as `KeyIndexed`
  wrapper: ~60 LoC change + tests adjusted, 2 hours.
- `AnomalyKind::CorrelationTableEvictionPressure` variant +
  metric label + tracing field: ~30 LoC, 1 hour.
- Doc updates (`docs/recipes.md`, `docs/concepts.md` note): ~80
  lines, 2 hours.
- Criterion benches under `benches/correlate.rs`: ~200 LoC,
  2 hours.
- **Implementation total:** ~20 hours, ~840 LoC. Two to three
  days focused.

## Provenance

Originated from the `netring` round-2 retrospective (item F6)
where the author identified this as the single biggest enabler
for their anomaly-correlation roadmap and offered to draft the
RFC. This plan documents what flowscope expects from the final
RFC — it's a contract for the joint authorship rather than a
finished design.

Target landing for the RFC document: 0.7.0. Target landing
for the implementation: 0.8.0, contingent on reviewer
agreement on the design questions above.
