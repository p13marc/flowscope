# Plan 42 — Reassembly observability (0.2.0 bundle)

## Summary

Three coupled features delivered as one minor release (0.2.0):

1. **Per-side buffer cap** on `BufferedReassembler`, with a chosen
   `OverflowPolicy` (sliding window vs. drop-flow). Caps memory for
   stuck/adversarial flows.
2. **Reassembly diagnostics in `FlowStats`** — per-side OOO drops and
   over-cap byte drops surface on `FlowEvent::Ended`.
3. **Live `FlowEvent::Anomaly` variant** — opt-in inline emission for
   buffer overflow, OOO segments, and flow-table eviction pressure.

These three were originally drafted as plans 42, 43, 44. They share a
breaking-change window (`#[non_exhaustive]` on `FlowStats` /
`FlowTrackerConfig`, and `FlowEvent::key() -> Option<&K>`), so we ship
them together to absorb that churn once.

The motivating consumer is `tools/des-test-harness` /
`tools/des-capture` from <https://github.com/p13marc/des-rs>: those
tools currently hand-roll a `TcpStreamTracker` with 1 MB / 60 s caps
because flowscope can't bound reassembler memory or surface drop
counters. After 0.2.0 they can drop their custom tracker entirely.

## Status

Not started. Targets the next minor release (0.2.0).

## Prerequisites

- Plan 03 (Reassembler) — shipped.
- Plan 31 (SessionParser) — shipped (so anomaly events flow through
  `SessionEvent`).

## Out of scope

- Per-message buffer caps inside shipped `SessionParser`s
  (HTTP/TLS/DNS). Those parsers manage their own buffers; this plan
  only touches the generic `BufferedReassembler`.
- Anomaly-driven `metrics::counter!` integration. That's Plan 40
  (observability). Plan 42 ships the *event* stream; Plan 40 layers
  the metrics façade on top of the same `AnomalyKind` vocabulary.
- Cross-`netring`-adapter changes beyond what the new `FlowEvent`
  variant naturally requires. The async adapters propagate
  `FlowEvent` verbatim; they pick up `Anomaly` for free.
- A bundled `BufferStats` type that groups OOO + over-cap counters.
  Stick to the flat field naming that mirrors existing
  `packets_initiator` / `packets_responder` pairs.
- IPv6-fragment reassembly counters. Plan 50.5 territory.

---

## Section 1 — Buffer cap + `OverflowPolicy`

### Why both policies

The original Plan 42 draft chose **sliding window only** ("drop oldest
bytes"). That's wrong for framed binary protocols (DES PSMSG, TLS
records, length-prefixed wire formats) — once you drop bytes mid-frame
the parser is desynced and may never resync. For those consumers the
correct behaviour is to **tear the flow down** and let upstream
reconnect.

Both policies are equally cheap. Ship both, default to `SlidingWindow`
(matches the original draft's behaviour and is the safer choice for
unframed text protocols like HTTP body streams).

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Drop oldest bytes from the front of the buffer until the new
    /// payload fits. The flow stays alive; the parser sees a gap and
    /// must resync. `bytes_dropped_oversize` is incremented by the
    /// number of bytes rotated out.
    SlidingWindow,
    /// Mark the reassembler as poisoned and signal end-of-flow on the
    /// next driver tick via `EndReason::BufferOverflow`. Subsequent
    /// segments are no-ops; the buffer is cleared.
    DropFlow,
}

impl Default for OverflowPolicy {
    fn default() -> Self { OverflowPolicy::SlidingWindow }
}
```

`EndReason` gains a new variant:

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Fin,
    Rst,
    IdleTimeout,
    Evicted,
    /// New in 0.2.0. Reassembler hit its cap with policy
    /// `OverflowPolicy::DropFlow`. The driver synthesises an `Ended`
    /// event for the next tick after the cap is breached.
    BufferOverflow,
}
```

### `BufferedReassembler` API

```rust
#[derive(Debug, Default)]
pub struct BufferedReassembler {
    buffer: Vec<u8>,
    expected_seq: Option<u32>,
    dropped_segments: u64,
    bytes_dropped_oversize: u64,           // new in 0.2.0
    max_buffer: Option<usize>,             // new in 0.2.0
    overflow_policy: OverflowPolicy,       // new in 0.2.0
    poisoned: bool,                        // new in 0.2.0 (DropFlow)
}

impl BufferedReassembler {
    pub fn new() -> Self { Self::default() }

    /// Set a maximum in-flight buffer size in bytes. Default policy
    /// is [`OverflowPolicy::SlidingWindow`].
    pub fn with_max_buffer(mut self, max_bytes: usize) -> Self {
        self.max_buffer = Some(max_bytes);
        self
    }

    /// Override the overflow policy. Has no effect unless
    /// [`with_max_buffer`] is also called.
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }

    pub fn bytes_dropped_oversize(&self) -> u64 { self.bytes_dropped_oversize }
    pub fn dropped_segments(&self) -> u64 { self.dropped_segments }

    /// True after a `DropFlow` overflow. The driver checks this once
    /// per tick; `true` triggers an `Ended { reason: BufferOverflow }`
    /// event for the flow.
    pub fn is_poisoned(&self) -> bool { self.poisoned }
}
```

### Sliding-window vs drop-flow semantics

```rust
fn append_with_cap(&mut self, payload: &[u8]) {
    let Some(cap) = self.max_buffer else {
        self.buffer.extend_from_slice(payload);
        return;
    };
    if self.poisoned { return; }
    let projected = self.buffer.len() + payload.len();
    if projected <= cap {
        self.buffer.extend_from_slice(payload);
        return;
    }
    match self.overflow_policy {
        OverflowPolicy::DropFlow => {
            self.bytes_dropped_oversize += payload.len() as u64;
            self.buffer.clear();
            self.poisoned = true;
        }
        OverflowPolicy::SlidingWindow => {
            let to_drop = projected - cap;
            if to_drop >= self.buffer.len() {
                self.bytes_dropped_oversize += self.buffer.len() as u64;
                self.buffer.clear();
                if payload.len() > cap {
                    let extra = payload.len() - cap;
                    self.bytes_dropped_oversize += extra as u64;
                    self.buffer.extend_from_slice(&payload[extra..]);
                } else {
                    self.buffer.extend_from_slice(payload);
                }
            } else {
                self.bytes_dropped_oversize += to_drop as u64;
                self.buffer.drain(..to_drop);
                self.buffer.extend_from_slice(payload);
            }
        }
    }
}
```

### `BufferedReassemblerFactory`

```rust
#[derive(Debug, Default)]
pub struct BufferedReassemblerFactory {
    max_buffer: Option<usize>,
    overflow_policy: OverflowPolicy,
}

impl BufferedReassemblerFactory {
    pub fn with_max_buffer(mut self, max_bytes: usize) -> Self {
        self.max_buffer = Some(max_bytes);
        self
    }
    pub fn with_overflow_policy(mut self, policy: OverflowPolicy) -> Self {
        self.overflow_policy = policy;
        self
    }
}

impl<K: Send + 'static> ReassemblerFactory<K> for BufferedReassemblerFactory {
    type Reassembler = BufferedReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide) -> BufferedReassembler {
        let mut r = BufferedReassembler::new();
        if let Some(m) = self.max_buffer {
            r = r.with_max_buffer(m).with_overflow_policy(self.overflow_policy);
        }
        r
    }
}
```

### `FlowTrackerConfig`

```rust
#[non_exhaustive]
pub struct FlowTrackerConfig {
    pub idle_timeout_tcp: Duration,
    pub idle_timeout_udp: Duration,
    pub idle_timeout_other: Duration,
    pub max_flows: usize,
    pub initial_capacity: usize,
    pub sweep_interval: Duration,
    /// New in 0.2.0. Hint to the default `BufferedReassemblerFactory`
    /// when used via `FlowDriver::buffered`. Custom factories must
    /// honour this themselves; the tracker doesn't own reassemblers.
    pub max_reassembler_buffer: Option<usize>,
    /// New in 0.2.0. Companion to `max_reassembler_buffer`.
    pub overflow_policy: OverflowPolicy,
}
```

`#[non_exhaustive]` lands here in 0.2.0 (one-time minor break — see
"Migration" below). All future `FlowTrackerConfig` fields are
purely additive.

---

## Section 2 — Diagnostics in `FlowStats`

### `Reassembler` trait additions

```rust
pub trait Reassembler: Send + 'static {
    fn segment(&mut self, seq: u32, payload: &[u8]);
    fn fin(&mut self) {}
    fn rst(&mut self) {}

    /// Number of TCP segments dropped because they arrived out of
    /// order for this side. Default: 0.
    fn dropped_segments(&self) -> u64 { 0 }

    /// Number of payload bytes dropped because the per-side buffer
    /// cap was exceeded. Default: 0.
    fn bytes_dropped_oversize(&self) -> u64 { 0 }
}
```

`BufferedReassembler` overrides both. Existing inherent accessors
are kept for backwards compatibility but documented as forwarding to
the trait method.

### `FlowStats`

```rust
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FlowStats {
    pub packets_initiator: u64,
    pub packets_responder: u64,
    pub bytes_initiator: u64,
    pub bytes_responder: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
    /// New in 0.2.0. Per-side reassembly diagnostics, populated by
    /// `FlowDriver` when the flow ends. Zero when no driver is in
    /// play (i.e. the consumer used `FlowTracker` directly).
    pub reassembly_dropped_ooo_initiator: u64,
    pub reassembly_dropped_ooo_responder: u64,
    pub reassembly_bytes_dropped_oversize_initiator: u64,
    pub reassembly_bytes_dropped_oversize_responder: u64,
}
```

`#[non_exhaustive]` for the same one-time-break reason. Construct
via `FlowStats::default()` everywhere.

### Wiring in `FlowDriver`

The current driver `track`/`sweep` end-of-flow loop (`src/driver.rs`)
is `for ev in &events`; widen to `for ev in &mut events` and patch
the diagnostics into `Ended { stats, .. }` before calling `r.fin()`
/ `r.rst()`:

```rust
for ev in &mut events {
    if let FlowEvent::Ended { key, reason, stats, .. } = ev {
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            let Some(mut r) = reassemblers.remove(&(key.clone(), side)) else { continue; };
            let dropped = r.dropped_segments();
            let oversize = r.bytes_dropped_oversize();
            match side {
                FlowSide::Initiator => {
                    stats.reassembly_dropped_ooo_initiator = dropped;
                    stats.reassembly_bytes_dropped_oversize_initiator = oversize;
                }
                FlowSide::Responder => {
                    stats.reassembly_dropped_ooo_responder = dropped;
                    stats.reassembly_bytes_dropped_oversize_responder = oversize;
                }
            }
            match reason {
                EndReason::Fin | EndReason::IdleTimeout => r.fin(),
                EndReason::Rst | EndReason::Evicted | EndReason::BufferOverflow => r.rst(),
            }
        }
    }
}
```

### `BufferOverflow` end-of-flow synthesis

After per-segment processing, the driver checks `r.is_poisoned()`
for every reassembler and synthesises an `Ended { reason:
BufferOverflow }` event for any poisoned flow. The synthesis happens
**before** the diagnostics-patch loop above, so the same loop fills
in stats for the synthesised event.

```rust
let mut to_terminate = Vec::new();
for ((key, _side), r) in &reassemblers {
    if r.is_poisoned() && !already_ending.contains(key) {
        to_terminate.push(key.clone());
    }
}
for key in to_terminate {
    let stats = self.tracker.snapshot_stats(&key).unwrap_or_default();
    events.push(FlowEvent::Ended {
        key,
        reason: EndReason::BufferOverflow,
        stats,
        history: /* current history string */,
    });
    // Tracker forgets the entry separately so subsequent packets
    // start a fresh flow.
    self.tracker.forget(&key);
}
```

Requires a small `FlowTracker` API addition: `snapshot_stats(&K) ->
Option<FlowStats>` and `forget(&K) -> bool`. Both are thin wrappers
over the existing `LruCache`.

### `SessionEvent::Closed`

`SessionEvent::Closed { stats }` already carries `FlowStats` whole
(verified — netring's `session_stream.rs` propagates the struct, no
manual field copy). The new fields surface there for free.

---

## Section 3 — Live `FlowEvent::Anomaly`

### API

```rust
#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    Started { /* ... */ },
    Packet { /* ... */ },
    Established { /* ... */ },
    StateChange { /* ... */ },
    Ended { /* ... */ },
    /// New in 0.2.0. Live, in-flight anomaly. Flow is still alive
    /// (use `Ended` for end-of-life events).
    Anomaly {
        key: Option<K>,                // None for tracker-global anomalies
        kind: AnomalyKind,
        ts: Timestamp,
    },
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// Reassembler dropped bytes from the buffer because the
    /// per-side cap was hit. `bytes` is the count dropped during
    /// this tick (not running total — see `FlowStats` for that).
    BufferOverflow {
        side: FlowSide,
        bytes: u64,
        policy: OverflowPolicy,
    },
    /// Reassembler dropped one or more out-of-order segments during
    /// this tick. Coalesced — at most one anomaly per (flow, side)
    /// per tick, with `count` summing the drops in that tick.
    OutOfOrderSegment {
        side: FlowSide,
        count: u64,
    },
    /// Tracker hit `max_flows` and evicted at least one LRU flow
    /// during this tick. The evicted flow's own `Ended { reason:
    /// Evicted }` is still emitted; this anomaly is the system-level
    /// signal that capacity is the bottleneck.
    FlowTableEvictionPressure {
        evicted_in_tick: u64,
        evicted_total: u64,
    },
}
```

### `FlowEvent::key()` — clean break

Today `key() -> &K`. Pre-1.0; small consumer set (netring's
adapters + tests). Change to `key() -> Option<&K>` in this release;
update netring + workspace tests in the same PR series. CHANGELOG
flags it.

```rust
impl<K> FlowEvent<K> {
    pub fn key(&self) -> Option<&K> {
        match self {
            FlowEvent::Started { key, .. }
            | FlowEvent::Packet { key, .. }
            | FlowEvent::Established { key, .. }
            | FlowEvent::StateChange { key, .. }
            | FlowEvent::Ended { key, .. } => Some(key),
            FlowEvent::Anomaly { key, .. } => key.as_ref(),
        }
    }
}
```

### Emission

Opt-in via `FlowDriver::with_emit_anomalies(true)`. Default `false`
— existing consumers see no behaviour change.

```rust
impl<E, F, S> FlowDriver<E, F, S> { /* ... */
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }
}
```

### Per-tick coalescing

A pathological flow can drop hundreds of OOO segments in one
`track()` call. Emitting one anomaly per drop swamps the stream.
Coalesce within a tick:

1. **Snapshot** each reassembler's `dropped_segments()` /
   `bytes_dropped_oversize()` once at the start of `track()`.
2. **Re-snapshot** at the end.
3. If a delta is non-zero, emit **one** anomaly per (flow, side, kind)
   for the tick, with `count` / `bytes` summing the per-tick deltas.

This is simpler and cheaper than per-segment hooks, and gives users
a single signal per tick they can throttle further if needed.

### Eviction-pressure detection

Read `tracker.stats().flows_evicted` before and after each tracker
call. Delta > 0 → emit one `Anomaly { key: None, kind:
FlowTableEvictionPressure { evicted_in_tick: delta, evicted_total } }`.
The displaced flow's own `Ended { reason: Evicted }` event is
emitted by the tracker as today.

> The original Plan 44 draft assumed `FlowTracker::evicted_total()`
> exists. It doesn't — `flows_evicted` lives in `FlowTrackerStats`
> and is reachable via `tracker.stats().flows_evicted` (verified at
> `src/tracker.rs:83, 379`). No new tracker accessor needed.

---

## Section 4 — Migration (0.2.0 break)

This release introduces three breaking changes, all small and easy
to migrate:

| Break | Where | Migration |
|-------|-------|-----------|
| `#[non_exhaustive]` on `FlowStats` | `src/event.rs` | Construct via `FlowStats::default()` and mutate (already the canonical pattern; tracker uses it). Code that writes `FlowStats { ... }` literally must switch. |
| `#[non_exhaustive]` on `FlowTrackerConfig` | `src/tracker.rs` | Same — `FlowTrackerConfig::default()` + field mutation. Existing code already does this. |
| `FlowEvent::key() -> Option<&K>` | `src/event.rs` | Wrap call sites in `?` or `.expect("non-anomaly event")` for hot paths that don't subscribe to anomalies. |

CLAUDE.md and `docs/SESSION_GUIDE.md` are updated with the migration
recipe.

**Project convention** (recorded in INDEX.md): every public struct
in the public API gets `#[non_exhaustive]` from now on. Future
additions are unconditionally additive.

---

## Files

### MODIFIED

- `src/reassembler.rs` — `OverflowPolicy`, `max_buffer` /
  `overflow_policy` / `poisoned` fields, `is_poisoned()`,
  `with_overflow_policy()`, `bytes_dropped_oversize()`, factory caps,
  trait method overrides.
- `src/event.rs` — `FlowStats` non_exhaustive + 4 new fields,
  `FlowEvent::Anomaly` variant, `AnomalyKind` enum, `EndReason::BufferOverflow`,
  `FlowEvent::key() -> Option<&K>`.
- `src/tracker.rs` — `FlowTrackerConfig` non_exhaustive +
  `max_reassembler_buffer` + `overflow_policy`, `snapshot_stats(&K)`
  and `forget(&K)` accessors.
- `src/driver.rs` — diagnostics-patch loop, BufferOverflow
  synthesis, `with_emit_anomalies()`, anomaly snapshot/diff
  logic.
- `CHANGELOG.md` — 0.2.0 entry covering all three changes.
- `docs/SESSION_GUIDE.md` — new "Reassembly health" + "Recovery
  after buffer cap" + "Anomaly events" subsections.
- `Cargo.toml` — bump version to 0.2.0.

### NEW

None.

---

## Implementation order

Land in three commits inside one PR series:

1. **Buffer cap + `OverflowPolicy`** (Section 1). Behaviour-preserving
   when no cap is set; existing tests pass without modification.
2. **Diagnostics in `FlowStats`** (Section 2). Adds the four fields,
   wires the driver patch loop, adds `non_exhaustive` to `FlowStats`
   and `FlowTrackerConfig`. This is the breaking-change commit.
3. **Live anomaly events** (Section 3). Adds `FlowEvent::Anomaly`,
   `AnomalyKind`, `EndReason::BufferOverflow`, anomaly emission, and
   the `FlowEvent::key()` signature change.

The split keeps each commit independently reviewable and lets us
roll back any one piece if integration testing catches something.

---

## Tests

### Reassembler unit tests (additions)

```rust
#[test]
fn cap_unbounded_by_default() { /* ... */ }

#[test]
fn cap_drops_oldest_on_overflow_sliding_window() {
    let mut r = BufferedReassembler::new().with_max_buffer(100);
    r.segment(0, &vec![b'a'; 80]);
    r.segment(80, &vec![b'b'; 80]);
    assert_eq!(r.buffered_len(), 100);
    assert_eq!(r.bytes_dropped_oversize(), 60);
    let drained = r.take();
    assert_eq!(&drained[..20], &vec![b'a'; 20][..]);
    assert_eq!(&drained[20..], &vec![b'b'; 80][..]);
}

#[test]
fn cap_poisons_on_overflow_drop_flow() {
    let mut r = BufferedReassembler::new()
        .with_max_buffer(100)
        .with_overflow_policy(OverflowPolicy::DropFlow);
    r.segment(0, &vec![b'a'; 80]);
    r.segment(80, &vec![b'b'; 80]);
    assert!(r.is_poisoned());
    assert_eq!(r.bytes_dropped_oversize(), 80);
    assert_eq!(r.buffered_len(), 0);
    // Subsequent segments are no-ops.
    r.segment(160, &vec![b'c'; 10]);
    assert_eq!(r.buffered_len(), 0);
}

#[test]
fn cap_payload_bigger_than_cap_keeps_tail() { /* ... */ }
#[test]
fn cap_skips_ooo_segments_without_changing_overflow_counter() { /* ... */ }
#[test]
fn cap_take_resets_buffer_but_not_counters() { /* ... */ }
```

### Driver integration tests

```rust
#[test]
fn ended_event_carries_reassembly_diagnostics() {
    // Drive a flow with two OOO initiator segments + FIN.
    // Expect Ended.stats.reassembly_dropped_ooo_initiator == 2.
}

#[test]
fn ended_event_with_buffer_overflow_reason() {
    // Configure DropFlow + 64-byte cap, push 80 bytes initiator.
    // Expect FlowEvent::Ended { reason: BufferOverflow, .. }.
}

#[test]
fn anomaly_event_emitted_for_buffer_overflow() {
    // emit_anomalies(true) + 64-byte cap + SlidingWindow.
    // Push 80 bytes — expect one Anomaly { kind: BufferOverflow { bytes: 16, .. }, .. }.
}

#[test]
fn anomaly_event_coalesces_ooo_per_tick() {
    // 5 OOO segments in one track() call — expect one anomaly with count=5.
}

#[test]
fn anomaly_event_emitted_on_table_eviction() {
    // max_flows=2; create 3 flows in one tick — expect one
    // FlowTableEvictionPressure anomaly with evicted_in_tick=1, evicted_total=1.
}

#[test]
fn no_anomaly_events_when_flag_off() { /* ... */ }
```

### Proptest invariants

In `tests/proptest_invariants.rs`:

```rust
proptest! {
    #[test]
    fn buffered_reassembler_byte_conservation(
        cap in 16usize..1024,
        payloads in proptest::collection::vec(any::<Vec<u8>>(), 0..32),
    ) {
        let mut r = BufferedReassembler::new().with_max_buffer(cap);
        let total: usize = payloads.iter().map(|p| p.len()).sum();
        let mut seq = 0u32;
        for p in &payloads {
            r.segment(seq, p);
            seq = seq.wrapping_add(p.len() as u32);
        }
        prop_assert!(r.buffered_len() <= cap);
        prop_assert_eq!(r.buffered_len() as u64 + r.bytes_dropped_oversize(), total as u64);
    }
}
```

### Doctests

In `BufferedReassembler::with_max_buffer`:

```rust
/// ```
/// use flowscope::{Reassembler, BufferedReassembler};
/// let mut r = BufferedReassembler::new().with_max_buffer(10);
/// r.segment(0, b"helloworld!");
/// assert_eq!(r.bytes_dropped_oversize(), 1);
/// assert_eq!(r.take(), b"elloworld!");
/// ```
```

---

## Acceptance criteria

- [ ] `BufferedReassembler::with_max_buffer` /
      `with_overflow_policy` ship with both `SlidingWindow` and
      `DropFlow` semantics.
- [ ] `BufferedReassemblerFactory::with_max_buffer` /
      `with_overflow_policy` propagate the cap.
- [ ] `FlowTrackerConfig` is `#[non_exhaustive]` and gains the two
      new fields.
- [ ] `FlowStats` is `#[non_exhaustive]` and gains four reassembly
      diagnostic fields.
- [ ] `Reassembler::dropped_segments` and `bytes_dropped_oversize`
      are trait methods with default-zero impls.
- [ ] `EndReason::BufferOverflow` exists; driver synthesises an
      `Ended` event when a `DropFlow`-policy reassembler is poisoned.
- [ ] `FlowEvent::Anomaly` variant + `AnomalyKind` enum (non_exhaustive)
      exist.
- [ ] `FlowDriver::with_emit_anomalies(bool)` builder; default `false`.
- [ ] OOO and BufferOverflow anomalies coalesce per (flow, side, kind)
      per tick.
- [ ] Eviction-pressure anomaly fires once per tick where evictions
      occurred, with `evicted_in_tick` and `evicted_total`.
- [ ] `FlowEvent::key()` returns `Option<&K>`.
- [ ] netring's async adapters compile against the new shape; no
      manual field copies hide the new `FlowStats` fields.
- [ ] CHANGELOG entry describes all three breaking changes plus the
      migration.
- [ ] SESSION_GUIDE.md links from "Custom protocols" and "Async
      streams" to the new "Reassembly health" / "Recovery after
      buffer cap" / "Anomaly events" sections.
- [ ] `cargo test --all-features` passes.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.
- [ ] `cargo doc --all-features --no-deps` zero warnings.

---

## Risks

1. **`OverflowPolicy::SlidingWindow` breaks parsers mid-message.**
   Documented loudly. Recommend `DropFlow` for framed binary
   protocols (DES, TLS records, length-prefixed wire formats); use
   `SlidingWindow` for stream-shaped / append-only protocols where
   resync after a gap is well-defined.
2. **Anomaly volume.** Even with per-tick coalescing, a long pcap
   replay on a chronically lossy link emits one OOO anomaly per
   tick. Document the `with_emit_anomalies(false)` default and
   point users to Plan 40 (metrics) for production aggregation.
3. **`FlowEvent::key()` signature change.** Pre-1.0 break, audited.
   netring is the only known external consumer; we update both in
   the same PR series.
4. **`FlowTracker::snapshot_stats` / `forget` are new API surface.**
   Minimal: thin wrappers on the existing `LruCache`. Document.
5. **BufferOverflow synthesis can race a tracker `Ended`.** If a
   flow naturally FINs in the same tick that overflows, we deduplicate
   by checking whether the tracker has already emitted `Ended` for
   the key; the driver's `to_terminate` list excludes any key with a
   pre-existing `Ended` event in the same tick.
6. **Counter saturation.** `u64` fields don't realistically wrap, but
   document them as monotonic for the lifetime of the
   reassembler / tracker instance.
7. **Existing `dropped_segments()` inherent method on `BufferedReassembler`**
   is kept as a thin forwarder to the new trait method to avoid
   breaking existing callers. Mark with `#[doc(hidden)]` on the
   inherent and document the trait method as canonical.
8. **Plan 40 (observability) coordination.** The same `AnomalyKind`
   names should appear as `metrics::counter!` labels when Plan 40
   lands, so consumers see one vocabulary. Coordinate during 40's
   implementation; cross-reference in `docs/OBSERVABILITY.md`.

---

## Effort

- LOC: ~400 (Section 1: ~140, Section 2: ~80, Section 3: ~180).
- Tests: ~350 LOC.
- Time: 2.5 days (1 day Section 1, 0.5 day Section 2, 1 day Section 3
  including netring + workspace audit for the `key()` signature change).

---

## Provenance

This plan supersedes the original drafts:
- `42-reassembler-bounds.md` (sliding-window cap only)
- `43-reassembler-diagnostics.md` (FlowStats fields)
- `44-flow-anomaly-events.md` (live anomaly variant)

Those three were drafted independently before the bundling decision
was made. They share a breaking-change window and a target consumer
(`des-rs`); shipping them together absorbs the churn once.
