# Plan 154 — `FlowStateMap<T, K>`: per-flow typed state

> **Simplified from the wishlist.** Originally proposed as two
> hashmaps + bespoke sweep logic (~200 LoC). Layering over the
> existing `KeyIndexed<K, T>` cuts it to ~80 LoC and reuses the
> TTL + LRU machinery already shipped in `flowscope::correlate`.

## Summary

`FlowStateMap<T, K>` provides per-flow user-typed state with:
- Lazy `Default` construction on first access for a key.
- Auto-evict on `FlowEvent::Ended` (driven by `feed(&FlowEvent<K>)`).
- TTL sweep matching `FlowTrackerConfig::idle_timeout`.

Layered over `KeyIndexed<K, T>` — the heavy lifting (HashMap +
LRU + per-key timestamp) is already implemented and shipped.

## Status

Not started. P2 for 0.13.

## Prerequisites

- `KeyIndexed::new_unbounded` (shipped 0.12.0).
- `KeyIndexed::peek` (shipped 0.10.0).

## Out of scope

- **Cross-process state replication.** In-memory only.
- **Persistence.** Consumer snapshots externally if `T: Serialize`.
- **`T: !Default` slots.** `Default` is required for lazy
  creation. Consumers needing manual construction can use
  `KeyIndexed<K, T>` directly.
- **Tracker integration.** `FlowStateMap` is a sibling utility;
  the tracker doesn't drive it. Consumers explicitly `feed` the
  events.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/correlate/flow_state_map.rs` | `FlowStateMap<T, K>` |
| Modify | `src/correlate/mod.rs` | `pub use flow_state_map::FlowStateMap;` |
| Modify | `src/prelude.rs` | optional re-export |
| New | `tests/flow_state_map.rs` | Unit tests |
| Modify | `docs/recipes.md` | "Per-flow state" recipe |

## API

```rust
// src/correlate/flow_state_map.rs
use std::hash::Hash;
use std::time::Duration;
use crate::correlate::KeyIndexed;
use crate::event::FlowEvent;
use crate::Timestamp;

/// Per-flow typed state, keyed by `FiveTupleKey` (default) or
/// any `K: Hash + Eq + Clone`.
///
/// Each slot stores a `T: Default`. Lifecycle:
/// - First access via `get_or_default(&key)` lazily constructs
///   `T::default()`.
/// - `feed(&FlowEvent<K>)` updates `last_seen` for any event
///   carrying the key; `Ended` evicts the slot.
/// - `sweep(now)` removes entries with `last_seen + idle_timeout
///   < now`.
///
/// Backed by `KeyIndexed<K, T>` — TTL and LRU are shared
/// machinery with the rest of `flowscope::correlate`.
pub struct FlowStateMap<T, K = crate::extract::FiveTupleKey>
where
    K: Hash + Eq + Clone,
    T: Default,
{
    inner: KeyIndexed<K, T>,
}

impl<T, K> FlowStateMap<T, K>
where
    K: Hash + Eq + Clone,
    T: Default,
{
    /// New empty map. `idle_timeout` should match the
    /// consumer's `FlowTrackerConfig::idle_timeout` by
    /// convention.
    pub fn new(idle_timeout: Duration) -> Self {
        Self { inner: KeyIndexed::new_unbounded(idle_timeout) }
    }

    /// Lazy access. If `key` is new, inserts `T::default()` and
    /// returns `&mut` to the new slot. If existing, updates
    /// `last_seen` to `now` and returns `&mut` to the slot.
    pub fn get_or_default(&mut self, key: &K, now: Timestamp) -> &mut T { … }

    /// Read-only lookup. Does NOT bump `last_seen` — pure peek.
    pub fn get(&self, key: &K) -> Option<&T> { … }

    /// Drive the lifecycle. Inspects each event:
    /// - `FlowEvent::Ended { key, .. }` → evict the slot.
    /// - Any other variant carrying a key → bump `last_seen`.
    /// - Variants without a key (e.g. `TrackerAnomaly`) → no-op.
    pub fn feed(&mut self, event: &FlowEvent<K>) { … }

    /// Drop entries with `last_seen + idle_timeout < now`.
    /// Consumer drives from their tick handler (typically once
    /// per second).
    pub fn sweep(&mut self, now: Timestamp) {
        self.inner.evict_expired(now);
    }

    /// Active entry count.
    pub fn len(&self) -> usize { self.inner.len() }

    /// True if no entries are active.
    pub fn is_empty(&self) -> bool { self.inner.is_empty() }

    /// Iterate active entries.
    pub fn iter(&self) -> impl Iterator<Item = (&K, &T)> { self.inner.iter() }
}
```

(Methods on `KeyIndexed` that don't exist today but are simple
to add — `len`, `is_empty`, `iter`, the `get_or_default` shape
— are included in this PR's scope. `KeyIndexed` already has
`evict_expired`.)

## Implementation steps

1. Write `FlowStateMap<T, K>` as a thin wrapper.
2. Add the missing `KeyIndexed` accessors (`len`, `is_empty`,
   `iter`) if not already present — small additive cleanup.
3. `feed` matches on `FlowEvent` variants; bumps `last_seen` on
   keyed variants, evicts on `Ended`.
4. Tests + a documentation example.

## Tests

- `flow_state_map_lazy_creates_on_get_or_default`.
- `flow_state_map_get_does_not_bump_last_seen`.
- `flow_state_map_feed_ended_evicts_entry`.
- `flow_state_map_feed_packet_bumps_last_seen`.
- `flow_state_map_sweep_evicts_idle`.
- `flow_state_map_default_key_type_is_fivetuplekey`.
- `flow_state_map_works_with_custom_key_type`.

## Acceptance criteria

- `cargo test --all-features` clean.
- netring 0.21 §2.12 (`ctx.flow_state_mut::<T>()`) wraps
  `FlowStateMap<T, FiveTupleKey>` as a thin context accessor.

## Risks

**R1: Memory growth between Ended events.** Long-lived flows
accumulate state. Mitigation: `sweep` is documented and
consumer-driven.

**R2: `T: Default` requirement.** A `with_init(fn(&K) -> T)`
constructor would let consumers initialise without Default.
Mitigation: defer; ship the Default variant first. The
constructor can be added additively when a consumer asks.

## Effort

- LOC delta: +120 (wrapper + tests + docs; KeyIndexed accessors
  add +30).
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 154 / D1 from the previous wishlist. Simplified
via the KeyIndexed-foundation observation.
