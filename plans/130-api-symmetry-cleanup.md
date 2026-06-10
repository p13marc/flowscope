# Plan 130 — API symmetry + trait shape cleanup

## Summary

Five small breaks bundled into one plan because they all touch
the same surface area (the public trait shape). Pre-1.0 cleanup
of debt surfaced by the 0.12 audit:

1. Split `AnomalyFields` into two traits: `KeyFields` (5-tuple
   accessors) and `AnomalyFields` (anomaly classification).
   Current single trait is a layering smell — `anomaly_type` /
   `anomaly_event` are properties of `AnomalyKind`, not of a
   flow key.
2. Make every `flowscope::emit` writer generic over
   `K: KeyFields`. `EveJsonWriter` already is; CSV / NDJSON /
   Zeek are hardcoded to `FiveTupleKey`. Asymmetric.
3. Redesign `Event::FlowPacket.tcp: Option<TcpInfo>` — the
   field is `None` by default and only populated when
   `DriverBuilder::emit_packet_details(true)`. Public field
   silently driven by a hidden config flip is a footgun.
4. Make `Timestamp` ↔ `chrono::DateTime<Utc>` interop
   symmetric. Today: `From<DateTime>` and `TryFrom<Timestamp>`
   with an error case that "can never trigger" in practice.
5. Builder-method bound parity between `DriverBuilder<E>` and
   `DeferredDriverBuilder<E>`. The latter requires
   `P::Message: Send` on every registration; the former
   doesn't. Trap.

Plus folding in the Phase 7 leftovers caught by the post-0.12
audit:

6. Add `BurstDetector::new_unbounded` and `TopK::new_unbounded`
   (wishlist named 5 ctors; 0.12 shipped 3).

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **No new emit writers.** Plan 141 (IPFIX) and any future
  Parquet/OpenTelemetry writer are orthogonal.
- **No `KeyFields` trait method changes** beyond the split.
  `src_ip` / `dest_ip` / etc. stay as-is.
- **No `AnomalyKind` variant changes.** Trait method moves are
  mechanical.
- **Driver internals stay single-threaded.** `Driver<E>` itself
  remains `!Send` (central `FlowTracker` holds `Rc<RefCell>`).

## Pre-1.0 breaks

- **`flowscope::AnomalyFields`** loses `src_ip` / `src_port` /
  `dest_ip` / `dest_port` / `proto_str` / `app_proto_str` —
  those move to `flowscope::KeyFields`. Users that imported
  `AnomalyFields` for the key accessors need to add
  `use flowscope::KeyFields;`. Mechanical.
- **`FlowEventCsvWriter::write_event<K>`** /
  **`FlowEventNdjsonWriter::write_event<K>`** /
  **`ZeekConnLogWriter::write_event<K>`** become generic over
  `K: KeyFields`. Callers using `FiveTupleKey` are unaffected
  (it impls `KeyFields`).
- **`Event::FlowPacket.tcp`** field deleted. Replaced by
  `Event::FlowPacket::tcp(&self) -> Option<&TcpInfo>` accessor
  that returns the value from a side-channel populated when
  `emit_packet_details(true)` is set. Callers `match` on the
  variant; if they were reading the field, they call the
  method now. `match e { FlowPacket { key, side, len, ts, tcp,
  .. } => …}` → `match e { FlowPacket { key, side, len, ts, .. }
  => … e.tcp() }`. The `..` already covers `non_exhaustive`.
- **`TryFrom<Timestamp> for chrono::DateTime<Utc>`** becomes
  `From<Timestamp> for chrono::DateTime<Utc>` with **saturating
  clamp** to chrono's range. The `ChronoOutOfRange` error type
  is deleted. Saturating semantics: `Timestamp::sec` u32 fits
  inside chrono's `i64`-seconds range with room to spare
  (u32::MAX ≈ 2106; chrono goes to year ±262_142), so the
  conversion is genuinely infallible. The prior `TryFrom`
  shape was theatre.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/anomaly_fields.rs` | Split into two traits; keep file name (logical home of both) |
| Modify | `src/extractor.rs` | `L4Proto` impls `KeyFields` (proto_str) only — moves out of `AnomalyFields` |
| Modify | `src/extract/five_tuple.rs` | `FiveTupleKey` impls `KeyFields`; `AnomalyFields` impl removed (no anomaly methods on a key) |
| Modify | `src/event.rs` | `AnomalyKind` impls `AnomalyFields` only (no key methods). `Event::FlowPacket::tcp` field → accessor. |
| Modify | `src/emit/csv.rs` | `FlowEventCsvWriter::write_event<K: KeyFields>` |
| Modify | `src/emit/ndjson.rs` | `FlowEventNdjsonWriter::write_event<K: KeyFields + Serialize>` |
| Modify | `src/emit/zeek.rs` | `ZeekConnLogWriter::write_event<K: KeyFields>` |
| Modify | `src/emit/eve.rs` | Two-trait constraint: `K: KeyFields` + `AnomalyKind: AnomalyFields` |
| Modify | `src/driver/typed.rs` | `DeferredDriverBuilder` registration methods drop the redundant `Send` bound (already on `SlotHandle`) |
| Modify | `src/driver/typed.rs` | `Event::FlowPacket` no longer has public `tcp` field; add `Event::tcp(&self) -> Option<&TcpInfo>` accessor + internal side-channel |
| Modify | `src/timestamp.rs` | `From<Timestamp> for chrono::DateTime<Utc>` (saturating); delete `ChronoOutOfRange` + `TryFrom` impl |
| Modify | `src/correlate/burst.rs` | `BurstDetector::new_unbounded(burst_kind, threshold, window, trigger_kind)` |
| Modify | `src/correlate/topk.rs` | `TopK::new_unbounded()` — `k = usize::MAX` |
| Modify | `src/prelude.rs` | Re-export `KeyFields` alongside `AnomalyFields` |
| Modify | `tests/anomaly_fields.rs` | Split assertions across the two traits |
| New | `tests/key_fields.rs` | `KeyFields` impls on `FiveTupleKey`, `L4Proto` |
| Modify | `tests/emit_csv.rs` | Custom-K test confirms generic writer |
| Modify | `tests/emit_eve.rs` | Update to two-trait shape |
| Modify | `CHANGELOG.md` | 0.12 entry with migration recipe |

## API

### `KeyFields` (new, primary trait for emit writers)

```rust
// src/anomaly_fields.rs

use std::net::IpAddr;

/// Structured-key accessor trait used by every
/// [`crate::emit`] writer. All methods default to `None`;
/// partial impls work fine for keys that carry only some of
/// these fields.
pub trait KeyFields {
    fn src_ip(&self)        -> Option<IpAddr>       { None }
    fn src_port(&self)      -> Option<u16>          { None }
    fn dest_ip(&self)       -> Option<IpAddr>       { None }
    fn dest_port(&self)     -> Option<u16>          { None }
    fn proto_str(&self)     -> Option<&'static str> { None }
    fn app_proto_str(&self) -> Option<&'static str> { None }
}

/// Anomaly-classification accessor trait, used by EVE / future
/// alert-shaped writers. Today implemented only on
/// [`crate::AnomalyKind`].
pub trait AnomalyFields {
    fn anomaly_type(&self)  -> Option<&'static str> { None }
    fn anomaly_event(&self) -> Option<&'static str> { None }
}
```

### `Event::FlowPacket` accessor (replaces public field)

```rust
// src/driver/typed.rs

#[non_exhaustive]
pub enum Event<K> {
    // … FlowStarted / FlowEstablished unchanged …
    FlowPacket {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        // `tcp` field deleted — public field driven by a hidden
        // config flip is a footgun. Use Event::tcp() instead.
    },
    // … rest unchanged …
}

impl<K> Event<K> {
    /// Per-packet TCP details, populated only on
    /// [`Self::FlowPacket`] events when
    /// [`DriverBuilder::emit_packet_details`] was called with
    /// `true`. Returns `None` for non-packet variants.
    pub fn tcp(&self) -> Option<&TcpInfo> { … }
}
```

Internal: store the per-packet `TcpInfo` in a parallel
`Vec<Option<TcpInfo>>` aligned to the event Vec, indexed at
construction time by the driver. Single-driver, single-thread
— no atomics needed. Plumbed through `track_into`.

### `From<Timestamp> for chrono::DateTime<Utc>` (symmetric)

```rust
// src/timestamp.rs (under #[cfg(feature = "chrono")])

impl From<Timestamp> for chrono::DateTime<chrono::Utc> {
    fn from(ts: Timestamp) -> Self {
        // Saturating clamp to chrono's representable range.
        // `Timestamp::sec: u32` is bounded by 0..=u32::MAX
        // (year 2106) which lies fully inside chrono's
        // year ±262 143 range — the conversion is infallible
        // in practice; the saturation is defence in depth.
        chrono::DateTime::<chrono::Utc>::from_timestamp(
            ts.sec as i64, ts.nsec
        ).unwrap_or(chrono::DateTime::<chrono::Utc>::MAX_UTC)
    }
}
```

The `TryFrom` impl + `ChronoOutOfRange` type are deleted.

### Correlate `new_unbounded` (Phase 7 leftovers)

```rust
// src/correlate/burst.rs

impl<K, E> BurstDetector<K, E>
where K: Hash + Eq + Clone, E: Hash + Eq + Clone
{
    /// Unbounded `max_keys` capacity. Equivalent to passing
    /// `usize::MAX`. Prefer the bounded ctor when memory
    /// pressure matters.
    pub fn new_unbounded(
        burst_kind: E,
        threshold: u32,
        window: Duration,
        trigger_kind: Option<E>,
    ) -> Self { Self::new(burst_kind, threshold, window, trigger_kind) }
    // ^ assuming `new` already capacity-less; if it grew a cap
    //   parameter in the interim, pass `usize::MAX` here.
}

// src/correlate/topk.rs

impl<K> TopK<K>
where K: Hash + Eq + Clone,
{
    /// Top-K with effectively unbounded `k` — every key seen
    /// is retained. Equivalent to `Self::new(usize::MAX)`.
    /// Useful for offline / bounded-input scenarios.
    pub fn new_unbounded() -> Self { Self::new(usize::MAX) }
}
```

## Implementation steps

1. **`KeyFields` introduction**: add the new trait beside the
   existing `AnomalyFields` in `src/anomaly_fields.rs`. Move
   `src_*` / `dest_*` / `proto_str` / `app_proto_str` defaults
   to `KeyFields`; keep `anomaly_type` / `anomaly_event` on
   `AnomalyFields`.
2. **Impl moves**: `impl KeyFields for FiveTupleKey`,
   `impl KeyFields for L4Proto`. Drop the `AnomalyFields` impls
   on keys.
3. **`AnomalyKind`**: keep `impl AnomalyFields for AnomalyKind`;
   no key methods to remove (it never had them).
4. **`prelude`**: re-export both traits.
5. **`Event::FlowPacket` redesign**: drop the public `tcp`
   field; add an `Event::tcp` accessor backed by a parallel
   `Vec<Option<TcpInfo>>` plumbed through `track_into`. The
   Vec is allocated once per `track_into` call (length-equal to
   the event Vec) and reused across calls; lookup is O(1).
6. **Emit writers**: parameterise `write_event` on
   `K: KeyFields`. CSV's column population uses the trait
   accessors; NDJSON requires `K: Serialize` too; Zeek same as
   CSV.
7. **`Timestamp` chrono symmetry**: delete `ChronoOutOfRange`;
   replace `TryFrom` with infallible `From`. Update the
   `chrono` cross-check test in `src/timestamp.rs`.
8. **DeferredDriverBuilder bound parity**: every registration
   method on `DeferredDriverBuilder<E>` carries
   `P::Message: Send + 'static`; `DriverBuilder<E>` carries
   only `P::Message: 'static`. Since the `SlotHandle<M, K>`
   bound now requires `M: Send + 'static`, both builders need
   the `Send` bound — apply it consistently to
   `DriverBuilder` too. The break is invisible: every shipped
   parser already meets `Send`.
9. **Correlate `new_unbounded`**: add ctors on `BurstDetector`
   and `TopK`. Existing tests untouched; new test per type.
10. **`tests/anomaly_fields.rs`**: split assertions. Half move
    to `tests/key_fields.rs`.
11. **`tests/emit_csv.rs`**: add a custom-`K` regression test
    proving the generic writer accepts a user-defined key.
12. **`tests/emit_eve.rs`**: replace `AnomalyFields` usages
    that touched key accessors with `KeyFields`.
13. **CHANGELOG**: migration recipe lines for each break.

## Tests

### Unit

- `src/anomaly_fields.rs::tests::default_methods_return_none`
- `src/correlate/burst.rs::tests::new_unbounded_matches_new_max`
- `src/correlate/topk.rs::tests::new_unbounded_matches_new_max`
- `src/timestamp.rs::tests::chrono_from_is_infallible_at_u32_max`

### Integration

- `tests/key_fields.rs::five_tuple_key_impls_key_fields`
- `tests/key_fields.rs::l4proto_impls_key_fields_proto_str_only`
- `tests/anomaly_fields.rs::anomaly_kind_classifies_per_eve_schema`
- `tests/emit_csv.rs::custom_key_writes_columns_via_key_fields`
- `tests/driver.rs::flow_packet_event_has_no_public_tcp_field`
  (compile-fail-style assertion via `match` not bound to `tcp`)
- `tests/driver.rs::event_tcp_accessor_populated_when_details_on`

## Acceptance criteria

- `cargo build --all-features` clean.
- `cargo test --all-features` clean — every existing test
  continues to pass after the trait split (no behavioural
  drift).
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 11 CI feature-matrix entries clean.
- `static_assertions::assert_impl_all!(FiveTupleKey: KeyFields);`
  compiles.
- `static_assertions::assert_impl_all!(AnomalyKind: AnomalyFields);`
  compiles.
- No `Timestamp::try_into::<DateTime<Utc>>()` callsites remain
  in the crate.
- CHANGELOG 0.12 entry lists all 5 breaks with one-line
  migrations.

## Risks

- **R1: Parallel Vec for `FlowPacket.tcp`.** Allocating a
  side-channel buffer doubles the per-`track_into` Vec count.
  Mitigation: reuse across calls (`Vec::clear()`); steady-state
  cost is zero. Verified by `benches/zero_alloc.rs`.
- **R2: NDJSON `K: Serialize` bound.** Custom keys must
  implement `Serialize`. Already required for serde feature
  users; existing constraint, just made explicit at the
  method level.
- **R3: Doc churn.** Every doc reference to "AnomalyFields"
  needs to be audited — does it mean keys, anomalies, or
  both? Mitigation: plan 132 (documentation overhaul) lands
  in the same cycle.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Trait split + impl moves | 80 | 2 |
| Event::FlowPacket redesign + tcp accessor | 90 | 3 |
| Emit writers generic over K | 120 | 3 |
| Timestamp chrono symmetry | 30 | 1 |
| DeferredDriverBuilder bound parity | 20 | 0.5 |
| BurstDetector + TopK new_unbounded | 30 | 0.5 |
| Tests (8 unit + 6 integration) | 200 | 4 |
| CHANGELOG + doc references | 30 | 1 |
| **Total** | **~600** | **~15 hours (~2 days)** |

## Provenance

Driven by the 0.12 post-release audit (this conversation,
2026-06). Five distinct rough edges named in the audit; bundled
into one plan because they all touch the public trait shape
and shipping them piecemeal would mean five user migrations
across consecutive cycles. Pre-1.0 cleanup before community
adoption hardens the surface.
