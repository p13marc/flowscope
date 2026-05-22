# Plan 43 — Split `Anomaly { key: Option<K> }` on `FlowEvent` and `SessionEvent`

## 1. Summary

Both `FlowEvent::Anomaly` and `SessionEvent::Anomaly` carry a
`key: Option<K>` because some `AnomalyKind`s are per-flow
(`OutOfOrderSegment`, `BufferOverflow`, `SessionParseError`) and
some are tracker-global (`FlowTableEvictionPressure`). Every
consumer ends up writing `if let Some(k) = key { … }` to route.

This plan replaces the single `Anomaly` variant with two:
`FlowAnomaly { key: K, kind, ts }` (per-flow) and
`TrackerAnomaly { kind, ts }` (global). Removes the `Option<K>`
plumbing from every consumer hot path. Per the netring feedback,
"a per-flow anomaly is 'this stream is sick', a tracker-global one
is 'the whole pipeline is sick'" — the two are semantically
different and the variant split makes that explicit.

Same shape applied to both event types. `#[non_exhaustive]` is
already on both enums (project convention), so the *addition* of
the new variants is non-breaking. The *removal* of the old
`Anomaly { key: Option<K> }` variant is the breaking part.

## 2. Status

Not started.

## 3. Prerequisites

None — independent of all other 0.5 plans.

## 4. Out of scope

- Splitting `AnomalyKind` itself into per-flow and tracker-global
  enums. The netring feedback notes this could follow but is "a
  bigger swing"; we keep `AnomalyKind` as one enum for now —
  consumers that want to assert "this kind only appears as a
  FlowAnomaly" rely on the variant routing, not the kind taxonomy.
- Changing what triggers each anomaly (no behavioural change).
- Anything in the `obs.rs` metrics surface beyond the matching
  label arms.

## 5. Files

| File | Change |
|------|--------|
| `src/event.rs` | `FlowEvent`: add `FlowAnomaly` + `TrackerAnomaly` variants; remove `Anomaly`. |
| `src/session.rs` | `SessionEvent`: same. |
| `src/driver.rs` | `FlowDriver::diff_anomaly_state` constructs the two new variants based on per-flow vs global kind. |
| `src/session_driver.rs`, `src/datagram_driver.rs` | Anomaly forwarding from `FlowEvent` to `SessionEvent`: route per-flow to `FlowAnomaly`, global to `TrackerAnomaly`. |
| `src/event.rs::tests`, driver tests | Update match arms in existing anomaly tests. |
| `tests/metrics_integration.rs` | Update if it matches `Anomaly` variants. |
| `docs/SESSION_GUIDE.md`, `docs/OBSERVABILITY.md` | Update any prose / examples that mention `Anomaly`. |
| `CHANGELOG.md` | Breaking entry + migration recipe. |

## 6. API

```rust
// ── FlowEvent ───────────────────────────────────────────────
#[non_exhaustive]
pub enum FlowEvent<K> {
    Started { key: K, ts: Timestamp, /* … */ },
    Established { /* … */ },
    Packet { /* … */ },
    Ended { /* … */ },

    /// Per-flow anomaly tied to a specific stream.
    FlowAnomaly { key: K, kind: AnomalyKind, ts: Timestamp },

    /// Tracker-global anomaly (e.g., eviction pressure).
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },

    // (removed) Anomaly { key: Option<K>, kind, ts }
}

// ── SessionEvent (same split) ───────────────────────────────
#[non_exhaustive]
pub enum SessionEvent<K, M> {
    Started { /* … */ },
    Application { /* … */ },
    Closed { /* … */ },

    /// Forwarded per-flow anomaly.
    FlowAnomaly { key: K, kind: AnomalyKind, ts: Timestamp },

    /// Forwarded tracker-global anomaly.
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },
}
```

Mapping per `AnomalyKind` (today's variants):

| `AnomalyKind` | Lands in |
|---------------|----------|
| `BufferOverflow { side, bytes, policy }` | `FlowAnomaly` |
| `OutOfOrderSegment { side, count }` | `FlowAnomaly` |
| `SessionParseError { side, reason }` | `FlowAnomaly` |
| `FlowTableEvictionPressure { evicted_in_tick, evicted_total }` | `TrackerAnomaly` |
| `ReassemblerHighWatermark { side, … }` (new in plan 44) | `FlowAnomaly` |

The routing is mechanical and centralised in the driver code; consumers
just match the variant.

Migration recipe (CHANGELOG):

```rust
// before
match ev {
    SessionEvent::Anomaly { key: Some(k), kind, ts } => per_flow(k, kind, ts),
    SessionEvent::Anomaly { key: None, kind, ts }    => tracker_wide(kind, ts),
    /* … */
}

// after
match ev {
    SessionEvent::FlowAnomaly { key, kind, ts }    => per_flow(key, kind, ts),
    SessionEvent::TrackerAnomaly { kind, ts }      => tracker_wide(kind, ts),
    /* … */
}
```

## 7. Implementation steps

1. **`src/event.rs`** — add `FlowAnomaly` and `TrackerAnomaly`
   variants to `FlowEvent`. Remove `Anomaly`. Update any helper
   methods (`FlowEvent::key()` — currently returns `Option<&K>`;
   should still work, returning `Some(&key)` for `FlowAnomaly`,
   `None` for `TrackerAnomaly`, and same as before for the
   non-anomaly variants).
2. **`src/session.rs`** — same on `SessionEvent`.
3. **`src/driver.rs`** — `diff_anomaly_state` currently constructs
   `FlowEvent::Anomaly { key: Some(...) | None, ... }`. Route each
   kind to the appropriate variant based on whether it's per-flow
   or global. Add a small helper / match table for the mapping.
4. **`src/session_driver.rs`** — the anomaly-forwarding code (when
   `with_emit_anomalies(true)`) maps `FlowEvent::Anomaly` to
   `SessionEvent::Anomaly` today. Change to forward `FlowAnomaly`
   to `SessionEvent::FlowAnomaly` and `TrackerAnomaly` to
   `SessionEvent::TrackerAnomaly` 1:1.
5. **`src/datagram_driver.rs`** — same as session_driver.
6. **Tests** — update any tests that match on `Anomaly { key: ...
   }`. Most live in driver tests + `tests/metrics_integration.rs`.
   Add a dedicated test that constructs each kind and asserts it
   lands in the right variant.
7. **`docs/SESSION_GUIDE.md` + `docs/OBSERVABILITY.md`** — replace
   prose mentions of `Anomaly` with the split, update sample match
   blocks.
8. **`CHANGELOG.md`** — breaking entry with the migration recipe.

## 8. Tests

- **Routing test** (`driver.rs` test module): force each
  `AnomalyKind` to fire (BufferOverflow via DropFlow,
  OutOfOrderSegment via OOO segment, FlowTableEvictionPressure via
  `max_flows = 1` + extra flow). Assert each lands in the correct
  variant.
- **Session forwarding test**: same in `session_driver.rs`, with
  `with_emit_anomalies(true)`, asserting `SessionEvent::FlowAnomaly`
  / `TrackerAnomaly` variants land correctly.
- **`FlowEvent::key()` semantics**: assert it returns
  `Some(&key)` for `FlowAnomaly`, `None` for `TrackerAnomaly`.

## 9. Acceptance criteria

- No occurrence of `Anomaly { key: Option<K>` (old shape) remains
  in `src/`, `tests/`, `examples/`.
- `cargo build/test/clippy/fmt/doc --all-features` clean.
- The new variants are `#[non_exhaustive]` consistent with the
  enum-level `#[non_exhaustive]` (variants inherit; no extra
  attribute needed unless variant-level future-additivity is
  desired — defer).
- CHANGELOG carries the migration recipe.

## 10. Risks

- **netring lockstep.** netring's stream adapters match on the
  current `Anomaly { key: Option<K>, ... }`. Mechanical update.
- **`FlowEvent::key()` consumers.** Returns `Option<&K>` already;
  callers expecting `None` for tracker-global anomalies still get
  it. No further change there.
- **Future `AnomalyKind` additions need explicit routing.** Adding
  a new `AnomalyKind` variant requires an explicit decision: per-
  flow or tracker-global? Capture that in the
  `obs.rs::anomaly_label` convention block (same place new kinds
  already need a metric label arm).

## 11. Effort

M — many small touches across drivers + tests + docs. Estimate
half a day including the lockstep coordination notes for netring.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#4**. See [`docs/0.5-PLAN-OF-RECORD.md`](../docs/0.5-PLAN-OF-RECORD.md)
§2 for sequencing.
