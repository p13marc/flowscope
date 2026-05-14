# Plan 51 — `SessionEvent::Anomaly` forwarding

## Summary

`FlowEvent::Anomaly { kind: AnomalyKind, .. }` shipped in 0.2.0
([plan 42](./42-reassembly-observability.md) §3) with an enumerated
non_exhaustive `AnomalyKind`. The async netring `session_stream`
adapter forwards it through to consumers naturally because it
just relays `FlowEvent`s.

The sync [`FlowSessionDriver`](../src/session_driver.rs) does NOT
forward anomalies today — `translate_events` matches `FlowEvent::Anomaly`
and silently drops it. Consumers wired through `FlowSessionDriver`
miss the live anomaly stream entirely.

This plan adds `SessionEvent::Anomaly { key, kind, ts }` and
forwards `FlowEvent::Anomaly` through. Opt-in via a
`FlowSessionDriver::with_emit_anomalies(true)` toggle parallel to
the existing `FlowDriver` one.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 42 §3 (anomaly events on `FlowDriver`) — shipped in 0.2.0.
- Plan 25 §1 (`FlowSessionDriver`) — shipped in 0.2.0.

## Out of scope

- Adding new `AnomalyKind` variants. That's whatever consumer demand
  surfaces (e.g., `UnexpectedFin`, finer eviction-reason
  classification) — propose them as separate plans.
- Per-session-event metrics emission. Plan 40 already wires
  `flowscope_anomalies_total` from `FlowDriver`. The
  `FlowSessionDriver` path goes through the same `FlowDriver`-style
  emission infrastructure, so metrics fire correctly when
  anomalies are emitted — no additional wiring needed.
- Throttling / rate limiting at the `SessionEvent` layer. Anomalies
  are already coalesced per (flow, side, kind) per tick by
  `FlowDriver`'s diff logic ([plan 42 §3](./42-reassembly-observability.md)).
  Anything beyond that is consumer responsibility.

---

## Files

### MODIFIED

- `src/session.rs` — add `SessionEvent::Anomaly { key, kind, ts }`
  variant.
- `src/session_driver.rs` — `FlowSessionDriver::with_emit_anomalies`
  builder; plumb the toggle through to an inner `FlowDriver` (the
  current implementation doesn't use `FlowDriver`; this plan also
  rewires it to do so OR replicates the snapshot/diff logic — see
  Implementation steps below). Forward `FlowEvent::Anomaly` to
  `SessionEvent::Anomaly` in `translate_events`.
- `CHANGELOG.md` — 0.3.0 entry covering the new variant + accessor.
- `docs/SESSION_GUIDE.md` — extend the "Anomaly events (0.2.0)"
  subsection to cover the sync path.

### NEW

None.

---

## API

### `src/session.rs`

```rust
#[derive(Debug, Clone)]
pub enum SessionEvent<K, M> {
    Started { /* ... */ },
    Application { /* ... */ },
    Closed { /* ... */ },
    /// New in 0.3.0. Live, in-flight anomaly mirroring
    /// [`crate::FlowEvent::Anomaly`]. Emitted only when the driver
    /// has `with_emit_anomalies(true)` set.
    ///
    /// `key` is `None` for tracker-global anomalies (e.g.
    /// [`crate::AnomalyKind::FlowTableEvictionPressure`]).
    Anomaly {
        key: Option<K>,
        kind: AnomalyKind,
        ts: Timestamp,
    },
}
```

`SessionEvent` is not currently marked `#[non_exhaustive]`. This
plan adds the new variant; consumers' exhaustive `match` blocks
will need a new arm. Pre-1.0 acceptable.

While we're touching the enum, **add `#[non_exhaustive]` at the
same time** so future variants are additive forever (matches the
project convention recorded in INDEX.md).

### `src/session_driver.rs`

```rust
impl<E, P, S> FlowSessionDriver<E, P, S> {
    /// Opt in to forwarding [`SessionEvent::Anomaly`]s through the
    /// stream. Default: `false`. Mirrors
    /// [`crate::FlowDriver::with_emit_anomalies`].
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }
}
```

---

## Implementation steps

1. **Survey the current `FlowSessionDriver` internals**. Today the
   driver owns its own `FlowTracker` + reassemblers + parsers and
   does NOT wrap a `FlowDriver`. The anomaly snapshot/diff logic
   needed for emission lives entirely inside `FlowDriver`. Two
   options:
   - **Option A — wrap `FlowDriver`**: rewire `FlowSessionDriver`
     to hold a `FlowDriver<E, BufferedReassemblerFactory, S>` and
     delegate. Single source of truth for anomaly emission +
     reassembler accounting. Bigger refactor.
   - **Option B — replicate**: copy the snapshot/diff helpers from
     `FlowDriver` into `FlowSessionDriver`. Easier landing, but
     two near-identical copies of anomaly logic to keep in sync.

   **Recommendation: Option A.** The duplication risk in Option B
   is too high — Plan 42's anomaly logic is non-trivial and the
   coalescing rules are easy to drift on. The refactor is ~100
   LOC.
2. **Add `SessionEvent::Anomaly`** as the fourth variant. Mark
   `SessionEvent` `#[non_exhaustive]`.
3. **Update `translate_events`** to forward `FlowEvent::Anomaly`:
   ```rust
   FlowEvent::Anomaly { key, kind, ts } => {
       out.push(SessionEvent::Anomaly { key, kind, ts });
   }
   ```
4. **Add the `with_emit_anomalies` builder**. Default `false`.
5. **Update SESSION_GUIDE.md** — the existing "Anomaly events"
   subsection lives next to `FlowDriver`; add a paragraph noting
   sync session-stream parity.
6. **Run the existing session_driver tests**. Add three new tests:
   - Anomaly events appear in the `SessionEvent` stream when
     `with_emit_anomalies(true)`.
   - No anomaly events when the flag is off (default behaviour
     unchanged).
   - `FlowTableEvictionPressure` anomalies surface with `key:
     None` and trigger no spurious flow lookup in the session
     translation.
7. **CHANGELOG entry** — additive variant + builder method;
   non_exhaustive note on `SessionEvent`.

---

## Tests

### `src/session_driver.rs` (additions)

```rust
#[test]
fn anomaly_event_forwarded_when_emit_anomalies_on() {
    let factory_cap = 64;
    let mut cfg = FlowTrackerConfig::default();
    cfg.max_reassembler_buffer = Some(factory_cap);
    let mut d = FlowSessionDriver::<_, LineParser>::with_config(
        FiveTuple::bidirectional(),
        cfg,
    )
    .with_emit_anomalies(true);

    // 3WHS + 200B initiator payload — sliding-window cap, drops 136 B.
    let mut events = Vec::new();
    for f in build_3whs() {
        events.extend(d.track(view(&f, 0)));
    }
    let mac = [0u8; 6];
    let data = ipv4_tcp(
        mac, mac,
        [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1001, 5001, 0x18,
        &vec![b'A'; 200],
    );
    events.extend(d.track(view(&data, 0)));

    let buffer_overflow = events
        .iter()
        .find(|e| matches!(e, SessionEvent::Anomaly {
            kind: AnomalyKind::BufferOverflow { .. }, ..
        }))
        .expect("expected a BufferOverflow anomaly forwarded");
    match buffer_overflow {
        SessionEvent::Anomaly { kind: AnomalyKind::BufferOverflow { bytes, .. }, .. } => {
            assert_eq!(*bytes, 136);
        }
        _ => unreachable!(),
    }
}

#[test]
fn no_anomaly_events_by_default() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.max_reassembler_buffer = Some(64);
    let mut d = FlowSessionDriver::<_, LineParser>::with_config(
        FiveTuple::bidirectional(),
        cfg,
    );
    // Same flow shape that triggered the anomaly above.
    let mut events = Vec::new();
    for f in build_3whs() {
        events.extend(d.track(view(&f, 0)));
    }
    let mac = [0u8; 6];
    let data = ipv4_tcp(
        mac, mac,
        [10, 0, 0, 1], [10, 0, 0, 2],
        1234, 80, 1001, 5001, 0x18,
        &vec![b'A'; 200],
    );
    events.extend(d.track(view(&data, 0)));
    assert!(
        !events
            .iter()
            .any(|e| matches!(e, SessionEvent::Anomaly { .. })),
        "expected no anomaly events when emit_anomalies is off"
    );
}

#[test]
fn eviction_pressure_anomaly_has_no_key() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.max_flows = 2;
    let mut d = FlowSessionDriver::<_, LineParser>::with_config(
        FiveTuple::bidirectional(),
        cfg,
    )
    .with_emit_anomalies(true);
    let mut events = Vec::new();
    for src_port in [1234u16, 1235, 1236] {
        let frame = ipv4_tcp(
            [0; 6], [0; 6],
            [10, 0, 0, 1], [10, 0, 0, 2],
            src_port, 80, 0, 0, 0x02, b"",
        );
        events.extend(d.track(view(&frame, 0)));
    }
    let pressure = events
        .iter()
        .find(|e| matches!(e, SessionEvent::Anomaly {
            kind: AnomalyKind::FlowTableEvictionPressure { .. }, ..
        }))
        .expect("expected an eviction-pressure anomaly");
    match pressure {
        SessionEvent::Anomaly { key, kind: AnomalyKind::FlowTableEvictionPressure { evicted_in_tick, .. }, .. } => {
            assert!(key.is_none());
            assert_eq!(*evicted_in_tick, 1);
        }
        _ => unreachable!(),
    }
}
```

### Doctest in `FlowSessionDriver::with_emit_anomalies`

```rust
/// ```no_run
/// use flowscope::extract::FiveTuple;
/// use flowscope::{FlowSessionDriver, SessionParser};
///
/// #[derive(Default, Clone)]
/// struct Noop;
/// impl SessionParser for Noop {
///     type Message = ();
///     fn feed_initiator(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
///     fn feed_responder(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
/// }
///
/// let driver: FlowSessionDriver<_, Noop> =
///     FlowSessionDriver::new(FiveTuple::bidirectional())
///         .with_emit_anomalies(true);
/// ```
```

---

## Acceptance criteria

- [ ] `SessionEvent` is `#[non_exhaustive]`.
- [ ] `SessionEvent::Anomaly { key, kind, ts }` variant exists.
- [ ] `FlowSessionDriver::with_emit_anomalies(bool)` builder works;
      default is `false`.
- [ ] Anomaly events surface in the `SessionEvent` stream when the
      flag is on, with the same coalescing semantics as Plan 42 §3.
- [ ] No anomaly events when the flag is off (existing tests pass
      without modification).
- [ ] `FlowTableEvictionPressure` anomalies have `key: None`.
- [ ] CHANGELOG entry; SESSION_GUIDE.md updated.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Internal refactor of `FlowSessionDriver`.** Option A (wrap
   `FlowDriver`) is the recommended path; it consolidates anomaly
   logic but rewires the driver's internals. Existing session_driver
   tests pin the behaviour — if they all pass after the refactor,
   the change is invisible to consumers.
2. **`SessionEvent` non_exhaustive break.** Pre-1.0; same precedent
   as Plan 42's `FlowEvent::key()` signature change. CHANGELOG
   migration note: external `match` blocks need a `_ => {}` arm or
   handling of the new variant.
3. **No new test infrastructure needed.** Existing
   `tests/length_prefixed_example.rs` integration test surface
   covers the SessionEvent stream end-to-end.

---

## Effort

- LOC: ~120 (session.rs +30, session_driver.rs refactor + new
  builder ~80, tests ~10 new + reuse existing helpers).
- Time: half a day.

---

## Provenance

Reported as item #7 in
`flowscope-feedback-2026-05-14.md` (des-rs team). They asked for
"enumerated AnomalyKind on SessionEvent" — the `AnomalyKind` enum
already shipped in 0.2.0; this plan closes the forwarding gap.
