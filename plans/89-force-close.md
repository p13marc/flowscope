# Plan 89 — Programmatic flow termination (`force_close`)

## Summary

Today, a flow ends because of: FIN/RST (transport), idle timeout, LRU
eviction, buffer overflow (driver synthesis), parser-done (0.7), or
parse-error. Consumers cannot programmatically kill a specific flow
from outside. Three use cases for this:

1. **Resource management**: per-connection byte / time / message
   budgets enforced externally.
2. **Test harnesses**: deterministically end a flow at a known point.
3. **Rate limiting / circuit breakers**: drop flows tagged by a
   detector pipeline.

This plan adds:
- `FlowTracker::force_close(key, now) -> Option<FlowEvent>` on the
  tracker (the authoritative primitive).
- `FlowDriver::force_close`, `FlowSessionDriver::force_close`,
  `FlowDatagramDriver::force_close` — driver-level mirrors that also
  tear down the reassembler and parser slots.
- `EndReason::ForceClosed` — new variant under the existing
  `#[non_exhaustive]` enum; additive.

## Status

Not started.

## Prerequisites

- Plan 80 (`EndReason::ParserDone`) — shipped in 0.7.0. Establishes
  the pattern of driver-synthesised terminal events using an
  additive `EndReason` variant.
- Plan 79 (`FlowEvent::Ended { l4 }`) — shipped in 0.7.0. The
  synthesised event needs to populate `l4`.

## Out of scope

- Bulk close (force-close N flows in one call). Consumers iterate
  via `iter_active` (plan 90) and call `force_close` per key.
- Async / cancellation token integration. Cancellation is the
  caller's responsibility; this plan exposes the synchronous
  primitive.
- Force-close with a custom `EndReason` (e.g.
  `force_close_with_reason`). Adds API surface for an unclear
  benefit; revisit if asked. For now, `ForceClosed` is the single
  reason this path emits.

## Files

- `src/event.rs` — add `EndReason::ForceClosed` variant + Display
  / `obs::reason_label` arm.
- `src/obs.rs` — add `"force_closed"` arm to `reason_label`.
- `src/tracker.rs` — `pub fn force_close(&mut self, &E::Key, Timestamp)`.
- `src/driver.rs` — `FlowDriver::force_close` mirror that also
  tears down the reassembler slot.
- `src/session_driver.rs` — `FlowSessionDriver::force_close` that
  drains the parser, emits the `Closed` event, removes from
  `parsers`, forgets the tracker entry.
- `src/datagram_driver.rs` — same mirror.
- `tests/force_close.rs` — new integration tests covering tracker
  + driver behaviour.
- `docs/SESSION_GUIDE.md` — short subsection "Programmatic
  termination".
- `docs/OBSERVABILITY.md` — note the `reason="force_closed"` metric
  label.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/event.rs

#[non_exhaustive]
pub enum EndReason {
    Fin,
    Rst,
    IdleTimeout,
    Evicted,
    BufferOverflow,
    ParseError,
    ParserDone,
    /// New in 0.8.0. Driver synthesised an `Ended` event in response
    /// to [`crate::FlowTracker::force_close`] /
    /// [`crate::FlowDriver::force_close`]. Used for external
    /// orchestration (resource limits, test harnesses,
    /// rate limiters).
    ForceClosed,
}
```

```rust
// src/tracker.rs

impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// Force-end the flow with this key. Removes the tracker entry,
    /// emits an `Ended` event with [`EndReason::ForceClosed`]
    /// populated from the entry's last-seen counters.
    ///
    /// Returns the emitted `Ended` event, or `None` if the key
    /// was not active.
    ///
    /// Does **not** flush any reassembler or parser slots — those
    /// live on the driver. Use the driver-level
    /// [`crate::FlowDriver::force_close`] /
    /// [`crate::FlowSessionDriver::force_close`] /
    /// [`crate::FlowDatagramDriver::force_close`] when running
    /// through a driver; they handle the parser side too.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Option<FlowEvent<E::Key>>;
}
```

```rust
// src/driver.rs

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Driver-level mirror of [`FlowTracker::force_close`]. Tears
    /// down the per-(flow, side) reassembler slots before emitting
    /// the `Ended` event.
    ///
    /// Returns `Vec<FlowEvent>` matching the shape the consumer
    /// already expects from `track()` — same `Ended` event,
    /// potentially preceded by `FlowAnomaly` events if pending
    /// reassembler diagnostics fire.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Vec<FlowEvent<E::Key>>;
}
```

```rust
// src/session_driver.rs

impl<E, P, S> FlowSessionDriver<E, P, S> {
    /// Driver-level mirror of [`FlowDriver::force_close`]. Flushes
    /// any final parser messages (`fin_initiator`, `fin_responder`)
    /// before emitting `Closed { reason: ForceClosed, .. }`. Tears
    /// down the parser slot.
    pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>>;
}
```

Mirror on `FlowDatagramDriver` (no reassembler / no `fin_*` —
emits `Closed { reason: ForceClosed }` directly).

## Implementation steps

1. **Add `EndReason::ForceClosed`** in `src/event.rs`. Update
   `reason_label`. Add the parse-error/parser-done style rationale
   comment.
2. **Tracker `force_close`**:
   ```rust
   pub fn force_close(&mut self, key: &E::Key, now: Timestamp) -> Option<FlowEvent<E::Key>> {
       let removed = self.flows.pop(key)?;
       if self.hot.as_ref() == Some(key) {
           self.hot = None;
       }
       self.stats.flows_ended += 1;
       crate::obs::record_flow_ended(EndReason::ForceClosed, &removed.stats);
       crate::obs::trace_flow_ended(EndReason::ForceClosed, &removed.stats);
       let _ = now; // Reserved for future "Ended at now" timestamps.
       Some(FlowEvent::Ended {
           key: key.clone(),
           reason: EndReason::ForceClosed,
           stats: removed.stats,
           history: removed.history,
           l4: removed.l4,
       })
   }
   ```
3. **Driver `force_close`**: snapshot stats, drain reassembler slots
   (emit diagnostic anomalies if `emit_anomalies` is on), tear down
   reassemblers, call `tracker.force_close`, return the combined
   events.
4. **Session driver `force_close`**: drain into parser (final
   reassembled bytes through `feed_*`), call `parser.fin_initiator`
   / `fin_responder`, emit `Application` events, then forward the
   driver's `Ended` → `SessionEvent::Closed`. Tear down the parser
   slot.
5. **Datagram driver `force_close`**: no reassembly, no fin_*; just
   remove the parser slot, call `tracker.force_close`, translate
   the `Ended` event into a `Closed`.
6. **Reassembler treatment in `finalize_ended_flows`**: add
   `EndReason::ForceClosed` to the `Fin / IdleTimeout / ParserDone`
   group (clean close, not RST). Reassembler gets `fin()` not
   `rst()`.
7. **Tests** — see Tests section.
8. **CHANGELOG entry under `### Added`**:
   ```
   - **`FlowTracker::force_close` + driver mirrors + `EndReason::ForceClosed`**
     (plan 89). External orchestration can now end a specific flow
     ahead of FIN / idle / eviction. Use cases: resource budgets,
     test harnesses, rate limiters. Driver-level mirrors tear down
     the parser + reassembler slots before emitting the terminal
     event so no state leaks. `EndReason::ForceClosed` is additive
     in the existing `#[non_exhaustive]` enum; the new
     `flowscope_flows_ended_total{reason="force_closed"}` label
     fires per call.
   ```

## Tests

`tests/force_close.rs`:

- `tracker_force_close_unknown_key_returns_none`.
- `tracker_force_close_active_key_emits_ended`.
- `tracker_force_close_emits_ended_with_l4` — assert `Ended.l4` matches `Started.l4`.
- `tracker_force_close_clears_hot_cache`.
- `driver_force_close_tears_down_reassemblers` — feed some bytes,
  force-close, assert no further `Application` events on subsequent
  packets for the same key.
- `session_driver_force_close_flushes_fin_messages` — parser that
  emits a message in `fin_initiator()`; force-close on a flow with
  buffered initiator bytes; assert the message lands as
  `Application` before the `Closed`.
- `session_driver_force_close_does_not_double_close_on_subsequent_fin`
  — after force_close, a real FIN packet for the same flow doesn't
  emit a second `Closed` (tracker already forgot).
- `datagram_driver_force_close_removes_parser` — verify subsequent
  packets create a fresh parser instance.

## Acceptance criteria

- `force_close` correctly emits `Ended { reason: ForceClosed, l4: ..,
  stats: .., history: .. }` for active keys, `None` / empty vec for
  unknown keys.
- Driver-level mirrors tear down reassemblers + parsers + tracker
  entry.
- No double-close on subsequent FIN packets for force-closed flows.
- `flowscope_flows_ended_total{reason="force_closed"}` increments per
  call (verified via metrics_integration test extension).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- Feature-matrix CI green.

## Risks

- **Concurrent modification.** `force_close` takes `&mut self` —
  borrowing rules prevent concurrent iteration. Documented; if a
  consumer needs "iterate + close" they collect keys first
  (`iter_active` from plan 90).
- **Pending reassembler diagnostics.** The driver-level force_close
  must snapshot reassembler counters before tearing down — same
  pattern as `finalize_ended_flows`.
- **Parser final-flush semantics.** `fin_*` runs on force_close
  because we want clean close semantics. A parser that does
  "validate state on fin" might trip on an intentionally torn-down
  flow. Documented as expected behaviour; parsers can check
  `is_done()` first if they want to differentiate.

## Effort

~150 LoC source (event variant + tracker + 3 driver impls + obs
arm) + ~250 LoC tests + 20 lines docs. **~4–5 hours.**

## Provenance

Round-3 wishlist item B5 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Author noted they'd likely add a `StreamCapture::force_close_flow`
helper on netring's side rather than direct adoption — but the
underlying tracker primitive is what flowscope needs to ship.
