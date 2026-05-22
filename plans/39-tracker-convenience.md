# Plan 39 — `FlowTracker` convenience: `finish()` + `sweep_with_parsers`

## 1. Summary

Two helpers on `FlowTracker` to bring its direct-use path up to the
drivers' ergonomic level:

1. **`FlowTracker::finish()`** — `sweep(Timestamp::MAX)` under a
   readable name. Plan 33 added `finish()` to all three drivers but
   missed the tracker.
2. **`FlowTracker::sweep_with_parsers` /
   `sweep_with_datagram_parsers`** — bake the `on_tick`
   choreography from the drivers into a reusable helper. Today, a
   direct-tracker consumer (netring's `SessionStream`,
   `DatagramStream`, and the four `Multi*Stream` variants) must
   re-implement: "sweep → drive on_tick on every live parser before
   the closed-event translation." If they forget, `on_tick` never
   fires and there's no compile-time signal.

## 2. Status

Not started.

## 3. Prerequisites

None — independent of plan 38. Both helpers stand alone on the
tracker.

## 4. Out of scope

- Track-time `feed_*` / `parse` choreography. The drivers handle
  that, and netring's existing implementation continues to handle
  it for the per-flow-state path. This plan is sweep-side only.
- An async / Stream wrapper around these helpers — that's
  netring's territory.
- The auto-sweep mode (`with_auto_sweep`) — feedback item #2,
  deferred to its own RFC.

## 5. Files

| File | Change |
|------|--------|
| `src/tracker.rs` | Add `finish()`, `sweep_with_parsers`, `sweep_with_datagram_parsers` to `impl<E, S> FlowTracker<E, S>`. |
| `src/session_driver.rs` | Optional: refactor `sweep()` to call `tracker.sweep_with_parsers` internally. Reduces duplication but is not required for plan 39's acceptance. |
| `src/datagram_driver.rs` | Same — optional refactor. |
| `docs/SESSION_GUIDE.md` | Add a "FlowTracker direct-use" section showing the helpers. |
| `CHANGELOG.md` | Additive entry. |

## 6. API

```rust
impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// End-of-input flush. Equivalent to `sweep(Timestamp::MAX)`.
    /// Every still-open flow exceeds its idle threshold against
    /// this anchor and emits its terminal `Ended` event.
    pub fn finish(&mut self) -> FlowEvents<E::Key> {
        self.sweep(Timestamp::MAX)
    }

    /// Run a sweep, driving `on_tick` on every live parser
    /// **before** the flow events are translated. Mirrors the
    /// choreography that `FlowSessionDriver::sweep` does internally,
    /// so direct-tracker consumers don't have to spell it out.
    ///
    /// `parsers` is the caller-owned per-flow parser map (lets the
    /// caller control construction policy — clone, factory,
    /// per-flow user state via `S`). `on_message` is invoked for
    /// each emitted L7 message; see the contract below.
    ///
    /// # Callback contract
    ///
    /// `on_message(key, side, msg, ts)` fires for:
    /// - **Tick output:** `(&K, FlowSide::Initiator, msg, now)` —
    ///   from `parser.on_tick(now)`. By convention all tick output
    ///   is attributed to the initiator side.
    /// - **Fin flush output:** `(&K, side, msg, ended_ts)` — from
    ///   `parser.fin_initiator()` / `fin_responder()` on flows that
    ///   end in this sweep. `ended_ts` is the flow's `last_seen`.
    ///
    /// Ordering: all `on_tick` callbacks for a given flow fire
    /// before its fin-flush callbacks fire. Both fire before that
    /// flow's `Ended` event lands in the returned `FlowEvents`.
    /// Flows ending in this sweep have their parser removed from
    /// `parsers` automatically.
    pub fn sweep_with_parsers<P, F>(
        &mut self,
        now: Timestamp,
        parsers: &mut HashMap<E::Key, P>,
        on_message: F,
    ) -> FlowEvents<E::Key>
    where
        P: SessionParser,
        F: FnMut(&E::Key, FlowSide, P::Message, Timestamp);

    /// Datagram-parser mirror. `on_message` is called from
    /// `parser.on_tick(now)` only (datagram parsers have no
    /// fin/rst). Flows ending in this sweep still have their parser
    /// removed from `parsers`.
    pub fn sweep_with_datagram_parsers<P, F>(
        &mut self,
        now: Timestamp,
        parsers: &mut HashMap<E::Key, P>,
        on_message: F,
    ) -> FlowEvents<E::Key>
    where
        P: DatagramParser,
        F: FnMut(&E::Key, FlowSide, P::Message, Timestamp);
}
```

The `HashMap` is `std::collections::HashMap` (not the crate-internal
`ahash`-hashed one) so the caller can use whatever hasher they
prefer. If `ahash` parity matters internally, the helper accepts
`HashMap<E::Key, P, H: BuildHasher>` instead — pick one approach in
implementation; the bound stays additive either way.

## 7. Implementation steps

1. **`finish()`** — one-liner on `FlowTracker`.
2. **`sweep_with_parsers`** —
   1. Iterate `parsers` (no removal yet), calling `on_tick(now)` and
      invoking `on_message(key, FlowSide::Initiator, msg, now)` for
      each.
   2. Call `self.sweep(now)` to get `flow_events`.
   3. For each `FlowEvent::Ended { key, stats, .. }` in
      `flow_events`: if a parser exists in `parsers`, call
      `fin_initiator()` then `fin_responder()`, invoke `on_message`
      for each returned message with `stats.last_seen` as ts, then
      `parsers.remove(key)`.
   4. Return `flow_events`.
3. **`sweep_with_datagram_parsers`** — same shape, minus the fin
   flush (the `DatagramParser` trait has no `fin_*`). Just on_tick
   + flow-ended cleanup.
4. **Optional driver refactor:** `FlowSessionDriver::sweep` /
   `FlowDatagramDriver::sweep` can be reduced to calls into the
   helpers. Optional because the drivers also handle anomaly
   forwarding and reassembler finalize, which would need to stay
   inline. Skip unless cleanup is genuinely shorter.
5. **`docs/SESSION_GUIDE.md`** — add a section "FlowTracker direct-
   use: sweep choreography" with a worked example.
6. **`CHANGELOG.md`** — "Added" entries.

## 8. Tests

- **`finish()`** — open a flow with `track`, call `finish()`, assert
  one `Ended` event. Second `finish()` is empty.
- **`sweep_with_parsers` — on_tick fires.** A `TickParser` whose
  `on_tick` returns a sentinel message; drive it through `track` to
  open a flow, then call `sweep_with_parsers` with `now` past the
  idle timeout. Assert the sentinel was reported via `on_message`
  for that flow, the flow ended (returned `FlowEvents` contains
  `Ended`), and the parser was removed from the map.
- **`sweep_with_parsers` — fin flush fires.** A parser whose
  `fin_initiator` returns a sentinel; open a flow, sweep at
  `Timestamp::MAX` (`finish()`-equivalent), assert the fin sentinel
  fires via `on_message` and the parser is gone.
- **Ordering.** Both tick and fin in the same sweep: assert tick
  fires before fin for the same flow.
- **`sweep_with_datagram_parsers`** — mirror of the on_tick test
  for `DatagramParser`.

## 9. Acceptance criteria

- The three new helpers exist on `FlowTracker` with the contract
  documented above.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` clean.
- `SESSION_GUIDE.md` has a recipe section showing the direct-use
  pattern (open flows via `track`, periodic `sweep_with_parsers`,
  final `finish()`).
- netring 0.15 can replace its hand-rolled on_tick choreography
  with `sweep_with_parsers` (cross-repo, but the API supports it).

## 10. Risks

- **`HashMap` vs `crate::hash::RandomState` choice.** Picking `std::
  collections::HashMap` (default hasher) is the most consumer-
  friendly. Picking the crate-internal `ahash`-hashed map matches
  the drivers internally. The right answer is probably to accept a
  generic `HashMap<E::Key, P, H: BuildHasher>` — adds one type
  parameter per helper, lets the caller pass either. Decide during
  implementation.
- **Callback API vs returning `Vec<(K, side, msg, ts)>`.** A
  callback avoids the allocation; a returned Vec is easier to test
  and reason about. The drivers internally collect into a Vec
  anyway; the callback is a slight optimisation. Going with the
  callback per the netring feedback's proposed shape — it makes the
  caller's "emit per message" decision explicit.

## 11. Effort

S — ~80 lines in `tracker.rs` + ~80 lines of tests. Estimate one
afternoon.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
items **#3** (`finish`) and **#1** (`sweep_with_parsers`). After
plan 38 restores driver `S` (eliminating netring's main reason to
drop down to `FlowTracker`), the helpers stay useful for genuine
direct-tracker consumers and for any future driver alternative.
See [`docs/0.5-PLAN-OF-RECORD.md`](../docs/0.5-PLAN-OF-RECORD.md)
§3 for the relative-urgency note.
