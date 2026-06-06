# Plan 87 — `FlowEvent::Established { l4: Option<L4Proto> }`

## Summary

`FlowEvent::Started` (plan 32 / 0.4.0) and `FlowEvent::Ended` (plan 79
/ 0.7.0) both carry `l4: Option<L4Proto>`. `FlowEvent::Established` —
the TCP-3WHS-completed event — does not. Consumers that route on
`Established` to recognise "a TCP flow just opened" still have to
maintain or query a side-table for the L4. Plan 79 closed the parallel
gap on `Ended`; this plan rounds out the trio.

This is a small variant-field break: every `match` on
`FlowEvent::Established { … }` needs a new field or `..`. Mechanical
migration recipe in CHANGELOG.

## Status

Not started.

## Prerequisites

- Plan 32 (Started `l4`) — shipped in 0.4.0.
- Plan 79 (Ended / Closed `l4`) — shipped in 0.7.0. The driver
  patching pattern (`tracker.snapshot_l4`) is established and reused
  here.

## Out of scope

- Adding `l4` to `FlowEvent::StateChange`. The state machine fires
  many non-Established transitions; consumers route by state, not by
  l4. Add if a consumer asks.
- Adding `l4` to `FlowEvent::Tick` / `FlowEvent::Packet`. Hot-path
  events; per-packet l4 derivation already lives on the consumer if
  needed. (Tick consumers can correlate via the matching `Started`
  event's `l4`.)
- Making `l4` non-`Option`. Same future-proofing as plans 32 / 79;
  some flow types could be L4-less.

## Files

- `src/event.rs` — add `l4: Option<L4Proto>` to `FlowEvent::Established`.
- `src/tracker.rs` — emit `l4` on every constructed `Established` event
  (tracker already knows it from the flow entry).
- `src/session_driver.rs` — translate-events loop: pattern-match
  `Established { l4 }` if it needs the field; today it's a TCP-internal
  event not surfaced to `SessionEvent`, so no forwarding work, but the
  match pattern needs an update.
- `src/datagram_driver.rs` — same; `Established` is ignored on
  the datagram side, so just `..` on the match.
- `src/driver.rs` — `Established` is constructed in the tracker, not
  the driver; verify no direct construction here.
- All in-tree match sites on `Established` — update.
- `docs/SESSION_GUIDE.md` — update the Established subsection (none
  today; add a brief note).
- `CHANGELOG.md` — `### Breaking` entry with migration recipe.

## API

```rust
pub enum FlowEvent<K> {
    // ... unchanged variants ...

    /// TCP only — 3WHS completed for this flow.
    Established {
        key: K,
        ts: Timestamp,
        /// L4 protocol the flow was tracked under, or `None` if the
        /// extractor never classified one. New in 0.8.0; mirrors the
        /// `l4` field on `Started` (always `Some(L4Proto::Tcp)` for
        /// real TCP-3WHS-completed events).
        l4: Option<L4Proto>,
    },
}
```

## Implementation steps

1. **Add `l4` to `FlowEvent::Established`** in `src/event.rs`.
2. **Update tracker construction.** `Established` events are emitted
   in `FlowTracker::track_with_payload` when the TCP state machine
   transitions to `Established`. Read `entry.l4` and emit.
3. **Update match sites** in driver / session_driver / datagram_driver
   / examples / tests. `cargo build --all-features` surfaces every
   missed site at compile time.
4. **Tests** — add `tracker::tests::established_carries_l4`.
5. **CHANGELOG entry under `### Breaking`**:
   ```
   - **`FlowEvent::Established` gains a `l4: Option<L4Proto>`
     field** (plan 87). Rounds out the trio after Started (0.4) and
     Ended (0.7); same shape, same migration pattern.
     *Migration:*
     ```diff
     - FlowEvent::Established { key, ts } => …
     + FlowEvent::Established { key, ts, l4 } => …
       // or
     + FlowEvent::Established { key, ts, .. } => …
     ```
   ```

## Tests

- `src/tracker.rs::tests`:
  - `established_carries_l4` — drive a TCP 3WHS, assert
    `Established.l4 == Some(L4Proto::Tcp)`.
- Update any existing matches that destructure `Established` without
  `..`.

## Acceptance criteria

- `FlowEvent::Established { l4 }` matches the L4 of the flow that
  produced the 3WHS-complete signal.
- `cargo build --all-features` clean.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- Feature-matrix CI green.
- CHANGELOG migration recipe is copy-pastable.

## Risks

- **Cascade through match sites.** Each must update. Compile errors
  surface every site; nothing silently misses.
- **Doc-test breakage.** Any `///` block matching `Established { .. }`
  is fine (the `..` covers it). Specific-field destructures need
  updating; `cargo test --doc --all-features` catches them.

## Effort

~10 LoC source + ~30 LoC test + match-site updates (~5 sites in-tree).
**~1 hour** including CHANGELOG.

## Provenance

Round-3 wishlist item B3 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
The author tagged this as "Polish, ~10 LoC, ~0.1 day" — matches our
estimate.
