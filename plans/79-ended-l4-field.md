# Plan 79 — `FlowEvent::Ended { l4: Option<L4Proto> }`

## Summary

`FlowEvent::Started` carries `l4: Option<L4Proto>` so consumers
know the L4 protocol from first-sight. `FlowEvent::Ended` does
not — consumers wanting to log "TCP flow ended" maintain a side
`HashMap<K, L4Proto>` keyed by flow, populated on `Started`,
queried on `Ended`. netring's `multi_protocol_monitor` and
`full_monitor` examples both carry this workaround (~10 LoC
each).

This plan threads `l4: Option<L4Proto>` through to `Ended` (and
`SessionEvent::Closed`, which mirrors it). The tracker already
knows the L4 of every live flow — it's already part of the flow
entry. We just expose it on the terminal event.

This is a variant-field break: every `match` on
`FlowEvent::Ended { … }` needs a new field or `..`. Pre-1.0
acceptable; the migration is mechanical.

## Status

Not started.

## Prerequisites

- Plan 33 (`FlowDriver::finish` / `Timestamp::MAX` sweep) —
  shipped in 0.4.0. The driver's `finalize_ended_flows` is the
  patching point for the new `l4` field, mirroring how the
  reassembler diagnostic fields are patched today.
- Plan 71 (`FlowEvent::Tick`) — shipped in 0.5.0. The `Tick`
  variant already carries `stats: FlowStats`; `l4` is similarly
  "tracker-knows, surface-it" data.

## Out of scope

- Adding `l4` to `FlowEvent::Tick`. Tick consumers can call
  `event.key()` and re-derive l4 from the tracker if they need
  it; adding a third copy of l4 on a frequently-emitted variant
  is wasteful.
- Adding `l4` to `FlowEvent::FlowAnomaly` / `TrackerAnomaly`.
  Anomalies are per-kind; consumers route on `AnomalyKind`.
- Adding `l4` to `FlowEvent::Packet`. Hot-path event;
  per-packet l4 derivation already lives on the consumer if
  needed.
- Renaming `Option<L4Proto>` to a non-optional `L4Proto`. The
  feedback author already flagged that some future flow types
  (IPv6 extension-header edge cases) might be L4-less; the
  Option matches `Started.l4` 1:1 today and leaves room for
  later.

## Files

- `src/event.rs` — add `l4: Option<L4Proto>` to
  `FlowEvent::Ended` and `FlowEvent::Tick`-adjacent docs. **Not**
  added to `Tick` itself (see Out of scope).
- `src/session.rs` — add `l4: Option<L4Proto>` to
  `SessionEvent::Closed`.
- `src/tracker.rs` — `record_flow_ended` already reads the flow
  entry's `l4`; emit it on the `Ended` event. Update
  `FlowEntry` -> `FlowEvent::Ended` construction sites in
  `sweep`, `track`, `track_with_payload`.
- `src/driver.rs` — `finalize_ended_flows` patches `stats` and
  `history` post-tracker; no change to the patching pass
  (`l4` is tracker-derived, not driver-derived). Verify the
  match patterns destructuring `Ended` are updated.
- `src/session_driver.rs` — forward `l4` from `Ended` into the
  emitted `Closed`.
- `src/datagram_driver.rs` — same forward.
- `src/obs.rs` — no changes (label functions don't consume the
  field).
- `docs/SESSION_GUIDE.md` — update the consumer-loop pattern to
  show how `l4` is now first-class.
- `CHANGELOG.md` — `### Breaking` entry with the variant-field
  migration recipe.
- All in-tree match sites on `Ended` / `Closed`:
  `src/dns/datagram.rs`, `src/dns/session.rs`,
  `src/http/session.rs`, `src/tls/session.rs`,
  `tests/*` — add `l4` to destructure patterns (or `..`).

## API

```rust
pub enum FlowEvent<K> {
    // ... unchanged variants ...

    /// Flow ended (FIN/RST for TCP, idle/eviction for any flow).
    Ended {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        /// L4 protocol the flow was tracked under, or `None` if
        /// the extractor never classified one. Mirrors the
        /// `l4` field set on the matching `Started` event for
        /// this flow.
        l4: Option<L4Proto>,
    },
}

pub enum SessionEvent<K, M> {
    // ... unchanged variants ...

    /// Session ended.
    Closed {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        l4: Option<L4Proto>,
    },
}
```

## Implementation steps

1. **Add the field on `FlowEvent::Ended`.** Default in tests via
   the existing tracker plumbing.
2. **Read l4 from the flow entry** in `tracker.rs`'s `sweep` /
   `track` paths. The `FlowEntry::l4` field already exists (set
   on `Started`). Emit it on every constructed `Ended`.
3. **Add the field on `SessionEvent::Closed`** in `session.rs`.
4. **Forward in `session_driver.rs`**: the existing translation
   loop matches `FlowEvent::Ended { key, reason, stats, .. }` and
   constructs `SessionEvent::Closed { key, reason, stats }`. Add
   `l4` in both arms.
5. **Forward in `datagram_driver.rs`** mirror.
6. **Update all in-tree match sites.** `cargo build --all-features`
   surfaces every missed match arm at compile time.
7. **Doctest sweep.** Any `///` block matching `Ended { .. }` is
   fine (the `..` covers it). Blocks destructuring specific
   fields need a `, l4` addition.
8. **CHANGELOG entry under `### Breaking`**:
   ```
   - **`FlowEvent::Ended` gains a `l4: Option<L4Proto>` field**
     (plan 79). Mirrors `Started.l4` 1:1 — saves the per-consumer
     `HashMap<K, L4Proto>` workaround for "what protocol was this
     flow?" Pre-1.0 variant-field addition.
     *Migration:* update destructure patterns to bind or ignore
     the new field:
     ```diff
     - FlowEvent::Ended { key, reason, stats, history } => …
     + FlowEvent::Ended { key, reason, stats, history, l4 } => …
       // or
     + FlowEvent::Ended { key, reason, stats, history, .. } => …
     ```
     Same change applies to `SessionEvent::Closed`.
   ```

## Tests

- `src/event.rs::tests`:
  - `flow_event_ended_carries_l4` — construct a flow via the
    tracker with a TCP packet, drive to `Ended` via
    `sweep(Timestamp::MAX)`, assert `l4 == Some(L4Proto::Tcp)`.
  - `flow_event_ended_carries_l4_udp` — same with UDP.
- `tests/round_trip.rs` — extend the existing round-trip with
  an assertion that the round-tripped `Ended` event carries the
  same `l4` as the matching `Started`.
- `src/session_driver.rs::tests` — verify `Closed.l4` matches
  the synthesised `Ended.l4`.
- `src/datagram_driver.rs::tests` — same mirror.

## Acceptance criteria

- `FlowEvent::Ended { l4 }` and `SessionEvent::Closed { l4 }`
  match `Started.l4` for every test flow.
- `cargo build --all-features` — no missed match-pattern
  compile errors.
- `cargo test --all-features` clean (~300+ tests).
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- Feature-matrix CI green.
- CHANGELOG migration recipe is copy-pastable.

## Risks

- **Cascade through downstream consumers.** netring 0.16 will
  see compile errors on every `match Ended { … }`. Mitigated by
  CHANGELOG migration recipe + the same `..` escape hatch every
  Rust variant-field addition supports.
- **Doc-test breakage in `docs/SESSION_GUIDE.md`.** Run
  `cargo test --all-features --doc` explicitly to flush these.
- **`FlowEntry::l4` mutation between `Started` and `Ended`.** The
  tracker today never mutates `l4` after first-sight. If a future
  plan changes that, the `l4` on `Ended` would diverge from
  `Started`. Add a comment in `tracker.rs` flagging the invariant
  so a future maintainer notices.

## Effort

~30 LoC source + ~50 LoC test diffs + match-site updates
(~10 sites in-tree). ~1 hour including CHANGELOG.

## Provenance

Round-2 feedback item F4 (round-1 carry of item C2) in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
Carried explicitly because the author flagged it as still missing
after 0.6. Their `multi_protocol_monitor` and `full_monitor` both
carry the `HashMap<K, L4Proto>` workaround.
