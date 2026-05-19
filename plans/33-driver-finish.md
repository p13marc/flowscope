# Plan 33 — `finish()` on the drivers; public `Timestamp::MAX`

## 1. Summary

In a manual driver loop the caller must flush still-open flows at
end-of-input by calling `sweep()` with a far-future timestamp.
`examples/http_log.rs` does this with a magic-number hack
(`Timestamp::new(ts.sec.saturating_add(86_400), 0)`), and
`src/pcap/source.rs`'s `EventIter` does the same internally. A user
who simply forgets the final sweep silently loses their last flows —
a correctness footgun, not just an ergonomic one. This plan adds a
`Timestamp::MAX` associated constant and a `finish()` method on all
three drivers that sweeps at `Timestamp::MAX`, then removes the
`86_400` workaround from both the example and `EventIter`.

## 2. Status

Implemented in the working tree; not yet committed. Per the
`INDEX.md` convention, delete this file in the PR series that lands
the change. Note: `examples/pcap_flow_summary.rs` and
`examples/pcap_buffered_reassembly.rs` also carried the `86_400`
workaround and were converted (the former drives a raw
`FlowTracker`, so it uses `tracker.sweep(Timestamp::MAX)` directly;
`finish()` is a driver method).

## 3. Prerequisites

None. Independent of plan 32 — but if 32 lands first, `finish()` is
written once against the simplified (`S`-free) driver signatures
instead of twice. Recommended order: 32 → 33.

## 4. Out of scope

- Auto-calling `finish()` — drivers stay explicit; the caller decides
  when input ends. (The `PcapFlowSource` iterators in plan 35 *do*
  call it internally, because they own the input boundary.)
- Changing `sweep()` semantics. `finish()` is a thin convenience
  wrapper over `sweep(Timestamp::MAX)`.

## 5. Files

| File | Change |
|------|--------|
| `src/timestamp.rs` | Add `pub const MAX: Timestamp`. |
| `src/driver.rs` | Add `FlowDriver::finish()`. |
| `src/session_driver.rs` | Add `FlowSessionDriver::finish()`. |
| `src/datagram_driver.rs` | Add `FlowDatagramDriver::finish()`. |
| `src/pcap/source.rs` | `EventIter::next` — replace the `86_400` far-future computation with `sweep(Timestamp::MAX)`. |
| `examples/http_log.rs` | Replace the `far`/`86_400` block with `driver.finish()`. |
| `docs/SESSION_GUIDE.md` | Note `finish()` in the sync-driving section. |
| `CHANGELOG.md` | Additive-feature entry. |

## 6. API

```rust
// src/timestamp.rs
impl Timestamp {
    /// The maximum representable timestamp. Past any real capture
    /// time — pass to `sweep()` to force every live flow to its
    /// idle-timeout end. `finish()` uses this internally.
    pub const MAX: Timestamp = Timestamp { sec: u32::MAX, nsec: 999_999_999 };
}

// src/driver.rs
impl<E, F> FlowDriver<E, F> {
    /// Sweep every remaining flow to its end. Call once after the
    /// last `track()` when input is exhausted. Equivalent to
    /// `sweep(Timestamp::MAX)`.
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>> {
        self.sweep(Timestamp::MAX)
    }
}

// src/session_driver.rs / src/datagram_driver.rs
impl<E, P> FlowSessionDriver<E, P> {
    /// Sweep every remaining flow, emitting `Closed` events (and any
    /// parser-flushed `Application` events). Call once at end of input.
    pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, P::Message>> {
        self.sweep(Timestamp::MAX)
    }
}
```

Call-site effect:

```rust
// examples/http_log.rs — before
if let Some(ts) = last_ts {
    let far = flowscope::Timestamp::new(ts.sec.saturating_add(86_400), 0);
    for ev in driver.sweep(far) {
        if matches!(ev, FlowEvent::Ended { .. }) { ended += 1; }
    }
}
// after
for ev in driver.finish() {
    if matches!(ev, FlowEvent::Ended { .. }) { ended += 1; }
}
```

The `last_ts` tracking variable in `http_log.rs` becomes dead and is
deleted.

## 7. Implementation steps

1. **`src/timestamp.rs`** — add the `MAX` associated const. `nsec`
   is `999_999_999` (the largest valid sub-second value; the type
   invariant is `nsec < 1_000_000_000`). Add a doc-comment.
2. **`src/driver.rs`** — add `finish()` to the main `FlowDriver`
   `impl` block, directly after `sweep()`.
3. **`src/session_driver.rs`** — add `finish()` after `sweep()`.
4. **`src/datagram_driver.rs`** — add `finish()` after `sweep()`.
5. **`src/pcap/source.rs`** — in `EventIter::next`, the `None` arm
   currently computes `last_seen_sec` + `86_400`. Replace the whole
   far-future computation (the `last_seen_sec` fold and the `far`
   binding) with `self.tracker.sweep(Timestamp::MAX)`. Update the
   `EventIter` doc-comment that mentions "a far-future timestamp".
6. **`examples/http_log.rs`** — replace the `far` block with
   `driver.finish()`; delete the now-dead `last_ts` variable and its
   assignment in the loop.
7. **`docs/SESSION_GUIDE.md`** — in "Sync vs async session driving",
   add a line: end a sync loop with `driver.finish()` to flush
   still-open flows.
8. **`CHANGELOG.md`** — add an "Added" entry for `Timestamp::MAX`
   and `finish()`.

## 8. Tests

- **`src/timestamp.rs`** — unit test: `Timestamp::MAX` is greater
  than any constructed timestamp; `MAX.nsec < 1_000_000_000`.
- **`src/driver.rs`** — test: open a flow with `track()`, call
  `finish()`, assert an `Ended { reason: IdleTimeout }` event is
  produced and a second `finish()` yields nothing.
- **`src/session_driver.rs`** — test: `finish()` produces `Closed`
  for an open session and drains FIN-less parser state.
- **`tests/`** — `http_pcap.rs` / `pcap_integration.rs` already
  drive flows to completion; confirm the `EventIter` change keeps
  their flow-count assertions stable (the `86_400` and
  `Timestamp::MAX` sweeps are behaviourally identical for any real
  capture).

## 9. Acceptance criteria

- No occurrence of `86_400` anywhere in `src/` or `examples/`.
- `examples/http_log.rs` ends with `driver.finish()` and has no
  `last_ts` variable.
- `cargo test --all-features` clean; existing pcap integration
  flow-count assertions unchanged.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.

## 10. Risks

- **`u32::MAX` seconds vs `Duration` conversions.** `Timestamp::
  to_duration()` builds `Duration::new(sec as u64, nsec)` —
  `u32::MAX` seconds is ~136 years, well within `Duration` range; no
  overflow. `to_system_time()` adds to `UNIX_EPOCH` — also fine.
  Verify no code path multiplies `sec` into a narrower type.
- Idle-timeout arithmetic inside `FlowTracker::sweep` computes
  `now - last_seen`. With `now = Timestamp::MAX` and a tiny
  `last_seen`, the elapsed duration is huge but `saturating_*` math
  already guards this — confirm `sweep` uses saturating subtraction
  (it does, via `Timestamp::saturating_sub`).

## 11. Effort

S — ~40 lines added, ~10 deleted. A couple of hours including tests.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F3** (🟠). The `86_400`
magic number in a shipped example was the flagged smell — "the API
forced the user to invent a workaround."
