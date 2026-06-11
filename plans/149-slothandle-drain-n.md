# Plan 149 — `SlotHandle::drain_n` bounded drain

> **Narrowed from the wishlist.** Wishlist proposed `drain_n` +
> `swap` (with an exposed `Arc<SegQueue>`); I had counter-
> proposed `drain_n` + `swap` with an opaque `SlotBuf<M, K>`
> newtype. After review I'm dropping `swap` entirely from 0.13.
> Rationale below — TL;DR: the swap micro-optimisation isn't
> worth its API surface until a benchmark proves drain_n is the
> bottleneck.

## Summary

Add `SlotHandle::drain_n(out, max) -> usize` for bounded back-
pressure. Existing `drain` (unbounded) stays as the convenience
variant.

## Status

Not started. P1 for 0.13.

## Prerequisites

None.

## Out of scope

- **`swap()` / `SlotBuf<M, K>`.** The O(1) atomic-swap variant
  saves nanoseconds per drain in benches but adds significant
  API surface (a new public newtype, pool-management semantics,
  a clone race the user must understand). Defer to 0.14
  if/when a benchmark proves `drain_n(out, BIG)` is genuinely
  too slow. `SegQueue::pop` is ~10-15ns; batching even 10K
  messages stays under 200µs total — typically dwarfed by
  downstream emit cost.
- **Reordering / filtering during drain.** Consumer post-
  processes.
- **Cross-clone barriers.** Same FIFO-per-producer guarantees
  as today.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/driver/slot.rs` | Add `drain_n` method |
| Modify | `tests/driver_send.rs` | `drain_n` correctness + edge-case tests |
| Modify | `benches/zero_alloc.rs` (or extend slot bench) | Compare `drain_n(out, 64)` vs `drain(out)` at 1K / 10K message depths |

## API

```rust
impl<M, K> SlotHandle<M, K>
where M: Send + 'static, K: Send + 'static {
    /// Drain at most `max` queued messages into `out`. Returns
    /// the number actually drained.
    ///
    /// Bounded variant of [`drain`](Self::drain). Use when:
    ///
    /// - The consumer wants explicit back-pressure (drop the
    ///   rest if downstream can't keep up).
    /// - Drain cadence is unpredictable — one shard's drain
    ///   shouldn't monopolise a CPU when another shard has
    ///   packets waiting.
    ///
    /// `max = 0` is a valid no-op that returns 0 without
    /// touching the queue. `max = usize::MAX` is equivalent to
    /// `drain`.
    pub fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize {
        let mut n = 0;
        while n < max && let Some(msg) = self.inner.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }
}
```

## Implementation steps

1. Add the 5-line method. Mirrors `drain` with a bounded
   counter.
2. Tests + bench addition.

## Tests

- `drain_n_respects_max_when_queue_larger` — push 100, drain_n
  with max=10, get 10, queue has 90 remaining.
- `drain_n_returns_actual_count_when_queue_smaller` — push 5,
  drain_n with max=10, get 5.
- `drain_n_with_empty_queue_returns_zero`.
- `drain_n_max_zero_is_no_op`.
- `drain_n_max_usize_max_drains_all` — equivalence with `drain`.
- `drain_n_appends_to_existing_vec_contents` — pre-fill `out`
  with 3 items, drain_n adds to the end.
- Cross-thread test: producer pushes on one thread, two
  drain_n-calling clones on two consumer threads see the union
  of messages (MPMC contract preserved).

## Acceptance criteria

- `cargo test --all-features` clean.
- Bench: at 1K messages, `drain_n(out, 1000)` is within ±2%
  of `drain(out)` (same loop body, same atomic costs).
- Bench: at 10K messages, `drain_n(out, 64)` runs in <2µs,
  vs ~150µs for `drain(out)` — confirms the bounded-batch use
  case.
- netring 0.21 Phase C run loop adopts
  `drain_n(out, BATCH_CAP)` as the canonical pattern.

## Risks

None significant. 5-line additive method on an existing public
type.

## Effort

- LOC delta: +60 (method + tests + bench).
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 149. `swap`/`SlotBuf` deferred per the
consolidation pass (umbrella 157 §3.3 updated).
