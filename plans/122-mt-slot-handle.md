# Plan 122 — `SlotHandle: Send + Sync` (consolidation)

## Summary

**Consolidate** the existing `SlotHandle<M, K>` to be always
`Send + Sync` by switching its backing storage from
`Rc<RefCell<SlotBuf<M, K>>>` to
`Arc<crossbeam_queue::SegQueue<SlotMessage<M, K>>>`. Single
type, single API, no feature flag, no parallel `MtSlotHandle`
type.

The wishlist proposed a feature-gated `MtSlotHandle` +
`MtDriverBuilder` mirror — three new files, four new slot
types, a duplicated builder. This plan rejects that approach
in favour of upgrading the existing surface in place. Cost:
one new always-on dep (`crossbeam-queue`, ~2 KB), ~5–10 ns
extra per slot emit (negligible at realistic rates), and a
pre-1.0 break on the `!Send` → `Send` auto-trait transition.
Benefit: one slot type to learn, no code duplication, every
netring / multi-thread tokio user gets `Send` handles for
free.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **No tokio types.** Hard rule. `crossbeam-queue` is sync-only,
  no async deps.
- **The `Driver<E>` itself stays `!Send`.** The central
  tracker (`FlowTracker<E>`) holds `Rc<RefCell>` internals;
  the rewrite to make the whole driver `Send` is multi-day
  work and out of scope. Only the **handle** side becomes
  `Send` — drain on any thread, run the driver on one thread.
- **No `Mutex`-backed alternative.** SegQueue is the right
  primitive: lock-free MPMC, no lock contention, ~10-15 ns
  push/pop.
- **No broadcast clone semantics.** `SlotHandle::clone` hands
  out a second **competitive consumer** (race for messages)
  — matches the underlying SegQueue MPMC contract. Document
  this explicitly. (Single-consumer scenarios stay the
  default and don't need clones.)

## Pre-1.0 break

`SlotHandle<M, K>` transitions from `!Send + !Sync` to
`Send + Sync`. Auto-trait inheritance differences may surface
at downstream callsites that explicitly assert `!Send` (rare).

The `SlotHandle<M, K>` generic bounds also tighten from
`M: 'static, K: 'static` to `M: Send + 'static, K: Send +
'static` — but every shipped `SessionParser::Message` /
`DatagramParser::Message` is already `Send + 'static` (the
trait bounds require it), so in practice this constraint is
already met.

CHANGELOG migration recipe: for the vast majority of users,
nothing changes. For users that explicitly relied on `!Send`
in trait bounds (unusual), they update the bound or refactor.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/driver/slot.rs` | Switch backing to `Arc<SegQueue>`; update `drain` / `pending` / `clear` / `parser_kind`; add `Send + 'static` bounds on `M`, `K`; remove `SlotBuf` (replaced by SegQueue) |
| Modify | `src/driver/typed_slot.rs` | Slots write via `SegQueue::push` instead of `RefCell::borrow_mut().queue.push`; drop the `Rc<RefCell>` import; the slot trait stays unchanged |
| Modify | `src/driver/typed_slot_heuristic.rs` | Same as typed_slot.rs |
| Modify | `Cargo.toml` | `crossbeam-queue = "0.3"` (no longer optional) |
| Modify | `tests/driver.rs` | Add `static_assertions::assert_impl_all!(SlotHandle<u32, FiveTupleKey>: Send, Sync);` |
| New | `tests/driver_send.rs` | Cross-thread drain integration test |
| Modify | `.github/workflows/rust.yml` | No new matrix entry needed (no feature flag) |
| Modify | `CHANGELOG.md` | Document the `Send + Sync` transition |

## API

### `SlotHandle<M, K>` (consolidated)

```rust
// src/driver/slot.rs
use std::sync::Arc;

use crossbeam_queue::SegQueue;

use crate::event::FlowSide;
use crate::Timestamp;

/// One typed message emitted by a registered parser.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct SlotMessage<M, K> {
    pub key: K,
    pub side: FlowSide,
    pub message: M,
    pub ts: Timestamp,
}

/// Typed drain handle returned by the builder per registered
/// parser. The handle is **`Send + Sync`** — move across
/// threads, share across drainers, drain inside a tokio task.
///
/// Backed by `Arc<crossbeam_queue::SegQueue<SlotMessage<M, K>>>`
/// — a lock-free MPMC queue. Slots push, handles pop. Cost
/// per emit: ~10-15 ns (uncontended).
///
/// # Cloning
///
/// `Clone` hands out a second **competitive consumer** — both
/// drain from the same SegQueue and race for messages. For
/// broadcast (every consumer sees every message), drain into
/// a channel and fan out yourself.
pub struct SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    pub(super) inner: Arc<SegQueue<SlotMessage<M, K>>>,
    pub(super) parser_kind: &'static str,
}

impl<M, K> SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    /// Drain all currently-queued messages into `out`. Returns
    /// the count drained. Lock-free.
    ///
    /// Per-drain cost: O(n) where n is the message count
    /// — each pop is ~10-15 ns. For high-message-count drains
    /// (100+ messages per call), the SegQueue pop loop is
    /// notably slower than the pre-0.12 `Rc<RefCell<Vec>>` batch
    /// move. Typical 0-2 messages per drain at netring's
    /// `track_into` cadence makes this irrelevant in practice.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.inner.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }

    /// Approximate message count currently in the queue.
    /// Cheap inspection; result may be slightly stale under
    /// concurrent push/pop.
    pub fn pending(&self) -> usize {
        self.inner.len()
    }

    pub fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }

    /// Discard all queued messages without draining.
    pub fn clear(&mut self) {
        while self.inner.pop().is_some() {}
    }
}

impl<M, K> Clone for SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    fn clone(&self) -> Self {
        Self {
            inner: Arc::clone(&self.inner),
            parser_kind: self.parser_kind,
        }
    }
}

impl<M, K> std::fmt::Debug for SlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SlotHandle")
            .field("parser_kind", &self.parser_kind)
            .field("pending", &self.pending())
            .finish()
    }
}

// Send + Sync follow automatically:
//   Arc<T>:        Send + Sync where T: Send + Sync
//   SegQueue<T>:   Send + Sync where T: Send
//   SlotMessage<M, K>: Send where M: Send + K: Send (bound on the impl)
```

### Slot internals (`src/driver/typed_slot.rs`)

```rust
// Before:
let mut buf = self.msg_buf.borrow_mut();
for ev in self.session_scratch.drain(..) {
    route_session_event(ev, parser_kind, &mut buf, lifecycle_out);
}
// route_session_event pushed into `buf.queue.push(...)`

// After:
for ev in self.session_scratch.drain(..) {
    route_session_event(ev, parser_kind, &self.msg_buf, lifecycle_out);
}
// route_session_event pushes into `msg_buf.push(SlotMessage{...})`
```

The slot field changes from
`msg_buf: Rc<RefCell<SlotBuf<P::Message, E::Key>>>` to
`msg_buf: Arc<SegQueue<SlotMessage<P::Message, E::Key>>>`.

### Usage (consumer code is unchanged)

```rust
use flowscope::driver::{Driver, SlotHandle, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot: SlotHandle<HttpMessage, FiveTupleKey> =
    builder.session_on_ports(HttpParser::default(), [80]);
let mut driver = builder.build();

let mut events = Vec::new();
let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

for view in views() {
    events.clear();
    driver.track_into(view, &mut events);
    http_msgs.clear();
    http_slot.drain(&mut http_msgs);
    // identical to 0.11
}
```

### What changes for multi-thread consumers

```rust
let mut builder = Driver::builder(FiveTuple::bidirectional());
let http_slot = builder.session_on_ports(HttpParser::default(), [80]);
let mut driver = builder.build();

// Clone the handle and move it to a tokio task:
let drainer_handle = http_slot.clone();
tokio::spawn(async move {
    let mut h = drainer_handle;
    let mut buf = Vec::new();
    loop {
        h.drain(&mut buf);
        // process buf, push to a channel, …
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
});

// Drive on this task:
for view in views() {
    driver.track_into(view, &mut events);
    // The drainer in the other task sees typed messages without
    // any LocalSet pinning.
}
```

## Implementation steps

1. **`Cargo.toml`**: add `crossbeam-queue = "0.3"` to
   `[dependencies]` (not optional; not feature-gated).
2. **`src/driver/slot.rs`**: rewrite per the API above. Drop the
   `SlotBuf<M, K>` type — replaced by direct `SegQueue<SlotMessage<M,
   K>>`. Tighten the generic bounds (`M: Send + 'static, K: Send +
   'static`).
3. **`src/driver/typed_slot.rs`**: update slot fields + the
   `route_session_event` helper to take
   `&Arc<SegQueue<SlotMessage<M, K>>>` instead of
   `&mut SlotBuf<M, K>`. The push site is `msg_buf.push(SlotMessage
   {...})` (no `borrow_mut` needed — SegQueue is lock-free).
4. **`src/driver/typed_slot_heuristic.rs`**: same as typed_slot.rs.
5. **Drop `Rc<RefCell>` imports** from the slot internals.
6. **Slot `force_close_into`** (added in 0.11.1): already
   composes with the new shape; just push into the SegQueue
   from the same path.
7. **Tests**:
   - Existing `tests/driver.rs::slot_handle_capacity_is_reused`
     becomes irrelevant (SegQueue doesn't expose a capacity
     concept). Replace with `slot_handle_drain_stable_steady_state`
     — assert allocator stays flat after warmup.
   - Add `tests/driver.rs::send_sync_assertions` via
     `static_assertions::assert_impl_all!`.
   - New `tests/driver_send.rs::cross_thread_drain_basic`
     — spawn a thread holding a cloned handle, drive the
     driver on the main thread, assert messages cross.
   - New `tests/driver_send.rs::competitive_consumer_clone_does_not_duplicate`
     — clone the handle into two consumers, push 1000 messages,
     drain from both, sum is exactly 1000 (no broadcast).
8. **Bench**: re-run `cargo bench --bench zero_alloc`. Confirm
   the 5-slot zero-alloc gate stays at 0.000 allocs/pkt
   steady-state. SegQueue may add a one-time block allocation
   during warmup (first 31 messages) but steady-state stays
   flat.
9. **CHANGELOG**: 0.12.0 entry. The migration recipe is two
   lines:
   > **0.12 break**: `SlotHandle<M, K>` is now `Send + Sync`.
   > Auto-trait inheritance differences are very unlikely to
   > surface; if your code asserts `!Send` on a SlotHandle,
   > update the bound.
10. **`docs/concepts.md`**: short note on the cost change for
    high-message-count drains (rare in practice).

## Tests

### Unit (in `src/driver/slot.rs`)

- `slot_handle_drain_basic`
- `slot_handle_drain_returns_count`
- `slot_handle_clear_drops_all`
- `slot_handle_clone_competitive_consumers`

### Integration (`tests/driver.rs` / `tests/driver_send.rs`)

- `static_assertions::assert_impl_all!(SlotHandle<u32, u32>: Send, Sync);`
- `cross_thread_drain_basic` — push from driver thread, drain
  from spawned thread.
- `competitive_consumer_clone_does_not_duplicate`.
- `mt_drainer_in_tokio_task_works` (gated on a `tokio` dev-dep
  if not too heavy; otherwise use `std::thread`).
- `pending_counts_are_consistent_under_concurrent_drain`.
- All existing `tests/driver.rs` tests continue to pass
  unchanged.

### Bench

- `benches/zero_alloc.rs::bench_track_into_with_slots_steady_state`
  — confirms 0.000 allocs/pkt after SegQueue warmup.

## Acceptance criteria

- `cargo build --all-features` clean.
- `cargo test --all-features` clean — all existing tests pass
  + the new Send/Sync ones.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 9 existing CI feature-matrix entries clean (no new
  matrix entry needed — no feature flag).
- `static_assertions::assert_impl_all!(SlotHandle<u32, FiveTupleKey>:
  Send, Sync);` compiles.
- `cargo bench --bench zero_alloc` confirms the 5-slot steady-
  state gate stays at 0.000 allocs/pkt.
- CHANGELOG 0.12.0 entry documents the `Send + Sync` transition.
- Migration verified: take one of netring's sharded-test code
  paths, port to the new shape, confirm it compiles and runs.

## Risks

- **R1: SegQueue allocator pressure on cold start.** SegQueue
  grows by ~31-item blocks; the first push allocates 1 block.
  Subsequent pushes within the block are alloc-free.
  Mitigation: bench warm-up already happens (existing pattern).
  If real-world traffic shows blocks being allocated faster
  than expected (e.g. >31 pending messages per slot per
  packet, which would be extremely unusual), fall back to
  `crossbeam_queue::ArrayQueue<N>` (bounded) with a per-slot
  capacity knob. Document under future-work-on-perf if it
  surfaces.
- **R2: Drain pattern cost difference.** O(n) pop loop instead
  of O(1) batch move. At >100 messages per drain (rare —
  typical netring drain is 0-2 messages per `track_into`),
  the loop adds ~1500 ns. Negligible at any sane drain
  cadence. Documented in rustdoc.
- **R3: `crossbeam-queue` always-on dep.** ~2 KB compiled
  weight, no transitive deps beyond `crossbeam-utils`. The
  weight is small relative to flowscope's existing
  `etherparse` / `bytes` / `httparse` / etc. Accepted cost
  for the API simplification.
- **R4: `!Send` → `Send` auto-trait break.** Theoretical.
  No shipped consumer code is known to assert `!Send` on
  `SlotHandle`. CHANGELOG covers the recipe; pre-1.0 we ship.
- **R5: Clone-as-competitive surprise.** Documented in
  rustdoc + concepts. Single-consumer (no clone) stays the
  default path; doesn't require the user to learn anything new.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `slot.rs` rewrite | 100 | 3 |
| `typed_slot.rs` field + write-site update | 50 | 2 |
| `typed_slot_heuristic.rs` field + write-site update | 50 | 2 |
| `Cargo.toml` + `force_close_into` compose | 10 | 0.5 |
| Tests (8 unit + integration) | 200 | 4 |
| Bench verification | 20 | 1 |
| CHANGELOG + concepts docs | 30 | 1 |
| **Total** | **~460** | **~14 hours (~2 days)** |

The consolidation is *less* code than the feature-gated mt
variant (~860 LoC) because nothing is duplicated. ~2 days
of work, half-day faster than the original 3-day estimate.

## Provenance

Triggered by netring 0.21 Phase C (per-CPU sharding) +
multi-thread tokio runtime ask. flowscope 0.11.0's
`SlotHandle<M, K>` is `Rc<RefCell>`-backed and intentionally
`!Send`. 0.11 INDEX's "Deferred items" listed Send slot
handles as "revisit when a consumer needs a Send variant."
netring 0.21 is that consumer.

**Why this differs from the wishlist's proposal** (`mt`
feature flag + `MtSlotHandle`): the duplicated-types approach
adds ~860 LoC, two matrix entries, and a feature flag for a
~10 ns/emit saving that's negligible at netring's traffic
rates. Consolidating to one always-Send shape ships ~460 LoC,
zero new matrix entries, and a unified API. The per-emit
cost difference at 1 Mpps × 10% L7 = 100k slot writes/sec ×
~5 ns extra = 500 µs/sec = 0.05% of a core. The cost is
real but invisible.
