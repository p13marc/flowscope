# Plan 122 — `mt` feature: `Send + Sync` `MtSlotHandle`

## Summary

Opt-in `mt` Cargo feature that adds `MtSlotHandle<M, K>` —
a `Send + Sync` counterpart to today's `SlotHandle<M, K>` —
backed by `Arc<crossbeam_queue::SegQueue<SlotMessage<M, K>>>`
instead of `Rc<RefCell<SlotBuf<M, K>>>`. Same surface
(`drain`, `pending`, `parser_kind`, `clear`); different
thread-safety guarantees. Selected at builder time via a new
`DriverBuilder::mt()` finalizer that promotes the builder to
its multi-thread variant.

Default single-thread path (Rc/RefCell, ~1–2 ns per emit) is
unchanged. Multi-thread users pay ~5–10 ns per emit for the
SegQueue MPMC push/pop, in exchange for `Send + Sync` on the
handle.

## Status

Not started.

## Prerequisites

None — self-contained in `src/driver/`.

## Out of scope

- **No tokio types.** Hard rule. `flowscope` stays runtime-free;
  the `mt` feature pulls only `crossbeam-queue`, no async deps.
- **The `Driver<E>` itself stays `!Send`.** The central
  tracker (`FlowTracker<E>`) holds `Rc<RefCell>` internals;
  making the whole driver `Send` is multi-day work (deferred,
  see plan 118 era D2 / open items). Only the **handle** side
  is `Send` — drain on any thread, run the driver on one
  thread.
- **No `Mutex` fallback.** If `crossbeam-queue` isn't
  available the feature doesn't compile. Mutex-backed
  alternative was rejected at the 0.11 reanalysis pass —
  ~5% of a core at 1 Mpps × 5 slots is the wrong perf
  tradeoff.
- **No broadcast clone semantics.** `MtSlotHandle::clone` hands
  out a second *competitive* consumer (race for messages) —
  matches the underlying SegQueue MPMC contract. Document this
  explicitly.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/driver/mt_slot.rs` | `MtSlotHandle<M, K>`; `MtSlotBuf<M, K>` internal type |
| New | `src/driver/mt_typed.rs` | `MtDriverBuilder<E>` mirror of `DriverBuilder<E>` returning `MtSlotHandle` |
| New | `src/driver/mt_typed_slot.rs` | `MtConcreteSlot` / `MtConcreteDatagramSlot` / `MtHeuristic*Slot` impls (clones of typed_slot.* but writing into `Arc<SegQueue>`) |
| Modify | `src/driver/typed.rs` | Add `pub fn mt(self) -> MtDriverBuilder<E>` finalizer (cfg-gated) |
| Modify | `src/driver/mod.rs` | `#[cfg(feature = "mt")] mod mt_slot;` etc.; re-export `MtSlotHandle`, `MtDriverBuilder` |
| Modify | `Cargo.toml` | `crossbeam-queue = { version = "0.3", optional = true }`; `mt = ["dep:crossbeam-queue"]` |
| Modify | `src/lib.rs` | `#[cfg(feature = "mt")] pub use driver::{MtSlotHandle, MtDriverBuilder};` |
| New | `tests/driver_mt.rs` | `Send + Sync` static-asserts; cross-thread drain integration |
| Modify | `.github/workflows/rust.yml` | Add `mt` to the feature-matrix entries |

## API

### `MtSlotHandle<M, K>` (gated on `feature = "mt"`)

```rust
// src/driver/mt_slot.rs
use std::sync::Arc;

use crossbeam_queue::SegQueue;

use crate::driver::slot::SlotMessage;

/// `Send + Sync` slot handle. Backed by
/// `Arc<crossbeam_queue::SegQueue<SlotMessage<M, K>>>` — a
/// lock-free MPMC queue.
///
/// Use this when the slot handle must cross task / thread
/// boundaries (per-CPU sharding, multi-thread tokio runtime).
/// For single-threaded consumers, [`crate::driver::SlotHandle`]
/// is ~3x cheaper per emit.
///
/// # Cloning
///
/// `Clone` hands out a second **competitive consumer** — both
/// drain from the same SegQueue and race for messages. Only
/// clone if you want a competitive read pattern; for a
/// broadcast pattern, drain into a channel + fan out yourself.
pub struct MtSlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    pub(super) inner: Arc<SegQueue<SlotMessage<M, K>>>,
    pub(super) parser_kind: &'static str,
}

impl<M, K> MtSlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    /// Drain all currently-queued messages into `out`. Returns
    /// the count drained. Lock-free.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.inner.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }

    pub fn pending(&self) -> usize {
        self.inner.len()
    }
    pub fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }
    pub fn clear(&mut self) {
        while self.inner.pop().is_some() {}
    }
}

impl<M, K> Clone for MtSlotHandle<M, K>
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

// Send + Sync follow automatically because Arc<SegQueue<T>>:
//   - Arc<T>: Send + Sync where T: Send + Sync
//   - SegQueue<T>: Send + Sync where T: Send
// SlotMessage<M, K>: Send when M: Send + K: Send (already guaranteed).
```

### `MtDriverBuilder<E>` (gated on `feature = "mt"`)

```rust
// src/driver/mt_typed.rs

/// Multi-thread variant of [`crate::driver::DriverBuilder`].
/// Mirrors the non-mt builder's surface but every
/// `session_*` / `datagram_*` call returns
/// [`MtSlotHandle`] instead of `SlotHandle`. The built
/// `Driver<E>` is unchanged; only the slot internals + handle
/// representation differ.
pub struct MtDriverBuilder<E>
where
    E: FlowExtractor,
    E::Key: Send + 'static,
{ /* … same field shape as DriverBuilder<E> with Arc<SegQueue>-backed slots … */ }

impl<E> MtDriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    pub fn config(&mut self, c: FlowTrackerConfig) -> &mut Self;
    pub fn monotonic_timestamps(&mut self, on: bool) -> &mut Self;
    pub fn emit_anomalies(&mut self, on: bool) -> &mut Self;
    pub fn emit_packet_details(&mut self, on: bool) -> &mut Self;
    pub fn dedup(&mut self, d: Dedup) -> &mut Self;
    pub fn idle_timeout_fn<F>(&mut self, f: F) -> &mut Self
    where F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + 'static;

    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> MtSlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone, I: IntoIterator<Item = u16>,
          P::Message: Send + 'static;
    pub fn session_broadcast<P>(&mut self, parser: P) -> MtSlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone, P::Message: Send + 'static;
    pub fn session_heuristic<P>(&mut self, parser: P, sig: SignatureFn) -> MtSlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone, P::Message: Send + 'static;

    pub fn datagram_on_ports<D, I>(&mut self, parser: D, ports: I) -> MtSlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone, I: IntoIterator<Item = u16>,
          D::Message: Send + 'static;
    pub fn datagram_broadcast<D>(&mut self, parser: D) -> MtSlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone, D::Message: Send + 'static;
    pub fn datagram_heuristic<D>(&mut self, parser: D, sig: SignatureFn) -> MtSlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone, D::Message: Send + 'static;

    pub fn build(self) -> Driver<E>;
}
```

### Finalizer on the existing `DriverBuilder<E>`

```rust
// src/driver/typed.rs
impl<E> DriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    /// Promote this builder to its multi-thread variant. Call
    /// before registering any slots (the existing slots, if any,
    /// would be `Rc`-backed and can't be ported across).
    #[cfg(feature = "mt")]
    pub fn mt(self) -> MtDriverBuilder<E> { … }
}
```

### Usage

```rust
#[cfg(feature = "mt")]
fn shard() {
    use flowscope::driver::{Driver, MtSlotHandle};
    use flowscope::extract::{FiveTuple, FiveTupleKey};
    use flowscope::http::{HttpMessage, HttpParser};

    let mut builder = Driver::builder(FiveTuple::bidirectional()).mt();
    let http_slot: MtSlotHandle<HttpMessage, FiveTupleKey> =
        builder.session_on_ports(HttpParser::default(), [80]);
    let mut driver = builder.build();

    let cloned_handle = http_slot.clone(); // Send across thread boundary
    std::thread::spawn(move || {
        let mut h = cloned_handle;
        let mut buf = Vec::new();
        loop {
            h.drain(&mut buf);
            // process buf …
        }
    });

    // Drive on this thread.
    for view in views() {
        let mut lifecycle = Vec::new();
        driver.track_into(view, &mut lifecycle);
        // … (drainers on other thread pull the typed messages)
    }
}
```

## Implementation steps

1. **Cargo.toml**: add the dependency + feature gate. Verify
   `cargo build --features mt` compiles with empty `mt_*`
   stubs.
2. **`src/driver/mt_slot.rs`**: define `MtSlotHandle<M, K>` with
   `drain` / `pending` / `clear` / `parser_kind`. Include the
   `Send + Sync` impl (auto). Internal `MtSlotBuf<M, K>` is just
   a `pub(super)` newtype over `Arc<SegQueue<SlotMessage<M, K>>>`.
3. **`src/driver/mt_typed_slot.rs`**: clone the structure of
   `typed_slot.rs` + `typed_slot_heuristic.rs` with the slot
   internals writing into `MtSlotBuf` (`SegQueue::push`) instead
   of `RefCell::borrow_mut().queue.push`. Same `route_session_event`
   shape, different terminal write.
4. **`src/driver/mt_typed.rs`**: mirror the `DriverBuilder<E>` +
   `Driver<E>` impl from `typed.rs`. The `Driver<E>` itself is
   unchanged — only the *slot construction* path differs. So
   `MtDriverBuilder::build()` returns the same `Driver<E>`,
   carrying `Vec<Box<dyn ErasedSlot<E::Key>>>` populated with
   `MtConcreteSlot` etc.
5. **`src/driver/typed.rs`**: add the `mt()` finalizer that
   moves the builder's state into `MtDriverBuilder<E>`.
6. **`src/driver/mod.rs`** + **`src/lib.rs`**: re-export
   `MtSlotHandle` and `MtDriverBuilder` behind the feature.
7. **`tests/driver_mt.rs`**:
   - `static_assertions::assert_impl_all!(MtSlotHandle<u32, u32>: Send, Sync);`
   - `cross_thread_drain_basic` — spawn a thread holding a
     cloned handle; drive the driver on the main thread; assert
     all messages arrive.
   - `pending_counts_correctly_under_concurrent_drain` —
     push 1000 messages from the driver thread, drain
     concurrently from N threads, assert sum.
8. **`.github/workflows/rust.yml`**: add `"mt"` and
   `"mt,l7,pcap"` matrix entries.
9. **CHANGELOG** + **`docs/migration-0.11-to-0.12.md`** entry —
   migration is one-line (add `.mt()` after `builder()`).
10. **`docs/concepts.md`**: short section on single-thread vs
    multi-thread handles and the cost tradeoff.
11. **Bench addition**:
    `benches/zero_alloc.rs::bench_mt_track_into_with_5_http_slots`
    — verify steady-state allocation pressure. Expected: ~0
    allocs in steady state once SegQueue blocks have been
    allocated.

## Tests

### Unit (in `src/driver/mt_slot.rs`)

- `drain_returns_pushed_in_order`
- `pending_counts_under_pushes`
- `clear_empties_queue`
- `clone_yields_competitive_consumers`

### Integration (`tests/driver_mt.rs`)

- `send_sync_assertions`
- `cross_thread_drain_basic`
- `pending_counts_correctly_under_concurrent_drain`
- `mt_driver_equivalent_to_st_for_offline_pcap` — drive the
  same fixture pcap through both `Driver` shapes; compare the
  set of typed messages (order may differ across drainers but
  the set must match).

### Bench

- `benches/zero_alloc.rs::bench_mt_track_into_with_5_http_slots`
  — measures alloc/packet at the mt surface. Target: same
  0.000 allocs/packet steady-state as the non-mt path, modulo
  one-time SegQueue block initialisation.

## Acceptance criteria

- `cargo build --features mt` clean.
- `cargo test --features mt` clean.
- `cargo clippy --features mt --all-targets -- -D warnings` clean.
- `cargo doc --features mt --no-deps` zero warnings.
- New `mt` and `mt,l7,pcap` CI matrix entries clean.
- `static_assertions::assert_impl_all!(MtSlotHandle<u32, u32>: Send, Sync);`
  compiles.
- `cargo bench --bench zero_alloc --features mt,l7,...`
  hits ≤ 0.5 allocs/packet steady-state for the 5-slot
  `mt` configuration.
- Migration guide entry shows the one-line `.mt()` call.

## Risks

- **R1: SegQueue allocator pressure.** SegQueue internally
  grows by linked-list blocks (~8 entries per block). For true
  zero-alloc steady state, we need pushes to reuse freed
  blocks. Mitigation: bench harness catches this. Fallback if
  the data shows real per-message allocations: switch to
  `ArrayQueue<N>` with a per-slot capacity knob.
- **R2: `Clone` competitive-consumer semantics surprise
  consumers.** Document explicitly in rustdoc. The single-
  consumer case (one handle, no clones) is the common path.
- **R3: Code duplication between typed_slot.rs and
  mt_typed_slot.rs.** Mostly mechanical. A future refactor
  could parameterise the slot impls over a `MsgSink` trait
  (one impl `Rc<RefCell>`, one impl `Arc<SegQueue>`) — defer
  unless the duplicated code becomes a maintenance burden.
- **R4: SegQueue is Send + Sync only when `T: Send`.** All
  our `SlotMessage<M, K>` types are Send when `M: Send` +
  `K: Send`. The bound on `MtSlotHandle<M, K>` enforces both —
  catches any future type that wouldn't compose.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `mt_slot.rs` | 150 | 4 |
| `mt_typed_slot.rs` | 250 | 6 |
| `mt_typed.rs` | 200 | 5 |
| `typed.rs` `.mt()` finalizer | 20 | 1 |
| `mod.rs` + `lib.rs` re-exports | 10 | 0.5 |
| Cargo.toml + CI matrix | 10 | 0.5 |
| Tests + assertions | 120 | 4 |
| Bench addition | 40 | 1.5 |
| CHANGELOG + migration + concepts docs | 60 | 1.5 |
| **Total** | **~860** | **~24 hours (3 days)** |

## Provenance

Triggered by netring 0.21 Phase C (per-CPU sharding) +
multi-thread tokio runtime ask. flowscope 0.11.0's
`SlotHandle<M, K>` is `Rc<RefCell>`-backed and intentionally
`!Send` (CHANGELOG explicitly documents this). 0.11 INDEX's
"Deferred items" listed Send slot handles as "revisit when a
consumer needs a Send variant" — netring 0.21 is now that
consumer.
