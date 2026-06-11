# Plan 150 — `BroadcastSlotHandle<M, K>`: built-in fan-out

## Summary

Ship a `BroadcastSlotHandle<M, K>` sibling of `SlotHandle<M, K>`
where `Clone` produces a subscriber that sees **every** message
(not a competitive consumer). Push fans out to every live
subscriber. Backed by `Arc<BroadcastInner>` holding
`Mutex<Vec<Weak<SegQueue<...>>>>` of per-subscriber queues.

## Status

Not started. P1 for 0.13.

## Prerequisites

- Plan 149 (`drain_n` + `SlotBuf`) — broadcast subscribers
  benefit from bounded drain.

## Out of scope

- **Latching the last message.** No "last value cache" for late
  subscribers.
- **Cross-subscriber back-pressure.** Each subscriber's queue
  grows independently. Cap externally via `drain_n` from plan 149.
- **Subscriber registration after first push hot-path.** Allowed,
  but subscribers added later see only messages from registration
  forward.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/driver/broadcast.rs` | `BroadcastSlotHandle<M, K>` + `BroadcastInner` |
| Modify | `src/driver/mod.rs` | `pub use broadcast::BroadcastSlotHandle;` |
| Modify | `src/driver/typed.rs` | `DriverBuilder::session_on_ports_broadcast`, `datagram_on_ports_broadcast`, `session_heuristic_broadcast` |
| Modify | `src/driver/typed_slot.rs` | Broadcast push variants on typed slots |
| New | `tests/driver_broadcast.rs` | Cross-thread broadcast tests |
| New | `examples/00-getting-started/broadcast_demo.rs` | Showcase |

## API

```rust
// src/driver/broadcast.rs
use std::sync::{Arc, Mutex, Weak};
use crossbeam_queue::SegQueue;
use crate::driver::SlotMessage;

pub struct BroadcastSlotHandle<M, K>
where M: Send + Clone + 'static, K: Send + Clone + 'static {
    inner: Arc<BroadcastInner<M, K>>,
    my_queue: Arc<SegQueue<SlotMessage<M, K>>>,
    parser_kind: &'static str,
}

pub(super) struct BroadcastInner<M, K>
where M: Send + Clone + 'static, K: Send + Clone + 'static {
    subscribers: Mutex<Vec<Weak<SegQueue<SlotMessage<M, K>>>>>,
}

impl<M, K> BroadcastSlotHandle<M, K>
where M: Send + Clone + 'static, K: Send + Clone + 'static {
    /// Drain all messages this subscriber has received.
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize { … }

    /// Bounded variant.
    pub fn drain_n(&mut self, out: &mut Vec<SlotMessage<M, K>>, max: usize) -> usize { … }

    /// Pending message count for this subscriber.
    pub fn pending(&self) -> usize { self.my_queue.len() }

    /// Active subscriber count (best-effort; reads under a Mutex).
    pub fn subscribers(&self) -> usize { … }

    /// Parser-kind slug from registration.
    pub fn parser_kind(&self) -> &'static str { self.parser_kind }
}

impl<M, K> Clone for BroadcastSlotHandle<M, K>
where M: Send + Clone + 'static, K: Send + Clone + 'static {
    /// New subscriber: gets its own queue inside the broadcast
    /// set. Subsequent pushes go to every live queue.
    fn clone(&self) -> Self {
        let my_queue = Arc::new(SegQueue::new());
        self.inner.subscribers.lock().unwrap().push(Arc::downgrade(&my_queue));
        Self { inner: Arc::clone(&self.inner), my_queue, parser_kind: self.parser_kind }
    }
}

impl<M, K> Drop for BroadcastSlotHandle<M, K>
where M: Send + Clone + 'static, K: Send + Clone + 'static {
    fn drop(&mut self) {
        // Best-effort prune of Weak entries that no longer upgrade.
        if let Ok(mut subs) = self.inner.subscribers.try_lock() {
            subs.retain(|w| w.strong_count() > 0);
        }
    }
}
```

Builder variants:

```rust
impl<E: FlowExtractor> DriverBuilder<E> {
    /// Register a session parser whose typed messages broadcast
    /// to every clone of the returned handle. Each clone sees
    /// every message; messages are cloned on push.
    pub fn session_on_ports_broadcast<P>(
        &mut self,
        parser: P,
        ports: impl Into<smallvec::SmallVec<[u16; 4]>>,
    ) -> BroadcastSlotHandle<P::Message, E::Key>
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + Clone + 'static,
        E::Key: Send + Clone + 'static,
    { … }

    // datagram_on_ports_broadcast, session_heuristic_broadcast — analogous
}
```

## Implementation steps

1. Implement `BroadcastInner` with `Mutex<Vec<Weak<...>>>`.
2. Implement `BroadcastSlotHandle::push` (private; called by the
   typed slot's broadcast variant). Iterates the subscriber
   list, upgrades each `Weak` to `Arc`, pushes the cloned
   message, prunes dead entries inline.
3. Implement `drain` / `drain_n` / `pending` over the per-
   subscriber queue.
4. Implement `Clone` (adds subscriber) and `Drop` (prune).
5. Add the three `*_broadcast` builder methods.
6. Cross-thread tests: 1 producer + N consumers, each drain
   sees the same message count.

## Tests

- `broadcast_two_subscribers_both_see_every_message`.
- `broadcast_subscriber_dropped_is_pruned`.
- `broadcast_late_subscriber_misses_pre_registration_messages`.
- `broadcast_clone_produces_distinct_queue`.
- `broadcast_push_with_zero_subscribers_is_noop_no_alloc`.
- `broadcast_send_assertion` — compile-time
  `assert_impl_all!(BroadcastSlotHandle<u32, u8>: Send + Sync)`.

## Acceptance criteria

- `cargo test --all-features` clean.
- Bench: push cost scales linearly with subscriber count;
  zero-subscriber push is allocation-free past initial setup.
- netring 0.21 Phase F (`monitor.subscribe::<E>`) becomes a thin
  wrapper over `BroadcastSlotHandle<E::Payload, FiveTupleKey>`.

## Risks

**R1: `M: Clone` bound is new.** Existing parser messages
(`HttpMessage`, `DnsMessage`, `TlsMessage`) are already `Clone`
(Bytes underneath). Verify via static_assertion in tests.
Documented constraint.

**R2: Mutex on every push.** Lock contention with concurrent
registration. For the typical case (subscribers register at
startup, then push hot loop only iterates), this is fine.
Mitigation: if profiling shows contention, swap to `ArcSwap` in
a follow-up; the API stays unchanged.

**R3: Memory growth.** Slow subscriber → unbounded queue growth.
Mitigation: consumers use `drain_n` from plan 149 to cap and
observe `pending()` for back-pressure.

## Effort

- LOC delta: +500.
- Time estimate: **2 days**.

## Provenance

Wishlist plan 150. Design matches the wishlist; ship as
proposed.
