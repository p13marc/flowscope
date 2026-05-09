# Plan 41 — Performance foundations (flowscope hot-cache)

## Summary

A single targeted optimization on flowscope's tracker: a "last flow
seen" hot cache that skips the LRU lookup when consecutive packets
belong to the same flow. ~50 LOC, no API impact, measurable win on
monoflow workloads (single iperf3 stream, single HTTP/2 connection,
etc.).

The original Plan 41 draft also covered a `BytesMut` pool
optimization in netring's `flow_stream` async adapter — that lives
in netring's repo, not flowscope's, so it has been moved out of
this plan. See "Companion work in netring" below.

## Status

Not started.

## Prerequisites

- Some form of profiling/micro-bench so the hot-cache win can be
  measured. Ad-hoc local profiling against a synthetic monoflow pcap
  is enough; doesn't need a full criterion harness.

## Out of scope

- SIMD acceleration of header parsing (would warrant its own plan).
- Replacing `LruCache` with a lock-free / shard-by-key flow table.
  Worth considering only if profiling points to lookup contention,
  which it currently doesn't.
- AF_XDP zero-copy frame ownership for flow tracking. Lives in
  netring; separate plan; needs aya / xsk-rs evolution first.
- The `BytesMut` pool optimization for netring's async reassembler
  path (was Part A of the original plan; see below).

---

## The hot cache

### Cost we're paying

Today every `FlowTracker::track` call does:

```rust
let key = extractor.extract(view).key;
let entry = self.flows.get_mut(&key);  // LruCache lookup
```

For monoflow workloads (a single iperf3 stream saturating a link, a
single HTTP/2 connection, a single long-lived TLS tunnel) every
packet has the **same** key. The lookup is ~50 ns per packet —
redundant when consecutive packets share a key.

Suricata profiles this; their fix is a per-thread "last flow seen"
pointer. We borrow the same idea.

### Fix — sticky reference

Add a hot-cache field to `FlowTracker`:

```rust
pub struct FlowTracker<E: FlowExtractor, S = ()> {
    extractor: E,
    flows: LruCache<E::Key, FlowEntry<S>, RandomState>,
    config: FlowTrackerConfig,
    stats: FlowTrackerStats,
    init: StateInit<E::Key, S>,
    /// New: most recently accessed key. Skips the LruCache lookup
    /// (and the LRU promotion that follows) when the same key
    /// reappears immediately. Cleared on `Ended`/`Evicted`/`forget`.
    hot: Option<E::Key>,
}
```

`track_with_payload` becomes:

```rust
let key = match self.extractor.extract(view) {
    Some(e) => e.key,
    None => { self.stats.packets_unmatched += 1; return events; }
};
let entry = if Some(&key) == self.hot.as_ref() {
    // Fast path — key matches the cached one. Skip LRU lookup
    // entirely; entry is by definition the LRU front for this key
    // (we just touched it last call).
    self.flows.get_mut(&key).expect("hot key must exist")
} else {
    self.hot = Some(key.clone());
    self.flows.get_or_insert_mut(&key, /* ... */)
};
// ... existing logic continues with `entry` ...
```

### Hot-cache invalidation

Three places clear `hot`:

1. **End-of-flow.** When a flow ends (`Fin`/`Rst`/`IdleTimeout`/
   `Evicted`/`BufferOverflow`), if `hot == Some(key)`, set
   `hot = None`.
2. **Eviction.** Same condition — handled by the Ended path.
3. **`FlowTracker::forget(&K)`** — Plan 42's new accessor; also
   clears `hot` if it points to the forgotten key.

### Estimated win

- Monoflow workload (1 active flow): ~2× throughput on `track`.
- Two-flow workload (alternating packets): ~0.95× — slight
  pessimization from the failed hot-check. Real-world traffic is
  bursty per flow, so this is rare in practice.
- Heterogeneous (1000+ flows, even mix): ~1.05–1.1× — small win
  from the per-burst stickiness.

### API impact

Zero. Field is `pub(crate)`; behaviour is observably identical.

---

## Companion work in netring (not in this plan)

The `BytesMut`-pool optimization (one alloc per kernel-batch
instead of one alloc per TCP segment) lives in netring's
`async_adapters/flow_stream.rs`. It is the bigger throughput win
(estimated 1.5–2.5× on TCP-heavy workloads) but is netring's
problem, not flowscope's.

When picking that up, file it as `netring/plans/NN-bytes-pool.md`
and cross-link from netring's CHANGELOG. The `AsyncReassembler::segment`
trait already takes `Bytes`; the optimization is purely about how
that `Bytes` is sourced.

---

## Files

### MODIFIED

- `src/tracker.rs` — `hot: Option<E::Key>` field + fast-path branch
  in `track_with_payload` + invalidation in the eviction/Ended
  paths.
- `docs/PERFORMANCE.md` — new file documenting the methodology +
  before/after numbers for the hot-cache.

### NEW

None.

---

## Implementation steps

1. **Capture a baseline** with whatever profiler / micro-bench you
   prefer (`perf stat`, `flamegraph`, `criterion` ad-hoc, `hyperfine`
   wrapping `pcap-driven` replay). Document inline in PERFORMANCE.md
   the methodology + numbers — what workload, what hardware, what
   compile flags.
2. **Land the hot-cache** in `src/tracker.rs`. Single new field, two
   new branches (fast path, invalidation).
3. **Re-measure**; document the delta.
4. **Property test** that the event stream is identical with the
   hot-cache enabled vs. a `cfg!(feature = "no-hot-cache")` fork.
   Add to `tests/proptest_invariants.rs`.

---

## Tests

- All existing tests pass after the change. The hot cache changes
  only the lookup mechanism, not the events emitted.
- New proptest: random sequences of (key, packet) pairs from a pool
  of 4 keys; assert that the `Vec<FlowEvent<K>>` produced with the
  hot cache matches the `Vec<FlowEvent<K>>` produced when forced to
  always take the slow path. Use a `cfg(test)`-gated method like
  `set_hot_cache_enabled(bool)` to test both branches from one
  binary.

---

## Acceptance criteria

- [ ] Hot-cache fast path implemented; baseline benchmark exists in
      `docs/PERFORMANCE.md`.
- [ ] Measurable throughput gain on monoflow workload (target ≥10%;
      stretch goal ≥50% — the original draft estimated 2×).
- [ ] Proptest verifies identical event sequences across enabled /
      disabled.
- [ ] No regression on existing tests.
- [ ] PERFORMANCE.md has the numbers (workload, hardware, before /
      after, methodology).
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Wrong fast-path on tail of bidirectional flow.** Initiator
   then responder packets share the same key in bidirectional mode
   — verified, fast-path wins.
2. **Hot-key invalidation correctness.** Three invalidation sites
   (Ended, Evicted, forget). Easy to miss one; the proptest catches
   that case (a key whose entry was removed but whose `hot` slot
   wasn't would trigger an `expect("hot key must exist")` panic).
3. **`E::Key: Clone` cost.** The fast path's miss branch clones the
   key into `hot`. For `FiveTuple` (the canonical key) `Clone` is a
   trivial 24-byte copy. For larger custom keys the clone may matter
   — but no worse than the LRU's existing requirement that keys be
   cheap to hash + compare.
4. **Code complexity.** ~50 LOC. Trivial.

---

## Effort

- LOC: ~50.
- Time: 1 day (½ day implementation + ½ day benchmarking + writing
  PERFORMANCE.md).

---

## Provenance

This plan was originally a two-part scope: Part A (BytesMut pool
in `flow_stream`) and Part B (hot-cache in `FlowTracker`). Part A
lives in netring (which owns `flow_stream.rs`), not flowscope, and
has been moved to a netring-side plan. This file now covers Part B
only.
