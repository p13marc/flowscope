# Plan 155 — Sharded-driver recipe + example

## Summary

Pure documentation + example. Shows how to drive N
`Driver<E>` instances on N OS threads, each with its own
`SlotHandle` drained from a worker. After plan 156 lands,
`Driver<E>: Send` makes this straightforward with `std::thread`
(or tokio multi-thread); the example demonstrates the pattern
without prescribing a runtime.

## Status

Not started. P3 for 0.13.

## Prerequisites

- Plan 156 (`Driver<E>: Send` unconditionally).
- Plan 149 (`drain_n` for back-pressure).

## Out of scope

- **A `flowscope::sharded::*` module.** No library code; pure
  recipe.
- **Cross-shard correlation.** Each shard is independent.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `examples/00-getting-started/sharded_capture.rs` | N-thread sharded driver example |
| New | `docs/recipes/sharded.md` | Recipe with architecture overview + FAQ |
| Modify | `docs/concepts.md` | Cross-reference to the recipe |
| Modify | `examples/README.md` | Catalogue row |

## Implementation steps

1. Write the example showing:
   - One `Driver<FiveTuple>` per shard (one per CPU).
   - Each shard's `SlotHandle<HttpMessage, FiveTupleKey>`
     drained inside a worker thread.
   - Cross-shard counter merge via `Arc<AtomicU64>`.
   - Bounded drain via `drain_n` from plan 149.
2. Recipe doc covering:
   - When sharding helps (multi-Gbps capture; CPU-bound parsing).
   - When it hurts (low-volume, single-flow workloads — overhead
     of cross-thread dispatch).
   - Pinning shards to specific CPUs via `core_affinity`
     (mentioned, optional; example doesn't depend on it).
3. Cross-reference from `docs/concepts.md`.

## Tests

- `cargo build --example sharded_capture` succeeds.
- `cargo run --example sharded_capture -- trace.pcap` runs end-
  to-end on the bundled `tests/data/mixed_short.pcap` fixture.

## Acceptance criteria

- Example runs.
- Recipe reads cleanly + answers "when do I shard."
- netring 0.21 Phase C docs can link to `docs/recipes/sharded.md`.

## Risks

None significant. Pure docs + example.

## Effort

- LOC delta: +400 (example + docs).
- Time estimate: **1 day**.

## Provenance

Wishlist plan 155.
