# Performance

flowscope ships a criterion-driven bench harness under
[`benches/`](../benches). Each group exercises one layer of the
pipeline so future perf work has a baseline to regression-test
against.

This document is the methodology. Numbers are point-in-time
snapshots — re-run locally on your target hardware before
treating them as gospel.

## Running

```sh
cargo bench --all-features                       # all groups
cargo bench --all-features --bench tracker       # one group
cargo bench --all-features --bench reassembler   # ...
```

criterion writes HTML reports to `target/criterion/`. Open
`target/criterion/index.html` to compare runs side by side.

## What's measured

| Bench group | What it covers |
|-------------|----------------|
| `extractor` | `FiveTuple` parsing over IPv4 TCP / IPv4 UDP. The floor every other layer pays. |
| `tracker` | `FlowTracker::track` for varying flow-table sizes — validates the hot-cache fast path. |
| `reassembler` | `BufferedReassembler::segment` for in-order, capped (sliding-window), gap-skipping and stopped (`DropFlow`) cases. |
| `session_driver` | End-to-end typed `Driver<E>` session slot with a no-op parser — the shared session engine, with its default `SegmentBufferReassembler`. |
| `dedup` | `Dedup` content-hash + lookup over typical and MTU-sized frames. |
| `zero_alloc` | Allocation-counting harness: prints `allocs/iter` / `bytes/iter` for `track_into` (with and without slots), parser feeds, HTTP / DNS / TLS parses. |

Each `bench_function` measures one hot-path call; criterion
iterates ~5 seconds with statistical analysis. Throughput is
reported in nanoseconds per call — multiply by your
packets-per-second target to estimate CPU load.

## Baseline (0.3.0 snapshot)

Measured on a developer workstation (x86_64 Linux, stable Rust,
`--release`). **Relationships matter more than absolutes** — your
hardware will differ.

### Extractor

| Bench | Time / call |
|-------|-------------|
| `extractor/five_tuple_ipv4_tcp` | ~115 ns |
| `extractor/five_tuple_ipv4_udp` | ~110 ns |

`FiveTuple` parsing is the floor every other layer pays. Modern
x86 does ~9M parses / sec / core.

### Tracker (hot-cache fast path)

| Bench | Time / call | vs monoflow |
|-------|-------------|-------------|
| `tracker/monoflow` | ~315 ns | 1.00× |
| `tracker/n_flows/10` | ~330 ns | 1.05× |
| `tracker/n_flows/100` | ~340 ns | 1.08× |
| `tracker/n_flows/1000` | ~375 ns | 1.19× |
| `tracker/n_flows/10000` | ~450 ns | 1.43× |

The hot-cache fast path is observable: monoflow is ~43% faster
than 10k-flow round-robin where every packet misses. Real-world
traffic is bursty per flow, so per-burst stickiness recovers most
of the win on heterogeneous workloads.

### Reassembler

| Bench | Time / call |
|-------|-------------|
| `reassembler/in_order_1500_uncapped` | ~87 ns |
| `reassembler/in_order_1500_capped_1m` | ~87 ns |
| `reassembler/sliding_window_overflow` | ~50–100 ns (varies) |
| `reassembler/drop_flow_poisoned` | ~5 ns |

The cap check costs nothing measurable on the under-cap hot path
— design goal met. The stopped-reassembler path (a side stopped by
`OverflowPolicy::DropFlow`; the bench keeps its historical
`_poisoned` name) is essentially free (flag check + early return)
because the segment is dropped without buffer manipulation.
`reassembler/gap_skips` (new in 0.25, no 0.3.0 figure) measures a
hole being skipped and reported on every segment, drained into
`StreamChunks` as a session engine does.

The session engines use `SegmentBufferReassembler`. On its hot path
an in-order segment is not buffered at all
(`Reassembler::segment_into` returns `SegmentOutcome::Passthrough`
and the engine hands the bytes to the parser straight from the
frame); out-of-order data is kept as coalescing pieces with
O(log n + k) insertion, so even the adversarial one-byte ascending
case above a hole stays linear.

### Dedup

| Bench | Time / call | What it measures |
|-------|-------------|------------------|
| `dedup/unique_64` | ~860 ns | Small-frame hash + lookup |
| `dedup/unique_1500` | ~1.2 µs | Typical-MTU hash + lookup |
| `dedup/duplicate_1500` | ~1.2 µs | Match-and-drop path |

Most of the cost is the `ahash` of the frame bytes. For loopback
captures at ~1 Gbps with 1500-byte MTU (~80k pps), that's ~80k ×
1.2 µs = ~100 ms/sec of CPU — about 10% of one core. Acceptable
for the bug class it prevents.

### Session driver

| Bench | Time / call |
|-------|-------------|
| `session_driver/passthrough` | ~500–800 ns |

End-to-end typed `Driver<E>` with a single session slot and a no-op
`SessionParser`. Dominated by tracker + reassembler dispatch + the
per-side drain loop. (0.3.0 figure; the 0.25 engine is faster — see
the comparison below.)

## Allocations (measured)

`tests/alloc_steady_state.rs` counts heap blocks on the real path —
the typed `Driver` and `SessionDriver`, in-order request/response
TCP after warm-up, a parser that produces no messages — and asserts:

- **0 allocations per in-order packet** once the flow is
  established (no reassembly buffer, no scratch growth, no event
  container);
- **0 allocations for a sweep that ends nothing**.

What still allocates: a new flow (table entry, per-side stream
state, parser instance), out-of-order data held while a hole is
open, whatever your parser allocates for its messages, and the slot
queues that carry them.

## Comparison against 0.24.1

`compat/` is a workspace-excluded crate that runs identical
synthetic captures through this tree's typed `Driver` and the
released flowscope 0.24.1, counting allocations per thread:

| Scenario | Shape |
|---|---|
| S1 / S2 / S3 | 1 / 8 / 32 port slots |
| S4 | heuristic slot |
| S5 | datagram slot |
| S6 | 100k open flows (retained memory per idle flow) |
| S7 | one lost segment per flow |
| S8 | 300k one-byte out-of-order segments above a hole |

```sh
cd compat
cargo test --release                      # the gates (tests/gates.rs)
cargo run --release --bin compat-bench    # the table + throughput gate
```

The gates assert that 0.25 is strictly better: a superset of 0.24.1's
output (a side stopped after a gap counts in place of its `fin_*`),
fewer allocations, less retained memory per idle flow, and bounded,
fast adversarial out-of-order handling. At release: **5–10× fewer
allocations** on S1–S7, **1.4–2.5× the throughput**, and S8 in
~0.17 s with ~262 KB resident (0.24.1 is quadratic there).

## Reading the numbers

- **Don't optimise without measuring.** Re-run locally on your
  target hardware before assuming flowscope is the bottleneck.
- **The bench is the regression detector.** If a future change
  shows ≥10% slower in `cargo bench`, investigate before shipping.
  criterion's HTML reports diff against the previous run
  automatically.
- **Per-call vs per-packet.** All numbers above are per call to
  the named function. Many real packets trigger multiple calls
  (extract → `tracker.track` → `reassembler.segment` → ...).

## Saving baselines

```sh
# Save the current run as a named baseline:
cargo bench --all-features --bench tracker -- --save-baseline before

# Make changes, re-run, compare:
cargo bench --all-features --bench tracker -- --baseline before

# Stress run with extra iterations:
cargo bench --all-features --bench tracker -- \
    --warm-up-time 5 --measurement-time 30
```

## Future perf work

Areas a future plan could investigate, ordered by potential
impact:

1. **Zero-copy out-of-order reassembly.** In-order bytes already
   bypass the reassembly buffer (0.25); data held across a hole is
   still copied once into the out-of-order pieces.
2. **Faster hashing for `Dedup`.** `xxhash3` is no-std and
   faster than `ahash` on large frames. Cost: one new dep. Win:
   maybe ~30% on `dedup/unique_1500`.
3. **HashMap shard / `dashmap` for `FlowTracker`.** Only relevant
   if profiling shows the `LruCache` as a contention point under
   multi-thread access — not the current model (flowscope is
   sync; parallelism happens outside).
4. **SIMD header parsing.** `etherparse` is already fast; SIMD
   wins are real but marginal at our packet sizes. Skip unless
   real evidence surfaces.
