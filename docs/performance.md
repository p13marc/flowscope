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
| `reassembler` | `BufferedReassembler::segment` for in-order, OOO, capped, poisoned cases. |
| `session_driver` | End-to-end typed `Driver<E>` session slot with a no-op parser. |
| `dedup` | `Dedup` content-hash + lookup over typical and MTU-sized frames. |

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
| `reassembler/ooo_drops` | ~25 ns |
| `reassembler/drop_flow_poisoned` | ~5 ns |

The cap check costs nothing measurable on the under-cap hot path
— design goal met. The poisoned-reassembler path is essentially
free (flag check + early return) because the segment is dropped
without buffer manipulation.

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
per-side drain loop.

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

1. **Zero-copy reassembly via a `BytesMut` pool** (netring-side).
   ~80k allocs/sec/Gbps eliminated; estimated 1.5–2.5× throughput
   on TCP-heavy workloads.
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
