# Performance

> Baseline numbers measured on a developer workstation (x86_64
> Linux, recent stable Rust, `--release`). Your mileage will
> vary; the *relationships* between configurations matter more
> than the absolute numbers.

flowscope ships a criterion-driven bench harness under `benches/`.
Each group exercises one layer of the pipeline so future perf
work has a baseline to regress-test against. Numbers here are a
point-in-time snapshot from the 0.3.0 release; re-run locally
with:

```sh
cargo bench --all-features
cargo bench --all-features --bench tracker  # just one group
```

Criterion writes HTML reports to `target/criterion/`; open
`target/criterion/index.html` to compare runs.

## Methodology

- One bench file per layer: `extractor`, `tracker`,
  `reassembler`, `session_driver`, `dedup`.
- Each `bench_function` measures one hot-path call; criterion
  iterates ~5 seconds with statistical analysis.
- Throughput reported in nanoseconds per call. Multiply by your
  packets-per-second target to estimate CPU load.

## Baseline (0.3.0)

### Extractor

| Bench                            | Time/call |
|----------------------------------|-----------|
| `extractor/five_tuple_ipv4_tcp`  | ~115 ns   |
| `extractor/five_tuple_ipv4_udp`  | ~110 ns   |

`FiveTuple` parsing is the floor on every other layer — every
packet pays this once. Modern x86 does ~9M parses/sec/core.

### Tracker (Plan 41 hot-cache validation)

| Bench                       | Time/call | vs monoflow |
|-----------------------------|-----------|-------------|
| `tracker/monoflow`          | ~315 ns   | 1.00x       |
| `tracker/n_flows/10`        | ~330 ns   | 1.05x       |
| `tracker/n_flows/100`       | ~340 ns   | 1.08x       |
| `tracker/n_flows/1000`      | ~375 ns   | 1.19x       |
| `tracker/n_flows/10000`     | ~450 ns   | 1.43x       |

The hot-cache fast path (Plan 41) is observable: monoflow is
~43% faster than the 10k-flow round-robin case where every
packet misses the cache. Real-world traffic is bursty per flow,
so the per-burst stickiness recovers most of the win on
heterogeneous workloads.

The original Plan 41 "~2× on monoflow" estimate was optimistic;
the actual win is ~1.4× when comparing the cache-hit path
against a 10k-flow cache-miss baseline. Plenty good for the
~50 LOC cost.

### Reassembler

| Bench                                       | Time/call |
|---------------------------------------------|-----------|
| `reassembler/in_order_1500_uncapped`        | ~87 ns    |
| `reassembler/in_order_1500_capped_1m`       | ~87 ns    |
| `reassembler/sliding_window_overflow`       | ~50–100 ns (varies) |
| `reassembler/ooo_drops`                     | ~25 ns    |
| `reassembler/drop_flow_poisoned`            | ~5 ns     |

The cap check (Plan 42 §1) costs nothing measurable on the
under-cap hot path — confirms the design goal. The poisoned-
reassembler path is essentially free (just a flag check + early
return) because the underlying segment is dropped without
buffer manipulation.

### Dedup (Plan 49)

| Bench                  | Time/call | What it measures           |
|------------------------|-----------|----------------------------|
| `dedup/unique_64`      | ~860 ns   | small-frame hash + lookup  |
| `dedup/unique_1500`    | ~1.2 µs   | typical-MTU hash + lookup  |
| `dedup/duplicate_1500` | ~1.2 µs   | match-and-drop path        |

Most of the cost is the `ahash` of the frame bytes. For loopback
captures running at ~1 Gbps with 1500-byte MTU (~80k pps),
that's ~80k × 1.2 µs = ~100 ms/sec of CPU — about 10% of one
core. Acceptable for the bug-class it prevents.

### Session driver

| Bench                       | Time/call |
|-----------------------------|-----------|
| `session_driver/passthrough` | ~500–800 ns |

End-to-end cost of `FlowSessionDriver::track` with a no-op
`SessionParser`. Dominated by tracker + reassembler dispatch +
the per-side drain loop.

## Reading the numbers

- **Don't optimise without measuring.** Re-run locally on your
  target hardware before assuming flowscope is the bottleneck.
- **The bench is the regression detector.** If a future change
  shows up as ≥10% slower in `cargo bench`, investigate before
  shipping. criterion's HTML reports diff against the previous
  run automatically.
- **Per-call vs per-packet.** All numbers above are *per call*
  to the named function. Many real packets trigger multiple
  calls (extract → tracker.track → reassembler.segment, etc.).

## Running benchmarks

```sh
# All groups:
cargo bench --all-features

# One group:
cargo bench --all-features --bench tracker

# Compare against a saved baseline (criterion auto-saves):
cargo bench --all-features --bench tracker -- --save-baseline before
# ... make changes ...
cargo bench --all-features --bench tracker -- --baseline before

# Stress run with extra iterations:
cargo bench --all-features --bench tracker -- --warm-up-time 5 --measurement-time 30
```

## Future perf work

Areas a future plan could investigate, ordered by potential
impact:

1. **Zero-copy reassembly via `BytesMut` pool** in netring's
   async path. ~80k allocs/sec/Gbps eliminated. Estimated 1.5–
   2.5× throughput on TCP-heavy workloads. (netring-side work,
   not flowscope.)
2. **Faster hashing for `Dedup`.** xxhash3 (no-std,
   ~zero-cost) is faster than ahash on large frames. Cost: one
   new dep. Win: maybe ~30% on `dedup/unique_1500`.
3. **HashMap shard / dashmap for `FlowTracker`.** Only relevant
   if profiling shows the LruCache as a contention point under
   multi-thread access (currently not the model — flowscope is
   sync, parallelism happens outside).
4. **SIMD header parsing.** etherparse is already fast; SIMD
   wins are real but marginal at our packet sizes. Skip unless
   real evidence surfaces.
