# Plan 54 — Criterion benchmark harness + PERFORMANCE.md

## Summary

flowscope has no formal benchmark suite. Plan 41 (hot-cache fast
path) shipped with rough estimates ("~2× on monoflow") but no
measurements. Plan 42 (overflow policies) has zero data on the
per-cap overhead. Future perf work has no baseline.

This plan ships:

1. A `criterion` benchmark harness under `benches/` with five
   benchmark groups covering the hot path: extractor, tracker,
   reassembler, session driver, dedup.
2. A `docs/PERFORMANCE.md` documenting the methodology, baseline
   numbers, and the hardware/OS context they were measured on.
3. CI integration as `cargo bench --no-run` (compile check) by
   default; full runs on-demand via a `bench` CI job.

The goal isn't "make flowscope faster" — that's Plan 41 and
follow-ups. The goal is "measure first, optimise second."

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- None. New `benches/` directory; pure dev-dep addition.

## Out of scope

- Optimisation work. This plan ships infrastructure + baseline
  numbers; perf wins are separate plans (Plan 41 follow-ups, e.g.
  zero-copy reassembly, or new perf plans driven by what the
  baselines reveal).
- CI dashboards / regression detection. `cargo bench` runs
  locally for now; trend-tracking infrastructure can come later
  if there's demand.
- Cross-platform numbers. The baselines are recorded on one
  developer machine (documented in PERFORMANCE.md). Different
  hardware will show different absolute numbers; the
  *relationships* between configurations (with/without hot
  cache, with/without cap) should hold across machines.

---

## Files

### NEW

- `benches/extractor.rs` — `FiveTuple` / `IpPair` extraction throughput.
- `benches/tracker.rs` — `FlowTracker::track` throughput with
  hot-cache on/off and at 1 / 100 / 10k flows.
- `benches/reassembler.rs` — `BufferedReassembler` segment
  throughput, capped vs uncapped, in-order vs OOO.
- `benches/session_driver.rs` — end-to-end `FlowSessionDriver`
  throughput with a no-op `SessionParser`.
- `benches/dedup.rs` — `Dedup::keep` throughput at typical packet
  sizes (64, 1500, 9000 bytes).
- `docs/PERFORMANCE.md` — methodology, hardware context,
  baseline numbers, comparison rows for the optimisations that
  shipped in 0.2.0.

### MODIFIED

- `Cargo.toml` — `criterion` under `[dev-dependencies]`;
  `[[bench]]` entries for each file under `benches/`.
- `.gitignore` — already ignores `target/`. No change needed.
- `CHANGELOG.md` — 0.3.0 entry under "Tooling".
- `README.md` — short "Performance" subsection pointing at
  PERFORMANCE.md.

---

## API

The plan is non-code-changing as far as flowscope's public API
goes. The bench harness consumes existing public APIs.

```toml
# Cargo.toml additions

[dev-dependencies]
criterion = { version = "0.5", features = ["html_reports"] }

[[bench]]
name = "extractor"
harness = false
required-features = ["extractors", "test-helpers"]

[[bench]]
name = "tracker"
harness = false
required-features = ["tracker", "extractors", "test-helpers"]

[[bench]]
name = "reassembler"
harness = false
required-features = ["reassembler"]

[[bench]]
name = "session_driver"
harness = false
required-features = ["session", "reassembler", "extractors", "test-helpers"]

[[bench]]
name = "dedup"
harness = false
required-features = ["extractors"]
```

Each bench file follows the standard criterion shape:

```rust
// benches/tracker.rs
use criterion::{Criterion, black_box, criterion_group, criterion_main};
use flowscope::extract::FiveTuple;
use flowscope::extract::parse::test_frames::ipv4_tcp;
use flowscope::{FlowTracker, PacketView, Timestamp};

fn bench_monoflow(c: &mut Criterion) {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let frame = ipv4_tcp(/* same key every call */);
    let view = PacketView::new(&frame, Timestamp::default());
    c.bench_function("tracker/monoflow", |b| {
        b.iter(|| black_box(t.track(view)))
    });
}

fn bench_n_flows(c: &mut Criterion, n: usize) {
    // Pre-build N distinct frames; cycle through them.
    let frames: Vec<Vec<u8>> = (0..n).map(|i| ipv4_tcp(/* port = 1024+i */)).collect();
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut group = c.benchmark_group("tracker/n_flows");
    group.throughput(criterion::Throughput::Elements(1));
    group.bench_with_input(criterion::BenchmarkId::from_parameter(n), &frames, |b, fs| {
        let mut i = 0;
        b.iter(|| {
            let view = PacketView::new(&fs[i % fs.len()], Timestamp::default());
            black_box(t.track(view));
            i += 1;
        });
    });
}

criterion_group!(benches,
    bench_monoflow,
    |c| bench_n_flows(c, 10),
    |c| bench_n_flows(c, 100),
    |c| bench_n_flows(c, 10_000),
);
criterion_main!(benches);
```

---

## Benchmark groups

### extractor

- `extractor/five_tuple` — `FiveTuple::extract(view)` on a stock
  IPv4 TCP frame.
- `extractor/five_tuple_ipv6` — same on IPv6.
- `extractor/ip_pair` — `IpPair::extract`.
- `extractor/strip_vlan` — `StripVlan(FiveTuple).extract` on a
  VLAN-tagged frame.
- `extractor/auto_detect` — `AutoDetectEncap` worst case (frame
  doesn't match any encap, falls through to plain).

### tracker

- `tracker/monoflow` — same frame repeated (hot-cache hit path).
- `tracker/n_flows/{10,100,10000}` — round-robin across N distinct
  flows. Hot cache misses on every packet at N > 1.
- `tracker/sweep_10k` — `sweep(now)` on a 10k-flow table at
  steady state.

### reassembler

- `reassembler/in_order_1500` — feed in-order 1500-byte segments
  to `BufferedReassembler` (uncapped).
- `reassembler/in_order_1500_capped_1m` — same with 1 MiB cap
  (no overflow expected; pure cap-check overhead).
- `reassembler/sliding_window_overflow` — cap is set such that
  every segment overflows; measures the rotation cost.
- `reassembler/ooo_drops` — random-seq segments hitting the OOO
  branch.

### session_driver

- `session_driver/passthrough` — `FlowSessionDriver` with a no-op
  `SessionParser` (just consumes bytes). Measures the driver's
  per-packet overhead end-to-end.

### dedup

- `dedup/unique_64` — 64-byte frames, all distinct, dedup never
  triggers.
- `dedup/unique_1500` — 1500-byte frames, all distinct.
- `dedup/duplicate_1500` — every other frame is a duplicate.

---

## docs/PERFORMANCE.md

Structure:

```markdown
# Performance

> Numbers measured on $hardware running $OS with $rustc. Your
> mileage will vary; the *relationships* between configurations
> matter more than the absolute numbers.

## Methodology

`cargo bench --all-features` runs criterion across `benches/`.
Each benchmark group is described below with what it measures
and how to read the numbers.

## Baseline (0.3.0)

### tracker

| Benchmark              | Throughput      | Per-packet     |
|------------------------|-----------------|----------------|
| `tracker/monoflow`     | $X ns/iter      | ~$Y ns         |
| `tracker/n_flows/100`  | $X ns/iter      | ~$Y ns         |
| `tracker/n_flows/10k`  | $X ns/iter      | ~$Y ns         |
| `tracker/sweep_10k`    | $X ms/iter      | —              |

The hot-cache fast path (`tracker/monoflow`) is roughly $N× the
slow path (`tracker/n_flows/10k`), as predicted by Plan 41.

### reassembler

…

### session_driver

…

### dedup

…

## Notes

- $observation about per-flow allocation costs
- $observation about LRU eviction overhead
- $observation about OOO drop accounting

## Running locally

\`\`\`
cargo bench --all-features
cargo bench --all-features --bench tracker
\`\`\`

Criterion writes HTML reports to `target/criterion/`. Open
`target/criterion/index.html` to compare runs.
```

Fill in `$X`, `$Y`, `$N`, etc., once the harness lands and the
benches run on a known machine. The PERFORMANCE.md commit
records both the methodology AND a snapshot of the numbers, so
later readers can diff against history.

---

## Implementation steps

1. **Add `criterion` to dev-deps** in Cargo.toml.
2. **Create `benches/` dir** with the five files.
3. **Write the bench scaffolds** following the criterion idiom
   (no `harness = false` confusion — each `[[bench]]` entry sets
   it).
4. **Wire `[[bench]]` entries** with `required-features` matching
   what each bench actually uses.
5. **Run `cargo bench --all-features`** locally; capture numbers.
6. **Write `docs/PERFORMANCE.md`** with the methodology + the
   captured numbers + interpretation.
7. **Update README.md** with a one-paragraph "Performance"
   subsection pointing at PERFORMANCE.md.
8. **CHANGELOG entry** under 0.3.0 "Tooling".

---

## Tests

The benches themselves are the test deliverable. `cargo bench
--no-run --all-features` is added to the recommended pre-commit
hook (just verifies they compile; running them is slow).

For CI: `cargo bench --no-run --all-features` on the standard
test job (compile-only). A separate `bench` job (manually
triggered or on-tag) runs them and uploads the criterion HTML
report as an artifact.

---

## Acceptance criteria

- [ ] `benches/{extractor,tracker,reassembler,session_driver,dedup}.rs`
      exist and compile under `cargo bench --no-run --all-features`.
- [ ] `cargo bench --bench tracker --all-features` runs and
      produces results.
- [ ] `docs/PERFORMANCE.md` exists with methodology, hardware
      context, and the five benchmark groups' baseline numbers.
- [ ] README.md mentions PERFORMANCE.md in a one-paragraph
      "Performance" subsection.
- [ ] CHANGELOG entry under 0.3.0 "Tooling".
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean
      (criterion's hot-path code occasionally triggers clippy
      lints; `#[allow(...)]` at the bench-file scope if needed).

---

## Risks

1. **Criterion's overhead.** criterion's per-iter measurement
   loop has ~50 ns of harness overhead. For the cheapest
   benchmark (`extractor/five_tuple` at ~30 ns/iter), this is
   significant. Use `Throughput::Elements(1)` + the iteration
   loop pattern instead of `iter_with_setup` where the setup
   cost dominates.
2. **Compile-time cost.** criterion brings in `tinytemplate`,
   `plotters`, `rayon`, and friends — adds ~30 s to a clean
   `cargo bench --no-run`. Acceptable for bench-only use.
3. **Bench drift on different hardware.** PERFORMANCE.md
   documents the hardware once; numbers from different machines
   will differ. The user comparing runs locally on their own
   machine is the primary audience; the published numbers are a
   sanity-check reference.
4. **Test-helper feature for benches.** `bench tracker` and
   `bench session_driver` need `test-helpers` for the
   `test_frames` synthesizer. Already exposed via the
   `test-helpers` feature; benches use it.

---

## Effort

- LOC: ~400 (five bench files, ~80 LOC each).
- PERFORMANCE.md: ~200 lines of prose + numbers.
- Time: 1 day (¾ d to write the benches + capture numbers, ¼ d
  to write up).

---

## Provenance

Identified during the 0.3.0 planning review. Plan 41 (hot-cache
fast path, shipped in 0.2.0) was supposed to deliver a
`docs/PERFORMANCE.md` and never did — the "~2× on monoflow"
claim is empirical estimation, not a measured number. This plan
closes that debt and sets up the bench infrastructure for future
perf work.
