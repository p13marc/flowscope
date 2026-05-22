# Plan 61 — Cargo feature-matrix CI

## 1. Summary

The `obs::trace_session_message` dead-code warning under
`--no-default-features --features dns` (fixed in the
`chore: tidy + retire …` commit, post-plan-37) was a latent
cfg-gate bug present since plan 36 and never caught by CI — the
workflow only builds `--all-features`. Add a small matrix of
partial-feature combinations to the CI so future cfg-gate misses
fail at PR time, not when a user enables an unusual combo.

This is not in the netring feedback; it's something I want to fix
based on direct experience during the 0.4 series.

## 2. Status

Not started.

## 3. Prerequisites

None.

## 4. Out of scope

- A full N-by-N feature matrix. The cost / value curve flattens
  quickly past ~5 well-chosen combinations.
- MSRV checks on the matrix. The existing CI only runs stable;
  adding MSRV is a separate concern (and `rust-version = "1.85"`
  is documented in `Cargo.toml`).
- Cross-platform builds (Windows / macOS). flowscope is
  cross-platform in principle, but the existing CI runs on
  `ubuntu-latest`. Expanding OS coverage is a separate plan.

## 5. Files

| File | Change |
|------|--------|
| `.github/workflows/rust.yml` | Add a `matrix:` strategy over a small list of feature combinations; the existing fmt/clippy/test/doc steps run once with `--all-features` as today and once per matrix entry with `--no-default-features --features <combo>` (build + clippy only; full test suite stays on `--all-features` to keep CI fast). |
| `CHANGELOG.md` | Internal-tooling note (or omit — CI changes aren't user-visible). |

## 6. API

N/A — CI configuration change.

Concretely, the workflow gains:

```yaml
jobs:
  build:
    # … existing fmt + all-features build / clippy / test / doc steps …

  feature-matrix:
    runs-on: ubuntu-latest
    strategy:
      fail-fast: false
      matrix:
        features:
          - ""                                  # default features only
          - "pcap"                              # offline source, no L7
          - "dns"                               # plan 37 surfaced the gap here
          - "http,tls"
          - "metrics,tracing"
          - "l7,pcap"                           # plan 60's umbrella + offline
    steps:
      - uses: actions/checkout@v4
      - name: Build (--no-default-features --features ${{ matrix.features }})
        run: cargo build --no-default-features --features "${{ matrix.features }}"
      - name: Clippy (--no-default-features --features ${{ matrix.features }})
        run: cargo clippy --no-default-features --features "${{ matrix.features }}" --all-targets -- -D warnings
```

The empty-string entry runs default features (`extractors`,
`tracker`, `reassembler`, `session`). It's a thin add but catches
the case where a user does `flowscope = "0.5"` with no features
list.

## 7. Implementation steps

1. **Edit `.github/workflows/rust.yml`** — add the second job.
2. **Verify each combo** locally before pushing:
   ```
   cargo build --no-default-features
   cargo build --no-default-features --features pcap
   cargo build --no-default-features --features dns
   cargo build --no-default-features --features http,tls
   cargo build --no-default-features --features metrics,tracing
   cargo build --no-default-features --features l7,pcap
   ```
   Same set with `clippy --all-targets -- -D warnings`.
3. **Fix any cfg-gate misses** caught by the local sweep before
   the workflow lands.
4. **CHANGELOG** — optional brief mention under "internal".

## 8. Tests

- The CI job itself is the test. The local pre-flight sweep
  (step 2 above) catches anything before the PR.

## 9. Acceptance criteria

- The workflow runs both `build` and `feature-matrix` jobs on every
  push to `master` and every PR.
- All matrix entries build and pass clippy with `-D warnings`.
- Latent dead-code warnings in unusual feature combos are now
  caught at PR time, not by users.

## 10. Risks

- **CI time.** Each matrix entry runs build + clippy separately.
  With six entries, that's roughly 6× incremental compile time —
  but each is a cold compile, so wall-clock ≈ 4–6 minutes per
  entry on `ubuntu-latest`. Mitigated by `fail-fast: false` so a
  single failure doesn't block the others reporting, and by
  scoping each entry to build + clippy only (not the full
  `--all-features` test run, which already covers behaviour).
- **Matrix entry creep.** Tempting to add ever more combos. Keep
  the list ≤ 6 entries; only add when a real cfg-gate miss
  motivates it.
- **PR latency.** The new job runs in parallel with the existing
  `build` job, so total wall-clock is `max(build, matrix)`, not
  the sum. Existing 1m07s `build` job stays the critical path
  for green-PR latency.

## 11. Effort

Trivial — ~30 lines of YAML. The bulk of the work is the local
pre-flight verification (~10 minutes) and fixing any latent
warnings the sweep catches.

## 12. Provenance

Not in the netring feedback. Motivated by the
`obs::trace_session_message` dead-code warning that latently
existed from plan 36 until I caught it during the plan-37 tidy.
[`docs/0.5-PLAN-OF-RECORD.md`](../docs/0.5-PLAN-OF-RECORD.md) §5
covers the rationale.
