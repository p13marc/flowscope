# Plan 77 — `impl Display` on `L4Proto`, `EndReason`, `AnomalyKind`

## Summary

Every L7 consumer ends up writing the same `match l4 { … }` to
render a flow's L4 protocol as a short label for logs, prompts,
or summary lines. The netring author counted five mostly-identical
impls across the four example monitors they wrote against 0.6.

This plan ships `Display` on the three labelled enums consumers
write these matches for: `L4Proto`, `EndReason`, `AnomalyKind`.
The format strings are the same `&'static str` constants the
metric labels already use, so the rendered text matches what
`flowscope_anomalies_total{kind=…}` and friends look like in a
Prometheus scrape.

## Status

Not started.

## Prerequisites

- Plan 40 (observability hooks) — shipped in 0.2.0. The metric-
  label functions in `src/obs.rs` (`l4_label`, `reason_label`,
  `anomaly_label`) are the source-of-truth strings; the `Display`
  impls reuse them.

## Out of scope

- `Display` on every public enum. We only do the three the
  feedback author identified as repeated friction; further impls
  land when a second consumer asks.
- `Display` on `FlowEvent` / `SessionEvent` (carrying nested
  payloads). The shape isn't a single short label; `Debug` is
  already adequate for ad-hoc rendering.
- `serde::Serialize` impls. Display is enough for logs and
  rendering; structured serialisation is a separate ask.
- Localised / pluralised formatting. The labels are operator
  vocabulary, not user-facing text.

## Files

- `src/extractor.rs` — `impl fmt::Display for L4Proto`.
- `src/event.rs` — `impl fmt::Display for EndReason` and
  `impl fmt::Display for AnomalyKind`.
- `src/obs.rs` — promote the existing `fn l4_label`, `fn
  reason_label`, `fn anomaly_label` from `#[cfg(feature = "metrics")]`
  -gated private functions to `pub(crate)` always-available
  helpers (the `Display` impls call them). Add `#[cfg(feature =
  "reassembler")]` where required to keep the gating consistent.
- `tests/display_impls.rs` — new file; covers every variant of
  every enum + format-arg compatibility (`format!("{l4}")`).
- `CHANGELOG.md` — `Added` entry.

## API

```rust
// src/extractor.rs
impl std::fmt::Display for L4Proto {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::obs::l4_label(Some(*self)))
    }
}
```

```rust
// src/event.rs
impl std::fmt::Display for EndReason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::obs::reason_label(*self))
    }
}

impl std::fmt::Display for AnomalyKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::obs::anomaly_label(self))
    }
}
```

Rendered strings (matches metric labels exactly):

- `L4Proto::Tcp` → `"tcp"`
- `L4Proto::Udp` → `"udp"`
- All other `L4Proto` variants → `"other"` (matches the metric
  collapse; if a consumer needs a finer label they pattern-match
  themselves)
- `EndReason::Fin` → `"fin"`, `Rst` → `"rst"`, `IdleTimeout` →
  `"idle"`, `Evicted` → `"evicted"`, `BufferOverflow` →
  `"buffer_overflow"`, `ParseError` → `"parse_error"`
- `AnomalyKind::BufferOverflow` → `"buffer_overflow"`,
  `OutOfOrderSegment` → `"ooo_segment"`,
  `FlowTableEvictionPressure` → `"flow_table_eviction"`,
  `SessionParseError` → `"parse_error"`,
  `RetransmittedSegment` → `"retransmit"`,
  `ReassemblerHighWatermark` → `"reassembler_high_watermark"`

## Implementation steps

1. **Hoist label functions out of `metrics`-feature gate** in
   `src/obs.rs`:
   - `l4_label` — remove `#[cfg(feature = "metrics")]`, change to
     `pub(crate)`. It's pure data, zero runtime cost.
   - `reason_label` — same.
   - `anomaly_label` — keep the `#[cfg(feature = "reassembler")]`
     gate (it depends on `AnomalyKind`, which is reassembler-
     gated), but drop `feature = "metrics"`. Change to
     `pub(crate)`.
2. **Add `Display for L4Proto`** in `src/extractor.rs`. One
   `f.write_str` call.
3. **Add `Display for EndReason`** in `src/event.rs`. Same shape.
4. **Add `Display for AnomalyKind`** in `src/event.rs`. Gate on
   `#[cfg(feature = "reassembler")]` to match the enum's gate.
5. **Tests** — `tests/display_impls.rs` covers:
   - `format!("{l4}")` for every `L4Proto` variant.
   - `format!("{reason}")` for every `EndReason` variant.
   - `format!("{kind}")` for every `AnomalyKind` variant
     (gated on `--features reassembler`).
   - Round-trip with `obs::*_label` to assert the strings are
     identical.
6. **CHANGELOG entry** under `### Added`:
   ```
   - `impl Display` for `L4Proto`, `EndReason`, `AnomalyKind`.
     Rendered strings match the existing metric-label vocabulary
     (`tcp`/`udp`, `fin`/`rst`/…, `buffer_overflow`/…), so logs
     and Prometheus scrapes use the same tokens. Saves the
     `match l4 { … }` boilerplate that every consumer was writing
     against 0.6.
   ```

## Tests

- `tests/display_impls.rs`:
  - One `#[test]` per enum, asserting `format!("{x}")` matches
    the expected string for every variant.
  - One cross-check `#[test]` round-tripping through
    `obs::*_label` so any future drift between Display and the
    metric label fires at test time.
- All variants of `AnomalyKind` covered including the two new
  ones from 0.5.0 (`RetransmittedSegment`) and 0.6.0
  (`ReassemblerHighWatermark`).

## Acceptance criteria

- `cargo test --all-features --test display_impls` passes.
- `format!("{l4}")` for `L4Proto::Tcp` returns `"tcp"` (matching
  the metric label, not the author's proposed uppercase `"TCP"`).
- The label-functions in `obs.rs` are no longer `metrics`-feature
  -gated; consumers building with `--features extractors` (no
  metrics) can use `Display` for free.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- Feature-matrix CI green (the hoisting of `l4_label` /
  `reason_label` out of the `metrics` gate must not introduce
  dead-code under partial features).

## Risks

- **Author preference for uppercase.** The author proposed
  `TCP`/`UDP`/`ICMP`. We ship lowercase to match metric labels;
  see plan-of-record §5. If they object on the netring side, the
  fix is one-line per impl; not committed.
- **Label drift over time.** If a future plan changes a metric
  label string, `Display` changes silently. The cross-check test
  catches this — drift fires as a test failure with a clear
  expected/actual diff.

## Effort

~40 LoC source (3 trivial impls + visibility hoists) + ~80 LoC
tests. ~1 hour including CHANGELOG entry.

## Provenance

Round-2 feedback item F2 in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
The author counted five copies of the same `match` in
netring's L7 examples. The lowercase choice deviates from their
proposal but matches the existing metric label convention; see
`docs/0.7-PLAN-OF-RECORD.md` §5.
