# Plan 88 — `AnomalyKind::short_kind()`

## Summary

Ship a `pub fn short_kind(&self) -> &'static str` on `AnomalyKind`
that returns the variant slug used as a metric label —
`"buffer_overflow"`, `"ooo_segment"`, etc.

The 0.7 `Display` impl already returns exactly these strings (it
forwards to `obs::anomaly_label`). `short_kind` doesn't fix a real
defect in `Display`; it gives the semantic name to callers that want
to express *"I want a metric label, not a render"* at the call site.
Both methods are zero-cost forwards to the same source string.

## Status

Not started.

## Prerequisites

- Plan 77 (`Display for AnomalyKind`) — shipped in 0.7.0.
- Plan 43 (`AnomalyKind` variant set, `#[non_exhaustive]`) — shipped
  in 0.6.0.

## Out of scope

- A separate accessor for `Display`-style verbose rendering. `Debug`
  already serves that role for ad-hoc rendering; `Display` and
  `short_kind` are intentionally identical strings.
- A `Severity::short_kind()` mirror. `Severity` already renders
  short lowercase via `Display` (plan 82) and the four values
  (`Info`/`Warning`/`Error`/`Critical`) are not pluralised. No new
  accessor needed.
- A `From<AnomalyKind> for &'static str` impl. Out of scope; `short_kind`
  is the explicit-method shape.

## Files

- `src/event.rs` — `impl AnomalyKind { pub fn short_kind(&self) -> &'static str { … } }`.
- `tests/severity.rs` — extend with a `short_kind` cross-check
  against `Display`.
- `docs/OBSERVABILITY.md` — note the relationship to `Display` in
  the routing-by-severity subsection.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
impl AnomalyKind {
    /// Stable variant slug used as a metric label.
    ///
    /// Same string as `<Self as Display>::fmt` produces — both forward
    /// to the same source-of-truth. Use this method when intent is
    /// "label", `to_string()` / `format!` when intent is "render".
    ///
    /// The slug vocabulary is the same as
    /// `flowscope_anomalies_total{kind=...}` — locked from 0.6 forward.
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | `BufferOverflow` | `"buffer_overflow"` |
    /// | `OutOfOrderSegment` | `"ooo_segment"` |
    /// | `FlowTableEvictionPressure` | `"flow_table_eviction"` |
    /// | `SessionParseError` | `"parse_error"` |
    /// | `RetransmittedSegment` | `"retransmit"` |
    /// | `ReassemblerHighWatermark` | `"reassembler_high_watermark"` |
    pub fn short_kind(&self) -> &'static str {
        crate::obs::anomaly_label(self)
    }
}
```

## Implementation steps

1. Add the method to `src/event.rs` just below the existing `Display`
   impl. Forwards to `crate::obs::anomaly_label`.
2. Extend `tests/severity.rs` with `short_kind_matches_display`: for
   every variant, `kind.short_kind() == format!("{kind}")`.
3. OBSERVABILITY.md: under "Routing by severity", add a note that
   `short_kind()` is the explicit-named accessor for the metric-label
   slug.
4. CHANGELOG entry.

## Tests

- `tests/severity.rs`:
  - `short_kind_matches_display` — exhaustive: every `AnomalyKind`
    variant's `short_kind()` equals its `Display` rendering.
  - `short_kind_is_static_str` — `let s: &'static str = kind.short_kind();`
    compiles (proves no allocation involved).

## Acceptance criteria

- `AnomalyKind::short_kind()` returns the same string as `Display`
  for every variant.
- Return type is `&'static str` (zero-allocation; usable as a
  `metrics` label without `format!`).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.

## Risks

- **Drift between `short_kind` and `Display`.** Both forward to
  `obs::anomaly_label`. The cross-check test guarantees parity at
  test time; drift fires as a test failure.
- **Adding a new `AnomalyKind` variant.** Must update
  `obs::anomaly_label` (existing project convention). `short_kind`
  / `Display` / metrics all stay in lockstep automatically.

## Effort

~10 LoC source + ~20 LoC tests + 5 lines OBSERVABILITY.md.
**~15 minutes.**

## Provenance

Round-3 wishlist item B4 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md).
Ship as a semantic alias for `Display`; see plan-of-record §5 for the
rationale on why this isn't redundant.
