# Plan 82 — `AnomalyKind::severity() -> Severity`

## Summary

Today every `AnomalyKind` is flat — `BufferOverflow` and
`OutOfOrderSegment` look the same to a routing layer. netring's
anomaly-correlation roadmap wants to route by severity (info → logs,
warn → metrics, error → alerts, critical → page). Today consumers
write their own per-kind classification, repeated across every
crate that consumes anomalies.

This plan adds a `Severity` enum and a defaulted
`AnomalyKind::severity() -> Severity` method that returns a sensible
default per kind. Consumers can override by wrapping the kind; the
default mapping covers the common case.

The severity is also surfaced in the `flowscope.anomaly` `tracing`
target as a structured field, so subscribers can filter without
re-classifying.

## Status

Not started.

## Prerequisites

- Plan 43 (anomaly event split) — shipped in 0.6.0. `FlowAnomaly`
  / `TrackerAnomaly` carriers are stable.
- Plan 44 (`ReassemblerHighWatermark`) — shipped in 0.6.0. The
  default-severity mapping needs to cover it.

## Out of scope

- Per-event severity override. `Severity` is a property of the
  *kind*, not the instance — `BufferOverflow` is always
  warning-level regardless of how many bytes were dropped.
  Consumers wanting instance-aware severity match on the kind +
  inner fields themselves.
- A `tracing::Level` -compatible enum. The two systems serve
  different purposes (tracing levels are subscriber-filter
  thresholds; anomaly severity is event taxonomy). Plan documents
  the recommended mapping; doesn't blur the boundary.
- `EndReason::severity()`. End reasons are operational outcomes,
  not anomalies; a flow ending is not an anomaly. The single
  exception is `EndReason::ParseError`, which already produces a
  matching `AnomalyKind::SessionParseError` — consumers route on
  that.
- A `serde::Serialize` impl on `Severity`. Add if asked; defer
  until a second consumer needs it.

## Files

- `src/event.rs` — new `pub enum Severity`; defaulted method on
  `AnomalyKind`.
- `src/obs.rs` — `severity_label(Severity) -> &'static str` for
  the tracing field; thread it through `trace_anomaly`.
- `tests/severity.rs` — new file; covers every variant's
  default mapping + extension hook.
- `docs/OBSERVABILITY.md` — new subsection under "Tracing"
  documenting the severity field and recommended subscriber
  routing.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/event.rs

/// Severity classification for anomaly events. Defaults are
/// returned by [`AnomalyKind::severity`]; consumers free to
/// override.
///
/// Ordered ascending: `Info < Warning < Error < Critical`. Use
/// `PartialOrd` for filter thresholds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Severity {
    /// Routine, informational — high-volume; log-only.
    Info,
    /// Notable but expected — log + count; no immediate action.
    Warning,
    /// Error-level — operator should investigate.
    Error,
    /// System-impact — reserved for future use; no `AnomalyKind`
    /// variant currently defaults to `Critical`.
    Critical,
}

impl AnomalyKind {
    /// Default severity for this kind.
    ///
    /// | Kind | Default severity | Why |
    /// |------|------------------|-----|
    /// | `OutOfOrderSegment` | `Info` | Lossy/multi-path networks have these routinely |
    /// | `RetransmittedSegment` | `Info` | Normal TCP behaviour at low rates |
    /// | `ReassemblerHighWatermark` | `Warning` | Cap pressure building; tune `max_reassembler_buffer` |
    /// | `BufferOverflow` (any policy) | `Warning` | Bytes dropped (sliding) or flow torn down (drop-flow) |
    /// | `SessionParseError` | `Error` | Parser is poisoned; flow ended |
    /// | `FlowTableEvictionPressure` | `Warning` | Tracker bottleneck; bump `max_flows` or shorten idle |
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::OutOfOrderSegment { .. }
            | AnomalyKind::RetransmittedSegment { .. } => Severity::Info,
            AnomalyKind::ReassemblerHighWatermark { .. }
            | AnomalyKind::BufferOverflow { .. }
            | AnomalyKind::FlowTableEvictionPressure { .. } => Severity::Warning,
            AnomalyKind::SessionParseError { .. } => Severity::Error,
        }
    }
}
```

## Implementation steps

1. **Define `Severity`** in `src/event.rs` next to `AnomalyKind`.
   Derive `Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord,
   Hash`. Ordering matters — consumers will write
   `if sev >= Severity::Warning { … }`.
2. **Add `AnomalyKind::severity`** with the default mapping
   table above. Gate behind `#[cfg(feature = "reassembler")]`
   (matches the enum's gate).
3. **Wire into tracing** via `obs::trace_anomaly`:
   ```rust
   #[cfg(all(feature = "tracing", feature = "reassembler"))]
   pub(crate) fn trace_anomaly(kind: &AnomalyKind) {
       tracing::warn!(
           target: "flowscope.anomaly",
           ?kind,
           severity = %severity_label(kind.severity()),
           "anomaly"
       );
   }
   ```
   where `severity_label` returns `"info"`/`"warning"`/`"error"`/
   `"critical"`. (Lowercase to match the metric-label convention
   plan 77 establishes; consumers wanting uppercase write
   `severity.to_string().to_ascii_uppercase()`.)

   For tracing's level routing, document that subscribers can
   filter by reading the field — the tracing log line itself
   stays at `warn!` level because anomalies are always at least
   notable. Subscribers needing precise level routing wrap a
   custom layer.
4. **Tests** (new `tests/severity.rs`):
   - Each variant's `severity()` returns the documented default.
   - `Severity` ordering: `Info < Warning < Error < Critical`.
   - Round-trip through `format!("{:?}")` produces stable strings.
5. **OBSERVABILITY.md** subsection:
   ```markdown
   ### Routing by severity (0.7.0+)

   Every emitted `flowscope.anomaly` event carries a `severity`
   field — `info` / `warning` / `error` / `critical` — derived
   from `AnomalyKind::severity()`. Subscribers route on it:

   ```rust,ignore
   tracing_subscriber::fmt()
       .with_filter(filter::Targets::new()
           .with_target("flowscope.anomaly", LevelFilter::WARN))
       .init();
   ```

   The default mapping is conservative: routine TCP-noise kinds
   (`OutOfOrderSegment`, `RetransmittedSegment`) map to `info`;
   cap-pressure / eviction kinds map to `warning`; parser
   poisoning maps to `error`. `critical` is reserved for future
   use.
   ```
6. **CHANGELOG entry under `### Added`**.

## Tests

- `tests/severity.rs`:
  - `every_variant_has_a_severity` — exhaustive match (compiler
    enforces `#[non_exhaustive]`-aware listing) asserting the
    documented default per variant.
  - `severity_ordering` — `Info < Warning < Error < Critical`.
  - `severity_routing_filter_example` — doctest showing a
    subscriber filter routing on the severity field.
- `src/event.rs::tests::severity_is_copy` — guard against the
  enum gaining variants that break `Copy` later.

## Acceptance criteria

- `AnomalyKind::severity()` returns the documented default for
  every variant.
- `Severity` is `Copy + PartialOrd`, so `if sev >= Warning`
  compiles directly.
- Tracing `flowscope.anomaly` events carry a structured
  `severity` field when `--features tracing reassembler`.
- `cargo test --all-features --test severity` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- Feature-matrix CI green.

## Risks

- **Default mappings are opinionated.** A consumer could
  reasonably classify `OutOfOrderSegment` as `Warning` (some
  protocols are sensitive to OOO drops). Plan covers this by
  documenting the defaults transparently; consumers free to
  override by re-classifying in their event loop.
- **Future `AnomalyKind` variants need explicit severity.** The
  exhaustive-match test catches this — adding a variant without
  updating the match fails the test.
- **Naming bikeshed: `Warning` vs `Warn`.** Author proposed
  `Warn`. We ship `Warning` to match `tracing::Level::WARN`'s
  spelled-out cousin. Trivial flip if pushed back.

## Effort

~30 LoC source (enum + impl + tracing-field add) + ~80 LoC
tests + ~30 lines OBSERVABILITY.md. ~1.5 hours.

## Provenance

Round-2 feedback item F9 in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
The naming choice (`Warning` over `Warn`, lowercase tracing
field over the author's uppercase) and the deferral of an
`AnomalyKind` variant that defaults to `Critical` are documented
in `docs/0.7-PLAN-OF-RECORD.md` §5.
