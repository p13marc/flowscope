# Plan 131 — Error module + feature-flag pruning

## Summary

Cleanup pass on two related shapes the 0.12 audit flagged as
"surface debt":

1. **`flowscope::Error::Module` enum** — drop the stale
   `Pipeline` variant (Pipeline was deleted in 0.11; the enum
   still lists it). Add the missing `Driver` / `Emit` /
   `Detect` / `Aggregate` / `Correlate` variants for
   subsystems that don't error today but will as soon as one
   does. Reconcile `ErrorCode::Other` + `#[non_exhaustive]`.
2. **Cargo features** — 21 features is a lot. Three
   consolidations and one rename:
   - `ja3` + `ja4` → `tls-fingerprints` (rarely useful in
     isolation; a future JA4+ family expansion would make the
     two-flag split worse, so collapse now while the surface
     is small).
   - `l7` umbrella stays; `full` umbrella stays; document the
     convention so they don't drift independently.
   - `tracing-messages` reconsidered: the feature exists to
     add a `Message: Debug` bound. Per-cycle audit shows it's
     niche. Either fold into `tracing` (always-on bound) or
     drop entirely.
   - Document the implicit `reassembler`/`session`/`tracker`
     dependency graph — today `FlowSessionDriver` requires
     both but neither feature pulls the other.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **No new error variants beyond the missing `Module` arms.**
- **No new features added by this plan.** Plan 146 (file-hash)
  is the only feature this cycle ships under its own gate.
- **CI matrix net change:** this plan swaps two entries (`ja3`
  / `ja4`) for one (`tls-fingerprints`); plan 146 adds one
  (`file-hash`). Net +0 / +1.

## Pre-1.0 breaks

- **`flowscope::Error::Module::Pipeline` removed.** Behaviour-
  preserving — Pipeline was deleted in 0.11, so no Error ever
  carried this variant in shipped 0.12.x. Any external `match`
  arm referencing it was already dead code.
- **`ja3` and `ja4` features removed**; replaced by
  `tls-fingerprints` (enables today's JA3 + JA4 client TLS
  fingerprints; a future JA4+ family expansion drops cleanly
  under the same gate). Migration: rename the feature in
  `Cargo.toml`. The `Ja3Parts` / `ja3()` / `Ja4Parts` /
  `ja4_fingerprint()` / `ja4_parts()` exports stay at the
  same paths; only the feature flag rename.
- **`tracing-messages` feature removed.** Per-message Debug
  bound moves to always-on under `tracing`. Per-message
  `tracing::trace!` emission becomes a runtime knob on the
  driver builder (`with_trace_messages(bool)`). Compile cost
  shift: any consumer that enabled `tracing` but not
  `tracing-messages` to avoid `Message: Debug` bound now
  pays it — every shipped parser already satisfies `Debug`
  so this is invisible.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/error.rs` | Drop `Module::Pipeline`; add `Module::{Driver, Emit, Detect, Aggregate, Correlate}` |
| Modify | `Cargo.toml` | `tls-fingerprints` feature replaces `ja3` + `ja4`; remove `tracing-messages`; document core-feature graph in comments |
| Modify | `src/obs.rs` | `with_trace_messages` runtime knob replaces `tracing-messages` cfg gate |
| Modify | `src/driver/typed.rs` + `src/flow_driver.rs` | Plumb `trace_messages: bool` flag through `DriverBuilder` → `FlowDriver` |
| Modify | `src/lib.rs` | Add doc-section "feature graph" in the top-level rustdoc |
| Modify | `.github/workflows/rust.yml` | Replace `ja3` / `ja4` matrix entries with `tls-fingerprints` |
| Modify | `examples/02-forensics/extract_iocs.rs` + others | Update `required-features` from `ja3, ja4` → `tls-fingerprints` |
| Modify | `examples/02-forensics/tls_inventory.rs` | Same rename |
| Modify | `Cargo.toml` `[[example]]` blocks | Bulk rename of `required-features` |
| Modify | `CHANGELOG.md` | 0.12 entry: 1 error variant added (×5), 1 removed, 1 feature renamed, 1 feature removed |
| Modify | `docs/observability.md` | Drop `tracing-messages` section; document the new runtime knob |
| Modify | `docs/recipes.md` | tls-fingerprints rename in feature snippets |
| Modify | `README.md` | Feature table updated |

## API

### `Error::Module` after this plan

```rust
// src/error.rs

#[non_exhaustive]
pub enum Module {
    Http,
    Tls,
    Dns,
    Icmp,
    Pcap,
    Reassembler,
    Tracker,
    Layers,
    // ── New in 0.12.0 ──
    Driver,     // typed Driver<E> / SlotHandle path
    Emit,       // emit::* writers (e.g. IPFIX template errors)
    Detect,     // detect::patterns / detect::signatures
    Aggregate,  // aggregate::Histogram / Percentile
    Correlate,  // correlate::* primitives
    // Pipeline ← removed (was deleted in 0.11.0)
}
```

`#[non_exhaustive]` is retained — adding variants is
unconditionally additive. Removing `Pipeline` is the one
break.

### Tracing knob (`tracing-messages` replacement)

```rust
// src/obs.rs

// Old (0.11): cfg-gated emission, bound on the trait.
// #[cfg(feature = "tracing-messages")]
// pub(crate) fn trace_session_message<M: Debug>(…) { … }

// New (0.12.0): always-compiled, runtime no-op when off.
pub(crate) fn trace_session_message<M: Debug>(
    enabled: bool, parser_kind: &str, msg: &M, …
) {
    if !enabled { return; }
    // emit tracing::trace! event
}
```

```rust
// src/driver/typed.rs

impl<E> DriverBuilder<E> { … }
// New: runtime knob.
impl<E> DriverBuilder<E> {
    pub fn with_trace_messages(&mut self, on: bool) -> &mut Self { … }
}
```

The `Message: Debug` bound becomes always-on for L7 parser
trait impls — every shipped parser already satisfies it.

### Cargo features after this plan

```toml
# Core (always-on combinations)
default = ["extractors", "tracker", "reassembler", "session"]

# Protocol parsers
http  = [...]
tls   = [...]
dns   = [...]
icmp  = [...]

# TLS fingerprint family (replaces ja3 + ja4)
tls-fingerprints = ["tls", "dep:md-5", "dep:sha2", "dep:hex"]

# Plus feature added by plan 146 this cycle:
file-hash = ["reassembler", "dep:sha2", "dep:md-5"]

# Umbrellas
l7 = ["http", "tls", "tls-fingerprints", "dns", "icmp"]
full = [ /* every shipped feature */ ]
```

The implicit core-feature graph gets a comment block:

```toml
# Core feature graph (transitive deps shown):
#   extractors       — required by everything
#   tracker          — extractors
#   reassembler      — tracker (+ extractors)
#   session          — tracker (+ extractors)
#   FlowSessionDriver needs both reassembler + session.
#   default = [extractors, tracker, reassembler, session].
```

## Implementation steps

1. **`src/error.rs`**: remove `Module::Pipeline`; add the 5
   new arms; update `Module::Display` to render the new
   variants in their natural snake_case slug.
2. **`Cargo.toml`**: introduce `tls-fingerprints = ["tls",
   "dep:md-5", "dep:sha2", "dep:hex"]`. Delete `ja3` and `ja4`
   features. Delete `tracing-messages`. Move the bound-adding
   logic to runtime (step 3).
3. **`src/obs.rs`**: remove `#[cfg(feature = "tracing-messages")]`
   gates. Add a runtime `enabled: bool` argument. Default
   off; opt-in via builder.
4. **`src/driver/typed.rs`**: plumb the `trace_messages: bool`
   flag through `DriverBuilder` and into the slot dispatch
   path so every `route_session_event` callsite gets it.
5. **`src/flow_driver.rs`** + `src/session_driver.rs` +
   `src/datagram_driver.rs`: same plumbing, exposed via
   `with_trace_messages`.
6. **`examples/`**: bulk-rename `required-features =
   ["pcap", "http", "tls", "ja3", "ja4", "dns",
   "extractors"]` patterns to `["pcap", "tls-fingerprints",
   "http", "tls", "dns", "extractors"]`. Verify each builds
   with the new feature.
7. **`.github/workflows/rust.yml`**: feature-matrix update.
8. **`docs/observability.md`**: drop the
   "compile-time `tracing-messages` sub-feature" paragraph;
   document the runtime knob.
9. **`docs/recipes.md`** + **`README.md`**: rename `ja3, ja4`
   → `tls-fingerprints` in feature snippets.
10. **`src/lib.rs`**: add a top-level rustdoc section
    documenting the feature graph and the umbrellas.
11. **CHANGELOG**: per-break recipe.

## Tests

### Unit

- `src/error.rs::tests::module_display_snake_case_slugs` —
  cover the 5 new variants.
- No regression test for `tracing-messages` (deleted); add a
  new test verifying `with_trace_messages(true)` emits an
  event under `tracing-subscriber` capture.

### Integration

- `tests/error_chain.rs` already covers Pipeline-era variants;
  drop those arms.
- `tests/metrics_integration.rs` — verify the `trace_messages`
  knob doesn't perturb the metrics surface.

### Feature matrix

- Add a CI matrix entry for `"tls-fingerprints"` (no-default
  build).
- Drop the `"ja3"`, `"ja4"` entries.

## Acceptance criteria

- `cargo build --no-default-features --features "tls-fingerprints"`
  clean.
- `cargo build --all-features` clean.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo +stable check --no-default-features` clean — proves
  the default-feature set still builds.
- No `Module::Pipeline` references remain anywhere.
- No `feature = "tracing-messages"` cfg attributes remain.
- No `feature = "ja3"` or `feature = "ja4"` cfg attributes
  remain.
- Examples that previously needed `ja3, ja4` now declare
  `tls-fingerprints` and build clean.
- CHANGELOG 0.12.0 entry lists all 4 changes with one-line
  migrations.

## Risks

- **R1: Examples rename churn.** 20+ example files (`Cargo.toml`
  `[[example]]` blocks) reference `ja3` / `ja4` and need
  consistent rename. Mitigation: scripted `sed` + per-feature
  build verification.
- **R2: `tracing-messages` semantic change.** Today's compile-
  out can be cheap; runtime-flag opt-in adds a branch per
  message even when off. Branch is `if !enabled { return; }`
  before the `tracing::trace!` macro; cost is one
  `bool` load + branch ≈ 1 ns. Negligible at any traffic rate
  flowscope handles.
- **R3: Error variant additions break downstream `match`
  expressions.** Mitigation: `#[non_exhaustive]` is on the
  enum; downstream code must already wildcard-match.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Error module rework | 50 | 1 |
| `tls-fingerprints` feature rename + example sweep | 60 | 2 |
| `tracing-messages` → runtime knob | 80 | 2 |
| Doc updates (observability, recipes, README, lib.rs) | 60 | 1.5 |
| Tests | 80 | 2 |
| CHANGELOG | 20 | 0.5 |
| **Total** | **~350** | **~9 hours (~1 day)** |

## Provenance

0.12 post-release audit flagged `Module::Pipeline` stale,
feature-flag count at 21 (sustainability concern),
`tracing-messages` as a future-trap. This plan pays down the
debt before community adoption hardens the surface. Coupled
with plan 130 (trait shape) and plan 132 (doc overhaul) into
the API-debt retirement phase of the 0.12 expanded cycle.
