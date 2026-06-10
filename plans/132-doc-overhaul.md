# Plan 132 — Documentation overhaul (typed Driver primacy)

## Summary

Pure documentation pass. No code changes. The 0.12 audit found
that `docs/concepts.md`, `docs/recipes.md`,
`docs/getting-started.md`, and the top-level rustdoc in
`src/lib.rs` still position **`FlowSessionDriver`** as a
primary recommended API path. The typed `Driver<E>` +
`SlotHandle` shape (plan 121, shipped 0.11) is the headline; the
docs hedge.

This plan rewrites the docs so:

- `Driver::builder(ext)` is the **only** recommended entry
  point in §0 of getting-started, the primary tier in
  concepts.md, the lead example in recipes.md.
- `FlowSessionDriver` / `FlowDatagramDriver` / `FlowDriver`
  are documented as **raw sync primitives** for power users
  who need per-flow state (`S` param) or the raw
  `SessionEvent` stream directly. Cross-link from where they
  appear.
- `Pipeline`, `FlowMultiSessionDriver`, `driver_unified`
  references are deleted everywhere they survive.
- The intra-doc-link "Re-exporting flowscope types" recipe in
  `src/lib.rs` top-level rustdoc leads with `Driver` instead
  of `FlowSessionDriver`.

## Status

Not started.

## Prerequisites

- **Plan 130** lands first (trait shape — `KeyFields` /
  `AnomalyFields` split affects doc snippets).
- **Plan 131** lands first (feature renames — doc snippets
  reference `tls-fingerprints`).

## Out of scope

- **No new API documented.** Plans 143 / 144 / 146 each ship
  their own doc + rustdoc.
- **No fresh design rationale.** `docs/design.md` already
  captures the runtime-free / layered design.

## Pre-1.0 breaks

None. Pure doc.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/lib.rs` | Top-level rustdoc rewrite: typed `Driver` as primary; `FlowSessionDriver` re-export-recipe demoted to a "raw primitives" appendix |
| Modify | `docs/getting-started.md` | §2 ("Typed HTTP messages from a pcap") moves to `Driver<E>`; the `FlowSessionDriver`-based variant becomes an alternative shown after |
| Modify | `docs/concepts.md` | Section "Tier 2 — raw `FlowSessionDriver` / `FlowDatagramDriver`" clarified as "power-user / raw stream" tier; lead with `Driver<E>` |
| Modify | `docs/recipes.md` | Sweep §"Custom `SessionParser` for a line-based protocol", §"Writing your own — full trait surface", §"Per-flow state via tracker `with_state*`", §"Migrating to …", §"Structured event output" code samples — every callsite uses `Driver::builder` |
| Modify | `docs/observability.md` | Driver-level knobs (`emit_anomalies`, `with_trace_messages`) shown on `DriverBuilder`, not `FlowDriver::with_emit_anomalies` |
| Modify | `docs/migration-0.10-to-0.11.md` | Pre-existing migration doc; verify still correct after plan 130/131; no rewrite, just sanity-check |
| Modify | `docs/migration-0.11-to-0.12.md` | Existing doc gets the plan 130 + 131 break recipes appended |
| Modify | `docs/eve-format.md` | "Custom keys" section updated to `KeyFields` (plan 130 trait split) |
| Modify | `docs/recipes.md` | "Re-exporting flowscope types" recipe shows `Driver`, not `FlowSessionDriver` |
| Modify | `README.md` | §"Status" up-leveled to 0.12 final scope (after plans 140-146 ship) |
| Modify | `examples/README.md` | Catalogue rewritten to lead with the `Driver`-shaped examples; raw-driver examples relegated to a "power users" section |
| Modify | `CLAUDE.md` | Project-instructions agent file — `Implementation Status` updated to summarise the 0.12 expanded cycle; module map cross-checked |

## Implementation steps

1. **Audit pass**: `grep -rn 'FlowSessionDriver\|FlowDatagramDriver\|FlowDriver' docs/ src/lib.rs examples/README.md README.md CLAUDE.md` to enumerate every reference. Tag each as KEEP (raw-primitives section), DEMOTE (move to "alternatives") or DELETE (stale).
2. **`src/lib.rs` top-level rustdoc**: rewrite intro to lead
   with `Driver<E>` + `SlotHandle`. Move the
   "Re-exporting flowscope types" appendix to use `Driver` in
   the example. `FlowSessionDriver` re-export recipe stays
   verbatim — it's still correct — but moves below.
3. **`docs/getting-started.md`** §0: already on `Driver<E>`
   after plan 0.12. §2 (Typed HTTP messages from a pcap)
   currently leads with `FlowSessionDriver`. Rewrite the lead
   to `Driver::builder(ext).session_on_ports(...).build()`;
   keep `FlowSessionDriver` as an "if you need the raw
   `SessionEvent` stream" subsection.
4. **`docs/concepts.md`** "Tier 2" block: clarify framing.
   Current text describes `FlowSessionDriver::new(ext, parser)`
   as "the only parser per driver" with `S` parameter access.
   Reword to "raw sync primitive for power users who need
   `S` parameter or the un-routed `SessionEvent` stream."
   Cross-link to typed `Driver<E>` from every mention.
5. **`docs/recipes.md`** sweep: every code sample that uses
   `FlowSessionDriver::new`, `let mut driver = FlowSessionDriver…`
   gets rewritten to `Driver::builder(ext).session_*(...)` /
   `driver.track_into(...)` / `slot.drain(...)`. ~7 sample
   blocks to update.
6. **`docs/observability.md`**: `FlowDriver::with_emit_anomalies(true)`
   examples become `DriverBuilder::emit_anomalies(true)`.
   Plus document the new `with_trace_messages(bool)` knob from
   plan 131.
7. **`docs/migration-0.11-to-0.12.md`** append: §7 — plan 130
   trait split recipe + §8 — plan 131 feature renames.
8. **`docs/eve-format.md`**: "Custom keys" section moves from
   `AnomalyFields` (key methods) to `KeyFields` per plan 130.
9. **`README.md`** §"Status" updated to summarise the expanded
   0.12 cycle.
10. **`examples/README.md`**: §00 "getting started" examples
    already use `Driver<E>` (hello_pipeline.rs, etc.).
    Cross-check; nothing to change beyond text framing.
11. **`CLAUDE.md`**: `Implementation Status` gets a new "0.12.0
    cycle (expanded)" header listing the 6 surviving plans
    (130 / 131 / 132 / 143 / 144 / 146) with one-line
    descriptions. Module map cross-checked against the new
    modules: `src/detect/patterns/` (plan 143),
    `src/detect/file/` (plan 146), and the `src/anomaly_fields.rs`
    trait split (plan 130).

## Tests

Doc-only plan; no Rust tests. Verification harness:

- `cargo doc --all-features --no-deps` builds with zero
  rustdoc warnings (intra-doc-link errors would catch
  type renames).
- `cargo test --all-features --doc` passes — every
  `rust,no_run` / `rust,ignore` block continues to compile
  with the new API references.
- `grep -rn 'FlowSessionDriver\|FlowDriver\|FlowDatagramDriver'
  docs/` returns only the controlled set of references
  documented under the "raw primitives" subsections.
- `grep -rn 'Pipeline\b' docs/ src/` returns zero hits.
- `grep -rn 'FlowMultiSessionDriver\|driver_unified' docs/
  src/ README.md CLAUDE.md` returns zero hits (after the
  audit pass).

## Acceptance criteria

- All `grep` checks above pass.
- `cargo doc --all-features --no-deps` clean.
- `cargo test --all-features --doc` clean.
- Every doc reference to `FlowSessionDriver` /
  `FlowDatagramDriver` / `FlowDriver` carries a cross-link
  to the typed `Driver<E>` either inline or in its section
  header.
- `docs/migration-0.11-to-0.12.md` covers plan 130/131
  breaks.
- `README.md` §"Status" reflects the expanded 0.12 scope.
- `CLAUDE.md` §"Implementation Status" lists all 6
  expanded-cycle plans (130 / 131 / 132 / 143 / 144 / 146).

## Risks

- **R1: `cargo test --doc` regressions.** Doc examples that
  previously compiled may break when API references change.
  Mitigation: run after every batched change; the
  `rust,no_run` block grammar is strict.
- **R2: Drift from plans 143 / 144 / 146 docs.** Each new
  feature plan ships its own rustdoc; this plan establishes
  the framing those feature docs should fit into. Sequencing:
  this plan lands after 130 / 131 and before 143 / 144 / 146
  so the new feature docs can lean on its conventions.
- **R3: Migration-doc churn.** `migration-0.11-to-0.12.md` is
  appended, not rewritten. Easy to drift; mitigation is
  one focused review pass per appended §.

## Effort

| Step | LoC | Hours |
|---|---|---|
| Audit pass + tagging | — | 1 |
| `src/lib.rs` rustdoc rewrite | 80 | 1.5 |
| `docs/getting-started.md` §2 rewrite | 50 | 1 |
| `docs/concepts.md` Tier-2 rewrite | 40 | 1 |
| `docs/recipes.md` 7 sample blocks | 150 | 3 |
| `docs/observability.md` driver knob updates | 30 | 0.5 |
| `docs/migration-0.11-to-0.12.md` §7-§8 append | 80 | 1.5 |
| `docs/eve-format.md` Custom-keys update | 20 | 0.5 |
| `README.md` Status section | 40 | 1 |
| `examples/README.md` framing pass | 20 | 0.5 |
| `CLAUDE.md` updates | 50 | 1 |
| Verification pass | — | 1 |
| **Total** | **~560** | **~13 hours (~2 days)** |

## Provenance

0.12 post-release audit flagged stale primary-recommendation
docs in `docs/getting-started.md` §2, `docs/concepts.md`
Tier 2, `docs/recipes.md` (multiple sections), and
`src/lib.rs` top-level rustdoc. The typed `Driver` shape
shipped in 0.11; the docs caught up only in §0 of
getting-started. This plan retires the rest of the debt
before community-adoption traffic hits docs.rs.
