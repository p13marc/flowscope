# Plan 62 — Intra-doc-link recipe in published docs

## Summary

The 0.6 cycle's plan 60 added a recipe explaining how downstream
re-exporters should write intra-doc links to `flowscope` types
without tripping rustdoc's `redundant_explicit_links` lint. The
recipe shipped to `CLAUDE.md`, which is in-repo only. The audience
for the recipe — maintainers of crates that re-export `flowscope`
types (netring, future sister crates) — reads **docs.rs** and the
crates.io readme. They never see `CLAUDE.md`.

This plan closes the gap by moving the recipe (or a copy) into the
published reference material so it surfaces on docs.rs.

The netring author specifically called this out in
[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
§12: *"Saves every downstream crate the same 5-minute debug
session."* The recipe is correct as written; only its discoverable
location is wrong.

## Status

Not started.

## Prerequisites

- Plan 60 — shipped in 0.6.0. The recipe text already exists in
  `CLAUDE.md:320–340` and can be copy-edited / adapted; this plan
  does not re-derive it.

## Out of scope

- Changing the recipe content itself. The CLAUDE.md version is
  battle-tested (debugged across three netring doc fixes per the
  feedback author).
- Removing the CLAUDE.md copy. CLAUDE.md is the right place for
  in-repo maintainer guidance; keeping it there also serves
  contributors who are writing rustdoc inside flowscope itself.
  This plan **adds** a published location; it does not migrate
  away from CLAUDE.md.
- Auditing existing flowscope rustdoc for `redundant_explicit_links`
  warnings inside the crate. That's a separate housekeeping pass.
- Adding the recipe to the crates.io README. The README is the
  landing-page elevator pitch; reference details belong in
  `docs/` and rustdoc.

## Files

- `docs/SESSION_GUIDE.md` — add a new top-level section titled
  "Re-exporting flowscope types" near the end of the file (after
  the existing reassembly-health section but before the trait-shape
  reference block). Recipe lives here.
- `src/lib.rs` — one-paragraph crate-level rustdoc breadcrumb that
  links to the SESSION_GUIDE section, so the recipe surfaces from
  the docs.rs landing page without bloating the crate-level
  module-overview text.
- `CLAUDE.md` — replace the existing recipe block with a one-line
  pointer to the SESSION_GUIDE section (avoid duplicate maintenance).
  In-repo readers follow the pointer; the source of truth lives in
  `docs/`.

No source-code changes; no Cargo.toml changes; no test changes.

## API

No new API. Doc-only.

## Implementation steps

1. **Move the recipe.** Copy the body of `CLAUDE.md:320–340` (the
   "Intra-doc links for re-exporters" section, including the
   one-line code example) into a new `## Re-exporting flowscope
   types` section in `docs/SESSION_GUIDE.md`. Adjust phrasing for
   audience: SESSION_GUIDE is consumer-facing reference; CLAUDE.md
   is maintainer-facing. Specifically:
   - Replace any in-repo path references (none currently) with
     intra-crate item links that resolve on docs.rs.
   - Lead with the *problem* (a downstream re-exporter writes
     `[FlowSessionDriver](flowscope::FlowSessionDriver)` and
     rustdoc warns) before the *fix*.
   - Add a second small example showing the netring-shape
     re-export pattern, since that's the modal consumer:
     ```rust,ignore
     // In netring/src/lib.rs:
     pub use flowscope::FlowSessionDriver;

     // In netring's rustdoc:
     /// See [`FlowSessionDriver`] for the sync session-event driver.
     ```
2. **Crate-level breadcrumb.** Add a short paragraph at the bottom
   of the existing module-overview section in `src/lib.rs`'s
   crate-level rustdoc:
   ```text
   # Re-exporting flowscope types

   Crates that re-export flowscope types should write intra-doc
   links in the bare `[FlowSessionDriver]` form, not the explicit
   `[FlowSessionDriver](flowscope::FlowSessionDriver)` form — see
   the SESSION_GUIDE's "Re-exporting flowscope types" section for
   the rationale.
   ```
   Keep it under five lines so the crate-level overview stays
   scannable on docs.rs.
3. **CLAUDE.md update.** Replace the full recipe block in
   `CLAUDE.md` with:
   ```markdown
   ## Intra-doc links for re-exporters

   See `docs/SESSION_GUIDE.md` → "Re-exporting flowscope types"
   for the recipe. (Lives there so downstream consumers can find
   it on docs.rs.)
   ```
4. **Verify.** Run `cargo doc --all-features --no-deps` and
   spot-check the rendered SESSION_GUIDE section + crate-level
   breadcrumb in a browser. Confirm the SESSION_GUIDE link from
   the crate-level docs resolves correctly (it goes through
   docs.rs's static rendering of the file).

## Tests

No code tests — doc-only change.

Manual verification:
- `cargo doc --all-features --no-deps` produces zero warnings.
- The new SESSION_GUIDE section renders correctly.
- The crate-level breadcrumb section appears on the docs.rs
  landing page.

## Acceptance criteria

- `docs/SESSION_GUIDE.md` has a `Re-exporting flowscope types`
  section that contains a working code example and explains the
  rationale (rustdoc resolves through re-exports; explicit paths
  duplicate that resolution and trigger `redundant_explicit_links`).
- `src/lib.rs` crate-level rustdoc points readers from the
  module-overview to the SESSION_GUIDE section.
- `CLAUDE.md` no longer holds a duplicate copy of the recipe; it
  contains a one-line pointer to the SESSION_GUIDE section so the
  source of truth is unambiguous.
- `cargo doc --all-features --no-deps` clean (no warnings).
- `cargo test --all-features` still passes (defensive — doctest
  blocks marked `ignore` shouldn't break, but verifying).

## Risks

- **Drift between CLAUDE.md and SESSION_GUIDE.** Mitigated by
  collapsing CLAUDE.md to a pointer; the SESSION_GUIDE section is
  the single source of truth. Future edits land in one file.
- **The recipe stops applying after a rustdoc behaviour change.**
  Low: this is a long-standing rustdoc lint, and the recipe is
  the documented mitigation for it. If rustdoc changes, the
  netring author will be the first to notice.

## Effort

~30 lines of documentation movement, zero source-code changes.
30–45 minutes including rebuild + visual verification on docs.rs
rendering (use `cargo doc --open`).

## Provenance

Identified as a partial-implementation gap during the post-0.6.0
audit of `docs/feedback-2026-05-22-netring.md` (2026-05-23, after
0.6.0 release): every other proposal in that document landed in
its intended location, but item 12's recipe shipped to a location
its audience doesn't read.

The netring author explicitly framed item 12 as a
discoverability fix — *"saves every downstream crate the same
5-minute debug session"* — which means the recipe is only valuable
if downstream crates can find it. CLAUDE.md, being source-tree
only and excluded from the crates.io package, fails that test.

Target release: 0.7.0 (next minor; no need to rush a 0.6.1 for a
doc-only fix).
