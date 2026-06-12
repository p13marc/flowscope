# Plan 174 — Docs cross-link + README/CLAUDE/discoverability sweep

**Cycle:** 0.14.0 pre-release polish
**Priority:** P1 (DX gate)
**Effort:** ~half day
**Status:** drafted

## Motivation

Three discoverability seams remain after plans 170-173:

1. **Rustdoc "see also" links between sibling primitives are
   missing.** `RollingRate` doesn't reference
   `TimeBucketedCounter` / `TopK` / `BurstDetector`.
   `DestUnreachableKind` doesn't link to
   `IcmpType::dest_unreachable_kind` (or — after plan 170 —
   `MtuSignalKind`). `lookup_inner` doesn't link to
   `from_inner_canonical` / `from_inner_literal`.
2. **README features table** doesn't mention `LabelTable` /
   `RollingRate` / `MtuSignalKind` as part of the prelude's
   public surface.
3. **`docs/discoverability.md`** (shipped in plan 167) doesn't
   yet reference the three new examples from plan 173.

This is pure DX. Zero code changes; zero new public surface.

## Proposed changes

### Rustdoc cross-links

Add `[…]` doc links in these positions:

- `src/correlate/rolling_rate.rs`:
  - Crate-level: "see also [`TimeBucketedCounter`], [`TopK`],
    [`Ewma`] for related primitives."
  - On `top_k` (plan 171): "lighter-weight than maintaining a
    separate [`TopK`] — `top_k` sorts at query time, [`TopK`]
    sorts at update time."
- `src/icmp/types.rs`:
  - On `DestUnreachableKind`: "see [`MtuSignalKind`] for v4
    `FragmentationNeeded` / v6 `PacketTooBig` MTU mismatch
    signal." (After plan 170 lands.)
  - On `IcmpType::dest_unreachable_kind`: "pairs with
    [`IcmpType::mtu_signal`] for MTU events."
- `src/tracker.rs`:
  - On `lookup_inner`: "internally calls
    [`FiveTupleKey::from_inner_canonical`]. Use that directly
    if you need to construct a key without consulting the
    tracker."
- `src/extract/five_tuple.rs`:
  - On `app_label`: "see [`Self::app_label_with`] for site-
    custom overrides via [`LabelTable`]."
  - On `app_label_with`: "see [`Self::app_label`] when no
    overrides are needed."
- `src/correlate/indexed.rs`:
  - On `drain_expired`: "discards-only variant:
    [`Self::evict_expired`]."
  - On `evict_expired`: "inspecting variant:
    [`Self::drain_expired`]."
- `src/event.rs`:
  - On `bytes_for` / `pkts_for` / `direction_skew`: cross-link
    each from the others.

### README features table

`README.md` — extend the "Quick API map" or equivalent
section (whichever is the table) with:

| Surface | Path | Since |
|---|---|---|
| Site-custom port labels | `flowscope::well_known::LabelTable` | 0.14 |
| Per-key sliding-window rate | `flowscope::correlate::RollingRate` | 0.14 |
| MTU mismatch signal | `flowscope::icmp::MtuSignalKind` | 0.14 |
| ICMP error → flow join | `FlowTracker::lookup_inner` | 0.14 |

### `docs/discoverability.md`

Append a "## Worked examples" section listing the three new
examples from plan 173 with one-line pitches each. Cross-link
from the "Count things per key over time" / "React to ICMP
errors" / "Emit structured anomalies" sections to the
appropriate example.

### `CLAUDE.md`

Update the 0.14.0 cycle section to add the post-cycle
additions (plans 170-174) inline at the end of the existing
plan list. Keep it brief — one bullet per plan.

### `docs/recipes.md`

The "0.14 patterns" section already covers ICMP correlation,
RollingRate bandwidth-by-app, LabelTable, and drain_expired.
After plan 170 lands, add a 5th recipe: "MTU-mismatch
detection with `mtu_signal()`".

### `CHANGELOG.md`

Extend the 0.14.0 section's "Added" list with the new
plan 170 / 171 / 172 surfaces. Plans 173 / 174 are pure DX
and don't add public surface — call them out in a
"Documentation" sub-section if one doesn't exist.

## Files touched

- ~8 source files with rustdoc `[Type]` links
- `README.md`
- `CLAUDE.md`
- `CHANGELOG.md`
- `docs/discoverability.md`
- `docs/recipes.md`
- `docs/migration-0.13-to-0.14.md` — append §11 for plans 170-172

## Acceptance criteria

- `cargo doc --all-features --no-deps` reports zero broken
  intra-doc links.
- README features table includes the four new entries.
- `docs/discoverability.md` references each new example.
- `CLAUDE.md` 0.14 section reflects plans 170-174.

## Non-goals

- Rewriting `docs/getting-started.md` — the example surface
  there is intentionally minimal.
- Adding a `docs/0.14-overview.md` standalone doc — the
  CHANGELOG + migration + recipes triad covers it.
