# Plan 174 — DX sweep: examples + docs cross-link + README/CLAUDE/recipes

**Cycle:** 0.14.0 pre-release polish
**Priority:** P0 (DX gate — examples are the discoverability fix)
**Effort:** ~1 day
**Status:** drafted (consolidation review merged old plans 173+174)

## Motivation

Two seams remain at the end of the polish cycle:

1. **Zero runnable examples touch the 0.14 surface.** `grep -l
   'RollingRate|lookup_inner|LabelTable|DestUnreachableKind|drain_expired|app_label|direction_skew|throughput_bps|mtu_signal' examples/`
   returns nothing. Users have rustdoc, recipes in
   `docs/recipes.md` §"0.14 patterns", and the migration doc —
   but nothing to `cargo run`.
2. **Rustdoc "see also" links between sibling primitives are
   missing.** `RollingRate` doesn't reference
   `TimeBucketedCounter` / `TopK` / `BurstDetector`.
   `DestUnreachableKind` doesn't link to
   `MtuSignalKind` (after plan 170). `lookup_inner` doesn't
   link to `from_inner_canonical` / `from_inner_literal`.

This plan ships both threads as one DX sweep — they're
naturally co-edited and the same review pass covers both.

## §1 Examples — three runnable scripts

Place under `examples/04-observability/`.

### `bandwidth_by_app.rs`

`RollingRate<&'static str, u64>` keyed on `app_label_with(&LabelTable)`,
fed from a pcap source, prints top-10 talkers every second.
Demonstrates: plans 163 + 164 + 165 + 171 (`top_k`).

### `icmp_explained_drops.rs`

`FlowTracker::lookup_inner` joins ICMP errors back to live
flows; `DestUnreachableKind` classifies DU codes;
`MtuSignalKind` (plan 170) handles v4/v6 MTU events. Result:
"flow X died because of port-unreachable from host Y"
log lines. Demonstrates: plans 161 + 162 + 170.

### `direction_skew_anomaly.rs`

`FlowStats::direction_skew` + `bytes_for(side)` +
`throughput_bps_for(side)` (plan 173) flag flows that ended
with |skew| > 0.9. Demonstrates: plans 168 + 173.

## §2 Rustdoc cross-links

Add `[…]` doc links in these positions (purely additive):

- `src/correlate/rolling_rate.rs`:
  - Module: "see also [`TimeBucketedCounter`], [`TopK`],
    [`Ewma`] for related primitives."
  - `top_k`: "lighter-weight than maintaining a separate
    [`TopK`] — `top_k` sorts at query time, [`TopK`] sorts
    at update time."
  - `sum`: "sibling to [`Self::rate`] — same data without the
    per-second divide."
- `src/icmp/types.rs`:
  - `DestUnreachableKind`: "see [`MtuSignalKind`] for v4
    `FragmentationNeeded` / v6 `PacketTooBig` MTU mismatch."
  - `IcmpType::dest_unreachable_kind`: "pairs with
    [`IcmpType::mtu_signal`] for MTU events."
  - `MtuSignalKind` (plan 170): "sibling to
    [`DestUnreachableKind`] for non-MTU Destination Unreachable
    classification."
- `src/tracker.rs`:
  - `lookup_inner`: "internally calls
    [`crate::extract::FiveTupleKey::from_inner_canonical`].
    Use that directly to construct a key without consulting
    the tracker."
- `src/extract/five_tuple.rs`:
  - `app_label`: "see [`Self::app_label_with`] for site-
    custom overrides via [`crate::well_known::LabelTable`]."
  - `app_label_with`: "see [`Self::app_label`] when no
    overrides are needed."
- `src/correlate/indexed.rs`:
  - `drain_expired`: "discards-only variant:
    [`Self::evict_expired`]."
  - `evict_expired`: "inspecting variant:
    [`Self::drain_expired`]."
- `src/event.rs` (`FlowStats`):
  - `bytes_for` ↔ `throughput_bps_for` ↔ `pkts_for` ↔
    `throughput_pps_for` — all 4 cross-link.
  - `direction_skew`: "complements [`Self::bytes_for`] for
    per-side analysis."

## §3 README features table

`README.md` — extend the "Quick API map" or equivalent table
with five new rows:

| Surface | Path | Since |
|---|---|---|
| Site-custom port labels | `flowscope::well_known::LabelTable` | 0.14 |
| Per-key sliding-window rate | `flowscope::correlate::RollingRate` | 0.14 |
| MTU mismatch signal | `flowscope::icmp::MtuSignalKind` | 0.14 |
| ICMP error → flow join | `FlowTracker::lookup_inner` | 0.14 |
| Flow throughput accessors | `FlowStats::throughput_bps*` | 0.14 |

## §4 `docs/discoverability.md`

Append a "## Worked examples" section listing the three
plan 174 §1 examples with one-line pitches each. Cross-link
from "Count things per key over time" / "React to ICMP errors"
sections to the appropriate example.

## §5 `docs/recipes.md`

Append a 5th 0.14 recipe: **MTU-mismatch detection with
`mtu_signal()`** (plan 170). 30 lines, shows v4 + v6 in one
match arm.

## §6 `docs/migration-0.13-to-0.14.md`

Append three sections:
- §11: `IcmpType::mtu_signal()` + `MtuSignalKind` (plan 170)
- §12: `LabelTable` completeness + `override_count` removal
  (plan 172) — the only breaking change in the polish round
- §13: `RollingRate` completeness — `sum`, `top_k`, `clear`,
  `len` (plan 171)
- §14: `FlowStats::throughput_bps*` (plan 173)

## §7 `CHANGELOG.md`

Extend the 0.14.0 section's "Added" list with the new
surfaces from plans 170 + 171 + 172 + 173. Add a "Removed"
sub-section listing `LabelTable::override_count` → `len`.

## §8 `CLAUDE.md`

Update the 0.14.0 cycle section to add the post-cycle
additions (plans 170-174) inline. Keep brief — one bullet
per plan. Update test count.

## Files touched

- `examples/04-observability/bandwidth_by_app.rs` — new
- `examples/04-observability/icmp_explained_drops.rs` — new
- `examples/04-observability/direction_skew_anomaly.rs` — new
- `examples/04-observability/README.md` — append rows
- `examples/Cargo.toml` — register `[[example]]` entries
- `examples/README.md` — append rows
- ~8 source files with rustdoc `[Type]` links
- `README.md` — features table
- `CLAUDE.md` — 0.14 cycle section
- `CHANGELOG.md` — Added + Removed sections
- `docs/discoverability.md` — Worked examples section
- `docs/recipes.md` — MTU recipe
- `docs/migration-0.13-to-0.14.md` — §11-§14

## Acceptance criteria

- All three examples build under their declared features.
- All three run end-to-end against `tests/data/mixed_short.pcap`
  (or available fixture) producing non-empty output.
- Each example's top doc-comment cites the plans it
  demonstrates + migration-doc section.
- `cargo doc --all-features --no-deps` reports zero broken
  intra-doc links.
- README features table includes the five new entries.
- `docs/discoverability.md` references each new example.
- `CLAUDE.md` 0.14 section reflects plans 170-174.
- Listed in `examples/README.md` index.

## Non-goals

- Async / live-capture variants — netring-side.
- A combined "all-three-in-one" mega-example — separate is
  clearer.
- Rewriting `docs/getting-started.md` — its example surface
  is intentionally minimal.
- Adding a `docs/0.14-overview.md` standalone doc — the
  CHANGELOG + migration + recipes triad covers it.
