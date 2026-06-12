# Plan 167 — Discoverability sweep

## Summary

Pure DX. Surface the existing `correlate::*` primitives + ICMP
helpers + `FlowStats` accessors that are hidden behind module
paths and missing rustdoc cross-links. Adds to `flowscope::prelude`,
introduces `docs/discoverability.md`, and writes "see also"
links between related types.

**No new code surface** — just makes the existing surface
scannable in 5 minutes by a new user who only reads the prelude.

## Status

Not started. P2 for 0.14.

## Prerequisites

- Plans 162, 163, 164 (so the new exports they ship land in
  the prelude at the same time).

## Out of scope

- **Sub-preludes** (`flowscope::prelude::reports`). The main
  prelude is ~25 names today; adding ~10 keeps it under 40 —
  well within "glance-able" range. Sub-preludes add a discovery
  step the cycle is meant to eliminate.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/prelude.rs` | Add the discoverability re-exports |
| New | `docs/discoverability.md` | One-page tour of the existing surface, organised by use case |
| Modify | `docs/recipes.md` | Cross-link from each pattern recipe to the relevant primitive's rustdoc |
| Modify | Each correlate primitive's rustdoc | Add "See also" sections linking related primitives |

## API additions to `flowscope::prelude`

Behind the existing feature gates (`tracker`, `extractors`, etc.):

| Re-export | Feature | Why prelude |
|---|---|---|
| `correlate::TimeBucketedCounter` | `tracker` | Most-reached-for rate-tracking primitive |
| `correlate::TimeBucketedSet` | `tracker` | Set-membership over window (powers `lateral_movement`) |
| `correlate::KeyIndexed` | `tracker` | TTL'd LRU index — every monitor reaches for it |
| `correlate::BurstDetector` | `tracker` | Spike detection — powers `pattern_detector!`-style alarms |
| `correlate::Ewma` | `tracker` | Smoothed latency / throughput |
| `correlate::TopK` | `tracker` | Top-N talkers |
| `correlate::RollingRate` | `tracker` | (Plan 164; ship as part of this sweep) |
| `correlate::FlowStateMap` | `tracker` + `extractors` | Per-flow user state |
| `icmp::IcmpType` | `icmp` | Match arm for ICMP error handlers |
| `icmp::IcmpMessage` | `icmp` | Parsed ICMP message |
| `icmp::IcmpInner` | `icmp` | Embedded original-packet 5-tuple |
| `icmp::DestUnreachableKind` | `icmp` | (Plan 162) |
| `well_known::LabelTable` | `extractors` | (Plan 165) site-custom port labels |

## `docs/discoverability.md` outline

A one-page tour grouped by use case:

```markdown
# Discoverability — find the right primitive in 5 minutes

## "I want to count things per key over time"
- [`TimeBucketedCounter<K>`] — `+= 1` per bump, rate over window
- [`RollingRate<K, V>`] — generic `V` increments (bytes/sec, custom units)
- [`Ewma<K>`] — exponential moving average for smoothed metrics

## "I want to track unique things per key over time"
- [`TimeBucketedSet<K, V>`] — distinct values seen per key in window
- [`KeyIndexed<K, V>`] — TTL'd lookup index with LRU eviction

## "I want to detect anomalies / patterns"
- [`BurstDetector<K, E>`] — spike vs baseline
- [`SequencePattern`] — FSM over typed events
- [`detect::patterns::PortScanDetector`] — Threshold Random Walk
- [`detect::patterns::BeaconDetector`] — CV-composite RITA-style
- [`detect::patterns::DgaScorer`] — bigram log-likelihood

## "I want top-N reports"
- [`TopK<K>`] — Misra-Gries
- [`RollingRate::snapshot`] + manual sort

## "I want per-flow state"
- [`FlowStateMap<T>`] — auto-evict on `FlowEvent::Ended`
- [`KeyIndexed<K, T>`] — manual TTL semantics

## "I want to react to ICMP errors"
- [`IcmpType::is_error`] — gate before unpacking
- [`IcmpType::error_inner`] — get the embedded 5-tuple
- [`IcmpType::dest_unreachable_kind`] — unified v4/v6 classification
- [`FlowTracker::lookup_inner`] — join the ICMP error back to a live flow

## "I want labels for metrics / reports"
- [`FiveTupleKey::protocol_label`] — well-known L7 label, Option
- [`FiveTupleKey::app_label`] — always-Some, L4 fallback
- [`L4Proto::canonical_name`] — lowercase L4 slug
- [`L4Proto::proto_str`] — uppercase EVE/Suricata schema slug
- [`well_known::LabelTable`] — site-custom port overrides

## "I want flow stats summaries"
- [`FlowStats::total_bytes`] / `total_packets` / `total_retransmits`
- [`FlowStats::retransmit_rate`] — fraction of total packets
- [`FlowStats::duration`] / `duration_secs`
- [`FlowStats::bytes_for(side)`] / `pkts_for(side)` (plan 168)
- [`FlowStats::direction_skew`] (plan 168)
```

## Implementation steps

1. Add the re-exports to `src/prelude.rs` (gated as listed
   above).
2. Write `docs/discoverability.md` from the outline.
3. Add "See also" sections to:
   - `TimeBucketedCounter` → cross-link to `RollingRate`,
     `Ewma`.
   - `KeyIndexed` → cross-link to `FlowStateMap`.
   - `IcmpType` → cross-link to `DestUnreachableKind`,
     `lookup_inner`.
   - `FlowStats` → cross-link to per-side accessors (plan
     168).
4. Update `docs/concepts.md` with a one-paragraph pointer to
   `discoverability.md`.

## Tests

- Compile-time: prelude re-exports actually resolve under
  every feature combination (CI matrix already covers this).
- `examples/01-discoverability/use_prelude.rs` (new example):
  one short program that uses 5 of the newly-prelude'd
  primitives, exercising the discoverability story.

## Acceptance criteria

- `cargo doc --all-features --no-deps` zero warnings (intra-
  doc links resolve).
- `flowscope::prelude::*` is enough to write a basic monitor
  without manual `use flowscope::correlate::…` imports.
- `docs/discoverability.md` reads in under 5 minutes.

## Risks

**R1: Prelude bloat.** ~35 names is near the comfort ceiling.
Mitigation: organize alphabetically; revisit if it hits ~50.

**R2: Intra-doc link breakage.** "See also" links can break
under `--all-features --no-deps`. Mitigation: run `cargo doc`
with all-features in CI; fix every warning.

## Effort

- LOC delta: +400 (prelude expansion + discoverability.md +
  rustdoc cross-links + example).
- Time estimate: **1 day**.

## Provenance

Wishlist plan 167.
