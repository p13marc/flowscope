# Plan 151 — 0.12 expanded cycle umbrella

## Summary

Expanded 0.12 cycle scope. The original 0.12 cycle (plan 128 +
plans 122-127, all shipped to master between
`781595f`-`3a96cfa`) covered Send slot handles, EVE writer,
deferred builder, AnomalyFields trait, Timestamp ISO 8601,
chrono interop, and 3 `correlate::*::new_unbounded` ctors.
Phase 8 release was gated on user consent.

After a deep-analysis pass (post-0.12 strategic review), the
user opted to expand the cycle and ship the focused
debt-retirement + lightweight feature additions as one 0.12.0
release before crates.io publish:

- **API debt retirement** (plans 130 / 131 / 132) — pre-1.0
  cleanup driven by the audit.
- **Detection-patterns library** (plan 143) — packages
  existing primitives as named detectors.
- **ECH signal extraction** (plan 144) — TLS modernisation.
- **File hash sinks** (plan 146) — DFIR / IR pipeline ask.

**Deferred to future cycles** (initially drafted, then
deferred per user judgement to keep the cycle shippable):

- JA4+ family completion (was plan 140) — spec drift +
  x509-parser dep + per-flow tracker state. Resurrect when
  a consumer specifically asks.
- IPFIX / NetFlow v9 exporter (was plan 141) — netgauze
  dep maturity + enterprise IE numbering verification.
  Resurrect under `flowscope-export` sister crate per
  `docs/design.md` when collector-base demand surfaces.
- HTTP/2 + Akamai fingerprint (was plan 142) — `httlib-hpack`
  maintenance risk + per-direction dynamic-table cost +
  significant LoC. Resurrect when the rust ecosystem
  consolidates around a passive-HTTP/2 crate.
- QUIC Initial parser + JA4-QUIC (was plan 145) — quinn-proto
  API churn + ~2 MB compiled-size cost. Resurrect when a
  consumer ships an HTTP/3-heavy use case.

These deferrals are tracked under the **stale-deferred** section
of `plans/INDEX.md` so a future cycle can pick them up without
re-doing the design.

1.0 is determined by community adoption, not a target. The
0.12 cycle ships a focused debt-retirement + small-wins release
that hardens the public surface before adoption traffic.

## Status

In progress. 0.12.0-base shipped to master 2026-06; expansion
plans drafted 2026-06.

## Cycle sequencing

**Phase A — API debt retirement** (must land first; affects
every following plan's references):

| Plan | Title | Effort | Status |
|---|---|---|---|
| 130 | Trait shape + API symmetry cleanup | 2 days | drafted |
| 131 | Error module + feature-flag pruning | 1 day | drafted |
| 132 | Documentation overhaul | 2 days | drafted |

**Phase B — Named detectors**:

| Plan | Title | Effort | Status |
|---|---|---|---|
| 143 | Detection-patterns library | 4 days | drafted |

**Phase C — Targeted modernisation + IR**:

| Plan | Title | Effort | Status |
|---|---|---|---|
| 144 | ECH signal extraction | 1.5 days | drafted |
| 146 | File hash sinks | 3 days | drafted |

**Phase E — release mechanics**:

| Step | Effort |
|---|---|
| Final bench gate + clippy + docs sweep | 0.5 days |
| `cargo publish` dry-run | 0.25 days |
| Tag + push (gated on per-release consent) | 0.25 days |

**Total estimated effort:** ~14.5 working days, single
developer. ~3 working weeks calendar. Parallelisable:
130 + 131 + 132 can run concurrently; 143 + 144 + 146 are
independent. Realistic single-developer pass: ~3 weeks.

## Breaking-change inventory

Total pre-1.0 breaks shipped in the expanded 0.12 cycle
(across plans 130 / 131):

| Source | Break | Migration |
|---|---|---|
| 130 | `AnomalyFields` loses key methods | `use flowscope::KeyFields;` |
| 130 | Emit writers gain `K: KeyFields` bound | Custom-K users add `impl KeyFields for MyKey` |
| 130 | `Event::FlowPacket.tcp` field → accessor | `e.tcp()` instead of `match { tcp, .. } =>` |
| 130 | `Timestamp` chrono interop becomes infallible `From` | drop `.try_into().unwrap()` |
| 130 | `DriverBuilder` registration gains `P::Message: Send` | invisible — every shipped parser already satisfies it |
| 131 | `Module::Pipeline` enum variant removed | drop the `match` arm (was dead code since 0.11) |
| 131 | `ja3` + `ja4` features collapsed into `tls-fingerprints` | rename in Cargo.toml |
| 131 | `tracing-messages` feature removed | use `DriverBuilder::with_trace_messages(bool)` |
| 144 | `TlsClientHello` / `TlsServerHello` / `TlsHandshake` grow ECH fields | additive, `#[non_exhaustive]` covers it |

Net: 9 user-visible changes; **3 are silent** (covered by
`#[non_exhaustive]` or dead-code removal: `DriverBuilder` Send
bound is a no-op for shipped parsers, `Module::Pipeline` was
dead code since 0.11, TLS field additions are
`#[non_exhaustive]`-additive). **6 require explicit consumer
migration** (per the table above: `KeyFields` import, `K`
bound on custom keys, `Event::tcp()` accessor, infallible
chrono `From`, `tls-fingerprints` feature rename,
`with_trace_messages(bool)` runtime knob). All mechanical;
CHANGELOG entries provide one-line recipes.

## CI matrix changes

The 0.12 expanded cycle grows the CI matrix by 2 entries:

- `tls-fingerprints` (replaces `ja3`, `ja4`)
- `file-hash`

Net: matrix grows from 11 to 12 entries (one rename swap +
one new gate). Each is a no-default feature build + clippy.

## Version + release

**Target version: 0.12.0** (per user directive: "release
everything for the 0.12").

The 0.12.0 base is sitting on master at commit `f300750` with
`Cargo.toml::version = "0.12.0"`. The 0.12 expanded cycle
lands as commits on master without a version bump until Phase E;
the user-facing label stays `0.12.0`.

The 1.0 timing is community-driven. Per the user:
> "1.0 will be determined by the community adoption"

No 1.0 deadline; we ship 0.12.0 focused on debt-retirement +
small wins and watch adoption.

## Phase E — Release mechanics (gated)

Per `feedback_release_consent.md` (memory), `cargo publish`
requires explicit per-release consent. The expanded 0.12
release process:

1. **Final gates** (automatic):
   - `cargo build --all-features` clean
   - `cargo test --all-features` clean (target ≥ 780 tests
     after the expansion; 721 in pre-expansion 0.12 base)
   - `cargo clippy --all-features --all-targets -- -D warnings`
     clean
   - `cargo doc --all-features --no-deps` zero warnings
   - `cargo machete` clean
   - All 12 CI matrix entries clean
   - `cargo bench --bench zero_alloc` — gate row
     `track_into_5_slots_steady_state` stays at 0 allocs/pkt
   - `cargo publish --dry-run --all-features` packages
2. **Consent**: user grants explicit per-release authorisation.
3. **Publish**: `cargo publish --all-features`.
4. **Tag**: `git tag 0.12.0 && git push origin 0.12.0` (no
   `v` prefix — matches the 0.1.0 / 0.2.0 / … / 0.11.1
   convention).
5. **Post-release**: CHANGELOG header marks 0.12.0 as shipped;
   plans/INDEX.md retires the 0.12 cycle entries; plan files
   for the 6 surviving plans (130 / 131 / 132 / 143 / 144 /
   146) deleted per project convention.

## Acceptance criteria (cycle-level)

- All 6 implementation plans (130, 131, 132, 143, 144, 146)
  shipped per their individual acceptance criteria.
- Test count post-cycle: ≥ 780 (up from 721).
- Zero clippy warnings, zero rustdoc warnings, zero
  `cargo machete` findings.
- Bench gate maintained: `track_into_5_slots_steady_state`
  reports 0 allocs/pkt.
- 12 CI feature-matrix entries clean.
- `cargo publish --dry-run --all-features` packages clean.
- Documentation reflects every new feature
  (`docs/detect-patterns.md`, `docs/tls-ech.md`,
  `docs/file-hash.md`).
- Migration recipes in `docs/migration-0.11-to-0.12.md` cover
  every break.
- `README.md` `Status` section + `CLAUDE.md`
  `Implementation Status` reflect the expanded scope.

## Risks (cycle-level)

- **R1: Quality near-misses (per 0.12 base audit pattern).**
  The original 0.12 cycle audit caught initial-commit
  thinness on plan 123 (EVE: missing flow_hash, docs, example)
  and plan 124 (deferred builder: 4/10 tests). Mitigation:
  each plan in this expansion ships its acceptance criteria
  AND test list AND doc list; per-plan sign-off requires all
  three.
- **R2: ECH spec drift.** ECH is still IETF draft; bytes-
  level parser breaks if the wire format changes between
  drafts. Mitigation in plan 144: pin a draft version in
  documentation; fixtures captured against specific browser
  builds.
- **R3: Tranco bigram-table reproducibility (plan 143).**
  Tranco regenerates daily. Mitigation: pin a snapshot date in
  documentation; ship a `tools/generate-bigrams.rs` so the
  table is independently re-generatable.
- **R4: API debt left over.** Plans 130 / 131 / 132 retire
  the audit-flagged debt but won't catch debt not yet
  identified. Mitigation: post-Phase-A code review pass
  before Phase B/C plans land.

## Effort summary

| Phase | Plans | Effort |
|---|---|---|
| A | 130, 131, 132 | 5 days |
| B | 143 | 4 days |
| C | 144, 146 | 4.5 days |
| E | Release mechanics | 1 day |
| **Total** | | **~14.5 days** |

## Provenance

This conversation (2026-06):
- 0.12 base shipped to master through `3a96cfa`.
- User asked: "is it the right direction? can we improve
  further? do we have to add more features?"
- Deep-analysis pass identified:
  - 7 audit-flagged rough edges (→ plans 130, 131, 132)
  - 3 Tier-1 strategic adds: JA4+ family, IPFIX, HTTP/2
  - 1 Tier-2 strategic add: detection patterns library
  - 3 Tier-3 strategic adds: ECH, QUIC, file hashing
- User opted to ship the focused subset as 0.12.0,
  deferring the heavier feature additions: "I think we can
  remove the plans: 140, 141, 142 and 145".

The deferred plans (140 JA4+, 141 IPFIX, 142 HTTP/2, 145 QUIC)
remain in the "stale-deferred" section of `plans/INDEX.md`
with their strategic motivation captured for a future cycle.
The design knowledge isn't lost — the plans were drafted in
full (with API signatures, test plans, risk analysis, effort
estimates) before being deferred; resurrecting any one of
them is a `git log` + apply exercise, not a redesign.

Plans 122 / 123 / 124 / 126 / 127 have shipped; their plan
files were retired per convention. Plans 130 / 131 / 132 /
143 / 144 / 146 are this expanded cycle's scope.

## Why this scope, why now

The 0.12 strategic review found:

- flowscope's niche ("Rust building-block library for passive
  flow analysis") is **genuinely uncontested** in published
  crates as of Jan 2026.
- 5 of the 0.12 audit's 7 "rough edges" are public-trait-
  shape debt; landing them pre-adoption is cheaper than
  post-adoption (Phase A).
- Detection patterns (BeaconDetector, PortScanDetector,
  DgaScorer) package the FAQ recipes consumers keep
  rebuilding — high ROI per LoC (Phase B).
- ECH + file hashes are surgical additions: small surface,
  obvious consumer (TLS modernisation; DFIR/IR pipelines).
  Phase C.
- The heavy feature additions (JA4+ / IPFIX / HTTP/2 / QUIC)
  each have substantial dep / spec / maintenance risks that
  could derail the cycle. Deferring them to a future cycle
  when a specific consumer ask lands keeps 0.12 shippable.

Shipping this focused 0.12.0 retires the public-surface debt
before adoption, ships three lightweight high-value features,
and leaves the heavy features as well-thought-through future
cycles whose designs are already captured.
