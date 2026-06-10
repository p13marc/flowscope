# Plan 151 — 0.12 expanded cycle umbrella

## Summary

Expanded 0.12 cycle scope. The original 0.12 cycle (plan 128 +
plans 122-127, all shipped to master between
`781595f`-`3a96cfa`) covered Send slot handles, EVE writer,
deferred builder, AnomalyFields trait, Timestamp ISO 8601,
chrono interop, and 3 `correlate::*::new_unbounded` ctors.
Phase 8 release was gated on user consent.

After a deep-analysis pass (this conversation, post-0.12
strategic review), the user opted to expand the cycle and ship
everything as one 0.12.0 release before going to crates.io:

- **API debt retirement** (plans 130 / 131 / 132) — pre-1.0
  cleanup driven by the audit.
- **JA4+ family completion** (plan 140) — table-stakes for
  2026 NDR / SIEM consumers.
- **IPFIX / NetFlow v9 exporter** (plan 141) — opens the
  NetFlow-collector consumer base.
- **HTTP/2 + Akamai fingerprint** (plan 142) — covers the
  majority of modern web traffic.
- **Detection-patterns library** (plan 143) — packages
  existing primitives as named detectors.
- **ECH signal extraction** (plan 144) — TLS modernisation.
- **QUIC Initial parser + JA4-QUIC** (plan 145) — covers the
  HTTP/3 traffic share.
- **File hash sinks** (plan 146) — DFIR / IR pipeline ask.

1.0 is determined by community adoption, not a target. The
0.12 cycle ships the maximally complete passive-flow library
flowscope can be in 2026, then we let real-world usage drive
1.0 timing.

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

**Phase B — Tier 1 features** (high consumer demand):

| Plan | Title | Effort | Status |
|---|---|---|---|
| 140 | JA4+ family completion | 4 days | drafted |
| 141 | IPFIX/NetFlow v9 exporter | 4 days | drafted |
| 142 | HTTP/2 + Akamai fingerprint | 5 days | drafted |

**Phase C — Tier 2 features** (named detectors):

| Plan | Title | Effort | Status |
|---|---|---|---|
| 143 | Detection-patterns library | 4 days | drafted |

**Phase D — Tier 3 features** (modernisation):

| Plan | Title | Effort | Status |
|---|---|---|---|
| 144 | ECH signal extraction | 1.5 days | drafted |
| 145 | QUIC Initial parser + JA4-QUIC | 5 days | drafted |
| 146 | File hash sinks | 3 days | drafted |

**Phase E — release mechanics**:

| Step | Effort |
|---|---|
| Final bench gate + clippy + docs sweep | 0.5 days |
| `cargo publish` dry-run | 0.25 days |
| Tag + push (gated on per-release consent) | 0.25 days |

**Total estimated effort:** ~32.5 working days, single
developer. ~6 working weeks calendar. Parallelisable: 130 +
131 + 132 can run concurrently; 140 + 141 + 142 are
independent; 143 + 144 + 146 are independent; 145 (QUIC) has
no hard prereqs but benefits from 140 (JA4+).

## Breaking-change inventory

Total pre-1.0 breaks shipped in the expanded 0.12 cycle
(across 130 / 131 / 140 / others):

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
| 140 | `TcpInfo::raw_options` field added | `#[non_exhaustive]` covers it; struct-literal callers add `..` |
| 140 | `TlsClientHello` / `TlsServerHello` / `TlsHandshake` grow fields | additive, `#[non_exhaustive]` covers it |
| 144 | `TlsClientHello` grows ECH fields | additive |

Net: 10 user-visible changes; 7 are silent under
`#[non_exhaustive]`; 3 require explicit consumer migration
(trait method moves, feature renames, field → accessor). All
mechanical; CHANGELOG entries provide one-line recipes.

## CI matrix changes

The 0.12 expanded cycle grows the CI matrix by 4 entries:

- `tls-fingerprints` (replaces `ja3`, `ja4`)
- `http2`
- `quic`
- `emit-ipfix`
- `file-hash`

Net: matrix grows from 11 to 15 entries. Each is a no-default
feature build + clippy.

## Version + release

**Target version: 0.12.0** (per user directive: "release
everything for the 0.12").

The 0.12.0 base is sitting on master at commit `f300750` with
`Cargo.toml::version = "0.12.0"`. The 0.12 expanded cycle
lands as commits on master without a version bump until Phase E;
the user-facing label stays `0.12.0`. Semver-pedantic readers
will note this is a larger break than 0.11 → 0.12, but the
user opted in explicitly.

The 1.0 timing is community-driven. Per the user:
> "1.0 will be determined by the community adoption"

No 1.0 deadline; we ship 0.12.0 maximally complete and watch
adoption.

## Phase E — Release mechanics (gated)

Per `feedback_release_consent.md` (memory), `cargo publish`
requires explicit per-release consent. The expanded 0.12
release process:

1. **Final gates** (automatic):
   - `cargo build --all-features` clean
   - `cargo test --all-features` clean (target ≥ 850 tests
     after the expansion; 721 in pre-expansion 0.12 base)
   - `cargo clippy --all-features --all-targets -- -D warnings`
     clean
   - `cargo doc --all-features --no-deps` zero warnings
   - `cargo machete` clean
   - All 15 CI matrix entries clean
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
   for shipped plans (130-146) deleted per project convention.

## Acceptance criteria (cycle-level)

- All 10 implementation plans shipped per their individual
  acceptance criteria.
- Test count post-cycle: ≥ 850 (up from 721).
- Zero clippy warnings, zero rustdoc warnings, zero
  `cargo machete` findings.
- Bench gate maintained: `track_into_5_slots_steady_state`
  reports 0 allocs/pkt.
- 15 CI feature-matrix entries clean.
- `cargo publish --dry-run --all-features` packages clean.
- Documentation reflects every new feature
  (`docs/ja4-plus.md`, `docs/http2-format.md`,
  `docs/ipfix-schema.md`, `docs/quic-observation.md`,
  `docs/detect-patterns.md`, `docs/file-hash.md`,
  `docs/tls-ech.md`).
- Migration recipes in `docs/migration-0.11-to-0.12.md` cover
  every break.
- `README.md` `Status` section + `CLAUDE.md`
  `Implementation Status` reflect the expanded scope.

## Risks (cycle-level)

- **R1: Scope creep regret.** 10 plans is a lot. Mitigation:
  Phase A is mechanical (debt retirement); Phase B + D
  features are independently shippable (no inter-plan
  dependencies beyond Phase A). If any Tier-3 feature (144
  ECH, 145 QUIC, 146 file-hash) hits unexpected complexity,
  defer to 0.13 without blocking the cycle.
- **R2: Quality near-misses (per 0.12 base audit pattern).**
  The original 0.12 cycle audit caught initial-commit
  thinness on plan 123 (EVE: missing flow_hash, docs, example)
  and plan 124 (deferred builder: 4/10 tests). Mitigation:
  each plan in this expansion ships its acceptance criteria
  AND test list AND doc list; per-plan sign-off requires all
  three. The plan-level acceptance gate is now sharper.
- **R3: Spec drift.** JA4+ (FoxIO), ECH (IETF draft), QUIC
  versions (RFC ongoing) all have ongoing revisions.
  Mitigation: each plan pins a spec version, captures
  reference fixtures, and treats drift as a test failure
  rather than a silent bug.
- **R4: Compiled size growth.** Plans 140 / 145 / 146 add
  optional deps (x509-parser, quinn-proto, sha2, md-5).
  All feature-gated; consumers pay only for what they
  enable. Documented in `docs/performance.md`.
- **R5: API debt left over.** Plans 130 / 131 / 132 retire
  the audit-flagged debt but won't catch debt not yet
  identified. Mitigation: post-0.12 strategic review pass
  (no new plan; just a code review) before tagging.

## Effort summary

| Phase | Plans | Effort |
|---|---|---|
| A | 130, 131, 132 | 5 days |
| B | 140, 141, 142 | 13 days |
| C | 143 | 4 days |
| D | 144, 145, 146 | 9.5 days |
| E | Release mechanics | 1 day |
| **Total** | | **~32.5 days** |

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
- User opted to ship it all as 0.12.0: "create plans for all
  of those. You are ALLOW to break the backward compatibility.
  Take your time. You can make research on internet. I want
  to release everything for the 0.12. 1.0 will be determined
  by the community adoption."

Plans 128 (the original 0.12 umbrella) is retired by this
plan. Plans 122 / 123 / 124 / 126 / 127 have shipped; their
plan files were retired per convention. Plans 130-146 are
this expanded cycle's scope.

## Open questions

1. **Concurrent vs serial implementation order?** Phase B
   plans (140 / 141 / 142) are independent; can run in
   parallel if multiple developers. Single-developer pass
   serialises naturally.
2. **Bench scope for HTTP/2 + QUIC?** Plans 142 + 145 each
   add one new bench row. Should the bench gate include them
   in the 0-allocs/pkt requirement, or accept a small allocs/
   parse budget for HPACK + QUIC decryption? Decision deferred
   to plan-level review.
3. **Tranco bigram-table licensing for plan 143.** Tranco is
   CC-BY-4.0; our derived statistical aggregate is
   reproducible, but include the attribution per the license.
   Captured in plan 143 §Risks.
4. **QUIC migration tracking (plan 145).** Out of scope for
   the initial implementation; consumers wanting it build a
   custom CID-keyed `FlowExtractor`. Documented in
   `docs/quic-observation.md`.

## Why this scope, why now

The 0.12 strategic review found:

- flowscope's niche ("Rust building-block library for passive
  flow analysis") is **genuinely uncontested** in published
  crates as of Jan 2026.
- HTTP/1.x is becoming the minority of modern web traffic;
  HTTP/2 + QUIC carry the bulk.
- JA4+ is 2026 table stakes for NDR / SIEM consumers
  (Suricata 7.x, Zeek pkg, CrowdStrike, Cloudflare).
- IPFIX consumer base (nfdump, Elastiflow, Vector, Splunk,
  ntopng) is the **bigger** export market than the text-
  format consumer base (CSV / NDJSON / EVE) combined.
- 5 of the 0.12 audit's 7 "rough edges" are public-trait-
  shape debt; landing them pre-adoption is cheaper than
  post-adoption.

Shipping all this as one 0.12.0 release maximises consumer
value-per-migration: one upgrade pays for itself for years.
1.0 timing follows.
