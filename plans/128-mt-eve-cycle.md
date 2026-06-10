# Plan 128 — 0.12.0 multi-thread + EVE cycle (umbrella)

## Summary

Umbrella plan for the 0.12.0 release. Six implementation plans
(122–127) translate the netring 0.21 wishlist
(`flowscope-0.12-wishlist.md`) into shippable work items.

Cycle theme: **add the multi-thread runtime surface +
Suricata-compatible EVE emit + the correlate / timestamp /
anomaly-fields ergonomics needed to retire netring's
duplicated upstream code.**

All additions are behind opt-in features (`mt`, `emit-eve`,
`chrono`) where they pull dependencies. No breaking changes to
existing 0.11 consumers.

## Status

Not started. All six implementation plans are queued.

## Prerequisites

- 0.11.1 published (✅ done).
- No outstanding 0.11 hot-fix work in flight.

## Out of scope

- **DNS / TLS decoder rewrite** — deferred from 0.11 cycle for
  the same reason: multi-day, no path to a patch. Revisit if a
  consumer profiles and asks.
- **Per-flow Ctx-state via `KeyIndexed`** — wishlist's D1.
  Defer to 0.13 (design needs more thought: auto-eviction on
  `FlowEnded` vs idle-timeout, etc.).
- **`Driver<E>` itself becoming `Send`** — wishlist's D2.
  Plan 122 ships **handles** as `Send`; the driver stays
  `!Send` (the central tracker's `Rc<RefCell>` internals
  would need substantial rework). Defer.
- **Per-protocol EVE event types** (`eve_http`, `eve_dns`,
  `eve_tls`) — plan 123 ships lifecycle + anomaly only. Add a
  follow-up plan if a consumer asks.

## The phases

| # | Plan | Goal | Priority | Effort |
|---|---|---|---|---|
| 1 | [`127-timestamp-iso8601.md`](./127-timestamp-iso8601.md) | `Timestamp::write_iso8601` + optional `chrono` interop | P3 | 1 day |
| 2 | [`126-anomaly-fields-trait.md`](./126-anomaly-fields-trait.md) | `AnomalyFields` trait + impls on `FiveTupleKey` / `L4Proto` / `AnomalyKind` | P2 | 1 day |
| 3 | [`125-correlate-unbounded-ctors.md`](./125-correlate-unbounded-ctors.md) | `TimeBucketedCounter::new_unbounded` + 2 more correlate primitives | P2 | ¼ day |
| 4 | [`123-emit-eve.md`](./123-emit-eve.md) | `flowscope::emit::eve::EveJsonWriter` (depends on 126 + 127) | P1 | 2.5 days |
| 5 | [`124-deferred-driver-builder.md`](./124-deferred-driver-builder.md) | `Driver::deferred()` + `DeferredDriverBuilder::build_with(ext)` | P1 | 2 days |
| 6 | [`122-mt-slot-handle.md`](./122-mt-slot-handle.md) | `mt` feature: `MtSlotHandle` + `MtDriverBuilder` | P0 | 3 days |

Total: **~10 days, single developer**.

Sequencing reflects dependencies (127 + 126 → 123) and
priority (P0 → P3) blended. The release waits on plan 122
(P0 — blocks netring's Phase C sharding) so it lands last.

## Sequencing

```
Week 1:    Plans 127, 126, 125 — small foundational additions.
           ~2.25 days total. Lands as a single mid-week commit
           pair (127 + 126) and a follow-up commit (125).
Week 2-3:  Plan 123 — EVE writer. Depends on week-1's 127 +
           126. ~2.5 days.
Week 3:    Plan 124 — Deferred builder. Parallel-developable
           with 123 but holds for review window. ~2 days.
Week 4-5:  Plan 122 — Multi-thread slot handles. The biggest
           change. ~3 days. Lands last so the release waits
           on the netring-blocking P0 work.
Week 5:    Phase 7 — release. Version bump, CHANGELOG,
           migration guide, dry-run, per-release consent,
           publish, tag.
Week 6+:   netring 0.21 implementation begins against
           published 0.12.0.
```

## Phase 7 — Release

Standard release mechanics, per
`feedback_release_consent.md`. See plan 118 Phase 5 for the
detailed checklist; abbreviated here:

1. `Cargo.toml` version 0.11.1 → 0.12.0.
2. `CHANGELOG.md` 0.12.0 section — `0.12.0 — multi-thread +
   EVE + correlate ergonomics cycle` with per-plan
   summary + the cumulative migration recipe.
3. `CLAUDE.md` Implementation Status updated.
4. `docs/migration-0.11-to-0.12.md` — short (no breaks): one
   recipe per opt-in feature (`mt`, `emit-eve`, `chrono`) +
   the `Driver::deferred()` use-case.
5. Pre-publish checklist: `cargo fmt --check`, `cargo clippy
   --all-features --all-targets -- -D warnings`, `cargo test
   --all-features`, `cargo doc --all-features --no-deps`,
   `cargo machete`, `cargo publish --dry-run`, full CI
   feature-matrix.
6. **Stop. Request per-release consent.** Do not `cargo
   publish` without explicit "yes."
7. On consent: `cargo publish`.
8. `git tag 0.12.0 && git push origin master && git push
   origin 0.12.0`.

## Acceptance criteria (cycle-wide)

- All six plans shipped (122–127).
- All shipped tests pass under `cargo test --all-features`.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- New CI matrix entries (`mt`, `emit-eve`, `chrono` permutations)
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- 0.12.0 published to crates.io.
- 0.12.0 tag pushed.
- Migration guide complete.
- CHANGELOG 0.12.0 section published.
- All cycle plan files (122 / 123 / 124 / 125 / 126 / 127 /
  128) deleted per convention; INDEX.md updated to mark
  cycle retired.

## Risks

- **Plan 122 (`mt`) is the keystone P0.** If SegQueue
  allocator pressure shows up under bench (Plan 122 R1), the
  fallback is `ArrayQueue<N>` — bounded, requires a per-slot
  capacity knob. Mitigation: build the bench gate row first;
  decide allocation strategy on measured data.
- **Plan 124 spec-materialisation closure complexity.** The
  deferred builder needs to capture the parser + ports + the
  shared-buf Rc up-front and instantiate the slot at
  `build_with` time. If the closure-based approach gets
  tangled in HRTB, fall back to a per-kind spec enum (rules
  out the same generic dispatch, but composes cleaner).
- **Plan 123 (EVE) golden-fixture stability.** serde_json's
  default field ordering is unspecified. Mitigation: tests
  parse-back each line via `serde_json::Value` rather than
  byte-comparing — field order doesn't affect downstream
  consumers (Suricata's own output isn't stable either).
- **Time budget pressure.** Wishlist estimates ~10 days; plan
  files refine to ~10.75 (some plans are slightly longer than
  the wishlist's optimistic estimate). Float ~½ day of buffer
  for inter-plan integration + the release dry-run.

## Effort summary

| Plan | Effort |
|---|---|
| 122 | 3 days |
| 123 | 2.5 days |
| 124 | 2 days |
| 125 | ¼ day |
| 126 | 1 day |
| 127 | 1 day |
| Phase 7 release | 1 day |
| **Total** | **~10.75 days** |

## Provenance

Built from `flowscope-0.12-wishlist.md` (in repo root, will
retire with the cycle). The wishlist itself is distilled from
netring 0.21's roadmap §5 and verified against the current
flowscope source at 0.11.1.

Plans 122–127 are my own renderings of the wishlist plans into
flowscope's standard 12-section template, with these
corrections / sharpenings from my own analysis:

- **Plan 124**: wishlist proposed `Driver::deferred()` whose
  `build()` panics if no extractor was set. Sharpened: return
  a distinct `DeferredDriverBuilder<E>` type that only exposes
  `build_with(ext)`. Compile-time guarantee preserved, no
  runtime regression.
- **Plan 125**: wishlist listed 5 primitives (including
  `BurstDetector`, `TopK`). Trimmed to 3 — only
  `TimeBucketedCounter`, `KeyIndexed`, `TimeBucketedSet` have
  the (window, bucket, capacity) shape that `new_unbounded`
  makes sense for. `BurstDetector` has a different signature;
  `TopK` is inherently bounded by k.
- **Plan 126**: wishlist's `AnomalyKind` mapping referenced
  variants that don't exist in flowscope (`SegmentOutOfWindow`,
  `TcpRstAfterFin`, `MalformedFrame`, `HttpProtocolViolation`,
  etc. — these are made-up names). Corrected to the 6 actual
  shipping variants (`BufferOverflow`, `OutOfOrderSegment`,
  `FlowTableEvictionPressure`, `SessionParseError`,
  `RetransmittedSegment`, `ReassemblerHighWatermark`).
- **Plan 127**: wishlist's "½ day" effort estimate is
  optimistic. Hand-rolled date algorithm + cross-check tests
  against chrono realistically take ~1 day.

## Cycle-completion checklist

- [ ] Plan 127 — Timestamp ISO 8601 shipped.
- [ ] Plan 126 — AnomalyFields trait shipped.
- [ ] Plan 125 — Correlate `new_unbounded` ctors shipped.
- [ ] Plan 123 — EVE writer shipped.
- [ ] Plan 124 — Deferred driver builder shipped.
- [ ] Plan 122 — `mt` feature + Send slot handles shipped.
- [ ] Phase 7 — 0.12.0 published + tagged.
- [ ] netring 0.21 implementation starts against published
      flowscope 0.12.0.
- [ ] Plan files 122 / 123 / 124 / 125 / 126 / 127 / 128
      deleted per convention.
- [ ] `flowscope-0.12-wishlist.md` retired from repo root.
- [ ] INDEX.md updated to mark the 0.12 cycle retired.
