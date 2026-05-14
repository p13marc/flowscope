# Plan 45 — 0.3.0 release planning

## Summary

`flowscope 0.3.0` is a "production hardening" minor release driven
by external feedback from the `des-rs` team
(`flowscope-feedback-2026-05-14.md`). They run flowscope in
production capture pipelines for an industrial-robotics protocol
and reported ten wishlist items after migrating onto `0.2.0`.

This plan is the **umbrella for 0.3.0**: it enumerates the scope,
the rejected proposals (with rationale), the implementation
order, the dependency graph, and the release-completion criteria.
Each individual feature lives in its own numbered sub-plan.

**Backward-compatibility policy.** Pre-1.0, flowscope optimises
for the best possible design over preserving compatibility — when
the sharper shape is better than the older one, we ship the sharper
shape and migrate. Consumers (`netring`, `des-rs`) update in lock-
step; both are mid-migration from 0.1.x → 0.2.x already, so the
0.2.x → 0.3.0 step is no extra burden.

Concretely for 0.3.0:

- `SessionEvent` gains `#[non_exhaustive]` and a new `Anomaly`
  variant ([Plan 51](./51-session-event-anomaly-forwarding.md)).
  Breaks exhaustive external `match` blocks.
- `FlowSessionDriver` is internally refactored to wrap `FlowDriver`
  ([Plan 51](./51-session-event-anomaly-forwarding.md)). No public
  signature changes, but consumers using the type alias / generic
  shape in places need a recompile.
- `Reassembler` trait gains a new `high_watermark()` method
  ([Plan 46](./46-flowstats-snapshots-and-watermark.md)) with a
  default impl, so external trait impls compile unchanged.
- New trait additions and new fields on `#[non_exhaustive]`
  structs (`FlowStats`) are purely additive.

CHANGELOG entries name every break with migration guidance.

## Status

Not started. Targets `0.3.0`.

## Prerequisites

- `0.2.0` shipped (current state of `master`).
- No dependencies on netring beyond what `0.2.0` already requires.

## Out of scope

- `flowscope-protolens` / `flowscope-export` / `flowscope-cli`
  sister crates. STALE pre-consolidation drafts; pick up only
  when a real consumer asks ([INDEX.md](./INDEX.md) "Sister-crate
  roadmap" section).
- IPv6 fragment reassembly (Plan 50.5). Deferred indefinitely;
  no consumer demand yet.
- `1.0` API freeze. The post-`0.2.0` API is settled in shape;
  `0.3.0` adds opt-in helpers but doesn't lock the trait surface
  yet. We'll cut `1.0` after at least one more consumer-feedback
  cycle on `0.3.0`.

---

## Sub-plans

Each sub-plan stands on its own (file paths to create/modify,
API sketch, tests, acceptance criteria). Land them in the order
below — earlier items unblock later ones.

| Plan | Title | Effort | Maps to feedback item |
|------|-------|--------|------------------------|
| [`46`](./46-flowstats-snapshots-and-watermark.md) | FlowStats live snapshots + reassembler high-watermark | 1 d | #1 (snapshot variant) + #2 |
| [`47`](./47-per-key-idle-timeouts.md) | Per-key idle timeouts via predicate | ½ d | #4 |
| [`48`](./48-monotonic-timestamps.md) | Monotonic timestamps (opt-in) | ¼ d | #5 |
| [`49`](./49-sync-dedup.md) | Sync-side content-hash dedup | 1 d | #6 |
| [`51`](./51-session-event-anomaly-forwarding.md) | `SessionEvent::Anomaly` forwarding | ½ d | #7 |
| [`52`](./52-round-trip-ci.md) | Cross-source round-trip CI fixture | ½ d | #10 |
| [`53`](./53-session-parser-author-guide.md) | `SessionParser` author guide | ½ d | #9 |

**Total effort: ~4 days of focused work** (plan-aligned commits,
following the same one-plan-per-PR-or-commit-series discipline
that landed `0.2.0`).

---

## Rejected proposals

Three feedback items have been declined or trimmed; rationale
recorded here so the next review knows what's been considered.

### Item #1 — Periodic `FlowTick` event variant (the **emission** half)

The feedback proposed two API shapes for surfacing live
`FlowStats`: a snapshot accessor OR a periodic `FlowTick` event
emitted at `flow_tick_interval`.

**Picked the snapshot accessor (Plan 46) only.** Reasons:

- The sync `FlowSessionDriver` is caller-driven — it doesn't
  run on its own. Periodic emission would require the driver
  to remember "last tick wall-time per flow" and gate emission
  on the `view.ts` argument passed to `track()`. That's
  awkward and async-y in a sync API.
- The poll accessor gives the consumer full control over
  cadence and integrates cleanly with whatever stats-export
  task they already run.
- No new event variant means no extra match-arm burden for
  every consumer.
- If a consumer specifically wants stream-embedded ticks, they
  can wrap the driver in their own scheduler that calls
  `snapshot_flow_stats()` on a `tokio::interval` and pushes
  ticks through their own channel.

The snapshot accessor is the better building block; the
periodic event is the easier wrapper, not vice versa.

### Item #3 — Backpressure-capable `SessionParser` (iterator return)

The feedback proposed changing `SessionParser::feed_initiator`
from `Vec<Self::Message>` to `Self::Iter<'_>` so consumers can
pull messages lazily.

**Declined.** Reasons:

- The current `Vec` return is intentionally simple. Most parsers
  generate messages eagerly as parsing progresses — there's no
  separable "produce next message" step that could be made lazy
  without the parser carrying a complex continuation state.
- Backpressure for async consumers is the **channel layer**'s job,
  not the parser layer's. netring's `session_stream` adapter
  pushes messages into a bounded `tokio::sync::mpsc` channel; if
  the downstream is slow, the channel applies backpressure all the
  way up to the kernel ring. The des-rs team's reported
  unbounded-growth concern is best solved by sizing their
  downstream channel, not by adding `SessionParser` API surface.
- For sync consumers (`FlowSessionDriver`), there's no
  concurrent producer — the caller decides when to call
  `track()` next. There's no backpressure problem.
- The alternative `feed_initiator_into(bytes, sink)` callback
  variant has merit but doubles the API surface for the same
  semantic. Hold off until someone shows a reproducer that
  bounded channels don't address.

If real demand surfaces (a reproducer where channel-sizing isn't
sufficient), revisit by adding `feed_initiator_into` as an
additive trait method with a default impl that delegates to the
existing `feed_initiator` + Vec drain.

### Item #5 — Parallel `monotonised_ts` field on every `FlowEvent`

The feedback proposed a `monotonised_ts: Timestamp` field on
every `FlowEvent` variant alongside the existing `ts` field.

**Trimmed to an opt-in builder helper (Plan 48).** Reasons:

- Adding fields to enum variants is a breaking match pattern
  even pre-1.0 — every external destructuring `match` block
  needs an `..` rest pattern or an explicit field match.
- It pays the cost (extra field allocation, extra clamp work)
  even for users who actively want raw NIC timestamps (latency
  analysis, NIC-internal correlation).
- The opt-in builder `with_monotonic_timestamps(true)` clamps
  the existing `ts` field, costs nothing when off, and works
  identically across `FlowEvent` / `SessionEvent`.

The trade-off is that the option is per-driver, not
per-consumer — different consumers of the same stream can't
independently opt in/out. Acceptable: monotonisation is a
stream-level property, and downstream consumers can always wrap
the stream with their own clamp if they need additional
guarantees.

### Item #8 — Tracing spans on every `Application` event by default

The feedback proposed that the `tracing` feature, when enabled,
emit a `tracing::trace_span!` per `SessionEvent::Application`.

**Deferred, not in 0.3.0 scope.** Reasons:

- Plan 40 deliberately kept per-packet / per-message tracing
  off because the overhead at high message rates is real (the
  `tracing` crate's span-creation cost is ~100 ns per event;
  for chatty protocols that's 100k events/sec × 100 ns = 1% CPU
  just on tracing).
- The current `tracing` feature already fires events on flow
  lifecycle transitions and anomalies. Per-message tracing is
  better as a separate sub-feature (e.g. `tracing-messages`) so
  consumers opt in explicitly.
- Add it later as `tracing-messages` if `0.3.0` users ask. Low
  cost to ship, low loss to defer.

---

## Sequencing

The sub-plans are mostly independent and can be developed in
parallel. The recommended landing order respects internal
dependencies and stacks small wins early so each commit is
reviewable on its own:

1. **Plan 51 — Anomaly forwarding** (½ d). Smallest, fixes a
   concrete consumer-visible gap. May refactor `FlowSessionDriver`
   to wrap `FlowDriver` (the recommended path); doing that
   refactor first simplifies the rest.
2. **Plan 46 — FlowStats snapshots + watermark** (1 d). Highest
   ⭐ rating from the feedback; touches reassembler, driver, and
   session-driver. Builds on the refactor from Plan 51 if that
   landed.
3. **Plan 47 — Per-key idle timeouts** (½ d). Independent of the
   above; small and well-bounded.
4. **Plan 49 — Sync dedup** (1 d). Independent; new module
   `src/dedup.rs`.
5. **Plan 48 — Monotonic timestamps** (¼ d). Small builder
   method; lands after Plan 51's refactor if landed.
6. **Plan 52 — Round-trip CI** (½ d). After most features land
   so the round-trip exercises them.
7. **Plan 53 — Parser-author guide** (½ d). Doc-only; can land
   any time but reads better once everything else is done so the
   guide can reference the final APIs.

Each lands as its own commit (or 2–3 commits for larger plans
like 46 and 49). Same discipline as `0.2.0`: plan-aligned commits,
tests + clippy + rustdoc green at each step, CHANGELOG growing
incrementally.

---

## Dependency graph

```
        Plan 51 (anomaly forwarding)
           │
           │  (refactors FlowSessionDriver to wrap FlowDriver;
           │   simplifies plans 46 and 48)
           ▼
        Plan 46 (FlowStats snapshots + watermark)
           │
           ▼
        Plan 52 (round-trip CI uses snapshot accessor in tests)


        Plan 47 (per-key timeouts)     — independent
        Plan 48 (monotonic ts)         — independent
        Plan 49 (sync dedup)           — independent
        Plan 53 (parser guide)         — doc-only, independent
```

The independent plans can be tackled in any order.

---

## Cross-cutting work

### CHANGELOG

The release entry grows incrementally as each sub-plan lands.
Final form is one consolidated `## 0.3.0 — Production hardening`
section with sub-bullets per feature, plus a migration paragraph
for the `SessionEvent` `#[non_exhaustive]` change from Plan 51.

### Documentation

Three doc files grow:

- `docs/SESSION_GUIDE.md` — new subsections from Plans 46
  (Reassembly health extension), 47 (Per-flow idle timeouts), 48
  (Timestamps and monotonicity), 49 (Loopback dedup), 53 (Writing
  your own SessionParser).
- `docs/OBSERVABILITY.md` — new metric documented in Plan 46
  (`flowscope_reassembler_high_watermark_bytes`).
- `CHANGELOG.md` — as above.

`README.md` Status block also updated to mention the 0.3.0
features in the same shape as the existing 0.2.0 list.

### CLAUDE.md

Updated at release time to mention `dedup` module, the
`set_idle_timeout_fn` accessor, and the `with_monotonic_timestamps`
/ `with_dedup` builders.

### Tests

Each sub-plan ships its own tests. After all sub-plans land:

- `cargo test --all-features` should pass (139 existing + ~30
  new tests).
- `cargo test --no-default-features --features tracker` should
  still pass (minimum-feature smoke).
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `cargo machete` clean (no new unused deps).
- `cargo publish --dry-run --allow-dirty` packages and verifies.

---

## Acceptance criteria for `0.3.0` release

- [ ] All seven sub-plans (46, 47, 48, 49, 51, 52, 53) marked
      done in INDEX.md.
- [ ] `Cargo.toml` version bumped to `0.3.0`.
- [ ] CHANGELOG `## 0.3.0` section complete with the migration
      paragraph for `SessionEvent` non_exhaustive.
- [ ] SESSION_GUIDE.md has all five new subsections.
- [ ] OBSERVABILITY.md documents the new watermark metric.
- [ ] README.md status block lists the new headline features.
- [ ] CLAUDE.md module list updated.
- [ ] Pre-publish checklist (CLAUDE.md §Pre-publish checklist) all
      green.
- [ ] `cargo publish --dry-run` packages and verifies.
- [ ] Tag `v0.3.0` annotated with the highlights summary.

---

## Risks

1. **`SessionEvent` non_exhaustive churn.** External consumers'
   exhaustive `match` blocks will need a wildcard arm. Pre-1.0;
   acceptable; documented in the CHANGELOG migration paragraph.
2. **FlowSessionDriver refactor.** Plan 51 wires
   `FlowSessionDriver` to wrap `FlowDriver` instead of
   duplicating its anomaly logic. This is the right shape — one
   source of truth for anomaly emission, BufferOverflow
   synthesis, and reassembler bookkeeping. The refactor is
   internal-only (no public signature changes); existing tests
   pin the behaviour.
3. **`Dedup` performance**. The ahash-based hash + 256-entry
   linear scan should be <1 µs/packet but isn't verified. Plan
   49 calls for a criterion check; if it shows up as a hot spot,
   swap to a `HashMap<u64, Timestamp>` backing for O(1) lookup.
4. **netring rebase**. netring currently re-exports
   `flowscope::Timestamp` / `PacketView` and matches on
   `FlowEvent`. The Plan 51 `SessionEvent` non_exhaustive change
   may break netring's match blocks; verify and patch in the same
   PR series. No netring changes needed for the other plans —
   they're all additive on flowscope's side.
5. **Watermark interpretation under SlidingWindow** (Plan 46).
   "Peak occupancy" is ambiguous; the plan picks post-rotation
   peak. Some users might expect pre-rotation peak. Document the
   choice in the rustdoc; if real disagreement surfaces, add a
   second accessor for the other interpretation.
6. **Predicate-API ergonomics for non-FiveTuple keys** (Plan 47).
   The predicate receives `&E::Key`, which is generic. For
   `FiveTupleKey` we ship `either_port` as a convenience; for
   custom keys, users write their own predicate body. Acceptable;
   the trade-off is documented.

---

## Effort

- LOC: ~1300 (across seven sub-plans + docs).
- Tests: ~600 LOC of new test coverage.
- Time: ~4 days of focused work.

---

## Provenance

External feedback from the `des-rs` team
(`flowscope-feedback-2026-05-14.md`, 2026-05-14). They reported
10 wishlist items after migrating onto flowscope 0.2.0; this
release plan addresses 8 of them as full sub-plans, declines 2
(items #3 and the periodic-emission half of #1) with documented
rationale, and trims 1 (#5) to a smaller opt-in shape than
proposed.

The feedback's "Things that already work well" section was used
to confirm we're not regressing on any current behaviour:
`FiveTuple::bidirectional()` canonicalisation, `SessionParser`
trait shape, `FlowSessionDriver::with_config`,
`OverflowPolicy::DropFlow`, `SessionEvent::Ended { history }`,
and rustdoc quality all stay as-is.
