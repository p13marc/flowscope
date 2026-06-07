# Plan 117 — legacy driver / event type deletion sweep (post-0.10)

## Summary

Plan 116 shipped the unified `Driver<E, M>` + `Event<K, M>`
alongside the 0.9-era types — `FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver`, `FlowMultiSessionDriver`,
`FlowSessionDriverBuilder`, `FlowDatagramDriverBuilder`, the
legacy `Pipeline<E, S, D>`, `FlowEvent<K>`, and
`SessionEvent<K, M>` all remain shipped so existing consumers
can migrate at their own pace.

Plan 117 is the deletion sweep: remove every legacy type, rename
`flowscope::driver_unified::Driver` → `flowscope::Driver` at the
crate root, and migrate every test + example. Lands as a single
breaking change in the next major release (likely `0.11.0` or
`1.0.0`).

This was originally specified as plan 116 PR 5; carved into its
own plan because PR 5's scope (~50 file edits + netring lockstep)
deserves a focused review window.

## Status

**Ready when post-0.10 cycle opens.** The cycle gate is:
1. 0.10 ships and downstream consumers have ≥1 release cycle to
   migrate.
2. netring sister-crate update is scheduled for the same release
   window.
3. No active 0.10 hot-fix work is in flight.

## Prerequisites

- **Plan 116** — unified `Driver<E, M>` + `Event<K, M>` (shipped
  0.10).
- A ≥4-week window between 0.10 release and 0.11 / 1.0 start so
  external consumers have time to migrate.

## Out of scope

- **Trait surface changes.** `SessionParser` / `DatagramParser`
  / `FlowExtractor` / `Reassembler` stay shape-stable.
- **Brand-new APIs.** Plan 117 is pure deletion + rename, not
  additions.
- **Macro-driven migration.** No `#[derive]` migration helpers.

---

## Files

```
src/driver.rs                    # DELETE — FlowDriver
src/session_driver.rs            # DELETE — FlowSessionDriver
src/datagram_driver.rs           # DELETE — FlowDatagramDriver
src/multi_session_driver.rs      # DELETE — FlowMultiSessionDriver
src/driver_builder.rs            # DELETE — FlowSessionDriverBuilder + FlowDatagramDriverBuilder
src/pipeline.rs                  # DELETE — legacy Pipeline + Event + EventKind + NoSessionParser + NoDatagramParser
src/event.rs                     # REWRITE — collapse FlowEvent + SessionEvent into the unified Event<K, M>
                                 #         (move from driver_unified::event)
src/driver_unified/              # RENAME → src/driver/
src/lib.rs                       # remove old re-exports; expose Driver / Event / Pipeline at root
src/prelude.rs                   # swap legacy types for unified ones

src/driver_unified/erased.rs     # internal: stop wrapping FlowSessionDriver — talk to
                                 # FlowTracker + reassembler::BufferedReassemblerFactory directly
src/driver_unified/heuristic.rs  # same

# Every test that imports a deleted type:
tests/auto_sweep.rs              # FlowDriver → Driver
tests/conversation_timeline.rs   # FlowSessionDriver → Driver
tests/round_trip.rs              # FlowSessionDriver → Driver
… and ~22 more …

# Every example that imports a deleted type:
examples/00-getting-started/hello_pipeline.rs           # legacy Pipeline → unified Pipeline
examples/01-l7-logging/http_log.rs                      # FlowSessionDriver → Driver
examples/01-l7-logging/http_exchanges.rs                # FlowSessionDriver → Driver
… and ~25 more …

docs/getting-started.md          # rewrite first example
docs/concepts.md                 # rewrite driver layer
docs/recipes.md                  # legacy → unified mapping table moves out (already migrated)
CHANGELOG.md                     # 0.11 / 1.0 breaking section

CLAUDE.md                        # update module map
README.md                        # bump version reference
```

## Implementation steps

### Phase 1 — rename and re-export

1. `git mv src/driver_unified src/driver` (after deleting the
   old `src/driver.rs` and replacing the now-empty mod path).
2. Move `Event<K, M>` from `src/driver/event.rs` →
   `src/event.rs`. Delete the legacy `FlowEvent` and
   `SessionEvent` from the same file.
3. Update every `crate::driver_unified::*` import to
   `crate::driver::*`.
4. `src/lib.rs`: replace the legacy `pub use` lines for
   `FlowDriver`, `FlowSessionDriver`, etc. with the unified
   `pub use driver::{Driver, DriverBuilder, Event, Pipeline,
   PipelineBuilder};`.
5. `src/prelude.rs`: swap.

### Phase 2 — internal driver refactor

The current unified `Driver` wraps N legacy
`FlowSessionDriver`/`FlowDatagramDriver` instances per slot.
After PR 5, those legacy types are gone — the slot impl needs
to talk directly to `FlowTracker` + a reassembler factory.

6. Refactor `src/driver/erased.rs::ConcreteSlot` to hold a bare
   `FlowTracker<E, ()>` + `BufferedReassemblerFactory` +
   `SessionParser`, replicating what `FlowSessionDriver` did
   internally but inlined.
7. Same for `ConcreteDatagramSlot`.
8. Same for `HeuristicSessionSlot` / `HeuristicDatagramSlot`.

### Phase 3 — test migration

9. For each `tests/*.rs` file that imports a deleted type,
   rewrite imports + match arms to the unified shape. Worked
   pattern in CHANGELOG 0.10 migration table.
10. Some tests will simplify dramatically — `SessionEvent::Started`
    / `Closed` arms collapse into `Event::FlowStarted` /
    `Event::ParserClosed`; the StateChange arm just deletes.

### Phase 4 — example migration

11. Same drill across `examples/`. The
    `unified_driver_demo` example becomes the canonical shape
    pattern; the others align with it.

### Phase 5 — docs sweep

12. `docs/getting-started.md` rewrite the hello-world.
13. `docs/concepts.md` drop the "driver vs tracker vs session
    driver" diagram in favour of a clean three-tier "Tracker /
    Driver / Pipeline" diagram.
14. `docs/recipes.md` remove the "Migrating to the unified
    Driver" section (no longer needed).
15. `CHANGELOG.md` "0.11 / 1.0 Breaking" entry with the deletion
    list.

### Phase 6 — version bump + netring lockstep

16. Bump `Cargo.toml` version to `0.11.0` (or `1.0.0` if the
    surface is judged 1.0-ready).
17. Update `netring`'s `flow_stream` / `session_stream` /
    `datagram_stream` adapters to consume the unified `Event`
    type. Co-release with flowscope.
18. Publish flowscope 0.11 / 1.0 ahead of netring's matching
    release; netring depends on the new shape.

## Tests

The migration regression test pattern from plan 116 PR 1 (legacy
vs unified equivalence on the same input) is removed in this
plan — once the legacy is gone there's nothing to compare
against. Tests instead verify the unified shape produces the
same outputs the 0.10 unified tests already verified.

## Acceptance criteria

- Every `src/{driver,session_driver,datagram_driver,
  multi_session_driver,driver_builder,pipeline}.rs` is gone.
- `FlowEvent` / `SessionEvent` collapsed into `Event<K, M>`.
- `flowscope::Driver` / `flowscope::Event` / `flowscope::Pipeline`
  resolve to the unified types at the crate root.
- All 30+ examples build + run on the bundled fixtures.
- All 30+ tests pass; `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `netring` updated to consume the new shape; published in the
  same release window.
- Public driver/event/builder type count: **3** (Driver,
  DriverBuilder, Event) + 2 (Pipeline, PipelineBuilder) = 5.
  Down from 14 (6 drivers + 4 events + 4 builders) in 0.9.

## Risks

- **Downstream consumer churn.** Every shipped consumer
  rewrites their match arms in a single release window.
  Mitigation: 4-week migration window between 0.10 release and
  0.11 / 1.0 cut; complete mapping table in CHANGELOG (already
  shipped in 0.10); the
  `flowscope::driver_unified::Driver` path stays valid in 0.10.
- **netring coordination.** netring is the dominant consumer.
  A botched lockstep means downstream users see a temporary
  broken release pair. Mitigation: stage netring changes against
  a flowscope `0.11.0-rc1` release; cut both together.
- **Hidden API surface.** Some types may be re-exported under
  multiple paths (e.g. `flowscope::FlowDriver` AND
  `flowscope::driver::FlowDriver`). Pre-deletion audit catches
  these.

## Effort

| Phase | LoC delta | Hours |
|-------|-----------|-------|
| 1 — rename + re-export | ~50 | 2 |
| 2 — internal slot refactor | ~400 | 8 |
| 3 — test migration (~25 files) | ~−200 net | 8 |
| 4 — example migration (~30 files) | ~−400 net | 12 |
| 5 — docs sweep | ~80 | 2 |
| 6 — version bump + netring lockstep | ~50 | 4 |
| Pre-publish checklist run | — | 1 |
| **Total** | **~−1,000 net** | **~37 hours** |

## Provenance

Plan 116's PR 5:
> Delete the old types + ship CHANGELOG. Move the new
> `src/driver/` contents into final location.

Carved out of plan 116 in the 0.10 release-prep audit because
PR 5's scope dwarfs PRs 1-4 combined and deserves its own
focused window. Plan 116 declared "substantially complete" at
0.10; plan 117 is its post-release follow-up.
