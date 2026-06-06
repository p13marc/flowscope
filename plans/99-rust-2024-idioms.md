# Plan 99 — Rust 2024 idioms pass + MSRV review

## Summary

A sweep of the codebase for Rust 2024-edition idioms that
flowscope's source predates, plus an MSRV review for the 0.9
cycle. The crate is `edition = "2024"` and `rust-version =
"1.85"`, but the source carries patterns from earlier editions
that the 2024 idioms supersede:

- `let-else` for early-return patterns currently spelled with
  `if let … { … } else { return … }`.
- `let chain` for nested `if let` blocks (stable on 1.85).
- `impl Fn(…)` parameters where `Box<dyn Fn(…)>` is used
  unnecessarily (in chainable setters).
- `&dyn Trait` parameters that could be `impl Trait` for the
  static-dispatch caller.
- `gen fn` for iterator implementations — *deferred*: still
  nightly-only as of 2026-06-06.
- A handful of pre-`?` `.ok_or(…)?` chains that are slightly
  noisier than necessary.

This plan also reviews the MSRV. Currently 1.85; we lift to 1.85
or 1.86 depending on what stabilises by the 0.9 release window
(see "MSRV review" below).

The sweep is mostly mechanical and produces a small net LoC
delta. Plan 93's audit calls this out as the smallest of the
three breaking-change plans (the others being 94 and 96).

## Status

**Ready to implement.** Targets 0.9.0. Lands last in the cycle
so it can sweep across whatever code the other plans land
(94, 95, 96, 97, 98 plus the four RFC promotions).

## Prerequisites

- All other 0.9 cycle plans land first, so the sweep covers the
  final code state, not intermediate states.

## Out of scope

- Performance-driven refactors. Idioms are about readability
  and ergonomics; perf work is a separate cycle.
- Major architectural changes. The trait shape (SessionParser /
  DatagramParser / Reassembler) is locked since 0.1.0 and stays.
- `unsafe` blocks. flowscope has none today; the sweep does not
  introduce any.
- `no_std` support. flowscope uses `std::` types throughout
  (`HashMap`, `Box`, `String`, `Vec`); going `no_std` is a much
  bigger refactor and out of scope. We document this explicitly
  in `docs/concepts.md` so it doesn't get re-litigated.
- Auto-derive `#[derive(Debug)]` for every type. Already the
  case; nothing to do.

---

## MSRV review

flowscope's MSRV is 1.85 (Rust 2024 edition GA, March 2025).
Stabilisations since then (verified via 2026-06 research):

| Version | Stabilises (date)      | Relevant feature                          |
|---------|------------------------|-------------------------------------------|
| 1.86    | Apr 2025               | `trait_upcasting` coercion                |
| 1.87    | May 2025               | `unsigned_is_multiple_of`, anonymous pipes |
| 1.88    | Jun 26 2025            | **let-chains** GA at expression position  |

**Not yet stable** as of 2026-06:

- `gen fn` / `gen` blocks (RFC 3513). Reserved keyword in
  edition 2024; still nightly. `genawaiter` / `gen-iter` remain
  the workaround. Do not ship API that assumes `gen fn` —
  the typed-stream `Vec<Self::Message>` return on
  `SessionParser` / `DatagramParser` stays the right shape.
- `impl Trait` in associated-type position (TAIT / ATPIT) —
  partial stabilisation; not universally usable. Treat as
  unstable for a library API.
- Return-type notation (RTN, RFC 3654) — nightly.

**Stable but not load-bearing for 0.9:**

- AFIT + RPITIT (since 1.75) — adopted widely (axum dropped
  `async-trait` in PR #2308). flowscope's runtime-free sync
  surface sidesteps the use case; stay sync. AFIT in *private*
  internal traits could land as part of plan 99, but no
  external trait grows an `async fn`.
- Async closures (since 1.85) — relevant only to `netring`'s
  async adapters, not flowscope core.
- Trait upcasting (since 1.86) — minor convenience for
  `Box<dyn Error>` walks in plan 96; not load-bearing.

### Decision: bump MSRV to **1.88**.

The let-chains stabilisation (1.88, Jun 2025) is the single
strongest case for an MSRV bump in this cycle. Concretely:

- A scan over the post-plan-94 code (estimated) shows
  ~8 nested `if let Some(a) = x { if let Some(b) = y { … } }`
  blocks that collapse to one-line `if let Some(a) = x && let
  Some(b) = y { … }` with let-chains. The code is materially
  cleaner.
- 1.88 is 11 months old at the planned 0.9 release window
  (≈ 2026-Q3); the broader Rust ecosystem has moved on. The
  audience cost of the bump is small.
- It avoids a 0.9 → 0.10 MSRV shuffle two releases later for
  a feature that already exists.

Trade-off: consumers pinned to a 1.85 toolchain (rare, but
some embedded / vendored stacks) must update. Documented as a
breaking-change line in CHANGELOG 0.9.0.

If a concrete consumer pushes back during the release window,
fallback is to hold at 1.85 for 0.9 and defer to 0.10 — let-
chains are a polish item, not a blocker.

---

## Files

The sweep touches most files in `src/`. Concrete edits live in
the per-plan implementations 74, 75, 81, 92, 94, 95, 96, 97, 98
and are not re-listed here. The 99-specific edits are:

```
src/lib.rs               # let-else + idiom sweep
src/tracker.rs           # idiom sweep
src/reassembler.rs       # idiom sweep
src/driver.rs            # idiom sweep (plan 94's net result first)
src/session_driver.rs    # idiom sweep
src/datagram_driver.rs   # idiom sweep
src/http/*               # idiom sweep
src/tls/*                # idiom sweep
src/dns/*                # idiom sweep
src/icmp/*               # idiom sweep
src/pcap/source.rs       # idiom sweep
docs/concepts.md         # add "no_std support" decision line
CHANGELOG.md             # 0.9.0 polish note
```

## Implementation steps

1. **let-else sweep.** Find every `if let Some(x) = … { … } else
   { return None; }` / `match … { Some(x) => x, None => return
   … }` and rewrite to `let Some(x) = … else { return None };`.
   Conservative rule: only rewrite when the rewrite is strictly
   shorter and the early-return scope is the function body.
2. **let-chains sweep.** With the MSRV bumped to 1.88, rewrite
   nested `if let Some(a) = x { if let Some(b) = y { … } }`
   blocks as `if let Some(a) = x && let Some(b) = y { … }`.
   Strictly improves readability; safety check is `cargo check
   --all-features` before each commit.
3. **`impl Fn` for setter parameters.** In chainable setters
   that take a closure (`with_idle_timeout_fn` etc.), switch
   `f: F where F: Fn(…)` to `f: impl Fn(…)` where doing so does
   not break callers (chainable setters generally don't
   monomorphise too aggressively in flowscope; verify each
   case).
4. **`?` on `Option`.** Find places where a `match …` collapses
   to `let x = opt?;` and apply.
5. **Remove redundant `return`.** Trailing `return foo;` →
   `foo`. Already done in most of the codebase; sweep for
   stragglers introduced by other 0.9 plans.
6. **Sweep `clippy::pedantic` advisory lints.** Run
   `cargo clippy --all-features --all-targets -- -W
   clippy::pedantic` and apply the high-value subset:
   `must_use_candidate` (add `#[must_use]` to plain getters),
   `unnested_or_patterns`, `redundant_else`, `single_match_else`.
   Do not blanket-apply pedantic; cherry-pick.
7. **Doc comment polish.** Sweep doc comments for the
   `///` / `//!` patterns that the 2024 edition's `rustdoc`
   surfaces warnings for (broken intra-doc links, missing
   `# Errors` / `# Panics` sections on fallible/panicking
   functions).
8. **`docs/concepts.md`:** add a one-paragraph "no_std support"
   section recording the decision (no plans).
9. **CHANGELOG entry:** "Internal: 2024-edition idiom sweep
   across the crate. No external API change."

## Tests

- All existing tests pass. The sweep is mechanical; behaviour is
  preserved.
- `cargo clippy --all-features --all-targets -- -D warnings`
  green.
- `cargo doc --all-features --no-deps` zero warnings.
- CI matrix entry on rustc 1.88 (the new MSRV) is green. Once
  this lands, the `rust-version = "1.85"` field in `Cargo.toml`
  updates to `"1.88"`.

## Acceptance criteria

- Zero clippy warnings under the configured deny-list.
- Zero rustdoc warnings.
- All tests pass.
- CI matrix entry on rustc 1.88 green; `Cargo.toml`
  `rust-version = "1.88"`.
- CHANGELOG calls out the 1.85 → 1.88 MSRV bump and the
  reasons (let-chains polish, ecosystem freshness).
- `docs/concepts.md` no_std decision recorded.
- CHANGELOG entry.

## Risks

- **Idiom application drift.** A reviewer's eye on what counts
  as "more idiomatic" varies. Mitigation: the sweep is small
  enough (estimated ~50–80 sites) that a single PR review is
  feasible.
- **Accidentally introducing a clippy::pedantic violation
  elsewhere.** Cherry-pick the advisory lints; do not blanket
  apply.
- **MSRV inadvertent bump.** A 1.86-only feature slipping in
  during the sweep breaks consumers on 1.85. Mitigation: CI
  must run on 1.85 (the rust-version field) explicitly.

## Effort

- Idiom sweep: ~3 hours of reading + editing.
- Clippy pedantic curated apply: ~1.5 hours.
- Doc + CHANGELOG: ~30 minutes.
- **Total:** ~5 hours, ~180 LoC delta (net delta close to zero;
  most rewrites preserve LoC).

## Provenance

Plan 93's inventory found a small but visible set of pre-2024
idioms in code that has accreted since 0.1.0 (originally
edition 2021). The 2024 edition was adopted in 0.5 / 0.6 but the
in-place edit only flipped the `edition` field; this plan
finishes the migration.

No external consumer ask drove this; it's maintainer hygiene.
