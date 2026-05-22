# Plan 38 — Restore the `S` parameter on the drivers (split-ctor design)

## 1. Summary

Plan 32 (shipped in 0.4.0) removed the per-flow user-state type
parameter `S` from `FlowDriver`, `FlowSessionDriver`, and
`FlowDatagramDriver`, on the reasoning that "a driver carrying both
a per-flow parser and per-flow user state is a rare combination."
Netring's 0.14.0 integration showed that assumption was wrong:
netring — the main consumer crate — is exactly that combination,
and now keeps ~300 LoC of hand-rolled driver clone to get its `U`
state alongside L7 messages.

This plan restores `S` to all three drivers with a split-constructor
design that keeps the common `S = ()` path **annotation-free**. The
common constructors live on `impl<E, F> FlowDriver<E, F, ()>` (no
type parameter to infer); the stateful constructors live on the
generic block. Existing 0.4 call sites (`FlowDriver::new(ext,
factory)` etc.) continue to compile unchanged — inference picks
`S = ()` from the impl block. Advanced consumers gain `with_state`
/ `with_state_and_config` and a custom-init variant.

## 2. Status

Not started.

## 3. Prerequisites

None. Foundation plan for 0.5 — plan 58 (`with_factory`) layers on
top of the restored `S` parameter, so 38 lands first.

## 4. Out of scope

- `FlowTracker`'s existing `S` parameter is unchanged.
- No changes to `feed_*` / `parse` / `on_tick` signatures.
- No changes to the existing parser-by-value `new(ext, parser)`
  shape from plan 32 — that ergonomic win is preserved.
- A trait-based parser factory on the driver (plan 58 covers that).

## 5. Files

| File | Change |
|------|--------|
| `src/driver.rs` | Re-add `S = ()` to the struct; split into pinned-`S` and generic-`S` impl blocks; add `with_state` / `with_state_and_config` and `with_state_init` / `with_state_init_and_config`. |
| `src/session_driver.rs` | Same; thread `S` through the inner `driver: FlowDriver<E, BufferedReassemblerFactory, S>` field and the `tracker()` / `tracker_mut()` return types. |
| `src/datagram_driver.rs` | Same. |
| `examples/*.rs` | No edits expected — existing `FlowDriver::new(...)` calls infer `S = ()` from the pin block. Verify. |
| `tests/*.rs`, `benches/session_driver.rs` | Same — should compile unchanged. Add new tests for the stateful constructors (§8). |
| `docs/SESSION_GUIDE.md` | Update any driver trait-shape mentions; add a worked example for `with_state`. |
| `CLAUDE.md` | Module-map lines: `FlowDriver<E, F>` → `FlowDriver<E, F, S>`; sync-vs-async parity section. |
| `CHANGELOG.md` | Breaking entry with the migration recipe and a note about reversing plan 32 option B. |

## 6. API

```rust
// ── FlowDriver ──────────────────────────────────────────────
pub struct FlowDriver<E, F, S = ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{ /* tracker: FlowTracker<E, S>, … */ }

// Common path — S pinned to (), annotation-free.
impl<E, F> FlowDriver<E, F, ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
{
    pub fn new(extractor: E, factory: F) -> Self;
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self;
}

// Stateful path — S: Default.
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Default + Send + 'static,
{
    pub fn with_state(extractor: E, factory: F) -> Self;
    pub fn with_state_and_config(
        extractor: E,
        factory: F,
        config: FlowTrackerConfig,
    ) -> Self;
}

// Stateful path with custom init.
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    pub fn with_state_init<G>(extractor: E, factory: F, init: G) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + 'static;
    pub fn with_state_init_and_config<G>(
        extractor: E,
        factory: F,
        config: FlowTrackerConfig,
        init: G,
    ) -> Self
    where
        G: FnMut(&E::Key) -> S + Send + 'static;

    // Everything else stays on this generic block:
    pub fn with_emit_anomalies(self, enable: bool) -> Self;
    pub fn with_idle_timeout_fn<H>(self, f: H) -> Self where H: ...;
    pub fn with_dedup(self, dedup: crate::dedup::Dedup) -> Self;
    pub fn with_monotonic_timestamps(self, enable: bool) -> Self;
    pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key>;
    pub fn track_pending<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key>;
    pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>>;
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>>;
    pub fn tracker(&self) -> &FlowTracker<E, S>;
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S>;
    // … etc.
}

// FlowSessionDriver and FlowDatagramDriver get the same treatment.
// Their constructors carry both P (parser) and S — pinned to `()`
// on the common block:
impl<E, P> FlowSessionDriver<E, P, ()>
where
    P: SessionParser + Clone + Send + 'static,
    /* + E bounds */
{
    pub fn new(extractor: E, parser: P) -> Self;
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self;
}
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    P: SessionParser + Clone + Send + 'static,
    S: Default + Send + 'static,
    /* + E bounds */
{
    pub fn with_state(extractor: E, parser: P) -> Self;
    pub fn with_state_and_config(
        extractor: E, parser: P, config: FlowTrackerConfig,
    ) -> Self;
}
// + with_state_init variants matching FlowDriver above.
```

Call-site effect — none for existing code:

```rust
// 0.4 (current, no annotation thanks to plan 32)
let mut d = FlowDriver::new(FiveTuple::bidirectional(), factory);

// 0.5 (same line — S = () inferred from pin block)
let mut d = FlowDriver::new(FiveTuple::bidirectional(), factory);

// 0.5 new: per-flow state
let mut d = FlowDriver::<_, _, MyState>::with_state(
    FiveTuple::bidirectional(),
    factory,
);
// or
let mut d = FlowDriver::with_state_init(
    FiveTuple::bidirectional(),
    factory,
    |key: &FiveTupleKey| MyState::from_key(key),
);
```

## 7. Implementation steps

1. **`src/driver.rs`** — re-add `S = ()` to `FlowDriver`'s generic
   list and the field type `tracker: FlowTracker<E, S>`. Add `S:
   Send + 'static` bound where appropriate.
2. Split the existing single `impl<E, F> FlowDriver<E, F>` (post-
   plan-32) into two blocks:
   - `impl<E, F> FlowDriver<E, F, ()>` holding `new` and
     `with_config` (the common path).
   - `impl<E, F, S> FlowDriver<E, F, S> where S: Default + Send +
     'static` holding `with_state` and `with_state_and_config`.
   - `impl<E, F, S> FlowDriver<E, F, S> where S: Send + 'static`
     holding everything else (builder methods, `track`, `sweep`,
     `finish`, `tracker` / `tracker_mut`, `with_state_init`).
3. The two stateful entry points (`with_state` and `with_state_init`)
   both ultimately construct a `FlowTracker<E, S>`. Reuse
   `FlowTracker::with_state` and `FlowTracker::with_state_init`
   (those exist on the tracker today).
4. **`src/session_driver.rs`** — same struct/impl shuffle. The
   inner `driver: FlowDriver<E, BufferedReassemblerFactory, S>`
   field now threads `S`. `parser_factory: P` stays; the new
   stateful constructors take `parser: P` AND apply state via the
   tracker init. `tracker() -> &FlowTracker<E, S>` /
   `tracker_mut() -> &mut FlowTracker<E, S>`.
5. **`src/datagram_driver.rs`** — same.
6. **CHANGELOG**: breaking entry. Recipe: existing call sites
   compile unchanged; advanced users (mainly `netring`) drop their
   custom driver clones and call `with_state_init` instead. Cite
   plan 32 as the partial reversal.
7. **`docs/SESSION_GUIDE.md`** — add a "Per-flow user state" section
   with a worked `FlowSessionDriver::with_state_init` example.
8. **`CLAUDE.md`** — update module-map lines:
   `FlowDriver<E, F>` → `FlowDriver<E, F, S>` (matching the 0.3-era
   wording, since the parameter is back).

## 8. Tests

- **Inference-regression (already in tree from plan 32).**
  `driver::tests::new_needs_no_type_annotation` and
  `session_driver::tests::accepts_non_default_parser` must continue
  to compile with no annotations — the pin-block constructors keep
  inference clean.
- **New: stateful constructor compile-test.** A test struct with
  `S = (u64, String)` constructed via `with_state_init`, with a
  closure that derives state from the flow key. Drives a packet
  through and asserts `tracker().get(key)` exposes the state.
- **New: parity test.** A `FlowSessionDriver::with_state_init`-built
  driver produces the same `SessionEvent` stream as a
  `FlowSessionDriver::new` one for the same wire bytes (state is
  side-channel only; doesn't affect events).
- Existing test suite (181+ tests) must pass with no edits to call
  sites.

## 9. Acceptance criteria

- All existing examples and tests compile **without driver type
  annotations** — the pin-block ctors preserve plan 32's win.
- A new `FlowSessionDriver::with_state_init` example or doctest
  demonstrates per-flow user state.
- `cargo build --all-features --all-targets` clean.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `cargo fmt --check` clean.
- The plan-32 inference-regression test still passes, demonstrating
  the split-ctor design works.

## 10. Risks

- **netring lockstep.** netring 0.15 must be ready to migrate from
  its custom driver path to the restored `FlowSessionDriver::with_
  state_init`. That's the *point* of this plan — but it's still a
  netring-side change to coordinate. CHANGELOG carries the recipe.
- **Three impl blocks per driver is more surface than two.** The
  pin-block / generic-`S` / `S: Default` / `S: Send` split looks
  busier than 0.4's single block. Mitigated: every method has one
  obvious home, and the rustdoc rendering groups by impl block
  cleanly.
- **`with_state` vs `with_state_init` naming.** Two stateful
  constructors (one using `Default`, one with a closure) duplicate
  some surface. The pattern matches `FlowTracker` (which has
  `new` / `with_state` / `with_state_init` today), so it's
  consistent. Document both in the SESSION_GUIDE recipe.

## 11. Effort

M — ~150 lines touched, mostly impl-block reshuffles. The bulk is
mechanical; the design decisions are already settled.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#6**, **option A**. The author leans toward option B (keep
drivers lean, ship a `FlowTracker` recipe); we adopt option A
instead — see [`docs/0.5-PLAN-OF-RECORD.md`](../docs/0.5-PLAN-OF-RECORD.md)
§3 for the rationale.

This is a partial reversal of plan 32 (shipped in 0.4.0). The
restored `S` parameter and the split-constructor design were
explicitly listed as "option A" in plan 32's review; the choice of
option B turned out to be wrong for the actual consumer landscape.
