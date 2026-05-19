# Plan 32 — Remove the `S` user-state parameter from the drivers

## 1. Summary

`FlowDriver`, `FlowSessionDriver`, and `FlowDatagramDriver` each
carry a third type parameter `S = ()` for per-flow user state. Rust
type-parameter defaults do not participate in inference, so `S` leaks
into every construction site as a `<_, ()>` / `<FiveTuple, _, ()>`
annotation — 4 of the 5 shipped examples carry one. This plan
**removes `S` from all three drivers**: drivers always run their
tracker with `S = ()`. Per-flow user state stays available on
`FlowTracker<E, S>` for users who build the tracker directly. The
same change makes `FlowSessionDriver` / `FlowDatagramDriver`
constructors take the parser **by value** (`new(extractor, parser)`)
instead of via a `Default`-constructed generic, killing the
`::<_, Parser>` turbofish and relaxing the `P` bound from
`SessionParser + Default + Clone` to `SessionParser + Clone`.

## 2. Status

Implemented in the working tree; not yet committed. Per the
`INDEX.md` convention, delete this file in the PR series that lands
the change.

## 3. Prerequisites

None. This is the foundation plan — land it first; plans 35 and 36
build on the simplified driver signatures.

## 4. Out of scope

- `FlowTracker<E, S>` keeps its `S` parameter unchanged. Direct
  tracker users (`FlowTracker::with_state`,
  `track_with_payload`) retain per-flow state. This plan only
  changes the *drivers*, which never exercised `S` beyond passing it
  through to the tracker type.
- Renaming the driver types (review finding F6) — separate, optional.
- `finish()` / `Timestamp::MAX` (plan 33) and the `track`-argument
  change (plan 34) — separate plans.

## 5. Files

| File | Change |
|------|--------|
| `src/driver.rs` | Drop `S` from `FlowDriver`; collapse the two `impl` blocks (the `S: Default` split disappears); the `BufferedReassemblerFactory` specialisation block loses `S`. |
| `src/session_driver.rs` | Drop `S` from `FlowSessionDriver`; `new`/`with_config` take `parser: P` by value; relax `P` bound. |
| `src/datagram_driver.rs` | Same as `session_driver.rs`. |
| `src/lib.rs` | Re-exported type *names* are unchanged — verify no `S`-naming in re-export lines (there is none today). |
| `src/pcap/source.rs` | `EventIter` already pins `FlowTracker<E, ()>` — unaffected; verify it still compiles. |
| `examples/http_log.rs`, `examples/tls_observer.rs` | Drop `: FlowDriver<FiveTuple, _, ()>`. |
| `examples/length_prefixed_pcap.rs` | `FlowSessionDriver::<_, LengthPrefixedParser>::new(ext)` → `FlowSessionDriver::new(ext, LengthPrefixedParser::default())`. |
| `examples/dns_log.rs` | Drop `: FlowTracker<_, ()>` only if it becomes inferable; `FlowTracker` keeps `S`, so this annotation may stay — confirm. |
| `docs/SESSION_GUIDE.md`, `README.md` | Update every `FlowDriver` / `FlowSessionDriver` snippet. |
| `CHANGELOG.md` | New "Unreleased / Breaking" entry with migration recipe. |
| `tests/length_prefixed_example.rs`, other driver tests | Update constructors. |

## 6. API

```rust
// ── FlowDriver ──────────────────────────────────────────────
// before
pub struct FlowDriver<E, F, S = ()> where E: FlowExtractor,
    F: ReassemblerFactory<E::Key>, S: Send + 'static { ... }
impl<E, F, S> FlowDriver<E, F, S> where S: Default + Send + 'static {
    pub fn new(extractor: E, factory: F) -> Self;
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self;
}
// after
pub struct FlowDriver<E, F> where E: FlowExtractor,
    F: ReassemblerFactory<E::Key> { ... }
impl<E, F> FlowDriver<E, F> {
    pub fn new(extractor: E, factory: F) -> Self;
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self;
}

// ── FlowSessionDriver ───────────────────────────────────────
// before
pub struct FlowSessionDriver<E, P, S = ()> where
    P: SessionParser + Default + Clone + Send + 'static, ... { ... }
impl<E, P, S> FlowSessionDriver<E, P, S> where S: Default + ... {
    pub fn new(extractor: E) -> Self;                      // P via Default
    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self;
}
// after
pub struct FlowSessionDriver<E, P> where
    P: SessionParser + Clone + Send + 'static, ... { ... }  // Default dropped
impl<E, P> FlowSessionDriver<E, P> {
    pub fn new(extractor: E, parser: P) -> Self;
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self;
}

// ── FlowDatagramDriver ──────────────────────────────────────
// mirror of FlowSessionDriver: drop S, drop Default, parser by value
impl<E, P> FlowDatagramDriver<E, P> {
    pub fn new(extractor: E, parser: P) -> Self;
    pub fn with_config(extractor: E, parser: P, config: FlowTrackerConfig) -> Self;
}
```

`tracker()` / `tracker_mut()` return type changes from
`&FlowTracker<E, S>` to `&FlowTracker<E, ()>`.

Call-site effect:

```rust
// before
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);
let mut d = FlowSessionDriver::<_, LengthPrefixedParser>::new(FiveTuple::bidirectional());

// after
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);
let mut d = FlowSessionDriver::new(FiveTuple::bidirectional(),
                                   LengthPrefixedParser::default());
```

## 7. Implementation steps

1. **`src/driver.rs`** — delete the `, S = ()` / `, S` from the
   `FlowDriver` struct decl and its `where` clause. Remove the
   `S: Send + 'static` / `S: Default` bounds.
2. Change `tracker: FlowTracker<E, S>` → `FlowTracker<E, ()>`.
3. Merge the two `impl<E, F, S>` blocks into one `impl<E, F>`. The
   block that had `S: Default` (holding `new` / `with_config`)
   merges with the `S: Send` block — no method renaming needed,
   names were already distinct.
4. Update the helper signatures `diff_anomaly_state` /
   `synthesise_buffer_overflow_ends` — replace `FlowTracker<E, S>`
   with `FlowTracker<E, ()>`.
5. The `impl<E, S> FlowDriver<E, BufferedReassemblerFactory, S>`
   block (`drain_buffer`) → `impl<E> FlowDriver<E, BufferedReassemblerFactory>`.
6. **`src/session_driver.rs`** — delete `S` from `FlowSessionDriver`;
   change the inner field `driver: FlowDriver<E, BufferedReassemblerFactory, S>`
   → `FlowDriver<E, BufferedReassemblerFactory>`.
7. Relax the `P` bound everywhere from
   `SessionParser + Default + Clone + Send + 'static` to
   `SessionParser + Clone + Send + 'static` (the driver only ever
   `.clone()`s `parser_factory`; it never calls `P::default()` or
   the `SessionParserFactory` trait).
8. Change `new(extractor: E)` → `new(extractor: E, parser: P)` and
   `with_config(extractor, config)` → `with_config(extractor, parser, config)`.
   Store `parser_factory: parser` instead of `P::default()`.
9. Collapse the two `impl<E, P, S>` blocks into one `impl<E, P>`.
10. **`src/datagram_driver.rs`** — repeat steps 6–9 for
    `FlowDatagramDriver`.
11. **Examples / docs / tests** — sweep every construction site;
    drop annotations and pass the parser by value. `cargo build
    --all-features --examples` and `cargo test --all-features` are
    the checklists.
12. **`CHANGELOG.md`** — add the breaking-change entry (see §6 for
    the before/after recipe).

## 8. Tests

- Existing driver tests (`driver.rs`, `session_driver.rs`,
  `datagram_driver.rs` `#[cfg(test)]` modules) cover behaviour —
  they only need constructor updates, no new assertions.
- Add one **inference regression test** per driver: a test fn that
  writes `let d = FlowDriver::new(ext, factory);` with **no type
  annotation** and calls `d.track(...)`. If `S` ever creeps back the
  test stops compiling.
- `tests/length_prefixed_example.rs` exercises `FlowSessionDriver`
  end-to-end — update its constructor; it is the integration guard.

## 9. Acceptance criteria

- All 5 files in `examples/` compile with **zero** driver type
  annotations and zero turbofish on driver constructors.
- `cargo build --all-features --all-targets` clean.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` zero warnings.
- A non-`Default` parser (e.g. one with only `with_config`) can be
  passed to `FlowSessionDriver::new` — verified by a compile test.

## 10. Risks

- **netring coupling.** `netring`'s sync-path re-exports or adapters
  may name `FlowDriver<_, _, _>` / `FlowSessionDriver<_, _, _>`.
  Audit `netring` before merging; update in lockstep per the pre-1.0
  policy (`INDEX.md`). The async adapters (`flow_stream` etc.) use
  their own reassembler path and likely do not name these types —
  confirm.
- `tracker_mut()` return type narrows to `FlowTracker<E, ()>`. Any
  consumer that called `tracker_mut()` expecting a non-`()` `S` was
  already impossible (drivers only ever built `S = ()` via
  `Default`), so this is a no-op in practice — note it anyway.
- Relaxing `P: Default + Clone` → `P: Clone` is widening (strictly
  more types accepted) — not a break.

## 11. Effort

M — ~200 lines touched, the majority deletions. Estimate half a day
including the netring audit and doc sweep.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F1** (🔴, "every user
hits this"). Option B of the two options in that finding —
recommended there because a driver that carries both a per-flow
parser *and* per-flow user state is a rare combination not worth
taxing every signature for.
