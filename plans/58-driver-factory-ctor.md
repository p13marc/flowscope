# Plan 58 — `FlowSessionDriver::with_factory` / `FlowDatagramDriver::with_factory`

## 1. Summary

`FlowSessionDriver::new(extractor, parser: P)` requires `P: Clone`
and clones the template parser for every new flow. For parsers with
expensive setup — compiled regex sets, ML model weights, cipher
suite tables, prebuilt FSMs — that clone burns CPU per flow even
when the heavy state is shareable via `Arc`.

The `SessionParserFactory<K>` trait already exists in the crate
(plan 0.1-phase-2) for exactly this use case: per-flow parser
construction with a `&K` hint. It's just not reachable through the
driver. This plan adds a sibling constructor that accepts an
`FnMut(&E::Key) -> P` closure — letting consumers share expensive
state up-front and mint cheap per-flow handles. Same on
`FlowDatagramDriver`.

## 2. Status

Not started.

## 3. Prerequisites

- **Plan 38** — `S` is restored to the drivers. The `with_factory`
  variants thread through `S` just like the existing constructors
  (pinned-`S = ()` common form + stateful generic form).

## 4. Out of scope

- Changing the `SessionParserFactory` trait itself.
- Removing the `P: Clone` bound from the existing `new` path. The
  parser-by-value `new(extractor, parser)` shape from plan 32 stays
  for the common case; `with_factory` is purely additive.
- A factory variant on `FlowDriver` (the reassembler/factory
  driver). `FlowDriver` already takes a `ReassemblerFactory` by
  value; no analogous gap.

## 5. Files

| File | Change |
|------|--------|
| `src/session_driver.rs` | Add `with_factory` + `with_factory_and_config` on the pinned-`S = ()` impl block; `with_state_factory` + `with_state_factory_and_config` on the stateful block. Store the factory closure in a private field. |
| `src/datagram_driver.rs` | Mirror. |
| `tests/*` | Compile-test using a parser that is `!Clone + !Default` constructed only via factory. |
| `docs/SESSION_GUIDE.md` | Add an "Expensive-init parsers" subsection. |
| `CHANGELOG.md` | Additive entry. |

## 6. API

```rust
// ── FlowSessionDriver ───────────────────────────────────────

impl<E, P> FlowSessionDriver<E, P, ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Send + 'static,    // note: no Clone bound
{
    /// Like [`Self::new`], but mint each flow's parser via a
    /// closure instead of cloning a template. Use when parser
    /// setup is expensive enough to warrant sharing state via
    /// `Arc` (compiled regex sets, ML model weights, prebuilt
    /// FSMs).
    pub fn with_factory<F>(extractor: E, factory: F) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + 'static;

    pub fn with_factory_and_config<F>(
        extractor: E,
        factory: F,
        config: FlowTrackerConfig,
    ) -> Self
    where
        F: FnMut(&E::Key) -> P + Send + 'static;
}

// Stateful + factory: combine the factory with custom per-flow state init.
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    /* same bounds plus S: Send + 'static */
{
    pub fn with_state_factory<FP, FS>(
        extractor: E,
        parser_factory: FP,
        state_init: FS,
    ) -> Self
    where
        FP: FnMut(&E::Key) -> P + Send + 'static,
        FS: FnMut(&E::Key) -> S + Send + 'static;

    pub fn with_state_factory_and_config<FP, FS>(
        extractor: E,
        parser_factory: FP,
        state_init: FS,
        config: FlowTrackerConfig,
    ) -> Self
    where
        FP: FnMut(&E::Key) -> P + Send + 'static,
        FS: FnMut(&E::Key) -> S + Send + 'static;
}

// Mirror on FlowDatagramDriver for DatagramParser.
```

The internal storage shifts to a boxed closure:

```rust
struct FlowSessionDriver<E, P, S> {
    /* … */
    parser_factory: Box<dyn FnMut(&E::Key) -> P + Send>,
    parsers: HashMap<E::Key, P, RandomState>,
}
```

`new(ext, parser)` (the existing parser-by-value form) wraps as
`Box::new(move |_| parser.clone())` — preserves today's behaviour
exactly, still requires `P: Clone` on that constructor only.
`with_factory` uses the user's closure directly and drops the
`Clone` requirement.

## 7. Implementation steps

1. **Refactor the internal storage.** Both driver structs change
   `parser_factory: P` to `parser_factory: Box<dyn FnMut(&E::Key)
   -> P + Send>`. Construction via `new` wraps the template parser
   in `Box::new(move |_| parser.clone())`. The Clone bound moves
   from the struct's where-clause onto `new`'s impl block (the
   factory variants don't need it).
2. **`with_factory` / `with_factory_and_config`** — straightforward
   constructors storing the user's closure directly.
3. **Per-flow parser construction** — the existing line
   `self.parser_factory.clone()` on `FlowEvent::Started` becomes
   `(self.parser_factory)(key)`.
4. **Stateful variants** — combine the parser factory with the
   tracker's state init closure (which lands via plan 38's
   `with_state_init`).
5. **Datagram driver** — mirror.
6. **Tests** — see §8.
7. **Docs** — `SESSION_GUIDE.md` "Expensive-init parsers" with the
   `Arc<RegexSet>` example pattern.
8. **CHANGELOG** — additive.

## 8. Tests

- **Compile-test for `!Clone + !Default` parser**: a parser struct
  with a private field that has no `Clone` impl (e.g. holds an
  `Arc<RegexSet>` shared across all per-flow instances). Construct
  the driver via `with_factory` only — wouldn't compile with the
  existing `new` (`P: Clone` bound).
- **Per-flow factory call count**: a counter wrapped in `Arc` that
  increments inside the factory closure. Drive multiple flows;
  assert the counter equals the number of distinct flows (not the
  number of packets).
- **Equivalence with `new`**: for a parser that IS `Clone`, the
  factory-built driver and the parser-by-value-built driver produce
  the same `SessionEvent` stream on the same wire bytes. Smoke test.
- **`tracker_mut()` / `with_emit_anomalies(true)` chain** —
  builder methods still chain after `with_factory`.

## 9. Acceptance criteria

- `with_factory` / `with_factory_and_config` exist on both
  `FlowSessionDriver` and `FlowDatagramDriver` with the API above.
- A parser that's neither `Clone` nor `Default` can be used via
  the factory path (compile-time guard).
- Existing `new(ext, parser)` call sites continue to compile and
  behave identically.
- `cargo build/test/clippy/fmt/doc --all-features` clean.

## 10. Risks

- **`Box<dyn FnMut>` indirection cost.** One virtual call per new
  flow (not per packet). Negligible compared to parser setup; the
  whole point is that setup is the expensive thing.
- **Backward-compatible refactor of `parser_factory: P` to a
  closure.** Internal-only field, no public-API impact. Existing
  consumers of `new` see no change.
- **Naming overlap with `SessionParserFactory` trait.** The trait
  exists; the new constructor name is `with_factory` (closure-
  shaped, not trait-shaped). Plan: leave the trait alone (other
  consumers may use it for their own factory abstractions); add the
  closure variant as the driver's surface. If at some point the
  closure variant subsumes the trait, deprecate later.

## 11. Effort

S — ~80 lines including tests. The refactor is mechanical.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#7**. Lifts the existing `SessionParserFactory` trait pattern
into the driver path. Sequenced after plan 38 so the stateful
factory variants thread through the restored `S`.
