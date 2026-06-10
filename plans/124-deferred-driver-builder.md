# Plan 124 — `DriverBuilder::deferred` (late extractor selection)

## Summary

Add a second builder constructor `DriverBuilder::deferred()`
that defers extractor-instance selection until builder
finalisation. The existing eager `Driver::builder(extractor)`
keeps the compile-time guarantee that an extractor is set; the
deferred path lets consumers (netring's `MonitorBuilder`)
register slots *before* the extractor is known.

Critically: returns a **distinct type** `DeferredDriverBuilder<E>`
that only exposes `build_with(ext) -> Driver<E>` as the
finalizer — `build()` is unreachable. The compile-time
guarantee is preserved by type-system separation, not weakened
to a runtime panic (the wishlist proposal). No regression.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **Trait-object–based parser registration.** Each
  registration call is still strongly typed at its callsite;
  the builder carries `Vec<Box<dyn ErasedSlot<E::Key>>>` as
  today.
- **Builder *type* change.** `E` is still chosen at builder
  creation; only the *instance* of `E` is deferred. The
  type-erased shape would require a different design and
  isn't asked for.
- **Default extractor.** No `Default for FiveTuple`; consumers
  must call `build_with(ext)` explicitly.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/driver/typed.rs` | Add `DeferredDriverBuilder<E>` mirror of `DriverBuilder<E>` minus `build()`; add `pub fn deferred() -> DeferredDriverBuilder<E>` on `Driver<E>` |
| Modify | `src/driver/mod.rs` | `pub use typed::DeferredDriverBuilder;` |
| Modify | `src/lib.rs` | (re-export via `pub mod driver` re-export — automatic) |
| New (optional) | `tests/driver_deferred.rs` | Equivalence + ordering tests |

## API

### Public constructor on `Driver<E>`

```rust
// src/driver/typed.rs
impl<E> Driver<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    /// Construct a builder *without* committing to a concrete
    /// extractor instance up front. Useful when slot
    /// registration ordering precedes extractor selection
    /// (consumer-built monitor chains).
    ///
    /// Caller must finalise via [`DeferredDriverBuilder::build_with`].
    /// The compile-time guarantee that an extractor is set is
    /// preserved by the type system — `DeferredDriverBuilder`
    /// has no `build()` method.
    pub fn deferred() -> DeferredDriverBuilder<E>
    where E: Clone + Send + 'static,
    { /* … */ }
}
```

### `DeferredDriverBuilder<E>`

Type-equivalent shape to `DriverBuilder<E>` minus:
- No `extractor: E` field at construction time.
- No `build()` method.
- New `build_with(self, ext: E) -> Driver<E>` finalizer.

```rust
// src/driver/typed.rs

pub struct DeferredDriverBuilder<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    config: FlowTrackerConfig,
    monotonic_timestamps: bool,
    emit_anomalies: bool,
    emit_packet_details: bool,
    dedup: Option<Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
    // Slot registration is deferred too — we keep one
    // `Box<dyn DeferredSlotSpec<E::Key>>` per call. At
    // build_with time, each spec is materialised with the
    // supplied extractor clone.
    pending_slots: Vec<Box<dyn DeferredSlotSpec<E::Key>>>,
}

impl<E> DeferredDriverBuilder<E>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    pub fn config(&mut self, c: FlowTrackerConfig) -> &mut Self;
    pub fn monotonic_timestamps(&mut self, on: bool) -> &mut Self;
    pub fn emit_anomalies(&mut self, on: bool) -> &mut Self;
    pub fn emit_packet_details(&mut self, on: bool) -> &mut Self;
    pub fn dedup(&mut self, d: Dedup) -> &mut Self;
    pub fn idle_timeout_fn<F>(&mut self, f: F) -> &mut Self
    where F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + 'static;

    pub fn session_on_ports<P, I>(&mut self, parser: P, ports: I) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone + Send + 'static, P::Message: Send + 'static,
          I: IntoIterator<Item = u16>;
    pub fn session_broadcast<P>(&mut self, parser: P) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone + Send + 'static, P::Message: Send + 'static;
    pub fn session_heuristic<P>(&mut self, parser: P, sig: SignatureFn) -> SlotHandle<P::Message, E::Key>
    where P: SessionParser + Clone + Send + 'static, P::Message: Send + 'static;

    pub fn datagram_on_ports<D, I>(&mut self, parser: D, ports: I) -> SlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone + Send + 'static, D::Message: Send + 'static,
          I: IntoIterator<Item = u16>;
    pub fn datagram_broadcast<D>(&mut self, parser: D) -> SlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone + Send + 'static, D::Message: Send + 'static;
    pub fn datagram_heuristic<D>(&mut self, parser: D, sig: SignatureFn) -> SlotHandle<D::Message, E::Key>
    where D: DatagramParser + Clone + Send + 'static, D::Message: Send + 'static;

    /// Materialise the driver with the supplied extractor
    /// instance.
    pub fn build_with(self, ext: E) -> Driver<E>;
}
```

The slot-registration methods return `SlotHandle` **immediately**
— the slot itself can't be constructed yet (no extractor), but
the handle's underlying `Rc<RefCell<SlotBuf>>` is allocated
up-front. The deferred slot spec carries the (parser, ports,
handle's shared buf) tuple; at `build_with` time we walk the
specs and instantiate `TypedConcreteSlot` etc. against the
supplied extractor.

### Usage

```rust
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};

// Build a deferred builder; register slots WITHOUT knowing the
// extractor yet.
let mut builder = Driver::<FiveTuple>::deferred();
let mut http_slot: SlotHandle<HttpMessage, FiveTupleKey> =
    builder.session_on_ports(HttpParser::default(), [80, 8080]);
builder.emit_anomalies(true);

// … later, perhaps after parsing a CLI flag for which extractor:
let driver = builder.build_with(FiveTuple::bidirectional());
```

### Equivalence guarantee

`Driver::deferred().session_on_ports(p, ports).build_with(ext)`
**must** produce a `Driver<E>` that's behaviourally identical to
`Driver::builder(ext).session_on_ports(p, ports).build()` for
identical (parser, ports, ext) tuples. Verified by integration
tests.

## Implementation steps

1. **Internal `DeferredSlotSpec<K>` trait**: defines
   `materialise(self: Box<Self>, ext: &E_runtime) -> Box<dyn
   ErasedSlot<K>>`. The trait is implemented per slot kind
   (session-on-ports, session-broadcast, session-heuristic,
   datagram-…). Each impl owns the parser + ports + the
   already-allocated `Rc<RefCell<SlotBuf>>` from when the
   handle was returned.
   - **Subtle**: the spec's `materialise` needs the concrete
     `E` to construct `TypedConcreteSlot<E, P>`. Since `E`
     varies per `DeferredDriverBuilder<E>`, the trait is
     parameterised over `E::Key` only and the impl stores the
     extractor type via a closure: `Box<dyn FnOnce(E) -> Box<dyn
     ErasedSlot<E::Key>>>`. This works because each registration
     call is at a single callsite where `E` is known.
   - Alternative path: parameterise the spec trait over both
     `E` and `K`. Cleaner but adds a generic to the spec list.
     Pick whichever lands more cleanly during implementation.
2. **`Driver::deferred()`**: constructs an empty
   `DeferredDriverBuilder<E>`.
3. **`DeferredDriverBuilder` slot methods**: each method
   creates the shared `Rc<RefCell<SlotBuf>>`, wraps a
   `SlotHandle` to return, builds a spec capturing the
   `(parser, ports, shared_buf)` tuple, and pushes the spec
   into `pending_slots`.
4. **`build_with(ext)`**: instantiates the central
   `FlowDriver` with `ext`, then iterates `pending_slots`
   materialising each into a real `ErasedSlot<E::Key>`.
   Returns the same `Driver<E>` shape today's `build()`
   returns.
5. **Tests** in `tests/driver_deferred.rs`:
   - `deferred_builder_produces_same_driver_as_immediate`
     — run both code paths over a 100-packet fixture; assert
     event streams identical.
   - `deferred_handle_drains_after_build_with` — register a
     slot, build_with, push traffic, drain handle.
   - `deferred_multi_slot_independent_drains` — two slots
     registered in deferred mode; both drain independently
     after `build_with`.
   - `deferred_emit_anomalies_propagates` — knob set before
     `build_with` shows up in the central tracker's behaviour.
6. **CHANGELOG**: "Added `Driver::deferred()` constructor for
   builders that defer extractor selection until
   `.build_with(ext)`."
7. **`docs/concepts.md`**: short paragraph on "eager vs
   deferred builder shapes" — the eager one is the canonical
   path for direct consumers; deferred is for consumer-built
   monitor chains where slot registration precedes source
   selection.

## Tests

See implementation step 5.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- All 9 CI feature-matrix entries clean.
- New `deferred_builder_produces_same_driver_as_immediate`
  test passes — confirms behavioural equivalence.
- `Driver::deferred()` is documented; eager path unchanged.
- No `build()` method on `DeferredDriverBuilder`; the
  type-system separation is preserved.

## Risks

- **R1: Spec materialisation complexity.** Each registration
  closure captures the parser, ports, and a shared
  `Rc<RefCell<SlotBuf>>`. At `build_with` time, we instantiate
  the concrete `TypedConcreteSlot<E, P>` using the supplied
  extractor. The `Box<dyn FnOnce(&E) -> Box<dyn ErasedSlot>>`
  shape works but type inference on the registration methods
  needs care. Mitigation: prototype in a scratch crate first;
  if the closure-based approach gets tangled, fall back to
  per-kind spec enums.
- **R2: Slot type erasure layer hides borrow errors.** The
  shared `Rc<RefCell<SlotBuf>>` exists from registration time
  → all good. The spec's parser is owned and `Send`, so no
  surprises.
- **R3: Reduced compile-time guarantees if the user calls
  `build_with` after the original `builder` was promoted to
  `.mt()`** (plan 122). Mitigation: `mt()` is on
  `DriverBuilder`, not `DeferredDriverBuilder`. Both deferred +
  mt would require a `MtDeferredDriverBuilder<E>` — defer that
  combinatorial expansion to a follow-up plan when a consumer
  asks.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `DeferredSlotSpec` trait + impls per kind | 200 | 6 |
| `DeferredDriverBuilder<E>` shell + methods | 200 | 5 |
| `build_with(ext)` finalizer | 50 | 1.5 |
| Tests | 120 | 3 |
| CHANGELOG + docs | 40 | 1 |
| **Total** | **~610** | **~16 hours (~2 days)** |

Wishlist's "1 day" was optimistic — the spec/materialisation
layer is non-trivial. Two days is realistic.

## Provenance

Triggered by netring 0.21 §4.2 (`MonitorBuilder::pcap_source(path)`).
netring's builder mutates the driver_builder mid-chain, which
forces "register all protocols before specifying the source."
Deferred extractor selection breaks that ordering constraint
cleanly.

## Open question

Should `DriverBuilder<E>` (the eager builder) also gain
`session_on_ports` etc. that return `Result<SlotHandle, …>` for
parity? No — the eager path is already infallible (the
extractor is set; registration always succeeds). The
asymmetry is intentional: eager path returns `SlotHandle`
directly; deferred path materialises slots at `build_with`
time but the handles are returned at registration time too,
not deferred. Slot construction failures (e.g. invalid port
set) would be panics in both paths today — no change in
fallibility semantics.
