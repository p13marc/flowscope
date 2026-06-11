# Plan 156 — `Driver<E>: Send` unconditionally

## Summary

Make `Driver<E>` `Send` for any extractor `E` whose key and state
types are already `Send`. This is the most-felt friction by
netring 0.21 (every example forced into `#[tokio::main(flavor =
"current_thread")]`). The wishlist proposed an `unsafe`
`SendCell<T>` newtype + opt-in `SendMode` enum; my verification
shows that path is **not needed** — the actual !Send root is a
single missing `+ Send` bound on the `Vec<Box<dyn ErasedSlot<...>>>`
slot list. Removing it is a structural one-line change with no
runtime overhead, no `unsafe`, no public-API enum.

## Status

Not started. P0 for 0.13.

## Verification — the wishlist was wrong about the cause

The wishlist's §11.5 §"Why I dismissed this" states:

> *"The first wishlist's §D2 said: …per-flow state mutation goes
> through a lock/queue. … `Send + !Sync` suffices … `Arc<UnsafeCell>`
> newtype …"*

This is grounded in the (stale) doc comments in
`src/driver/slot.rs:45`, `src/driver/mod.rs:28`, `:40` that say
*"central `FlowTracker` holds `Rc<RefCell>` state."* None of that
is true. Direct evidence:

```bash
$ grep -rn 'Rc<\|RefCell\|UnsafeCell' src/{tracker,flow_driver,driver}.rs src/driver/*.rs
src/driver/slot.rs:45:    /// `!Send` (the central `FlowTracker` holds `Rc<RefCell>` state
src/driver/mod.rs:28: //!   `Rc<RefCell<…>>`.
src/driver/mod.rs:40: //! `Rc<RefCell>` internals) — only the handle side is
```

— three doc comments, zero actual occurrences. The flow_driver
test fixture uses `RefCell` but it's gated to a test module.

A compile-time `Send` probe confirms:

```rust
fn assert_send<T: Send>() {}
assert_send::<FlowTracker<FiveTuple>>();        // ✅ compiles
assert_send::<FlowDriver<FiveTuple, NoopReassemblerFactory>>(); // ✅ compiles
assert_send::<Driver<FiveTuple>>();             // ❌ fails — see below
```

The failure points to the trait object in `slots`:

```
note: required because it appears within the type
  `Vec<Box<(dyn driver::typed_slot::ErasedSlot<FiveTupleKey> + 'static)>>`
note: required because it appears within the type
  `flowscope::driver::Driver<FiveTuple>`
```

`Box<dyn Trait>` without an explicit `+ Send` bound is `!Send`,
period. Every concrete `ErasedSlot` impl is structurally Send —
they hold `FlowSessionDriver` / `FlowDatagramDriver` (Send),
`Arc<SegQueue<...>>` (Send), `&'static str`, `Option<SmallVec>` —
but the trait object loses that bound at the cast point.

## Prerequisites

None.

## Out of scope

- **`Driver<E>: Sync`.** Driver methods take `&mut self`; there's
  no concurrent-access invariant to uphold beyond what the
  borrow checker already enforces. Auto-derive will give us
  Sync for free if every field is Sync (which they are —
  `Arc<SegQueue<_>>` is `Sync`, `FlowDriver` is `Sync`, etc.).
  **Decision:** ship `Send + Sync` and verify both. If a future
  consumer reports the Sync impl is problematic, drop it
  additively. The opposite (adding Sync later) is the harder
  change.
- **Splitting the driver across threads inside one task.** Still
  serial; this just enables tokio's multi-thread runtime to *move*
  the future across worker threads at await points, which is the
  actual netring friction.

## Files

| Action | Path | Change |
|---|---|---|
| Modify | `src/driver/typed.rs` | `slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>>` (line ~205); add `+ Send` (and ideally `+ Sync`) bounds on all `P: SessionParser` / `D: DatagramParser` builder methods |
| Modify | `src/driver/typed_slot.rs` | Add `P: Send + Sync` where parsers are wrapped; confirm `TypedConcreteSlot<E,P>` auto-derives Send + Sync from its fields |
| Modify | `src/driver/typed_slot_heuristic.rs` | Same audit |
| Modify | `src/driver/slot.rs:45` | Remove the stale `Rc<RefCell>` doc comment; rewrite to describe the trait-object Send bound |
| Modify | `src/driver/mod.rs:28,40` | Same — rewrite stale doc comments |
| Modify | `CLAUDE.md` | Update Plan 121/122 headlines to drop the `Rc<RefCell>` claim and note the 0.13 Send + Sync extension |
| Modify | `tests/driver_send.rs` | Extend (already exists from plan 122) with `Driver<E>: Send + Sync` compile-time assertions and a `std::thread::spawn` smoke test (NO tokio dep — runtime-free rule) |
| Modify | `CHANGELOG.md` | 0.13 §Changed entry; note this is a tightening of bounds — strictly additive at the type level (`Driver<E>: Send + Sync` is added; nothing was guaranteed about non-Send before). |

## API

No new public types or methods. The change is a bound on the
existing type:

```rust
// Before (0.12.0):
pub struct Driver<E>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    central: FlowDriver<E, NoopReassemblerFactory, ()>,
    extractor: E,
    emit_packet_details: bool,
    slots: Vec<Box<dyn ErasedSlot<E::Key>>>,                      // <— !Send !Sync
}

// After (0.13.0):
pub struct Driver<E>
where
    E: FlowExtractor + Send,
    E::Key: Hash + Eq + Clone + Send + 'static,
{
    central: FlowDriver<E, NoopReassemblerFactory, ()>,
    extractor: E,
    emit_packet_details: bool,
    slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>>,        // <— Send + Sync
}
```

Builder methods gain `P: Send + Sync` (or `D: Send + Sync`)
bounds where parsers are registered. The shipped parsers
(`HttpParser`, `DnsTcpParser`, `DnsUdpParser`, `TlsParser`,
`TlsHandshakeParser`, `IcmpParser`, `HttpExchangeParser`,
`DnsExchangeParser`) are already `Send + Sync` (they hold
`Bytes` / `Vec` / primitive state) — verified by adding
`assert_impl_all!` calls in their respective test modules.

Consumer-visible result:

```rust
#[tokio::main]  // default multi-thread runtime
async fn main() {
    let handle = tokio::spawn(async move {
        let mut driver = Driver::builder(FiveTuple::bidirectional())
            .session_on_ports(HttpParser::default(), [80])
            .build();
        for view in source { driver.track_into(view, &mut events); }
    });
    handle.await.unwrap();
}
```

— compiles + runs on `0.13.0`. Today (`0.12.0`) it errors with
*"cannot be sent between threads safely."*

## Implementation steps

1. Add `+ Send + Sync` to the `ErasedSlot` trait object in `slots`
   (1 line, `src/driver/typed.rs:205`).
2. Add `P: Send + Sync` (and analogous `D: Send + Sync`) bounds
   on the four `DriverBuilder` registration methods
   (`session_on_ports`, `datagram_on_ports`, `session_heuristic`,
   `datagram_heuristic`). Same on the `DeferredDriverBuilder`
   variants.
3. Verify the four concrete `ErasedSlot` impls auto-derive Send
   + Sync from their fields. Every field is structurally Send +
   Sync (`Arc<SegQueue<_>>`, `&'static str`, `Option<SmallVec>`,
   `Vec`, `FlowSessionDriver`). No explicit `unsafe impl`
   needed.
4. Add `static_assertions::assert_impl_all!` calls in the test
   modules of each shipped parser to lock in the Send+Sync
   contract (`HttpParser`, `TlsParser`, etc.).
5. Add compile-time assertion to `tests/driver_send.rs`:
   ```rust
   #[test]
   fn driver_is_send_and_sync() {
       fn assert_send_sync<T: Send + Sync>() {}
       assert_send_sync::<Driver<FiveTuple>>();
   }
   ```
6. Add a runtime smoke test that builds a driver on one thread,
   sends it to a worker thread via `std::thread::spawn`, drives
   one packet through, and reads back the events. NO tokio dep
   (consistent with the project's runtime-free rule); use
   `std::thread`.
7. Clean up stale `Rc<RefCell>` doc comments (4 sites in `src/`,
   one in `CLAUDE.md`).
8. Update `CLAUDE.md`, `CHANGELOG.md`.

## Tests

- `driver_is_send_and_sync` — compile-time assertion via
  `static_assertions::assert_impl_all!`.
- `driver_survives_thread_spawn_and_back` — runtime smoke test
  using `std::thread::spawn`, no tokio dep.
- `driver_event_ordering_unchanged_after_thread_hop` — same pcap
  fed before and after a thread hop produces the same event
  sequence (correctness regression guard).
- `shipped_parsers_are_send_and_sync` — assert each public
  parser type implements `Send + Sync`.
- `pipeline_is_send_and_sync` — by transitive composition,
  `Pipeline<E, P, S>` should pick up Send+Sync from `Driver`.
  Assert it.
- Existing tests under `tests/driver*.rs` pass unchanged.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- The compile-time `Send` assertion passes.
- A test that previously didn't compile (`tokio::spawn(driver)`)
  compiles. Cross-checked via a tokio-using example in the same
  PR (`examples/00-getting-started/threaded_driver.rs`) — uses
  `std::thread`, not tokio, to keep the dep ledger clean.
- Bench numbers from `benches/zero_alloc.rs::track_into_5_slots`
  show **0.000 allocs/pkt** preserved.
- netring 0.21's adoption: replace
  `#[tokio::main(flavor = "current_thread")]` with
  `#[tokio::main]` (multi-thread default) in every netring
  example. No flowscope change required to support that.

## Risks

**R1: An `ErasedSlot` impl turns out to be !Send.** Unlikely
given the field-level audit; the `tokio::spawn` test would catch
it at compile time. Mitigation: ship a per-impl
`unsafe impl Send` only if a field's autoderive fails — but every
field is structurally Send, so this is "if cosmic rays."

**R2: User code that *relies* on `!Send`.** Some code uses
`PhantomData<*const ()>` to force !Send for safety. None of
flowscope's public API does. Downstream consumers who built such
patterns around `Driver<E>` would break. Mitigation: documented
in CHANGELOG; not a real-world concern (no known consumer does
this).

**R3: Trait-object bound divergence between sync + heuristic
slot variants.** The two erased-slot trait impls
(`typed_slot.rs`, `typed_slot_heuristic.rs`) must both pick up
the same `+ Send` bound. Mitigation: covered by the trait-
definition change at `typed_slot.rs:37` — `ErasedSlot<K>` itself
doesn't need `+ Send` in the trait definition; it's the storage
type (`Box<dyn ErasedSlot<K> + Send>`) that carries the bound.
All four concrete impls auto-derive Send from their fields.

**R4: Stale doc comment regrowth.** The `Rc<RefCell>` strings
are sprinkled across `src/driver/`, `CLAUDE.md`, and the
0.11/0.12 retired plan files (no longer in tree but in git
history). Mitigation: this PR cleans every live site; the
historical record stays accurate (it documented a design that
was never shipped).

## Effort

- LOC delta: +50 (mostly tests + doc-comment rewrites).
- Time estimate: **2 hours**.

## Provenance

netring 0.21 §2.4 marks `Monitor: !Send` as the most-felt
friction by new users. The first wishlist's dismissal ("not a
roadblock anymore now that SlotHandle is Send") was reasonable
*for the Send-handle workaround*, but the round-2 wishlist is
right that for users who want the *entire driver* in a
multi-thread tokio task, the workaround is awkward.

The wishlist's recommended fix (unsafe `SendCell<T>` newtype +
`SendMode` enum opt-in) was based on the incorrect premise that
the central tracker is `Rc<RefCell>`-based. Cleaning up the
stale comments and adding `+ Send` to the trait object is the
real fix — no `unsafe`, no opt-in, no runtime overhead.
