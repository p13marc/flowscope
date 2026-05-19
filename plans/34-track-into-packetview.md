# Plan 34 — `track()` accepts `impl Into<PacketView>`

## 1. Summary

Every example threads an `OwnedPacketView` into the driver by hand
with `.as_view()`: `driver.track(view?.as_view())`. The borrow
conversion is per-packet boilerplate that appears in literally every
loop. This plan changes the `track` / `track_pending` entry points
on all flow consumers to accept `impl Into<PacketView<'_>>`, and adds
`impl From<&OwnedPacketView> for PacketView`, so callers write
`driver.track(&view)` (or `driver.track(view?)` when they own the
value). Existing call sites that pass a `PacketView` directly keep
compiling — `Into` is reflexive.

## 2. Status

Implemented in the working tree; not yet committed. Per the
`INDEX.md` convention, delete this file in the PR series that lands
the change. `track` / `track_pending` / `track_with_payload` on the
tracker and all three drivers now take `impl Into<PacketView<'_>>`;
`OwnedPacketView::as_view()` is retained.

## 3. Prerequisites

None. Independent of plans 32/33. If 32 lands first the `track`
signatures are edited once against the `S`-free drivers; recommended
order 32 → 34, but not required.

## 4. Out of scope

- `sweep()` / `finish()` — they take `Timestamp`, not a view.
- `Dedup::keep(view)` and the internal `clamp_view` helper stay on
  the concrete `PacketView` type — they are not public entry points.
- A `From<&netring::Packet>` impl — that belongs in `netring`, not
  flowscope (orphan rules; and `netring` already has `Packet::view()`).

## 5. Files

| File | Change |
|------|--------|
| `src/pcap/source.rs` | Add `impl<'a> From<&'a OwnedPacketView> for PacketView<'a>`. |
| `src/tracker.rs` | `FlowTracker::track` / `track_with_payload` accept `impl Into<PacketView<'_>>`. |
| `src/driver.rs` | `FlowDriver::track` / `track_pending` accept `impl Into<PacketView<'_>>`. |
| `src/session_driver.rs` | `FlowSessionDriver::track` accepts `impl Into<PacketView<'_>>`. |
| `src/datagram_driver.rs` | `FlowDatagramDriver::track` accepts `impl Into<PacketView<'_>>`. |
| `examples/*.rs` | Drop `.as_view()`. |
| `docs/SESSION_GUIDE.md`, `README.md` | Update snippets. |
| `CHANGELOG.md` | Breaking-signature entry (low impact). |

## 6. API

```rust
// src/pcap/source.rs — new
impl<'a> From<&'a OwnedPacketView> for PacketView<'a> {
    fn from(o: &'a OwnedPacketView) -> Self {
        PacketView::new(&o.frame, o.timestamp)
    }
}

// src/driver.rs — before
pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key>;
pub fn track_pending(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key>;
// after
pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key>;
pub fn track_pending<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key>;

// src/tracker.rs — before
pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key>;
// after
pub fn track<'v>(&mut self, view: impl Into<PacketView<'v>>) -> FlowEvents<E::Key>;
// track_with_payload: same treatment.

// FlowSessionDriver / FlowDatagramDriver track(): same treatment.
```

`OwnedPacketView::as_view()` is **kept** — it is harmless, the new
`From` impl can delegate to it, and removing it would be a gratuitous
break. It simply stops being mandatory.

Call-site effect:

```rust
// before
for view in src.views() {
    let view = view?;
    for ev in driver.track(view.as_view()) { ... }
}
// after
for view in src.views() {
    for ev in driver.track(view?) { ... }   // view? is OwnedPacketView; &-coerced via Into
}
```

> Note: `track(view?)` where `view?` is an *owned* `OwnedPacketView`
> requires `From<OwnedPacketView>` (by value) **or** the caller
> writing `track(&view?)`. `PacketView` borrows, so the `From` impl
> must be on `&OwnedPacketView`. The ergonomic target is therefore
> `driver.track(&view)` after `let view = view?;`, or keeping a bound
> name. Decide in step 1 whether to also add a by-value
> `From<OwnedPacketView>` that leaks the buffer — **no**: a borrowed
> view cannot outlive a by-value temporary. The shipped pattern is
> `let view = view?; driver.track(&view);`.

## 7. Implementation steps

1. **`src/pcap/source.rs`** — add `impl<'a> From<&'a OwnedPacketView>
   for PacketView<'a>`. It is inside the `#[cfg(feature = "pcap")]`
   module already, so it is correctly feature-gated.
2. **`src/tracker.rs`** — change `track` to
   `track<'v>(&mut self, view: impl Into<PacketView<'v>>)`; first
   line of the body: `let view: PacketView<'v> = view.into();`.
   Repeat for `track_with_payload`.
3. **`src/driver.rs`** — same treatment for `track` and
   `track_pending`. The internal `clamp_view` still takes a concrete
   `PacketView` — call it after `.into()`.
4. **`src/session_driver.rs`** / **`src/datagram_driver.rs`** —
   `track` accepts `impl Into<PacketView<'v>>`. Note
   `FlowDatagramDriver::track` extracts the UDP payload from the
   view *before* handing it on — do the `.into()` once at the top,
   bind it, and use the bound `PacketView` for both the payload peek
   and the inner `driver.track_pending`.
5. **Internal call sites** — `EventIter::next` in `pcap/source.rs`
   calls `self.tracker.track(view.as_view())`; change to
   `self.tracker.track(&view)`. Any other in-crate `track(...)`
   call still compiles (reflexive `Into`), but tidy the obvious ones.
6. **Examples** — drop `.as_view()`. Where the loop did
   `for view in src.views() { let view = view?; ... track(view.as_view()) }`,
   it becomes `... track(&view)`. Where it did `track(view?.as_view())`,
   it becomes `let view = view?; ... track(&view);`.
7. **Docs** — update `SESSION_GUIDE.md` and `README.md` snippets.
8. **`CHANGELOG.md`** — note the signature change. Impact is low:
   existing `track(some_packet_view)` calls still compile because
   `PacketView: Into<PacketView>` is reflexive.

## 8. Tests

- **`src/pcap/source.rs`** — unit test: build an `OwnedPacketView`,
  convert via `PacketView::from(&owned)`, assert `frame` and
  `timestamp` round-trip.
- **`src/driver.rs`** — test: `track` still accepts a bare
  `PacketView` (reflexive path) *and* a `&OwnedPacketView` — two
  call forms in one test, both compile and produce equal events.
- Existing example-driven integration tests
  (`tests/http_pcap.rs`, `tests/round_trip.rs`, etc.) exercise the
  new call form once the examples are updated.

## 9. Acceptance criteria

- No `.as_view()` call remains in `examples/` (the method still
  exists on `OwnedPacketView`, just unused by shipped code).
- `cargo build --all-features --all-targets` clean.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- A test confirms both `track(packet_view)` and
  `track(&owned_view)` compile.

## 10. Risks

- **Lifetime inference.** `impl Into<PacketView<'v>>` with a fresh
  `'v` should infer cleanly for both the reflexive and the
  `&OwnedPacketView` cases. If a call site ever fails inference the
  fallback is an explicit `PacketView::from(&view)` — document that
  in the CHANGELOG as the escape hatch.
- **netring.** netring's adapters call `track`-family methods with
  `netring::Packet`-derived views. They pass a `PacketView` today;
  the reflexive `Into` keeps them compiling unchanged. netring may
  *optionally* add `From<&Packet> for PacketView` on its side later
  — out of scope here, note it in the netring follow-up.

## 11. Effort

S — ~30 lines changed, one new `impl`. A couple of hours including
the example sweep.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F4** (🟠) — "`.as_view()`
noise in every hot loop."
