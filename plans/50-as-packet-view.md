# Plan 50 — `AsPacketView` trait + blanket `Into<PacketView>` impl

## 1. Summary

Plan 34 (shipped in 0.4.0) added `From<&OwnedPacketView> for
PacketView`, so flowscope's own `OwnedPacketView` (yielded by the
`pcap` source) can be fed straight to `track()`. Foreign owned-packet
types — netring's `OwnedPacket` (mmap-backed for live capture, owned
for pcap/offline), pcap-rs `Packet`, anything else — still need a
manual `PacketView::new(&owned.data, owned.timestamp)` per call site.

This plan generalises plan 34: introduce `flowscope::AsPacketView`
as a one-method trait, and a blanket `impl<'a, T: AsPacketView>
From<&'a T> for PacketView<'a>`. The existing explicit
`From<&OwnedPacketView>` impl is replaced by `impl AsPacketView for
OwnedPacketView`. Any external type opts in with three lines and
flows straight into `track(impl Into<PacketView<'_>>)` from plan 34.

## 2. Status

Not started.

## 3. Prerequisites

None — independent. Builds on plan 34's `impl Into<PacketView<'_>>`
contract on `track`, which is already in tree.

## 4. Out of scope

- A by-value `From<T: AsPacketView>` (would force the trait method
  to produce a `'static` PacketView, which contradicts the
  borrow-based design).
- A trait method that returns a `Cow<'a, [u8]>` or similar. The
  zero-copy / borrow shape is the point.
- Forcing existing users to migrate off `OwnedPacketView::as_view()`
  — that method is retained as an alias.

## 5. Files

| File | Change |
|------|--------|
| `src/view.rs` | Define the `AsPacketView` trait + the blanket `From<&T>` impl. |
| `src/pcap/source.rs` | Replace the explicit `From<&OwnedPacketView>` impl with `impl AsPacketView for OwnedPacketView`. Keep `as_view()` as a delegating convenience. |
| `src/lib.rs` | Re-export `AsPacketView` from the crate root (same shelf as `PacketView`). |
| `docs/SESSION_GUIDE.md` | A short "Foreign packet sources" section with the three-line opt-in pattern. |
| `CHANGELOG.md` | Mostly-additive entry; flag the minor break (the explicit `From<&OwnedPacketView>` impl is gone, replaced by the blanket — semantically identical for all in-crate users; only affects anyone who imported `From<&OwnedPacketView>` by name). |

## 6. API

```rust
// src/view.rs
/// One-method trait letting any owned-packet type produce a
/// borrowed [`PacketView`].  Combined with `track(impl
/// Into<PacketView<'_>>)`, it lets foreign packet types be passed
/// straight to `tracker.track(&owned)` / `driver.track(&owned)`.
///
/// Implementing for your own type is three lines:
///
/// ```
/// use flowscope::{AsPacketView, PacketView, Timestamp};
///
/// struct MyPacket { bytes: Vec<u8>, ts: Timestamp }
///
/// impl AsPacketView for MyPacket {
///     fn as_packet_view(&self) -> PacketView<'_> {
///         PacketView::new(&self.bytes, self.ts)
///     }
/// }
/// ```
pub trait AsPacketView {
    fn as_packet_view(&self) -> PacketView<'_>;
}

/// Blanket conversion from any reference to an `AsPacketView` type
/// into a borrowed `PacketView`. Lets `&owned` satisfy the
/// `impl Into<PacketView<'_>>` argument of `track()`.
impl<'a, T: AsPacketView + ?Sized> From<&'a T> for PacketView<'a> {
    fn from(t: &'a T) -> Self {
        t.as_packet_view()
    }
}
```

```rust
// src/pcap/source.rs — replace plan 34's explicit From impl
// (delete this):
// impl<'a> From<&'a OwnedPacketView> for PacketView<'a> { … }

impl AsPacketView for OwnedPacketView {
    fn as_packet_view(&self) -> PacketView<'_> {
        self.as_view()
    }
}
// `as_view()` stays as a hand-named alias; the blanket From makes
// it strictly optional.
```

```rust
// src/lib.rs — add the re-export next to PacketView
pub use view::{AsPacketView, PacketView};
```

Call-site effect for foreign types:

```rust
// netring 0.15 (illustrative)
impl flowscope::AsPacketView for netring::OwnedPacket {
    fn as_packet_view(&self) -> flowscope::PacketView<'_> {
        flowscope::PacketView::new(&self.data, self.timestamp)
    }
}

// Then:
tracker.track(&owned_packet);          // <— was track(PacketView::new(&owned.data, owned.timestamp))
driver.track(&owned_packet);           // same
PcapFlowSource::open(p)?.sessions(ext, parser)  // unchanged path stays unchanged
```

## 7. Implementation steps

1. **`src/view.rs`** — add the `AsPacketView` trait + the blanket
   `From<&T>` impl. The blanket carries `T: ?Sized` so it works on
   trait objects too.
2. **`src/pcap/source.rs`** — delete the explicit
   `impl<'a> From<&'a OwnedPacketView> for PacketView<'a>`.
   Add `impl AsPacketView for OwnedPacketView` calling
   `self.as_view()`. Keep `OwnedPacketView::as_view` (delegating
   method, unchanged).
3. **`src/lib.rs`** — re-export `AsPacketView` alongside `PacketView`.
4. **Verify the existing call sites** (`tracker.track(&owned)`,
   `driver.track(&view)` in examples and tests) continue to compile
   — they now go through the blanket impl instead of the deleted
   explicit one. Type inference is identical.
5. **`docs/SESSION_GUIDE.md`** — add a short "Foreign packet
   sources" section with the three-line `impl AsPacketView` pattern.
6. **`CHANGELOG.md`** — additive (new public trait + re-export)
   with a minor breaking note: the explicit `From<&OwnedPacketView>`
   impl is removed in favour of the blanket. In practice no
   external code names that impl directly — they use `Into<PacketView>`
   on the call site, which still works.

## 8. Tests

- **Trait coherence**: a unit test with a tiny `MyPacket` struct
  implementing `AsPacketView`. Pass `&MyPacket` to a function
  taking `impl Into<PacketView<'_>>`; assert it converts.
- **Existing `OwnedPacketView` path**: the `owned_view_converts_to_
  packet_view` test from plan 34 still passes after the trait
  swap. Optionally extend it to also assert via
  `AsPacketView::as_packet_view` explicitly.
- **Trait object compatibility**: `Box<dyn AsPacketView>` can be
  used (the `?Sized` bound on the blanket allows this). One-line
  test.

## 9. Acceptance criteria

- `flowscope::AsPacketView` is publicly exported from the crate
  root.
- The blanket `From<&T: AsPacketView> for PacketView<'_>` is in
  scope wherever `PacketView` is.
- `OwnedPacketView` opts in via the trait; `OwnedPacketView::as_view`
  remains.
- All existing call sites in `examples/`, `tests/`, `src/` compile
  unchanged.
- A documented three-line opt-in pattern for foreign packet types.
- `cargo build/test/clippy/fmt/doc --all-features` clean.

## 10. Risks

- **Coherence with future `From` impls.** The blanket
  `impl<'a, T: AsPacketView> From<&'a T> for PacketView<'a>` is
  broad. Other `From<&'a Foo> for PacketView<'a>` impls inside
  flowscope can't coexist (they'd conflict via `Foo: !AsPacketView`
  negative reasoning, which Rust doesn't have). Plan: don't write
  such alternative `From` impls; always go through `AsPacketView`.
  Document the convention in `view.rs` doc-comments.
- **`?Sized` bound usefulness.** Lets trait objects work but
  also slightly widens the impl. No practical downside; keep it.
- **Discoverability**: users reading the docs may not realise
  the trait is the opt-in surface. Mitigated by the `track(impl
  Into<PacketView<'_>>)` rustdoc mentioning it, and the
  `AsPacketView` rustdoc carrying the three-line snippet.

## 11. Effort

S — ~40 lines including doctest. The bulk of the value is in
documentation/discoverability rather than code.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#5**. Builds on plan 34's `track(impl Into<PacketView<'_>>)`
contract.
