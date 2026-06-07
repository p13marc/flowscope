# Plan 108 — `FlowEvent::Packet` enrichment

## Summary

Add opt-in per-packet protocol detail to `FlowEvent::Packet`.
Today the variant carries only `{ key, side, len, ts }` — debug-
grade timelines (the `conversation_timeline.rs` example was the
test case) need TCP flags / seq / ack but can't get them from
the event stream. They have to re-parse the frame in the
consumer, or skip Packet events entirely.

This plan adds two optional fields to `FlowEvent::Packet`:

- `tcp: Option<TcpInfo>` — populated when the packet is TCP
  and the tracker has packet-detail emission enabled.
- `frame: Option<&'a [u8]>` — borrowed pointer to the original
  frame bytes for consumers wanting layered-view inspection
  on the event stream.

Both default to `None`; opt in via
`FlowTrackerConfig::emit_packet_details`. The default-`None`
keeps the hot path lean; consumers who need timeline-quality
events flip the flag.

Theme 2 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md).
The single largest API gap surfaced by the example-writing
pass.

## Status

**Ready to implement.** Targets 0.10.0. Independent of the
other 0.10 plans (no shared internals). Lands in any order
within the cycle.

## Prerequisites

- None within flowscope. The `#[non_exhaustive]` policy on
  `FlowEvent` (since 0.2.0) makes additive field changes
  unconditionally non-breaking — consumers using `..` patterns
  survive verbatim.

## Out of scope

- **Adding TCP info to every event variant.** Only `Packet`
  needs it; `Started` / `Ended` / `Established` get their
  TCP context (3-way handshake state, sequence numbers at
  close) from `FlowStats` / `TcpInfo` already on the event.
- **Per-packet UDP / ICMP info.** The L4-agnostic `tcp` field
  uses `Option`; future plans can add `udp: Option<UdpInfo>` /
  `icmp: …` if a consumer asks. For now the only L4 we expose
  per-packet is TCP because TCP is the only protocol where
  per-packet state matters at this scale.
- **Adding a `Layers` view to events.** Consumers wanting full
  L2-L4 inspection can call `frame.unwrap().layers()` once we
  expose the frame slice. Pre-parsing into Layers every packet
  is too expensive for the default path; opt-in via the
  consumer side.
- **Eviction or LRU changes.** Tracker storage semantics stay
  identical.
- **The `tcp_state` machine.** The state machine drives
  `FlowEvent::Established` / `Ended` semantics; the
  per-packet enrichment is orthogonal.

---

## API

### New field on `FlowEvent::Packet`

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum FlowEvent<K> {
    // …

    Packet {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        /// New in 0.10.0. `Some` when the packet is TCP **and**
        /// [`FlowTrackerConfig::emit_packet_details`] is `true`.
        /// `None` otherwise — including for non-TCP packets.
        tcp: Option<TcpInfo>,
    },

    // …
}
```

`TcpInfo` already exists in `flowscope::extractor`; reuse it
verbatim — it carries `seq`, `ack`, `window`, `flags`,
`payload_offset`, `payload_len`.

### New config field

```rust
pub struct FlowTrackerConfig {
    // … existing fields …

    /// New in 0.10.0. When `true`, [`FlowEvent::Packet`] carries
    /// the parsed TCP info in its `tcp` field. When `false`
    /// (default), the field is always `None`.
    ///
    /// Off by default because parsing the TCP header into the
    /// event's `tcp` field adds ~5-10 ns per TCP packet (the
    /// per-packet parse already happens for extractor / tracker
    /// reasons; only the cloning into the event is gated).
    pub emit_packet_details: bool,
}
```

### Frame slice on `FlowEvent::Packet`

```rust
Packet {
    key: K,
    side: FlowSide,
    len: usize,
    ts: Timestamp,
    tcp: Option<TcpInfo>,
    /// New in 0.10.0. Borrowed pointer to the original frame
    /// bytes. `Some` when [`FlowTrackerConfig::emit_packet_details`]
    /// is `true`; `None` otherwise.
    ///
    /// Use [`PacketView::layers`](crate::PacketView::layers) on a
    /// fresh `PacketView::new(frame, ts)` to get the full
    /// per-packet layered view.
    ///
    /// **Lifetime caveat.** The slice borrows from the
    /// `PacketView` passed into the most recent
    /// [`FlowTracker::track`] call. It is only valid until
    /// the `Vec<FlowEvent>` returned by that call goes out of
    /// scope. Cloning the event copies the bytes into a
    /// `Vec<u8>` (`frame` becomes `Some(Vec<u8>)` on the
    /// clone; see the next sub-section).
    frame: Option<&'a [u8]>,
}
```

### Lifetime gymnastics + `OwnedFlowEvent`

`FlowEvent<K>` was lifetime-free before. Adding `frame:
Option<&'a [u8]>` introduces a lifetime parameter. Two paths:

**Option A — `FlowEvent<'a, K>`.** Every `FlowEvent` carries an
`'a` parameter. Breaking change for every consumer's type
signatures.

**Option B — Borrow-or-owned dichotomy.** Keep `FlowEvent<K>`
lifetime-free; instead expose a separate type for the borrowed
slice. The cleanest shape:

```rust
pub enum FlowEvent<K> {
    Packet {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        tcp: Option<TcpInfo>,
        /// When emit_packet_details is set + the packet is the
        /// caller's current view's frame, this returns a fresh
        /// PacketView via the supplied closure-callback.
        /// Otherwise empty.
        ///
        /// Implemented as a `bytes::Bytes` clone-on-write so the
        /// event can be cloned and outlived the original view
        /// without consumers caring about lifetimes.
        frame: Option<Bytes>,
    },
}
```

**Decision: Option B with `bytes::Bytes`.** flowscope already
depends on `bytes`; the `Bytes` ref-counted handle is cheap to
clone, lifetime-free, and owns its bytes only when needed
(the `PacketView::frame` slice is typically a `Bytes` clone
already in the netring + pcap paths).

The implementation: when `emit_packet_details = true`, the
tracker takes a `Bytes::copy_from_slice(view.frame)` clone for
the event's `frame` field. ~250 ns per packet at 1500-byte
frames; acceptable for opt-in detail mode. For zero-overhead
introspection, consumers stay on the borrowed `PacketView`
they pass into `tracker.track()` and ignore the event's
`frame`.

### Convenience accessor

```rust
impl<K> FlowEvent<K> {
    /// If this is a `Packet { frame: Some(_), … }`, return a
    /// `PacketView` over the frame at the event's timestamp.
    ///
    /// Use to invoke `pv.layers()` etc. directly off the event
    /// stream.
    pub fn as_packet_view(&self) -> Option<PacketView<'_>>;
}
```

---

## Files

```
src/event.rs            # FlowEvent::Packet gets new fields; OwnedFlowEvent typedef
src/tracker.rs          # populate tcp + frame fields when emit_packet_details is on
src/tracker.rs (cont)   # FlowTrackerConfig::emit_packet_details field + Default impl
src/lib.rs              # no changes (FlowEvent already re-exported)
tests/packet_events.rs  # new — TCP info + frame propagation coverage
docs/recipes.md         # add "Per-packet timeline" recipe
examples/conversation_timeline.rs  # MIGRATED to use the new tcp field
CHANGELOG.md            # 0.10.0 entry — additive, no migration recipe needed
```

## Implementation steps

1. **Add `emit_packet_details: bool`** to `FlowTrackerConfig`
   (default `false`). Update its `Default` impl.
2. **Add `tcp: Option<TcpInfo>` and `frame: Option<Bytes>`**
   fields to the `FlowEvent::Packet` variant.
3. **Add `FlowEvent::as_packet_view()`** convenience method
   that constructs a `PacketView` from `(frame, ts)` when
   both are present.
4. **In `FlowTracker::track_with_payload`** (the path that
   emits `FlowEvent::Packet`), populate the new fields when
   the config flag is set:
   - `tcp`: clone the existing `Extracted::tcp` field on the
     extracted packet (zero new parsing — the data is already
     there).
   - `frame`: `Some(Bytes::copy_from_slice(view.frame))`.
5. **Update every internal `FlowEvent::Packet { … }`
   construction site** to include the new fields with `None`
   defaults. ~6 sites in `src/tracker.rs`.
6. **Add `tests/packet_events.rs`** with three scenarios:
   - Default config: `Packet { tcp: None, frame: None, … }`.
   - `emit_packet_details = true`: `Packet { tcp: Some(_),
     frame: Some(_), … }` with correct TCP flags / seq /
     payload offset.
   - `frame.is_some()` allows `event.as_packet_view().layers()`
     to round-trip.
7. **Migrate `examples/conversation_timeline.rs`** to use the
   new field — print TCP flags + seq in the timeline.
8. **Add a `docs/recipes.md` "Per-packet timeline" section.**
9. **CHANGELOG entry** under 0.10.0 "Added" — additive, no
   migration recipe needed.

## Tests

### `tests/packet_events.rs` (new)

```rust
#[test]
fn default_config_omits_per_packet_details() {
    // Build a tracker with default config; track a TCP packet;
    // assert tcp is None and frame is None.
}

#[test]
fn emit_packet_details_populates_tcp_field() {
    let mut config = FlowTrackerConfig::default();
    config.emit_packet_details = true;
    let mut tracker = FlowTracker::<FiveTuple>::with_config(
        FiveTuple::bidirectional(),
        config,
    );

    // Build a SYN packet via test_frames::ipv4_tcp.
    let frame = test_frames::ipv4_tcp(/* SYN */);
    let events = tracker.track(&PacketView::new(&frame, Timestamp::default()));

    let packet_ev = events.iter().find_map(|e| match e {
        FlowEvent::Packet { tcp, .. } => Some(tcp.as_ref()),
        _ => None,
    }).flatten().expect("tcp field populated");

    assert!(packet_ev.flags.contains(TcpFlags::SYN));
    assert_eq!(packet_ev.payload_len, 0);
}

#[test]
fn emit_packet_details_provides_frame_slice() {
    // Same setup; verify event.frame.is_some() and
    // event.as_packet_view().layers().tcp().is_some().
}

#[test]
fn frame_outlives_track_call() {
    // Capture the event in a Vec, drop the view, then unpack
    // the frame and verify it still parses cleanly. Verifies
    // the Bytes clone vs borrow semantics.
}

#[test]
fn non_tcp_packets_get_no_tcp_field_even_when_enabled() {
    // ICMP packet through a tracker with emit_packet_details
    // = true. tcp should still be None; frame should be Some.
}
```

### `examples/conversation_timeline.rs` migration smoke test

After migration, the example should print TCP flags. Running
against `tests/data/mixed_short.pcap`:

```text
+0.000s [#    1] STARTED
+0.000s [#    1] → 54 B [S]      <-- new: flags
+0.000s [#    2] ← 54 B [SA]     <-- new
+0.000s [#    3] ESTABLISHED
+0.000s [#    3] → 54 B [A]      <-- new
+0.000s [#    7] ENDED reason=IdleTimeout pkts=2+1 bytes=108+54
```

## Acceptance criteria

- `FlowEvent::Packet` gains `tcp: Option<TcpInfo>` and
  `frame: Option<Bytes>` fields.
- `FlowTrackerConfig::emit_packet_details: bool` (default
  `false`) gates the population.
- `FlowEvent::as_packet_view()` convenience accessor lands.
- `tests/packet_events.rs` 5 scenarios pass.
- `examples/conversation_timeline.rs` migrated; output
  includes TCP flags.
- Default-config benchmarks show no regression (verified via
  `benches/tracker.rs`).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry under 0.10.0 "Added".

## Risks

- **`#[non_exhaustive]` policy compliance.** The field
  additions are non-breaking per the policy *as long as
  consumers use `..` patterns*. Consumers matching on
  `FlowEvent::Packet { key, side, len, ts }` without `..`
  break. Mitigation: scan known external consumers
  (netring, simple-nms) for exhaustive matches and warn
  pre-release. The fix at their end is one comma + `..`.

- **`Bytes::copy_from_slice` cost.** A 1500-byte clone takes
  ~250 ns on a 2024-era CPU. Doing this per packet at 10 M
  pps is 2.5 s/sec = 250 % overhead. Mitigation: opt-in
  config (the default-off knob is the whole point). Document
  the trade-off in rustdoc and CHANGELOG.

- **`Bytes` vs `&[u8]`.** Some downstream consumers may
  expect `&[u8]` for zero-copy paths. Mitigation: `Bytes`
  derefs to `&[u8]` transparently, and the consumer can call
  `event.as_packet_view()` to get a `PacketView` borrowing
  from the `Bytes`.

- **Memory bloat in `FlowEvent` enum size.** Each `Packet`
  variant grows by `sizeof(Option<TcpInfo>) +
  sizeof(Option<Bytes>)` ≈ 64-80 bytes. Other variants don't
  change (the enum uses the largest variant for size).
  Mitigation: measure the `Vec<FlowEvent>` allocator pressure;
  if it matters for hot-path users, box `TcpInfo` inside the
  Option (`tcp: Option<Box<TcpInfo>>`).

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `FlowTrackerConfig` field + Default + docs | ~25 | 1 |
| `FlowEvent::Packet` field additions + accessor | ~60 | 2 |
| Tracker dispatch updates (populate fields) | ~80 | 3 |
| Tests (5 scenarios in `tests/packet_events.rs`) | ~180 | 4 |
| `examples/conversation_timeline.rs` migration | ~−15 net | 1 |
| `docs/recipes.md` "Per-packet timeline" section | ~50 | 1 |
| Bench updates + regression check | ~30 | 1 |
| CHANGELOG entry | ~25 | 0.5 |
| **Total** | **~435 LoC** | **~13.5 hours** |

Smallest of the 0.10 cycle's substantive plans.

## Provenance

Postmortem theme 2:

> `FlowEvent::Packet { side, len, ts, .. }` exposes only side
> and len. I expected TCP info (flags / seq / ack) and wrote
> the example assuming it. Compile error.
>
> No way to get the underlying frame bytes from a Packet
> event — they're consumed inside the tracker.
>
> This means packet-level timelines aren't possible without
> re-parsing every packet outside the tracker (which doubles
> the parse cost).

The example file in question is `examples/conversation_timeline.rs`,
which still works after the 0.9 rewrite but skips TCP-level
detail because the field doesn't exist yet.
