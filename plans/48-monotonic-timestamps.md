# Plan 48 — Monotonised timestamps (opt-in helper)

## Summary

NIC timestamps are not strictly monotonic under load with
multi-queue receivers or NIC offload paths — small (microsecond)
backwards-going jumps are observable in real-world captures. Every
consumer that wants a strictly non-decreasing timeline currently
reinvents the same `max(prev, current)` clamp.

This plan adds an opt-in monotoniser on `FlowDriver` and
`FlowSessionDriver`: a single `Cell<Timestamp>` running-max,
applied to the `PacketView::timestamp` before it reaches the
tracker. Consumers opt in via a builder method; off by default,
zero cost when off.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- None.

## Out of scope

- Adding `monotonised_ts` as a parallel field on every
  `FlowEvent` variant. The feedback report (item #5) proposed
  this; we're not doing it because:
  - Adding fields to enum variants is a breaking match pattern
    even pre-1.0 (every destructuring `match` needs `..`).
  - It widens the public surface area for one use case.
  - Some users want the raw NIC timestamp (latency analysis,
    NIC-internal correlation). A baked-in extra field always
    pays the cost; an opt-in helper is free when off.

  See [Plan 45](./45-release-0.3.0.md) §Rejected proposals.
- Modifying `Timestamp` semantics. The struct stays a `(sec,
  nsec)` pair from the source; the monotoniser operates one
  layer up.
- Monotonising across multiple driver instances (e.g. multi-RSS
  workers all feeding one downstream). Out of scope — that's a
  downstream consumer problem; flowscope can't synchronise
  across drivers.

---

## Files

### MODIFIED

- `src/driver.rs` — add `monotonic_ts: Option<Timestamp>` field,
  builder method `with_monotonic_timestamps`, clamp logic at the
  top of `track` / `sweep`.
- `src/session_driver.rs` — same surface (delegating if Plan 51
  has refactored to wrap `FlowDriver`).
- `CHANGELOG.md` — 0.3.0 entry.
- `docs/SESSION_GUIDE.md` — new "Timestamps and monotonicity"
  subsection.

### NEW

None.

---

## API

### `src/driver.rs`

```rust
pub struct FlowDriver<E, F, S = ()>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    // existing fields ...
    /// When `Some`, the most recent clamped timestamp. The next
    /// packet's `view.timestamp` is `max(view.ts, last_ts)` and
    /// that becomes the new `last_ts`. When `None`, the option
    /// is off and raw timestamps flow through.
    monotonic_ts: Option<Timestamp>,
}

impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Opt in to strictly non-decreasing timestamps across the
    /// stream. Each packet's `view.timestamp` is clamped to
    /// `max(view.timestamp, last_emitted_timestamp)`.
    ///
    /// Useful for downstream consumers that build timelines
    /// from `FlowEvent` and want a guarantee that successive
    /// events never go backwards in time. Default: off (raw
    /// NIC timestamps flow through unmodified).
    ///
    /// Calling `with_monotonic_timestamps(true)` more than once
    /// is idempotent; calling `with_monotonic_timestamps(false)`
    /// after `true` resets the running max to `None`.
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable { Some(Timestamp::default()) } else { None };
        self
    }
}
```

### `src/session_driver.rs`

Same builder method, same semantics.

### Clamp logic

At the top of `FlowDriver::track`:

```rust
pub fn track(&mut self, view: PacketView<'_>) -> FlowEvents<E::Key> {
    let view = self.maybe_clamp_ts(view);
    // ... existing logic uses the clamped view ...
}

fn maybe_clamp_ts<'a>(&mut self, view: PacketView<'a>) -> PacketView<'a> {
    let Some(last) = self.monotonic_ts.as_mut() else {
        return view;
    };
    let clamped = if view.timestamp > *last {
        *last = view.timestamp;
        view.timestamp
    } else {
        *last
    };
    PacketView::new(view.frame, clamped)
}
```

Same shape for `sweep(now)` — clamp `now` against `monotonic_ts`
before passing it on:

```rust
pub fn sweep(&mut self, now: Timestamp) -> Vec<FlowEvent<E::Key>> {
    let now = match self.monotonic_ts.as_mut() {
        Some(last) => {
            let clamped = now.max(*last);
            *last = clamped;
            clamped
        }
        None => now,
    };
    // ... existing logic uses the clamped `now` ...
}
```

---

## Implementation steps

1. **Add `monotonic_ts` field** on `FlowDriver`, default `None`.
2. **Add `with_monotonic_timestamps(bool)`** builder method.
3. **Add `maybe_clamp_ts` helper** and call it at the top of
   `track`. Mirror for `sweep`.
4. **Mirror on `FlowSessionDriver`**. If Plan 51's refactor
   landed first, `FlowSessionDriver` delegates to its inner
   `FlowDriver` and this plan only needs to expose the builder
   passthrough. Otherwise inline the same logic.
5. **Add tests** (see Tests section).
6. **Update SESSION_GUIDE.md** with a "Timestamps and
   monotonicity" subsection explaining when to opt in.
7. **CHANGELOG entry** under 0.3.0.

---

## Tests

### `src/driver.rs` (unit)

```rust
#[test]
fn raw_timestamps_flow_through_by_default() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    );
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    // Send packets with backwards-going timestamps.
    let evs1 = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
    let evs2 = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
    let ts2 = match &evs2[evs2.len() - 1] {
        FlowEvent::Packet { ts, .. } => *ts,
        _ => unreachable!(),
    };
    assert_eq!(ts2, Timestamp::new(5, 0), "raw ts preserved by default");
    let _ = evs1;
}

#[test]
fn monotonic_timestamps_clamp_backwards_jumps() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_monotonic_timestamps(true);
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let _ = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
    let evs2 = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
    let ts2 = evs2
        .iter()
        .find_map(|e| match e {
            FlowEvent::Packet { ts, .. } => Some(*ts),
            _ => None,
        })
        .expect("Packet event");
    assert_eq!(ts2, Timestamp::new(10, 0), "backwards jump clamped to prior max");
}

#[test]
fn monotonic_timestamps_forward_jumps_pass_through() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_monotonic_timestamps(true);
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let _ = d.track(PacketView::new(&f, Timestamp::new(5, 0)));
    let evs2 = d.track(PacketView::new(&f, Timestamp::new(10, 0)));
    let ts2 = evs2
        .iter()
        .find_map(|e| match e {
            FlowEvent::Packet { ts, .. } => Some(*ts),
            _ => None,
        })
        .expect("Packet event");
    assert_eq!(ts2, Timestamp::new(10, 0));
}

#[test]
fn monotonic_timestamps_sweep_clamps_too() {
    let mut d = FlowDriver::<_, _>::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_monotonic_timestamps(true);
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    let _ = d.track(PacketView::new(&f, Timestamp::new(100, 0)));
    // sweep at t=50s (before the last packet) — internally
    // clamped to 100s, so the flow is NOT considered idle for
    // long enough to expire (UDP default 60s).
    let ended = d.sweep(Timestamp::new(50, 0));
    assert_eq!(ended.len(), 0);
}
```

### Doctest

```rust
/// ```no_run
/// use flowscope::extract::FiveTuple;
/// use flowscope::{BufferedReassemblerFactory, FlowDriver};
///
/// let driver = FlowDriver::new(
///     FiveTuple::bidirectional(),
///     BufferedReassemblerFactory::default(),
/// )
/// .with_monotonic_timestamps(true);
/// ```
```

---

## Acceptance criteria

- [ ] `FlowDriver::with_monotonic_timestamps(bool)` exists; default
      is off.
- [ ] `FlowSessionDriver::with_monotonic_timestamps(bool)` mirrors
      it.
- [ ] When off (default), raw NIC timestamps flow through —
      existing tests pass without modification.
- [ ] When on, every `FlowEvent::*::ts` field is `>=` the previous
      one emitted from this driver.
- [ ] Sweep's `now` arg is clamped against the running max too.
- [ ] SESSION_GUIDE.md "Timestamps and monotonicity" subsection
      added.
- [ ] CHANGELOG entry under 0.3.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **`Cell` vs plain field.** The running max lives in `&mut self`
   methods (`track`, `sweep`), so a plain `Option<Timestamp>`
   field works — no interior mutability needed.
2. **`sweep(now)` clamping might delay timeouts.** If the user
   passes an artificially-low `now` for testing and monotonisation
   is on, the clamp keeps `now` at the running max, which may
   feel surprising. Documented behaviour — the test for it is
   above. Sweep is the wrong API to use for "rewind time" anyway.
3. **No effect on the `Timestamp` field of `view`.** The clamp
   happens at the driver layer; the original `view.timestamp` is
   not mutated (we construct a fresh `PacketView`). Extractors
   downstream see the clamped value.
4. **First-packet behaviour**. The initial running max is
   `Timestamp::default()` = `(0, 0)`. All real packet timestamps
   are `>=` that, so the first packet is unclamped. Fine.
5. **Cross-stream consistency**. Two `FlowDriver` instances both
   with monotonisation on don't share state. Document.

---

## Effort

- LOC: ~70 (field + builder + clamp helper + tests).
- Time: ¼ day.

---

## Provenance

Reported as item #5 in `flowscope-feedback-2026-05-14.md`
(des-rs team). They proposed either a parallel `monotonised_ts`
field on every `FlowEvent`, or a documented clamp guarantee. This
plan picks the opt-in builder shape — preserves raw timestamps
for users who want them, zero cost when off, and the API surface
is one builder method instead of a parallel field on five enum
variants.
