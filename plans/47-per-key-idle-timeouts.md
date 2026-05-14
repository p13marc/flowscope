# Plan 47 — Per-key idle timeouts

## Summary

`FlowTrackerConfig::idle_timeout_{tcp,udp,other}` is currently
per-protocol. Real deployments often need finer policy: DES control
flows on port 15987 stay quiet for minutes by design and want a
long timeout; DES data flows on ephemeral ports go silent in
seconds when a publisher dies and want a short timeout. One global
timeout forces a memory-vs-eviction trade-off the operator
shouldn't have to make.

This plan adds a **predicate API** on `FlowTracker` for per-key
idle-timeout overrides. The predicate receives `(&E::Key,
Option<L4Proto>)` and returns `Option<Duration>` — `None` falls
back to the per-protocol default. Generic over the extractor's
key type, so it works with `FiveTupleKey`, `IpPair`, custom keys,
or whatever the user plumbed in.

Plus a small `FiveTupleKey::either_port(u16) -> bool` helper so
the common port-based override case stays one-liner ergonomic.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- None — purely additive on top of the existing tracker.

## Out of scope

- Per-protocol override beyond TCP/UDP/other. The three existing
  buckets cover everything in `L4Proto`. A finer split (e.g.
  ICMP vs SCTP) isn't asked for and would inflate
  `FlowTrackerConfig`.
- Async-clock-based timeout (idle-since-last-call rather than
  idle-since-`now`-arg). The tracker's `sweep(now)` API
  signature stays the same; the only change is which `Duration`
  is consulted per flow.
- An `idle_timeout_by_port: Vec<(u16, Duration)>` config field
  as a parallel API. We thought about it for ergonomics; the
  predicate API covers it via the new `FiveTupleKey::either_port`
  helper, and shipping both would double the surface for no real
  win. See [Plan 45](./45-release-0.3.0.md) §Rejected proposals.

---

## Files

### MODIFIED

- `src/tracker.rs` — add `idle_timeout_fn` field on `FlowTracker`,
  setter, and consult in `sweep`.
- `src/extract/five_tuple.rs` — add `FiveTupleKey::either_port`
  helper.
- `src/driver.rs`, `src/session_driver.rs` — passthrough builder
  methods so users can set the predicate without unwrapping the
  driver to get at the tracker.
- `CHANGELOG.md` — 0.3.0 entry.
- `docs/SESSION_GUIDE.md` — new "Per-flow idle timeouts"
  subsection.

### NEW

None.

---

## API

### `src/tracker.rs`

```rust
/// Predicate type for per-key idle-timeout overrides.
///
/// Receives the flow's key and L4 protocol (when known).
/// Return `Some(d)` to use `d` as the idle timeout for this flow.
/// Return `None` to fall back to the per-protocol default from
/// [`FlowTrackerConfig`].
type IdleTimeoutFn<K> =
    Box<dyn Fn(&K, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static>;

pub struct FlowTracker<E: FlowExtractor, S = ()> {
    // existing fields ...
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
}

impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// Set a predicate that returns a per-flow idle timeout
    /// override. Replaces any previously-set predicate.
    ///
    /// Receives the flow's key and L4 protocol (when extractable).
    /// Return `Some(d)` to use `d` for that flow; return `None`
    /// to fall back to [`FlowTrackerConfig`]'s per-protocol
    /// default.
    pub fn set_idle_timeout_fn<F>(&mut self, f: F)
    where
        F: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.idle_timeout_fn = Some(Box::new(f));
    }

    /// Remove any per-flow timeout override. Subsequent sweeps
    /// use only the per-protocol defaults.
    pub fn clear_idle_timeout_fn(&mut self) {
        self.idle_timeout_fn = None;
    }
}
```

### `src/extract/five_tuple.rs`

```rust
impl FiveTupleKey {
    /// Convenience: matches either endpoint's port. Useful in
    /// idle-timeout predicates and routing logic.
    ///
    /// ```
    /// use flowscope::extract::FiveTupleKey;
    /// # let key: FiveTupleKey = unimplemented!();
    /// // True if either side talks to port 15987.
    /// if key.either_port(15987) { /* ... */ }
    /// ```
    #[inline]
    pub fn either_port(&self, port: u16) -> bool {
        self.a.port() == port || self.b.port() == port
    }
}
```

### `src/driver.rs`, `src/session_driver.rs`

```rust
impl<E, F, S> FlowDriver<E, F, S>
where
    E: FlowExtractor,
    F: ReassemblerFactory<E::Key>,
    S: Send + 'static,
{
    /// Set a per-flow idle-timeout override (see
    /// [`crate::FlowTracker::set_idle_timeout_fn`]).
    pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
    where
        G: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }
}
```

Same on `FlowSessionDriver`.

### Sweep logic (`src/tracker.rs::sweep`)

Replace:

```rust
let timeout = match entry.l4 {
    Some(L4Proto::Tcp) => self.config.idle_timeout_tcp,
    Some(L4Proto::Udp) => self.config.idle_timeout_udp,
    _ => self.config.idle_timeout_other,
};
```

with:

```rust
let timeout = self
    .idle_timeout_fn
    .as_ref()
    .and_then(|f| f(k, entry.l4))
    .unwrap_or_else(|| match entry.l4 {
        Some(L4Proto::Tcp) => self.config.idle_timeout_tcp,
        Some(L4Proto::Udp) => self.config.idle_timeout_udp,
        _ => self.config.idle_timeout_other,
    });
```

---

## Usage examples

### Port-based override (the des-rs case)

```rust
use std::time::Duration;
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::{FlowSessionDriver, L4Proto};

let driver = FlowSessionDriver::<_, MyParser>::new(FiveTuple::bidirectional())
    .with_idle_timeout_fn(|key: &FiveTupleKey, l4| {
        if key.either_port(15987) {
            Some(Duration::from_secs(60))  // control flows: long
        } else if l4 == Some(L4Proto::Tcp) {
            Some(Duration::from_secs(5))   // data flows: short
        } else {
            None  // UDP / other: per-protocol default
        }
    });
```

### Address-family override (illustrative)

```rust
driver.with_idle_timeout_fn(|key, _l4| {
    match key.a.ip() {
        IpAddr::V4(_) => Some(Duration::from_secs(120)),
        IpAddr::V6(_) => Some(Duration::from_secs(60)),
    }
});
```

### Custom-key override

For users with their own `FlowExtractor::Key`, the predicate just
operates on the user's type:

```rust
.with_idle_timeout_fn(|key: &MyCustomKey, _l4| {
    if key.is_management { Some(Duration::from_secs(300)) }
    else { Some(Duration::from_secs(10)) }
});
```

---

## Implementation steps

1. **Add `IdleTimeoutFn<K>` type alias** in `tracker.rs`.
2. **Add the `idle_timeout_fn` field** on `FlowTracker` and
   initialize to `None` in both constructors (`with_state`,
   `with_config_and_state`).
3. **Add `set_idle_timeout_fn` / `clear_idle_timeout_fn`**
   methods on `FlowTracker`.
4. **Wire the predicate into `sweep`**. One added closure call
   per flow per sweep — negligible when the closure is empty
   (`None` case bails out early).
5. **Add `with_idle_timeout_fn`** builder methods on `FlowDriver`
   and `FlowSessionDriver`. Both just forward to the inner
   tracker.
6. **Add `FiveTupleKey::either_port(u16) -> bool`** helper.
7. **Update SESSION_GUIDE.md** — new "Per-flow idle timeouts"
   subsection.
8. **CHANGELOG entry** under 0.3.0.

---

## Tests

### `src/tracker.rs` (unit)

```rust
#[test]
fn idle_timeout_fn_overrides_per_protocol_default() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    // Default TCP idle = 300s. Override: 5s for non-port-80 flows.
    t.set_idle_timeout_fn(|key: &FiveTupleKey, _l4| {
        if key.either_port(80) { None } else { Some(Duration::from_secs(5)) }
    });
    // Start two flows: one on port 80, one on port 1234.
    let f80 = ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
                       1234, 80, 1, 0, 0x02, b"");
    let f8080 = ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
                          1235, 8080, 1, 0, 0x02, b"");
    t.track(view(&f80, 0));
    t.track(view(&f8080, 0));
    // Sweep at t=10s — port 80 flow keeps the 300s default, port
    // 8080 flow has overridden 5s timeout and should expire.
    let ended = t.sweep(Timestamp::new(10, 0));
    assert_eq!(ended.len(), 1);
    if let FlowEvent::Ended { key, reason, .. } = &ended[0] {
        assert_eq!(*reason, EndReason::IdleTimeout);
        assert!(key.either_port(8080), "the 8080 flow expired, not the 80 flow");
    }
}

#[test]
fn idle_timeout_fn_returning_none_uses_protocol_default() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    t.set_idle_timeout_fn(|_, _| None);
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 2, b"x");
    t.track(view(&f, 0));
    // UDP default = 60s. At t=10s the flow is alive; at t=120s it expires.
    assert_eq!(t.sweep(Timestamp::new(10, 0)).len(), 0);
    assert_eq!(t.sweep(Timestamp::new(120, 0)).len(), 1);
}

#[test]
fn clear_idle_timeout_fn_restores_defaults() {
    let mut t = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    t.set_idle_timeout_fn(|_, _| Some(Duration::from_secs(1)));
    let f = ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
                      1234, 80, 1, 0, 0x02, b"");
    t.track(view(&f, 0));
    t.clear_idle_timeout_fn();
    // After clearing, TCP default (300s) applies — flow survives a 10s sweep.
    assert_eq!(t.sweep(Timestamp::new(10, 0)).len(), 0);
}
```

### `src/extract/five_tuple.rs` (unit)

```rust
#[test]
fn either_port_matches_src_or_dst() {
    let k = FiveTupleKey { /* ... a.port=1234, b.port=80 ... */ };
    assert!(k.either_port(1234));
    assert!(k.either_port(80));
    assert!(!k.either_port(443));
}
```

### `src/driver.rs` (integration)

```rust
#[test]
fn driver_with_idle_timeout_fn_threads_through_to_tracker() {
    let factory = BufferedReassemblerFactory::default();
    let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory)
        .with_idle_timeout_fn(|_, _| Some(Duration::from_secs(1)));
    // ... drive a flow, sweep at t=2s, assert it expired
}
```

---

## Acceptance criteria

- [ ] `FlowTracker::set_idle_timeout_fn` / `clear_idle_timeout_fn`
      exist and replace any previously-set predicate.
- [ ] `sweep()` consults the predicate before falling back to the
      per-protocol defaults.
- [ ] `FlowDriver::with_idle_timeout_fn` /
      `FlowSessionDriver::with_idle_timeout_fn` builder methods
      forward to the inner tracker.
- [ ] `FiveTupleKey::either_port(u16) -> bool` helper exists.
- [ ] Default behaviour unchanged when no predicate is set
      (existing tests pass without modification).
- [ ] SESSION_GUIDE.md "Per-flow idle timeouts" subsection added.
- [ ] CHANGELOG entry under 0.3.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Predicate panic propagation.** If the user's predicate
   panics, it propagates out of `sweep()`. Document this
   behaviour; recommend the predicate be infallible. We don't
   catch_unwind because the cost is wrong for the happy path.
2. **Hot-path call overhead.** The predicate is called once per
   live flow per sweep. For a 100k-flow table and a 1s sweep
   interval that's 100k closure calls/second. With an empty `None`
   default, modern CPUs handle this in microseconds. Document that
   the predicate should be cheap.
3. **`Fn + Send + Sync + 'static` bound.** Restrictive but
   matches netring's async-stream contract. Internal state in
   the closure must be `Arc<...>`-wrapped. Documented in the
   rustdoc.
4. **Predicate returning `Some(Duration::ZERO)`.** Edge case:
   immediate expiry of the flow on the next sweep. Well-defined
   semantics — the flow ends with `IdleTimeout` on the first
   `sweep()` call after the override is set. No special handling
   needed.

---

## Effort

- LOC: ~120 (tracker field + accessors + sweep wiring +
  driver builders + `either_port` + tests).
- Time: half a day.

---

## Provenance

Reported as item #4 in `flowscope-feedback-2026-05-14.md`
(des-rs team). They proposed two API shapes — table-based
(`idle_timeout_by_port: Vec<(PortMatch, Duration)>`) and
predicate. This plan picks the predicate shape because:

- It's strictly more expressive (covers their port-based case via
  `FiveTupleKey::either_port`, plus IP-family overrides,
  loopback-only timeouts, custom-key consumers, etc.).
- It avoids `FlowTrackerConfig` becoming generic over `E::Key`,
  which would ripple through every consumer.
- It avoids a struct-field addition that would clutter
  `FlowTrackerConfig`.

The table form can be added later as a thin builder if real demand
surfaces; the predicate covers every described case today.
