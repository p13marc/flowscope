# Migration: 0.12 → 0.13

Quick reference for upgrading from `flowscope = "0.12"` to
`flowscope = "0.13"`.

The 0.13 cycle is mostly **additive** — most 0.12 code keeps
working unchanged. The few changes that aren't strictly
additive are bound-tightening on existing generic parameters
(`Send + Sync` instead of just `Send` in some places). All
shipped types satisfy the new bounds; downstream impls almost
certainly do too.

## TL;DR — 30-second cheat sheet

```toml
# Cargo.toml
[dependencies]
flowscope = "0.13"
```

Things that just work better with no code change:

```rust
// 0.12: this needed #[tokio::main(flavor = "current_thread")]
//       because Driver<E> was !Send.
// 0.13: works on the default multi-thread runtime.
#[tokio::main]
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

New idioms worth adopting:

```rust
// Detector → canonical owned anomaly → EVE sink (0.13).
let score: ScanScore<FiveTupleKey> = port_scan.observe(key, success);
eve.write_owned_anomaly(&score.into_anomaly(ts))?;

// Bounded drain for back-pressure on busy slots (0.13).
let drained = http_slot.drain_n(&mut messages, 64);

// Fan-out to multiple consumers via broadcast (0.13).
let mut logger = builder.session_on_ports_broadcast_each(HttpParser::default(), [80]);
let mut metrics = logger.clone();
```

## §1 `Driver<E>` is now `Send + Sync` (plan 156)

The 0.12 CHANGELOG claimed `Driver<E>` was `!Send` because
`FlowTracker` held `Rc<RefCell>` interior-mutability state.
That was incorrect — the real cause was a missing `+ Send`
bound on the `Vec<Box<dyn ErasedSlot<E::Key>>>` slot list.

### What changed

- `Driver<E>: Send + Sync` unconditionally.
- `slots: Vec<Box<dyn ErasedSlot<E::Key> + Send + Sync>>`
  (was `Vec<Box<dyn ErasedSlot<E::Key>>>`).
- Bound tightening on the registration methods:
  - `SessionParser` / `DatagramParser` impls now need
    `Send + Sync` (was `Send`).
  - `P::Message` / `D::Message` now need `Send + Sync` (was
    `Send`).
  - `StateInit`, `IdleTimeoutFn`, `ParserFactory` boxed
    closures now need `Send + Sync`.

### Impact on downstream code

- **Shipped parsers** (`HttpParser`, `TlsParser`,
  `TlsHandshakeParser`, `DnsTcpParser`, `DnsUdpParser`,
  `DnsExchangeParser`, `HttpExchangeParser`, `IcmpParser`) all
  satisfy the new bounds — no consumer code changes needed.
- **Custom parsers** that hold `Bytes`, `Arc`, primitive state,
  `&'static` references, etc., are automatically `Send + Sync`.
- **Custom parsers that hold `Rc<T>` or `RefCell<T>` directly**
  will fail to compile. Switch to `Arc<T>` / `Mutex<T>` /
  `RwLock<T>` (or `parking_lot` equivalents). In practice these
  patterns are rare in passive observation code.

### Removing `LocalSet` workarounds

If your code wraps the driver in a `tokio::task::LocalSet`,
`current_thread` runtime, or single-thread executor purely to
work around the previous `!Send` constraint, you can drop those
workarounds:

```rust
// Before (0.12):
#[tokio::main(flavor = "current_thread")]
async fn main() {
    LocalSet::new().run_until(async { /* drive driver */ }).await;
}

// After (0.13):
#[tokio::main]  // multi-thread default
async fn main() {
    tokio::spawn(async { /* drive driver */ }).await.unwrap();
}
```

## §2 `OwnedAnomaly` + `DetectorScore` (plan 147)

Detector code that emitted anomalies through `FlowEvent::FlowAnomaly`
or hand-rolled JSON now has a canonical path:

```rust
// 0.12: hand-roll a FlowAnomaly + serde_json::to_string + write.
// Or wrap your detector output in a Vec<(label, value)> and emit
// custom JSON. Each detector framework reinvented the wheel.

// 0.13: every shipped detector score gets `.into_anomaly(ts)`.
use flowscope::DetectorScore;

let score = port_scan.observe(key, success);  // ScanScore<FiveTupleKey>
let anomaly: flowscope::OwnedAnomaly = score.into_anomaly(ts);
eve.write_owned_anomaly(&anomaly)?;
```

### `OwnedAnomaly` shape

```rust
pub struct OwnedAnomaly {
    pub kind: Cow<'static, str>,
    pub severity: Severity,
    pub ts: Timestamp,
    pub src_ip: Option<IpAddr>,
    pub src_port: Option<u16>,
    pub dest_ip: Option<IpAddr>,
    pub dest_port: Option<u16>,
    pub proto: Option<&'static str>,
    pub observations: SmallVec<[(&'static str, Cow<'static, str>); 4]>,
    pub metrics: SmallVec<[(&'static str, f64); 4]>,
    pub flowscope_kind: Option<AnomalyKind>,
}
```

`SmallVec<[..; 4]>` for observations + metrics: zero-alloc in
the typical case (detectors produce 2–5 of each). `&'static str`
labels — compile-time constants. `Cow<'static, str>` values —
zero-alloc for literals, owned for runtime-built strings.

### Bridging flowscope-internal anomalies

```rust
// FlowEvent::FlowAnomaly { key, kind, ts } from the tracker:
let bridged = OwnedAnomaly::from_flow_anomaly(&key, kind, ts);
// flowscope_kind is set; anomaly.type follows the typed kind's
// classification.
```

### Custom detectors

Implement `DetectorScore` on your score type:

```rust
impl DetectorScore for MyCustomScore {
    fn name(&self) -> &'static str { "MyCustomDetector" }
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly {
        OwnedAnomaly::new("MyCustomDetector", Severity::Warning, ts)
            .with_observation("verdict", self.verdict_slug())
            .with_metric("score", self.score)
    }
}
```

Now anywhere a `S: DetectorScore` is accepted, your detector
fits the slot — including `EveJsonWriter::write_owned_anomaly`.

## §3 `BroadcastSlotHandle` for fan-out (plan 150)

`SlotHandle::clone` is **competitive consumer** semantics: each
clone races to pop messages from one shared queue. For
**broadcast** semantics (every consumer sees every message),
register through the new method:

```rust
// 0.12: hand-roll a fan-out loop draining one SlotHandle into
// an std::sync::mpsc and pushing to N receivers.

// 0.13:
let mut logger = builder.session_on_ports_broadcast_each(
    HttpParser::default(), [80, 8080]);
let mut metrics = logger.clone();
let mut alerter = logger.clone();
// logger / metrics / alerter each see every HTTP message.
```

`BroadcastSlotHandle` adds a `M: Clone` bound (each push clones
once per live subscriber). Every shipped parser message
(`HttpMessage`, `DnsMessage`, `TlsMessage`) is already `Clone`
under `Bytes`.

Note: 0.13 ships the **session port-routed** broadcast variant
only. Datagram + heuristic broadcast variants are 0.14 if a
consumer asks.

## §4 `SlotHandle::drain_n` for bounded back-pressure (plan 149)

```rust
// 0.12:
http_slot.drain(&mut messages);  // unbounded; risks monopolising a CPU.

// 0.13:
let drained = http_slot.drain_n(&mut messages, 64);  // at most 64 per call.
```

`max = 0` is a valid no-op; `max = usize::MAX` is equivalent to
`drain()`. Use when shard run-loops need to bound per-iteration
drain volume.

## §5 `PcapFlowSource::with_speed_factor` for paced replay (plan 152)

```rust
// 0.12: unpaced replay. 1 GB pcap took ~10 s.
// 0.13: opt into time-realistic pacing.
let source = PcapFlowSource::open("trace.pcap")?
    .with_speed_factor(1.0);  // real-time
```

`f64::INFINITY` = as-fast-as-possible (default). Uses
`std::thread::sleep`; **blocks the current thread** — wrap in
`tokio::task::spawn_blocking` or use a dedicated thread when
embedding in a tokio runtime.

## §6 `FlowStateMap<T, K>` for per-flow typed state (plan 154)

```rust
use flowscope::correlate::FlowStateMap;
use std::time::Duration;

#[derive(Default)]
struct PerFlow { packets: u64, bytes: u64 }

let mut state: FlowStateMap<PerFlow> = FlowStateMap::new(Duration::from_secs(60));

for event in driver_events {
    state.feed(&event);  // evicts on Ended, refreshes on others
    if let Event::FlowPacket { key, len, ts, .. } = event {
        let entry = state.get_or_default(&key, ts);
        entry.packets += 1;
        entry.bytes += len as u64;
    }
}

// From your tick handler:
state.sweep(now);
```

Defaults `K` to `FiveTupleKey`. `T: Default` for lazy creation;
override with `KeyIndexed::insert` directly if you need a
custom init.

## §7 `KeyIndexed::new_unbounded` regression fix (plan 154)

The 0.12 release shipped `KeyIndexed::new_unbounded(ttl)` with
a hashbrown capacity overflow on first insert — the underlying
`LruCache::new(usize::MAX)` would try to pre-allocate `usize::MAX`
buckets.

The 0.13 fix switches to `LruCache::unbounded()`, which lazy-
grows. No API change; if you were using `new_unbounded` and
hitting a panic, the panic goes away.

## §8 Test helpers — synthetic event constructors (plan 153)

```rust
#[cfg(feature = "test-helpers")]
use flowscope::test_helpers::events;

let evt = events::started(my_key, Timestamp::new(0, 0));
let driver_evt = events::driver::flow_started(my_key, Timestamp::new(0, 0));
```

Replaces the `#[doc(hidden)] pub fn new` escape hatch some
downstream test crates had been using.

## §9 `EveOptions::custom_anomaly_type` (plan 147)

New field on `EveOptions`:

```rust
let mut options = EveOptions::default();
options.custom_anomaly_type = "applayer";  // default; override per detector framework
```

Used by `write_owned_anomaly` when the anomaly carries no
`flowscope_kind`. Suricata-compatible values: `"stream"`,
`"applayer"`, `"decode"`. Schema-permissive — downstream tools
tolerate new values.

## §10 No tracking-only / metric-only API changes

Metrics vocabulary (`flowscope_*_total`, `flowscope_*_seconds`)
is unchanged in 0.13. Existing Prometheus / OpenTelemetry
scrapers keep working.

Tracing structured fields are unchanged.

Serde wire format is unchanged (locked since 0.8).

## §11 If something broke

The realistic failure modes are:

1. **`Send + Sync` bound failures**: your custom parser holds an
   `Rc<T>` or `RefCell<T>`. Switch to `Arc<T>` / `Mutex<T>`.
2. **Unused `LocalSet` / `current_thread`**: harmless leftover;
   you can simplify but don't have to.
3. **Stale doc comments referring to `Driver<E>: !Send`** in
   your own code: just update them.

For anything else, file a regression — the cycle aimed for
strictly additive behavior on top of the bound tightening.
