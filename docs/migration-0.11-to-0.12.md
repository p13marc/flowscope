# Migration: flowscope 0.11 → 0.12

The 0.12 cycle ships one pre-1.0 break and four opt-in
additions. For most users the upgrade is no code change.

## Cheat sheet

| You used … | You now use … |
|---|---|
| `SlotHandle<M, K>: !Send` (was `Rc<RefCell>`-backed) | `SlotHandle<M, K>: Send + Sync` (`Arc<crossbeam_queue::SegQueue>`-backed). Same API; gains cross-thread drain. |
| Manually formatting a `Timestamp` for log lines | `ts.to_iso8601()` or `ts.write_iso8601(&mut buf)?` |
| `chrono::Utc.timestamp_opt(ts.sec as i64, ts.nsec).unwrap()` | `chrono::DateTime::<Utc>::try_from(ts)?` (with `chrono` feature) |
| `TimeBucketedCounter::new(window, bucket, usize::MAX)` | `TimeBucketedCounter::new_unbounded(window, bucket)` |
| Hand-rolled JSON for SIEM ingest | `EveJsonWriter` (Suricata 7.x EVE; `emit-eve` feature) |
| `Driver::builder(extractor).…build()` (must commit to `extractor` up front) | `Driver::deferred().…build_with(extractor)` (commit at finalisation) |
| `use flowscope::AnomalyFields;` for `src_ip` / `dest_port` / `proto_str` accessors | `use flowscope::KeyFields;` (plan 130 trait split) |
| `Timestamp::try_into::<DateTime<Utc>>()?` | `ts.into()` — chrono From is infallible (plan 130 §4) |
| `[features] = ["ja3", "ja4"]` in Cargo.toml | `[features] = ["tls-fingerprints"]` (plan 131) |
| `[features] = ["tracing", "tracing-messages"]` | `[features] = ["tracing"]` — per-message emission is always-on; filter via `EnvFilter::new("flowscope.message=warn")` (plan 131) |

## 1. `SlotHandle<M, K>` is now `Send + Sync`

The handle returned by every
`builder.session_*` / `builder.datagram_*` registration call
moved from `Rc<RefCell<Vec<…>>>` to
`Arc<crossbeam_queue::SegQueue<…>>` backing.

### What changed

- `SlotHandle<M, K>` is `Send + Sync`.
- Generic bounds tighten from `M: 'static, K: 'static` to
  `M: Send + 'static, K: Send + 'static`. Every shipped
  `SessionParser::Message` and `DatagramParser::Message`
  already meets this (the trait bounds require it), so in
  practice this constraint is invisible.
- The `Driver<E>` itself remains `!Send` — the central
  `FlowTracker` holds `Rc<RefCell>` internals. Only the handle
  side is cross-thread.
- `Clone` hands out a **competitive consumer**: each clone
  drains from the same queue and races for messages. Sum
  across all clones equals total pushed. For broadcast
  semantics (every consumer sees every message), drain into a
  channel and fan out.

### Migration

For the vast majority of users: no code change.

If your code asserted `!Send` on a `SlotHandle` (unusual),
update the bound — that compile error is the only thing the
break can surface.

If you need cross-thread drain, you can now:

```rust,ignore
use std::thread;
let drainer = http_slot.clone();   // Send + Sync since 0.12
thread::spawn(move || {
    let mut h = drainer;
    let mut buf = Vec::new();
    loop {
        h.drain(&mut buf);
        // forward to a channel / sink
    }
});

// Drive on the original thread (Driver<E> stays !Send).
for owned in source.views() {
    driver.track_into(PacketView::from(&owned?), &mut events);
}
```

Bench gate: `benches/zero_alloc.rs::track_into_5_slots_steady_state`
holds at **0.000 allocs/pkt** in steady state after the
SegQueue change. Per-slot push/pop is ~10–15 ns uncontended.

## 2. `Timestamp::to_iso8601` / `write_iso8601`

`Timestamp` gains alloc-free RFC 3339 / ISO 8601 rendering:

```rust,ignore
let ts = Timestamp::new(1_700_000_000, 123_456_789);
assert_eq!(ts.to_iso8601(), "2023-11-14T22:13:20.123456789Z");

// Allocation-free path:
let mut buf = String::with_capacity(40);
ts.write_iso8601(&mut buf)?;
```

Uses Howard Hinnant's `civil_from_days` algorithm directly —
no chrono dependency required.

### `chrono` feature

When the `chrono` feature is on:

```rust,ignore
use chrono::{DateTime, Utc};

// Convert from chrono:
let ts: Timestamp = utc_now.into();

// Convert to chrono — infallible since plan 130 §4:
let dt: DateTime<Utc> = Timestamp::new(1_700_000_000, 0).into();
```

The runtime path is alloc-free regardless; the feature pulls
chrono with `default-features = false, features = ["alloc"]`.

> The plan 127 ship initially used a `TryFrom` shape with a
> `ChronoOutOfRange` error type for the theoretical-only
> out-of-range case; plan 130 §4 retired it before release
> because `Timestamp::sec: u32` fits inside chrono's range with
> room to spare. The full break recipe is in §11 below.

## 3. `Driver::deferred()`

> **Removed in 0.20 (#98).** The deferred builder was retired —
> nothing used it, and the eager `DriverBuilder` carries every knob.
> Use `Driver::builder(extractor)` → register slots → `build()`. The
> recipe below is kept for historical context only.

If you build the driver from a chain that doesn't know the
extractor instance until finalisation:

```rust,ignore
// Old (0.11): had to commit to FiveTuple::bidirectional() up front.
let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http = builder.session_on_ports(HttpParser::default(), [80]);
let mut driver = builder.build();

// New (0.12): register first, commit later.
let mut builder = Driver::<FiveTuple>::deferred();
let mut http = builder.session_on_ports(HttpParser::default(), [80]);
// …after CLI / config resolution:
let mut driver = builder.build_with(FiveTuple::bidirectional());
```

The deferred builder is API-identical to `DriverBuilder` minus
`build()`. The compile-time guarantee that an extractor is set
is preserved by type-system separation — `DeferredDriverBuilder`
has **no** `build()` method, so finalising without an
extractor is a compile error, not a runtime panic.

## 4. `EveJsonWriter` (Suricata EVE)

```toml
flowscope = { version = "0.12", features = ["emit-eve", "pcap"] }
```

```rust,ignore
use flowscope::emit::{EveJsonWriter, EveOptions};
let mut opts = EveOptions::default();
opts.in_iface = "eth0".to_string();
let mut eve = EveJsonWriter::with_options(BufWriter::new(file), opts);

for ev in driver.track(view) {
    eve.write_event(&ev)?;
}
eve.finish()?;
```

Three EVE `event_type` values: `"flow"` (per-flow on `Ended`),
`"anomaly"` (per `FlowAnomaly` / `TrackerAnomaly`), `"stats"`
(per `Tick`; off by default).

Every record carries a `flow_hash` field — a 16-char hex
FNV-1a over `(proto, sorted endpoints)`, deterministic and
direction-invariant. Use as a stable correlation key across
pipelines.

To use with a custom flow-key type, implement
`flowscope::AnomalyFields` — see
[`docs/eve-format.md`](eve-format.md) for the field-by-field
schema mapping and a worked custom-key recipe.

## 5. `AnomalyFields` trait

New trait `flowscope::AnomalyFields` exposes structured field
accessors used by `EveJsonWriter` (and any future field-aware
emitter):

```rust,ignore
pub trait AnomalyFields {
    fn src_ip(&self)         -> Option<IpAddr>       { None }
    fn src_port(&self)       -> Option<u16>          { None }
    fn dest_ip(&self)        -> Option<IpAddr>       { None }
    fn dest_port(&self)      -> Option<u16>          { None }
    fn proto_str(&self)      -> Option<&'static str> { None }
    fn app_proto_str(&self)  -> Option<&'static str> { None }
    fn anomaly_type(&self)   -> Option<&'static str> { None }
    fn anomaly_event(&self)  -> Option<&'static str> { None }
}
```

Shipped impls:

- `FiveTupleKey` — src/dest IP/port + proto + app_proto via
  the `well_known` port table.
- `L4Proto` — uppercase EVE label (`"TCP"` / `"UDP"` /
  `"ICMP"` / `"ICMPv6"` / `"SCTP"`).
- `AnomalyKind` — Suricata-style `anomaly.type`
  (`"stream"` for buffer/OOO/retransmit/watermark/eviction;
  `"applayer"` for parse errors) and `anomaly_event` = the
  stable `short_kind` slug.

Custom keys opt in by implementing whichever accessors they
can — all 8 methods default to `None`, so partial impls work.

## 6. `correlate::*::new_unbounded` convenience constructors

Three trivial delegates on existing types:

```rust,ignore
TimeBucketedCounter::new_unbounded(window, bucket_width)
TimeBucketedSet::new_unbounded(window, bucket_width)
KeyIndexed::new_unbounded(ttl)
```

Each is equivalent to passing `usize::MAX` as the capacity
argument to the bounded `new`. Prefer the bounded constructors
when memory pressure matters.

## CI matrix

The 0.12 feature matrix grew by two entries:

- `chrono` — `Timestamp` ↔ `chrono::DateTime<Utc>` interop.
- `emit-eve` — Suricata EVE JSON writer.

Both are opt-in; default features and existing combos are
unchanged.

## 7. `KeyFields` / `AnomalyFields` trait split (plan 130)

The `AnomalyFields` trait shipped in 0.12 base conflated two
concerns: 5-tuple key accessors and anomaly-classification
accessors. Plan 130 split them along the natural cleavage:

```rust,ignore
// Before (0.12 base):
pub trait AnomalyFields {
    fn src_ip(&self)        -> Option<IpAddr>       { None }
    fn src_port(&self)      -> Option<u16>          { None }
    // … 4 more key methods …
    fn anomaly_type(&self)  -> Option<&'static str> { None }
    fn anomaly_event(&self) -> Option<&'static str> { None }
}

// After (0.12 final):
pub trait KeyFields {
    fn src_ip(&self)        -> Option<IpAddr>       { None }
    fn src_port(&self)      -> Option<u16>          { None }
    fn dest_ip(&self)       -> Option<IpAddr>       { None }
    fn dest_port(&self)     -> Option<u16>          { None }
    fn proto_str(&self)     -> Option<&'static str> { None }
    fn app_proto_str(&self) -> Option<&'static str> { None }
}

pub trait AnomalyFields {
    fn anomaly_type(&self)  -> Option<&'static str> { None }
    fn anomaly_event(&self) -> Option<&'static str> { None }
}
```

### Migration

- Custom keys with `impl AnomalyFields for MyKey { fn src_ip(...) ... }`
  → rename to `impl KeyFields for MyKey { ... }`.
- `AnomalyKind` keeps its `impl AnomalyFields` unchanged.
- Both traits live at the crate root and `prelude`. If you
  used `use flowscope::prelude::*;` nothing changes.
- Code calling `key.src_ip()` / `.dest_port()` etc. needs
  `use flowscope::KeyFields;` in scope (or the prelude).

The emit writers (CSV / NDJSON / Zeek / EVE) are now generic
over `K: KeyFields` — custom keys flow through them by
implementing the trait.

## 8. Cargo feature changes (plan 131)

Three changes:

```toml
# Before
flowscope = { version = "0.12", features = ["ja3", "ja4", "tracing", "tracing-messages"] }

# After
flowscope = { version = "0.12", features = ["tls-fingerprints", "tracing"] }
```

- `ja3` + `ja4` → `tls-fingerprints`. Both fingerprints now
  ship under one gate. Runtime selection via
  `TlsConfig::ja3` / `TlsConfig::ja4` still works.
- `tracing-messages` deleted. The `Message: Debug` bound was
  already always-on; the feature was just toggling per-message
  emission. Now the trace events are always emitted under
  `tracing`; filter at runtime via `tracing-subscriber`:
  ```rust,ignore
  use tracing_subscriber::EnvFilter;
  let filter = EnvFilter::new("info,flowscope.message=warn");
  tracing_subscriber::fmt().with_env_filter(filter).init();
  ```

## 9. `Error::Module` variants (plan 131)

- `Module::Pipeline` removed (Pipeline was deleted in 0.11;
  the enum entry was dead code).
- Five new variants added for subsystems that don't error
  today but will as soon as one does: `Driver` / `Emit` /
  `Detect` / `Aggregate` / `Correlate`.

If your code matched on `Module::Pipeline`, drop the arm —
the variant could only ever appear from code paths that no
longer exist. `#[non_exhaustive]` means your `match` already
had a wildcard arm.

## 10. `Event::tcp()` cross-variant accessor (plan 130 §3)

New additive accessor on `flowscope::driver::Event<K>`:

```rust,ignore
match ev {
    Event::FlowPacket { key, side, len, ts, tcp, .. } => {
        // pre-existing destructure still works
        if let Some(info) = tcp { /* use TcpInfo */ }
    }
    other => {
        // new: cross-variant accessor returns None on non-Packet
        if let Some(info) = other.tcp() { /* TcpInfo if available */ }
    }
}
```

The `tcp` field is unchanged — still public on the variant,
still `None` unless `DriverBuilder::emit_packet_details(true)`
was set. The accessor just saves callers from repeating that
destructure when they want "TCP info if available, on any
variant."

## 11. `Timestamp` → `chrono::DateTime<Utc>` is infallible

`TryFrom<Timestamp>` → `From<Timestamp>`. The error case
(`ChronoOutOfRange`) was unreachable in practice (`Timestamp::sec`
is u32, chrono's range is ±262 143 years). Migration:

```rust,ignore
// Before
let dt: DateTime<Utc> = ts.try_into().unwrap();

// After
let dt: DateTime<Utc> = ts.into();
```

The `ChronoOutOfRange` type was deleted.

## 12. `BurstDetector::new_unbounded` + `TopK::new_unbounded` (plan 130 §5)

Completing the `correlate::*::new_unbounded` set the 0.12
base shipped for `TimeBucketedCounter` / `TimeBucketedSet` /
`KeyIndexed`. Additive — no migration required.
