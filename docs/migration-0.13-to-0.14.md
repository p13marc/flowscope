# Migration: 0.13 → 0.14

Quick reference for upgrading from `flowscope = "0.13"` to
`flowscope = "0.14"`.

**The 0.14 cycle is strictly additive.** Every plan extends an
existing public surface or adds a new type — no existing API
breaks, no bound tightening, no deprecations. `cargo update -p
flowscope` should compile your existing code unchanged.

The migrations below are entirely **adoption** patterns: idioms
you can lean into to drop hand-rolled code you were maintaining
locally.

## TL;DR — 30-second cheat sheet

```toml
# Cargo.toml
[dependencies]
flowscope = "0.14"
```

Drop-in adoption patterns:

```rust
// 0.13: hand-rolled HashMap<FlowKey, FlowStats> mirror cache
// for ICMP error correlation.
// 0.14: one method call.
if let Some(key) = tracker.lookup_inner(&icmp_inner) {
    // …
}

// 0.13: 30-line v4/v6 DU code classifier inline.
// 0.14: one method.
match icmp_type.dest_unreachable_kind() {
    Some(DestUnreachableKind::Port) => /* … */,
    _ => /* … */,
}

// 0.13: rolled your own bucketed bandwidth tracker.
// 0.14: built-in primitive.
let mut bw: RollingRate<&'static str, u64> =
    RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
bw.record(flow_key.app_label(), bytes as u64, now);

// 0.13: `(if is_tcp { "tcp" } else if is_udp { "udp" } …)` at every call site.
// 0.14: always-Some `app_label`.
let label = flow_key.app_label();  // "http" / "tls/https" / "tcp" / "sctp" / "other"

// 0.13: hand-coded per-side accessors.
// 0.14: built-in sugar.
let upload_bytes = stats.bytes_for(FlowSide::Initiator);
let skew = stats.direction_skew();  // [-1, 1]; positive = upload-heavy
```

## §1 `FlowTracker::lookup_inner` (plan 161)

The headline 0.14 addition. Specialised impl block on
`FlowTracker<FiveTuple, S>` — takes an `IcmpInner` from an
ICMPv4 / ICMPv6 error message and returns the matching live
flow's canonical key.

```rust
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::icmp::{IcmpInner, IcmpType};
use flowscope::FlowTracker;

// In an on_icmp_error handler:
if let Some(IcmpType::V4(v4_type)) = icmp_msg.ty {
    if let Some(IcmpInner { .. }) = v4_type.dest_unreachable_inner() {
        let inner = /* the IcmpInner */;
        if let Some(key) = tracker.lookup_inner(&inner) {
            // The flow exists — emit a "flow died because of
            // ICMP error" anomaly with the canonical key.
            eprintln!("ICMP DU joined back to flow {:?}", key);
        }
    }
}

// Companion: get the key AND the FlowStats snapshot.
if let Some((key, stats)) = tracker.stats_for_inner(&inner) {
    let bytes = stats.total_bytes();
    // …
}
```

Direction-agnostic: matches whether the ICMP error reports the
flow's forward direction OR the reverse direction. The
canonicalisation logic is the same the `FiveTuple::bidirectional()`
extractor applies internally.

For unidirectional trackers (`FiveTuple::directional()`), use
`FiveTupleKey::from_inner_literal` + `tracker.get(&key)`
directly:

```rust
if let Some(key) = FiveTupleKey::from_inner_literal(&inner) {
    if let Some(entry) = tracker.get(&key) {
        // …
    }
}
```

## §2 `DestUnreachableKind` (plan 162)

Unified v4/v6 vocabulary. Replaces the ~30-line classifier
every ICMP consumer was writing.

```rust
use flowscope::DestUnreachableKind;
// also re-exported from flowscope::prelude::*;

match icmp_type.dest_unreachable_kind() {
    Some(DestUnreachableKind::Host)           => /* host unreachable */,
    Some(DestUnreachableKind::Port)           => /* port unreachable / "connection refused" */,
    Some(DestUnreachableKind::Network)        => /* no route */,
    Some(DestUnreachableKind::Protocol)       => /* unsupported L4 (v4 only) */,
    Some(DestUnreachableKind::AdministrativelyProhibited) => /* firewall */,
    Some(DestUnreachableKind::FragmentationNeeded) => /* MTU mismatch */,
    Some(DestUnreachableKind::Other)          => /* niche codes */,
    None => /* not a DU */,
}

// Stable metric label:
metrics::counter!("icmp_du_total", "kind" => kind.as_str()).increment(1);
```

The v4 `FragmentationNeeded` variant loses the `mtu` value in
the unified mapping. Match on `Icmpv4DestUnreachCode` directly
if you need it. (v6 `PacketTooBig` is type 2, not under DU; a
separate `IcmpType::mtu_signal()` accessor is possible in 0.15
if a consumer asks.)

## §3 `RollingRate<K, V>` (plan 164)

Per-key per-second rate over a sliding window. Generic over
the value type — `u64` for bytes/sec, `u64` with
`record(k, 1, now)` for request-rate, `f64` for latency-sums.

```rust
use std::time::Duration;
use flowscope::correlate::RollingRate;
use flowscope::Timestamp;

// Bandwidth-by-app:
let mut bw: RollingRate<&'static str, u64> =
    RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));

for event in driver_events {
    if let Event::FlowPacket { key, len, ts, .. } = event {
        bw.record(key.app_label(), len as u64, ts);
    }
}

// Per-key rate:
println!("HTTP rate: {} B/s", bw.rate(&"http", now));

// Top-N snapshot:
let mut snap: Vec<_> = bw.snapshot(now).collect();
snap.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
for (label, rate) in snap.iter().take(10) {
    println!("{label}: {rate:.0} B/s");
}
```

**Bucket-reuse zero-alloc**: consecutive `record` calls falling
in the same bucket reuse the same `HashMap` — no per-call
allocation. Match `TimeBucketedCounter`'s contract.

**`RateValue` trait**: implemented for `u64` / `u32` / `i64` /
`i32` / `f64` / `f32`. Implement on custom newtype wrappers to
prevent accidental crossover (e.g., a `Bytes(u64)` newtype that
can't be mixed with a `RequestCount(u64)`).

## §4 `LabelTable` for site-custom port labels (plan 165)

Every real deployment has internal services on non-standard
ports ("our gRPC on 8765", "metrics scrape on 9101"). The
built-in `well_known` table covers ~80 standard ports; this
struct lets you layer custom overrides without forking.

```rust
use flowscope::well_known::LabelTable;
use flowscope::extractor::L4Proto;

let mut table = LabelTable::new();  // inherits the built-in table
table.set(L4Proto::Tcp, 8765, "grpc-internal");
table.set(L4Proto::Tcp, 9101, "metrics-scrape");
table.extend([
    (L4Proto::Tcp, 30443, "legacy-app"),
    (L4Proto::Udp, 5683, "coap-iot"),
]);

// Lookup:
let label = flow_key.protocol_label_with(&table);  // Option<&'static str>
let label = flow_key.app_label_with(&table);       // always-Some

// Strict whitelist mode (no built-in fallback):
let mut strict = LabelTable::standalone();
strict.set(L4Proto::Tcp, 443, "tls");
```

For runtime-loaded labels (YAML/JSON config), use `Box::leak`:

```rust
let cfg_label = String::from(/* read from config */);
let leaked: &'static str = Box::leak(cfg_label.into_boxed_str());
table.set(L4Proto::Tcp, port, leaked);
```

`LabelTable` is `Clone + Send + Sync`.

## §5 `app_label` + `L4Proto::canonical_name` (plan 163)

Two new always-Some accessors, sibling to the existing
`Option`-returning / uppercase ones:

| Method | Variant | Returns |
|---|---|---|
| `KeyFields::proto_str()` | Uppercase EVE/Suricata schema | `Option<&'static str>` |
| `L4Proto::canonical_name()` | Lowercase metric label | `&'static str` always |
| `FiveTupleKey::protocol_label()` | Well-known L7 label | `Option<&'static str>` |
| `FiveTupleKey::app_label()` | Always-Some — L4 fallback | `&'static str` always |

```rust
// Before (0.13): the `is_tcp` workaround.
let label = if let Some(l7) = key.protocol_label() {
    l7
} else if matches!(key.proto, L4Proto::Tcp) {
    "tcp"
} else if matches!(key.proto, L4Proto::Udp) {
    "udp"
} else {
    "other"
};

// After (0.14): one method.
let label = key.app_label();
```

## §6 `KeyIndexed::drain_expired` (plan 160)

Sibling to the existing `evict_expired` (which discards):
returns the expired entries as owned `(K, V)` pairs so you can
inspect them.

```rust
use flowscope::correlate::KeyIndexed;

// Periodic inspection loop:
let drained = pending_lookups.drain_expired(now);
for (key, value) in drained {
    // "DNS resolved but no connection followed in 30s" anomaly.
    emit_anomaly(key, value);
}

// Reusable-buffer variant (amortizes allocation):
let mut out = Vec::with_capacity(64);
loop {
    let n = pending.drain_expired_into(now, &mut out);
    if n == 0 { break; }
    for (k, v) in out.drain(..) {
        // process
    }
}
```

Honest allocation contract: the underlying `lru::LruCache` has
no `drain()` method, so a `Vec` is unavoidable. The `_into`
variant amortizes across calls.

## §7 `FlowStats` per-`FlowSide` accessors (plan 168)

Pure sugar over the existing `bytes_initiator` /
`bytes_responder` / `packets_*` fields.

```rust
use flowscope::FlowSide;

let upload = stats.bytes_for(FlowSide::Initiator);
let download = stats.bytes_for(FlowSide::Responder);

let init_pkt_size = stats.mean_pkt_size_for(FlowSide::Initiator);  // f64, 0.0 on empty side
let resp_pkt_size = stats.mean_pkt_size_for(FlowSide::Responder);

// Direction skew — [-1, 1]; positive = init-heavy (uploads), negative = resp-heavy (downloads).
let skew = stats.direction_skew();
if skew > 0.8 {
    // One-sided flow — DoS / scan / asymmetric streaming.
}
```

## §8 Discoverability sweep (plan 167)

The `flowscope::prelude::*` expansion adds ~13 new names
(grouped behind the existing feature gates). After upgrading,
`use flowscope::prelude::*;` brings these into scope:

- `correlate::*` — `TimeBucketedCounter`, `TimeBucketedSet`,
  `KeyIndexed`, `BurstDetector`, `Ewma`, `TopK`, `RollingRate`,
  `FlowStateMap`.
- `icmp::*` — `IcmpType`, `IcmpMessage`, `IcmpInner`,
  `DestUnreachableKind`.
- `well_known::LabelTable`.

If your code already uses qualified paths
(`flowscope::correlate::TimeBucketedCounter`), nothing changes
— the qualified paths still work. The prelude expansion is
purely additive.

New `docs/discoverability.md` page lists every shipped
primitive grouped by use case — "count things per key over
time" / "react to ICMP errors" / "emit structured anomalies" /
etc. See it for the full taxonomy.

## §9 What didn't change

- Wire format (serde) — locked since 0.8.
- `FlowEvent` variants — no new ones (additive future).
- `Driver<E>: Send + Sync` (0.13 plan 156) — unchanged.
- `OwnedAnomaly` / `DetectorScore` (0.13 plan 147) — unchanged.
- All emit writers (`EveJsonWriter`, etc.) — unchanged.
- MSRV — still Rust 1.88.
- Metric label vocabulary — only additions
  (`icmp_du_total{kind=…}` slugs are new; existing labels
  unchanged).

## §10 If something broke

Likely failure modes after `cargo update -p flowscope`:

1. **`LabelTable::override_count` is gone** — renamed to
   `LabelTable::len` (plan 172). Find/replace:

   ```rust,ignore
   // before
   table.override_count()
   // after
   table.len()
   ```

   This is the **only breaking removal in the 0.14 cycle**.
   Safe because `override_count` only ever shipped on master
   for hours, never on crates.io.
2. **`use flowscope::prelude::*;` brings in new names that
   shadow your local types.** Switch to qualified
   `flowscope::correlate::RollingRate` etc., or move your
   local types out of scope.

## §11 `IcmpType::mtu_signal()` + `MtuSignalKind` (plan 170)

Plan 162 (`DestUnreachableKind`) deliberately scoped to
Destination Unreachable codes only. Plan 170 adds the parallel
PMTU-mismatch signal that covers ICMPv4 DU code 4
(Fragmentation Needed) AND ICMPv6 type 2 (Packet Too Big) —
which v6 splits out of DU entirely.

```rust
use flowscope::{DestUnreachableKind, MtuSignalKind};
// Also re-exported via prelude.

match icmp_type.mtu_signal() {
    Some(MtuSignalKind::FragmentationNeeded { next_hop_mtu }) => {
        // v4: next_hop_mtu may be None for RFC 1191
        // non-conformant senders.
        if let Some(mtu) = next_hop_mtu {
            eprintln!("v4 PMTUD: next hop wants <= {mtu}");
        }
    }
    Some(MtuSignalKind::PacketTooBig { next_hop_mtu }) => {
        // v6: next_hop_mtu is mandatory.
        eprintln!("v6 PacketTooBig: next hop wants <= {next_hop_mtu}");
    }
    None => {}
}

// Stable metric label slug:
metrics::counter!("icmp_mtu_total", "kind" => kind.as_str())
    .increment(1);

// Unified accessor:
let mtu: Option<u32> = kind.next_hop_mtu();
```

`MtuSignalKind` is `Send + Sync + Copy`, re-exported at the
crate root and in the prelude.

## §12 `LabelTable` completeness (plan 172)

Four new operations on `LabelTable`:

```rust
let mut table = LabelTable::new();
table.set(L4Proto::Tcp, 8765, "grpc-internal");

// Inverse of set():
let prev = table.remove(L4Proto::Tcp, 8765);
assert_eq!(prev, Some("grpc-internal"));

// Override-only membership check (does NOT consult built-in):
assert!(!table.contains(L4Proto::Tcp, 8765));

// Standard collection idioms:
assert!(table.is_empty());
assert_eq!(table.len(), 0);
```

Plus `override_count` removed (see §10 above).

## §13 `RollingRate` completeness (plan 171)

Four new methods on `RollingRate<K, V>`:

```rust
use std::time::Duration;
use flowscope::correlate::RollingRate;
use flowscope::Timestamp;

let mut bw: RollingRate<&'static str, u64> =
    RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
bw.record("http", 1000, ts1);
bw.record("tls", 500, ts1);

// Raw sum without per-second divide — for "bytes-in-last-minute":
let bytes_last_window: u64 = bw.sum(&"http", now);

// Sorted top-N, descending; ties by snapshot insertion order:
let top10 = bw.top_k(10, now);
for (label, rate) in top10 {
    println!("{label:<12} {rate:>10.0} B/s");
}

// Reset for tests:
bw.clear();
assert!(bw.is_empty());

// Count unique in-window keys:
let active_apps = bw.len(now);
```

**Note on `is_empty` vs `len(now)`**: `is_empty()` is a
storage-state query (no `now` arg) — true when no buckets are
tracked. `len(now)` is the in-window analog — counts unique
keys observed within the active sliding window. A
`RollingRate` with stale unevicted buckets can have
`is_empty()==false` while `len(now)==0`.

## §14 `FlowStats::throughput_bps*` accessors (plan 173)

Four new methods on `FlowStats` for lifetime-average
throughput. Safe-divide built in — zero-duration flows return
`0.0` instead of NaN / Infinity.

```rust
use flowscope::FlowSide;

// Overall lifetime throughput:
let bps = stats.throughput_bps();   // bytes/sec
let pps = stats.throughput_pps();   // packets/sec

// Per-side:
let init_bps = stats.throughput_bps_for(FlowSide::Initiator);
let resp_bps = stats.throughput_bps_for(FlowSide::Responder);
let init_pps = stats.throughput_pps_for(FlowSide::Initiator);
let resp_pps = stats.throughput_pps_for(FlowSide::Responder);

// Sanity: sides sum to total.
assert!((bps - (init_bps + resp_bps)).abs() < 1e-9);
```

These replace the manual divide-by-`duration_secs()` pattern
at every call site — easy to forget the
`max(EPSILON)` guard, which is why the project ships the
safe-divide once and exposes it through these accessors.

For sliding-window throughput (last-N-seconds rate, not
lifetime average), use `RollingRate` instead — `FlowStats`
gives you the flow's lifetime aggregate.

For wider migration context, see:

- [`docs/migration-0.12-to-0.13.md`](migration-0.12-to-0.13.md) — `Driver<E>: Send + Sync`, `OwnedAnomaly`, `BroadcastSlotHandle`.
- [`docs/migration-0.11-to-0.12.md`](migration-0.11-to-0.12.md) — `SlotHandle: Send + Sync`.
- [`docs/migration-0.10-to-0.11.md`](migration-0.10-to-0.11.md) — parser API break + `Driver<E>` introduction.
