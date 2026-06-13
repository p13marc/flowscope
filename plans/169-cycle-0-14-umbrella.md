# Plan 169 — 0.14 cycle umbrella

**Status:** shipped to master, pending release. Triggered by
the netring-side 0.14 wishlist (9 asks: plans 160–168;
wishlist file retired after the cycle's release). This umbrella
synthesises the verification pass against the shipped 0.13.0
source, confirms each ask's premise, and lays out the
implementation plan set.

The user has explicitly authorised breaking-change cycles to
land the best designs, but this cycle is **strictly additive** —
every ask extends a public surface or adds a new type. No
existing API breaks.

---

## §1 Verification headlines

### §1.1 The wishlist's "FlowTracker is mutate-only" caveat is wrong

Plan 161 (`lookup_inner`) carries an explicit caveat in the
wishlist:

> *"…if the flow tracker doesn't currently expose a public
> read-only lookup, this may require a small refactor to
> split read-from-write. The existing public API tends to be
> mutate-only (`track`, `flush`, etc.) — confirm before
> estimating."*

Verification: **`FlowTracker<E, S>` already exposes a rich
public read API**:

- `get(&E::Key) -> Option<&FlowEntry<S>>` (src/tracker.rs:690)
- `snapshot_stats(&E::Key) -> Option<FlowStats>` (line 714)
- `flows() -> impl Iterator<Item = (&E::Key, &FlowEntry<S>)>` (line 700)
- `iter_active() -> impl Iterator<Item = ActiveFlow<…>>` (line 767)
- Plus `snapshot_history` / `snapshot_l4` / `flow_count` / etc.

No refactor is needed. Plan 161 drops from "may require
refactor" to "small additive method".

### §1.2 `drain_expired` can't be a true zero-alloc lazy iterator

Plan 160's wishlist signature is:

```rust
pub fn drain_expired(&mut self, now: Timestamp)
    -> impl Iterator<Item = (K, V)> + '_;
```

The existing `KeyIndexed::evict_expired` (src/correlate/indexed.rs)
already implements the only achievable pattern: collect expired
keys into `Vec<K>` first, then pop them one by one. The `lru`
crate doesn't expose a `drain()` method, so we can't yield
owned `(K, V)` pairs from a borrowed-`&mut` iterator without an
intermediate `Vec`.

The wishlist's signature is misleading — `impl Iterator + '_`
implies zero-allocation but a Vec is unavoidable.

**Counter-proposal**: ship two variants:

```rust
/// Drain expired entries, returning owned (K, V). Allocates
/// a Vec internally; suitable when the expired set is small
/// (typical case) and ergonomics matter.
pub fn drain_expired(&mut self, now: Timestamp) -> Vec<(K, V)>;

/// Same but reuses caller-supplied storage. Use when draining
/// in a hot loop where the Vec can be amortized across calls.
pub fn drain_expired_into(&mut self, now: Timestamp,
                          out: &mut Vec<(K, V)>) -> usize;
```

The `_into` variant is the zero-alloc-amortized path (matches
plan 119's `track_into` precedent). Document the allocation
contract honestly.

### §1.3 `L4Proto::proto_str` already exists — `canonical_name` is a sibling

Plan 163 asks for `L4Proto::canonical_name() -> &'static str`
(always-Some, lowercase). The shipped `L4Proto::proto_str()`
returns uppercase EVE-shaped labels (`"TCP"`, `"UDP"`,
`"ICMP"`, `"ICMPv6"`, `"SCTP"`, `None` for `Other(_)`).

These are sibling concerns: `proto_str` is EVE/Suricata
schema-compatible; `canonical_name` is metric-label/snake_case
ready. Both ship; both serve different consumer needs.

### §1.4 Plan 166 (icmp::types re-export) folds into Plan 162

Plan 166 is a 30-minute fix: promote `mod types;` (private) to
`pub mod types`, leaving `pub use types::*;` as the backward-
compat shim. Plan 162 already touches `src/icmp/mod.rs` (to
add `DestUnreachableKind` re-export). Fold them — one PR
covers both ICMP module hygiene concerns.

---

## §2 Asks at a glance — corrected

| # | Plan | Title | Priority | Effort (corrected) | Disposition |
|---|---|---|---|---|---|
| 160 | [160](./160-keyindexed-drain-expired.md) | `KeyIndexed::drain_expired` + `drain_expired_into` | **P0** | ~0.5 day | Honest allocation contract: ship Vec-returning + reusable-Vec variants |
| 161 | [161](./161-flowtracker-lookup-inner.md) | `FlowTracker<FiveTuple, S>::lookup_inner` + `stats_for_inner` + `FiveTupleKey::from_inner_canonical` | **P0** | ~1.5 days | Specialised impl on `FlowTracker<FiveTuple, S>` (not generic) + public canonicalisation helper |
| 162 | [162](./162-dest-unreachable-kind.md) | `DestUnreachableKind` enum + `IcmpType::dest_unreachable_kind` + **promote `icmp::types` to `pub mod`** (absorbs Plan 166) | **P0** | ~1 day | Combined ICMP module polish |
| 163 | [163](./163-app-label-canonical-name.md) | `FiveTupleKey::app_label` + `L4Proto::canonical_name` | **P1** | ~0.5 day | Sibling to `proto_str` (lowercase, always-Some) |
| 164 | [164](./164-correlate-rolling-rate.md) | `correlate::RollingRate<K, V>` primitive | **P1** | ~1.5 days | Mirrors `TimeBucketedCounter`'s bucket-reuse discipline; generic over `V` |
| 165 | [165](./165-protocol-label-extensibility.md) | `well_known::LabelTable` + `FiveTupleKey::protocol_label_with` / `app_label_with` | **P1** | ~1 day | Site-custom port label extensibility |
| 166 | — | — | — | — | **Folded into 162** (ICMP module hygiene) |
| 167 | [167](./167-discoverability-sweep.md) | Prelude expansion + `docs/discoverability.md` + rustdoc cross-links | **P2** | ~1 day | Surface existing correlate + ICMP + FlowStats helpers |
| 168 | [168](./168-flowside-byte-split.md) | `FlowStats::bytes_for` / `pkts_for` / `mean_pkt_size_for` / `direction_skew` | **P3** | ~0.5 day | Pure sugar over existing fields |

**Corrected total effort: ~6.5 days** (down from the wishlist's
~8). Two reasons:
- Plan 161 drops 0.5 day (no refactor needed; the read API
  already exists).
- Plan 166 folds into 162 (no separate plan overhead).

P0 alone (160 + 161 + 162): **~3 days**.
P0 + P1 (160, 161, 162, 163, 164, 165): **~6 days**.

---

## §3 Counter-proposals — design notes

### §3.1 Plan 160 — honest allocation contract

The wishlist signature `impl Iterator<Item = (K, V)> + '_`
implies zero-alloc. The `lru` crate's `LruCache` can't yield
owned values during borrowed iteration without an intermediate
Vec. Ship the truth:

- `drain_expired(now) -> Vec<(K, V)>` — ergonomic
- `drain_expired_into(now, &mut Vec<(K, V)>) -> usize` —
  reusable buffer for hot loops

The `_into` variant matches the precedent set by 0.11's
`Driver::track_into` (plan 119) and 0.13's `SlotHandle::drain`
/ `drain_n`.

### §3.2 Plan 161 — specialise on `FlowTracker<FiveTuple, S>`

The wishlist proposes a generic `FlowTracker<K>::lookup_inner`
method. But `IcmpInner` carries a 5-tuple (`IpAddr` + ports +
proto), which is FiveTupleKey-shaped. Other extractor types
(`IpPair`, `MacPair`, custom keys) don't have a meaningful
"lookup by 5-tuple" semantics.

The cleaner design: specialise the impl block.

```rust
impl<S> FlowTracker<crate::extract::FiveTuple, S>
where
    S: Send + 'static,
{
    pub fn lookup_inner(&self, inner: &IcmpInner) -> Option<FiveTupleKey>;
    pub fn stats_for_inner(&self, inner: &IcmpInner)
        -> Option<(FiveTupleKey, &FlowStats)>;
}
```

This requires a public helper to construct the canonical
FiveTupleKey from an `IcmpInner` (today the canonicalisation
logic is private inside `extract_from_parsed`):

```rust
impl FiveTupleKey {
    /// Construct a canonical key from a partial 5-tuple
    /// (typically extracted from an ICMP error's inner
    /// packet). Returns `None` if the ports are missing for
    /// a port-carrying proto (TCP/UDP/SCTP).
    pub fn from_inner_canonical(inner: &IcmpInner) -> Option<Self>;
}
```

This helper is independently useful (testing, custom ICMP
correlation pipelines) and the right level for the
canonicalisation logic.

### §3.3 Plan 162 — fold in Plan 166 + crate-root re-export

The wishlist's Plan 166 (`pub mod types`) is a 30-minute fix
that touches the same file as Plan 162. Ship them together.

Plan 162's open question: **prelude inclusion** for
`DestUnreachableKind`. My call: **yes**. It's the kind of enum
a netring `on_icmp_error` handler imports in every example.
Cost: 1 line in `src/prelude.rs`.

Also add `pub use icmp::DestUnreachableKind` at the crate root
(parallel to `pub use anomaly::OwnedAnomaly` at the crate root
since 0.13). Top-level enum exports for frequently-imported
items.

### §3.4 Plan 163 — `canonical_name` is lowercase, sibling to `proto_str`

`L4Proto::proto_str()` returns:

```
TCP, UDP, ICMP, ICMPv6, SCTP, None
```

`L4Proto::canonical_name()` should return:

```
tcp, udp, icmp, icmp6, sctp, other
```

— always-Some, lowercase, snake-case-compatible. The two methods
serve different consumers (`proto_str` for EVE schema;
`canonical_name` for metric labels and `app_label` fallbacks).

### §3.5 Plan 164 — drop the `From<u64>` bound

The wishlist's `V` bound is:

```
V: Default + Copy + AddAssign + From<u64> + Into<f64>
```

The `From<u64>` is for zero-initialisation. But `V: Default`
already gives us zero-init. The simpler bound:

```
V: Default + Copy + AddAssign + Into<f64>
```

works for both `V = u64` (bandwidth) and `V = f64` (e.g.
latency-sum) and custom newtypes. Drop `From<u64>`.

Naming: stick with `RollingRate`. The Prometheus-flavoured
"rate" framing matches how the primary accessor (`rate(k, now)`)
behaves — bytes-per-sec or count-per-sec depending on `V`.

Ship `new_unbounded` + `record` + `rate` + `snapshot` +
`evict_expired` as v1; add `with_capacity` only when a real
consumer asks.

### §3.6 Plan 165 — `LabelTable` with `&'static str` (no `Cow`)

The wishlist's open question Q4 asks whether the table should
hold `&'static str` or `Cow<'static, str>` to allow runtime
strings.

Stick with `&'static str`. Reasons:
- Matches the existing `well_known::protocol_label` contract.
- Runtime strings can be `Box::leak(string)` — one-line
  documented escape hatch.
- The table stays `Clone + Send + Sync` trivially.
- If a real consumer needs runtime strings, add a
  `LabelTableOwned` sibling type — but defer until that
  consumer arrives.

### §3.7 Plan 167 — main-prelude expansion (no sub-prelude)

The wishlist's Q5 asks: main prelude or sub-prelude for the
discoverability additions?

My call: **main prelude**. The shipped `flowscope::prelude` is
~25 names today; adding ~10 more from `correlate::*` + a few
ICMP types keeps it under 40 — well within reasonable
"glance-able" range.

Sub-preludes (`flowscope::prelude::reports`) add a discovery
step. The whole point of plan 167 is to reduce friction.

### §3.8 Plan 168 — strictly additive sugar

Ship the four methods (`bytes_for` / `pkts_for` /
`mean_pkt_size_for` / `direction_skew`) on `FlowStats`. They
shadow no existing methods; field access stays as fast as
ever; no perf concern.

---

## §4 Open questions answered

The wishlist's §13 has 5 open questions. My calls:

| # | Question | Verdict |
|---|---|---|
| Q1 | Plan 161 — FlowTracker read-only API exists? | **YES** — `get`, `snapshot_stats`, `flows`, `iter_active`. No refactor. |
| Q2 | Plan 162 — `FragmentationNeeded` vs `PacketTooBig`? | **Wishlist's pick** — ship `DestUnreachableKind` tight to DU codes; add `IcmpType::mtu_signal()` in 0.15 if asked. |
| Q3 | Plan 164 — `RollingRate` vs `RollingSum`? | **`RollingRate`** — `rate()` is the primary accessor. Add `RollingRate::sum(k, now) -> V` companion if needed. |
| Q4 | Plan 165 — `Send + Sync` `LabelTable`? | **YES** with `&'static str` values. Runtime strings via `Box::leak`. |
| Q5 | Plan 167 — main prelude or sub-prelude? | **Main prelude.** Single discovery step. ~35 names is still glance-able. |

---

## §5 Backwards-compatibility ledger

The user authorised breaking-change cycles, but **this cycle
is entirely additive** — every change extends a public surface
or adds a new type. No existing API breaks.

| Plan | Break? | Notes |
|---|---|---|
| 160 | No | Adds new `drain_expired` / `drain_expired_into` methods |
| 161 | No | Adds new methods on `FlowTracker<FiveTuple, S>` + `FiveTupleKey` |
| 162 | No | Adds `DestUnreachableKind` enum + accessor; promotes `mod types` to `pub mod` (was private — `pub use types::*` shim stays) |
| 163 | No | Adds `app_label` + `canonical_name` methods |
| 164 | No | Adds new `RollingRate<K, V>` type |
| 165 | No | Adds `LabelTable` + `*_with` variants on `FiveTupleKey` |
| 167 | No | Prelude additions only (re-exports); rustdoc + docs/discoverability.md additions |
| 168 | No | Adds new methods on `FlowStats` |

---

## §6 Phasing for 0.14

Suggested 4-PR series, smallest-blast-radius first:

| PR | Plans | Reason for ordering |
|---|---|---|
| 1 | **160 + 168** | Trivial additive methods on existing types. Low risk; fast review. |
| 2 | **162** (absorbs 166) | ICMP module hygiene + new enum. Unblocks netring's `IcmpError.kind`. |
| 3 | **161 + 163** | `FiveTupleKey::from_inner_canonical` is shared infrastructure; `app_label` consumes it. Ship together to keep the FiveTupleKey changes coherent. |
| 4 | **164 + 165 + 167** | The larger additions (`RollingRate`, `LabelTable`, prelude expansion + docs). All independent of each other; bundle for cycle close. |

Each PR is independently reviewable. PRs 1–3 are the P0
minimum-viable cycle (ship as 0.14.0-alpha). PR 4 closes the
cycle.

---

## §7 What stays out of 0.14

Echoing the wishlist's §12 + my own pass:

- **R1 (split `Protocol`)** — netring-side trait split.
  flowscope's `Driver<E>` shape already supports both modes.
- **R2 (drop `FlowPacket<P>` parameterization)** — netring-side.
- **R3 (`ReportSink` trait)** — netring-side.
- **R4 (eBPF-backed bandwidth)** — out of scope; possibly a
  `flowscope-ebpf` companion crate in a later cycle.
- **JA4+ family / IPFIX / HTTP/2 / QUIC** — same deferrals as
  the 0.12 / 0.13 cycles.

Plus my own additions:

- **`swap` / `SlotBuf<M, K>`** for `SlotHandle` — deferred from
  0.13 (plan 149); no consumer ask yet.
- **Datagram + heuristic broadcast variants** for
  `BroadcastSlotHandle` — deferred from 0.13 (plan 150); ship
  if a consumer asks.
- **`LabelTableOwned`** — defer until a consumer needs runtime
  strings.
- **`IcmpType::mtu_signal()` for `PacketTooBig`** — defer to 0.15
  if asked (wishlist Q2).
- **`RollingRate::with_capacity`** for bounded LRU — defer
  until a consumer hits the memory pressure.

---

## §8 References

- Source wishlist: retired after cycle release (durable record
  in `CHANGELOG.md` 0.14.0 entry).
- Per-plan files (160-168 base + 170-174 polish): retired
  after implementation shipped; commit-by-commit record in
  `git log` under subjects `plan NNN: …`.
- Verification source-anchors:
  `src/tracker.rs:690-810` (FlowTracker read API) ·
  `src/correlate/indexed.rs` (KeyIndexed evict_expired
  collect-then-pop pattern) ·
  `src/extract/five_tuple.rs:129-177` (canonicalisation
  logic, currently private) ·
  `src/extractor.rs:116-125` (`L4Proto::proto_str`) ·
  `src/icmp/types.rs:118-282` (ICMPv4/v6 DU codes,
  `IcmpInner`) ·
  `src/correlate/bucketed.rs:23-153` (`TimeBucketedCounter`
  reference shape for `RollingRate`) ·
  `src/well_known/mod.rs:53-175` (binary-search port label
  table) ·
  `src/event.rs:160-236` (`FlowStats` field layout +
  existing accessors) ·
  `src/prelude.rs:15-50` (current prelude content).
