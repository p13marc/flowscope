# Discoverability — find the right primitive in 5 minutes

flowscope ships a lot of small composable types. This page is
the directory: grouped by use case, one-line pitches, links to
the rustdoc.

For the conceptual layer-by-layer reference, see
[`concepts.md`](concepts.md). For worked patterns, see
[`recipes.md`](recipes.md).

> **Prelude shortcut**: `use flowscope::prelude::*;` brings
> every primitive on this page into scope. New in 0.14
> (plan 167); see the end of this page for the full prelude
> manifest.

## "I want to count things per key over time"

| Primitive | Pitch |
|---|---|
| [`TimeBucketedCounter<K>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.TimeBucketedCounter.html) | Bumps `+= 1` per call; window + bucket-width split. Pre-built for rate-based anomaly thresholds. |
| [`RollingRate<K, V>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.RollingRate.html) | Generic `V` increments (bytes/sec, custom units); `rate()` returns `f64` per-second. Bucket-reuse zero-alloc. **0.14, plan 164.** |
| [`Ewma<K>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.Ewma.html) | Exponential moving average — smoothed view for latency / throughput dashboards. |

## "I want to track unique things per key over time"

| Primitive | Pitch |
|---|---|
| [`TimeBucketedSet<K, V>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.TimeBucketedSet.html) | Distinct values seen per key in a window. Powers lateral-movement detection. |
| [`KeyIndexed<K, V>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.KeyIndexed.html) | TTL'd LRU lookup index — DNS query/response correlation, ICMP error tying, generic request/response matching. `drain_expired` for inspection (0.14). |

## "I want to detect anomalies / patterns"

| Primitive | Pitch |
|---|---|
| [`BurstDetector<K, E>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.BurstDetector.html) | Spike vs baseline detection — credential stuffing, scrape storms. |
| [`SequencePattern`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.SequencePattern.html) | Typed-event FSM ("auth failure → auth failure → success"). |
| [`detect::patterns::PortScanDetector<K>`](https://docs.rs/flowscope/latest/flowscope/detect/patterns/struct.PortScanDetector.html) | Threshold Random Walk (Jung 2004) — port-scan classification. |
| [`detect::patterns::BeaconDetector<K>`](https://docs.rs/flowscope/latest/flowscope/detect/patterns/struct.BeaconDetector.html) | CV-composite RITA-style beacon score. |
| [`detect::patterns::DgaScorer`](https://docs.rs/flowscope/latest/flowscope/detect/patterns/struct.DgaScorer.html) | Bigram log-likelihood with embedded English baseline. |
| [`detect::signatures::*`](https://docs.rs/flowscope/latest/flowscope/detect/signatures/index.html) | 10 magic-byte recognizers + registry. |

## "I want top-N reports"

| Primitive | Pitch |
|---|---|
| [`TopK<K>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.TopK.html) | Misra-Gries — exact for the top, approximate for the long tail. Bounded memory. |
| `RollingRate::snapshot` | `(key, rate)` iterator — feed into `TopK` for the report. |

## "I want per-flow state"

| Primitive | Pitch |
|---|---|
| [`FlowStateMap<T>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.FlowStateMap.html) | Auto-evict on `FlowEvent::Ended`; TTL sweep. Default `K = FiveTupleKey`. (0.13, plan 154.) |
| [`KeyIndexed<K, T>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.KeyIndexed.html) | Manual TTL semantics; more flexible if you don't want auto-evict. |

## "I want to react to ICMP errors"

| Primitive | Pitch |
|---|---|
| [`IcmpType::is_error`](https://docs.rs/flowscope/latest/flowscope/icmp/enum.IcmpType.html#method.is_error) | Gate before unpacking. |
| [`IcmpType::error_inner`](https://docs.rs/flowscope/latest/flowscope/icmp/enum.IcmpType.html#method.error_inner) | Returns `(short_label, &IcmpInner)` for the embedded original 5-tuple. |
| [`IcmpType::dest_unreachable_kind`](https://docs.rs/flowscope/latest/flowscope/icmp/enum.IcmpType.html#method.dest_unreachable_kind) | Unified v4/v6 → `Option<DestUnreachableKind>` classification. (0.14, plan 162.) |
| [`IcmpType::short_kind`](https://docs.rs/flowscope/latest/flowscope/icmp/enum.IcmpType.html#method.short_kind) | Stable metric-label slug for the outer type. |
| [`FiveTupleKey::from_inner_canonical`](https://docs.rs/flowscope/latest/flowscope/extract/struct.FiveTupleKey.html#method.from_inner_canonical) | Build a canonical key from `IcmpInner` for tracker lookup. (0.14, plan 161.) |
| [`FlowTracker::lookup_inner`](https://docs.rs/flowscope/latest/flowscope/tracker/struct.FlowTracker.html#method.lookup_inner) | Join an ICMP error back to a live flow with one call. (0.14, plan 161.) |
| [`FlowTracker::stats_for_inner`](https://docs.rs/flowscope/latest/flowscope/tracker/struct.FlowTracker.html#method.stats_for_inner) | Same, but returns the `FlowStats` snapshot too. |

## "I want labels for metrics / reports"

| Primitive | Pitch |
|---|---|
| [`FiveTupleKey::protocol_label`](https://docs.rs/flowscope/latest/flowscope/extract/struct.FiveTupleKey.html#method.protocol_label) | Well-known L7 label (`"http"`, `"dns"`, …). `Option`-returning. |
| [`FiveTupleKey::app_label`](https://docs.rs/flowscope/latest/flowscope/extract/struct.FiveTupleKey.html#method.app_label) | Always-Some — falls back to the L4 canonical name. (0.14, plan 163.) |
| [`L4Proto::canonical_name`](https://docs.rs/flowscope/latest/flowscope/extractor/enum.L4Proto.html#method.canonical_name) | Lowercase always-Some slug (`"tcp"`, `"udp"`, …). For metric labels. (0.14, plan 163.) |
| [`KeyFields::proto_str`](https://docs.rs/flowscope/latest/flowscope/trait.KeyFields.html#method.proto_str) | Uppercase Suricata/EVE schema slug (`"TCP"`). Option-returning. |
| [`well_known::LabelTable`](https://docs.rs/flowscope/latest/flowscope/well_known/struct.LabelTable.html) | Site-custom port overrides. `Send + Sync`. (0.14, plan 165.) |
| [`well_known::protocol_label`](https://docs.rs/flowscope/latest/flowscope/well_known/fn.protocol_label.html) | Free function; binary-search over the built-in ~80-entry table. |
| [`FiveTupleKey::protocol_label_with`](https://docs.rs/flowscope/latest/flowscope/extract/struct.FiveTupleKey.html#method.protocol_label_with) / `app_label_with` | LabelTable-aware variants. (0.14, plan 165.) |

## "I want flow stats summaries"

| Primitive | Pitch |
|---|---|
| `FlowStats::total_bytes` / `total_packets` / `total_retransmits` | Two-field sums. |
| `FlowStats::retransmit_rate` | Fraction of total packets. |
| `FlowStats::duration` / `duration_secs` | `last_seen - started`. |
| `FlowStats::bytes_for(side)` / `pkts_for(side)` / `mean_pkt_size_for(side)` | Per-`FlowSide` accessors. (0.14, plan 168.) |
| `FlowStats::direction_skew` | `(init - resp) / total`. `[-1, 1]`. (0.14, plan 168.) |

## "I want to emit structured anomalies"

| Primitive | Pitch |
|---|---|
| [`OwnedAnomaly`](https://docs.rs/flowscope/latest/flowscope/struct.OwnedAnomaly.html) | Canonical owned anomaly value. `SmallVec` observations + metrics. (0.13, plan 147.) |
| [`DetectorScore`](https://docs.rs/flowscope/latest/flowscope/trait.DetectorScore.html) | `name()` + `into_anomaly(ts)`. Every shipped score impls it. |
| `EveJsonWriter::write_owned_anomaly` | One-call Suricata EVE emission. |
| `FlowEventNdjsonWriter::write_owned_anomaly` | NDJSON variant for ES / Loki / ClickHouse. |

## Prelude manifest (0.14)

`use flowscope::prelude::*;` brings the following into scope
(behind their respective feature gates):

**Always available:**
`AnomalyFields`, `AsPacketView`, `Error`, `ErrorCode`, `ErrorKind`,
`KeyFields`, `Module`, `PacketView`, `Result`, `Timestamp`.

**`extractors`:** `FiveTuple`, `Extracted`, `FlowExtractor`, `L4Proto`,
`Orientation`, `TcpFlags`, `TcpInfo`, `Layer`, `LayerKind`,
`LayerParser`, `LayerStack`, `Layers`, `LabelTable` *(0.14)*.

**`tracker`:** `AnomalyKind`, `EndReason`, `FlowEvent`, `FlowSide`,
`FlowStats`, `FlowTracker`, `FlowTrackerConfig`,
`TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`,
`BurstDetector`, `Ewma`, `TopK`, `RollingRate` *(0.14)*.

**`tracker` + `extractors`:** `FlowStateMap`.

**`session`:** `DatagramParser`, `SessionEvent`, `SessionParser`.

**`extractors` + `reassembler` + `session`:** `Driver`,
`DriverBuilder`, `Event`, `SlotHandle`, `SlotMessage`. (Register one
session/datagram slot per protocol; this replaced the per-parser
`FlowSessionDriver` / `FlowDatagramDriver` in 0.20.)

**`pcap`:** `PcapFlowSource`.

**`icmp`:** `DestUnreachableKind` *(0.14)*, `IcmpInner` *(0.14)*,
`IcmpMessage` *(0.14)*, `IcmpType` *(0.14)*, `MtuSignalKind`
*(0.14)*.

## Worked examples

Three runnable examples under `examples/04-observability/`
demonstrate the 0.14 surface end-to-end. Run any of them
against the bundled `tests/data/mixed_short.pcap` fixture (or
pass your own pcap path).

| Example | Demonstrates | Primary 0.14 APIs |
|---------|--------------|-------------------|
| `bandwidth_by_app` | Per-app bytes/sec with top-N report | `RollingRate`, `RollingRate::top_k`, `LabelTable`, `FiveTupleKey::app_label_with` |
| `icmp_explained_drops` | Join ICMP errors back to live flows + classify v4/v6 unreachable + MTU events | `FlowTracker::lookup_inner` / `stats_for_inner`, `DestUnreachableKind`, `MtuSignalKind` |
| `direction_skew_anomaly` | One-sided flow detection at end-of-life | `FlowStats::direction_skew`, `bytes_for`, `throughput_bps_for` |

```bash
cargo run --features pcap,extractors,tracker --example bandwidth_by_app
cargo run --features pcap,icmp,extractors,tracker --example icmp_explained_drops
cargo run --features pcap,extractors,tracker --example direction_skew_anomaly
```

## Convention notes

- **Always-Some vs `Option`**: when both exist (e.g.
  `app_label` vs `protocol_label`, `canonical_name` vs
  `proto_str`), the `Option`-returning one is the strict
  schema variant; the always-Some one has an explicit L4
  fallback. Use the always-Some one for metric labels.
- **Uppercase vs lowercase slugs**: uppercase
  (`"TCP"` / `"UDP"`) is the Suricata/EVE schema convention.
  Lowercase is the metric-label / snake_case convention. The
  two methods on `L4Proto` (`proto_str` and `canonical_name`)
  cover both.
- **`new_unbounded` vs `new`**: every `correlate::*` primitive
  with a capacity parameter ships both. Use `new_unbounded`
  unless you have memory-pressure constraints; the bounded
  variant adds extra arithmetic.
