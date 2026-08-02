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
| [`BandwidthByKey<K>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.BandwidthByKey.html) | Per-owner **tx/rx** byte-rate over a window — bandwidth grouped by an opaque owner key (PID / cgroup / `Attribution`). `tx_bps` / `rx_bps` / `top_k`, `ByteSemantics` (wire vs goodput) tag. **0.22, #141.** |
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
| [`EwmaVar<K>`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.EwmaVar.html) | Per-key EWMA mean **and** variance → `zscore` N-sigma outlier baselines. Zero-variance warmup never alarms. **0.21, #134.** |
| [`Cusum`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.Cusum.html) / [`PageHinkley`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.PageHinkley.html) | Sequential change-point — "has the *mean* shifted", not "is this sample far out". Two-sided, reset-on-alarm. Page-Hinkley needs no target mean. **0.21, #134.** |

## "I want percentiles / quantiles"

| Primitive | Pitch |
|---|---|
| [`DdSketch`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.DdSketch.html) | Relative-error quantiles (p50/p95/p99) over a positive-valued stream; log-spaced bins, bounded memory, `Mergeable` for RSS-sharded union. No extra deps. **0.21, #134.** |
| [`WindowedQuantiles`](https://docs.rs/flowscope/latest/flowscope/correlate/struct.WindowedQuantiles.html) | Sliding-window quantiles ("p99 latency over the last 60 s") — rotates `DdSketch`es through time buckets. **0.21, #134.** |
| [`aggregate::Percentile`](https://docs.rs/flowscope/latest/flowscope/aggregate/struct.Percentile.html) | Whole-stream t-digest (behind the `aggregate` feature) — use when you want one lifetime distribution, not windowed/sharded. |

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
| `FlowStats::initiator_orientation` | Canonical `Orientation` of the flow's initiator — the deterministic axis. (0.20, #118.) |
| `FlowStats::side_for(orientation)` / `orientation_for(side)` | Translate between the role axis (`FlowSide`) and canonical axis (`Orientation`). (0.20, #118.) |
| `FlowStats::source_idx_for(orientation)` / `capture_leg_inconsistent` | Physical capture leg (NIC) bound per direction on a merged flow + tap-miswire IOC. (0.20, #120.) |
| `FlowTrackerConfig::infer_tcp_initiator` + `FlowStats::direction_flipped` | SYN-based initiator inference: keep `FlowSide` correct under a tap-merge race. (0.20, #122.) |

## "I want a stable per-direction label across sensors"

`FlowSide` (`Initiator`/`Responder`) is arrival-order-relative — a
tap-merge race can flip it. `Orientation` (`Forward`/`Reverse`,
address-sorted) is deterministic. Every `Started`/`Packet` event
carries **both**. Reach for `orientation` when two captures/runs must
agree (Community ID, biflow keys, dedup); reach for `side` for
"who started it". Full model: `docs/concepts.md` →
"Direction, orientation, and capture leg".

| Primitive | Pitch |
|---|---|
| `FlowEvent::Packet { orientation, .. }` | Deterministic canonical direction per packet. (0.20, #118.) |
| [`Orientation`](https://docs.rs/flowscope/latest/flowscope/enum.Orientation.html) | `Forward`/`Reverse` + `flipped()` / `as_str()`. |

## "I want to emit structured anomalies"

| Primitive | Pitch |
|---|---|
| [`OwnedAnomaly`](https://docs.rs/flowscope/latest/flowscope/struct.OwnedAnomaly.html) | Canonical owned anomaly value. `SmallVec` observations + metrics. (0.13, plan 147.) |
| [`DetectorScore`](https://docs.rs/flowscope/latest/flowscope/trait.DetectorScore.html) | `name()` + `into_anomaly(ts)`. Every shipped score impls it. |
| `EveJsonWriter::write_owned_anomaly` | One-call Suricata EVE emission. |
| `FlowEventNdjsonWriter::write_owned_anomaly` | NDJSON variant for ES / Loki / ClickHouse. |

## "I want to identify the app over an encrypted transport"

| Primitive | Pitch |
|---|---|
| [`app_proto::classify`](https://docs.rs/flowscope/latest/flowscope/app_proto/fn.classify.html) | ALPN + SNI + port → [`AppProtocol`](https://docs.rs/flowscope/latest/flowscope/app_proto/enum.AppProtocol.html) — h2 / h3 / DoT / DoQ / DoH, no decryption. **0.22, #138.** |
| [`app_proto::is_known_doh_host`](https://docs.rs/flowscope/latest/flowscope/app_proto/fn.is_known_doh_host.html) | Curated public-resolver SNI list — the only passive tell that HTTPS is actually DoH. **0.22, #138.** |
| `AppProtocol::from_tls_handshake` / `from_quic_initial` | Classify straight from a parsed `TlsHandshake` / `QuicInitial`. **0.22, #138.** |
| [`tls::is_pq_hybrid_group`](https://docs.rs/flowscope/latest/flowscope/tls/fn.is_pq_hybrid_group.html) / `pq_hybrid_group_name` | Recognise post-quantum hybrid key-exchange groups (X25519MLKEM768…). `TlsClientHello.pq_key_share` / `key_share_groups` carry the signal. **0.22, #135.** |

## "I want to defeat fragmentation evasion"

| Primitive | Pitch |
|---|---|
| [`ip_fragment::IpFragmentReassembler`](https://docs.rs/flowscope/latest/flowscope/ip_fragment/struct.IpFragmentReassembler.html) | Reassemble a fragmented IP datagram (RFC 791 key) so a split payload can't slip past an L4/L7 parser. `push` / `push_ipv4`; **overlapping fragments drop the datagram** (RFC 5722) + `overlaps()` IOC. **0.22, #138.** |

## "I want an asset inventory keyed by MAC"

| Primitive | Pitch |
|---|---|
| [`Inventory`](https://docs.rs/flowscope/latest/flowscope/struct.Inventory.html) / [`Asset`](https://docs.rs/flowscope/latest/flowscope/struct.Asset.html) | LRU `Asset` records keyed by MAC (behind `asset`). Fed by `from_arp` / `from_dhcp` / `from_lldp` / `from_mdns` / … |
| `Asset::from_tls_handshake` / `from_ssh_kexinit` / `from_tcp_fingerprint` | Correlate JA3 / JA4 / JA4X / HASSH / p0f — and x509 subject / SAN — into the same MAC record. **0.22, #137.** |
| `Asset::role()` / `source_count()` / `first_seen` | Derived device [`AssetRole`](https://docs.rs/flowscope/latest/flowscope/enum.AssetRole.html), confidence, and age. **0.22, #137.** |

## "I want TLS / HTTP / SSH fingerprints"

| Primitive | Pitch |
|---|---|
| [`flowscope::fingerprint`](https://docs.rs/flowscope/latest/flowscope/fingerprint/index.html) | One import site for the whole JA4+ family, grouped by license (royalty-free `tls-fingerprints` vs FoxIO `ja4plus`). **0.22, #136.** |
| `tls::ja3_fingerprint` / `ja3_canonical` | Standalone JA3 from a parsed `TlsClientHello`. **0.22, #136.** |

## "I want to route a connection before I've seen the body"

The inline path. Everything here is sans-IO: you own the sockets, and
the parser tells you where messages begin and end.

| Want | Reach for |
|---|---|
| decide what protocol this is, from the first bytes | [`classify_first_bytes`](https://docs.rs/flowscope/latest/flowscope/classify/fn.classify_first_bytes.html) → `Classify::Decided(WireProtocol)` / `NeedMore` |
| route an HTTP request on its head, before the body | `http::HttpProxyParser` → `HttpEvent::RequestHead` → `RequestHead::authority()` |
| the same, keyed by stream, over HTTP/2 | `http2::Http2Parser` → `Http2Event::Head` → `StreamHead::authority()` / `path()` |
| dispatch a gRPC call, and get its *real* outcome | `http2::grpc_call` → `GrpcCall`; `http2::grpc_status` / `grpc_status_of` → `GrpcStatus` |
| route TLS by SNI / ALPN, degrading safely under ECH | `TlsHandshake::routing_sni()` / `routing_alpn()`, and [`tls-routing.md`](tls-routing.md) |
| let flowscope drive the bytes instead | `http::HttpProxySession` on the typed `Driver` |

Not the same as `app_proto::classify`: that answers "what is this"
from a *negotiated handshake* (ALPN / SNI / port), after TLS or QUIC
has been parsed. `classify::classify_first_bytes` answers it from the
first cleartext bytes, before anything has been parsed at all.

## "I want an access log, or to know why a connection was refused"

| Want | Reach for |
|---|---|
| one record per HTTP exchange, without retaining bodies | `http::HttpAccessLog` → `HttpAccessRecord` |
| tell apart completed / unanswered / tunnelled / refused | `HttpAccessOutcome` |
| the specific framing rule a refusal broke | `http::HttpPoison` (and its `as_str()` slug, which is also the metric label) |
| write it where a SIEM already looks | `EveJsonWriter::write_http_access` → `event_type: "http"` |
| count it | `flowscope_http_messages_total{direction}`, `flowscope_http_poisoned_total{reason}` |

## Prelude manifest

`use flowscope::prelude::*;` brings the following into scope
(behind their respective feature gates):

**Always available:**
`AnomalyFields`, `AsPacketView`, `Error`, `ErrorCode`, `ErrorKind`,
`KeyFields`, `Module`, `PacketView`, `Result`, `Timestamp`,
`AppProtocol` *(0.22)*, `AppTransport` *(0.22)*, `FragmentKey`
*(0.22)*, `IpFragmentReassembler` *(0.22)*, `Classify` *(0.23)*,
`WireProtocol` *(0.23)*, `classify_first_bytes` *(0.23)*.

**`extractors`:** `FiveTuple`, `Extracted`, `FlowExtractor`, `L4Proto`,
`Orientation`, `TcpFlags`, `TcpInfo`, `Layer`, `LayerKind`,
`LayerParser`, `LayerStack`, `Layers`, `LabelTable` *(0.14)*.

**`tracker`:** `AnomalyKind`, `EndReason`, `FlowEvent`, `FlowSide`,
`FlowStats`, `FlowTracker`, `FlowTrackerConfig`,
`TimeBucketedCounter`, `TimeBucketedSet`, `KeyIndexed`,
`BurstDetector`, `Ewma`, `TopK`, `RollingRate` *(0.14)*,
`BandwidthByKey` *(0.22)*, `ByteSemantics` *(0.22)*, `Attribution`
*(0.22)*.

**`tracker` + `extractors`:** `FlowStateMap`.

**`session`:** `DatagramParser`, `SessionParser`.

**`extractors` + `reassembler` + `session`:** `Driver`,
`DriverBuilder`, `Event`, `SlotHandle`, `SlotMessage`. (Register one
session/datagram slot per protocol; this replaced the per-parser
`FlowSessionDriver` / `FlowDatagramDriver` in 0.20.)

**`http2`:** `Http2Event` *(0.23)*, `Http2Parser` *(0.23)*,
`StreamHead` *(0.23)*.

> The HTTP/1 streaming types (`HttpProxyParser`, `HttpEvent`,
> `RequestHead`, …) are deliberately **not** in the prelude: they
> share names with the passive `http` types a monitor already
> imports, and silently pulling both into scope would make which one
> you got depend on import order. Import them explicitly from
> `flowscope::http`.

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
