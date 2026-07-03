# flowscope examples

Runnable examples organized into one directory per category.
Every example defaults to a fixture path under `tests/data/` or
`tests/fixtures/` when run with no arguments, so you can poke at
them without bringing your own pcap.

Run any of them with:

```bash
cargo run --features <FEATURES> --example <NAME> -- [optional pcap path]
```

Some examples open standard output for piping into other tools
(CSV / JSON / Zeek conn.log shapes); redirect with `>`.

The directory naming uses numeric prefixes (`00-`, `01-`, …) so
the categories sort logically in `ls`.

---

## 00 — getting started

[`examples/00-getting-started/`](./00-getting-started/)

| Example | Features | What it shows |
|---|---|---|
| **`hello_pipeline`** | `pcap,extractors,reassembler,session` | Shortest `flowscope::driver::Driver<E>` program — one builder chain, one slot drain. The recommended starting point. |
| **`unified_driver_demo`** | `pcap,http,dns` | Plan-121 typed `Driver<E>` showcase — port-routed HTTP + DNS slots plus a signature-based heuristic catch-all. Drain each parser slot independently. |
| **`broadcast_subscribers`** | `pcap,http` | `BroadcastSlotHandle` fan-out delivery (0.13, plan 150) — one HTTP parser, three subscribers (logger / metrics / alerter), each sees every message. Contrast with `SlotHandle::clone`'s competitive-consumer semantics. |
| **`from_stdin`** *(0.18)* | `pcap,http` | Read pcap bytes from `stdin` via `PcapFlowSource::from_reader` — the `tcpdump -w - \| ...` pipe-mode pattern. |

> *For sharded multi-thread capture, see [`examples/08-performance/sharded_capture.rs`](./08-performance/sharded_capture.rs). For a packet-walker tour over the `layers` module, see [`examples/09-low-level/inspect_packet.rs`](./09-low-level/inspect_packet.rs).*

## 01 — L7 message logging

[`examples/01-l7-logging/`](./01-l7-logging/)

| Example | Features | What it shows |
|---|---|---|
| **`http_log`** | `http,pcap` | One-line summary of every HTTP request + response (per-message). |
| **`http_exchanges`** | `http,pcap` | One log line per request/response PAIR via `HttpExchangeParser` (plan 107). Access-log-shaped rows with RTT and outcome. |
| **`tls_observer`** | `tls,pcap` | SNI / ALPN / cipher list for every TLS ClientHello + ServerHello. |
| **`quic_initial_observer`** *(0.18)* | `quic,pcap` | SNI / ALPN for every QUIC Initial packet (passive Initial decrypt). |
| **`encrypted_app_classify`** *(0.22)* | *(none)* | Identify h2/h3 + DoT/DoQ/DoH over an encrypted transport from ALPN / SNI / port via `app_proto::classify` (#138). |
| **`pcap_pulses`** | `tls,pcap` | Unified `session_pulses::<P>` stream — flow lifecycle **and** typed L7 messages from one loop, in wire order (#111). |
| **`dns_log`** | `dns,pcap` | Query / response pairs with RTT correlation via `Correlator`. |

## 02 — forensics / IoC extraction

[`examples/02-forensics/`](./02-forensics/)

| Example | Features | What it shows |
|---|---|---|
| **`extract_iocs`** *(0.18)* | `pcap,http,tls,tls-fingerprints,dns,extractors,tracker,smtp,ftp,smb,kerberos,ldap` | Dedup'd hostnames + JA3/JA4 + UAs + 0.18-cycle identity sources (SMTP envelope, FTP USERs, SMB NTLM tuple, Kerberos cnames, LDAP Bind DNs). IPs split into external vs internal buckets. |
| **`tls_inventory`** *(0.18)* | `tls,tls-fingerprints,pcap` | Aggregated TLS handshake catalog via `TlsHandshakeParser` — versions, ECH outcomes, cert chains, JA4X (gated on `ja4plus`), AlertDescription codes. |
| **`kerberoast_hunter`** *(0.18)* | `pcap,kerberos` | Detect TGS-REQ for RC4-HMAC service tickets (T1558.003) via `KerberosMessage::kerberoast_suspect`. |
| **`ldap_recon_hunter`** *(0.18)* | `pcap,ldap` | BloodHound / GetUserSPNs enumeration (T1087.002) — flags LDAP searches for `servicePrincipalName` + Simple binds with cleartext credentials. |
| **`asset_inventory`** *(0.18)* | `pcap,asset,arp` | Build a MAC-keyed `flowscope::asset::Inventory` from ARP traffic. |
| **`client_fingerprint_catalog`** *(0.18)* | `pcap,tls,tls-fingerprints,http,ssh,extractors,tracker` | Per-source-IP join of JA3 / JA4 / JA4H (gated on `ja4plus`) / HASSH / HTTP User-Agent — the cross-protocol client identity catalog. |
| **`arp_spoof_detector`** *(0.18)* | `arp,pcap` | Flag ARP-cache-poisoning patterns via IP→MAC binding changes (`NeighborTable`). |
| **`smb_lateral_movement`** *(0.18)* | `smb,pcap` | SMB2/3 lateral-movement signals — tree connects, NTLM identity tuples, DCE-RPC binds. |
| **`smtp_credentials`** *(0.18)* | `smtp,pcap` | SMTP cleartext AUTH credential + named-exfil (MAIL FROM / RCPT TO) detector. |

## 03 — security / detection

[`examples/03-detection/`](./03-detection/)

| Example | Features | What it shows |
|---|---|---|
| **`port_scan_detector`** | `pcap,extractors,tracker` | SYN-without-ACK rate per `(src, dst)` via `TimeBucketedCounter` + distinct-port set via `TimeBucketedSet` (plan 102 sub-A). |
| **`dns_tunnel_detector`** | `pcap,dns,extractors,tracker,emit-eve` | The `DnsTunnelDetector` distinct-subdomain heuristic (#132) driven through a `DetectorRegistry`, emitting T1071.004 EVE anomalies. |
| **`failed_auth_burst`** | `pcap,http` | HTTP 401/403 burst followed by 200 — credential-stuffing pattern via `BurstDetector` (plan 102 sub-A). |
| **`c2_beacon_finder`** | `pcap,extractors,tracker` | RITA-style CV beacon detector via `flowscope::detect::patterns::BeaconDetector` (plan 143). |
| **`dga_finder`** | `pcap,dns,extractors` | Bigram log-likelihood DGA scoring on DNS query SLDs via `flowscope::detect::patterns::DgaScorer` (plan 143). |
| **`composite_c2`** | `pcap,extractors,tracker,dns,tls,emit-eve` | Composite AND of `BeaconDetector` ∧ `DgaScorer` ∧ weak-TLS-version per source IP; ≥2-of-3 legs → Suricata EVE anomaly via `write_owned_anomaly`. |
| **`detector_registry`** | `tracker,dns,pcap,emit-eve` | The unified `DetectorRegistry` (#131): register beacon / RITA-beacon / port-scan / DGA once, drive them all from one `Event` stream over a real `Driver`, emit each anomaly (with its MITRE ATT&CK technique) as EVE. |
| **`tcp_evasion_detector`** | `pcap,extractors,tracker,reassembler` | Ptacek-Newsham TCP overlap IOC via `AnomalyKind::TcpRexmitInconsistency` surfaced by `FlowDriver::with_emit_anomalies(true)`. |
| **`flow_analysis`** | `analysis,tls,dns,emit-eve` | The `analysis` composition layer: `FlowAnalyzer` accumulates per-flow `L7Summary`, `finalize` computes `FlowRisk` + screens an `IocSet`, yielding enriched `AnalyzedFlow` records printed as a table and as SIEM-ready EVE JSON (`write_analyzed_flow`). Synthetic flows; no pcap (#83). |
| **`flow_analysis_driver`** | `analysis,tls,dns,pcap,emit-eve` | The same `FlowAnalyzer` wired to a real typed `Driver<E>` over a pcap: drain `TlsHandshakeParser`/`DnsUdpParser` slots into the analyzer, `finalize` on `Event::Ended` → enriched EVE (#83). |

## 04 — observability / SRE

[`examples/04-observability/`](./04-observability/)

| Example | Features | What it shows |
|---|---|---|
| **`top_talkers`** | `pcap,extractors,tracker` | Top-N source IPs by bytes and packets (HashMap-of-everything). |
| **`top_talkers_topk`** | `pcap,extractors,tracker` | Same shape but bounded-memory via `TopK` (Misra-Gries) — exact for the top, approximate for the long tail (plan 102 sub-A). |
| **`http_error_rate`** | `pcap,http` | Per-host 1xx/2xx/3xx/4xx/5xx counts and error-rate ranking. |
| **`flow_duration_histogram`** | `pcap,aggregate` | Distribution of flow durations with p50 / p99 / max via `Histogram` (plan 102 sub-B). |
| **`conversation_timeline`** | `pcap,extractors,reassembler` | Timeline of a single TCP conversation — every state transition, every direction-marked packet. |
| **`bandwidth_by_app`** *(0.14)* | `pcap,extractors,tracker` | Per-app bytes/sec via `RollingRate` + `top_k` (plan 171), keyed by `FiveTupleKey::app_label_with(&LabelTable)` (plan 165). |
| **`bandwidth_by_owner`** *(0.22)* | `tracker` | Per-owner (PID/cgroup) tx/rx byte-rate via `BandwidthByKey<Attribution>` + `ByteSemantics` (#141) — bandwidth grouped by an opaque consumer-supplied owner key. |
| **`icmp_explained_drops`** *(0.14)* | `pcap,icmp,extractors,tracker` | Join every ICMP error back to a live flow via `FlowTracker::lookup_inner` (plan 161); classify v4/v6 unreachable + MTU events via `DestUnreachableKind` (plan 162) + `MtuSignalKind` (plan 170). |
| **`direction_skew_anomaly`** *(0.14)* | `pcap,extractors,tracker` | One-sided-flow detection via `FlowStats::direction_skew` (plan 168) + per-side `bytes_for` / `throughput_bps_for` (plans 168 + 173). |
| **`tap_merge_orientation`** *(0.20)* | `extractors,tracker,test-helpers` | The three direction axes (#118–#122): deterministic `Orientation` vs arrival-order `FlowSide` under a tap-merge race, per-direction capture-leg binding (`source_idx_for`), and SYN-based initiator inference (`infer_tcp_initiator` + `direction_flipped`). Synthetic frames; no pcap. |
| **`ml_features_pipeline`** *(0.18)* | `pcap,ml-features,serde` | Full CICFlowMeter feature-vector export — one `CicFlowFeatures` row per finalized flow. |
| **`tcp_retransmit_audit`** | `pcap,extractors,reassembler` | Per-flow retransmit-rate ranking. Production reliability signal. |

## 05 — data export

[`examples/05-export/`](./05-export/)

| Example | Features | Output |
|---|---|---|
| **`flow_csv_export`** | `pcap,emit` | `flows.csv` via `FlowEventCsvWriter` (RFC-4180 quoted; plan 101). |
| **`flow_json_export`** | `pcap,emit-ndjson` | NDJSON via `FlowEventNdjsonWriter` — drop-in for Elasticsearch / Loki / ClickHouse. |
| **`zeek_style_conn_log`** | `pcap,emit` | Tab-separated Zeek `conn.log` via `ZeekConnLogWriter` (with `#fields` / `#types` / `#close` headers + UID generation). |
| **`eve_writer`** | `pcap,emit-eve` | Suricata EVE JSON via `EveJsonWriter` (0.12) — drop-in for Filebeat / Splunk Suricata TA / Tenzir / ECS pipelines. With `community-id`, every record carries the portable cross-tool `community_id`. |
| **`detector_to_eve`** | `pcap,extractors,tracker,emit-eve` | Plan-147 single-detector → SIEM pipeline: `PortScanDetector` scores route through `EveJsonWriter::write_owned_anomaly`. |
| **`prometheus_exporter`** | `pcap,extractors,tracker,reassembler,metrics` | Render the `metrics` feature's counters / gauges / summaries as Prometheus text-exposition. Doc-comment shows the canonical production wiring via `metrics-exporter-prometheus`. |
| **`ipfix_wire_export`** | `pcap,extractors,tracker,ipfix-export` | Build RFC 7011 IPFIX Messages via `flowscope::ipfix::wire::MessageBuilder` + default IPv4/IPv6 templates. Pure-bytes (no UDP / SCTP I/O). |
| **`ipfix_udp_collector`** *(0.18)* | `pcap,extractors,tracker,ipfix-export` | Wraps `ipfix_wire_export` in a `std::net::UdpSocket` send loop targeting IANA port 4739; re-emits the template set every 64 Data records. |
| **`tracing_subscriber`** *(0.18)* | `pcap,extractors,tracker,reassembler,tracing` | First example for the `tracing` Cargo feature — wires `tracing_subscriber::fmt` + `EnvFilter` so `flowscope.flow` / `.anomaly` / `.tracker` events fire to stderr. |
| **`nprint_export`** *(0.18)* | `pcap,extractors,tracker,ml-features-nprint` | Materialise per-flow `NPrintMatrix` ternary-bit rows into CSV files (loadable by `numpy.loadtxt` / `pandas.read_csv`). |
| **`ml_features_libsvm`** *(0.18)* | `pcap,extractors,tracker,ml-features` | libsvm / svmlight sibling of `ml_features_pipeline.rs` — one row per finalized flow, loadable by `sklearn.datasets.load_svmlight_file`. |
| **`pcap_dir_tail`** *(0.18)* | `pcap,extractors,tracker,reassembler,emit-eve` | Poll a directory for rotating pcap fragments (tcpdump `-G` / dumpcap `-b`) — process each through `FlowDriver` + EVE writer, move to `processed/`. |

## 06 — custom protocols

[`examples/06-custom-protocols/`](./06-custom-protocols/)

| Example | Features | What it shows |
|---|---|---|
| **`accumulating_line_parser`** | `pcap,extractors,session` | Helper-based: one constructor call (`AccumulatingSessionParser`, plan 106) replaces a 25-LoC manual `SessionParser` impl. **Start here.** |
| **`length_prefixed_pcap`** | `pcap,session` | Hand-written `SessionParser`: a custom binary protocol (`PFX2,`/`PFX4,` length-prefixed) driven through a typed `Driver<E>` session slot. |
| **`redis_protocol`** | `pcap,extractors,reassembler` | RESP protocol parser as `SessionParser`. Demonstrates the splitting-invariance contract and a real recursive parser. |

## 07 — multi-protocol pipelines

[`examples/07-multi-protocol/`](./07-multi-protocol/)

| Example | Features | What it shows |
|---|---|---|
| **`multi_parser_pipeline`** | `pcap,extractors,reassembler,session` | Multiple session parsers under one `Driver<E>` — each registration call returns its own typed slot handle. |
| **`multi_protocol_monitor`** | `l7,pcap` | Real-world HTTP + TLS + DNS + ICMP on one pcap walk, with one `Driver<E>`. |

## 08 — performance

[`examples/08-performance/`](./08-performance/)

| Example | Features | What it shows |
|---|---|---|
| **`layer_fast_path`** | `pcap,extractors` | Wall-clock comparison of `Layers::parse_ethernet` (ergonomic, per-frame alloc) vs `LayerParser` + `LayerStack` (zero-allocation fast path). Run with `--release` to see the real numbers. |
| **`threaded_slot_drain`** | `pcap,http` | Cross-thread slot drain — `SlotHandle: Send + Sync` since 0.12, `Driver<E>` `Send + Sync` since 0.13. Worker thread drains an HTTP slot while the capture loop runs on main. |
| **`sharded_capture`** | `pcap,http` | N-thread sharded driver pattern with cross-shard aggregation via `AtomicU64` counters (0.13, plan 155). Built on `Driver<E>: Send + Sync` — each shard owns its own dispatcher. See [`docs/sharded.md`](../docs/sharded.md) for the recipe. |
| **`allocations_per_packet`** *(0.18)* | `pcap,extractors,tracker` | Counting global allocator wrapping `System` — warms up a bare driver, then measures steady-state allocs/packet to verify the zero-allocation claim. Run `--release`. |

## 09 — reassembly / low-level

[`examples/09-low-level/`](./09-low-level/)

| Example | Features | What it shows |
|---|---|---|
| **`pcap_flow_summary`** | `pcap` | Minimal flow accounting via `FlowTracker` directly. |
| **`pcap_flow_keys`** | `pcap` | Just print flow keys as packets arrive. |
| **`pcap_buffered_reassembly`** | `pcap,reassembler` | Configure a `BufferedReassembler` with caps + overflow policy. |
| **`inspect_packet`** | `pcap,extractors` | Packet-walker tour over `flowscope::layers` — dump every L2 / L3 / L4 / tunnel slice via the dynamic walk. Reference for the layers module. |
| **`overflow_policy`** *(0.18)* | `pcap,extractors,tracker,reassembler` | Side-by-side comparison of `OverflowPolicy::{SlidingWindow,DropFlow}` + cross-flow `MemcapPolicy::DropFlow` (issues #17 / #26). |

## utilities — fixture generators

[`examples/utilities/`](./utilities/)

These are internal tools the test suite uses to regenerate the
synthetic pcaps under `tests/data/`. They're shipped as examples
so the generation logic stays close to the fixtures.

| Example | Purpose |
|---|---|
| `gen_fixtures` | Regenerate the bundled test pcaps (HTTP, DNS, mixed). |
| `gen_length_prefixed_pcap` | Regenerate `tests/fixtures/length_prefixed/sample.pcap`. |

---

## Notes

- All examples use the `flowscope::prelude` re-exports where
  helpful — `use flowscope::prelude::*;` is the conventional
  starting line.
- Outputs are deliberately plain text (no fancy formatting deps)
  so the examples stay portable and consumable in scripts.
- Anything emitting structured data writes to stdout —
  redirect with `> output.{csv,ndjson,log}`.
- The typed `flowscope::driver::Driver<E>` + `SlotHandle<M, K>`
  surface is the canonical shape for both single- and multi-parser
  pipelines; the
  [`00-getting-started/unified_driver_demo.rs`](./00-getting-started/unified_driver_demo.rs)
  example showcases it. Register one session/datagram slot per
  protocol. The per-parser `FlowSessionDriver` / `FlowDatagramDriver`
  types were removed in 0.20 (#99); the legacy closed-`M`
  `Driver<E, M>` and `FlowMultiSessionDriver` types were removed in
  plan 121 (0.11.0).
- For the highest-level common-case demos (TLS / QUIC / SMB
  ClientHello extraction), reach for the per-parser
  `*_from_pcap` helpers (`flowscope::tls::client_hellos_from_pcap`,
  `flowscope::quic::initials_from_pcap`,
  `flowscope::smb::messages_from_pcap`) — they wrap the whole
  pcap → tracker → parser pipeline into a single
  `impl Iterator<Item = (FiveTupleKey, Message)>` call.
