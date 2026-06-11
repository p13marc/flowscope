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
| **`inspect_packet`** | `pcap,extractors` | Dump a layered view of every packet: L2 / L3 / L4 / tunnel headers via the dynamic walk on `flowscope::layers`. |
| **`unified_driver_demo`** | `pcap,http,dns` | Plan-121 typed `Driver<E>` showcase — port-routed HTTP + DNS slots plus a signature-based heuristic catch-all. Drain each parser slot independently. |

## 01 — L7 message logging

[`examples/01-l7-logging/`](./01-l7-logging/)

| Example | Features | What it shows |
|---|---|---|
| **`http_log`** | `http,pcap` | One-line summary of every HTTP request + response (per-message). |
| **`http_exchanges`** | `http,pcap` | One log line per request/response PAIR via `HttpExchangeParser` (plan 107). Access-log-shaped rows with RTT and outcome. |
| **`tls_observer`** | `tls,pcap` | SNI / ALPN / cipher list for every TLS ClientHello + ServerHello. |
| **`dns_log`** | `dns,pcap` | Query / response pairs with RTT correlation via `Correlator`. |

## 02 — forensics / IoC extraction

[`examples/02-forensics/`](./02-forensics/)

| Example | Features | What it shows |
|---|---|---|
| **`extract_iocs`** | `pcap,http,tls,ja3,ja4,dns,extractors` | Dedup'd list of hostnames (SNI + HTTP Host + DNS qnames), IPs, JA3/JA4 fingerprints, user-agents — the starting point for IR enrichment. |
| **`tls_inventory`** | `tls,ja3,ja4,pcap` | Aggregated TLS handshake catalog via `TlsHandshakeParser` — outcomes, top SNIs, top JA3/JA4. |

## 03 — security / detection

[`examples/03-detection/`](./03-detection/)

| Example | Features | What it shows |
|---|---|---|
| **`port_scan_detector`** | `pcap,extractors,tracker` | SYN-without-ACK rate per `(src, dst)` via `TimeBucketedCounter` + distinct-port set via `TimeBucketedSet` (plan 102 sub-A). |
| **`dns_tunnel_detector`** | `pcap,dns,extractors` | High Shannon entropy + long-label + high-rate DNS queries = probable DNS tunnel. Uses `flowscope::detect::shannon_entropy`. |
| **`failed_auth_burst`** | `pcap,http` | HTTP 401/403 burst followed by 200 — credential-stuffing pattern via `BurstDetector` (plan 102 sub-A). |
| **`c2_beacon_finder`** | `pcap,extractors,tracker` | RITA-style CV beacon detector via `flowscope::detect::patterns::BeaconDetector` (plan 143). |
| **`dga_finder`** | `pcap,dns,extractors` | Bigram log-likelihood DGA scoring on DNS query SLDs via `flowscope::detect::patterns::DgaScorer` (plan 143). |
| **`tcp_retransmit_audit`** | `pcap,extractors,reassembler` | Per-flow retransmit-rate ranking. Production reliability signal. |

## 04 — observability / SRE

[`examples/04-observability/`](./04-observability/)

| Example | Features | What it shows |
|---|---|---|
| **`top_talkers`** | `pcap,extractors,tracker` | Top-N source IPs by bytes and packets (HashMap-of-everything). |
| **`top_talkers_topk`** | `pcap,extractors,tracker` | Same shape but bounded-memory via `TopK` (Misra-Gries) — exact for the top, approximate for the long tail (plan 102 sub-A). |
| **`http_error_rate`** | `pcap,http` | Per-host 1xx/2xx/3xx/4xx/5xx counts and error-rate ranking. |
| **`bandwidth_by_protocol`** | `pcap,extractors,tracker` | Bytes / kbps per recognised L7 protocol via `flowscope::well_known::protocol_label`. |
| **`flow_duration_histogram`** | `pcap,aggregate` | Distribution of flow durations with p50 / p99 / max via `Histogram` (plan 102 sub-B). |
| **`conversation_timeline`** | `pcap,extractors,reassembler` | Timeline of a single TCP conversation — every state transition, every direction-marked packet. |

## 05 — data export

[`examples/05-export/`](./05-export/)

| Example | Features | Output |
|---|---|---|
| **`flow_csv_export`** | `pcap,emit` | `flows.csv` via `FlowEventCsvWriter` (RFC-4180 quoted; plan 101). |
| **`flow_json_export`** | `pcap,emit-ndjson` | NDJSON via `FlowEventNdjsonWriter` — drop-in for Elasticsearch / Loki / ClickHouse. |
| **`zeek_style_conn_log`** | `pcap,emit` | Tab-separated Zeek `conn.log` via `ZeekConnLogWriter` (with `#fields` / `#types` / `#close` headers + UID generation). |
| **`eve_writer`** | `pcap,emit-eve` | Suricata EVE JSON via `EveJsonWriter` (0.12) — drop-in for Filebeat / Splunk Suricata TA / Tenzir / ECS pipelines. Every record carries a deterministic 16-char `flow_hash`. |

## 06 — custom protocols

[`examples/06-custom-protocols/`](./06-custom-protocols/)

| Example | Features | What it shows |
|---|---|---|
| **`length_prefixed_pcap`** | `pcap,session` | Custom binary protocol (`PFX2,`/`PFX4,` length-prefixed) using `FlowSessionDriver` directly. |
| **`accumulating_line_parser`** | `pcap,extractors,session` | Same shape via `AccumulatingSessionParser` (plan 106) — one constructor call replaces the 25-LoC manual `SessionParser` impl. |
| **`redis_protocol`** | `pcap,extractors,reassembler` | RESP protocol parser as `SessionParser`. Demonstrates the splitting-invariance contract and a real recursive parser. |

## 08 — performance

[`examples/08-performance/`](./08-performance/)

| Example | Features | What it shows |
|---|---|---|
| **`layer_fast_path`** | `pcap,extractors` | Zero-allocation `LayerParser` + `LayerStack` for the per-packet view (plan 94 Tier 3 fast path). |
| **`threaded_slot_drain`** | `pcap,http` | Cross-thread slot drain — `SlotHandle: Send + Sync` (0.12). Worker thread drains an HTTP slot while the capture loop runs on main. |

## 07 — multi-protocol pipelines

[`examples/07-multi-protocol/`](./07-multi-protocol/)

| Example | Features | What it shows |
|---|---|---|
| **`multi_parser_pipeline`** | `pcap,extractors,reassembler,session` | `FlowMultiSessionDriver` composite driver — port-routed + broadcast parsers with a user sum type. |
| **`multi_protocol_monitor`** | `l7,pcap` | The older "open the source N times, one driver per parser" pattern; kept as a comparison reference. |

> For the 0.10 unified `Driver<E, M>` equivalent of the
> multi-protocol shape, see
> [`00-getting-started/unified_driver_demo.rs`](./00-getting-started/unified_driver_demo.rs).

## 08 — performance

[`examples/08-performance/`](./08-performance/)

| Example | Features | What it shows |
|---|---|---|
| **`layer_fast_path`** | `pcap,extractors` | Wall-clock comparison of `Layers::parse_ethernet` (ergonomic, per-frame alloc) vs `LayerParser` + `LayerStack` (zero-allocation fast path). Run with `--release` to see the real numbers. |

## 09 — reassembly / low-level

[`examples/09-low-level/`](./09-low-level/)

| Example | Features | What it shows |
|---|---|---|
| **`pcap_flow_summary`** | `pcap` | Minimal flow accounting via `FlowTracker` directly. |
| **`pcap_flow_keys`** | `pcap` | Just print flow keys as packets arrive. |
| **`pcap_buffered_reassembly`** | `pcap,reassembler` | Configure a `BufferedReassembler` with caps + overflow policy. |

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
- The 0.11 cycle ships the typed `flowscope::driver::Driver<E>`
  + `SlotHandle<M, K>` surface — the
  [`00-getting-started/unified_driver_demo.rs`](./00-getting-started/unified_driver_demo.rs)
  example showcases it. The 0.9-era closed-`M`
  `Driver<E, M>` + lift-closure pattern and the legacy
  `FlowSessionDriver` / `FlowDatagramDriver` /
  `FlowMultiSessionDriver` / `Pipeline` types are deleted in
  0.11.
