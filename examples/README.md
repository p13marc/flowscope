# flowscope examples

Runnable examples grouped by what they show. Every example
defaults to a fixture path under `tests/data/` or
`tests/fixtures/` when run with no arguments, so you can poke at
them without bringing your own pcap.

Run any of them with:

```bash
cargo run --features <FEATURES> --example <NAME> -- [optional pcap path]
```

Some examples open standard output for piping into other tools
(CSV / JSON / Zeek conn.log shapes); redirect with `>`.

---

## 0. Hello world

| Example | Features | What it shows |
|---|---|---|
| **`hello_pipeline`** | `pcap,extractors,reassembler,session` | Shortest `flowscope::Pipeline` program — one builder chain, one iterator. The recommended starting point. |
| **`inspect_packet`** | `pcap,extractors` | Dump a layered view of every packet: L2 / L3 / L4 / tunnel headers via the dynamic walk on `flowscope::layers`. |

## 1. L7 message logging (per-protocol)

| Example | Features | What it shows |
|---|---|---|
| **`http_log`** | `http,pcap` | One-line summary of every HTTP request + response. |
| **`tls_observer`** | `tls,pcap` | SNI / ALPN / cipher list for every TLS ClientHello + ServerHello. |
| **`dns_log`** | `dns,pcap` | Query / response pairs with RTT correlation via `Correlator`. |

## 2. Forensics / IoC extraction

| Example | Features | What it shows |
|---|---|---|
| **`extract_iocs`** | `pcap,http,tls,ja3,ja4,dns,extractors` | Dedup'd list of hostnames (SNI + HTTP Host + DNS qnames), IPs, JA3/JA4 fingerprints, user-agents — the starting point for IR enrichment. |
| **`tls_inventory`** | `tls,ja3,ja4,pcap` | Aggregated TLS handshake catalog via `TlsHandshakeParser` — outcomes, top SNIs, top JA3/JA4. |

## 3. Security / detection

| Example | Features | What it shows |
|---|---|---|
| **`port_scan_detector`** | `pcap,extractors,tracker` | SYN-without-ACK rate per `(src, dst)` via `TimeBucketedCounter`; reports diverse-port probes. |
| **`dns_tunnel_detector`** | `pcap,dns,extractors` | High Shannon entropy + long-label + high-rate DNS queries = probable DNS tunnel. |
| **`failed_auth_burst`** | `pcap,http` | HTTP 401/403 burst followed by 200 from same source — credential-stuffing pattern. |
| **`tcp_retransmit_audit`** | `pcap,extractors,reassembler` | Per-flow retransmit-rate ranking. Production reliability signal. |

## 4. Observability / SRE

| Example | Features | What it shows |
|---|---|---|
| **`top_talkers`** | `pcap,extractors,tracker` | Top-N source IPs by bytes and packets. |
| **`http_error_rate`** | `pcap,http` | Per-host 1xx/2xx/3xx/4xx/5xx counts and error-rate ranking. |
| **`bandwidth_by_protocol`** | `pcap,extractors,tracker` | Bytes / kbps per recognised L7 protocol (HTTP, TLS, DNS, Redis, Postgres, MQTT, …). |
| **`flow_duration_histogram`** | `pcap,extractors,tracker` | Distribution of flow durations with p50 / p99 / max. |
| **`conversation_timeline`** | `pcap,extractors,reassembler` | Timeline of a single TCP conversation — every state transition, every direction-marked packet. |

## 5. Data export

| Example | Features | Output |
|---|---|---|
| **`flow_csv_export`** | `pcap,extractors,tracker` | `flows.csv` with start/end/duration/proto/bytes/packets. |
| **`flow_json_export`** | `pcap,extractors,tracker,serde` | NDJSON drop-in for Elasticsearch / Loki / ClickHouse. |
| **`zeek_style_conn_log`** | `pcap,extractors,tracker` | Tab-separated Zeek `conn.log` shape — feeds existing Zeek pipelines. |

## 6. Custom protocols

| Example | Features | What it shows |
|---|---|---|
| **`length_prefixed_pcap`** | `pcap,extractors,reassembler` | Custom binary protocol (`PFX2,`/`PFX4,` length-prefixed) using `FlowSessionDriver`. |
| **`redis_protocol`** | `pcap,extractors,reassembler` | RESP protocol parser as `SessionParser`. Demonstrates the splitting-invariance contract and a real recursive parser. |

## 7. Multi-protocol pipelines

| Example | Features | What it shows |
|---|---|---|
| **`multi_parser_pipeline`** | `pcap,extractors,reassembler,session` | `FlowMultiSessionDriver` composite driver — port-routed + broadcast parsers with a user sum type. |
| **`multi_protocol_monitor`** | `l7,pcap` | The older "open the source N times, one driver per parser" pattern; kept as a comparison reference. |

## 8. Performance

| Example | Features | What it shows |
|---|---|---|
| **`layer_fast_path`** | `pcap,extractors` | Wall-clock comparison of `Layers::parse_ethernet` (ergonomic, per-frame alloc) vs `LayerParser` + `LayerStack` (zero-allocation fast path). Run with `--release` to see the real numbers. |

## 9. Reassembly / low-level

| Example | Features | What it shows |
|---|---|---|
| **`pcap_flow_summary`** | `pcap,extractors,tracker` | Minimal flow accounting via `FlowTracker` directly. |
| **`pcap_flow_keys`** | `pcap,extractors,tracker` | Just print flow keys as packets arrive. |
| **`pcap_buffered_reassembly`** | `pcap,http` | Configure a `BufferedReassembler` with caps + overflow policy. |

## Utilities (fixture generators — not user-facing)

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
- The 0.9 release deleted the legacy callback-factory L7 APIs
  (`HttpFactory`, `TlsFactory`); every example here uses the
  `SessionParser` typed-stream shape.
