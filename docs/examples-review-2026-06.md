# Examples review — flowscope 0.18 cycle

**Status:** for user review · written 2026-06-21 · pre-0.18.0 publish
**Method:** 4 parallel reading agents across 47 example files + external
research against quinn / gopacket + Rust API guidelines.

---

## TL;DR

The example directory has matured into a real feature catalogue but
still leaks several pre-0.11 ergonomic patterns. The fix is mostly
ergonomic helpers, not new examples — though a few high-value
examples (Kerberos, LDAP, asset inventory, detector→EVE composition,
nPrint→numpy, Prometheus) are conspicuously missing for the 0.18
cycle.

**The five most impactful findings:**

1. **The "hello world" isn't.** `00-getting-started/hello_pipeline.rs`
   is 73 LoC of typed-driver tour, not a 10-line first-pcap demo.
   The new `PcapFlowSource::sessions()` + per-parser `*_from_pcap`
   helpers make a true 6-line hello-world possible today.
2. **Half the examples leak pre-0.11 boilerplate.** ~12 files still
   build `Driver::builder + SlotHandle + scratch Vecs + per-loop
   clear+drain + duplicated end-of-input flush block`. The fix is
   already in the codebase — just port the older examples to the
   newer `*_from_pcap` / `PcapFlowSource::sessions()` shape.
3. **0.18 marquee features have no examples.** Kerberos
   `kerberoast_suspect`, LDAP `search_attributes_spn_query`, the
   `asset::Inventory`, the `nprint` per-packet bit matrix, the
   `metrics` Prometheus path, and `tracing` integration — all zero
   coverage. These are the headline cycle features.
4. **Detector → EVE/IPFIX composition is missing.** Every detector
   ships an `into_anomaly(ts)` method and every emit writer has a
   `write_owned_anomaly` sink — but no single example wires them
   together. That's the SIEM-ingest pipeline operators actually want.
5. **Several existing examples teach the wrong primitive.**
   `port_scan_detector.rs` hand-rolls a `TimeBucketedSet` count when
   `PortScanDetector` (TRW / Jung 2004) ships in `detect::patterns`.
   `bandwidth_by_protocol.rs` hand-builds a label table when
   `well_known::protocol_label` exists. `http_error_rate.rs` uses a
   `HashMap` when `RollingRate + TopK` is the SLO-shaped answer.

---

## Cross-cutting pain points

### P1 — Boilerplate duplication: the `clear+drain` quartet

Every typed-driver example writes some flavor of:

```rust
let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
let mut msgs:   Vec<SlotMessage<TlsMessage, FiveTupleKey>> = Vec::new();
for view in PcapFlowSource::open(&path)?.views() {
    let view = view?;
    events.clear();
    driver.track_into(&view, &mut events);
    msgs.clear();
    slot.drain(&mut msgs);
    for m in &msgs { /* business logic */ }
}
// then duplicate the same drain block once more for finish_into:
events.clear();
driver.finish_into(&mut events);
msgs.clear();
slot.drain(&mut msgs);
for m in &msgs { /* SAME business logic, again */ }
```

This pattern hits ~12 examples (`hello_pipeline`, `http_log`,
`http_exchanges`, `unified_driver_demo`, `multi_protocol_monitor`,
`extract_iocs`, every 03-detection file, several 04-observability).

**Two fixes already shipped this cycle (just need wider adoption):**

- `SlotHandle::drain_replacing(&mut Vec<_>)` — collapses the
  `clear; drain` pair to one call.
- `PcapFlowSource::sessions(ext, parser)` and `.datagrams(...)` —
  collapses the whole loop + finish dance to `for ev in source.sessions(ext, parser) { ... }`.

**Recommended additional fix:**

- `Driver::run_pcap(extractor, path) -> impl Iterator<Item = Event>` —
  the equivalent of `sessions(...)` but for the typed driver shape
  with `BroadcastSlotHandle` support and multi-parser routing.
  Currently the only way to do multi-parser is the manual loop.

### P2 — `main()` return-type inconsistency

Three shapes in play across examples:
- `flowscope::Result<()>` (~3 files)
- `Result<(), Box<dyn std::error::Error>>` (~30 files)
- No `Result` at all (a few utility/synthetic files)

`flowscope::Result<()>` doesn't support the `.ok_or("usage: ...")?`
idiom because `&'static str → flowscope::Error` isn't wired. The
`Box<dyn Error>` form is std-only and supports the usage-error idiom
trivially.

**Recommended:** standardize on `Result<(), Box<dyn std::error::Error>>`
across all 47 examples. Document the convention in
`examples/README.md`.

### P3 — Import style inconsistency

Some examples use `flowscope::prelude::*`; most enumerate paths;
some mix. The enumerated form is more pedagogical (a reader of the
example learns *where* each type lives), the prelude form is what
production code should use.

**Recommended:** all examples enumerate; document `use
flowscope::prelude::*;` as the production convention in
README. Add a comment line to a couple of examples noting they
*could* have used prelude.

### P4 — Stale doc-comments from earlier cycles

- `examples/utilities/gen_fixtures.rs` says
  `cargo run -p netring-flow --example generate_fixtures` — the
  crate was renamed to `flowscope` long ago. Output path is wrong
  too (`netring-flow/tests/data/` vs current `tests/data/`).
- `09-low-level/*.rs` — all three files have stale `-p netring-flow`
  in cargo invocations.
- `unified_driver_demo.rs` doc claims `--features … test-helpers`
  but doesn't import anything from `test-helpers`.
- `threaded_slot_drain.rs` doc claims `Driver<E>` is `!Send` — fixed
  structurally in 0.13 (plan 156). The doc lies.
- `examples/README.md` says "all 47 examples"; `find` reports 48
  (or 47 if you exclude utilities — recount).
- Two `## 08 — performance` headers in `examples/README.md` (typo).

### P5 — Stringly-typed where enums exist

Several examples handle `L4Proto` / `EndReason` / `IcmpType` via
string matches instead of via the typed enum methods that shipped
later. E.g., `bandwidth_by_protocol.rs` defines its own label table
when `FiveTupleKey::protocol_label()` exists.

### P6 — Numbered directories, unnumbered files

Directories are `00-getting-started/`, `01-l7-logging/`, etc., but
files inside aren't prefixed. Mostly fine, but `00-getting-started/`
mixes a true onboarding step (`hello_pipeline`) with a packet-walker
tour (`inspect_packet` is 215 LoC of `match` arms — that's not
"getting started").

### P7 — False-positive blindness in detection examples

Most `03-detection/` examples don't acknowledge well-known false
positives in their doc-comments (e.g., DNS-tunnel detector that
trips on CDNs, port-scan that fires on internal Shodan-like
scanners, beacon detector that fires on Prometheus push gateways).
Operators reading these examples to learn the technique need the
caveats.

### P8 — No MITRE / ATT&CK attribution

Only `smtp_credentials.rs` and `smb_lateral_movement.rs` cite
MITRE technique IDs in their doc-comments. The other security
examples (port scan, beacon, DGA, brute force, ARP spoof, DNS
tunnel) all map cleanly to specific T-numbers but don't say so.
Operators search by ATT&CK and won't find these examples.

---

## Per-cluster findings

### 00-getting-started

| File | LoC | Verdict |
|---|---|---|
| `hello_pipeline.rs` | 73 | ✗ Bloated. Should be ~12 LoC using `PcapFlowSource::sessions`. The "hello world" claim in the doc is false. |
| `inspect_packet.rs` | 215 | ✓ Best doc in cluster; ⚠ mis-shelved (it's a layers tour, not a getting-started step). Consider moving to `09-low-level/`. |
| `broadcast_subscribers.rs` | 84 | ✓ Best doc in cluster #2; demonstrates `BroadcastSlotHandle` cleanly. |
| `sharded_capture.rs` | 178 | ✓ ASCII-art architecture diagram. ⚠ Wrong directory — production-shape concurrency belongs in `08-performance/`. Also hand-decodes Ethernet+IPv4 offsets when a `FlowExtractor` would do (its own TODO comment admits this). |
| `unified_driver_demo.rs` | 143 | ✓ Three dispatch modes demo. ⚠ Stale `--features test-helpers` in doc-comment. |

### 01-l7-logging

| File | LoC | Verdict |
|---|---|---|
| `http_log.rs` | 83 | ✗ Pre-helper pattern. Port to `PcapFlowSource::sessions(FiveTuple::bidirectional(), HttpParser::default())` → drops to ~30 LoC. |
| `http_exchanges.rs` | 124 | ✗ Same. Plus a **UTF-8 panic bug** at the UA truncation (`s[..8]` panics on multi-byte chars; use `s.chars().take(8).collect()`). |
| `dns_log.rs` | 85 | ✓ Already uses `PcapFlowSource::datagrams(...)`. Reference shape. |
| `tls_observer.rs` | 65 | ✓ Gold standard — uses `PcapFlowSource::sessions(...)`. |
| `quic_initial_observer.rs` | 52 | ✓ Other gold standard — uses the new `quic::initials_from_pcap` one-call. |

### 02-forensics

| File | Verdict |
|---|---|
| `extract_iocs.rs` | ⚠ Missing 0.18 IoC sources: SMTP/FTP envelopes, SMB NTLM identity, Kerberos cnames, LDAP DNs. The "every IP" dump is noise — split internal vs external by `is_global()`. |
| `tls_inventory.rs` | ⚠ Doesn't surface the 0.18 TLS additions: `certificate_chain`, `ja4x`, `EchOutcome`, `resumption_attempted`. Should also flag any < TLS 1.2 handshake (PCI/HIPAA signal). |
| `arp_spoof_detector.rs` | ✓ Uses `NeighborTable` correctly. ⚠ Missing MITRE T1557.002. ⚠ No FP caveat for DHCP renewals / VRRP / macOS Wi-Fi roaming. |
| `smtp_credentials.rs` | ✓ Cites T1078/T1110/T1048 (best in cluster). ⚠ Doesn't base64-decode `Credentials.pass` before printing — operator sees `"dGVzdA=="` instead of `"test"`. |
| `smb_lateral_movement.rs` | ✓ Reference quality — cites 5 MITRE techniques + CVE-2021-34527. The pattern the others should imitate. |

### 03-detection

| File | Verdict |
|---|---|
| `port_scan_detector.rs` | ✗ Hand-rolls TRW logic instead of using `PortScanDetector`. Doesn't print destination ports observed. No FP guardrail for multicast/link-local. Missing T1046 cite. |
| `dns_tunnel_detector.rs` | ⚠ Composition is right (entropy + label-length + rate) but doesn't use `BurstDetector`. **Critical FP blindness:** doesn't acknowledge CDN cover-domains, DoH/DoT, anti-virus telemetry, NSEC3 walking. |
| `c2_beacon_finder.rs` | ✓ Uses `BeaconDetector` correctly. ⚠ Missing MITRE T1071/T1573 + no FP note for NTP/Prometheus/cron-driven agents. |
| `dga_finder.rs` | ✓ Best in cluster — uses `DgaScorer` correctly, prints all score components. ⚠ Missing T1568.002 + AV/CDN FP caveat. |
| `failed_auth_burst.rs` | ✓ Uses `BurstDetector`. ⚠ Missing T1110.003 (Password Spraying) + T1110.004 (Credential Stuffing). |
| `tcp_retransmit_audit.rs` | ⚠ Mis-shelved — retransmits are an observability signal, not a security one. Belongs in `04-observability/`. The security flavor (`Reassembler::rexmit_inconsistencies()` — Ptacek-Newsham IOC) shipped in 0.18 and has no example. |

### 04-observability

| File | Verdict |
|---|---|
| `top_talkers.rs` | ⚠ Hand-rolls `HashMap<IpAddr, Rollup>` when `FlowStats` (with `direction_skew` / `bytes_for` / `throughput_bps_for`) gives the same for free. |
| `top_talkers_topk.rs` | ✓ Not a duplicate — bounded-memory variant. ⚠ Cross-link missing in `top_talkers.rs`. |
| `http_error_rate.rs` | ⚠ Uses `HashMap` for per-host accounting. Prime candidate for `RollingRate<String, u64>` + `TopK<String>` — that's the SLO question operators actually ask. |
| `bandwidth_by_protocol.rs` | ✗ Hand-rolls a `label_for()` table when `FiveTupleKey::protocol_label()` (since 0.10) exists. Should be merged into / replaced by `bandwidth_by_app.rs`. |
| `bandwidth_by_app.rs` | ✓ Reference quality — `RollingRate + LabelTable + app_label_with + top_k`. Keep as-is. |
| `flow_duration_histogram.rs` | ✓ Uses `Histogram` correctly. ⚠ Doesn't mention `Percentile` (t-digest) alternative for rank-error-bounded p99. |
| `conversation_timeline.rs` | ⚠ Hand-codes `matches_key(ev, k)` switch when `FlowEvent::key()` returns `Option<&K>` (since 0.8). ⚠ Doesn't pull anomalies from the stream — biggest teaching gap for 0.18's `rexmit_inconsistencies`. |
| `icmp_explained_drops.rs` | ✓ Reference — uses `DestUnreachableKind`, `MtuSignalKind`, `lookup_inner`. Keep. |
| `direction_skew_anomaly.rs` | ✓ Reference primitives. ⚠ Duplicated 20-line `if let FlowEvent::Ended` block (track + finish). |
| `ml_features_pipeline.rs` | ✓ Marquee 0.18 demo. ⚠ `let _ = EndReason::Fin;` smell. ⚠ Only NDJSON output; should offer `--format csv\|libsvm\|ndjson` for sklearn / pandas / Jupyter audiences. |

### 05-export

| File | Verdict |
|---|---|
| `flow_csv_export.rs` | ✓ ~37 LoC, correct minimalism. |
| `flow_json_export.rs` | ✓ Same. |
| `zeek_style_conn_log.rs` | ✓ Same. |
| `eve_writer.rs` | ⚠ Misses the flagship sell — comment says "for live FlowAnomaly emission, wrap the tracker in a `FlowDriver` and call `.with_emit_anomalies(true)`" but **the example doesn't do this**. Also no `write_owned_anomaly` demo despite that being the explicit detector→SIEM pipeline (plan 147). |
| `ipfix_wire_export.rs` | ✓ Real RFC 7011 producer. ⚠ Useless `reason_to_owned` identity helper. ⚠ No UDP socket sibling — a 10-line `udp_send_ipfix.rs` would close the loop for any operator shipping to nfcapd/softflowd. |

### 06-custom-protocols

| File | Verdict |
|---|---|
| `redis_protocol.rs` | ✓ Strong worked example with real RESP parser. ⚠ Cargo feature mismatch in doc-comment header (says `pcap,extractors,reassembler` but code needs `session` too). |
| `accumulating_line_parser.rs` | ✓ Excellent before/after framing. ⚠ Wrong `--features` (claims `test-helpers` but doesn't use it). |
| `length_prefixed_pcap.rs` | ✓ Solid. Only example with the `// hand-off to netring's flow_stream(...)` stub at the top — should be in others too. |

**Order issue:** README orders them `length_prefixed_pcap, accumulating_line_parser, redis_protocol`. Natural learning order is the reverse direction: helper-based → hand-written → recursive grammar.

### 07-multi-protocol

| File | Verdict |
|---|---|
| `multi_parser_pipeline.rs` | ⚠ Two synthetic toys, not three real parsers. Consider removing or merging with `multi_protocol_monitor`. |
| `multi_protocol_monitor.rs` | ✓ Real HTTP+TLS+DNS+ICMP-on-one-pcap. ⚠ README calls it "the older comparison reference" — pre-0.11 framing that should be removed. |

**Missing in this directory:**
- `session_heuristic` / `datagram_heuristic` demo (exists in `00-getting-started/unified_driver_demo.rs` — misplaced).
- `BroadcastSlotHandle` demo (exists in `00-getting-started/broadcast_subscribers.rs` — misplaced).

### 08-performance

| File | Verdict |
|---|---|
| `layer_fast_path.rs` | ✓ Honest wall-clock comparison with `Instant`. Mentions `--release`. |
| `threaded_slot_drain.rs` | ✗ Structural demo, not a throughput benchmark. **Doc comment lies** — claims `Driver<E>` is `!Send`, but it's been `Send + Sync` since 0.13 (plan 156). Should print msgs/sec, drain-batch histogram, worker wake-up count. |

**Missing in this directory:**
- `allocations_per_packet.rs` — the headline 0.000 allocs/pkt claim needs a runnable demo.
- nPrint / ml-features cost demo.

### 09-low-level

All three files have stale `-p netring-flow` references (pre-0.9
crate name). All three lack a "when to drop here" framing.
`pcap_buffered_reassembly.rs` doc says "drained and sizes printed"
but the code only prints `FlowStats` counters — misleading.

**Missing:**
- `overflow_policy.rs` demonstrating `BufferedReassembler` with
  `SlidingWindow` / `DropFlow` and the `BufferOverflow` event.
- ARP-spoof / DHCP-fingerprint asset-inventory composition.

### utilities

Both files have stale `-p netring-flow --example generate_*` lines
and the output path is wrong (`netring-flow/tests/data/`).

---

## Missing examples by category

### Security (high operator value)
- **`02-forensics/kerberoast_hunter.rs`** — Kerberos `kerberoast_suspect` → EVE. T1558.003. No coverage today.
- **`02-forensics/ldap_recon_hunter.rs`** — LDAP `search_attributes_spn_query`. T1087.002 / BloodHound. No coverage today.
- **`02-forensics/client_fingerprint_catalog.rs`** — JA3 + JA4 + HASSH + JA4H + TCP_FINGERPRINT joined per-host. The client-classification story.
- **`02-forensics/asset_inventory.rs`** — 0.18's `asset::Inventory` composition layer. Zero example coverage today.
- **`03-detection/composite_c2.rs`** — BeaconDetector ∧ DgaScorer ∧ low-cipher TLS, driven by one pcap loop, piped through `EveJsonWriter::write_owned_anomaly`. The SIEM pipeline.
- **`03-detection/tcp_evasion_detector.rs`** — `Reassembler::rexmit_inconsistencies()` (Ptacek-Newsham IOC). The security flavor `tcp_retransmit_audit` should have been.

### Export & integration
- **`05-export/prometheus_exporter.rs`** — `metrics` feature has **zero examples**. Biggest documented-feature/example gap.
- **`05-export/tracing_subscriber.rs`** — `tracing` feature has zero examples.
- **`05-export/detector_to_eve.rs`** — see composite_c2 above; the SIEM ingest pipeline.
- **`05-export/ipfix_udp_collector.rs`** — wrap `MessageBuilder::finalize()` in a UDP send loop.
- **`05-export/nprint_to_npz.rs`** — 0.18 marquee ML feature has zero example.
- **`05-export/ml_features_libsvm.rs`** — sklearn / xgboost training file output.
- **`05-export/pcap_dir_tail.rs`** — watch a directory of rotating pcap fragments. Real replay-from-disk pattern.

### Onboarding
- **`00-getting-started/from_stdin.rs`** — `tcpdump -w - | flowscope-tool` mode. Small lift, big operator value.
- **A real ~12-line `hello_pipeline.rs`** that replaces the current 73-line tour.

### Low-level
- **`09-low-level/overflow_policy.rs`** — `BufferedReassembler` policies.

---

## Recommendations for high-level / strongly-typed / idiomatic APIs

These are *new library APIs* that would improve every example. Many
are additive; flagged where breaking.

### A1 — `Driver::run_pcap(extractor, path) -> impl Iterator<Item = Event>` (additive)

Closes the per-packet `track_into + finish_into` boilerplate for
the multi-parser typed-driver shape. Today only the single-parser
shape (`PcapFlowSource::sessions(ext, parser)`) has this. Should
work for the `Driver::builder().session_on_ports(...).build()`
shape too.

### A2 — More `*_from_pcap` helpers (additive)

Already shipped for TLS / QUIC / SMB. Add:
- `flowscope::http::requests_from_pcap(path) -> Iterator<(FiveTupleKey, HttpRequest)>`
- `flowscope::http::responses_from_pcap(...)`
- `flowscope::http::exchanges_from_pcap(...)`
- `flowscope::dns::queries_from_pcap(...)`
- `flowscope::dns::exchanges_from_pcap(...)`
- `flowscope::kerberos::messages_from_pcap(...)`
- `flowscope::ldap::messages_from_pcap(...)`
- `flowscope::ssh::handshakes_from_pcap(...)` — surfacing HASSH

Estimated 30–50 LoC each, very high consumer-side ergonomic win.

### A3 — `flowscope::flow_summaries_from_pcap(path)` (additive)

`-> Iterator<(FiveTupleKey, FlowStats, EndReason)>` over the
finalized flows. The bare-tracker examples in `09-low-level/` all
implement this by hand; the 0.18 cycle's `FlowStats` per-side
accessors (`direction_skew`, `bytes_for`, `throughput_bps_for`)
make this the natural shape.

### A4 — `Result` over `Option` on parse functions (BREAKING — pre-publish)

Per the prior API audit, `dnp3::parse`, `kerberos::parse`,
`ldap::parse`, `smb::parse`, `quic::parse` all return `Option<T>`.
Idiomatic Rust is `Result<T, ParseError>` so consumers can route
on failure mode (`Truncated` vs `BadMagic` vs `DecodeFailed`). Per
plan-131-style typed errors, add `ParseError` per module.

Deferred from the previous API quality pass because of churn, but
fits this examples review's "make it more idiomatic" frame.

### A5 — Strong types for remaining primitives (BREAKING — pre-publish)

Already shipped this cycle: `QuicVersion`, `KerberosEtype`,
`DceRpcInterfaceUuid`. Remaining:
- LDAP `result_code: Option<u32>` → `Option<LdapResultCode>` enum
  (Success=0, InvalidCredentials=49, InsufficientAccess=50, ...).
- LDAP `search_scope: Option<u32>` → `Option<LdapSearchScope>`
  (BaseObject / SingleLevel / WholeSubtree).
- Kerberos `error_code: Option<i32>` → `Option<KerberosErrorCode>`
  (KDC_ERR_PREAUTH_REQUIRED=25, ...).
- nPrint `Vec<i8>` → `Vec<NPrintBit>` (Absent / Zero / One).
- DNP3 `link_dir: bool` + `link_prm: bool` → `DnpLinkDirection`
  + `DnpLinkRole` enums.

### A6 — `IntoIterator` on `Inventory` / `LabelTable` / etc. (additive)

Currently most container types expose `.iter()` but not
`IntoIterator`. Implementing `IntoIterator` lets consumers write
`for asset in inventory` directly. Small idiom alignment.

### A7 — `tracker.run_pcap(path, |ev| {})` callback shape (additive)

For the bare-tracker examples in `09-low-level/`, the
event-callback shape is shorter than the iterator shape. Optional
addition next to `flow_summaries_from_pcap`.

### A8 — `flowscope::detect::patterns::Pipeline` (additive)

A composition wrapper that drives BeaconDetector +
PortScanDetector + DgaScorer + custom detectors against a single
event stream, yielding a unified `Iterator<Item = OwnedAnomaly>`.
That's the `composite_c2.rs` example's natural shape.

### A9 — `flowscope::run_with(...)` builder for multi-format export (additive)

For the `eve_writer.rs` use case: "run a pcap through a
FlowTracker with anomalies enabled and route events to an
EveJsonWriter". Today users assemble this manually. A
chain-builder:

```rust
flowscope::Pipeline::new()
    .extract(FiveTuple::bidirectional())
    .with_emit_anomalies(true)
    .emit_eve(stdout)
    .with_detector(BeaconDetector::default())
    .run_pcap("trace.pcap")?;
```

(Note: this resurrects the `Pipeline` name that was deleted in
plan 121. A re-introduction is reasonable — but only if it's
*genuinely* the highest-level shape, not a Driver alias.)

---

## External-research synthesis

From a quick scan of competitive libraries:

### Quinn (QUIC) — flat, descriptive
- 5 example files, no numbering, no grouping: `client.rs`,
  `server.rs`, `connection.rs`, `insecure_connection.rs`,
  `single_socket.rs`.
- "Hello world" is `connection.rs` — smallest possible QUIC
  connection on localhost.
- **Takeaway:** smaller catalogues stay flat; flowscope's 47-file
  catalogue is large enough that grouping is justified.

### gopacket — flat, action-named directories
- 13 example *directories* (not files), names like `arpscan`,
  `synscan`, `httpassembly`, `pcaplay`, `reassemblydump`.
- Verb-object naming: every example name is "what it does".
- **Takeaway:** flowscope's `02-forensics/extract_iocs.rs` already
  follows this; `04-observability/conversation_timeline.rs` also
  works. The 03-detection cluster names (e.g., `c2_beacon_finder`)
  read well too.

### Rust API guidelines — items that hit hardest for flowscope
- **Builders over multi-arg constructors** for >3-field configs —
  the existing `EveOptions` / `CsvOptions` shape is right;
  `DriverBuilder` is the model.
- **Newtypes over primitives** — already taken on
  `QuicVersion` / `KerberosEtype` / `DceRpcInterfaceUuid`; the
  remaining gaps (A5 above) are the natural follow-up.
- **`as_` / `to_` / `into_` conversion conventions** — flowscope's
  `as_str()` on enum-of-known-values is correct; the
  `from_raw() -> Self` / `as_raw() -> i32` shape on
  `KerberosEtype` is also correct (cheap by-value conversion).
- **Iterator chains over `for + push`** — examples often build a
  `Vec` then iterate; `Iterator::filter_map` chains would read
  cleaner.
- **Document errors** — none of the new parsers document their
  failure modes (because they return `Option`). A4 above.

### Patterns to adopt
- **gopacket's "verb + object" file names** — already mostly there.
- **quinn's small first-example contract** — flowscope's
  `hello_pipeline.rs` should be ~10 lines.
- **Inline mini-tutorials in doc-comments** — `smb_lateral_movement.rs`
  is the model (MITRE technique IDs, what each event means).

### Patterns to avoid
- Sprawling multi-line generic type annotations on temporaries
  (`Vec<SlotMessage<TlsMessage, FiveTupleKey>>`) — collapse with
  helper methods (the A1/A2/A3 additions above).
- "Final flush" duplicate blocks at end-of-main — these are a
  library-shape symptom, not a user-side problem.

---

## Priority-ordered ship list

### P0 — must-fix before publish

1. **Rewrite `hello_pipeline.rs`** to a real ~12-line `PcapFlowSource::sessions(...)` demo.
2. **Fix the UTF-8 panic bug** in `http_exchanges.rs` (`s[..8]` on user-agent).
3. **Fix stale `-p netring-flow`** in 5 files (`09-low-level/*.rs`, `utilities/gen_fixtures.rs`).
4. **Fix the `threaded_slot_drain.rs` doc lie** about `Driver<E>` being `!Send`.
5. **Fix `gen_fixtures.rs` output path** (`netring-flow/tests/data/` → `tests/data/`).
6. **Fix the wrong `--features test-helpers`** in `unified_driver_demo.rs` + `accumulating_line_parser.rs` doc-comments.
7. **Dedupe** the two `## 08 — performance` headers in `examples/README.md`.

### P1 — ship before / shortly after 0.18

8. **Port pre-helper examples** to the high-level shape:
   - `http_log.rs`, `http_exchanges.rs` → `PcapFlowSource::sessions(...)`.
   - Pre-helper detection examples that hand-roll boilerplate.
9. **Standardize `main()` return type** to `Result<(), Box<dyn std::error::Error>>` across all 47 examples.
10. **Ship the 5 highest-value missing examples:**
    - `02-forensics/kerberoast_hunter.rs`
    - `02-forensics/ldap_recon_hunter.rs`
    - `02-forensics/asset_inventory.rs`
    - `03-detection/composite_c2.rs` (the SIEM pipeline)
    - `05-export/prometheus_exporter.rs` (close the metrics-feature gap)
11. **Migrate `port_scan_detector.rs`** to use the actual `PortScanDetector` (TRW) instead of hand-rolling.
12. **Delete or merge** `bandwidth_by_protocol.rs` into `bandwidth_by_app.rs`.
13. **Ship `05-export/detector_to_eve.rs`** — the bridge composition.
14. **Fix `eve_writer.rs`** — actually demonstrate `FlowDriver::with_emit_anomalies(true)` instead of mentioning it in a comment.

### P2 — ergonomic API additions (informs P1)

15. **Add per-parser `*_from_pcap` helpers** for HTTP / DNS / Kerberos / LDAP / SSH / Modbus / SMTP / FTP (A2 above).
16. **Add `flowscope::flow_summaries_from_pcap`** (A3 above).
17. **Add `Driver::run_pcap()` / drain iterator** (A1 above).
18. **Resurrect `Pipeline` builder** (A9 above) — fixes the CLAUDE.md ghost reference too.

### P3 — nice-to-have

19. **Add MITRE attribution** to each `03-detection/` example.
20. **Add false-positive paragraphs** to each `03-detection/` example.
21. **Move `sharded_capture.rs`** from `00-getting-started/` to `08-performance/`.
22. **Move `tcp_retransmit_audit.rs`** from `03-detection/` to `04-observability/`.
23. **Add the remaining missing examples** (nprint→npz, tracing subscriber, ipfix udp, pcap dir tail, from-stdin, ssh hassh demo, ml-features libsvm).
24. **Document the import-style + main-return conventions** in `examples/README.md`.

### P4 — breaking but pre-publish (would land in 0.18.0)

25. **`parse() -> Option<T>` → `Result<T, ParseError>`** across dnp3 / kerberos / ldap / smb / quic (A4 above).
26. **LDAP / Kerberos / nPrint / DNP3 remaining primitive→enum lifts** (A5 above).

---

## Summary scorecard

| Cluster | Examples | Reference-quality | Pre-helper boilerplate | Missing |
|---|---|---|---|---|
| 00-getting-started | 5 | 0 | 1 (`hello_pipeline`) | a real hello-world |
| 01-l7-logging | 5 | 3 | 2 (`http_log`, `http_exchanges`) | kerberos / ldap / ssh logs |
| 02-forensics | 5 | 2 (`smb`, `arp`) | 2 | kerberoast, ldap-recon, asset-inventory, client-fp catalog |
| 03-detection | 6 | 3 | 0 | composite_c2, tcp_evasion |
| 04-observability | 10 | 4 | 2 | (mostly internal cleanups) |
| 05-export | 5 | 4 | 0 | prometheus, tracing, detector→eve, nprint→npz, ml→libsvm, pcap-dir-tail, ipfix-udp |
| 06-custom-protocols | 3 | 3 | 0 | reorder README only |
| 07-multi-protocol | 2 | 1 | 0 | heuristic-routing here (currently in 00) |
| 08-performance | 2 | 1 | 0 | allocations-per-packet, ml-features cost |
| 09-low-level | 3 | 0 (stale crate name) | 0 | overflow-policy |
| utilities | 2 | 0 (stale) | 0 | — |

Reference-quality = uses the highest-appropriate API tier + cites
relevant external context (MITRE / RFC / plan) + clean output.

**Overall:** 21/47 examples are reference-quality, 5/47 have real
correctness issues (stale crate name + UTF-8 panic + Send lie + wrong
feature list + wrong output path), 12/47 leak pre-0.11 boilerplate
that's now fixable via shipped helpers, 9/47 need their primitive
choice corrected. Roughly 10 high-value examples are missing entirely
— 6 of them (Kerberoast, LDAP recon, asset, composite C2,
prometheus, detector→EVE) are the natural "killer demos" for the
0.18 cycle's headline features.
