# Changelog

## Unreleased — 0.10.0 cycle (in progress)

### Added

- **Plan 116 PR 2b + Plan 113 sub-B — heuristic routing.**
  Adds four builder methods on `DriverBuilder` —
  `session_heuristic`, `session_heuristic_with_budget`,
  `datagram_heuristic`, `datagram_heuristic_with_budget` —
  that wire a payload `SignatureFn` (from plan 113 sub-A)
  into per-flow detection state. Each heuristic slot keeps a
  Probing / Pinned / GaveUp state per flow:
  - Probing: buffer up to 64 B per side; evaluate the
    signature on each side every probe packet.
  - Pinned (first `Match`): dispatch every subsequent packet
    directly to the inner driver — O(1) cost.
  - GaveUp (`max_probe_packets` exhausted with no Match): no
    further dispatch for that flow.
  `DEFAULT_PROBE_PACKETS = 4` and `PROBE_BUFFER_CAP = 64`
  constants are public for consumers wanting to scale.
- **Plan 116 PR 2a — datagram dispatch on the unified Driver.**
  Adds `DriverBuilder::datagram_on_ports` and
  `DriverBuilder::datagram_broadcast` mirroring their session
  counterparts. UDP parsers (DnsUdpParser, IcmpParser,
  PerDatagramParser, etc.) compose with TCP parsers under one
  `Driver<E, M>`. Internal `ConcreteDatagramSlot` wraps a
  `FlowDatagramDriver`; same lift-and-filter behaviour as the
  session path.
- **Plan 116 PR 1 — unified `Driver<E, M>` + `Event<K, M>`
  preview.** First step of the centerpiece API redesign that
  collapses the 0.9-era 6-driver / 4-event surface into one
  driver and one event type. Ships under
  `flowscope::driver_unified::{Driver, Event, DriverBuilder}`
  alongside the legacy `FlowSessionDriver` /
  `FlowMultiSessionDriver` / `Pipeline` types for migration.
  - `Driver::builder(extractor).session_on_ports(parser, ports,
    lift)` — port-routed session parsers.
  - `Driver::builder(extractor).session_broadcast(parser, lift)`
    — fire on every flow regardless of port.
  - `Driver::track(view) / sweep(now) / finish()` return
    `Vec<Event<K, M>>` merging the central tracker's flow
    lifecycle (`FlowStarted` / `FlowEstablished` /
    `FlowPacket` / `FlowEnded` / `FlowTick` / `FlowAnomaly` /
    `TrackerAnomaly`) with parser-sourced outputs (`Message` /
    `ParserClosed`).
  - `Event::key() / timestamp() / parser_kind() /
    anomaly_kind() / is_flow_event() / is_parser_event()`
    accessors.
  - Follow-up PRs (2-5, not yet started): UDP / datagram
    dispatch + heuristic routing; Pipeline rewrite; test +
    example migration; legacy-type deletion.
- **Plan 107 — HTTP + DNS exchange aggregators.** Mirror of the
  0.9 `TlsHandshakeParser` shape for two more L7 protocols. One
  rich event per logical exchange instead of per-message
  decomposition.
  - `HttpExchangeParser` — emits one `HttpExchange` per
    request/response pair. Handles HTTP/1.1 pipelining (FIFO
    matching). Outcomes: `Completed` / `NoResponse` / `Reset`.
    Convenience accessors: `status_class()` / `is_success()` /
    `is_error()`.
  - `DnsExchangeParser` — emits one `DnsExchange` per
    query/response pair (UDP only — TCP variant deferred).
    Built atop `DnsUdpParser` with correlation enabled.
    Outcomes: `Completed` / `NoResponse` /
    `Failed { rcode }`.
- **Plan 106 — parser ergonomics.** Three helpers for writing
  custom `SessionParser` / `DatagramParser` impls without
  reinventing the buffer + drain boilerplate that every
  custom-protocol example writes.
  - `BufferedFrameDrain<M>` — accumulate bytes, repeatedly call
    a `parse_one(&[u8]) -> Option<(M, usize)>` closure, drain
    consumed prefix, retain partial. Catches off-by-one bugs and
    poisons on overflow / zero-byte advance.
  - `AccumulatingSessionParser<F, M>` — one-line `SessionParser`
    impl wrapping two `BufferedFrameDrain`s + the closure +
    parser_kind label. Reduces ~25 LoC of boilerplate per custom
    parser to one constructor call.
  - `PerDatagramParser<F, M>` — one-line `DatagramParser` impl
    over `Fn(&[u8]) -> Option<M>` — UDP parity.
  - `FrameDrainError` for `BufferFull` / `ZeroByteAdvance`
    poison reasons; `DEFAULT_FRAME_DRAIN_MAX_BUFFER` constant
    (64 KiB) for the default per-side cap.

  Fallible `feed_*` trait extension was scoped out of this PR —
  driver-level Err routing is folded into plan 116 (unified
  Driver).
- **Plan 102 sub-A — `flowscope::correlate` extensions.** Four
  cross-flow correlation primitives that every detector example
  reinvented:
  - `TimeBucketedSet<K, V>` — TTL'd set keyed by `K` with value
    set `V`; cardinality + entries-above-threshold queries.
    For port-scan detection ("distinct destination ports per
    source within window") and DNS-tunnel detection ("distinct
    labels per source").
  - `BurstDetector<K, E>` + `BurstHit<K>` — N events of kind X
    within window, optionally followed by event of kind Y.
    Pure-burst (SYN floods) and burst-then-trigger (failed-auth
    burst → success) modes.
  - `TopK<K>` — bounded "top K by count" Misra-Gries tracker.
    Exact under capacity; bounded-error after. `.observe` /
    `.observe_n(weight)` / `.top()` / `.estimate(&K)`.
  - `Ewma<K>` — per-key exponentially weighted moving average
    with optional `.evict_stale(now, ttl)` for memory bounding.
- **Plan 113 sub-A — `flowscope::detect::signatures`.** Pure-
  function magic-byte recognizers for 10 protocols. Each
  signature returns `Match` / `NoMatch` / `NeedMoreData`; no
  state, no allocation, suitable for hot-path dispatch.
  - HTTP: `http_request` / `http_response`.
  - TLS: `tls_client_hello` / `tls_server_hello`.
  - DNS: `dns_message`.
  - Banner protocols: `ssh_banner` / `smtp_banner` /
    `ftp_banner` / `irc_message`.
  - Framed protocols: `redis_resp` / `mqtt_connect` /
    `postgres_startup`.
  - `registry()` iterates `(parser_kind, SignatureFn)` for the
    curated set — strings align with
    `flowscope::parser_kinds::*` so signature matches dispatch
    back to the existing parsers.
  - Each signature ships with a splitting-invariance test: any
    prefix of a `Match` input is `Match` or `NeedMoreData`,
    never `NoMatch`.
- **Plan 110 sub-A — rustdoc landing pages + 9 HTTP accessors.**
  Module-level rustdoc on `flowscope::http`, `flowscope::tls`,
  `flowscope::dns`, and `flowscope::icmp` now leads with a
  curated `# Convenience accessors` table listing every shipped
  accessor on the main types — same surface, much more
  discoverable. Plus 9 new accessor methods (per plan: 7; this
  release: 9 — two extras mirror existing HttpResponse helpers
  on HttpRequest):
  - `HttpRequest::referer()` / `accept()` /
    `content_type()` / `content_length()`
  - `HttpResponse::status_class()` / `is_success()` /
    `is_redirect()` / `is_client_error()` / `is_server_error()`
- **Plan 102 sub-B — `flowscope::aggregate`.** Distribution +
  quantile primitives behind a new `aggregate` Cargo feature.
  - `Histogram` — explicit-bucket counter with `record` /
    `quantile` (linear-interp) / `merge` / `buckets()` iterator,
    plus `log_spaced(low, high, count)` for geometric ranges.
    No extra deps.
  - `Percentile` — streaming quantile estimator wrapping the
    `tdigest` crate. Buffered-record API (`record` is `&mut`,
    batches into the digest in 512-sample chunks).
  - `HistogramError` for boundary-validation failures.
  - `examples/flow_duration_histogram.rs` migrated to
    `Histogram` (drops the manual bucket-loop + sort-based
    quantile).
- **Plan 102 sub-C — `flowscope::detect`.** Small toolkit of
  lightweight detection primitives every detector example
  reinvented:
  - `shannon_entropy(&[u8]) -> f64` — DNS tunnel detection,
    encoded-payload spotting.
  - `is_high_entropy(&[u8], threshold) -> bool` — entropy +
    threshold convenience.
  - `ngram_distribution(&[u8], n) -> NgramDist` — n-gram
    frequency table with built-in `mode()` / `entropy()` /
    `distinct()`.
  - `is_base64ish(&str) -> bool` — base64-shaped string
    detection (≥16 chars).
  - `is_hex_string(&str) -> bool` — hex-shaped string detection
    (≥16 chars).
  - `hamming_distance(a, b) -> Option<usize>` — fixed-length
    byte comparison.
  - `examples/dns_tunnel_detector.rs` migrated to the shipped
    `shannon_entropy` helper (drops a 19-line local copy).
- **Plan 101 — `flowscope::emit`.** Structured event sinks for
  the three log formats every flow-analysis pipeline ends up
  emitting. Each writer takes a `std::io::Write` sink and a
  `FlowEvent<FiveTupleKey>` per call; defaults to emitting only
  `FlowEvent::Ended`.
  - `FlowEventCsvWriter` — RFC-4180-quoted CSV (no extra deps).
    Behind the `emit` feature.
  - `FlowEventNdjsonWriter` — newline-delimited JSON using the
    locked snake_case wire vocabulary. Behind the `emit-ndjson`
    feature (pulls in `serde_json` + requires `serde`).
  - `ZeekConnLogWriter` — tab-separated Zeek `conn.log` rows
    with `#fields` / `#types` / `#close` headers, auto-generated
    UIDs, full `EndReason` → Zeek `conn_state` mapping. Behind
    the `emit` feature.
  - `EndReason::as_zeek_state()` — pure-function mapping
    documented stable for the 0.10 cycle.
  - The three existing examples (`flow_csv_export`,
    `flow_json_export`, `zeek_style_conn_log`) migrated to the
    new writers — each dropped from 60-100 LoC to ~15 LoC.
- **Plan 102 sub-D — `flowscope::well_known`.** Curated
  `(L4Proto, port)` → label table with ~70 entries (IANA-aligned
  plus widely-deployed cloud-native services like Kafka, Redis,
  Elasticsearch, MinIO, MongoDB, etc.). Lookup is binary-search
  based, zero-cost on miss. Lower-numbered port disambiguates
  the client/server side automatically.
  - `flowscope::well_known::protocol_label(proto, src_port, dst_port)`
    → `Option<&'static str>`.
  - `flowscope::well_known::entries()` iterates every shipped row.
  - `FiveTupleKey::well_known_port()` → lower-numbered endpoint
    port.
  - `FiveTupleKey::protocol_label()` → forwards to
    `well_known::protocol_label`.
- **Plan 110 sub-B — quick-win helper sweep.** Small additive
  helpers across `Timestamp`, `FlowStats`, `EndReason`,
  `LayerKind`, `Layer<'_>`, `LayerStack`, and `KeyIndexed`. No
  breaking changes; consumers can keep doing what they're doing
  or opt in to the new helpers as they encounter them.
  - `Timestamp::to_unix_f64()` / `from_unix_f64()` /
    `relative_to()` / `from_system_time()`. The existing
    `Display` impl is unchanged (Zeek-compatible
    `"{sec}.{nsec:09}"`).
  - `FlowStats::total_bytes()` / `total_packets()` /
    `total_retransmits()` / `retransmit_rate()` / `duration()` /
    `duration_secs()` — convenience over the per-side fields
    every consumer aggregated by hand.
  - `EndReason::as_str()` — snake-case short label (canonical
    source for the metric vocabulary and `Display` output).
    `Display` continues to render the same slug.
  - `LayerKind::is_l2()` / `is_l3()` / `is_l4()` / `is_tunnel()`
    `const` predicates — group dispatch on the layer enum
    without spelling out variants.
  - `Layer<'_>::Display` — one-line summary like
    `tcp src_port=12345 dst_port=80 seq=1000 ack=0 flags=[S]`.
    Stable, grep-friendly format for ad-hoc tracing /
    debug logs.
  - `LayerStack::depth()` / `iter_kinds()` — inspect the
    zero-alloc parser's populated slots.
  - `KeyIndexed::peek(&key, now)` — read-only `get` that does
    NOT bump LRU recency. Use when the outer scope holds
    `&self` rather than `&mut self`, or when the access is
    incidental (logging / metrics).

## Unreleased — 0.9.0 cycle (in progress)

The biggest release since 0.1: a high-level `Pipeline` entry
point, a public per-packet layered view (`flowscope::layers`),
unified errors, cross-flow correlation primitives, a composite
multi-parser driver, OOO TCP reassembly, JA4 + a TLS
handshake aggregator, packet-clock auto-sweep for live/offline
parity, MSRV 1.85 → 1.88, and removal of the legacy
callback-factory L7 APIs.

### 0.9 audit (measured against 0.8.0, 2026-06-06)

Per the umbrella that drove the cycle:

- **38 driver constructors** across the three sync driver
  structs (`FlowDriver` 6+4, `FlowSessionDriver` 10+4,
  `FlowDatagramDriver` 10+4). New
  `Driver::builder(extractor)` shape consolidates the common
  case; existing constructors stay for 0.9 (deletion deferred
  to 0.10).
- **No "start here" entry point** — every prior example began
  `FlowSessionDriver::new(…)`. The 0.9 introduces
  `flowscope::Pipeline` + `flowscope::prelude` so a new
  program needs one `use flowscope::prelude::*;`.
- **No public per-packet layered view** — `etherparse::SlicedPacket`
  was parsed internally by the FiveTuple extractor and
  discarded. The 0.9 `flowscope::layers` module exposes a
  zero-copy view with tunnel walking, ARP / MPLS / ICMP
  slices, and a `LayerParser` + `LayerStack` zero-allocation
  fast path.
- **Two duplicated L7 API shapes** — every L7 module shipped
  both a callback-style `*Factory` / `*Handler` surface and
  the strategic `SessionParser` shape. The legacy column is
  deleted (see Breaking).
- **Five separate `Error` enums** (`http::Error`, `tls::Error`,
  `dns::Error`, `pcap::Error`, `icmp::Error`) with no shared
  trait. Collapsed into one `flowscope::Error` carrying
  `Module` + `ErrorCode` + source chain.

### Added

- **`flowscope::correlate` module** (plan 81). Three composable
  primitives for cross-flow correlation patterns:
  - `TimeBucketedCounter<K>` — windowed per-key event counter
    with bucket-based aggregation (DDoS rate-limits, SYN-flood
    thresholds, "did key K cross N in W seconds").
  - `KeyIndexed<K, V>` — TTL'd LRU cache with packet-clock
    eviction (DNS query/response correlation, ICMP error tying
    back to the original flow, generic request/response
    matching).
  - `SequencePattern` trait + `KeylessSequencePattern` blanket-
    adapter — generic FSM for event-stream pattern detectors
    (port scans, "auth-failure-then-success", retry storms).
- **`FlowTracker::with_auto_sweep(interval)`** (plan 75).
  Packet-clock-driven implicit sweeps so live and offline
  pipelines emit identical event streams for identical inputs.
  Off by default. Sets `FlowTrackerConfig::auto_sweep_interval`.
  After each `track()` call, if
  `view.timestamp - last_sweep_ts >= interval`, runs an implicit
  sweep and merges its events into the returned vector. Manual
  `sweep()` resets `last_sweep_ts` so mixing manual + auto
  is safe.
- **Driver builders** (plan 94 Tier 2 partial). New
  `Driver::builder(extractor)` entry point on
  `FlowSessionDriver` + `FlowDatagramDriver`. Discoverable
  chainable shape: `.parser(p) / .config(c) /
  .emit_anomalies(b) / .monotonic_timestamps(b) / .dedup(d) /
  .idle_timeout_fn(f) / .build()`. The plan-94 Tier 2 spec
  called for collapsing all 38 driver constructors into one
  builder; this cut ships the most-discoverable entry point
  alongside the existing constructors. Constructor deletion
  is deferred to a follow-up cycle so consumers can migrate
  at their own pace.
- **`flowscope::layers` fast path** (plan 94 Tier 3 fast-path
  follow-up). Mirror of gopacket's `DecodingLayerParser`
  pattern. `LayerParser` + `LayerStack`: zero per-frame
  allocation, caller-owned scratch reusable across the
  packet loop, optional `.only(&[LayerKind…])` mask that
  skips slots the consumer doesn't care about. The
  ergonomic `Layers::parse_ethernet` path stays — the fast
  path is opt-in for consumers who have profiled and need it.
- **`SegmentBufferReassembler`** (plan 74). TCP reassembler
  with out-of-order hole-fill. Holds OOO segments in a
  `BTreeMap<start_seq, segment>` until the preceding hole is
  filled, then drains the contiguous prefix into the ready
  buffer. Segments older than `ooo_deadline` (default 1s) are
  expired; the `holes_expired` counter ticks. Defaults: 256 KiB
  OOO cap, 1s deadline, strict overlap (RFC 5722). Implements
  the [`Reassembler`] trait; pair with `FlowSessionDriver` /
  `BufferedReassemblerFactory` builders. Drop-in for binary
  protocols (HTTP/2 HPACK, TLS record alignment) where
  `BufferedReassembler`'s OOO-drop strategy desyncs the parser.
- **`FlowMultiSessionDriver<E, M>`** (plan 92). Composite
  driver running N session parsers against the same packet
  stream in one pass. Each registered parser observes packets
  matching its routing rule:
  - `.with_parser_on_ports(parser, ports, lift)` — fires when
    `dst_port ∈ ports || src_port ∈ ports`.
  - `.with_parser_broadcast(parser, lift)` — fires on every
    packet matching the flow's L4.
  Each parser's emitted messages are lifted to a user-supplied
  sum type `M` via the registration-time closure; events are
  merged in registration order. The 0.9 implementation runs
  parallel `FlowSessionDriver` instances internally (one per
  parser), trading the shared-tracker storage optimisation
  from the plan for ergonomic simplicity; this is documented
  inline and the optimisation can land in a follow-up.
- **TLS modernization** (plan 97). Two TLS additions behind
  Cargo features:
  - **`ja4` Cargo feature** — JA4 client fingerprint (FoxIO
    v1, 2023): cipher / extension sorting + GREASE removal +
    human-readable header (`t13d1516h2_8daaf6152771_b186095e22b6`).
    Public `flowscope::tls::ja4::ja4()` / `ja4_parts()`.
    Pulls `sha2` only when the feature is on.
  - **`TlsHandshakeParser`** — `SessionParser` that aggregates
    ClientHello + ServerHello + Alert into one `TlsHandshake`
    event per handshake. Carries SNI, ALPN (client + server),
    JA3/JA4 (when features on), negotiated version, cipher,
    `resumption_attempted`, and a `HandshakeOutcome` discriminant
    (`Completed` / `AlertedByServer` / `AlertedByClient` /
    `Truncated`). Reuses the existing `TlsParser` internally.
    `parser_kind()` returns `"tls-handshake"`.
  - `TlsConfig.ja4: bool` defaults to `false`.
  - `TlsMessage::Ja4 { fingerprint }` joins the existing
    `TlsMessage::Ja3 { … }` shape on the per-message stream.
- **`flowscope::layers` extensions** (plan 94 Tier 3 follow-up).
  Tunnel walking for VXLAN (UDP/4789), GTP-U (UDP/2152), GRE,
  and IP-in-IP — `Layers::has_tunnel()` / `Layers::truncated()`
  signal the outcome. New slice types: `ArpSlice`, `MplsSlice`,
  `Icmpv4Slice`, `Icmpv6Slice`, `GreSlice`, `VxlanSlice`,
  `GtpUSlice`. New convenience accessors: `.arp()`, `.mpls()`,
  `.icmpv4()`, `.icmpv6()`, `.gre()`, `.vxlan()`, `.gtpu()`.
  Inline `SmallVec` capacity grew from 6 → 8 to cover the
  outer-Eth+IP+UDP+VXLAN + inner-Eth+IP+TCP+Payload tunnel
  case without spilling.
- **`Pipeline::reset()` + `Pipeline::run_iter(iter)`** (plan 94
  Tier 1 follow-up). `reset()` drops per-flow tracker state so
  the same Pipeline can be re-run against multiple sources.
  `run_iter` drives the pipeline over any `IntoIterator<Item =
  OwnedPacketView>` — useful for custom sources (eBPF
  userspace, embedded, synthetic / test fixtures, netring's
  batched recv re-rolled into owned views). `OwnedPacketView`
  promoted from `pcap::source` to `view.rs` so `run_iter` is
  usable without the `pcap` feature.
- **`flowscope::layers` module** (plan 94 Tier 3). Public per-
  packet introspection: `Layers<'a>` with direct accessors
  (`.tcp()`, `.ipv4()`, `.vlan()`, …) and a dynamic walk
  (`iter` / `find` / `find_all` over `LayerKind`). Built atop
  `etherparse::SlicedPacket` with flowscope-shaped slice types
  (`TcpSlice`, `UdpSlice`, `Ipv4Slice`, `Ipv6Slice`,
  `EthernetSlice`, `VlanSlice`). Constructed via
  `PacketView::layers()` or `Layers::parse_ethernet` /
  `parse_ip`. Coverage in this first cut: Ethernet + VLAN
  (single + Q-in-Q) + IPv4/IPv6 + TCP (with options iterator) +
  UDP. Tunnel walking (VXLAN/GTP-U/GRE), ARP, ICMP slices, and
  a zero-allocation `LayerParser` fast path are scoped for
  follow-ups.
- **`flowscope::Pipeline` high-level entry point** (plan 94
  Tier 1). One import, one builder chain, one iterator over a
  unified `Event<K, SM, DM>` enum. Bundles
  `FlowSessionDriver` + `FlowDatagramDriver` with sensible
  defaults (anomalies emitted, monotonic timestamps for offline
  replay). Constructed via
  `Pipeline::builder(extractor).session(p).build()` /
  `.datagram(p)`. Runs via `pipeline.run_pcap("trace.pcap")`.
  Power users continue to drop down to the underlying drivers.
- **`flowscope::prelude` module**. `use flowscope::prelude::*;`
  imports `Pipeline`, `FiveTuple`, `FlowEvent`, `SessionEvent`,
  `Timestamp`, `Error`, `Result`, `Layers`, the protocol
  parsers, and the rest of the common surface so a
  hello-world program needs one `use`.

### Breaking

- **Callback-factory L7 APIs removed** (plan 94 acceptance).
  The legacy `HttpFactory` / `HttpReassembler` / `HttpHandler`
  and `TlsFactory` / `TlsReassembler` / `TlsHandler` types are
  deleted. They predated the strategic `SessionParser` trait
  (0.1.0) and have been redundant since. Every callback use
  case is strictly subsumed by a `SessionParser` + a consumer
  loop on `SessionEvent::Application`. Migration:

  ```diff
  - use flowscope::http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
  - use flowscope::FlowDriver;
  -
  - struct Logger;
  - impl HttpHandler for Logger {
  -     fn on_request(&self, req: &HttpRequest) { /* … */ }
  -     fn on_response(&self, resp: &HttpResponse) { /* … */ }
  - }
  -
  - let factory = HttpFactory::with_handler(Logger);
  - let mut driver = FlowDriver::new(ext, factory);
  - for view in source.views() {
  -     for _ev in driver.track(&view?) { /* lifecycle only */ }
  - }
  + use flowscope::extract::FiveTuple;
  + use flowscope::http::{HttpMessage, HttpParser};
  + use flowscope::{FlowSessionDriver, SessionEvent};
  +
  + let mut driver = FlowSessionDriver::new(ext, HttpParser::default());
  + for view in source.views() {
  +     for ev in driver.track(&view?) {
  +         if let SessionEvent::Application { message, .. } = ev {
  +             match message {
  +                 HttpMessage::Request(r)  => { /* … */ }
  +                 HttpMessage::Response(r) => { /* … */ }
  +             }
  +         }
  +     }
  + }
  ```

  Same shape for TLS: `TlsFactory` / `TlsHandler` →
  `TlsParser` + `for ev in driver.track(…)` consumer loop with
  `TlsMessage::ClientHello` / `ServerHello` / `Alert` arms.
  For one-shot handshake aggregation, use the new
  `TlsHandshakeParser` (plan 97).
- **MSRV bumped 1.85 → 1.88** (plan 99). Rust 1.88 (June 2025)
  stabilised let-chains at expression position
  (`if let Some(a) = x && let Some(b) = y { … }`), which
  flowscope's source already uses in several spots. The bump
  formalises the requirement and clears the way for an idiom
  sweep across the rest of the codebase. AFIT (1.75), async
  closures (1.85), and trait upcasting (1.86) are also
  available within the new MSRV.
- **Error types unified into `flowscope::Error`** (plan 96). The
  five module-local enums (`http::Error`, `tls::Error`,
  `dns::Error`, `pcap::Error`, `icmp::Error`) are removed.
  Every fallible flowscope API now returns
  `flowscope::Result<T>` (alias for `Result<T, flowscope::Error>`).
  `Error` carries a `Module`, an `ErrorCode`, a human-readable
  message, and an optional `source` chain to the upstream
  parser library's error type.

  *Migration:*
  ```diff
  - match err {
  -     flowscope::http::Error::Parse(s)          => log::warn!("http parse: {s}"),
  -     flowscope::http::Error::BufferOverflow(n) => log::error!("http overflow at {n}"),
  - }
  + use flowscope::{Module, ErrorCode};
  + match (err.module(), err.code()) {
  +     (Module::Http, ErrorCode::Parse)          => log::warn!("http: {err}"),
  +     (Module::Http, ErrorCode::BufferOverflow) => log::error!("http: {err}"),
  +     _ => {}
  + }
  ```

  Walk the underlying parser error with
  `std::error::Error::source()`. Display format is
  `"{module}: {code}: {message}"` — not API-stable, do not
  parse.

## 0.8.0 — serde, force_close, iter_active, ICMP helpers, DnsResolutionCache (2026-06-06)

Driven by the `netring` consolidated wishlist (2026-06-06,
after three prior feedback rounds). Pre-1.0 breaking changes;
`netring` updates in lockstep.

### Breaking

- **`FlowEvent::Established` gains a `l4: Option<L4Proto>` field**
  (plan 87). Rounds out the trio with `Started` (0.4.0) and
  `Ended` (0.7.0); same shape, same mechanical migration.
  *Migration:*
  ```diff
  - FlowEvent::Established { key, ts } => …
  + FlowEvent::Established { key, ts, l4 } => …
    // or
  + FlowEvent::Established { key, ts, .. } => …
  ```

### Deprecated

- **`FlowTracker::all_flow_stats`** in favour of
  [`FlowTracker::iter_active`] (plan 90). One-line migration; the
  new method exposes per-flow user state, TCP state, and L4
  protocol in addition to stats. Removal targeted for 0.9 or 0.10.

### Added

- **`serde` Cargo feature** (plan 83) — opt-in `Serialize` +
  `Deserialize` derives on every public event, message,
  accessor, and configuration type. **Locked wire vocabulary
  from 0.8 forward**: snake_case field / variant names; enums
  with payloads use adjacent tagging (`{"kind": "tcp"}` /
  `{"kind": "other", "value": 99}`); enums with all struct
  variants use internal tagging (`{"kind": "out_of_order_segment",
  "side": "initiator", "count": 5}`); `Timestamp` serializes as
  `{"sec": u32, "nsec": u32}`. Once shipped, dashboards depend
  on these names — renames require a CHANGELOG-documented
  breaking change. Adds `serde_json` / `bytes,serde` /
  `arrayvec,serde` / `smallvec,serde` transitive feature
  enablement. New CI feature-matrix entries: `serde` standalone
  + `serde,l7,pcap` combined.
- **Multi-protocol monitor recipe + example** (plan 91).
  `examples/multi_protocol_monitor.rs` demonstrates running
  HTTP + TLS + DNS + ICMP parsers against a single pcap with
  correlated (timestamp-merged) output. SESSION_GUIDE gains a
  "Multi-protocol monitoring" section covering both the simple
  "every parser, every pass" pattern and the performant manual-
  dispatch pattern. A full composite driver (wishlist B2) is
  deferred to a 0.9 RFC; this recipe is the recommended pattern
  until then.
- **`flowscope::dns::DnsResolutionCache`** (plan 85). TTL'd
  per-client DNS resolution cache for cross-protocol correlation:
  `"did client X recently resolve target Y?"` / `"what hostname
  did X use for Y?"`. Records every A / AAAA answer; skips
  CNAME / NS / MX. LRU-bounded (default 16,384 entries); periodic
  `sweep(now)` drops expired entries. Hostnames canonicalised to
  lowercase ASCII (RFC 1035 §2.3.1). Two netring detectors already
  hand-rolled this primitive; this lifts it once.
- **`FlowTracker::force_close` + driver mirrors + `EndReason::ForceClosed`**
  (plan 89). External orchestration can now end a specific flow
  ahead of FIN / idle / eviction. Use cases: resource budgets,
  test harnesses, rate limiters. Driver-level mirrors
  (`FlowDriver::force_close`, `FlowSessionDriver::force_close`,
  `FlowDatagramDriver::force_close`) tear down the parser +
  reassembler slots before emitting the terminal event. New
  `flowscope_flows_ended_total{reason="force_closed"}` metric label.
- **`FlowTracker::iter_active() -> impl Iterator<Item = ActiveFlow<'_, K, S>>`**
  (plan 90). Snapshots every live flow with key + stats + user
  state + TCP state + L4 protocol. `ActiveFlow` is
  `#[non_exhaustive]` named-struct so future fields stay
  non-breaking. LRU order untouched (uses `peek`-equivalent
  iteration).
- **`IcmpType::is_error()`, `error_inner()`, `short_kind()` +
  mirrors on `IcmpMessage`** (plan 84). `is_error` returns true
  for the seven error-class variants (Destination Unreachable,
  Redirect, Time Exceeded, Parameter Problem on v4; the v6
  counterparts plus Packet Too Big). `error_inner` returns
  `(label, &IcmpInner)` in one call — saves the 40-LoC manual
  match every ICMP-correlation consumer was writing.
  `short_kind` returns the stable variant slug as `&'static str`
  for metric labels (v4 and v6 variants with the same semantics
  share the same slug; `family` field disambiguates).
- **`AnomalyKind::short_kind() -> &'static str`** (plan 88).
  Stable variant slug returned for explicit metric-label intent.
  Same string as `Display`; pick whichever expresses your call
  site's intent.
- **`PARSER_KIND` / `PARSER_KIND_UDP` / `PARSER_KIND_TCP`
  constants per parser module + `flowscope::parser_kinds`
  umbrella re-export** (plan 86). Use the constants at match
  sites in place of `"http/1"` / `"dns-udp"` / `"tls"` / etc.
  string literals so typos fail to resolve (compile error)
  rather than silently miss at runtime. Each parser's
  `parser_kind()` impl now returns its module constant —
  single source of truth.

## 0.7.0 — ICMP parser, HTTP accessors, anomaly severity (2026-05-23)

Driven by the `netring` round-2 retrospective (2026-05-29, after
writing four L7 examples against 0.6). Pre-1.0 breaking changes;
`netring` updates in lockstep.

### Breaking

- **`FlowEvent::Ended` and `SessionEvent::Closed` gain a
  `l4: Option<L4Proto>` field** (plan 79). Mirrors the `l4` field
  already present on `FlowEvent::Started`; saves the per-consumer
  `HashMap<K, L4Proto>` workaround for "what protocol was this
  flow?" Pre-1.0 variant-field addition.
  *Migration:* update destructure patterns to bind or ignore the
  new field:
  ```diff
  - FlowEvent::Ended { key, reason, stats, history } => …
  + FlowEvent::Ended { key, reason, stats, history, l4 } => …
    // or
  + FlowEvent::Ended { key, reason, stats, history, .. } => …
  ```
  Same change applies to `SessionEvent::Closed`. New tracker
  accessor `FlowTracker::snapshot_l4(key)` populates the field on
  driver-synthesised Ended events (`BufferOverflow` / `ParseError`
  / `ParserDone`).

### Added

- **`flowscope::icmp` module + `icmp` Cargo feature** (plan 76).
  `IcmpParser` is a `DatagramParser` over ICMPv4 + ICMPv6,
  emitting a unified `IcmpMessage { family, ty }`. Type coverage
  via etherparse: v4 Echo Request/Reply, Destination Unreachable,
  Redirect, Time Exceeded, Parameter Problem, Timestamp; v6
  Destination Unreachable, Packet Too Big, Time Exceeded,
  Parameter Problem, Echo Request/Reply, plus manually-parsed
  Neighbor Solicitation / Advertisement. Other types surface as
  `Other { raw_type, raw_code, raw_body }`. **`IcmpInner`** —
  the killer feature for cross-protocol correlation — extracts
  `(src, dst, proto, src_port, dst_port)` from the embedded IP
  header in ICMP error messages, letting consumers tie ICMP
  errors back to the specific TCP/UDP flow they reference. The
  `l7` umbrella feature now includes `icmp`. Feature-matrix CI
  gains an `icmp`-standalone entry.
- **`SessionParser::is_done()` / `DatagramParser::is_done()`** +
  **`EndReason::ParserDone`** (plan 80). Reverses the 0.6 decline
  of round-1 #10. Lets a parser signal completion ahead of
  FIN/idle (HTTP/1.0 after body, DNS-over-TCP after Q/R pair,
  framed protocols with session-end sentinels). Default `false`;
  the driver checks after every `feed_*` / `parse` / `on_tick`.
  Poison precedence: a parser that's both poisoned AND done
  surfaces as `ParseError`. `OneShotSessionParser` /
  `OneShotDatagramParser` ship in `test_helpers` for driver
  integration tests. New `reason="parser_done"` label on
  `flowscope_flows_ended_total`.
- **`AnomalyKind::severity() -> Severity`** (plan 82). Defaulted
  classification: routine TCP noise (`OutOfOrderSegment`,
  `RetransmittedSegment`) → `Info`; cap / eviction pressure →
  `Warning`; parser poison → `Error`. `critical` reserved for
  future use. `Severity` is `Ord` so threshold filters compile
  directly (`kind.severity() >= Severity::Warning`). The
  `flowscope.anomaly` tracing target gains a structured
  `severity` field for subscriber routing.
- **HTTP and TLS convenience accessors** (plan 78). On
  `HttpRequest`: `host()`, `user_agent()`, `cookie()`. On
  `HttpResponse`: `content_type()`, `content_length()` (parsed
  `u64`), `set_cookie()` (iterator over multiple values). Both
  gain `header(name)` and `headers_all(name)` for arbitrary
  case-insensitive (RFC 7230 §3.2) lookup. `TlsClientHello::sni()`
  mirrors the `sni` field for accessor symmetry. Saves the
  `find().and_then(str::from_utf8)` dance every L7 example was
  carrying.
- **`impl Display` for `L4Proto`, `EndReason`, `AnomalyKind`**
  (plan 77). Rendered strings match the existing metric-label
  vocabulary (`tcp`/`udp`/`other`, `fin`/`rst`/`idle`/…,
  `buffer_overflow`/`ooo_segment`/…), so logs and Prometheus
  scrapes use the same tokens. Saves the `match l4 { … }`
  boilerplate that every consumer was writing against 0.6.
- **Intra-doc-link recipe in `docs/SESSION_GUIDE.md`** (plan 62).
  Closes a partial-implementation gap from the 0.6 cycle: the
  recipe shipped to `CLAUDE.md` (in-repo only); downstream
  re-exporters (`netring`, sister crates) read docs.rs and the
  crates.io package. Now in published reference material with a
  crate-level rustdoc breadcrumb for discoverability. CLAUDE.md
  collapses to a pointer so the source of truth doesn't drift.

## 0.6.0 — Driver state restore, anomaly split, watermark threshold (2026-05-23)

Driven by the `netring` 0.14.0 integration feedback (2026-05-22).
Pre-1.0 breaking changes; `netring` updates in lockstep.

This cycle was developed in parallel with the 0.5.0 release
(TCP rich diagnostics / FlowTick / parser_kind) which shipped
from a separate feedback source; the breaking-change notes below
are relative to 0.5.0.

### Breaking

- **Drivers regain the `S` per-flow-user-state type parameter
  (partial reversal of plan 32).** `FlowDriver<E, F>` →
  `FlowDriver<E, F, S = ()>`; same on `FlowSessionDriver` and
  `FlowDatagramDriver`. Existing call sites are **unchanged**: the
  common `new` / `with_config` constructors live on a pinned
  `impl<E, F> FlowDriver<E, F, ()>` block, so inference picks
  `S = ()` without an annotation. Advanced consumers (notably
  `netring`) can now drop their custom driver clones — every
  per-flow-state use case goes through the drivers again. New
  constructors: `with_state`, `with_state_and_config` (for
  `S: Default`), and `with_state_init`, `with_state_init_and_config`
  (custom init via `FnMut(&E::Key) -> S`). `tracker()` /
  `tracker_mut()` return `&FlowTracker<E, S>` again.
  *Migration:* code that explicitly named `FlowDriver<E, F>` /
  `FlowSessionDriver<E, P>` / `FlowDatagramDriver<E, P>` should
  either stay the same (the `S = ()` default kicks in) or be
  written explicitly as `FlowDriver<E, F, ()>`. Code that wants
  per-flow state switches from a hand-rolled `FlowTracker` + parser
  dispatch to the appropriate `with_state*` constructor.
- **`Anomaly { key: Option<K> }` split into `FlowAnomaly` +
  `TrackerAnomaly` on both `FlowEvent` and `SessionEvent`** (plan
  43). Per-flow anomalies (`BufferOverflow`, `OutOfOrderSegment`,
  `SessionParseError`, `ReassemblerHighWatermark`) land in
  `FlowAnomaly { key, kind, ts }`; tracker-global anomalies
  (`FlowTableEvictionPressure`) land in `TrackerAnomaly { kind, ts }`.
  Removes the `if let Some(k) = key` plumbing from every consumer.
  `FlowEvent` gains `#[non_exhaustive]` (was missing); both events
  gain a defaulted `anomaly_kind()` accessor for kind-only routing.
  *Migration:* replace `SessionEvent::Anomaly { key: Some(k), kind,
  ts } => …` with `SessionEvent::FlowAnomaly { key, kind, ts } =>
  …`, and `Anomaly { key: None, .. }` with `TrackerAnomaly { kind,
  ts }`.

### Added

- **`FlowTracker::finish()`** — `sweep(Timestamp::MAX)` under a
  readable name. Plan 33 added `finish()` to the drivers; plan 39
  brings the tracker to parity.
- **`FlowTracker::sweep_with_parsers`** and
  **`sweep_with_datagram_parsers`** — bake the on_tick choreography
  from the drivers into reusable helpers. Direct-tracker consumers
  (multi-stream wrappers, future custom drivers) drop their
  hand-rolled "sweep → on_tick → translate ended" boilerplate.
  Callback-shaped (`FnMut(&K, FlowSide, P::Message, Timestamp)`);
  per-flow parser map stays caller-owned for full construction-
  policy flexibility.
- **`l7` umbrella feature** — `flowscope = { version = "0.5",
  features = ["l7"] }` enables `http` + `tls` + `dns` together.
  Strict subset of `full` (no `pcap`, no observability).
- **CI feature-matrix** (internal): the workflow now runs
  library-only build + clippy across six partial-feature
  combinations to catch latent cfg dead-code at PR time.
- **`AsPacketView` trait + blanket `From<&T>` impl for
  `PacketView`** (plan 50). Foreign owned-packet types (netring's
  `OwnedPacket`, pcap-rs `Packet`, anything else) opt in with three
  lines and feed `tracker.track(&owned)` directly. Generalises 0.4's
  explicit `From<&OwnedPacketView>` (which is now an
  `AsPacketView` impl, going through the blanket). Existing call
  sites continue to compile via the blanket.
- **`flowscope::test_helpers::{NoopSessionParser,
  NoopDatagramParser, EchoSessionParser}`** (plan 59), under the
  existing `test-helpers` feature. Absorbs trait-shape evolution
  for downstream test crates: every minor that touches the parser
  trait shape no longer needs a sweep of hand-rolled noop stubs in
  consumer code.

### Breaking (minor)

- The explicit `impl From<&OwnedPacketView> for PacketView` from
  0.4 is removed in favour of `impl AsPacketView for OwnedPacketView`
  + the new blanket `impl<T: AsPacketView> From<&T> for
  PacketView<'_>` (plan 50). Existing `tracker.track(&owned)`
  calls go through the blanket and are unaffected. Only callers
  that named the explicit `From` impl by path are affected
  (extremely unlikely outside flowscope's own internals).

### Added (continued)

- **`AnomalyKind::ReassemblerHighWatermark { side, bytes, cap,
  threshold_pct }`** plus `BufferedReassembler::with_high_watermark_threshold(percent)`
  and the matching `BufferedReassemblerFactory` /
  `FlowTrackerConfig::reassembler_high_watermark_pct` knobs (plan
  44). Fires a `FlowAnomaly` once per below→above transition of
  the configured cap percentage (debounced; re-arms after the
  buffer drains below). Lets operators see cap pressure building
  before `BufferOverflow` bites. `Reassembler` trait grows
  defaulted `bytes_in_flight`, `high_watermark_crossings`, and
  `high_watermark_threshold` accessors (third-party impls
  unaffected).
- **`FlowSessionDriver::with_factory` /
  `FlowSessionDriver::with_state_factory` (and the
  `*_and_config` variants); same on `FlowDatagramDriver`** (plan
  58). Accept an `FnMut(&E::Key) -> P` closure per flow instead of
  cloning a template. Drops the `P: Clone` bound when constructed
  via the factory path — useful for parsers with expensive setup
  (compiled regex sets, ML model weights, big cipher tables) where
  the heavy state is shared via `Arc` and the per-flow handle is
  cheap. Existing `new` / `with_state*` ctors are unchanged.

## 0.5.0 — TCP rich diagnostics, periodic ticks, parser kinds (2026-05-28)

Driven by the `simple-nms` upstream wishlist (2026-08-11); the
two-consumer signal on the periodic-tick ask (also from `des-rs`
2026-05-14) reversed the previous snapshot-only stance.

### Breaking

- **`Reassembler::segment` takes a `ts: Timestamp`.** The new
  parameter is the carrying packet's kernel/source timestamp;
  `BufferedReassembler` uses it only to forward classified
  retransmits to `on_duplicate`. Pre-1.0 trait break per the BC
  policy.
  *Migration:* one-line signature update on every
  `Reassembler::segment` impl. Existing in-tree impls
  (`HttpReassembler`, `TlsReassembler`, `NoopReassembler`) take
  `_ts: crate::Timestamp` and ignore it.
- **`TcpInfo` is `#[non_exhaustive]`.** Closes an oversight from
  the 0.2.0 project-wide pass. External consumers always read the
  struct, so the change is benign in practice; internal
  constructors use struct-literal syntax.
- **`SessionEvent::Application` gains a `parser_kind: &'static
  str` field.** Variant-field addition — destructuring patterns
  need a new field name or `..`.
  *Migration:*
  ```diff
  - SessionEvent::Application { key, side, message, ts } => ...
  + SessionEvent::Application { key, side, message, ts, parser_kind } => ...
  + // OR
  + SessionEvent::Application { key, side, message, ts, .. } => ...
  ```

### Added

- **TCP retransmit classification.** `BufferedReassembler`
  distinguishes retransmits (`seq + len <= expected_seq`,
  including partial overlap) from strict OOO segments
  (`seq > expected_seq`) using wrap-aware sequence-space
  comparison. New `Reassembler::retransmits()` accessor and
  `on_duplicate(seq, payload, ts)` default-no-op hook let custom
  reassemblers track and react.
- **`AnomalyKind::RetransmittedSegment { side, count }`** —
  coalesced per (flow, side) per tick.
- **`FlowStats::retransmits_{initiator,responder}`** —
  populated by `FlowDriver::finalize_ended_flows` and
  `snapshot_flow_stats`.
- **`TcpInfo::window: u16`** — raw TCP receive window from the
  header (unscaled; window-scale tracking is a future plan).
- **Periodic `FlowEvent::Tick { key, stats, ts }` /
  `SessionEvent::FlowTick`** (opt-in via
  `FlowTrackerConfig::flow_tick_interval: Option<Duration>`,
  default `None`). The driver emits one Tick per live flow per
  interval, driven by packet timestamps (no wall-clock
  dependency). `stats` carries reassembler-patched diagnostics —
  same shape as `Ended.stats`.
- **`SessionParser::parser_kind` / `DatagramParser::parser_kind`**
  trait methods (default `""`). Shipped parsers report
  `http/1`, `tls`, `dns-udp`, `dns-tcp`. The length-prefixed
  example reports `length-prefixed`. Threaded into every
  `SessionEvent::Application::parser_kind`.
- **Metrics**:
  - `flowscope_retransmits_total{side=...}` — cumulative
    classified retransmits at `Ended`.
  - `flowscope_flow_ticks_total` — Tick emission counter.
  - New `retransmit` label on `flowscope_anomalies_total{kind}`.

### Fixed

- **Reassembly-diagnostic metrics on natural flow end.** The
  tracker called `record_flow_ended` from inside
  `track_with_payload` / `sweep` *before* the driver patched in
  reassembler-derived `FlowStats` fields, so
  `flowscope_reassembly_dropped_ooo_total`,
  `flowscope_reassembly_bytes_dropped_oversize_total`, and
  `flowscope_reassembler_high_watermark_bytes` always saw zeroes
  on FIN/RST/idle ends. Split into a new
  `record_reassembly_diagnostics` call fired from
  `finalize_ended_flows` after patching.

### Docs

- **SESSION_GUIDE.md**:
  - New "Updating per-flow state from parser messages" subsection
    documenting the canonical consumer-loop pattern that obviates
    threading `&mut S` through `SessionParser::feed_*`. The
    `simple-nms` wishlist's F1.4 ask is addressed here.
  - "Periodic flow ticks" subsection.
  - "Reassembly health" extended with retransmit + watermark
    fields and the new `Reassembler::segment(ts)` signature.
  - Trait-shape reference block updated with `parser_kind`.
- **OBSERVABILITY.md** — three new metric rows and corresponding
  Prometheus sample queries.
- Annotated responses to the simple-nms wishlist items F1.1–F1.7
  threaded into the per-plan commit messages and SESSION_GUIDE
  sections.

## 0.4.0 — API ergonomics (2026-05-20)

Driven by the audit in
[`docs/API-ERGONOMICS-REVIEW.md`](docs/API-ERGONOMICS-REVIEW.md).
Pre-1.0 breaking changes; `netring` and other consumers update in
lockstep.

### Breaking

- **Drivers lose the `S` per-flow-user-state type parameter.**
  `FlowDriver<E, F, S>` → `FlowDriver<E, F>`,
  `FlowSessionDriver<E, P, S>` → `FlowSessionDriver<E, P>`,
  `FlowDatagramDriver<E, P, S>` → `FlowDatagramDriver<E, P>`. The
  drivers always run their tracker with `S = ()`; per-flow user
  state remains on `FlowTracker<E, S>` for code that builds the
  tracker directly. This removes the `<_, ()>` /
  `<FiveTuple, _, ()>` annotation that type-parameter-default
  inference forced on every construction site.
  *Migration:* delete the trailing `, ()` from any explicit driver
  type; for per-flow user state, use `FlowTracker` directly.
- **`FlowSessionDriver` / `FlowDatagramDriver` constructors take the
  parser by value.** `new(extractor)` → `new(extractor, parser)`;
  `with_config(extractor, config)` → `with_config(extractor,
  parser, config)`. The parser bound relaxes from `Default + Clone`
  to just `Clone`, so non-`Default` (config-built) parsers now
  work.
  *Migration:* `FlowSessionDriver::<_, P>::new(ext)` →
  `FlowSessionDriver::new(ext, P::default())`.
- **`SessionParser` / `DatagramParser` data methods take a
  timestamp.** `feed_initiator` / `feed_responder` / `parse` gain a
  `ts: Timestamp` parameter — the observed time of the carrying
  packet — so stateful parsers can timestamp their messages and do
  time-driven correlation.
  *Migration:* add `_ts: Timestamp` (or `ts` if you use it) to every
  `feed_*` / `parse` implementation.
- **DNS-over-UDP unified on `DnsUdpParser`; `DnsUdpObserver` and the
  `DnsHandler` trait are removed.** `DnsUdpParser` is now a struct —
  construct it via `DnsUdpParser::new()` / `::with_correlation()` /
  `::with_config()`, not the bare `DnsUdpParser` literal.
  `with_correlation()` folds in the query/response correlation the
  observer used to own: `DnsResponse::elapsed` carries RTT, and
  `on_tick` emits the new `DnsMessage::Unanswered` variant.
  `DnsMessage` is now `#[non_exhaustive]`.
  *Migration:* replace `DnsUdpObserver` + `FlowTracker` + the
  hand-rolled `sweep_unanswered` timer with
  `FlowDatagramDriver::new(extractor, DnsUdpParser::with_correlation())`
  — or `PcapFlowSource::datagrams(...)` for offline pcap. The
  `DnsHandler` callbacks (`on_query` / `on_response` /
  `on_unanswered`) become `DnsMessage::{Query, Response,
  Unanswered}` match arms; periodic `sweep()` / `finish()` drives
  `on_tick`.

### Added

- **`SessionParser::on_tick` / `DatagramParser::on_tick`** — a
  defaulted periodic hook the drivers call on every `sweep` /
  `finish`, for every live parser (including one a sweep is about to
  close). Lets a parser emit time-driven messages — timeouts,
  unanswered requests — attributed to the initiator side. Default:
  no-op, so existing parsers are unaffected.

- **`finish()` on all three drivers** — `FlowDriver::finish()`,
  `FlowSessionDriver::finish()`, `FlowDatagramDriver::finish()`.
  Sweeps every still-open flow to its end; call once when input is
  exhausted. Equivalent to `sweep(Timestamp::MAX)` — replaces the
  ad-hoc "sweep with a far-future timestamp" pattern.
- **`Timestamp::MAX`** — the maximum representable timestamp
  (`u32::MAX` seconds), for forcing an end-of-input flush.
- **`track()` accepts `impl Into<PacketView>`** on `FlowTracker`,
  `FlowDriver`, `FlowSessionDriver`, and `FlowDatagramDriver`, plus a
  new `impl From<&OwnedPacketView> for PacketView`. A pcap
  `&OwnedPacketView` can be passed straight to `track()` — no
  `.as_view()`. Existing `track(packet_view)` calls are unaffected
  (`Into` is reflexive); `OwnedPacketView::as_view()` is retained.
- **`PcapFlowSource::sessions()` / `datagrams()`** — one-step
  offline L7 pipelines. `sessions(extractor, parser)` returns an
  iterator of typed `SessionEvent`s straight from a pcap, with the
  end-of-input flush folded in; `datagrams()` is the UDP mirror.
  Brings offline HTTP/TLS/DNS to the one-expression bar that
  `with_extractor()` already set for `FlowEvent`s.

## 0.3.0 — Production hardening

Eleven sub-plans driven by external feedback from the `des-rs`
team (2026-05-14) plus four planning-review additions. The plans
themselves have been pruned from `plans/` (shipped → deleted
convention); the implementation is in `git log` under the
`plan NN:` commit prefixes.

### Highlights

- **Live `FlowStats` snapshots** (Plan 46)
  via `FlowDriver::snapshot_flow_stats()` and
  `FlowSessionDriver::snapshot_flow_stats()`. Lazy iterator
  returning `(K, FlowStats)` with reassembler diagnostics
  patched in. Use `.collect::<Vec<_>>()` for the snapshot-
  everything case; `.take(1)` / `.filter()` consumers pay
  nothing for the rest.
- **Reassembler high-watermark** on `FlowStats` (peak buffer
  occupancy per side). Useful for tuning
  `max_reassembler_buffer`. New
  `flowscope_reassembler_high_watermark_bytes` metric (histogram).
- **Per-key idle timeouts** (Plan 47)
  via `FlowTracker::set_idle_timeout_fn(F)` and the matching
  `with_idle_timeout_fn(F)` builders on both drivers. Plus
  `FiveTupleKey::either_port(u16) -> bool` helper for the
  canonical port-based override case.
- **Monotonic timestamps** (opt-in,
  Plan 48) via
  `with_monotonic_timestamps(true)`. Clamps NIC timestamps to a
  running max — useful when downstream consumers want a strictly
  non-decreasing timeline.
- **Sync-side dedup** (Plan 49)
  via the new `flowscope::Dedup` primitive and
  `with_dedup(Dedup::loopback())` builder on both drivers.
  Content-hash + length + time-window match; ~1.2 µs per
  1500-byte frame.
- **`FlowDatagramDriver`** (Plan 57)
  — sync mirror of netring's `datagram_stream` for UDP-based
  `DatagramParser`s.
- **`SessionEvent::Anomaly`** forwarding
  (Plan 51) +
  `FlowSessionDriver::with_emit_anomalies(true)`. Plus an
  internal refactor: `FlowSessionDriver` now wraps `FlowDriver`
  for single source of truth on anomaly / overflow synthesis.
- **Parser fallibility** (Plan 55)
  via `SessionParser::is_poisoned()` / `poison_reason()` (mirror
  on `DatagramParser`). On poison, the driver synthesises
  `Ended { reason: ParseError }` plus optional
  `Anomaly { kind: SessionParseError, .. }`.
- **`tracing-messages` sub-feature** (Plan 56)
  — emit `tracing::trace!` per `SessionEvent::Application`.
  Off by default; targets `flowscope.message`.
- **Criterion benchmark harness** (Plan 54)
  under `benches/` with five groups (extractor, tracker,
  reassembler, session_driver, dedup). Documented baselines in
  [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md). Plan 41's
  hot-cache claim verified at ~1.4× monoflow vs 10k-flow
  round-robin.
- **Round-trip CI fixture** (Plan 52)
  — `tests/round_trip.rs` exercises
  synthesize→pcap→PcapFlowSource→FlowSessionDriver→assert
  byte-equality across hand-written + proptest cases.
- **SessionParser author guide**
  (Plan 53) — new
  walkthrough section in `docs/SESSION_GUIDE.md` covering the
  trait contract, partial-buffer pattern, resync strategies,
  and testing approach.

### Breaking changes

Pre-1.0 release; these are minor breaks that pay off in
long-term API quality:

- **`SessionEvent` is now `#[non_exhaustive]`** with a new
  `Anomaly` variant. External `match` blocks need a wildcard
  arm.
- **`EndReason` is now `#[non_exhaustive]`** with a new
  `ParseError` variant. External `match` blocks over
  `EndReason` need a new arm (treat it like `Rst` for
  cleanup semantics).
- **`SessionParser::Message` and `DatagramParser::Message`**
  gain a `Debug` trait bound (was just `Send + 'static`). All
  four shipped parsers + the example parser already derive
  `Debug`; external impls add one derive line.
- **`Reassembler` trait gains a `high_watermark()` method**
  with a default-zero impl. Existing impls compile unchanged;
  custom reassemblers can override to surface their own peak.
- **`SessionParser` / `DatagramParser` gain `is_poisoned()` +
  `poison_reason()`** methods with default impls (`false` /
  `None`). Existing impls compile unchanged.

Internal-only:
- **`FlowSessionDriver` is rewired** to wrap `FlowDriver`
  internally. Public signature unchanged; consumers using the
  type alias / generic shape need a recompile.
- **`FlowDriver::track` split into `track_pending` +
  `finalize`** for callers that need access to reassemblers
  between segment dispatch and Ended-event finalization. The
  high-level `track` and `sweep` methods keep the existing
  one-shot semantics.

### New API

- `flowscope::FlowDatagramDriver<E, P, S>` — sync UDP driver.
- `flowscope::Dedup` — content-hash dedup primitive.
- `flowscope::IdleTimeoutFn<K>` — predicate type alias for
  per-key idle-timeout overrides.
- `FlowTracker::all_flow_stats()` — borrow-iterator over live
  FlowStats.
- `FlowTracker::set_idle_timeout_fn` / `clear_idle_timeout_fn`.
- `FlowDriver::snapshot_flow_stats()` / `with_idle_timeout_fn`
  / `with_dedup` / `with_monotonic_timestamps` /
  `track_pending` / `sweep_pending` / `finalize` /
  `reassembler` / `drain_buffer` / `emits_anomalies` / `dedup`.
- `FlowSessionDriver::snapshot_flow_stats` /
  `with_idle_timeout_fn` / `with_dedup` /
  `with_monotonic_timestamps` / `dedup`.
- `FiveTupleKey::either_port(u16) -> bool`.
- `BufferedReassembler::high_watermark()` /
  `Reassembler::high_watermark()` trait method.
- `Timestamp::saturating_sub(other) -> Duration`.
- `EndReason::ParseError`.
- `AnomalyKind::SessionParseError { side, reason }`.
- `flowscope::obs::METRIC_REASSEMBLER_HIGH_WATERMARK`.

### Migration

Most consumers need only a recompile. The exhaustive-match
fixes:

```diff
- match reason {
-     EndReason::Fin => ...,
-     EndReason::Rst => ...,
-     EndReason::IdleTimeout => ...,
-     EndReason::Evicted => ...,
-     EndReason::BufferOverflow => ...,
- }
+ match reason {
+     EndReason::Fin => ...,
+     EndReason::Rst => ...,
+     EndReason::IdleTimeout => ...,
+     EndReason::Evicted => ...,
+     EndReason::BufferOverflow => ...,
+     EndReason::ParseError => ..., // treat like Rst
+     _ => ..., // future variants land in 0.4.0+
+ }

- match event {
-     SessionEvent::Started { .. } => ...,
-     SessionEvent::Application { .. } => ...,
-     SessionEvent::Closed { .. } => ...,
- }
+ match event {
+     SessionEvent::Started { .. } => ...,
+     SessionEvent::Application { .. } => ...,
+     SessionEvent::Closed { .. } => ...,
+     SessionEvent::Anomaly { .. } => ..., // new in 0.3.0
+     _ => ..., // forward-compatible
+ }
```

For external `SessionParser` / `DatagramParser` impls whose
`Message` type didn't derive `Debug`:

```diff
- #[derive(Clone)]
+ #[derive(Debug, Clone)]
  struct MyMessage { ... }
```

## 0.2.0 — Reassembly observability + metrics/tracing hooks

This minor release ships the bundle described in
Plan 42:
optional buffer caps on `BufferedReassembler`, end-of-flow reassembly
diagnostics on `FlowStats`, and a live `FlowEvent::Anomaly` stream.
It also adds opt-in `metrics` + `tracing` features (Plan 40)
that share the same `AnomalyKind` vocabulary, plus a hot-cache
fast-path on `FlowTracker` (Plan 41).
The motivating consumer is [`des-rs`](https://github.com/p13marc/des-rs)'s
`tools/des-capture`, which can now drop its hand-rolled
`TcpStreamTracker` in favour of flowscope.

### Highlights

- **`BufferedReassembler::with_max_buffer(n)`** — optional per-side
  byte cap, paired with **`with_overflow_policy(...)`** to choose:
  - `OverflowPolicy::SlidingWindow` (default) — drop oldest bytes
    from the buffer; flow stays alive; parser sees a gap and must
    resync. Best for stream-shaped / append-only protocols.
  - `OverflowPolicy::DropFlow` — poison the reassembler; the driver
    synthesises an `Ended { reason: EndReason::BufferOverflow }`
    event on the next tick. Best for framed binary protocols (DES
    PSMSG, TLS records, length-prefixed wire formats).
- **Reassembly diagnostics on `FlowStats`** — four new fields
  (`reassembly_dropped_ooo_initiator/responder`,
  `reassembly_bytes_dropped_oversize_initiator/responder`) populated
  by `FlowDriver` when each flow ends.
- **Live `FlowEvent::Anomaly`** — opt-in via
  `FlowDriver::with_emit_anomalies(true)`. Emits one `AnomalyKind`
  per (flow, side, kind) per tick:
  - `BufferOverflow { side, bytes, policy }`
  - `OutOfOrderSegment { side, count }`
  - `FlowTableEvictionPressure { evicted_in_tick, evicted_total }` —
    tracker-global signal that `max_flows` is the bottleneck.

### Breaking changes

- **`#[non_exhaustive]`** applied project-wide to every public
  struct/enum that's likely to grow over time. From now on, additive
  changes are unconditionally non-breaking.
  Affected types: `FlowStats`, `FlowTrackerConfig`, `AnomalyKind`,
  `OverflowPolicy`. Construct via `::default()` and mutate; do not
  rely on struct-literal construction from outside the crate.
- **`FlowEvent::key()`** now returns `Option<&K>` (was `&K`).
  `None` is reserved for tracker-global anomalies (e.g.
  `FlowTableEvictionPressure`); per-flow events still return
  `Some(key)`. Migrate via `event.key().expect("non-anomaly")` or
  pattern-match.
- **`EndReason`** gained a new `BufferOverflow` variant. Any
  exhaustive `match EndReason { ... }` needs a new arm. Treat it
  like `Rst` for cleanup semantics (the driver does).
- **`Reassembler` trait** gained three default-zero diagnostic
  methods (`dropped_segments`, `bytes_dropped_oversize`,
  `is_poisoned`). Existing impls compile unchanged; surface real
  counts by overriding.

### Observability hooks (Plan 40)

- New optional `metrics` Cargo feature: counters, gauges, and
  histograms wired through `FlowTracker` and `FlowDriver`. Metric
  vocabulary documented in [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).
- New optional `tracing` Cargo feature: structured events at flow
  lifecycle transitions and on every emitted anomaly.
- Both features are zero-cost when off (compile-time stubbed).
- Public metric-name constants exported from `flowscope::obs`
  (`METRIC_FLOWS_CREATED`, `METRIC_ANOMALIES`, …).

### Sync session driver + worked example (Plan 25)

- **`FlowSessionDriver<E, P, S>`** — the sync mirror of netring's
  async `session_stream`. Bundles `FlowTracker` + per-(flow, side)
  `BufferedReassembler` + per-flow `SessionParser` and yields
  `SessionEvent`s without a runtime dependency. Honours
  `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`
  automatically.
- **`examples/length_prefixed_pcap.rs`** — end-to-end example of
  writing a custom `SessionParser` for a length-prefixed binary
  protocol (PSMSG-shaped). Demonstrates partial-header / partial-body
  buffering and pairs with a deterministic pcap fixture under
  `tests/fixtures/length_prefixed/`.
- New integration test `tests/length_prefixed_example.rs` verifies
  the parser against the fixture and against byte-by-byte sliced
  input.

### Performance (Plan 41)

- `FlowTracker` gains a "last flow seen" hot-cache that skips the
  hash lookup when consecutive packets share a key. Estimated 2x
  throughput on monoflow workloads (single iperf3 / HTTP/2 stream),
  small win on heterogeneous traffic. No API impact.

### New API

- `flowscope::OverflowPolicy` (`SlidingWindow`, `DropFlow`).
- `flowscope::AnomalyKind` (non_exhaustive).
- `BufferedReassembler::with_max_buffer` /
  `with_overflow_policy` / `bytes_dropped_oversize` / `is_poisoned`.
- `BufferedReassemblerFactory::with_max_buffer` /
  `with_overflow_policy`.
- `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`.
- `FlowTracker::snapshot_stats(&K)` /
  `snapshot_history(&K)` / `forget(&K)` — accessors used by the
  driver to synthesise `BufferOverflow` end events.
- `FlowDriver::with_emit_anomalies(bool)`.
- `FlowEvent::Anomaly { key, kind, ts }`.
- `FlowSessionDriver<E, P, S>` — sync session driver that bundles
  `FlowTracker` + per-(flow, side) reassembler + per-flow
  `SessionParser`. The sync mirror of netring's `session_stream`.
- `flowscope::obs` module — `metrics` / `tracing` hook surface plus
  the public metric-name constants.

### Migration

Most consumers need only:

```diff
- let cfg = FlowTrackerConfig { max_flows: 100, ..Default::default() };
+ let mut cfg = FlowTrackerConfig::default();
+ cfg.max_flows = 100;
```

(Within the same crate, struct-literal syntax with `..Default::default()`
keeps working — `non_exhaustive` only restricts external constructors.)

If you destructure or pattern-match `FlowEvent::Ended { stats: FlowStats { ... } }`,
add `..` to the inner pattern:

```diff
- FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, ... } } => ...
+ FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, .. } } => ...
```

If you call `event.key()` and treat the return as a borrow:

```diff
- let k: &K = event.key();
+ let k: Option<&K> = event.key();
```

---

## 0.1.0 — Initial release

`flowscope` is a passive flow & session tracking library extracted
from the previous `netring-flow{,-http,-tls,-dns,-pcap}` workspace
into a single, publishable crate with feature-gated modules. The
core layers (extractor → tracker → reassembler → session/datagram
parsers) are runtime-free and cross-platform; protocol parsers are
opt-in via Cargo features.

### Core

- `PacketView` / `Timestamp` — abstract input.
- `FlowExtractor` trait + built-in extractors: `FiveTuple`, `IpPair`,
  `MacPair`. Decap combinators: `StripVlan`, `StripMpls`, `InnerVxlan`,
  `InnerGtpU`, `InnerGre`. Combinator: `AutoDetectEncap` (tries
  plain → VLAN → MPLS → VXLAN → GTP-U → GRE in order). Key
  augmentation: `FlowLabel<E>` (IPv6 flow label).
- `FlowTracker<E, S>` — bidirectional flow accounting, TCP state
  machine (`SynSent → Established → FinWait → Closed` + `Reset`),
  per-protocol idle timeouts (Suricata defaults), LRU eviction.
  `manual_tick(now)` alias for `sweep`.
- `FlowEvent<K>` — `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with `EndReason`, `FlowStats`, `HistoryString`).
- `Reassembler` / `ReassemblerFactory<K>` — sync per-(flow, side) TCP-
  segment hook; `BufferedReassembler` built-in.
- `FlowDriver<E, F, S>` — sync wrapper combining tracker + reassembler.
- `SessionParser` / `DatagramParser` (with `*Factory<K>` companions
  and blanket impls for `Default + Clone` parsers) — typed L7 message
  parsing per flow. Trait shape stable for the 1.0 lock; future
  additions will be additive.
- `SessionEvent<K, M>` — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.

### Protocol parsers (each behind its own feature)

- **`http`** — HTTP/1.0 / HTTP/1.1 via `httparse`. Both
  `HttpFactory` (callback-style) and `HttpParser` (`SessionParser`)
  ship side by side. Pipelined messages, split segments, and
  Connection: close bodies handled.
- **`tls`** — passive TLS handshake observer. `TlsFactory`
  (callback) and `TlsParser` (`SessionParser`) emit ClientHello /
  ServerHello / Alert events. Records past ChangeCipherSpec are
  silently skipped (encrypted). Optional `ja3` sub-feature for JA3
  fingerprinting (GREASE stripped per RFC 8701).
- **`dns`** — DNS message parser. UDP path: `DnsUdpObserver`
  (callback-style tap on top of any `FlowExtractor`) and
  `DnsUdpParser` (`DatagramParser`). TCP path: `DnsTcpParser`
  (`SessionParser`, RFC 1035 §4.2.2 length-prefixed framing).
  Per-flow query/response correlator with 16-bit transaction ID
  scoping, oldest-first eviction on overflow, sweep for unanswered
  timeouts.
- **`pcap`** — `PcapFlowSource` for offline replay; produces views &
  flow events from any `.pcap` file.

### Tokio integration

For an async stream over flow / session / datagram events, see
[`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`,
`.session_stream`, `.datagram_stream`, and `.broadcast`. The traits
they consume live in this crate; the Stream impls live in `netring`.

### Tests

- 167 unit tests + 11 parser proptests (splitting invariance and
  no-panic across HTTP / TLS / DNS-UDP / DNS-TCP) + tracker
  proptests (FiveTuple canonicalization, TCP state-machine
  invariants).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo doc --all-features --no-deps` clean.

### Documentation

- [`docs/SESSION_GUIDE.md`](docs/SESSION_GUIDE.md) — decision-flow
  for picking between `FlowEvent`, `Reassembler`, `*Factory<H>`,
  `SessionParser`, `DatagramParser`, and `Conversation<K>`. Includes
  migration recipes from callback-style factories to the typed-stream
  parser API.

### Notes

- This crate replaces `netring-flow`, `netring-flow-http`,
  `netring-flow-tls`, `netring-flow-dns`, and `netring-flow-pcap`
  (none of which were ever published to crates.io). Migration:
  rename your dep to `flowscope` and update import paths from
  `netring_flow_http::X` → `flowscope::http::X` (and similarly for
  `tls` / `dns` / `pcap`). Trait names and types are unchanged.
- Out of scope for v0.1.0:
  - HTTP/2, HTTP/3 (no plan yet).
  - DoH / DoT / DoQ (no plan yet).
  - NetFlow / IPFIX export (plan 32, deferred).
  - Observability (`metrics` / `tracing` integration; plan 40,
    deferred).
  - Zero-copy reassembly (plan 41, deferred — needs profiling-guided
    redesign).
  - IPv6 fragment reassembly (plan 50.5, deferred).
  - `protolens` companion (plan 21, on demand).
  - CLI tooling (`flow-summary`, `flow-replay`; plan 60, would need
    workspace conversion).
