# Examples postmortem — DX pain points + 0.10 proposals

Authoring 17 new real-world examples for the 0.9 cycle surfaced
concrete friction points that didn't show up in the unit-test
phase. This document catalogs each one and proposes the API
shapes that would have made the examples shorter, more correct,
and more discoverable.

Status: working notes from the example-writing session. Not yet
adopted. Treat as input for the 0.10 plan-of-record discussion.

---

## TL;DR

Eight themes emerged across the 17 examples. Ranked by how often
they bit:

1. **`Timestamp` arithmetic is verbose.** Every example
   converting to seconds did
   `ts.sec as f64 + ts.nsec as f64 / 1e9`. Pure
   churn — needs a method.
2. **`FlowEvent::Packet` is too thin.** No TCP info, no frame
   bytes. Forces consumers into re-parsing or skipping packet
   events entirely.
3. **`FlowStats` lacks rollups.** Every example summing
   bytes/packets wrote the same
   `stats.bytes_initiator + stats.bytes_responder` expression.
4. **Discoverability of existing convenience accessors is poor.**
   I forgot `HttpRequest::host()` / `user_agent()` / `cookie()`
   exist and reinvented them in 4 examples. Found via
   `grep`, not rustdoc.
5. **`correlate` is missing common shapes.** Set-with-TTL,
   top-K-by-rate, percentile bucketers — every detector example
   reinvented one.
6. **Cross-L4 dispatch needs N drivers.** Multi-protocol
   examples ran 3–4 parallel drivers because TCP and UDP need
   separate composite types.
7. **Custom parsers lack error surfacing.** `feed_*` returns
   `Vec<Self::Message>` — no `Result`. Garbage input becomes
   empty Vec silently.
8. **Export to standard log formats is hand-rolled every time.**
   CSV, NDJSON, Zeek conn.log are 30–80 LoC of mostly mechanical
   formatting that belongs in the crate.

Below: per-example pain points → proposed fixes → suggested
sizing for the 0.10 cycle.

---

## Per-example pain log

### 0. `inspect_packet.rs` — per-packet dump

**Pain:**

- 100+ LoC of formatting because `Layer<'_>` has no
  `Display` impl. Every variant needed a `match` arm with bespoke
  formatting.
- `LayerKind` has 14 variants but no `is_l3()` / `is_l4()` /
  `is_tunnel()` predicates beyond the L-number helper.
- No way to render a layer "summary line" without writing the
  formatter myself.

**Proposed:**

```rust
// src/layers/mod.rs
impl<'a> fmt::Display for Layer<'a> {
    /// One-line summary (e.g. `ipv4 src=10.0.0.1 dst=10.0.0.2 proto=6`).
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { … }
}

impl LayerKind {
    pub const fn is_l2(self) -> bool;
    pub const fn is_l3(self) -> bool;
    pub const fn is_l4(self) -> bool;
    pub const fn is_tunnel(self) -> bool;
}
```

### 1. `port_scan_detector.rs` — TimeBucketedCounter + set

**Pain:**

- Needed "distinct destination ports per (src, dst) within
  window" — `TimeBucketedCounter` counts a single key, not a
  set per key. Ended up with a parallel `HashMap<K, BTreeSet<u16>>`
  for the set part. Verbose and unbounded in memory.
- `flowscope::correlate` has `TimeBucketedCounter` and
  `KeyIndexed` but no "TTL'd set with cardinality count".
- Extracting `(src_ip, dst_ip, dst_port)` from a packet view
  meant reaching into `layers.ipv4()`/`ipv6()` manually because
  the flow tracker's `key.a` is a `SocketAddr` (port is 0 for
  non-port flows).

**Proposed:**

```rust
// src/correlate/set.rs
/// TTL'd set keyed by K with value-set V — automatic eviction
/// of expired (K → V) pairs, cardinality count per K.
pub struct TimeBucketedSet<K, V> { … }

impl<K: Hash + Eq + Clone, V: Hash + Eq + Clone> TimeBucketedSet<K, V> {
    pub fn new(window: Duration, capacity: usize) -> Self;
    pub fn insert(&mut self, k: K, v: V, ts: Timestamp);
    pub fn cardinality(&self, k: &K, now: Timestamp) -> usize;
    pub fn entries_above(&self, threshold: usize, now: Timestamp)
        -> impl Iterator<Item = (&K, usize)>;
}
```

### 2. `top_talkers.rs` — bytes/packets aggregation

**Pain:**

- `stats.bytes_initiator + stats.bytes_responder` written
  3 times. Same for packets.
- Had to write `account()` helper and rollup HashMap manually.
- `key.a.ip()` vs `key.a` confusion — `key.a` is `SocketAddr`,
  not `IpAddr`. Caught at compile time (good) but the docs
  could prevent the slip.

**Proposed:**

```rust
// src/event.rs
impl FlowStats {
    /// `bytes_initiator + bytes_responder`.
    pub fn total_bytes(&self) -> u64;
    /// `packets_initiator + packets_responder`.
    pub fn total_packets(&self) -> u64;
    /// `retransmits_initiator + retransmits_responder`.
    pub fn total_retransmits(&self) -> u64;
    /// Retransmits as a fraction of total packets.
    pub fn retransmit_rate(&self) -> f64;
    /// `last_seen - started` as `Duration`.
    pub fn duration(&self) -> Duration;
}
```

### 3. `flow_csv_export.rs` — CSV emit

**Pain:**

- 30 LoC of `writeln!` with hand-written column list.
- `Timestamp` → seconds float was painful (see theme #1).
- `EndReason` `Debug` output is `Fin` / `Rst` / `IdleTimeout` —
  capitalized, doesn't match the snake_case wire vocabulary
  the serde feature uses.

**Proposed:**

```rust
// src/emit/csv.rs (new module behind a `csv` feature)
pub struct FlowEventCsvWriter<W: Write> { … }

impl<W: Write> FlowEventCsvWriter<W> {
    pub fn new(w: W) -> std::io::Result<Self>;  // writes header
    pub fn write<K: Serialize>(&mut self, ev: &FlowEvent<K>) -> std::io::Result<()>;
}

// src/event.rs
impl EndReason {
    /// Snake-case identifier matching the serde wire format.
    pub fn as_str(&self) -> &'static str;  // "fin", "rst", "idle_timeout", …
}
```

### 4. `flow_json_export.rs` — NDJSON emit

**Pain:**

Almost none — `serde_json::to_string(&event)` worked first try.
This is the gold-standard DX; the other emit paths should match.

**Proposed:**

```rust
// src/emit/ndjson.rs (new module behind a `ndjson` feature)
pub struct FlowEventNdjsonWriter<W: Write> { … }
// Same shape as CSV writer above — encoder choice differs.
```

### 5. `http_error_rate.rs` — per-host status tracking

**Pain:**

- I manually iterated `req.headers` for `Host`. The convenience
  accessor `HttpRequest::host()` already exists. Discoverability
  failure on my part.
- `HttpResponse::status_class()` would have replaced the
  `status / 100` match. Doesn't exist today.
- Hand-rolled the bucketing struct.

**Proposed:**

```rust
// src/http/types.rs
impl HttpResponse {
    /// 1 / 2 / 3 / 4 / 5, or `None` for non-standard codes.
    pub fn status_class(&self) -> Option<u8>;
    pub fn is_success(&self) -> bool;     // 2xx
    pub fn is_redirect(&self) -> bool;    // 3xx
    pub fn is_client_error(&self) -> bool; // 4xx
    pub fn is_server_error(&self) -> bool; // 5xx
}
```

Bigger DX win: a curated rustdoc landing page on
`flowscope::http` listing every convenience accessor at the top,
not buried in `HttpRequest`'s method list. The accessors exist;
nobody finds them.

### 6. `conversation_timeline.rs` — single-flow timeline

**Big pain.**

- `FlowEvent::Packet { side, len, ts, .. }` exposes only side
  and len. I expected TCP info (flags / seq / ack) and wrote
  the example assuming it. Compile error.
- No way to get the underlying frame bytes from a Packet
  event — they're consumed inside the tracker.
- This means **packet-level timelines aren't possible without
  re-parsing** every packet outside the tracker (which doubles
  the parse cost).

**Proposed:**

This is the single largest API gap I hit. Three options:

```rust
// Option A — fattest Packet event (breaking)
FlowEvent::Packet {
    key: K,
    side: FlowSide,
    len: usize,
    ts: Timestamp,
    /// New: per-packet protocol state.
    tcp: Option<TcpInfo>,
    /// New: tunnel chain summary, if any.
    tunnel: Option<TunnelInfo>,
}

// Option B — optional opt-in via FlowTrackerConfig
FlowTrackerConfig::emit_packet_details: bool

// Option C — a parallel event stream
FlowTracker::with_packet_listener(|view, layers| { … })
```

Option B is the least breaking. Default `false` keeps the hot
path lean; consumers who need timeline-quality events opt in.

### 7. `tcp_retransmit_audit.rs` — retransmit ranking

**Pain:**

- `stats.retransmits_initiator + stats.retransmits_responder` —
  same rollup theme as `top_talkers`.
- `(retx as f64 / total as f64) * 100.0` — would have been
  `stats.retransmit_rate() * 100.0` if the method existed.
- `key.clone()` warning even though `FiveTupleKey: Copy`. Compiler
  is right; my muscle memory was wrong.

**Proposed:** the `FlowStats` rollup helpers from theme #3 above.

### 8. `redis_protocol.rs` — custom RESP parser

**Pain:**

- `SessionParser::feed_*` returns `Vec<Self::Message>` — no
  `Result`. When I hit garbage I could either return `Vec::new()`
  silently or implement `is_poisoned()` myself. Both feel
  wrong: silent-drop hides bugs, manual poison flag is
  duplication.
- Recursive parsers (RESP arrays) need to consume bytes
  partially. The drain pattern `let n = parse_one(&buf); buf.drain(..n);`
  was awkward — easy to get wrong if `n` exceeds the buffer.
- Orphan-rule wall: I tried `impl From<std::io::Error> for
  flowscope::Error` in the example and obviously couldn't. The
  example boilerplate around this is annoying. A documented
  recipe for "how a custom example should surface flowscope::Error"
  would help.

**Proposed:**

```rust
// src/session.rs — extend SessionParser with an optional fallible variant.
pub trait SessionParser: Send + 'static {
    type Message: …;
    type Error: std::error::Error + Send + 'static = std::convert::Infallible;

    fn feed_initiator_fallible(&mut self, bytes: &[u8], ts: Timestamp)
        -> Result<Vec<Self::Message>, Self::Error>
    {
        Ok(self.feed_initiator(bytes, ts))
    }
    // … existing methods …
}
```

The drivers would route `Err` into `SessionEvent::Closed { reason:
ParseError }` automatically. Backwards compatible: existing
impls keep using `feed_initiator`; only consumers who want
fallible parsing implement the new method.

Also: a `RingBufferDrain<T>` helper struct for the common
"buffer + recursive parse + drain" idiom in custom parsers.

### 9. `tls_inventory.rs` — handshake catalog

**Pain:** none significant. `TlsHandshakeParser` shipped exactly
the surface I needed. This was the smoothest example to write
because the aggregator collapsed the multi-message correlation
problem into a single `TlsHandshake` value.

This is the pattern other L7 protocols should adopt:
`HttpExchangeParser` (request/response pair aggregator),
`DnsExchangeParser` (query/response pair aggregator).

**Proposed:**

```rust
// src/http/exchange.rs (new)
pub struct HttpExchangeParser { … }

pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub elapsed: Option<Duration>,
    pub outcome: HttpOutcome,  // Completed | NoResponse | Reset
}
```

### 10. `flow_duration_histogram.rs` — duration buckets + p50/p99

**Pain:**

- Manual histogram bucketing.
- Manual p50 / p99 / max via sort+index.
- Same `Timestamp` → f64 boilerplate.

**Proposed:**

```rust
// src/aggregate.rs (new module behind an `aggregate` feature)
pub struct Histogram { … }

impl Histogram {
    pub fn with_buckets(buckets: &[f64]) -> Self;
    pub fn record(&mut self, value: f64);
    pub fn quantile(&self, q: f64) -> f64;  // approximate
    pub fn samples(&self) -> u64;
}
```

A bigger thought: `flowscope::aggregate` should ship the
common SRE/observability data structures (counters, gauges,
histograms, percentile bucketers) keyed by flow / L4 / etc.
Most observability examples reinvented these.

### 11. `extract_iocs.rs` — multi-protocol IoC extraction

**Pain:**

- Ran four drivers in parallel: `FlowSessionDriver<HttpParser>`,
  `FlowSessionDriver<TlsHandshakeParser>`,
  `FlowDatagramDriver<DnsUdpParser>`, plus a bare `FlowTracker`
  for IPs. Each takes its own extractor instance.
- `FlowMultiSessionDriver` solves this for TCP parsers but
  doesn't span L4 — no way to register a UDP parser into the
  same composite. So I had two composite drivers worth of
  ceremony.
- Hostname extraction: 3 sources (SNI / Host header / DNS qname).
  Each one had a different access pattern; there's no
  "give me all observed hostnames as a stream" abstraction.

**Proposed:**

```rust
// src/multi_driver.rs (new — replaces multi_session_driver.rs)
pub struct FlowMultiDriver<E, M> { … }

impl<E, M> FlowMultiDriver<E, M> {
    pub fn new(extractor: E) -> Self;
    pub fn with_session_parser<P: SessionParser>(self, parser: P,
        routing: Routing, lift: impl Fn(P::Message) -> M) -> Self;
    pub fn with_datagram_parser<P: DatagramParser>(self, parser: P,
        routing: Routing, lift: impl Fn(P::Message) -> M) -> Self;
    // Single shared tracker; per-parser reassemblers as in plan 92.
}
```

This is the shared-tracker optimisation deferred from plan 92
plus the cross-L4 unification.

### 12. `layer_fast_path.rs` — zero-alloc benchmark

**Pain:**

- `LayerStack` has no `depth()` mirror of `Layers::depth()`.
  Hard to get a quick "how many layers did the fast path see"
  printout.
- `LayerParser::only(&[…])` takes a slice — would be more
  ergonomic with a bitmask const.

**Proposed:**

```rust
impl LayerStack {
    pub fn depth(&self) -> usize;  // count of populated slots
    pub fn iter_kinds(&self) -> impl Iterator<Item = LayerKind> + '_;
}

// Const masks for common configurations.
impl LayerParser {
    pub const TCP_FAST_PATH: u32 = …;  // Eth + IPv4 + TCP
    pub const HTTP_FAST_PATH: u32 = …; // Eth + IPv4 + TCP (port 80/443)
    pub fn only_mask(self, mask: u32) -> Self;
}
```

### 13. `dns_tunnel_detector.rs` — DNS tunnel detection

**Pain:**

- Wrote Shannon entropy in 13 lines. Common enough it should
  ship.
- DNS qname is `String` per question — accessing it allocates.
  A borrowed variant for hot loops would matter at scale.

**Proposed:**

```rust
// src/detect.rs (new module — small lightweight detectors)
pub fn shannon_entropy(bytes: &[u8]) -> f64;
pub fn ngram_distribution(bytes: &[u8], n: usize) -> NgramDist;
pub fn is_base64ish(s: &str) -> bool;
pub fn is_hex_string(s: &str) -> bool;
```

These are pre-1.0 add. Don't overcommit — keep it to the
half-dozen building blocks every detector reaches for.

### 14. `zeek_style_conn_log.rs` — Zeek conn.log emit

**Pain:**

- Manual `EndReason` → Zeek `conn_state` mapping. 6-line
  match.
- Manual `HistoryString` access (worked fine — already has
  `.as_str()`).
- Same Timestamp / FlowStats theme.

**Proposed:**

```rust
// src/emit/zeek.rs (new module behind a `zeek` feature)
pub struct ZeekConnLogWriter<W: Write> { … }

impl<W: Write> ZeekConnLogWriter<W> {
    pub fn new(w: W) -> std::io::Result<Self>;
    pub fn write<K: ToZeekId>(&mut self, ev: &FlowEvent<K>) -> std::io::Result<()>;
}

impl EndReason {
    pub fn to_zeek_state(&self) -> &'static str;  // SF / RSTO / S0 / REJ / OTH
}
```

`flowscope::emit::{csv, ndjson, zeek}` would absorb three of
the export examples into ~5 LoC programs.

### 15. `bandwidth_by_protocol.rs` — port → protocol label

**Pain:**

- Hard-coded port table (24 entries). Will rot as new ports
  get assigned.
- `key.a.port()` was used to pick the lower port — convoluted
  because the canonical port could be on either side.

**Proposed:**

```rust
// src/well_known.rs (new module)
pub fn protocol_label(proto: L4Proto, src_port: u16, dst_port: u16)
    -> Option<&'static str>;

pub const PORT_TABLE: &[(L4Proto, u16, &str)] = &[ … ];

impl FiveTupleKey {
    /// Lower-numbered port — the "well-known" side for client/server flows.
    pub fn well_known_port(&self) -> u16;
    /// `protocol_label(...)` for this key.
    pub fn protocol_label(&self) -> Option<&'static str>;
}
```

Curated 50–100 entry table. Update in patch releases.

### 16. `failed_auth_burst.rs` — HTTP 401 → 200 pattern

**Pain:**

- `KeyIndexed::get` takes `&mut self` (LRU recency bump).
  Awkward when the outer scope also needs `&mut` access to
  the map for `insert`. Worked around with `.cloned()`.
- `SequencePattern` trait shipped in 0.9 but I didn't reach
  for it here — the "burst-then-success" pattern is
  straightforward enough to write inline. The trait may be
  too generic for its own good; a curated set of
  pre-implemented detectors (`StateBurst`, `RateThreshold`,
  `RecurrencePattern`) would be more discoverable.

**Proposed:**

```rust
// src/correlate/sequence.rs
impl<K> KeyIndexed<K, V> {
    /// Read-only get — does NOT bump LRU recency. Cheaper
    /// when called from an outer scope already holding &mut.
    pub fn peek(&self, k: &K, now: Timestamp) -> Option<&V>;
}

// src/detect/burst.rs (new)
pub struct BurstDetector<K> { … }
// Pre-baked "N events of kind X within window then event of kind Y".
```

---

## Cross-cutting themes

### Theme 1: `Timestamp` ergonomics

Every example doing time math did:

```rust
let t = ts.sec as f64 + ts.nsec as f64 / 1e9;
```

This belongs on `Timestamp`:

```rust
impl Timestamp {
    pub fn to_unix_f64(self) -> f64;
    pub fn from_unix_f64(secs: f64) -> Self;
    pub fn relative_to(self, other: Timestamp) -> f64;  // signed delta in seconds
}
```

Also: `Timestamp` could implement `Display` as
`"{sec}.{nsec:09}"` rather than the derived `Debug` format
consumers fall back to.

### Theme 2: `FlowStats` rollups

Every aggregation example wrote
`stats.bytes_initiator + stats.bytes_responder`.

```rust
impl FlowStats {
    pub fn total_bytes(&self) -> u64;
    pub fn total_packets(&self) -> u64;
    pub fn total_retransmits(&self) -> u64;
    pub fn retransmit_rate(&self) -> f64;
    pub fn duration(&self) -> Duration;
    pub fn duration_secs(&self) -> f64;
}
```

Trivial to add, would shave 3–5 lines from every observability
example.

### Theme 3: Convenience accessor discoverability

Several examples reinvented accessors that already exist
(`HttpRequest::host`, `user_agent`, `content_type`, …). The
existence of `host()` is mentioned in the README but not in
rustdoc-visible cross-references.

Two fixes:

1. **Curated accessor index in module-level rustdoc.**
   `flowscope::http`'s top-level docs should list every shipped
   convenience accessor in a `# Convenience accessors` heading.
   Same for `flowscope::tls`, `flowscope::dns`.

2. **Examples directory `README.md` should call out which
   accessors each example uses.** Done in part by the new
   examples README; a one-line annotation per example would
   close the loop.

### Theme 4: Custom-parser ergonomics

Writing `redis_protocol.rs` exposed three friction points
beyond what's documented in `docs/recipes.md`:

1. **No fallible `feed_*` variant.** Silent-drop on garbage is
   the only documented path. Proposal in `redis_protocol`
   section above.
2. **Recursive parsers need a drain helper.** `let n =
   parse_one(&buf); buf.drain(..n);` is correct but error-prone.
3. **The `init_buf` / `resp_buf` accumulator pattern is so
   universal it should be a struct.** Every custom-protocol
   example reimplements it.

```rust
// src/session.rs
pub struct AccumulatingSessionParser<F, M> where F: Fn(&[u8]) -> Option<(M, usize)> {
    parse_fn: F,
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl<F, M> SessionParser for AccumulatingSessionParser<F, M> { … }
```

With this, the RESP example becomes:

```rust
let parser = AccumulatingSessionParser::new(|buf| parse_one(buf));
```

instead of 60 LoC of buffer management. Demonstrably worth
shipping.

### Theme 5: `correlate` is too thin

The 0.9 `correlate` module shipped three primitives. The
example-writing pass surfaced a need for at least four more:

- **TTL'd set with cardinality** (port_scan_detector)
- **Burst detector** ("N of X then Y within window" —
  failed_auth_burst)
- **Top-K by rate** (would be useful for "noisiest sources"
  detectors)
- **Sliding average / EWMA** (latency tracking)

All are 50–150 LoC standalone primitives in the same shape as
`TimeBucketedCounter`.

### Theme 6: Export / sink modules

Three examples (`flow_csv_export`, `flow_json_export`,
`zeek_style_conn_log`) are pure formatting code. Each is
~30–80 LoC.

A `flowscope::emit::{csv, ndjson, zeek}` module collapses
each example to ~10 LoC and makes the wire format part of the
project contract (not the example's).

### Theme 7: Multi-protocol unification

`FlowMultiSessionDriver` works for TCP parsers. The
`extract_iocs` example wanted "all L7 protocols, route by L4
and port" — currently requires both a `FlowMultiSessionDriver`
AND a parallel set of UDP drivers. The plan-92 follow-up of a
shared-tracker `FlowMultiDriver<E, M>` spanning both L4s is
the right shape; the example-writing confirmed this is a
common ask.

### Theme 8: Packet-event richness

`FlowEvent::Packet` is the only event without protocol-specific
detail. Every example that wanted "what happened at the packet
level on flow X" had to skip Packet events and infer from
Started/Ended/Anomaly only. The
`conversation_timeline` example is the worst offender — it
shows direction and len but not flags, so a debug-grade
timeline isn't possible.

Adding `tcp: Option<TcpInfo>` to `FlowEvent::Packet` (opt-in
via tracker config) is the highest user-facing impact change
I can think of.

---

## Sizing & 0.10 prioritization

Suggested order, by user value per LoC:

### Quick wins (each <100 LoC, <2h) — pre-0.10

| Add | Affects |
|-----|---------|
| `Timestamp::to_unix_f64()` / `from_unix_f64()` / `Display` | every example |
| `FlowStats::total_bytes()` / `total_packets()` / `total_retransmits()` / `retransmit_rate()` / `duration()` | every observability example |
| `EndReason::as_str()` (snake_case) + `as_zeek_state()` | export examples |
| `KeyIndexed::peek()` (non-mutating) | correlate consumers |
| `Layer<'_>::Display` impl | `inspect_packet` and any debug-print pattern |
| `HttpResponse::status_class()` / `is_2xx()` / `is_5xx()` | `http_error_rate` |
| `LayerStack::depth()` / `iter_kinds()` | fast-path consumers |
| `LayerKind::is_l2/l3/l4/tunnel()` predicates | `inspect_packet` |

These are pure additions; no breakage.

### Plan-sized 0.10 work

| Plan | Scope |
|------|-------|
| **101** | `flowscope::emit` — CSV / NDJSON / Zeek conn.log writers. Removes 100+ LoC of formatting from the example set. |
| **102** | `flowscope::correlate` extensions — `TimeBucketedSet`, `BurstDetector`, `TopK`, `Ewma`. |
| **103** | `flowscope::aggregate` — `Histogram`, `Percentile`, common SRE primitives. |
| **104** | `flowscope::detect` — Shannon entropy, n-gram, base64-ish heuristics. |
| **105** | `flowscope::well_known` — port → protocol label table + `FiveTupleKey::protocol_label()`. |
| **106** | `AccumulatingSessionParser` + fallible `feed_*` variant. Custom-parser ergonomics overhaul. |
| **107** | `HttpExchangeParser` / `DnsExchangeParser` aggregators, mirroring `TlsHandshakeParser`. |
| **108** | `FlowEvent::Packet` enrichment — opt-in `tcp: Option<TcpInfo>` field. Breaking under the `#[non_exhaustive]` policy (additive); consumers using `..` patterns survive. |
| **109** | `FlowMultiDriver<E, M>` — shared-tracker, spans both L4s. Subsumes `FlowMultiSessionDriver`. |
| **110** | Rustdoc landing pages — module-level "convenience accessor index" tables on `http` / `tls` / `dns`. |

### Strategic — 0.11+ cycles

| Theme | Scope |
|-------|-------|
| **`#[derive(SessionParser)]`** macro | wsdf-style declarative parsers. Mentioned in plan 93's deferred list; example-writing confirmed it would replace half the custom-protocol boilerplate. |
| **Live snapshot iterator on `FlowTracker`** | "show me the current state every N seconds" without consuming the event stream. Useful for dashboards, top-talkers-live. |
| **Threat-intel matcher primitives** | IP / hostname / fingerprint blocklist matchers. Many examples could chain to these. |
| **OpenTelemetry semantic conventions** | `metrics`/`tracing` integration is raw; OTel network-flow semantic conventions are converging in 2025. |
| **Backpressure-aware event channel** | `Pipeline` could optionally write to a bounded channel. Decouples capture from processing for crash safety. |

---

## What I did NOT find painful

Reporting the absence of pain is also signal:

- **`Pipeline` builder** — every example using `Pipeline::builder(ext).session(p).build()` was clean.
- **`flowscope::Error` matching** — the `(module, code)` pattern worked first try in every example.
- **`SessionParser` consumer loop** — `for ev in driver.track(view) { match ev { ... } }` is the right shape; nobody missed the deleted callback factories.
- **`Layers` direct accessors (`.tcp()` / `.ipv4()`)** — discoverable, did what I expected.
- **`TlsHandshakeParser`** — exemplary. The pattern other L7 aggregators should adopt.
- **`PcapFlowSource::open()`** — simple and worked.
- **`FlowMultiSessionDriver` builder chain** — readable.
- **The `flowscope::prelude`** — `use flowscope::prelude::*;` covered ~90 % of imports.

The 0.9 cycle's high-level surface choices held up. The pain is
in the next layer down: the convenience methods, the recurring
boilerplate, and the gaps in the correlate / emit / detect
catalog.

---

## Recommended 0.10 plan-of-record

If I were writing the umbrella for 0.10:

1. **Sprint 1 — Quick wins.** Ship the Timestamp / FlowStats /
   accessor / Display additions as one PR. ~300 LoC delta, zero
   breakage. Closes maybe 30 % of the example-LoC count just by
   itself.
2. **Sprint 2 — Emit module.** Plan 101. CSV / NDJSON / Zeek.
   Three of the export examples become 10-LoC programs.
3. **Sprint 3 — Correlate extensions.** Plan 102. Closes the
   pain in detector examples.
4. **Sprint 4 — Packet enrichment.** Plan 108. Largest user-
   visible impact change.
5. **Sprint 5 — Composite driver unification.** Plan 109.
   Cleans up the `extract_iocs` shape.
6. **Sprint 6 — Aggregate / Detect / Well-known.** Plans 103,
   104, 105. Smaller modules that round out the
   batteries-included story.

Total estimated 0.10 cycle: ~2,500 LoC of additions, mostly
non-breaking. Smaller than the 0.9 cycle (~5,500 LoC) because
the major architectural shifts already landed.

---

## Anti-recommendations

Some things that *look* like they'd help but I argue against:

- **Don't ship a TUI / dashboard.** Tempting after writing
  `top_talkers` — but the right level for that is a sister
  crate (`flowscope-cli`) so the core stays
  network-stack-agnostic and dep-light.
- **Don't add Lua / scripting hooks.** Real-time configurability
  is a Suricata / Zeek concern; flowscope is a library, not a
  framework. Consumers compose Rust code; runtime config
  belongs in the consumer.
- **Don't ship a built-in YARA-like rule engine.** Same
  reasoning — push rule-matching to a sister crate or a
  consumer.
- **Don't add async to flowscope core.** Already a hard rule
  in CLAUDE.md; restated here because the temptation will
  return when someone asks for "Pipeline backpressure."
  The backpressure-aware channel belongs in `netring`.
- **Don't expand `prelude` to cover everything.** It already
  covers ~90 %; adding the long-tail types makes name collisions
  worse. Keep it deliberately small.

---

## Open questions for the maintainer

1. Is **plan 108** (`FlowEvent::Packet` enrichment with TCP info)
   compatible with the 0.5.0 trait stability lock? I read the
   policy as "additive fields stay non-breaking under
   `#[non_exhaustive]`," but consumers matching on Packet
   today may not use `..` patterns. Worth double-checking.

2. The **0.9 plan 92 follow-up** (shared-tracker
   `FlowMultiSessionDriver`) is folded into plan 109 above —
   is that the right shape or do they stay separate?

3. **`flowscope::emit` module** could plausibly be a sister
   crate (`flowscope-emit`) to keep the core dep-list lean.
   Trade-off: discoverability suffers in a sister crate.

4. Should the **OpenTelemetry semantic conventions for network
   flows** wait until they're stable in 2026, or land an
   experimental adapter now?

These need a human call before they're worth planning.
