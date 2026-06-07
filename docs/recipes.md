# Recipes

Patterns and worked examples for common flowscope use cases. Each
recipe is self-contained — read the heading, copy the code, adapt
to your needs. For the conceptual model, see
[`concepts.md`](concepts.md).

## Picking the right API

flowscope exposes three tiers + the underlying traits. Walk
top-to-bottom; the first "yes" picks your API.

0. **Just want a hello-world running against a pcap?**
   → `flowscope::Pipeline::builder(ext).session(parser).build()
   .run_pcap(path)`. One import (`use flowscope::prelude::*;`),
   one builder chain, one iterator. See `examples/hello_pipeline.rs`.

1. **Only care about flow lifecycle, not L7?**
   → Use `FlowTracker` directly, consume `FlowEvent`.

2. **Parsing a protocol flowscope doesn't ship?** (HTTP/2, AMQP,
   custom framed binary, …)
   → Implement `SessionParser` for TCP or `DatagramParser` for
   UDP. Pair with `FlowSessionDriver` / `FlowDatagramDriver` for
   sync use, or netring's `session_stream` / `datagram_stream`
   for async.

3. **Want typed L7 messages from a sync loop or pcap?**
   → `FlowSessionDriver` (HTTP/TLS/DNS-TCP) or
   `FlowDatagramDriver` (DNS-UDP/ICMP) — both available via the
   high-level `flowscope::Pipeline` entry point, or directly via
   their builders. For offline pcap, `Pipeline::run_pcap` and
   the `PcapFlowSource::sessions()` / `.datagrams()` one-shot
   adapters wrap them.

4. **Want a callback-shaped HTTP/TLS interface?**
   → Use the `SessionParser` shape with a consumer loop on
   `SessionEvent::Application` — the 0.9 release deleted the
   legacy `HttpFactory` / `TlsFactory` callback-handler shape
   in favour of the typed-stream API. The migration is a one-
   line change; see CHANGELOG 0.9.0 → Breaking.

5. **Want typed L7 messages from a tokio task?**
   → netring's `AsyncCapture::flow_stream(...).session_stream(...)`
   / `.datagram_stream(...)`.

6. **Need both directions of one TCP flow as one ordered byte
   stream?** (request + response transcript)
   → `netring::Conversation<K>`.

## Custom `SessionParser` for a line-based protocol

A minimal worked example. Newline-delimited input, one message
per line.

```rust,ignore
use flowscope::{FlowSide, SessionParser, Timestamp};

#[derive(Default, Clone)]
struct LineParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LineParser {
    type Message = (FlowSide, String);

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        consume_lines(&mut self.init_buf, bytes, FlowSide::Initiator)
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        consume_lines(&mut self.resp_buf, bytes, FlowSide::Responder)
    }
    fn parser_kind(&self) -> &'static str { "line" }
}

fn consume_lines(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide)
    -> Vec<(FlowSide, String)>
{
    buf.extend_from_slice(bytes);
    let mut out = Vec::new();
    while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
        let line = String::from_utf8_lossy(&buf[..nl]).into_owned();
        out.push((side, line));
        buf.drain(..=nl);
    }
    out
}
```

Key contracts:

- **Splitting invariance** — same input bytes in any chunking
  must produce the same messages.
- **No panic on garbage** — return `Vec::new()` on malformed
  input rather than panicking.
- **`#[derive(Default, Clone)]`** lets the parser act as its own
  `SessionParserFactory` via the blanket impl.

## Writing your own — full trait surface

The traits with every method explicit:

```rust,ignore
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;

    // Defaulted hooks — implement only what you need:
    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}

    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }

    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn is_done(&self) -> bool { false }

    fn parser_kind(&self) -> &'static str { "" }
}
```

| Hook | When you need it |
|------|------------------|
| `fin_*` | Protocol with EOF-terminated messages (HTTP `Connection: close`) |
| `rst_*` | Reset internal state on RST (most parsers ignore) |
| `on_tick` | Time-driven messages (DNS query timeout, heartbeat detection) |
| `is_poisoned` | Unrecoverable parse error; driver synthesises `ParseError` close |
| `is_done` | Successful completion ahead of FIN (HTTP/1.0 body done, DNS-TCP pair complete) |
| `parser_kind` | Stable slug for `SessionEvent::Application::parser_kind` routing |

`DatagramParser` mirrors the same shape with `parse(payload,
side, ts)` instead of `feed_initiator` / `feed_responder`.

## Multi-protocol monitoring

Running HTTP + TLS + DNS + ICMP against one pcap.

### Preferred — `FlowMultiSessionDriver` composite driver (0.9.0)

```rust,ignore
use flowscope::extract::FiveTuple;
use flowscope::FlowMultiSessionDriver;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::tls::{TlsMessage, TlsParser};

#[derive(Debug)]
enum L7 {
    Http(HttpMessage),
    Tls(TlsMessage),
}

let mut driver = FlowMultiSessionDriver::<_, L7>::new(FiveTuple::bidirectional())
    .with_parser_on_ports(HttpParser::default(), [80, 8080], L7::Http)
    .with_parser_on_ports(TlsParser::default(),  [443, 8443], L7::Tls);

for view in source.views() {
    for ev in driver.track(&view?) {
        // SessionEvent<K, L7>
    }
}
```

Each registered parser sees only the packets whose ports match
its routing rule. `with_parser_broadcast` registers a parser
that fires on every packet (use for ICMP).

### Legacy — one driver per parser, N pcap passes

Readable, fully decoupled, every parser sees every flow it might
apply to. Loads the pcap N times.

```rust,ignore
let source = PcapFlowSource::open(&path)?;
let mut http = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
let mut tls  = FlowSessionDriver::new(FiveTuple::bidirectional(), TlsParser::default());
let mut dns  = FlowDatagramDriver::new(FiveTuple::bidirectional(), DnsUdpParser::default());
let mut icmp = FlowDatagramDriver::new(FiveTuple::bidirectional(), IcmpParser::new());

// ... feed every view to each driver ...
```

A turnkey reference at `examples/multi_protocol_monitor.rs`:
`cargo run --features l7,pcap --example multi_protocol_monitor
-- trace.pcap`.

### Performant pattern — single pass, manual port dispatch

One pcap read, route by L4 + port:

```rust,ignore
for view in source.views() {
    let view = view?;
    let port = peek_dst_port(&view); // user-supplied helper
    match (l4_classification(&view), port) {
        (Some(L4Proto::Tcp), 80) | (Some(L4Proto::Tcp), 8080) => {
            for ev in http.track(&view) { ... }
        }
        (Some(L4Proto::Tcp), 443) => {
            for ev in tls.track(&view) { ... }
        }
        (Some(L4Proto::Udp), 53) => {
            for ev in dns.track(&view) { ... }
        }
        _ => {}
    }
}
```

## Cross-protocol correlation — DNS resolutions

flowscope ships a focused `DnsResolutionCache` for the common
*"did client X recently resolve target Y?"* pattern.

```rust,ignore
use flowscope::dns::DnsResolutionCache;
use std::time::Duration;

let mut cache = DnsResolutionCache::new(Duration::from_secs(300));

// On every DNS response message in your loop:
cache.observe_response(client_ip, &response, now);

// On every TCP/UDP flow start:
if !cache.was_resolved(client_ip, target_ip, now) {
    println!("⚠ {client_ip} → {target_ip} without DNS context");
}

// Periodically:
cache.sweep(now);
```

The cache is LRU-bounded (default 16,384 entries), records every
A/AAAA answer record, skips CNAME/NS/MX. Hostnames are
canonicalised to lowercase ASCII (RFC 1035 §2.3.1).

`was_resolved` and `lookup_name` mutate LRU order; use
`peek_resolved` / `peek_name` for read-only contexts.

## ICMP error correlation

When you see an ICMP error message, link it back to the original
TCP/UDP flow it references. The `IcmpInner` field (in error-class
variants) holds the embedded original-packet header; `error_inner()`
extracts it in one call.

```rust,ignore
use flowscope::icmp::{IcmpMessage, IcmpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::extract::FiveTuple;
use flowscope::SessionEvent;

let source = PcapFlowSource::open("trace.pcap")?
    .datagrams(FiveTuple::bidirectional(), IcmpParser::new());

for evt in source {
    if let SessionEvent::Application { message, .. } = evt? {
        if let Some((kind, inner)) = message.error_inner() {
            println!("ICMP {kind}: orig {} → {} (proto={}, {}:{} → {}:{})",
                kind,
                inner.src, inner.dst, inner.proto,
                inner.src, inner.src_port.unwrap_or(0),
                inner.dst, inner.dst_port.unwrap_or(0));
        }
    }
}
```

`is_error()` filters at the type level; `short_kind()` returns a
stable `&'static str` slug for metric labels (`"dest_unreachable"`,
`"time_exceeded"`, …).

## Snapshotting active flows

`FlowTracker::iter_active()` yields a snapshot per live flow
without touching LRU order:

```rust,ignore
let mut top: Vec<_> = driver.tracker().iter_active().collect();
top.sort_by_key(|af|
    u64::MAX - (af.stats.bytes_initiator + af.stats.bytes_responder));

println!("--- top 5 by bytes at {ts}");
for af in top.iter().take(5) {
    println!("  {:?} state={:?} l4={:?} bytes={}+{}",
        af.key, af.state, af.l4,
        af.stats.bytes_initiator, af.stats.bytes_responder);
}
```

`ActiveFlow` is `#[non_exhaustive]` — future fields are additive.

## Programmatic flow termination

`force_close(key, now)` ends a specific flow ahead of FIN/idle.
Available on the tracker and all three drivers; the driver
versions tear down parser + reassembler slots cleanly.

```rust,ignore
// Resource budget: kill flows over a per-connection byte limit.
let offenders: Vec<_> = driver
    .tracker()
    .iter_active()
    .filter(|af| af.stats.bytes_initiator + af.stats.bytes_responder > 100_000_000)
    .map(|af| *af.key)
    .collect();

for key in offenders {
    for evt in driver.force_close(&key, now) {
        // Closed event with reason=ForceClosed; parser final messages
        // (if any) come through as Application events first.
    }
}
```

## Buffer-cap pressure on the reassembler

Watch occupancy without waiting for `BufferOverflow`:

```rust,ignore
let factory = BufferedReassemblerFactory::default()
    .with_max_buffer(1024 * 1024)
    .with_overflow_policy(OverflowPolicy::SlidingWindow)
    .with_high_watermark_threshold(80);

let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory)
    .with_emit_anomalies(true);

// Now driver.track() emits FlowAnomaly { kind: ReassemblerHighWatermark }
// when any per-side buffer crosses 80% of the cap. One event per
// crossing — debounced; re-arms when occupancy drains back below.
```

## Per-flow user state via the consumer loop

The recommended pattern for rich per-flow state — counters,
state machines, derived analytics — without plumbing `&mut S`
through every parser call.

```rust,ignore
use std::collections::HashMap;

#[derive(Default)]
struct PerFlow {
    messages: u64,
    first_seen_at: Option<Timestamp>,
}

let mut state: HashMap<FiveTupleKey, PerFlow> = HashMap::new();

for ev in driver.track(view) {
    match ev {
        SessionEvent::Started { key, ts } => {
            state.insert(key, PerFlow {
                first_seen_at: Some(ts),
                ..Default::default()
            });
        }
        SessionEvent::Application { key, ts, .. } => {
            let pf = state.entry(key).or_default();
            pf.messages += 1;
            // ... whatever else you need ...
        }
        SessionEvent::Closed { key, .. } => {
            state.remove(&key);
        }
        _ => {}
    }
}
```

Why this beats `&mut S` in `feed_*`: the parser stays a pure byte
→ messages function; the state machine sees both parser output
and lifecycle events. The pattern composes with any parser shape.

If your state genuinely lives inside the parser, use the tracker's
`with_state*` constructors instead — they thread `S` through the
tracker as `FlowEntry::user`, surfaced via `iter_active()`.

## Structured event output

Three drop-in writers in `flowscope::emit` (0.10) cover the
formats every flow-analysis pipeline ends up emitting. Each
takes a `std::io::Write` sink and a
`FlowEvent<FiveTupleKey>`; the constructor writes the header
(CSV column names; Zeek `#fields` / `#types`); `finish()`
flushes and recovers the sink.

```toml
# CSV + Zeek conn.log writers — no extra deps.
flowscope = { version = "0.10", features = ["emit"] }

# NDJSON writer — adds serde_json.
flowscope = { version = "0.10", features = ["emit-ndjson"] }
```

```rust,ignore
use flowscope::emit::{FlowEventCsvWriter, ZeekConnLogWriter};

// CSV — `start_sec, end_sec, duration_sec, proto, src_ip, …, end_reason`
let mut csv = FlowEventCsvWriter::new(file)?;
for ev in driver.track(view) {
    csv.write_event(&ev)?;
}
csv.finish()?;

// Zeek conn.log — tab-separated, `zeek-cut`-compatible
let mut zeek = ZeekConnLogWriter::new(file)?;
for ev in driver.track(view) { zeek.write_event(&ev)?; }
zeek.finish()?;
```

The NDJSON writer reuses the locked 0.8 serde wire format
(snake_case + adjacent tagging):

```rust,ignore
use flowscope::emit::FlowEventNdjsonWriter;
let mut ndjson = FlowEventNdjsonWriter::new(file);
for ev in driver.track(view) { ndjson.write_event(&ev)?; }
ndjson.finish()?;
```

Wire format details (locked from 0.8):

- snake_case field names everywhere
- Tagged enums:
  - All-struct variants use internal tagging:
    `{"type": "started", "key": ..., "side": "initiator", ...}`.
  - Tuple variants use adjacent tagging:
    `{"kind": "tcp"}` / `{"kind": "other", "value": 99}`.
- `Timestamp` → `{"sec": u32, "nsec": u32}`
- `bytes::Bytes` → JSON byte array (use a base64 wrapper if
  your log shipper prefers it).

Once consumers ship dashboards depending on field names,
renames require a CHANGELOG-documented breaking change.

## Per-packet introspection — `flowscope::layers`

The 0.9 `layers` module gives every `PacketView` a zero-copy
layered view: direct typed accessors plus a dynamic walk.

```rust,ignore
use flowscope::layers::LayerKind;

for view in source.views() {
    let view = view?;
    let layers = view.layers()?;

    // Direct accessors.
    if let Some(tcp)  = layers.tcp()  { println!("seq={}", tcp.seq()); }
    if let Some(vlan) = layers.vlan() { println!("vid={}", vlan.vid()); }

    // Dynamic walk — outer to inner, tunnel-aware.
    for layer in layers.iter() {
        println!("{} ({}B)", layer.kind(), layer.bytes().len());
    }

    // Tunnel? Inner IPv4 inside VXLAN frames.
    if layers.has_tunnel() {
        let inner_ipv4 = layers.find_all(LayerKind::Ipv4).nth(1);
    }
}
```

Tunnel walking covers VXLAN (UDP/4789), GTP-U (UDP/2152), GRE,
and IP-in-IP. `layers.truncated()` flags a partial tunnel inner
re-parse (the outer layers stay accessible).

For high-throughput consumers, `LayerParser` + `LayerStack` are
the zero-allocation fast path (gopacket `DecodingLayerParser`
shape):

```rust,ignore
use flowscope::layers::{LayerParser, LayerStack, LayerKind};

let parser = LayerParser::new().only(&[LayerKind::Ipv4, LayerKind::Tcp]);
let mut stack = LayerStack::new();

for frame in frames {
    stack.reset();
    parser.parse_ethernet(&frame, &mut stack)?;
    if let Some(tcp) = stack.tcp() {
        // … per-frame zero-alloc hot path …
    }
}
```

## TLS handshakes — aggregator parser

`TlsHandshakeParser` emits one `TlsHandshake` event per
observed handshake, carrying SNI, ALPN (client + server),
JA3/JA4 (when their features are on), negotiated version,
cipher, and a `HandshakeOutcome` discriminant.

```rust,ignore
use flowscope::tls::{HandshakeOutcome, TlsHandshakeParser};
use flowscope::extract::FiveTuple;
use flowscope::{FlowSessionDriver, SessionEvent};

let mut driver = FlowSessionDriver::builder(FiveTuple::bidirectional())
    .parser(TlsHandshakeParser::default())
    .build();

for view in source.views() {
    for ev in driver.track(&view?) {
        if let SessionEvent::Application { message: hs, .. } = ev {
            println!("SNI={:?} version={:?} outcome={:?}",
                hs.sni, hs.version, hs.outcome);
            match hs.outcome {
                HandshakeOutcome::Completed => { /* … */ }
                HandshakeOutcome::AlertedByServer { description } => { /* … */ }
                _ => {}
            }
        }
    }
}
```

Build with `--features tls,ja3,ja4` to get both fingerprints
populated. `TlsHandshakeParser::default()` turns on JA3/JA4
when their features are compiled in.

## Cross-flow correlation — `flowscope::correlate`

The 0.9 `correlate` module ships three primitives for
cross-flow patterns:

- `TimeBucketedCounter<K>` — windowed per-key event counter for
  rate-limit / threshold detection.
- `KeyIndexed<K, V>` — TTL'd LRU cache for request/response
  matching.
- `SequencePattern` trait — generic FSM for event-stream
  detectors.

### Rate-limit detection

```rust,ignore
use flowscope::correlate::TimeBucketedCounter;
use std::time::Duration;

let mut counter: TimeBucketedCounter<std::net::IpAddr> =
    TimeBucketedCounter::new(
        Duration::from_secs(60),  // 60 s window
        Duration::from_secs(10),  // 10 s buckets
        10_000,                   // distinct-key cap
    );

// On every observed source IP:
counter.bump(src_ip, ts);

// Periodically check for offenders:
for (ip, count) in counter.entries_above(1_000, now) {
    println!("rate-limit hit: {ip} = {count} events / 60s");
}
```

### Request/response matching

```rust,ignore
use flowscope::correlate::KeyIndexed;
use std::time::Duration;

// Key = transaction id, value = question. 5 s TTL, 16 k cache.
let mut pending: KeyIndexed<u16, String> =
    KeyIndexed::new(Duration::from_secs(5), 16 * 1024);

// On query observed:
pending.insert(tx_id, qname, ts);

// On response observed:
if let Some(qname) = pending.get(&tx_id, ts) {
    // matched within TTL
}

// Sweep periodically:
pending.evict_expired(now);
```

### Burst-then-trigger detection

0.10 adds `BurstDetector<K, E>` for the canonical "N events
of kind X within W, optionally followed by event of kind Y"
pattern — the shape every failed-auth / port-scan /
SYN-flood detector reinvents.

```rust,ignore
use flowscope::correlate::{BurstDetector, BurstHit};
use std::time::Duration;

#[derive(Clone, PartialEq, Eq)]
enum AuthEvent { Fail, Success }

// 5 failures within 60 s followed by a success → suspicious login.
let mut d: BurstDetector<std::net::IpAddr, AuthEvent> =
    BurstDetector::new(
        AuthEvent::Fail, 5, Duration::from_secs(60),
        Some(AuthEvent::Success),
    );

for (src, evt, ts) in event_stream {
    if let Some(BurstHit { key, burst_count, .. }) = d.observe(&src, &evt, ts) {
        println!("burst hit on {key}: {burst_count} failures then success");
    }
}
```

Other 0.10 correlate primitives:

- `TimeBucketedSet<K, V>` — distinct values per key over a
  sliding window (port-scan: distinct destination ports per
  source).
- `TopK<K>` — Misra-Gries bounded top-K tracker (top noisy
  IPs).
- `Ewma<K>` — per-key exponentially weighted moving average
  (latency tracking with optional `.evict_stale(now, ttl)`).

## Distribution + quantile reports

0.10 adds `flowscope::aggregate` behind the `aggregate`
feature — `Histogram` for explicit-bucket distributions
(flow durations, packet sizes, response times) and
`Percentile` for streaming t-digest-based p95 / p99 / p999
reads on unbounded streams.

```toml
flowscope = { version = "0.10", features = ["aggregate"] }
```

```rust,ignore
use flowscope::aggregate::Histogram;

// Log-spaced buckets between 100 ms and 1 h (6 buckets + overflow).
let mut h = Histogram::log_spaced(0.1, 3600.0, 6);
for stats in flow_durations() {
    h.record(stats.duration_secs());
}
println!(
    "p50 {:.3}s   p99 {:.3}s   max {:.3}s",
    h.quantile(0.5), h.quantile(0.99), h.max(),
);
```

## Lightweight detection helpers

0.10 ships `flowscope::detect` (always on) — the small set
of detection primitives every detector example reinvented:

```rust,ignore
use flowscope::detect::{shannon_entropy, is_high_entropy, is_hex_string};

assert!(shannon_entropy(b"aaaa") < 0.1);
assert!(is_high_entropy(b"compressed-payload-bytes", 7.0));
assert!(is_hex_string("deadbeefcafebabe"));
```

`flowscope::detect::signatures` adds 10 pure-function
magic-byte recognizers (`http_request`, `tls_client_hello`,
`dns_message`, `ssh_banner`, …) — useful standalone for
"is this flow's first segment HTTP-shaped?" checks. They're
the building block for the heuristic-routing feature
shipping under plan 116.

## Protocol labels — `flowscope::well_known`

0.10 adds a curated `(L4Proto, port) → "label"` table (~70
entries: IANA-aligned plus widely-deployed cloud-native
services like Kafka, Redis, Elasticsearch, MinIO, MongoDB,
Postgres, Kubernetes API). Lookup is binary-search-based and
zero-cost on miss.

```rust,ignore
use flowscope::well_known::protocol_label;
use flowscope::L4Proto;

assert_eq!(protocol_label(L4Proto::Tcp, 33000, 80), Some("http"));
assert_eq!(protocol_label(L4Proto::Udp, 53, 33000), Some("dns"));

// Or directly off a flow key:
let label = key.protocol_label(); // FiveTupleKey method
```

The lower-numbered port disambiguates the well-known side
automatically.

## Aggregating L7 exchanges

0.10 ships per-exchange aggregator parsers for HTTP and DNS,
mirroring the 0.9 `TlsHandshakeParser` shape — one rich
event per logical exchange instead of per-message
decomposition the consumer has to stitch.

```rust,ignore
use flowscope::http::{HttpExchangeParser, HttpOutcome};

let mut driver = FlowSessionDriver::new(ext, HttpExchangeParser::new());

for ev in driver.track(view) {
    if let SessionEvent::Application { message: ex, .. } = ev {
        match ex.outcome {
            HttpOutcome::Completed if ex.is_success() => { /* 2xx */ }
            HttpOutcome::Completed if ex.is_error()   => { /* 4xx/5xx */ }
            HttpOutcome::NoResponse                   => { /* flow ended pending */ }
            HttpOutcome::Reset                        => { /* RST mid-exchange */ }
            _ => {}
        }
    }
}
```

`DnsExchangeParser` is the UDP equivalent (DNS-over-TCP
variant deferred). `DnsExchange::outcome` is one of
`Completed` / `NoResponse` / `Failed { rcode }`.

## Writing custom parsers — `AccumulatingSessionParser`

0.10 adds `flowscope::AccumulatingSessionParser<F, M>` for
the universal "accumulate bytes, repeatedly call a parser
closure, drain consumed prefix" pattern. Most custom
binary/text protocols collapse to one constructor call:

```rust,ignore
use flowscope::AccumulatingSessionParser;

#[derive(Debug, Clone)]
struct LengthPrefixed(Vec<u8>);

fn parse_one(buf: &[u8]) -> Option<(LengthPrefixed, usize)> {
    if buf.len() < 4 { return None; }
    let n = u32::from_be_bytes(buf[..4].try_into().ok()?) as usize;
    if buf.len() < 4 + n { return None; }
    Some((LengthPrefixed(buf[4..4 + n].to_vec()), 4 + n))
}

let parser = AccumulatingSessionParser::new("len-prefixed", parse_one);
```

The closure must be `Clone + Send + 'static` for per-session
reuse via the `SessionParserFactory` blanket impl. For more
control, use `BufferedFrameDrain` directly inside your own
`SessionParser` impl.

`PerDatagramParser<F, M>` is the UDP parity:
`Fn(&[u8]) -> Option<M>` → one message per datagram.

## Re-exporting flowscope types

When a downstream crate re-exports flowscope types, intra-doc
links should use the bare form, not the explicit-path form:

```rust,ignore
// In your-crate/src/lib.rs:
pub use flowscope::FlowSessionDriver;

// In your-crate's rustdoc:
/// See [`FlowSessionDriver`] for the sync session-event driver.
```

The explicit form `[FlowSessionDriver](flowscope::FlowSessionDriver)`
trips `redundant_explicit_links` under `-D warnings` because
rustdoc resolves the bare form through the re-export anyway.
