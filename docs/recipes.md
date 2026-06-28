# Recipes

Patterns and worked examples for common flowscope use cases. Each
recipe is self-contained — read the heading, copy the code, adapt
to your needs. For the conceptual model, see
[`concepts.md`](concepts.md).

## Picking the right API

flowscope exposes two tiers + the underlying traits. Walk
top-to-bottom; the first "yes" picks your API.

0. **Want typed L7 messages with zero per-packet allocation?**
   → `flowscope::driver::Driver<E>`. Register one or more
   parsers via `builder.session_on_ports(p, [ports])` etc.;
   each call returns a `SlotHandle<P::Message, E::Key>`. Per
   packet: `driver.track_into(view, &mut events)` +
   `slot.drain(&mut msgs)`. Handles are `Send + Sync` (0.12).

1. **Only care about flow lifecycle, not L7?**
   → Use `FlowTracker` directly, consume `FlowEvent`. Cheapest
   path; no reassembler, no parsers.

2. **Parsing a protocol flowscope doesn't ship?** (HTTP/2, AMQP,
   custom framed binary, …)
   → Implement `SessionParser` for TCP or `DatagramParser` for
   UDP. Register it on the typed `Driver` with
   `Driver::builder(ext).session_on_ports(p, ports)` (or
   `datagram_on_ports` for UDP), or use netring's
   `session_stream` / `datagram_stream` for async.

3. **Need per-flow user state (`S` parameter)?**
   → Keep that state on `FlowEntry::user` via `FlowDriver`, or
   maintain it in your own consumer loop keyed by the flow key.
   The typed `Driver` runs parsers with `S = ()`.

4. **Want typed L7 messages from a tokio task?**
   → Move the `SlotHandle` to the task (it's `Send + Sync`
   since 0.12) and drain on a worker thread, OR use netring's
   `AsyncCapture::flow_stream(...).session_stream(...)` /
   `.datagram_stream(...)` from the start.

5. **Need both directions of one TCP flow as one ordered byte
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
| `parser_kind` | Stable slug surfaced on `Event::ParserClosed::parser_kind` (register one slot per parser to route by protocol) |

`DatagramParser` mirrors the same shape with `parse(payload,
side, ts)` instead of `feed_initiator` / `feed_responder`.

## Multi-protocol monitoring

Running HTTP + TLS + DNS + ICMP against one pcap.

### Preferred — `Driver<E>` with multiple typed slots (0.11+)

```rust,ignore
use flowscope::driver::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::tls::{TlsMessage, TlsParser};
use flowscope::dns::DnsUdpParser;
use flowscope::PacketView;

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
let mut tls_slot  = builder.session_on_ports(TlsParser::default(),  [443, 8443]);
let mut dns_slot  = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
let mut driver = builder.build();

let mut events  = Vec::new();
let mut http_m  = Vec::new();
let mut tls_m   = Vec::new();
let mut dns_m   = Vec::new();

for owned in source.views() {
    let owned = owned?;
    events.clear();
    http_m.clear();
    tls_m.clear();
    dns_m.clear();
    driver.track_into(PacketView::from(&owned), &mut events);
    http_slot.drain(&mut http_m);
    tls_slot.drain(&mut tls_m);
    dns_slot.drain(&mut dns_m);
    // process the typed per-parser drains independently
}
```

Each slot is independently typed (`SlotHandle<HttpMessage, _>`
vs `SlotHandle<TlsMessage, _>`) — no sum-type enum, no lift
closures. Slots only see packets matching their port routing;
`session_broadcast(p)` / `datagram_broadcast(p)` registers
parsers that fire on every flow (use for ICMP or
heuristic-routed parsers).

`session_heuristic(p, signature_fn)` / `datagram_heuristic` —
introduced via `flowscope::detect::signatures` — runs the
signature against each new flow's initial bytes; pins to the
parser when it matches, gives up after the configured probe
budget. Useful for non-standard ports.

The typed `Driver` already does single-pass, port-routed
dispatch: one pcap read, each parser only sees the flows matching
its registered ports. There is no longer a separate "one driver
per parser, N passes" shape — register every parser as a slot on
one `Driver` as shown above.

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
use flowscope::icmp::IcmpParser;
use flowscope::pcap;

// `datagram_messages` yields (key, message) for any DatagramParser
// with a Default — the public offline message iterator.
for (_key, message) in pcap::datagram_messages::<IcmpParser>("trace.pcap")? {
    if let Some((kind, inner)) = message.error_inner() {
        println!("ICMP {kind}: orig {} → {} (proto={}, {}:{} → {}:{})",
            kind,
            inner.src, inner.dst, inner.proto,
            inner.src, inner.src_port.unwrap_or(0),
            inner.dst, inner.dst_port.unwrap_or(0));
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
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};

#[derive(Default)]
struct PerFlow {
    messages: u64,
    first_seen_at: Option<Timestamp>,
}

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut slot = builder.session_on_ports(MyParser::default(), [PORT]);
let mut driver = builder.build();

let mut state: HashMap<FiveTupleKey, PerFlow> = HashMap::new();
let mut events = Vec::new();
let mut msgs = Vec::new();

// Per packet:
events.clear();
msgs.clear();
driver.track_into(view, &mut events);
slot.drain(&mut msgs);

for ev in &events {
    match ev {
        Event::Started { key, ts, .. } => {
            state.insert(key.clone(), PerFlow {
                first_seen_at: Some(*ts),
                ..Default::default()
            });
        }
        Event::Ended { key, .. } => {
            state.remove(key);
        }
        _ => {}
    }
}
for m in &msgs {
    let pf = state.entry(m.key.clone()).or_default();
    pf.messages += 1;
    // ... whatever else you need ...
}
```

Why this beats `&mut S` in `feed_*`: the parser stays a pure byte
→ messages function; the state machine sees both parser output
and lifecycle events. The pattern composes with any parser shape.

If your state genuinely lives inside the parser, use the tracker's
`with_state*` constructors instead — they thread `S` through the
tracker as `FlowEntry::user`, surfaced via `iter_active()`.

## Structured event output

Four drop-in writers in `flowscope::emit` (0.10 + 0.12) cover the
formats every flow-analysis pipeline ends up emitting. Each
takes a `std::io::Write` sink and a
`FlowEvent<FiveTupleKey>`; the constructor writes the header
(CSV column names; Zeek `#fields` / `#types`); `finish()`
flushes and recovers the sink.

```toml
# CSV + Zeek conn.log writers — no extra deps.
flowscope = { version = "0.18", features = ["emit"] }

# NDJSON writer — adds serde_json.
flowscope = { version = "0.18", features = ["emit-ndjson"] }

# Suricata 7.x EVE JSON — adds serde_json (0.12).
flowscope = { version = "0.18", features = ["emit-eve"] }
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

### EVE JSON (Suricata schema) — 0.12

For SIEM-shaped output that drops into Filebeat's Suricata
module, Splunk Suricata TA, Tenzir's `read_suricata`, or any
ECS-converting pipeline, use `EveJsonWriter` (`emit-eve`
feature). Three EVE `event_type` shapes are produced:

- `"flow"` for `FlowEvent::Ended` (per-flow rollup with
  pkts_toserver / pkts_toclient / bytes / start / end / age /
  reason).
- `"anomaly"` for `FlowAnomaly` / `TrackerAnomaly` (Suricata-
  shaped `anomaly.{type, event, code}` + `severity` numeric).
- `"stats"` for `FlowEvent::Tick` (off by default — opt in
  with `EveOptions::include_stats`).

```rust,ignore
use flowscope::emit::{EveJsonWriter, EveOptions};

let mut opts = EveOptions::default();
opts.in_iface = "eth0".to_string();
let mut eve = EveJsonWriter::with_options(file, opts);

for ev in driver.track(view) {
    eve.write_event(&ev)?;
}
eve.finish()?;
```

When built with the `community-id` feature, every record carries a
`community_id` field — Corelight Community ID v1, the portable
cross-tool flow identifier (Zeek / Suricata / Security Onion all
pivot on it), deterministic and direction-invariant. Use it as the
stable correlation key across pipelines. (Before 0.19 this was a
proprietary FNV-1a `flow_hash`; that field was dropped in issue #88
— the FNV hash remains available in-process as
`KeyFields::stable_hash()` but is no longer emitted.)

Custom flow-key types opt in by implementing
[`AnomalyFields`](#custom-anomalyfields-impl). See
[`docs/eve-format.md`](eve-format.md) for the field-by-field
schema mapping and severity vocabulary.

### Custom `AnomalyFields` impl

```rust,ignore
use std::net::IpAddr;
use flowscope::AnomalyFields;

struct MyKey { src: IpAddr, dst: IpAddr, sport: u16, dport: u16 }

impl AnomalyFields for MyKey {
    fn src_ip(&self)    -> Option<IpAddr> { Some(self.src) }
    fn src_port(&self)  -> Option<u16>    { Some(self.sport) }
    fn dest_ip(&self)   -> Option<IpAddr> { Some(self.dst) }
    fn dest_port(&self) -> Option<u16>    { Some(self.dport) }
    fn proto_str(&self) -> Option<&'static str> { Some("TCP") }
}
```

Once your key implements `AnomalyFields`, `EveJsonWriter` (and
any future field-aware emitter) renders the typed accessors
into the EVE schema. All 8 trait methods default to `None`, so
you only fill in what your key carries.

### Cross-thread slot drain (0.12)

`SlotHandle<M, K>` is `Send + Sync` since 0.12 (backed by
`Arc<crossbeam_queue::SegQueue<…>>`). Drain on a worker thread
while the driver runs on the capture thread:

```rust,ignore
use std::thread;
use flowscope::driver::Driver;
use flowscope::http::HttpParser;

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot = builder.session_on_ports(HttpParser::default(), [80]);
let mut driver = builder.build();

// Hand a clone of the handle to a worker thread.
let drainer = http_slot.clone();
thread::spawn(move || {
    let mut h = drainer;
    let mut buf = Vec::new();
    loop {
        h.drain(&mut buf);
        for m in buf.drain(..) {
            // forward to your channel / sink
        }
    }
});

// Capture loop on the main thread.
let mut events = Vec::new();
for owned in source.views() {
    driver.track_into(PacketView::from(&owned?), &mut events);
}
```

`Clone` hands out a **competitive consumer** (each handle pops
from the same queue; sum of drains across clones = total
pushed). For broadcast — every consumer sees every message —
drain into a `tokio::sync::broadcast` or `crossbeam::channel`
yourself.

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
use flowscope::driver::Driver;
use flowscope::PacketView;

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut tls = builder.session_on_ports(TlsHandshakeParser::default(), [443]);
let mut driver = builder.build();

let mut events = Vec::new();
let mut handshakes = Vec::new();
for view in source.views() {
    events.clear();
    handshakes.clear();
    driver.track_into(PacketView::from(&view?), &mut events);
    tls.drain(&mut handshakes);
    for m in &handshakes {
        let hs = &m.message;
        println!("SNI={:?} version={:?} outcome={:?}",
            hs.sni, hs.version, hs.outcome);
        match hs.outcome {
            HandshakeOutcome::Completed => { /* … */ }
            HandshakeOutcome::AlertedByServer { description } => { /* … */ }
            _ => {}
        }
    }
}
```

Build with `--features tls,tls-fingerprints` to get both fingerprints
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
flowscope = { version = "0.18", features = ["aggregate"] }
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
use flowscope::driver::Driver;
use flowscope::PacketView;

let mut builder = Driver::builder(ext);
let mut http = builder.session_on_ports(HttpExchangeParser::new(), [80, 8080]);
let mut driver = builder.build();

let mut events = Vec::new();
let mut exchanges = Vec::new();
driver.track_into(PacketView::from(&view), &mut events);
http.drain(&mut exchanges);
for m in &exchanges {
    let ex = &m.message;
    match ex.outcome {
        HttpOutcome::Completed if ex.is_success() => { /* 2xx */ }
        HttpOutcome::Completed if ex.is_error()   => { /* 4xx/5xx */ }
        HttpOutcome::NoResponse                   => { /* flow ended pending */ }
        HttpOutcome::Reset                        => { /* RST mid-exchange */ }
        _ => {}
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

## The typed `Driver<E>` (0.11+)

0.11 replaced the closed-`M` `Driver<E, M>` with a typed-slot-
drain shape: `Driver<E>` emits flow-lifecycle `Event<K>` only;
per-parser typed messages flow through `SlotHandle<M, K>`
returned at registration time. No lift closures, no sum-type
`M`, zero per-message Box.

```rust,ignore
use flowscope::driver::{Driver, Event};
use flowscope::detect::signatures::http_request;
use flowscope::dns::DnsUdpParser;
use flowscope::extract::FiveTuple;
use flowscope::http::HttpParser;

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
let mut dns_slot  = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
// Heuristic — catches HTTP on unusual ports.
let mut http_alt  = builder.session_heuristic(HttpParser::default(), http_request);
let mut driver    = builder.build();

let mut events  = Vec::new();
let mut http_m  = Vec::new();
let mut dns_m   = Vec::new();
let mut alt_m   = Vec::new();

for owned in source.views() {
    let owned = owned?;
    events.clear();
    http_m.clear(); dns_m.clear(); alt_m.clear();
    driver.track_into(PacketView::from(&owned), &mut events);
    http_slot.drain(&mut http_m);
    dns_slot.drain(&mut dns_m);
    http_alt.drain(&mut alt_m);
    for ev in &events {
        match ev {
            Event::Started { key, .. } => /* lifecycle */ {}
            Event::ParserClosed { parser_kind, .. } => /* per-parser close */ {}
            Event::Ended { key, reason, stats, .. } => /* lifecycle */ {}
            _ => {}
        }
    }
}
```

For the full set of migration recipes from prior versions, see:

- [`docs/migration-0.10-to-0.11.md`](migration-0.10-to-0.11.md)
  — parser API break + `Driver<E>` introduction.
- [`docs/migration-0.11-to-0.12.md`](migration-0.11-to-0.12.md)
  — `SlotHandle: Send + Sync` and the new opt-in features.
- [`docs/migration-0.12-to-0.13.md`](migration-0.12-to-0.13.md)
  — `Driver<E>: Send + Sync`, `OwnedAnomaly` + `DetectorScore`,
  `BroadcastSlotHandle`, `drain_n`, `FlowStateMap`.
- [`docs/migration-0.13-to-0.14.md`](migration-0.13-to-0.14.md)
  — `FlowTracker::lookup_inner`, `DestUnreachableKind`,
  `RollingRate`, `LabelTable`, `app_label` / `canonical_name`,
  `drain_expired`, per-side `FlowStats` accessors. Strictly
  additive.

## 0.14 patterns

### Joining ICMP errors back to live flows

Every L4 monitor that watches for "why did this flow die"
asks the same question: an ICMPv4 Destination Unreachable
arrives carrying the original packet's headers — does it
correlate to a live flow in the tracker? `FlowTracker<FiveTuple, S>::lookup_inner`
answers this in one method call. Direction-agnostic via the
shared canonicalisation helper.

```rust,ignore
use flowscope::extract::FiveTuple;
use flowscope::icmp::IcmpType;
use flowscope::FlowTracker;
use flowscope::DestUnreachableKind;

let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(
    FiveTuple::bidirectional());

// In your ICMP handler:
fn on_icmp_message<S>(
    tracker: &FlowTracker<FiveTuple, S>,
    icmp_type: &IcmpType,
) where S: Send + 'static {
    if !icmp_type.is_error() {
        return;
    }
    let Some((_label, inner)) = icmp_type.error_inner() else {
        return; // truncated embed
    };

    if let Some((flow_key, stats)) = tracker.stats_for_inner(inner) {
        let kind = icmp_type.dest_unreachable_kind()
            .map(|k| k.as_str())
            .unwrap_or_else(|| icmp_type.short_kind());
        eprintln!(
            "Flow {flow_key:?} reported {kind}: {} bytes in flight",
            stats.total_bytes()
        );
    }
}
```

For unidirectional trackers (`FiveTuple::directional()`), use
`FiveTupleKey::from_inner_literal` + `tracker.get(&key)`
directly — `lookup_inner` is bidirectional-specific.

### Bandwidth-by-app with `RollingRate` + `app_label`

The operationally-most-common monitor pattern: per-app
bytes/sec over a sliding window, ranked top-N. `RollingRate`
is the new primitive; `app_label` is the always-Some label
key.

```rust,ignore
use std::time::Duration;
use flowscope::correlate::RollingRate;
use flowscope::driver::Event;

let mut bw: RollingRate<&'static str, u64> =
    RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));

for event in driver_events {
    if let Event::Packet { key, len, ts, .. } = event {
        // app_label is always-Some; falls back to L4 name
        // ("tcp" / "udp" / "sctp") for unknown ports.
        bw.record(key.app_label(), len as u64, ts);
    }
}

// In your tick handler — top-10 talkers:
let mut snap: Vec<_> = bw.snapshot(now).collect();
snap.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());
for (label, rate) in snap.iter().take(10) {
    println!("{label:<12} {rate:>10.0} B/s");
}
```

`RollingRate` is generic over the value type. For request-
rate, use `record(k, 1, now)` and the same `RollingRate<K, u64>`
shape:

```rust,ignore
let mut rps: RollingRate<&'static str, u64> =
    RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
// On each Established event:
rps.record(key.app_label(), 1, ts);
```

### Site-custom port labels with `LabelTable`

Every real deployment has internal services on non-standard
ports. `LabelTable` lets you layer overrides on top of (or
replacing) the built-in well-known table.

```rust,ignore
use flowscope::well_known::LabelTable;
use flowscope::extractor::L4Proto;

// Build once at startup:
let mut table = LabelTable::new();  // inherits the built-in ~80 entries
table.extend([
    (L4Proto::Tcp, 8765,  "grpc-internal"),
    (L4Proto::Tcp, 9101,  "metrics-scrape"),
    (L4Proto::Tcp, 30443, "legacy-app"),
    (L4Proto::Udp, 5683,  "coap-iot"),
]);

// In your monitor handler:
let label = flow_key.app_label_with(&table);
// "grpc-internal" if proto=TCP and port=8765,
// "http" if proto=TCP and port=80 (built-in fallback),
// "tcp" if proto=TCP and ports are ephemeral (L4 fallback).
```

For runtime-loaded labels (YAML/JSON config), use `Box::leak`
to bridge owned `String` into `&'static str`:

```rust,ignore
let label_from_config: String = read_from_config();
let leaked: &'static str = Box::leak(label_from_config.into_boxed_str());
table.set(L4Proto::Tcp, port, leaked);
```

`LabelTable` is `Clone + Send + Sync` — share via `Arc` across
threads.

### Inspection patterns with `drain_expired`

When you're using `KeyIndexed` for request/response
correlation (DNS, ICMP-to-flow, custom RPC), you usually want
to ask "what timed out without a response?" `drain_expired`
returns the expired `(K, V)` pairs so you can emit anomalies.

```rust,ignore
use std::time::Duration;
use flowscope::correlate::KeyIndexed;
use flowscope::Timestamp;

let mut pending_dns: KeyIndexed<u16 /* txid */, String /* qname */> =
    KeyIndexed::new_unbounded(Duration::from_secs(5));

// On every DNS query:
pending_dns.insert(txid, qname, ts);

// On every DNS response: remove (correlate).
let _ = pending_dns.remove(&txid);

// Periodic tick — emit anomalies for unanswered queries:
let unanswered = pending_dns.drain_expired(now);
for (txid, qname) in unanswered {
    println!("DNS qname={qname} txid={txid} timed out");
}
```

Reusable-buffer variant for hot loops:

```rust,ignore
let mut out: Vec<(u16, String)> = Vec::with_capacity(64);
loop {
    let n = pending_dns.drain_expired_into(now, &mut out);
    if n == 0 { break; }
    for (txid, qname) in out.drain(..) {
        emit_timeout_anomaly(txid, qname);
    }
}
```

Honest allocation contract: the underlying `lru::LruCache` has
no `drain()` method, so a `Vec` is unavoidable. The `_into`
variant amortizes across calls.

### MTU-mismatch detection across v4/v6 with `mtu_signal`

Path-MTU discovery is non-optional in IPv6, and v6's
`PacketTooBig` is type 2 (not under `DestUnreachable`).
`IcmpType::mtu_signal()` folds both protocol versions into a
single classification, preserving the next-hop MTU:

```rust,ignore
use flowscope::{DestUnreachableKind, MtuSignalKind};
use flowscope::icmp::IcmpType;

fn classify_icmp(t: &IcmpType) -> &'static str {
    if let Some(kind) = t.dest_unreachable_kind() {
        return kind.as_str();
    }
    if let Some(mtu) = t.mtu_signal() {
        // mtu_signal covers v4 DU code 4 AND v6 type 2.
        return mtu.as_str();  // "fragmentation_needed" / "packet_too_big"
    }
    t.short_kind()
}

// Surfacing the next-hop MTU for PMTUD blackhole reports:
if let Some(mtu) = icmp_type.mtu_signal() {
    match mtu.next_hop_mtu() {
        Some(mtu_val) => {
            eprintln!("PMTU shrink: {} → {mtu_val}", mtu.as_str());
        }
        None => {
            // v4-only: RFC 1191 non-conformant sender.
            eprintln!("PMTU shrink: {} (MTU unknown)", mtu.as_str());
        }
    }
}
```

`MtuSignalKind::next_hop_mtu()` returns `Option<u32>` — `None`
only happens on v4 with a non-RFC-1191-conformant sender; v6
always carries the MTU. Pair with `FlowTracker::stats_for_inner`
(plan 161) to join the MTU event back to the flow it concerns.

The `examples/04-observability/icmp_explained_drops.rs` example
shows the full pattern with both `DestUnreachableKind` and
`MtuSignalKind` classification + flow correlation in one match.

### Emitting detector-shaped anomalies via `OwnedAnomaly`

Every shipped detector's score (`ScanScore<K>`, `BeaconScore<K>`,
`DgaScore`) has an `into_anomaly(ts) -> OwnedAnomaly` method.
Route through `EveJsonWriter::write_owned_anomaly` or
`FlowEventNdjsonWriter::write_owned_anomaly` for a uniform emit
shape across detector types:

```rust,ignore
use std::fs::File;
use std::io::BufWriter;
use flowscope::detect::patterns::PortScanDetector;
use flowscope::emit::EveJsonWriter;
use flowscope::extract::FiveTupleKey;
use flowscope::Timestamp;

let mut port_scan: PortScanDetector<FiveTupleKey> = PortScanDetector::new();
let mut eve = EveJsonWriter::new(BufWriter::new(File::create("eve.json")?));

let score = port_scan.observe(flow_key, success);
eve.write_owned_anomaly(&score.into_anomaly(ts))?;
```

For generic-over-detector routing, write the function bound on
the `DetectorScore` trait — every detector's score implements it:

```rust,ignore
use flowscope::{DetectorScore, Timestamp};
use flowscope::emit::EveJsonWriter;
use std::io::Write;

fn emit<S: DetectorScore, W: Write>(
    eve: &mut EveJsonWriter<W>,
    score: S,
    ts: Timestamp,
) -> std::io::Result<()> {
    eve.write_owned_anomaly(&score.into_anomaly(ts))
}
```

To bridge a flowscope-internal `FlowEvent::FlowAnomaly` into the
owned shape (so a single routing function handles both detector
output and tracker anomalies):

```rust,ignore
use flowscope::{FlowEvent, OwnedAnomaly};
if let FlowEvent::FlowAnomaly { key, kind, ts } = event {
    eve.write_owned_anomaly(
        &OwnedAnomaly::from_flow_anomaly(&key, kind, ts)
    )?;
}
```

See [`docs/eve-format.md`](eve-format.md) §"Custom anomaly
emission via `OwnedAnomaly` (0.13)" for the EVE schema details.

### Fan-out to multiple consumers via `BroadcastSlotHandle`

`SlotHandle::clone` is **competitive consumer** semantics
(MPMC — each message goes to exactly one drainer). When you
want **broadcast** semantics (each consumer sees every message),
register through the broadcast variant:

```rust,ignore
use flowscope::driver::{Driver, BroadcastSlotHandle};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_logger: BroadcastSlotHandle<HttpMessage, FiveTupleKey> =
    builder.session_on_ports_broadcast_each(HttpParser::default(), [80, 8080]);
let mut http_metrics = http_logger.clone();
let mut http_alerter = http_logger.clone();
let mut driver = builder.build();

// In the event loop, drain each subscriber independently:
let mut log_buf = Vec::new();
let mut metric_buf = Vec::new();
let mut alert_buf = Vec::new();
http_logger.drain(&mut log_buf);
http_metrics.drain(&mut metric_buf);
http_alerter.drain(&mut alert_buf);
// log_buf, metric_buf, alert_buf each see every HTTP message.
```

Trade-off vs the MPMC `SlotHandle`:

| Aspect             | `SlotHandle`        | `BroadcastSlotHandle` |
|--------------------|---------------------|-----------------------|
| Clone semantics    | Competitive consumer (MPMC) | Broadcast (each clone sees every message) |
| Per-push cost      | O(1) atomic         | O(subscribers) clones + pushes |
| `M` bound          | `Send`              | `Send + Clone` |
| Memory per subscriber | Shares one queue | One private queue each |

For 0.13, the broadcast variant exists for `session_on_ports`
only. Datagram + heuristic broadcast variants defer to 0.14
if a consumer asks.

### Bounded back-pressure via `SlotHandle::drain_n`

When shards / async tasks drain slot handles, an unbounded
`drain` call can monopolise a CPU if one slot has thousands of
pending messages. `drain_n(out, max)` caps per-call drain
volume:

```rust,ignore
let mut messages = Vec::with_capacity(64);
loop {
    let drained = http_slot.drain_n(&mut messages, 64);
    if drained == 0 { break; }
    for msg in messages.drain(..) {
        // forward to a channel, write to disk, …
    }
}
```

`max = 0` is a valid no-op; `max = usize::MAX` is equivalent to
`drain()`. The shipped sharded-driver example
(`examples/00-getting-started/sharded_capture.rs`) uses
`drain_n(out, 64)` as the canonical pattern.

### Per-flow typed state via `FlowStateMap`

For per-flow side-channel state (custom counters, decoder
context, etc.), use `FlowStateMap<T, K>`. It auto-evicts on
`FlowEvent::Ended` and supports TTL sweep:

```rust,ignore
use std::time::Duration;
use flowscope::correlate::FlowStateMap;
use flowscope::driver::Event;

#[derive(Default)]
struct PerFlow {
    packets: u64,
    bytes: u64,
}

let mut state: FlowStateMap<PerFlow> = FlowStateMap::new(Duration::from_secs(60));

for event in driver_events {
    // Drive lifecycle: evict on Ended, refresh last-seen on others.
    state.feed(&event);

    if let Event::Packet { key, len, ts, .. } = event {
        let entry = state.get_or_default(&key, ts);
        entry.packets += 1;
        entry.bytes += len as u64;
    }
}

// Periodic sweep (driven by your tick handler):
state.sweep(current_packet_ts);
```

Defaults `K` to `FiveTupleKey`. Layered over `KeyIndexed<K, T>`,
so the underlying TTL + LRU machinery is shared with
`flowscope::correlate`.

### Cross-thread `Driver<E>` via `tokio::spawn` (0.13)

Now that `Driver<E>: Send + Sync` (0.13), the default tokio
multi-thread runtime just works:

```rust,ignore
#[tokio::main]  // multi-thread default
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = flowscope::driver::Driver::builder(
        flowscope::extract::FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(
        flowscope::http::HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    let handle = tokio::spawn(async move {
        // Driver runs on whatever worker thread the executor picks.
        for view in source { driver.track_into(view, &mut events); }
    });
    handle.await?;
    Ok(())
}
```

Before 0.13, this required `#[tokio::main(flavor = "current_thread")]`
or `tokio::task::LocalSet::run_until` because the driver was
incorrectly classified as `!Send`. The 0.13 cycle's plan 156 fixed
this structurally — no `unsafe`, no opt-in knob, no runtime
overhead. See [`docs/migration-0.12-to-0.13.md`](migration-0.12-to-0.13.md)
§1 for the full story.

## Re-exporting flowscope types

When a downstream crate re-exports flowscope types, intra-doc
links should use the bare form, not the explicit-path form:

```rust,ignore
// In your-crate/src/lib.rs:
pub use flowscope::FlowDriver;

// In your-crate's rustdoc:
/// See [`FlowDriver`] for the sync run-to-completion driver.
```

The explicit form `[FlowDriver](flowscope::FlowDriver)`
trips `redundant_explicit_links` under `-D warnings` because
rustdoc resolves the bare form through the re-export anyway.
