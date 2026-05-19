# Session Guide — picking the right L7 parser API

`flowscope` exposes three layered abstractions for working with L7
protocol data on a flow. They build on each other, but they're
independently useful at their own level.

This guide explains:

1. The four APIs at a glance.
2. Which to pick for which use case.
3. How to migrate from one to another.

## The four APIs

```
                                      .─→ FlowEvent  (lifecycle only)
                                     /
PacketView → FlowExtractor → FlowTracker
                                     \
                                      `─→ Reassembler         (1) per-side bytes
                                                  ↓
                                              SessionParser   (2) typed messages
                                                  ↑
                                          (callback handler)
                                                  ↑
                                            *Factory<H>       (3) callback API

UDP payload                       → DatagramParser            (4) typed messages
```

| Layer | When to reach for it | Example |
|------|----------------------|---------|
| `FlowEvent`             | "I just want flow lifecycle (created / packet / ended)." | NetFlow-style summary |
| `Reassembler`            | "I have my own L7 parser; give me the per-side TCP byte stream." | Custom protocol decoder |
| `*Factory<H>` (callback) | "I want HTTP/TLS/DNS events via a sync callback handler." | Embedded in a sync packet loop |
| `SessionParser` (TCP) / `DatagramParser` (UDP) | "I want an `async` stream of typed L7 messages." | Tokio app on top of `netring::flow_stream` |

`SessionParser` and the callback-style `*Factory<H>` produce **the
same events** for the same wire bytes. They're API shapes for
different consumers: factories suit synchronous loops; parsers
suit async iteration with backpressure.

## Decision flow

> **Start here.** Walk the questions top-to-bottom; the first "yes"
> picks your API.

1. **Do you only care about flow lifecycle, not L7 content?**
   → Use `FlowTracker` directly and consume `FlowEvent`. Skip the
   rest of this guide.

2. **Are you parsing a protocol `flowscope` doesn't ship?** (HTTP/2,
   AMQP, your own binary protocol, …)
   → Implement `SessionParser` (TCP) or `DatagramParser` (UDP) for
   your protocol. Pair with `flow_stream(...).session_stream(parser)`
   in `netring`. The trait is generic over `Message`, so your
   types just become the stream's `Item`. (Or implement
   `Reassembler` if a callback model is more natural; both work.)

3. **Are you running synchronously? (no tokio, embedded, offline
   pcap)**
   → Use the callback-style factory: `HttpFactory<H>`,
   `TlsFactory<H>`, or `DnsUdpObserver`. Drive packets through
   `FlowDriver` (sync) and you'll get callback invocations on
   parsed events.

4. **Are you running asynchronously and want to `for await msg in
   stream` on typed L7 messages?**
   → Use `HttpParser`, `TlsParser`, `DnsUdpParser`, `DnsTcpParser`
   with `netring::FlowStream::session_stream(...)` or
   `.datagram_stream(...)`. You'll get `SessionEvent<K, M>` in
   the stream.

5. **Do you need both directions of one TCP flow as a single
   ordered byte stream?** (e.g., reassemble both HTTP request *and*
   response into one transcript)
   → Use `Conversation<K>` (in `netring`). It exposes the two
   directions as one `Stream<Item = (FlowSide, Bytes)>`.

## Examples

### Lifecycle only (`FlowEvent`)

```rust,no_run
use flowscope::{FlowTracker, FlowEvent};
use flowscope::extract::FiveTuple;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let mut tracker: FlowTracker<_, ()> =
    FlowTracker::new(FiveTuple::bidirectional());
// drive packets through `tracker.track(view)`
# Ok(()) }
```

### Custom protocol via `SessionParser`

```rust,no_run
use flowscope::{FlowSide, SessionParser};

#[derive(Default, Clone)]
struct LineParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LineParser {
    type Message = (FlowSide, String);

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.init_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = self.init_buf.iter().position(|&b| b == b'\n') {
            out.push((FlowSide::Initiator, String::from_utf8_lossy(&self.init_buf[..nl]).into_owned()));
            self.init_buf.drain(..=nl);
        }
        out
    }

    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.resp_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = self.resp_buf.iter().position(|&b| b == b'\n') {
            out.push((FlowSide::Responder, String::from_utf8_lossy(&self.resp_buf[..nl]).into_owned()));
            self.resp_buf.drain(..=nl);
        }
        out
    }
}
```

### Sync HTTP via `HttpFactory<H>`

```rust,no_run
use flowscope::http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
use flowscope::FlowDriver;
use flowscope::extract::FiveTuple;

struct Logger;
impl HttpHandler for Logger {
    fn on_request(&self, req: &HttpRequest)  { println!("→ {} {}", req.method, req.path); }
    fn on_response(&self, resp: &HttpResponse) { println!("← {} {}", resp.status, resp.reason); }
}

# fn main() -> Result<(), Box<dyn std::error::Error>> {
let factory = HttpFactory::with_handler(Logger);
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);
// drive packets through driver.track(view)
# Ok(()) }
```

### Async HTTP via `HttpParser` + `netring`

```rust,no_run
use futures::StreamExt;
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::SessionEvent;

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let mut s = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());
while let Some(evt) = s.next().await {
    if let SessionEvent::Application { message: HttpMessage::Request(req), .. } = evt? {
        println!("{} {}", req.method, req.path);
    }
}
# Ok(()) }
```

### Async DNS-over-UDP via `DnsUdpParser`

```rust,no_run
use futures::StreamExt;
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::SessionEvent;

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let mut s = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .datagram_stream(DnsUdpParser);
while let Some(evt) = s.next().await {
    if let SessionEvent::Application { message: DnsMessage::Query(q), .. } = evt? {
        println!("DNS Q  id={:#x}", q.transaction_id);
    }
}
# Ok(()) }
```

### Async DNS-over-TCP

```rust,no_run
use futures::StreamExt;
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::dns::{DnsMessage, DnsTcpParser};
use flowscope::SessionEvent;

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let mut s = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(DnsTcpParser::default());
while let Some(evt) = s.next().await {
    let _ = evt?;
}
# Ok(()) }
```

## Migration paths

### From a callback factory to a `SessionParser`

The factory and parser produce the same events; the move is an API
shape change.

```rust,ignore
// Before — sync callback:
struct H;
impl HttpHandler for H {
    fn on_request(&self, req: &HttpRequest) { do_something(req); }
}
let factory = HttpFactory::with_handler(H);
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);
loop {
    let view = next_packet();
    for _ in driver.track(view) {}
}

// After — async stream:
let mut s = cap
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());
while let Some(evt) = s.next().await {
    if let SessionEvent::Application { message: HttpMessage::Request(req), .. } = evt? {
        do_something(&req);
    }
}
```

The shared `Arc<Handler>` pattern of factories is gone — the parser
is per-flow, owned by the stream. If you need a shared sink across
flows, send messages out via a `tokio::sync::mpsc` channel.

### From `Reassembler` to `SessionParser`

If you're feeding raw bytes to your own parser via `Reassembler`,
moving to `SessionParser` lets you skip the byte-stream layer and
return parsed messages directly.

```rust,ignore
// Before:
struct MyReass { buf: Vec<u8>, side: FlowSide }
impl Reassembler for MyReass {
    fn segment(&mut self, _seq: u32, payload: &[u8]) {
        self.buf.extend_from_slice(payload);
        // your parsing happens here, callbacks fire elsewhere
    }
}

// After:
#[derive(Default, Clone)]
struct MyParser { init: Vec<u8>, resp: Vec<u8> }
impl SessionParser for MyParser {
    type Message = MyMsg;
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<MyMsg> {
        self.init.extend_from_slice(bytes);
        // … parse, return messages directly
    }
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<MyMsg> { /* mirror */ }
}
```

## When `Conversation<K>` fits

`netring`'s `Conversation<K>` is for the case where you want both
sides of a TCP flow as one ordered `Stream<(FlowSide, Bytes)>`. It's
the right tool when:

- You're capturing transcripts (request + response together).
- You want to write your parser as a small async function that
  reads bytes in either direction.
- You need a single bytes-output you can pipe somewhere else (a
  file writer, a TCP forwarder, etc.).

It's **not** the right tool when:

- You only care about parsed events. Use `SessionParser` instead.
- You need to emit messages synchronously inside your packet loop
  (sync). `Conversation` is async.

## Writing your own `SessionParser`

This is the worked walkthrough that the
`examples/length_prefixed_pcap.rs` example demonstrates.

### Trait-method contract

| Method | When called | Driver guarantees | Parser responsibilities |
|--------|-------------|-------------------|--------------------------|
| `feed_initiator(bytes)` | Per packet on the initiator side | `bytes` is 1..N bytes, never empty. Calls are serialised — never concurrent. Subsequent calls deliver bytes in TCP-sequence order (reassembler ensures this). | Buffer partial frames in `&mut self`. Return only complete decoded messages. Don't assume `bytes` is aligned to a frame boundary. |
| `feed_responder(bytes)` | Mirror of initiator | Same | Same |
| `fin_initiator() -> Vec<Message>` | Initiator-side stream closes cleanly (FIN observed) | Called once per flow; not after `rst_initiator` | Flush any in-flight decodable state and return it. Drop partial / undecodable buffers silently. Default impl returns an empty `Vec`. |
| `fin_responder() -> Vec<Message>` | Mirror | Same | Same |
| `rst_initiator()` | Initiator-side aborts (RST, eviction, buffer-overflow, or parse-error tear-down) | Called once per flow; not after `fin_initiator` | Drop in-flight buffers. **Don't** flush — the truncation is unrecoverable. Default impl is a no-op. |
| `rst_responder()` | Mirror | Same | Same |
| `is_poisoned() -> bool` (0.3.0) | After every `feed_*` / `fin_*` call | `false` means "keep going" | Return `true` once you've hit an unrecoverable error (desynced framing, invalid magic that won't appear later). The driver then tears the flow down with `EndReason::ParseError` and drops your parser slot. Default returns `false`. |
| `poison_reason() -> Option<&str>` (0.3.0) | After `is_poisoned()` returns `true` | Consulted once | Optional human-readable reason; truncated to ~256 bytes when forwarded via `SessionEvent::Anomaly`. |

### The canonical partial-buffer pattern

```rust,ignore
#[derive(Default, Clone)]
struct MyParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for MyParser {
    type Message = MyMessage;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf, FlowSide::Initiator)
    }
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.resp_buf.extend_from_slice(bytes);
        drain(&mut self.resp_buf, FlowSide::Responder)
    }
}

fn drain(buf: &mut Vec<u8>, side: FlowSide) -> Vec<MyMessage> {
    let mut out = Vec::new();
    while let Some(consumed) = try_decode_one(buf, side) {
        out.push(consumed);
    }
    out
}
```

Key rules:
- **Don't drain the buffer until a complete message is in.** Decode-and-consume is atomic per message; the next call sees the rest.
- **Per-side buffers are independent.** A partial frame on initiator does not block responder progress.

### Resync after bytes dropped

When `FlowStats.reassembly_bytes_dropped_oversize_* > 0` on an `Ended` event (or `FlowEvent::Anomaly { kind: BufferOverflow, .. }` fires inline), your parser's buffer is no longer contiguous with the wire. Three recovery strategies, in increasing order of parser-side cost:

1. **Use `OverflowPolicy::DropFlow`** (recommended for framed binary protocols). The driver tears the flow down on first overflow with `EndReason::BufferOverflow`; the parser never sees a desynced continuation. See [Recovery after buffer cap](#recovery-after-buffer-cap).
2. **Marker re-scan** for protocols with a fixed-length marker prefix (HTTP `\r\n\r\n`, PSMSG-style framing). Walk the buffer looking for the next marker, discard everything before it.
3. **Tear down at the parser layer** via `is_poisoned()` (0.3.0): return `true` from `is_poisoned()` after detecting the desync; the driver synthesises `EndReason::ParseError` and drops your state. Consumers observe a `SessionEvent::Closed { reason: ParseError }`.

### Signalling unrecoverable errors (0.3.0)

For per-message errors (one bad message but the rest of the stream is fine), just don't push the bad message into the returned `Vec`. The framework can't tell the difference between "no message ready" and "bad message skipped" — both are fine.

For flow-level errors (the parser's internal state is corrupted past recovery), set `is_poisoned() -> true` after you detect it. The driver then:

1. Optionally emits `SessionEvent::Anomaly { kind: SessionParseError { side, reason } }` (when `with_emit_anomalies(true)`).
2. Synthesises `SessionEvent::Closed { reason: EndReason::ParseError }`.
3. Calls `rst_initiator` / `rst_responder` on your parser, then drops the slot.

Subsequent packets for the same 5-tuple will start a fresh flow with a fresh parser instance.

### Testing pattern

Pair every custom parser with a byte-by-byte sliced test. Run the same wire bytes one byte at a time and assert identical output:

```rust,ignore
#[test]
fn handles_partial_chunks() {
    let wire_bytes: &[u8] = /* ... build via test_frames or hex ... */;
    let mut parser = MyParser::default();
    let mut out = Vec::new();
    for byte in wire_bytes {
        out.extend(parser.feed_initiator(std::slice::from_ref(byte)));
    }
    assert_eq!(out, expected_messages);
}
```

This catches the vast majority of partial-frame bugs without a proptest harness. Recommended for every custom parser.

### Length-prefixed binary protocols — worked reference

The [`examples/length_prefixed_pcap.rs`](../examples/length_prefixed_pcap.rs) example implements a PSMSG-shaped protocol with two variable-length markers (PFX2/PFX4). It demonstrates:

1. **Variable-length headers** — `peek_header` returns `Some((header_len, body_len))` only when the full header is present.
2. **Partial-header / partial-body buffering** — both wait for "enough bytes" before consuming.
3. **Unknown-marker handling** — the example stalls on unknown markers; real parsers should pair with `OverflowPolicy::DropFlow` and signal poison via `is_poisoned()`.

The example is paired with a deterministic pcap fixture and an integration test that exercises both the standard path and the byte-by-byte sliced path. Worth reading end-to-end if you're writing a custom binary-protocol parser.

## Sync vs async session driving (0.2.0)

`SessionParser` is just a trait — the *driver* that feeds it bytes
and emits `SessionEvent` lives in two places:

| Path | Helper | Where |
|------|--------|-------|
| Async (tokio) | `cap.flow_stream(...).session_stream(parser)` | `netring` |
| Sync (no runtime) | `FlowSessionDriver::new(extractor, parser)` | `flowscope` |

Both produce the same `SessionEvent` stream for the same wire bytes.
Pick by control flow:

- **Live capture, tokio app** → netring's `session_stream`.
- **Offline pcap replay, embedded, CLI tools** → `FlowSessionDriver`.

The sync path is exercised end-to-end by
`examples/length_prefixed_pcap.rs`, which implements a custom
length-prefixed binary protocol parser and runs it against a pcap
fixture without any runtime dependency.

```rust,ignore
let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), MyParser::default());
for view in PcapFlowSource::open("trace.pcap")?.views() {
    let view = view?;
    for ev in driver.track(&view) {
        // SessionEvent::Started / Application / Closed
    }
}
// End of input — flush every still-open flow.
for ev in driver.finish() {
    // SessionEvent::Closed for each remaining flow
}
```

End a sync loop with `driver.finish()`: it sweeps every still-open
flow to its end (equivalent to `sweep(Timestamp::MAX)`). Forgetting
it silently drops the last flows.

`FlowSessionDriver::with_config` honours
`FlowTrackerConfig::max_reassembler_buffer` and `overflow_policy`
automatically — buffer caps and overflow policies (Plan 42) work
identically across sync and async.

## Reassembly health (0.2.0)

Every `FlowEvent::Ended` now carries reassembly diagnostics in its
`stats` field:

```rust,ignore
let FlowEvent::Ended { stats, .. } = ev else { return };
println!(
    "ooo init={} resp={}; oversize init={} resp={}",
    stats.reassembly_dropped_ooo_initiator,
    stats.reassembly_dropped_ooo_responder,
    stats.reassembly_bytes_dropped_oversize_initiator,
    stats.reassembly_bytes_dropped_oversize_responder,
);
```

`reassembly_dropped_ooo_*` counts segments dropped because they
arrived out of order. `reassembly_bytes_dropped_oversize_*` counts
payload bytes dropped from the buffer because of an
[`OverflowPolicy`](#recovery-after-buffer-cap)-driven cap (zero
unless `with_max_buffer` was set). Custom `Reassembler` impls can
opt into surfacing these counters by overriding the default-zero
trait methods.

## Recovery after buffer cap

`BufferedReassembler::with_max_buffer(n)` caps the per-side
in-flight buffer at `n` bytes. When the cap is hit the
[`OverflowPolicy`] decides what happens next.

### `OverflowPolicy::SlidingWindow` (default)

The reassembler drops oldest bytes from the front of the buffer
until the new payload fits. The flow stays alive; the parser sees a
gap and must resync. Best for **stream-shaped / append-only
protocols** (HTTP body streams, plain TCP).

`bytes_dropped_oversize` (per-side, on `FlowStats` and via
`Reassembler::bytes_dropped_oversize()`) records the count of
rotated-out bytes. A non-zero value tells your parser its buffered
state is no longer contiguous with the wire.

### `OverflowPolicy::DropFlow`

The reassembler poisons itself on first overflow; subsequent
segments are no-ops. The driver synthesises an
`Ended { reason: EndReason::BufferOverflow }` event for the flow on
the next tick, after which the tracker forgets it (so the next
packet starts a fresh flow).

Best for **framed binary protocols** (DES PSMSG, TLS records,
length-prefixed wire formats) where dropping bytes mid-frame would
permanently desync the parser.

```rust,ignore
use flowscope::{BufferedReassemblerFactory, OverflowPolicy, FlowDriver};
use flowscope::extract::FiveTuple;

let factory = BufferedReassemblerFactory::default()
    .with_max_buffer(1_000_000)               // 1 MiB cap
    .with_overflow_policy(OverflowPolicy::DropFlow);
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);
```

Or set both at the tracker-config level via
`FlowTrackerConfig::max_reassembler_buffer` and `overflow_policy`,
which the default factory honours when constructed via
`FlowDriver::with_config`.

## Anomaly events (0.2.0)

For live observability — operators watching long-lived flows want
to know the moment a buffer overflow / OOO drop / eviction-pressure
event happens, not when the flow eventually closes.

Opt in via `FlowDriver::with_emit_anomalies(true)`:

```rust,ignore
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory)
    .with_emit_anomalies(true);
```

The driver then emits `FlowEvent::Anomaly { kind, .. }` events
inline, coalesced per (flow, side, kind) per tick:

| `AnomalyKind` | Fires when | Carries |
|---------------|-----------|---------|
| `BufferOverflow` | reassembler dropped bytes due to a cap | `side`, `bytes` (delta this tick), `policy` |
| `OutOfOrderSegment` | reassembler dropped one or more OOO segments | `side`, `count` (delta) |
| `FlowTableEvictionPressure` | tracker hit `max_flows` and evicted ≥ 1 flow | `evicted_in_tick`, `evicted_total` |

Anomalies appear **before** any synthesised `Ended` event for the
same flow so cause-then-effect ordering is preserved. The default
is `false` — existing consumers see no behaviour change without
opting in.

For production aggregation (Prometheus / OpenTelemetry), pair this
with the `metrics` feature (Plan 40, future release): the same
`AnomalyKind` vocabulary drives the metric labels.

## Trait stability

The `SessionParser` / `DatagramParser` trait shape locked in
flowscope 0.1 phase 2 (commit `cc24a0f`). Across the four shipped
parsers (HTTP, TLS, DNS-UDP, DNS-TCP) plus 11 splitting-invariance
proptests, the shape has been validated. Future additions are
**additive** (new methods with default implementations); breaking
changes will require a major bump.

## Concrete trait shape, for reference

```rust,ignore
pub trait SessionParser: Send + 'static {
    type Message: Send + 'static;
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}
}

pub trait DatagramParser: Send + 'static {
    type Message: Send + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message>;
}
```

Both have a `*Factory<K>` companion trait so you can implement
custom per-flow construction. Any `Default + Clone` parser is its
own factory via a blanket impl — the common case requires no
factory boilerplate.
