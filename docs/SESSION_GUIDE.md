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
   → For HTTP/TLS, use the callback-style factory (`HttpFactory<H>`
   / `TlsFactory<H>`) driven through `FlowDriver`. For typed L7
   messages — including DNS — use `FlowSessionDriver` /
   `FlowDatagramDriver`, or `PcapFlowSource::sessions()` /
   `datagrams()` for offline pcap.

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
use flowscope::{FlowSide, SessionParser, Timestamp};

#[derive(Default, Clone)]
struct LineParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LineParser {
    type Message = (FlowSide, String);

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        self.init_buf.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(nl) = self.init_buf.iter().position(|&b| b == b'\n') {
            out.push((FlowSide::Initiator, String::from_utf8_lossy(&self.init_buf[..nl]).into_owned()));
            self.init_buf.drain(..=nl);
        }
        out
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
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
        println!("{} {} (host={}, ua={})",
            req.method, req.path,
            req.host().unwrap_or("?"),
            req.user_agent().unwrap_or("?"));
    }
}
# Ok(()) }
```

`HttpRequest` and `HttpResponse` ship case-insensitive header
accessors (0.7.0): `host()`, `user_agent()`, `cookie()`,
`content_type()`, `content_length()`, `set_cookie()` (iterator),
plus generic `header(name)` / `headers_all(name)` for anything
else. `TlsClientHello::sni()` mirrors the `sni` field for
accessor symmetry.

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
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<MyMsg> {
        self.init.extend_from_slice(bytes);
        // … parse, return messages directly
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<MyMsg> { /* mirror */ }
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
| `feed_initiator(bytes, ts)` | Per packet on the initiator side | `bytes` is 1..N bytes, never empty; `ts` is the carrying packet's observed time. Calls are serialised — never concurrent. Subsequent calls deliver bytes in TCP-sequence order (reassembler ensures this). | Buffer partial frames in `&mut self`. Return only complete decoded messages. Don't assume `bytes` is aligned to a frame boundary. |
| `feed_responder(bytes, ts)` | Mirror of initiator | Same | Same |
| `on_tick(now) -> Vec<Message>` (0.4.0) | On every `sweep` / `finish`, for every live parser | Fires before the flow's `Closed` if the same sweep closes it | Optional. Emit time-driven messages (timeouts, unanswered requests); output is attributed to the initiator side. Default returns an empty `Vec`. |
| `fin_initiator() -> Vec<Message>` | Initiator-side stream closes cleanly (FIN observed) | Called once per flow; not after `rst_initiator` | Flush any in-flight decodable state and return it. Drop partial / undecodable buffers silently. Default impl returns an empty `Vec`. |
| `fin_responder() -> Vec<Message>` | Mirror | Same | Same |
| `rst_initiator()` | Initiator-side aborts (RST, eviction, buffer-overflow, or parse-error tear-down) | Called once per flow; not after `fin_initiator` | Drop in-flight buffers. **Don't** flush — the truncation is unrecoverable. Default impl is a no-op. |
| `rst_responder()` | Mirror | Same | Same |
| `is_poisoned() -> bool` (0.3.0) | After every `feed_*` / `fin_*` call | `false` means "keep going" | Return `true` once you've hit an unrecoverable error (desynced framing, invalid magic that won't appear later). The driver then tears the flow down with `EndReason::ParseError` and drops your parser slot. Default returns `false`. |
| `poison_reason() -> Option<&str>` (0.3.0) | After `is_poisoned()` returns `true` | Consulted once | Optional human-readable reason; truncated to ~256 bytes when forwarded via `SessionEvent::FlowAnomaly`. |

### The canonical partial-buffer pattern

```rust,ignore
#[derive(Default, Clone)]
struct MyParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for MyParser {
    type Message = MyMessage;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf, FlowSide::Initiator)
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
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

When `FlowStats.reassembly_bytes_dropped_oversize_* > 0` on an `Ended` event (or `FlowEvent::FlowAnomaly { kind: BufferOverflow, .. }` fires inline), your parser's buffer is no longer contiguous with the wire. Three recovery strategies, in increasing order of parser-side cost:

1. **Use `OverflowPolicy::DropFlow`** (recommended for framed binary protocols). The driver tears the flow down on first overflow with `EndReason::BufferOverflow`; the parser never sees a desynced continuation. See [Recovery after buffer cap](#recovery-after-buffer-cap).
2. **Marker re-scan** for protocols with a fixed-length marker prefix (HTTP `\r\n\r\n`, PSMSG-style framing). Walk the buffer looking for the next marker, discard everything before it.
3. **Tear down at the parser layer** via `is_poisoned()` (0.3.0): return `true` from `is_poisoned()` after detecting the desync; the driver synthesises `EndReason::ParseError` and drops your state. Consumers observe a `SessionEvent::Closed { reason: ParseError }`.

### Signalling unrecoverable errors (0.3.0)

For per-message errors (one bad message but the rest of the stream is fine), just don't push the bad message into the returned `Vec`. The framework can't tell the difference between "no message ready" and "bad message skipped" — both are fine.

For flow-level errors (the parser's internal state is corrupted past recovery), set `is_poisoned() -> true` after you detect it. The driver then:

1. Optionally emits `SessionEvent::FlowAnomaly { kind: SessionParseError { side, reason } }` (when `with_emit_anomalies(true)`).
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
        out.extend(parser.feed_initiator(std::slice::from_ref(byte), Timestamp::default()));
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

### Updating per-flow state from parser messages (0.5.0)

If your application maintains **rich per-flow state** — TCP rich stats, connection-level counters, middleware state machines — that gets updated by BOTH the reassembler (TCP-layer signals) and the L7 parser (application-layer signals), you have a state-consolidation problem: where does the state live, and who writes it?

flowscope's answer: state lives on `FlowEntry::user`, and the **consumer's event loop** writes it. The parser produces messages; the consumer turns messages into state updates.

This avoids piping `&mut S` through `SessionParser::feed_*`, which would ripple a generic parameter through every shipped parser and every consumer of `SessionParserFactory`.

#### The canonical pattern

```rust,ignore
use flowscope::{FlowSessionDriver, FlowSide, SessionEvent, Timestamp};
use flowscope::extract::FiveTuple;

// 1. Define your per-flow state.
#[derive(Default)]
struct RichFlowState {
    init_messages: u64,
    resp_messages: u64,
    last_message_at: Option<Timestamp>,
}

// 2. Wire the driver with `S = RichFlowState`.
let mut driver = FlowSessionDriver::<_, MyParser, RichFlowState>::new(
    FiveTuple::bidirectional(),
    MyParser::default(),
);

// 3. After each `track()`, walk the events and update state.
for view in source.views() {
    for ev in driver.track(view?) {
        match ev {
            SessionEvent::Application { key, side, message, ts, .. } => {
                if let Some(entry) = driver.tracker_mut().get_mut(&key) {
                    let s = &mut entry.user;
                    match side {
                        FlowSide::Initiator => s.init_messages += 1,
                        FlowSide::Responder => s.resp_messages += 1,
                    }
                    s.last_message_at = Some(ts);
                    consume_message(message);
                }
            }
            SessionEvent::Closed { key, stats, .. } => {
                if let Some(entry) = driver.tracker().get(&key) {
                    publish_rich_summary(&key, &stats, &entry.user);
                }
            }
            _ => {}
        }
    }
}
```

#### Why this works

- **No second `HashMap` in the consumer.** State lives on `FlowEntry` next to the standard `FlowStats`; tracker LRU eviction cleans both up together.
- **No trait change.** `SessionParser` stays minimal — message production is decoupled from state mutation.
- **Reassembler-side updates use the same shape.** A custom `Reassembler` can keep its own per-side counters and the consumer reads `reassembler.dropped_segments()` / `.retransmits()` after `track()`, writing deltas into `entry.user`.

#### Trade-offs vs the "parser holds state" pattern

| Concern | Consumer-loop (this) | Parser-holds-state |
|---------|----------------------|--------------------|
| Where state lives | `FlowEntry::user` (one source) | Per-parser HashMap (a second source) |
| Eviction | LRU drops together with stats | Manual cleanup in `rst_*` |
| Thread safety | Single accessor via `tracker_mut()` | Parser manages |
| Looks like | Imperative event-handler | Encapsulated parser |

For the common case (one consumer, one parser-per-protocol, state updated by reassembler AND parser), consumer-loop wins on simplicity.

#### When the parser DOES need state on every byte

For state that genuinely tracks at the parsing-step level — HPACK decoder state in HTTP/2, FIX session state in middle-of-stream re-keying — that state belongs **inside** the parser. The "per-flow rich state" pattern above is for state that's *about* the flow, not state that's *internal* to parsing.

If your use case is genuinely the latter and a `StateAwareSessionParser` trait would help, file an issue with the concrete reproducer; we revisit the API change once a second consumer asks.

## Sync vs async session driving (0.2.0)

`SessionParser` is just a trait — the *driver* that feeds it bytes
and emits `SessionEvent` lives in two places:

| Path | Helper | Where |
|------|--------|-------|
| Async (tokio) | `cap.flow_stream(...).session_stream(parser)` | `netring` |
| Sync (no runtime) | `FlowSessionDriver::new(extractor, parser)` | `flowscope` |
| Sync, offline pcap | `PcapFlowSource::open(path)?.sessions(extractor, parser)` | `flowscope` |

All three produce the same `SessionEvent` stream for the same wire
bytes. Pick by control flow:

- **Live capture, tokio app** → netring's `session_stream`.
- **Offline pcap replay** → `PcapFlowSource::sessions()` (TCP) /
  `datagrams()` (UDP) — a single iterator, end-of-input flush
  folded in.
- **Embedded, custom frame source, manual control** →
  `FlowSessionDriver` directly.

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

For offline pcap specifically, `PcapFlowSource::sessions(extractor,
parser)` collapses the whole loop — including the final `finish()` —
into one iterator:

```rust,ignore
for evt in PcapFlowSource::open("trace.pcap")?
    .sessions(FiveTuple::bidirectional(), MyParser::default())
{
    // SessionEvent::Started / Application / Closed — already flushed
}
```

`FlowSessionDriver::with_config` honours
`FlowTrackerConfig::max_reassembler_buffer` and `overflow_policy`
automatically — buffer caps and overflow policies (Plan 42) work
identically across sync and async.

### Per-flow user state (0.6)

`FlowSessionDriver` (and `FlowDatagramDriver`, `FlowDriver`) carry
an optional third type parameter `S` for per-flow user state,
defaulting to `()`. The common-case constructors (`new`,
`with_config`) live on a pinned `impl<E, P> FlowSessionDriver<E, P,
()>` block, so call sites that don't need state require no type
annotation. Three additional constructors target the stateful path:

| Constructor | When to use |
|-------------|-------------|
| `with_state(extractor, parser)` | `S: Default`; state is `S::default()` per flow |
| `with_state_and_config(extractor, parser, config)` | same + explicit `FlowTrackerConfig` |
| `with_state_init(extractor, parser, |key| -> S)` | derive state from the flow key |
| `with_state_init_and_config(extractor, parser, config, init)` | same + explicit config |

```rust,ignore
let mut driver: FlowSessionDriver<_, _, MyPerFlowState> =
    FlowSessionDriver::with_state_init(
        FiveTuple::bidirectional(),
        MyParser::default(),
        |key: &FiveTupleKey| MyPerFlowState::from_key(key),
    );
// driver.tracker_mut() now returns &mut FlowTracker<E, MyPerFlowState>
// — read/mutate the state through the tracker's per-flow accessors.
```

The same split (`with_state`, `with_state_init`, …) is on
`FlowDriver` and `FlowDatagramDriver`.

## Reassembly health (0.2.0; expanded 0.5.0, 0.6.0)

Every `FlowEvent::Ended` carries reassembly diagnostics in its
`stats` field:

```rust,ignore
let FlowEvent::Ended { stats, .. } = ev else { return };
println!(
    "ooo init={} resp={}; oversize init={} resp={}; retx init={} resp={}",
    stats.reassembly_dropped_ooo_initiator,
    stats.reassembly_dropped_ooo_responder,
    stats.reassembly_bytes_dropped_oversize_initiator,
    stats.reassembly_bytes_dropped_oversize_responder,
    stats.retransmits_initiator,
    stats.retransmits_responder,
);
```

- `reassembly_dropped_ooo_*` — segments strictly past the expected
  sequence number; they carry bytes the reassembler has not yet
  seen but cannot place in-order.
- `reassembly_bytes_dropped_oversize_*` — payload bytes dropped
  from the buffer because of an
  [`OverflowPolicy`](#recovery-after-buffer-cap)-driven cap (zero
  unless `with_max_buffer` was set).
- `retransmits_{initiator,responder}` (0.5.0) — segments whose
  payload re-delivers bytes the reassembler has already accounted
  for (`seq + len <= expected_seq`, including partial overlap).
- `reassembler_high_watermark_*` — peak in-flight buffer occupancy
  ever observed.

Custom `Reassembler` impls can opt into surfacing these counters
by overriding the default-zero trait methods
(`dropped_segments`, `bytes_dropped_oversize`, `retransmits`,
`high_watermark`).

### Segment timestamps (0.5.0)

`Reassembler::segment(seq, payload, ts)` receives the carrying
packet's kernel/source timestamp. The default `BufferedReassembler`
uses `ts` only to forward classified retransmits to
[`Reassembler::on_duplicate`]; custom reassemblers can use it for
RTT estimation, staleness windows, etc. The signature is a
breaking change vs 0.4.0 — existing impls need a one-line update.

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

The driver then emits `FlowEvent::FlowAnomaly { key, kind, .. }`
(per-flow) and `FlowEvent::TrackerAnomaly { kind, .. }` (tracker-
global) events inline, coalesced per (flow, side, kind) per tick:

| `AnomalyKind` | Fires when | Carries |
|---------------|-----------|---------|
| `BufferOverflow` | reassembler dropped bytes due to a cap | `side`, `bytes` (delta this tick), `policy` |
| `OutOfOrderSegment` | reassembler dropped one or more OOO segments | `side`, `count` (delta) |
| `FlowTableEvictionPressure` | tracker hit `max_flows` and evicted ≥ 1 flow | `evicted_in_tick`, `evicted_total` |
| `SessionParseError` (0.3.0) | a `SessionParser` / `DatagramParser` returned `is_poisoned() == true` | `side`, `reason` (truncated `poison_reason()`) |
| `RetransmittedSegment` (0.5.0) | reassembler classified one or more segments as retransmits | `side`, `count` (delta) |

Anomalies appear **before** any synthesised `Ended` event for the
same flow so cause-then-effect ordering is preserved. The default
is `false` — existing consumers see no behaviour change without
opting in.

For production aggregation (Prometheus / OpenTelemetry), pair this
with the `metrics` feature (Plan 40, future release): the same
`AnomalyKind` vocabulary drives the metric labels.

## Periodic flow ticks (0.5.0)

Push-style periodic `FlowStats` emission for flow-statistics
publishers. Opt in by setting
`FlowTrackerConfig::flow_tick_interval` to `Some(d)`:

```rust,ignore
use std::time::Duration;
use flowscope::{FlowDriver, FlowTrackerConfig, BufferedReassemblerFactory};
use flowscope::extract::FiveTuple;

let cfg = FlowTrackerConfig {
    flow_tick_interval: Some(Duration::from_secs(5)),
    ..FlowTrackerConfig::default()
};
let mut driver = FlowDriver::with_config(
    FiveTuple::bidirectional(),
    BufferedReassemblerFactory::default(),
    cfg,
);
```

The driver then emits one `FlowEvent::Tick { key, stats, ts }`
per live flow per interval. `stats` is a fresh `FlowStats`
clone with all reassembly-diagnostic fields patched in
(`reassembly_dropped_ooo_*`, `bytes_dropped_oversize_*`,
`reassembler_high_watermark_*`, `retransmits_*`). Consumers can
keep the clone past further `track()` calls.

`FlowSessionDriver` and `FlowDatagramDriver` forward as
`SessionEvent::FlowTick`.

### Semantics

- **Timing is driven by packet timestamps**, not wall clock. A
  flow that goes silent between ticks emits no ticks during the
  silence; idle detection still belongs to
  `FlowTracker::sweep` / the idle-timeout machinery.
- **First packet fires an initial tick** — `last_tick_at` starts
  at `None`, so the first observed packet for the flow is past-
  due.
- **`flow_tick_interval = None`** (default) — no ticks; existing
  behaviour preserved.
- Compatible with `with_monotonic_timestamps(true)`: tick timing
  uses the clamped timestamp.

A new `flowscope_flow_ticks_total` counter fires per emitted
Tick when the `metrics` feature is on.

### Pull alternative

`FlowDriver::snapshot_flow_stats()` /
`FlowSessionDriver::snapshot_flow_stats()` stay as the pull
alternative for consumers that want full control over emission
cadence. Pick whichever fits your control flow:

- **Push (ticks)**: integrates cleanly with an event-loop
  consumer that already matches on `FlowEvent` / `SessionEvent`.
- **Pull (snapshot)**: integrates with a separate scrape loop
  (Prometheus scrape, periodic exporter timer).

## Trait stability

The `SessionParser` / `DatagramParser` trait shape is validated
across the four shipped parsers (HTTP, TLS, DNS-UDP, DNS-TCP) plus
11 splitting-invariance proptests. In 0.4.0 the data methods
(`feed_initiator` / `feed_responder` / `parse`) gained a
`ts: Timestamp` parameter and both traits gained a defaulted
`on_tick` hook — a one-time pre-1.0 break (migration: add a
`_ts: Timestamp` argument to your `feed_*` / `parse` signatures).
Post-1.0, additions stay **additive** (new methods with default
implementations); breaking changes require a major bump.

## Concrete trait shape, for reference

```rust,ignore
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;
    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn parser_kind(&self) -> &'static str { "" } // 0.5.0
}

pub trait DatagramParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp) -> Vec<Self::Message>;
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn parser_kind(&self) -> &'static str { "" } // 0.5.0
}
```

### `parser_kind` (0.5.0)

Identify which parser produced a message via the new
`parser_kind` field on `SessionEvent::Application`. The shipped
parsers report stable identifiers (`http/1`, `tls`, `dns-udp`,
`dns-tcp`); the length-prefixed example reports
`length-prefixed`. Operators route metric labels by this string;
keep it lowercase, ASCII, snake-case or slash-separated, and
stable for the parser's lifetime.

Both have a `*Factory<K>` companion trait so you can implement
custom per-flow construction. Any `Default + Clone` parser is its
own factory via a blanket impl — the common case requires no
factory boilerplate.

## Re-exporting flowscope types (0.7.0)

Downstream crates that re-export flowscope types — `netring`,
sister crates, internal forks — hit a small rustdoc trap on the
intra-doc links they write back to the re-exported types.

The obvious form:

```rust
//! See [`FlowSessionDriver`](flowscope::FlowSessionDriver) for the
//! sync session-event driver.
```

triggers `rustdoc`'s `redundant_explicit_links` lint under `-D
warnings`. The reason: path resolution already flows through the
re-export, so the explicit `flowscope::FlowSessionDriver` target
equals what `[FlowSessionDriver]` would resolve to anyway. The
explicit path is duplication, not disambiguation.

The fix is to write the bare form:

```rust
//! See [`FlowSessionDriver`] for the sync session-event driver.
```

Concretely, in a netring-shape re-export:

```rust,ignore
// In netring/src/lib.rs:
pub use flowscope::FlowSessionDriver;

// In netring's rustdoc anywhere downstream:
/// See [`FlowSessionDriver`] for the sync session-event driver.
```

Bare-form `[FlowSessionDriver]` resolves correctly on docs.rs
because rustdoc walks the re-export. No warning. No round-trip
to debug. This saves every re-exporter the same 5-minute
investigation.
