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
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);
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
