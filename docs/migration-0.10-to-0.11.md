# Migration: flowscope 0.10 → 0.11

The 0.11 cycle is the zero-allocation cycle. Most users see two
breaking changes: the parser trait shape, and the driver shape.
Everything else is mechanical.

## Cheat sheet

| You used … | You now use … |
|---|---|
| `fn feed_initiator(&mut self, b, ts) -> Vec<Msg>` | `fn feed_initiator(&mut self, b, ts, out: &mut Vec<Msg>)` |
| `Driver::<_, MyL7>::builder(ext).session_on_ports(p, [80], MyL7::Http).build()` | `let mut b = Driver::builder(ext); let mut s = b.session_on_ports(p, [80]); let mut d = b.build();` |
| `for ev in driver.track(view) { Event::Message { message, .. } => … }` | `driver.track_into(view, &mut events); slot.drain(&mut msgs);` |
| `req.method == "GET"` | `req.method.as_ref() == b"GET"` or `req.method_str() == Some("GET")` |
| `req.headers: Vec<(String, Vec<u8>)>` | `req.headers: Vec<(Bytes, Bytes)>` |
| `flowscope::driver_unified::Driver` | `flowscope::driver::Driver` |
| `flowscope::FlowDriver` | unchanged (top-level re-export) |
| `flowscope::FlowMultiSessionDriver` | deleted; register multiple slots on `Driver::builder` |
| `flowscope::Pipeline` | deleted; use `Driver::builder` directly |

## 1. Parser trait signature change

`SessionParser` and `DatagramParser` methods take an `out`
buffer instead of returning `Vec<Self::Message>`. Same idiom as
`httparse::Request::parse`.

### Before (0.10):

```rust
impl SessionParser for MyParser {
    type Message = MyMsg;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp)
        -> Vec<Self::Message>
    {
        let mut out = Vec::new();
        // ...parse bytes...
        out.push(msg);
        out
    }

    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp)
        -> Vec<Self::Message> { Vec::new() }
}
```

### After (0.11):

```rust
impl SessionParser for MyParser {
    type Message = MyMsg;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp,
        out: &mut Vec<Self::Message>)
    {
        // ...parse bytes...
        out.push(msg);
    }

    fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp,
        _out: &mut Vec<Self::Message>) {}
}
```

Same shape for `fin_initiator` / `fin_responder` / `on_tick`
(`SessionParser`) and `parse` / `on_tick` (`DatagramParser`).

**Why**: every `Vec::new()` per parser call was an
allocation-on-first-push; sharing one buffer across calls
reuses capacity → zero allocation in steady state.

## 2. Driver shape: typed slot drains

The closed-`M` sum-type driver is gone. Each parser stays
typed at its own `P::Message`; consumers drain a typed handle.

### Before (0.10):

```rust
use flowscope::driver_unified::{Driver, Event};

#[derive(Debug)]
enum MyL7 { Http(HttpMessage), Dns(DnsMessage) }

let mut driver = Driver::<_, MyL7>::builder(FiveTuple::bidirectional())
    .session_on_ports(HttpParser::default(), [80], MyL7::Http)
    .datagram_on_ports(DnsUdpParser::default(), [53], MyL7::Dns)
    .build();

for event in driver.track(view) {
    match event {
        Event::Message { message: MyL7::Http(http), .. } => { /* … */ }
        Event::Message { message: MyL7::Dns(dns), .. } => { /* … */ }
        Event::FlowStarted { .. } => { /* … */ }
        _ => {}
    }
}
```

### After (0.11):

```rust
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};

let mut builder = Driver::builder(FiveTuple::bidirectional());
let mut http_slot = builder.session_on_ports(HttpParser::default(), [80]);
let mut dns_slot  = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
let mut driver   = builder.build();

let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
let mut dns_msgs:  Vec<SlotMessage<DnsMessage, FiveTupleKey>>  = Vec::new();

for view in views {
    events.clear();
    driver.track_into(view, &mut events);

    http_msgs.clear();
    http_slot.drain(&mut http_msgs);
    dns_msgs.clear();
    dns_slot.drain(&mut dns_msgs);

    for ev in &events {
        match ev {
            Event::FlowStarted { .. } => { /* … */ }
            _ => {}
        }
    }
    for m in &http_msgs { /* m.message: &HttpMessage, m.key: &FiveTupleKey */ }
    for m in &dns_msgs  { /* m.message: &DnsMessage */ }
}
```

**Why**: the new shape eliminates the closed-`M` sum type and
the lift closures. Each parser keeps its native `Message`; the
consumer drains a typed handle. Zero per-message `Box` —
critical for netring 0.19's zero-allocation contract.

**Single-threaded.** The slot bufs are `Rc<RefCell>`, not
`Arc<Mutex>`. Drain inside one event loop and post over a
channel for cross-task delivery.

## 3. Module renames

| 0.10 | 0.11 |
|---|---|
| `flowscope::driver_unified` | `flowscope::driver` |
| `flowscope::driver_unified::Driver<E, M>` | `flowscope::driver::Driver<E>` |
| `flowscope::driver_unified::Event<K, M>` | `flowscope::driver::Event<K>` |
| `flowscope::driver_unified::Pipeline<E, M>` | (deleted) |
| `flowscope::driver` (`FlowDriver`) | `flowscope::flow_driver` (re-exported at `flowscope::FlowDriver`) |

The top-level `flowscope::FlowDriver` re-export is unchanged.

## 4. Bytes-typed payload fields

HTTP / DNS / TLS payload types now use `bytes::Bytes`. Existing
header accessors keep their signatures.

### HTTP

| Field | 0.10 | 0.11 |
|---|---|---|
| `HttpRequest::method` | `String` | `Bytes` |
| `HttpRequest::path` | `String` | `Bytes` |
| `HttpRequest::headers` | `Vec<(String, Vec<u8>)>` | `Vec<(Bytes, Bytes)>` |
| `HttpResponse::reason` | `String` | `Bytes` |
| `HttpResponse::headers` | same | same |

New convenience accessors:

- `HttpRequest::method_str() -> Option<&str>`
- `HttpRequest::path_str() -> Option<&str>`
- `HttpResponse::reason_str() -> Option<&str>`

### DNS

- `DnsRdata::TXT(Vec<Vec<u8>>)` → `TXT(SmallVec<[Bytes; 4]>)`
- `DnsRdata::Other.data: Vec<u8>` → `Bytes`

### TLS

- `TlsClientHello::compression: Vec<u8>` → `Bytes`

### Common compare patterns

```rust
// 0.10:
if req.method == "GET" { … }
let host = req.headers.iter()
    .find(|(n, _)| n.eq_ignore_ascii_case("host"))
    .map(|(_, v)| String::from_utf8_lossy(v));

// 0.11:
if req.method.as_ref() == b"GET" { … }
//   or
if req.method_str() == Some("GET") { … }
// Header lookup is unchanged — req.host() / req.content_type() etc.:
let host = req.host();
// Direct iteration is now (Bytes, Bytes):
let host = req.headers.iter()
    .find(|(n, _)| n.as_ref().eq_ignore_ascii_case(b"host"))
    .map(|(_, v)| String::from_utf8_lossy(v));
```

## 5. Removed types

The following 0.10 types are deleted:

- `flowscope::FlowMultiSessionDriver` — register multiple slots
  on the typed `Driver::builder` instead. Each parser keeps its
  own typed `SlotHandle`; no need for a lift closure.
- `flowscope::Pipeline` + `flowscope::PipelineBuilder` (the
  legacy top-level pipeline) — use `Driver::builder` directly,
  paired with `PcapFlowSource` for the iteration loop:
  ```rust
  for view in PcapFlowSource::open(path)?.views() {
      events.clear();
      driver.track_into(&view?, &mut events);
      // ... drain slot handles, process events ...
  }
  ```
- `flowscope::driver_unified::Pipeline` (the unified pipeline) —
  same migration as above.
- `flowscope::FlowSessionDriverBuilder` /
  `flowscope::FlowDatagramDriverBuilder` — call
  `FlowSessionDriver::with_config(...)` /
  `FlowDatagramDriver::with_config(...)` directly.
- `flowscope::driver_unified::Driver<E, M>` and its supporting
  types — replaced by `flowscope::driver::Driver<E>`.

## 6. `Event::FlowPacket::frame` field removed

```rust
// 0.10:
Event::FlowPacket { key, side, len, ts, tcp, frame } => {
    if let Some(f) = frame { /* use bytes */ }
}

// 0.11:
Event::FlowPacket { key, side, len, ts, tcp } => {
    // For frame bytes: hold onto the source PacketView you
    // handed to track_into(); the bytes are still there.
}
```

The `emit_packet_details(true)` builder knob still populates
`tcp: Option<TcpInfo>` per packet. The `frame` field was a
per-packet `view.frame.to_vec()` clone — 1.5 GB/sec of
allocator + memcpy at 1 Mpps with 1500-byte frames. The bytes
are still reachable on the source `PacketView`.
