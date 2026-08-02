# Getting started

flowscope is passive flow & session tracking for packet-capture
pipelines. Single crate, runtime-free, cross-platform. Pair with
[netring](https://crates.io/crates/netring) for live Linux capture
or with pcap files for offline replay.

This guide walks through four minimal pipelines so you can see
the shape before you commit to a layer:

0. **The shortest path** — `Driver<E>` with a typed slot handle.
1. Lifecycle only — flow events without bytes.
2. Typed L7 messages — HTTP requests from a pcap.
3. Async live capture — same, but via netring.

After each, the right doc to read next is called out.

## Install

```toml
[dependencies]
flowscope = "0.23"
```

MSRV is Rust 1.97.

The default features cover the core stack (`extractors`,
`tracker`, `reassembler`, `session`). Opt into protocol parsers
and observability piecemeal:

```toml
flowscope = { version = "0.23", features = ["l7", "pcap", "metrics", "tracing", "emit-eve"] }
```

| Feature | What it adds |
|---------|--------------|
| `http`, `tls`, `dns`, `icmp` | L7 parsers, one feature each. `http` is HTTP/1.x. |
| `http2` | HTTP/2 frame layer + HPACK + per-stream routing, and the gRPC call/status surface |
| `l7` | Umbrella — every license-clean protocol parser (`parsers-core` + `parsers-l2l3` + `parsers-tier2` + `tls-fingerprints`) |
| `pcap` | Offline pcap source |
| `metrics`, `tracing` | Observability (zero-cost when off) |
| `serde` | `Serialize` + `Deserialize` on every public event / message type |
| `tls-fingerprints` | JA3 + JA4 TLS client fingerprinting (sub-feature of `tls`) |
| `emit`, `emit-ndjson`, `emit-eve` | Structured event sinks — CSV / Zeek / NDJSON / Suricata EVE JSON |
| `chrono` | `Timestamp` ↔ `chrono::DateTime<Utc>` interop |
| `test-helpers` | Reusable parser stubs for downstream test crates |

## 0. The shortest path: `Driver<E>` with a slot handle

The 90 % case: one builder, one slot handle per protocol,
`track_into` for the flow-lifecycle stream, `drain` for the
typed parser output.

```rust,ignore
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::PacketView;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs:   Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open("trace.pcap")?.views() {
        let owned = owned?;
        events.clear();
        msgs.clear();
        driver.track_into(PacketView::from(&owned), &mut events);
        http.drain(&mut msgs);

        for m in &msgs {
            println!("{:?} {:?}", m.side, m.message);
        }
        for ev in &events {
            if let Event::Started { key, .. } = ev {
                println!("+ flow {key:?}");
            }
        }
    }
    Ok(())
}
```

Build with `cargo run --features http,pcap`.

`builder.session_on_ports(parser, ports)` returns a typed
`SlotHandle<P::Message, E::Key>`. Each registration returns a
fresh handle — register HTTP on 80/8080, TLS on 443, DNS on 53;
drain each independently per packet. The handle is `Send + Sync`
(0.12) and the whole `Driver<E>` is `Send + Sync` since 0.13 —
`tokio::spawn(driver_task)` on the default multi-thread runtime
just works. For broadcast delivery (every clone sees every
message, not competitive-consumer), register through
`session_on_ports_broadcast_each` and use `BroadcastSlotHandle`
(0.13).

For per-flow user state on the central tracker, drop to
`FlowDriver`. The typed `Driver<E>` is the single supported
single-parser surface — register one slot per protocol and drain
it.

**Read next:** [`concepts.md`](concepts.md) — the four-layer
trait shape.

## 1. Lifecycle only

The cheapest layer: a tracker that emits a `FlowEvent` per
packet. No L7. No bytes. Five tuples + state machine.

```rust,ignore
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker, PacketView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());

    for owned in PcapFlowSource::open("trace.pcap")?.views() {
        let owned = owned?;
        for evt in tracker.track(PacketView::from(&owned)) {
            match evt {
                FlowEvent::Started { l4, key, .. } => {
                    println!("+ {:?} {:?}", l4, key);
                }
                FlowEvent::Ended { reason, stats, l4, .. } => {
                    println!("- {:?} {:?} packets={}",
                        l4, reason,
                        stats.packets_initiator + stats.packets_responder);
                }
                _ => {}
            }
        }
    }
    for evt in tracker.finish() {
        if let FlowEvent::Ended { reason, l4, .. } = evt {
            println!("- final {:?} {:?}", l4, reason);
        }
    }
    Ok(())
}
```

Build with `cargo run --features pcap`.

**Read next:** [`concepts.md`](concepts.md) — Layer 1 (extractor)
and Layer 2 (tracker).

## 2. Typed HTTP messages from a pcap (`Driver<E>` + a session slot)

A single-parser pipeline is just section 0 with one slot. The
slot drains typed `HttpMessage`s; the lifecycle `Event<K>` stream
comes out of `track_into`:

```rust,ignore
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::PacketView;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open("trace.pcap")?.views() {
        let owned = owned?;
        events.clear();
        msgs.clear();
        driver.track_into(PacketView::from(&owned), &mut events);
        http.drain(&mut msgs);
        for m in &msgs {
            match &m.message {
                HttpMessage::Request(req) => {
                    println!("{:?} {:?} (host={})",
                        req.method, req.path,
                        req.host().unwrap_or("?"));
                }
                HttpMessage::Response(resp) => {
                    println!("  → {} {:?}", resp.status, resp.reason);
                }
                _ => {}
            }
        }
    }
    Ok(())
}
```

Build with `cargo run --features http,pcap`.

The `host()` / `user_agent()` / `cookie()` / `content_type()` /
`content_length()` / `set_cookie()` / generic `header(name)`
accessors save the `find().and_then(str::from_utf8)` dance every
header lookup would otherwise need.

**Read next:** [`recipes.md`](recipes.md) — picking the right
parser API, writing your own, and multi-protocol patterns.

## 3. Async live capture

Same parser, but driven from a live AF_PACKET / AF_XDP socket via
netring:

```rust,ignore
use futures::StreamExt;
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut stream = AsyncCapture::open("eth0")?
        .flow_stream(FiveTuple::bidirectional())
        .session_stream(HttpParser::default());

    // netring owns its async session-event type as of the
    // 0.20-coordinated release — flowscope no longer exports
    // `SessionEvent`. Its `Application` arm carries the parser
    // message; see netring's docs for the exact item type.
    while let Some(evt) = stream.next().await {
        if let netring::SessionEvent::Application {
            message: HttpMessage::Request(req), ..
        } = evt?
        {
            println!("{} {}", req.method, req.path);
        }
    }
    Ok(())
}
```

flowscope itself is sync — `tokio` lives in netring. The trait
`HttpParser` is the same one in both the offline and async
pipelines.

## Where to go from here

Pick one based on what you're building:

| Want | Read |
|------|------|
| Understand the layers | [`concepts.md`](concepts.md) |
| Worked patterns (multi-protocol, correlation, custom parsers) | [`recipes.md`](recipes.md) |
| Metrics + tracing + severity routing | [`observability.md`](observability.md) |
| Benchmarks and methodology | [`performance.md`](performance.md) |
| Why flowscope is shaped this way | [`design.md`](design.md) |

## Running the bundled examples

```sh
cargo run --features pcap --example pcap_flow_summary -- trace.pcap
cargo run --features http,pcap --example http_log       -- trace.pcap
cargo run --features dns,pcap  --example dns_log        -- trace.pcap
cargo run --features tls,pcap  --example tls_observer   -- trace.pcap
cargo run --features l7,pcap   --example multi_protocol_monitor -- trace.pcap
```

`generate_fixtures` builds the synthesised pcap test data the
parser tests use; you don't normally need it.
