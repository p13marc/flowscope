# flowscope

[![crates.io](https://img.shields.io/crates/v/flowscope.svg)](https://crates.io/crates/flowscope)
[![docs.rs](https://img.shields.io/docsrs/flowscope)](https://docs.rs/flowscope)
[![CI](https://github.com/p13marc/flowscope/actions/workflows/ci.yml/badge.svg)](https://github.com/p13marc/flowscope/actions)

Passive flow & session tracking for packet capture.

`flowscope` is a runtime-free, cross-platform Rust library for **observing**
what's happening on the wire. It pairs with any source of `&[u8]` frames:
[`netring`](https://crates.io/crates/netring) (Linux AF_PACKET / AF_XDP),
pcap files, tun/tap, eBPF, embedded — anywhere bytes show up.

No tokio, no futures, no async runtime in the core. (For tokio integration,
see `netring`'s `AsyncCapture::flow_stream` etc., which consume this crate's
traits.)

## What's here

```
PacketView   →   FlowExtractor   →   FlowTracker   →   Reassembler   →   SessionParser / DatagramParser
   ↑                                                                              ↓
   anything                                                              typed L7 messages
```

Core (always on):

- `FlowExtractor` trait + built-in extractors (5-tuple, IP-pair, MAC-pair) +
  decap combinators (VLAN, MPLS, VXLAN, GTP-U, GRE) + `AutoDetectEncap`
  combinator + `FlowLabel` IPv6 augmentation.
- `FlowTracker` — bidirectional flow accounting, TCP state machine, idle
  timeouts, LRU eviction.
- `Reassembler` — sync per-(flow, side) hook for TCP byte streams.
- `SessionParser` / `DatagramParser` — typed L7 message parsing per flow.

Protocol parsers (each behind its own feature):

| Feature | What you get |
|---------|--------------|
| `http`  | HTTP/1.x request/response parsing — both `HttpFactory` (callback) and `HttpParser` (`SessionParser`) |
| `tls`   | TLS handshake observer (ClientHello/ServerHello/Alert) — passive only, no decryption |
| `ja3`   | [JA3](https://github.com/salesforce/ja3) client fingerprinting (sub-feature of `tls`) |
| `dns`   | DNS message parser, per-flow query/response correlator. UDP via `DnsUdpParser` (`DatagramParser`); TCP via `DnsTcpParser` (`SessionParser`, RFC 1035 §4.2.2 length-framed) |
| `pcap`  | pcap file source for offline replay |
| `l7`    | Umbrella: enables `http` + `tls` + `dns` together |
| `full`  | All of the above (incl. `ja3`, `pcap`, observability) |

## Quick start

```toml
[dependencies]
flowscope = { version = "0.9", features = ["full"] }
```

MSRV is Rust 1.88.

One import, one builder chain, one iterator — the high-level
`Pipeline` entry point introduced in 0.9.0:

```rust,no_run
use flowscope::prelude::*;
use flowscope::http::HttpParser;

# fn main() -> flowscope::Result<()> {
let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
    .session(HttpParser::default())
    .build();

for event in pipeline.run_pcap("trace.pcap")? {
    if let Event::Tcp(SessionEvent::Application { message, .. }) = event? {
        println!("{message:?}");
    }
}
# Ok(()) }
```

`Pipeline` bundles the common driver setup with sensible defaults
(anomalies emitted, monotonic timestamps for offline replay).
For per-flow user state, custom drainers, or multiple parsers
per L4, drop to `FlowSessionDriver` / `FlowDatagramDriver`
directly.

### Per-packet introspection

The 0.9 `flowscope::layers` module exposes a zero-copy view of a
frame with both direct accessors and a dynamic walk:

```rust,no_run
use flowscope::PacketView;
use flowscope::layers::LayerKind;

# fn ex(pv: PacketView<'_>) -> flowscope::Result<()> {
let layers = pv.layers()?;

// Direct accessors — the common case.
if let Some(tcp) = layers.tcp() {
    println!("seq={} window={}", tcp.seq(), tcp.window());
}
if let Some(vlan) = layers.vlan() {
    println!("vid={}", vlan.vid());
}

// Dynamic walk — "show me everything".
for layer in layers.iter() {
    println!("{} ({}B)", layer.kind(), layer.bytes().len());
}
# Ok(()) }
```

### Custom protocols

For an end-to-end example of writing a `SessionParser` for your own
wire format — including the synchronous offline pcap path via
[`FlowSessionDriver`](https://docs.rs/flowscope/latest/flowscope/session_driver/struct.FlowSessionDriver.html) —
see `examples/length_prefixed_pcap.rs`. The example demonstrates a
length-prefixed binary protocol (PSMSG-shaped) with two
variable-length markers and is paired with a deterministic pcap
fixture under `tests/fixtures/length_prefixed/`.

## Tokio integration

`flowscope` itself is runtime-free. To consume a live capture into a stream
of `FlowEvent` / `SessionEvent` via tokio, use [`netring`](https://crates.io/crates/netring):

```rust,no_run
use netring::AsyncCapture;
use flowscope::extract::FiveTuple;
use flowscope::http::HttpParser;
use futures::StreamExt;

# async fn ex() -> Result<(), Box<dyn std::error::Error>> {
let mut s = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());
while let Some(evt) = s.next().await { /* ... */ }
# Ok(()) }
```

## Status

0.9.0 (in progress) — high-level `Pipeline` entry point,
public `flowscope::layers` per-packet view, unified
`flowscope::Error`, `FlowTracker::with_auto_sweep` for
live/offline parity, `flowscope::prelude`, MSRV bumped to 1.88.

0.8.0 was the last point release: serde wire-format lock,
ICMP correlation helpers, programmatic flow termination,
per-flow snapshot iterator, multi-protocol monitor recipe.

Core flow APIs (`FlowExtractor`, `FlowTracker`, `Reassembler`,
`SessionParser`, `DatagramParser`) are settled; public structs
and enums are `#[non_exhaustive]` so future variants and fields
are additive. See [`CHANGELOG.md`](CHANGELOG.md) for the
release history.

See [`docs/getting-started.md`](docs/getting-started.md) for a
hello-world,
[`docs/concepts.md`](docs/concepts.md) for the conceptual model,
[`docs/recipes.md`](docs/recipes.md) for worked patterns,
[`docs/observability.md`](docs/observability.md) for metrics +
tracing, and [`CHANGELOG.md`](CHANGELOG.md) for the per-release
feature list and migration recipes.

## License

MIT OR Apache-2.0, your choice.
