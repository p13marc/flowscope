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
  decap combinators (VLAN, MPLS, VXLAN, GTP-U).
- `FlowTracker` — bidirectional flow accounting, TCP state machine, idle
  timeouts, LRU eviction.
- `Reassembler` — sync per-(flow, side) hook for TCP byte streams.
- `SessionParser` / `DatagramParser` — typed L7 message parsing per flow.

Protocol parsers (each behind its own feature):

| Feature | What you get |
|---------|--------------|
| `http`  | HTTP/1.x request/response parsing (built on `httparse`) |
| `tls`   | TLS handshake observer (ClientHello/ServerHello/Alert) — passive only, no decryption |
| `ja3`   | [JA3](https://github.com/salesforce/ja3) client fingerprinting (sub-feature of `tls`) |
| `dns`   | DNS-over-UDP message parser + per-flow query/response correlator |
| `pcap`  | pcap file source for offline replay |
| `full`  | All of the above |

## Quick start

```toml
[dependencies]
flowscope = { version = "0.1", features = ["full"] }
```

```rust,no_run
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::FlowEvent;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
for evt in PcapFlowSource::open("trace.pcap")?.with_extractor(FiveTuple::bidirectional()) {
    if let FlowEvent::Started { key, .. } = evt? {
        println!("flow started: {key:?}");
    }
}
# Ok(()) }
```

For HTTP / TLS / DNS examples and the typed `SessionParser` / `DatagramParser`
APIs, see `examples/` and the per-module documentation on docs.rs.

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

Pre-1.0. The core flow APIs (`FlowExtractor`, `FlowTracker`, `Reassembler`)
are settling. `SessionParser` / `DatagramParser` shipped in 0.1 as the
strategic 1.0 abstraction; the trait shape is on probation pending
real-world feedback.

See `plans/INDEX.md` for the roadmap.

## License

MIT OR Apache-2.0, your choice.
