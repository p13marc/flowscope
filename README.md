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
| `full`  | All of the above |

## Quick start

```toml
[dependencies]
flowscope = { version = "0.5", features = ["full"] }
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

Typed L7 messages are one iterator away — `sessions()` runs an
extractor plus a per-flow `SessionParser` over the pcap, with the
end-of-input flush folded in:

```rust,no_run
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::http::HttpParser;
use flowscope::SessionEvent;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
for evt in PcapFlowSource::open("trace.pcap")?
    .sessions(FiveTuple::bidirectional(), HttpParser::default())
{
    if let SessionEvent::Application { message, .. } = evt? {
        println!("{message:?}");
    }
}
# Ok(()) }
```

`datagrams()` is the UDP mirror. For TLS / DNS and the callback-style
`*Factory<H>` APIs, see `examples/` and the per-module documentation
on docs.rs.

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

0.5.0 — TCP rich diagnostics + periodic ticks + parser identity,
driven by the
[`simple-nms` upstream wishlist](docs/feedback-2026-08-11-simple-nms.md).
Core flow APIs (`FlowExtractor`, `FlowTracker`, `Reassembler`,
`SessionParser`, `DatagramParser`) are settled; public structs
and enums are `#[non_exhaustive]` so future variants and fields
are additive.

0.5.0 ships:
- TCP retransmit classification on `BufferedReassembler`
  (`Reassembler::retransmits()`, `on_duplicate(seq, payload, ts)`
  hook, `AnomalyKind::RetransmittedSegment`,
  `FlowStats::retransmits_*`, `flowscope_retransmits_total`).
- `Reassembler::segment(seq, payload, ts)` — segment timestamps
  for downstream RTT estimation (one-line trait break vs 0.4.0).
- `TcpInfo::window` raw receive window + `#[non_exhaustive]`.
- Opt-in periodic `FlowEvent::Tick` / `SessionEvent::FlowTick`
  via `FlowTrackerConfig::flow_tick_interval`. Driven by packet
  timestamps; pairs with `flowscope_flow_ticks_total`.
- `SessionParser::parser_kind()` / `DatagramParser::parser_kind()`
  threaded into `SessionEvent::Application::parser_kind`. Shipped
  parsers report `http/1`, `tls`, `dns-udp`, `dns-tcp`.
- Reassembly-diagnostic metrics now fire correctly on natural
  flow ends (latent bug — the tracker called `record_flow_ended`
  before the driver patched reassembler-derived fields).
- New SESSION_GUIDE walkthrough for the consumer-loop pattern
  that updates per-flow rich state without piping `&mut S`
  through `SessionParser::feed_*`.

See [`CHANGELOG.md`](CHANGELOG.md) for the full migration
recipes, [`docs/SESSION_GUIDE.md`](docs/SESSION_GUIDE.md) for the
decision-flow on which API to pick, and
[`docs/OBSERVABILITY.md`](docs/OBSERVABILITY.md) for the metric
vocabulary.

0.4.0 features remain: drivers without the `S` type parameter,
`SessionParser`/`DatagramParser` timestamp-aware data methods +
`on_tick`, three-driver `finish()`, `PcapFlowSource::sessions()` /
`datagrams()` one-step pipelines, DNS-UDP unified on
`DnsUdpParser`. 0.3.0 / 0.2.0 features remain: `FlowDatagramDriver`,
sync `Dedup`, per-key idle-timeout predicates, monotonic
timestamps, parser-poison synthesis, anomaly forwarding,
criterion bench harness, buffer caps with `SlidingWindow` /
`DropFlow` policies.

## License

MIT OR Apache-2.0, your choice.
