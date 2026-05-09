# Changelog

## 0.1.0 — Initial release

`flowscope` is a passive flow & session tracking library extracted
from the previous `netring-flow{,-http,-tls,-dns,-pcap}` workspace
into a single, publishable crate with feature-gated modules. The
core layers (extractor → tracker → reassembler → session/datagram
parsers) are runtime-free and cross-platform; protocol parsers are
opt-in via Cargo features.

### Core

- `PacketView` / `Timestamp` — abstract input.
- `FlowExtractor` trait + built-in extractors: `FiveTuple`, `IpPair`,
  `MacPair`. Decap combinators: `StripVlan`, `StripMpls`, `InnerVxlan`,
  `InnerGtpU`, `InnerGre`. Combinator: `AutoDetectEncap` (tries
  plain → VLAN → MPLS → VXLAN → GTP-U → GRE in order). Key
  augmentation: `FlowLabel<E>` (IPv6 flow label).
- `FlowTracker<E, S>` — bidirectional flow accounting, TCP state
  machine (`SynSent → Established → FinWait → Closed` + `Reset`),
  per-protocol idle timeouts (Suricata defaults), LRU eviction.
  `manual_tick(now)` alias for `sweep`.
- `FlowEvent<K>` — `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with `EndReason`, `FlowStats`, `HistoryString`).
- `Reassembler` / `ReassemblerFactory<K>` — sync per-(flow, side) TCP-
  segment hook; `BufferedReassembler` built-in.
- `FlowDriver<E, F, S>` — sync wrapper combining tracker + reassembler.
- `SessionParser` / `DatagramParser` (with `*Factory<K>` companions
  and blanket impls for `Default + Clone` parsers) — typed L7 message
  parsing per flow. Trait shape stable for the 1.0 lock; future
  additions will be additive.
- `SessionEvent<K, M>` — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.

### Protocol parsers (each behind its own feature)

- **`http`** — HTTP/1.0 / HTTP/1.1 via `httparse`. Both
  `HttpFactory` (callback-style) and `HttpParser` (`SessionParser`)
  ship side by side. Pipelined messages, split segments, and
  Connection: close bodies handled.
- **`tls`** — passive TLS handshake observer. `TlsFactory`
  (callback) and `TlsParser` (`SessionParser`) emit ClientHello /
  ServerHello / Alert events. Records past ChangeCipherSpec are
  silently skipped (encrypted). Optional `ja3` sub-feature for JA3
  fingerprinting (GREASE stripped per RFC 8701).
- **`dns`** — DNS message parser. UDP path: `DnsUdpObserver`
  (callback-style tap on top of any `FlowExtractor`) and
  `DnsUdpParser` (`DatagramParser`). TCP path: `DnsTcpParser`
  (`SessionParser`, RFC 1035 §4.2.2 length-prefixed framing).
  Per-flow query/response correlator with 16-bit transaction ID
  scoping, oldest-first eviction on overflow, sweep for unanswered
  timeouts.
- **`pcap`** — `PcapFlowSource` for offline replay; produces views &
  flow events from any `.pcap` file.

### Tokio integration

For an async stream over flow / session / datagram events, see
[`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`,
`.session_stream`, `.datagram_stream`, and `.broadcast`. The traits
they consume live in this crate; the Stream impls live in `netring`.

### Tests

- 167 unit tests + 11 parser proptests (splitting invariance and
  no-panic across HTTP / TLS / DNS-UDP / DNS-TCP) + tracker
  proptests (FiveTuple canonicalization, TCP state-machine
  invariants).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo doc --all-features --no-deps` clean.

### Documentation

- [`docs/SESSION_GUIDE.md`](docs/SESSION_GUIDE.md) — decision-flow
  for picking between `FlowEvent`, `Reassembler`, `*Factory<H>`,
  `SessionParser`, `DatagramParser`, and `Conversation<K>`. Includes
  migration recipes from callback-style factories to the typed-stream
  parser API.

### Notes

- This crate replaces `netring-flow`, `netring-flow-http`,
  `netring-flow-tls`, `netring-flow-dns`, and `netring-flow-pcap`
  (none of which were ever published to crates.io). Migration:
  rename your dep to `flowscope` and update import paths from
  `netring_flow_http::X` → `flowscope::http::X` (and similarly for
  `tls` / `dns` / `pcap`). Trait names and types are unchanged.
- Out of scope for v0.1.0:
  - HTTP/2, HTTP/3 (no plan yet).
  - DoH / DoT / DoQ (no plan yet).
  - NetFlow / IPFIX export (plan 32, deferred).
  - Observability (`metrics` / `tracing` integration; plan 40,
    deferred).
  - Zero-copy reassembly (plan 41, deferred — needs profiling-guided
    redesign).
  - IPv6 fragment reassembly (plan 50.5, deferred).
  - `protolens` companion (plan 21, on demand).
  - CLI tooling (`flow-summary`, `flow-replay`; plan 60, would need
    workspace conversion).
