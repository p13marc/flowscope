# Changelog

## Unreleased

### Plan 31 phase 2: TLS + DNS-TCP `SessionParser` bridges

Completes the `SessionParser` parser family started in 0.1.0. All
four shipped Tier 2 parsers now expose both the callback-style
factory API (`HttpFactory`, `TlsFactory`, `DnsUdpObserver`) and the
typed-message-stream `SessionParser` / `DatagramParser` API.

- **`flowscope::tls::TlsParser`** — `SessionParser` impl producing
  `TlsMessage::{ClientHello, ServerHello, Alert}`. With the `ja3`
  feature, also emits `TlsMessage::Ja3 { hash, canonical }`. Holds
  independent `DirState` per direction inside one parser; encrypted
  records (post-CCS in TLS 1.2, post-ServerHello in 1.3) are
  silently dropped, preserving the existing `TlsFactory` semantics.
  4 unit tests.

- **`flowscope::dns::DnsTcpParser`** — `SessionParser` impl for
  DNS over TCP (RFC 1035 §4.2.2). Each direction runs an
  independent length-framed state machine: read 2-byte big-endian
  length, then `len` bytes of message body, parse via the existing
  `parse_message`, emit. Pipelined and split-segment cases handled.
  Reuses `DnsMessage::{Query, Response}` from the UDP path.
  Malformed bodies are dropped without losing framing (the length
  prefix tells us how many bytes to skip). 8 unit tests.

The `SessionParser` trait shape is unchanged; phase 2 only adds
implementations. With four parsers (HTTP, TLS, DNS-UDP, DNS-TCP)
exercising the trait across both `SessionParser` and
`DatagramParser` variants, the trait shape can now be considered
stable for the 1.0 lock.

Out of scope for this release (deferred follow-ups):
- Property tests across all parsers (planned for pre-1.0).
- Migration guide (`docs/SESSION_GUIDE.md`).

## 0.1.0 — Initial release

`flowscope` is a one-crate consolidation of the previous
`netring-flow{,-http,-tls,-dns,-pcap}` workspace. Same code, single
publishable crate, feature-gated modules.

### Core

- `PacketView` / `Timestamp` — abstract input.
- `FlowExtractor` trait + built-in extractors: `FiveTuple`, `IpPair`,
  `MacPair`. Decap combinators: `StripVlan`, `StripMpls`, `InnerVxlan`,
  `InnerGtpU`.
- `FlowTracker<E, S>` — bidirectional flow accounting, TCP state machine
  (`SynSent → Established → FinWait → Closed` + `Reset`), per-protocol
  idle timeouts (Suricata defaults), LRU eviction.
- `FlowEvent<K>` — `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with `EndReason`, `FlowStats`, `HistoryString`).
- `Reassembler` / `ReassemblerFactory<K>` — sync TCP-segment hook;
  `BufferedReassembler` built-in.
- `FlowDriver<E, F, S>` — sync wrapper combining tracker + reassembler.
- `SessionParser` / `DatagramParser` (and their `Factory` variants) —
  typed L7 message parsing per flow. `SessionEvent<K, M>` encapsulates
  lifecycle + application messages.

### Protocol parsers

- `http` feature — HTTP/1.0 / HTTP/1.1 via `httparse`. `HttpFactory`
  (callback) and `HttpParser` (`SessionParser`) ship side by side.
- `tls` feature — passive TLS handshake observer (ClientHello,
  ServerHello, Alert). `TlsFactory` (callback) — `SessionParser` impl
  pending. Optional `ja3` sub-feature for JA3 fingerprinting (GREASE
  stripped per RFC 8701).
- `dns` feature — DNS-over-UDP message parser, per-flow query/response
  correlator (16-bit transaction ID, scoped per flow key, oldest-first
  eviction, sweep for unanswered timeouts). `DnsUdpObserver` (tap on
  inner extractor) and `DnsUdpParser` (`DatagramParser`).
- `pcap` feature — `PcapFlowSource` for offline replay; views & flow
  events from any `.pcap` file.

### Notes

- Migrated from the netring workspace (commits `dc7cb19` and earlier).
  Plans `12`, `20`, `22`–`24`, `30`–`32`, `41` move with the migration.
- Out of scope for v0.1: `TlsParser` / `DnsTcpParser` `SessionParser`
  bridges (mechanical follow-up — tracked in plans/31), HTTP/2,
  HTTP/3, DoH/DoT/DoQ, NetFlow/IPFIX export (plan 32).
- `netring-flow*` users: rename your dependency to `flowscope`,
  update import paths from `netring_flow_http::X` → `flowscope::http::X`
  (and similarly for `tls` / `dns` / `pcap`). Trait names and types
  unchanged.
