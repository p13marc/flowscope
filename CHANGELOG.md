# Changelog

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
