# Changelog

## Unreleased

### Plan 50 deferred-feature catchup (4 of 6 sub-plans)

- **50.1 `InnerGre<E>`** — decapsulate GRE (RFC 2784/2890) and run
  the inner extractor on the carried protocol. Handles IPv4-in-GRE,
  IPv6-in-GRE, and Transparent Ethernet Bridging (`0x6558`).
  Optional checksum/key/sequence headers walked correctly.
  PPTP-GRE (version 1) explicitly rejected. 6 unit tests.
- **50.2 `FlowLabel<E>`** — augment any inner key with the 20-bit
  IPv6 flow label (RFC 6437). IPv4 packets get `label = 0`. Useful
  for distinguishing flows that share a 5-tuple (MPTCP subflows,
  ECMP-affinity flows). 4 unit tests.
- **50.3 `AutoDetectEncap<E>`** — combinator that tries plain
  extraction, then each enabled decap variant in order (VLAN →
  MPLS → VXLAN → GTP-U → GRE), returning the first match. For
  homogeneous traffic, manual composition is faster; this is the
  ergonomic option for mixed traffic. 4 unit tests.
- **50.4 `FlowTracker::manual_tick(now)`** — alias for `sweep`,
  exists for tests that prefer a name not implying background-thread
  machinery. 5 LOC.

Out of scope for this release (deferred):
- 50.5 IPv6 fragment reassembly (its own micro-plan when demand
  surfaces; non-trivial state machine).
- 50.6 `FlowStream::broadcast(buffer)` (lives in netring, not
  flowscope, since FlowStream is a netring async adapter).

167 lib tests pass workspace-wide. Clippy + fmt clean.

### Plan 31 phase 3b: SESSION_GUIDE.md

[`docs/SESSION_GUIDE.md`](../docs/SESSION_GUIDE.md) explains how to
pick between `FlowEvent`, `Reassembler`, `*Factory<H>`,
`SessionParser`, `DatagramParser`, and `Conversation<K>` for a given
use case. Includes a decision-flow checklist, runnable examples for
each shape, and a migration recipe from the callback-style factory
API to the typed-stream parser API.

Also documents the trait-stability lock: `SessionParser` /
`DatagramParser` are now considered stable for the 1.0 lock; future
additions are additive. Plan 31 is now complete.

### Plan 31 phase 3a: parser property tests

11 proptest harnesses across the four parsers (HTTP, TLS, DNS-UDP,
DNS-TCP) cover two invariants:

1. **Splitting invariance** — feeding a known-valid byte sequence
   in one chunk produces the same set of messages as feeding it in
   two random-split chunks (or byte-by-byte for DNS-TCP). Catches
   buffer-management bugs in per-direction state machines.
2. **No-panic on random bytes** — the parsers accept any `Vec<u8>`
   without panicking. Pure robustness test.

Plus DNS-TCP-specific:
- `malformed_body_keeps_framing` — a length-prefixed garbage frame
  followed by a valid query must still emit the valid query
  (the parser must consume `len` bytes regardless of body
  validity).

Run with `cargo test --features http,tls,dns --test parser_proptest`.
Increase iterations via `PROPTEST_CASES=10000 cargo test ...`. The
in-tree harness defaults to 256 cases per property; verified at
2000 cases with no failures.

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
