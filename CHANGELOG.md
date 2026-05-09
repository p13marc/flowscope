# Changelog

## 0.2.0 — Reassembly observability + metrics/tracing hooks

This minor release ships the bundle described in
[plans/42-reassembly-observability.md](plans/42-reassembly-observability.md):
optional buffer caps on `BufferedReassembler`, end-of-flow reassembly
diagnostics on `FlowStats`, and a live `FlowEvent::Anomaly` stream.
It also adds opt-in `metrics` + `tracing` features ([Plan 40](plans/40-observability.md))
that share the same `AnomalyKind` vocabulary, plus a hot-cache
fast-path on `FlowTracker` ([Plan 41](plans/41-perf-foundations.md)).
The motivating consumer is [`des-rs`](https://github.com/p13marc/des-rs)'s
`tools/des-capture`, which can now drop its hand-rolled
`TcpStreamTracker` in favour of flowscope.

### Highlights

- **`BufferedReassembler::with_max_buffer(n)`** — optional per-side
  byte cap, paired with **`with_overflow_policy(...)`** to choose:
  - `OverflowPolicy::SlidingWindow` (default) — drop oldest bytes
    from the buffer; flow stays alive; parser sees a gap and must
    resync. Best for stream-shaped / append-only protocols.
  - `OverflowPolicy::DropFlow` — poison the reassembler; the driver
    synthesises an `Ended { reason: EndReason::BufferOverflow }`
    event on the next tick. Best for framed binary protocols (DES
    PSMSG, TLS records, length-prefixed wire formats).
- **Reassembly diagnostics on `FlowStats`** — four new fields
  (`reassembly_dropped_ooo_initiator/responder`,
  `reassembly_bytes_dropped_oversize_initiator/responder`) populated
  by `FlowDriver` when each flow ends.
- **Live `FlowEvent::Anomaly`** — opt-in via
  `FlowDriver::with_emit_anomalies(true)`. Emits one `AnomalyKind`
  per (flow, side, kind) per tick:
  - `BufferOverflow { side, bytes, policy }`
  - `OutOfOrderSegment { side, count }`
  - `FlowTableEvictionPressure { evicted_in_tick, evicted_total }` —
    tracker-global signal that `max_flows` is the bottleneck.

### Breaking changes

- **`#[non_exhaustive]`** applied project-wide to every public
  struct/enum that's likely to grow over time. From now on, additive
  changes are unconditionally non-breaking.
  Affected types: `FlowStats`, `FlowTrackerConfig`, `AnomalyKind`,
  `OverflowPolicy`. Construct via `::default()` and mutate; do not
  rely on struct-literal construction from outside the crate.
- **`FlowEvent::key()`** now returns `Option<&K>` (was `&K`).
  `None` is reserved for tracker-global anomalies (e.g.
  `FlowTableEvictionPressure`); per-flow events still return
  `Some(key)`. Migrate via `event.key().expect("non-anomaly")` or
  pattern-match.
- **`EndReason`** gained a new `BufferOverflow` variant. Any
  exhaustive `match EndReason { ... }` needs a new arm. Treat it
  like `Rst` for cleanup semantics (the driver does).
- **`Reassembler` trait** gained three default-zero diagnostic
  methods (`dropped_segments`, `bytes_dropped_oversize`,
  `is_poisoned`). Existing impls compile unchanged; surface real
  counts by overriding.

### Observability hooks (Plan 40)

- New optional `metrics` Cargo feature: counters, gauges, and
  histograms wired through `FlowTracker` and `FlowDriver`. Metric
  vocabulary documented in [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).
- New optional `tracing` Cargo feature: structured events at flow
  lifecycle transitions and on every emitted anomaly.
- Both features are zero-cost when off (compile-time stubbed).
- Public metric-name constants exported from `flowscope::obs`
  (`METRIC_FLOWS_CREATED`, `METRIC_ANOMALIES`, …).

### Performance (Plan 41)

- `FlowTracker` gains a "last flow seen" hot-cache that skips the
  hash lookup when consecutive packets share a key. Estimated 2x
  throughput on monoflow workloads (single iperf3 / HTTP/2 stream),
  small win on heterogeneous traffic. No API impact.

### New API

- `flowscope::OverflowPolicy` (`SlidingWindow`, `DropFlow`).
- `flowscope::AnomalyKind` (non_exhaustive).
- `BufferedReassembler::with_max_buffer` /
  `with_overflow_policy` / `bytes_dropped_oversize` / `is_poisoned`.
- `BufferedReassemblerFactory::with_max_buffer` /
  `with_overflow_policy`.
- `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`.
- `FlowTracker::snapshot_stats(&K)` /
  `snapshot_history(&K)` / `forget(&K)` — accessors used by the
  driver to synthesise `BufferOverflow` end events.
- `FlowDriver::with_emit_anomalies(bool)`.
- `FlowEvent::Anomaly { key, kind, ts }`.

### Migration

Most consumers need only:

```diff
- let cfg = FlowTrackerConfig { max_flows: 100, ..Default::default() };
+ let mut cfg = FlowTrackerConfig::default();
+ cfg.max_flows = 100;
```

(Within the same crate, struct-literal syntax with `..Default::default()`
keeps working — `non_exhaustive` only restricts external constructors.)

If you destructure or pattern-match `FlowEvent::Ended { stats: FlowStats { ... } }`,
add `..` to the inner pattern:

```diff
- FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, ... } } => ...
+ FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, .. } } => ...
```

If you call `event.key()` and treat the return as a borrow:

```diff
- let k: &K = event.key();
+ let k: Option<&K> = event.key();
```

---

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
