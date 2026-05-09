# CLAUDE.md

## Project Overview

`flowscope` is a passive flow & session tracking library for packet
capture pipelines. Single crate with feature-gated modules. Runtime-
free, cross-platform — no tokio, no futures, no Linux-specific code in
the core.

- Edition 2024, MSRV 1.85
- Single Cargo package; modules `http` / `tls` (+ `ja3`) / `dns` /
  `pcap` are opt-in via Cargo features
- Pairs with [`netring`](https://crates.io/crates/netring) for live
  Linux capture; with `pcap` files for offline replay; with any other
  source of `&[u8]` frames (tun-tap, eBPF userspace, embedded, etc.)
- Pre-1.0 API stable: `SessionParser` / `DatagramParser` shape locked
  in 0.1.0; future additions are additive, breaking changes need a
  major bump

## Implementation Status

**0.1.0 published** (crates.io). 167 lib + integration tests, 11
parser proptests, additional tracker proptests. Zero clippy warnings,
zero rustdoc warnings, fmt-clean.

### Modules

```
src/
├── lib.rs                       # re-exports + feature wiring
├── timestamp.rs                 # Timestamp (also re-exported by netring)
├── view.rs                      # PacketView<'a> = (frame: &[u8], ts)
├── extractor.rs                 # FlowExtractor trait + Extracted/Orientation
├── extract/                     # built-in extractors (extractors feature)
│   ├── parse.rs                 # internal etherparse wrappers
│   ├── five_tuple.rs            # FiveTuple { proto, a, b }
│   ├── ip_pair.rs               # IpPair (proto-agnostic, useful for ICMP)
│   ├── mac_pair.rs              # MacPair (L2 only)
│   ├── encap_vlan.rs            # StripVlan<E>
│   ├── encap_mpls.rs            # StripMpls<E>
│   ├── encap_vxlan.rs           # InnerVxlan<E>
│   ├── encap_gtp.rs             # InnerGtpU<E>
│   ├── encap_gre.rs             # InnerGre<E>            (plan 50.1)
│   ├── auto_detect.rs           # AutoDetectEncap<E>     (plan 50.3)
│   └── flow_label.rs            # FlowLabel<E>           (plan 50.2)
├── event.rs                     # FlowEvent / FlowSide / EndReason / FlowStats
├── history.rs                   # HistoryString (Zeek-style ShAdaFf)
├── tcp_state.rs                 # TCP state machine (transitions + idle policy)
├── tracker.rs                   # FlowTracker<E, S>      (manual_tick alias added in 50.4)
├── reassembler.rs               # Reassembler trait + BufferedReassembler
├── driver.rs                    # FlowDriver<E, F, S>     (sync wrapper)
├── session.rs                   # SessionParser / DatagramParser traits + factories + SessionEvent
├── http/                        # `http` feature
│   ├── parser.rs                # internal step() machine (httparse-based)
│   ├── factory.rs               # HttpFactory / HttpReassembler (callback-style)
│   ├── session.rs               # HttpParser (SessionParser-style, plan 31)
│   └── types.rs                 # HttpRequest / HttpResponse / HttpHandler / HttpConfig
├── tls/                         # `tls` feature
│   ├── parser.rs                # internal step() machine (tls-parser-based)
│   ├── factory.rs               # TlsFactory / TlsReassembler (callback-style)
│   ├── session.rs               # TlsParser (SessionParser-style, plan 31)
│   ├── fingerprint.rs           # JA3 (gated by `ja3` feature)
│   └── types.rs                 # TlsClientHello / TlsServerHello / TlsAlert / TlsHandler
├── dns/                         # `dns` feature
│   ├── parser.rs                # parse_message / parse_message_at (simple-dns-based)
│   ├── correlator.rs            # Correlator<S> — per-flow query/response matching
│   ├── observer.rs              # DnsUdpObserver — extractor-tap callback API
│   ├── datagram.rs              # DnsUdpParser (DatagramParser, plan 31)
│   ├── session.rs               # DnsTcpParser (SessionParser, RFC 1035 §4.2.2 framing)
│   └── types.rs                 # DnsQuery / DnsResponse / DnsRdata / DnsConfig / DnsHandler
└── pcap/                        # `pcap` feature
    └── source.rs                # PcapFlowSource — offline replay
```

### Tests

- `tests/parser_proptest.rs` — 11 splitting-invariance / no-panic
  proptests across all four parsers (HTTP / TLS / DNS-UDP / DNS-TCP).
  Run with `PROPTEST_CASES=10000` for stress testing.
- `tests/proptest_invariants.rs` — tracker-level proptests
  (FiveTuple canonicalization, TCP state machine).
- `tests/{http,tls,dns}_parser.rs` — fixture-based unit tests per parser.
- `tests/{http,pcap}_pcap.rs`, `tests/pcap_integration.rs`,
  `tests/pcap_fixtures.rs` — pcap-driven integration tests.

## Build & Test

```bash
# Default features
cargo test

# All features (incl. ja3, dns, pcap)
cargo test --all-features

# Just one module
cargo test --features http
cargo test --features dns

# Stress proptests
PROPTEST_CASES=10000 cargo test --features http,tls,dns --test parser_proptest

# Lint
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --all-features --no-deps
```

## Architecture

### Three layers, one trait per layer

1. **Extractor** (`FlowExtractor`) — turns a frame into a flow key +
   metadata. User-pluggable. Built-in extractors (5-tuple etc.) and
   decap combinators wrap each other (`StripVlan(InnerVxlan(FiveTuple))`).
2. **Tracker** (`FlowTracker<E, S>`) — bidirectional flow accounting
   on top of an extractor. TCP state machine with Suricata-style idle
   timeouts and LRU eviction. Emits `FlowEvent` lifecycle.
3. **Reassembler** / **SessionParser** / **DatagramParser** — three
   API shapes for consuming TCP / UDP payloads. Pick by use case
   ([SESSION_GUIDE.md](docs/SESSION_GUIDE.md) walks through the
   decision tree).

### Two API shapes for L7 parsing

Every shipped parser exposes both:

- **`*Factory<H>`** — callback handler trait (`HttpHandler`,
  `TlsHandler`, `DnsHandler`). Callback-driven. Pair with a sync
  `FlowDriver` or netring's `with_async_reassembler`.
- **`SessionParser` / `DatagramParser`** — typed message stream.
  `feed_initiator` / `feed_responder` return `Vec<Self::Message>`;
  pair with netring's `session_stream` / `datagram_stream` for async
  iteration.

Both produce the same events for the same wire bytes — pick the API
that matches your control flow.

### Design constraints

- **Runtime-free in core.** Tokio is forbidden in `flowscope`'s deps.
  Async lives in `netring` (which depends on flowscope, not the other
  way around). This is a hard project rule; PRs adding tokio to
  flowscope are wrong-shaped.
- **No `unsafe` outside well-justified zero-copy spots.** Buffer
  handling uses `Bytes` / `Vec<u8>` with `safe` slicing. Plan 41
  (zero-copy reassembly) when it lands will introduce some via
  `BytesMut` lifetime tricks; bounded scope.
- **Deterministic state machines.** No background threads, no global
  state. Every parser holds its state and returns messages
  synchronously.
- **Bounded memory.** Tracker has `max_flows`; reassemblers have
  `max_buffer`; correlator has `max_pending`. No unbounded growth.
- **Trait stability lock.** `SessionParser` / `DatagramParser` shape
  is committed as of 0.1.0. Future additions are additive (new
  methods with default implementations); breaking changes will need
  a 0.2 / 1.0 bump. Plan 31 phase 3b documents this in
  `docs/SESSION_GUIDE.md`.

## Plans

`plans/` (in-repo only — excluded from the published package via
`Cargo.toml`'s `exclude` field) contains the roadmap:

- `INDEX.md` — status of every plan
- `00-04` — historical: how flow types were originally split out of
  netring (now superseded by the single-crate consolidation)
- `12, 20, 22-24, 30, 31, 50.1-50.4, 50.6` — ✅ done
- `21` (protolens), `32` (NetFlow/IPFIX), `40` (observability),
  `41` (perf foundations), `50.5` (IPv6 frags), `60` (CLI tools) — deferred

`plans/DPI_ARCHITECTURE.md` is the SOTA-DPI research and crate-split
recommendations report.

## Pre-publish checklist

For the next `cargo publish` of flowscope:

1. Bump `Cargo.toml` `version` if user-facing changes have landed.
2. Update `CHANGELOG.md` with the new release section.
3. `cargo test --all-features` clean.
4. `cargo clippy --all-features --all-targets -- -D warnings` clean.
5. `cargo fmt --check` clean.
6. `cargo doc --all-features --no-deps` zero warnings.
7. `cargo machete` no unused deps.
8. `cargo publish --dry-run` packages and verifies.
9. `cargo publish`.
10. Tag the release in git: `git tag v0.x.y && git push origin v0.x.y`.

## Relationship to netring

netring (the published Linux-capture crate) has flowscope as a
non-optional dep. Specifically:

- `netring` re-exports `flowscope::Timestamp` and `flowscope::PacketView`
  unconditionally — they're fundamental types every netring user
  may touch.
- `netring`'s `parse` / `flow` features turn on flowscope's
  `extractors` / `tracker` / `reassembler` / `session` features.
- The async stream adapters (`flow_stream`, `session_stream`,
  `datagram_stream`, `flow_broadcast`, `conversation`) live in
  netring because they depend on tokio + `AsyncCapture`. They
  consume flowscope's traits.

If you add a new public API in flowscope, consider whether netring
needs a corresponding re-export under `netring::flow::*`.

## Key files

- `README.md` — front page (also published as the crates.io readme).
- `CHANGELOG.md` — release history.
- `docs/SESSION_GUIDE.md` — how to pick between FlowEvent /
  Reassembler / *Factory<H> / SessionParser / DatagramParser /
  Conversation. Includes migration recipes.
- `Cargo.toml` — package manifest. `exclude = ["plans/"]` keeps
  internal roadmap docs out of the published package.
- `src/lib.rs` — top-level rustdoc + feature/module wiring.
- `src/session.rs` — the strategic 1.0 abstraction
  (`SessionParser` / `DatagramParser`).
