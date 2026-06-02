# Plan 76 — `flowscope::icmp::IcmpParser`

## Summary

ICMP (v4 + v6) is the largest L4 protocol with no parser in
flowscope. `multi_protocol_monitor` reports
`[ICMP] + 10.0.0.1 <-> 10.0.0.2` based on `Started.l4 == Some(Icmp)`
and stops there — every ICMP packet looks the same. For network
monitoring (which is one of flowscope's core consumers), ICMP
type/code is the *most* informative field of the protocol:
"destination unreachable", "time exceeded", "redirect",
"parameter problem". Without it, ICMP is indistinguishable noise.

This plan ships a `flowscope::icmp` module behind an `icmp`
feature gate. It exposes `IcmpParser` (a `DatagramParser` impl)
that emits a typed `IcmpMessage` per packet. The wire-level parsing
delegates to `etherparse` (already a dependency at version 0.16,
which has complete ICMPv4 + ICMPv6 type parsing). The flowscope
wrapper adds:

1. A unified `IcmpType` enum spanning v4 and v6.
2. **`IcmpInner`** extraction — ICMP error messages embed the
   original IP header + first 8 bytes of L4 payload. flowscope
   extracts the embedded `(src, dst, proto, src_port, dst_port)`
   so consumers can correlate the error back to the original
   TCP/UDP flow. This is the killer feature.
3. A `DatagramParser`-shaped integration with `FlowDatagramDriver`
   / `netring::datagram_stream`.

## Status

Not started.

## Prerequisites

- Plan 31 (`DatagramParser` trait) — shipped in 0.2.0.
- Plan 37 (`DatagramParser::on_tick`) — shipped in 0.4.0. ICMP
  has no state, so `on_tick` is a no-op default. Listed for
  trait-shape stability.
- `etherparse` 0.16 — already a dep via the `extractors` feature.
  Has `Icmpv4Slice`, `Icmpv6Slice`, `Icmpv4Type`, `Icmpv6Type`
  with named-variant decoding.

## Out of scope

- ICMP-tunnel decapsulation (some monitoring deployments tunnel
  via ICMP; not common enough to ship a built-in parser for).
- Mobile-IPv6 ICMPv6 types (Home Agent Address Discovery,
  Mobile Prefix Solicitation). Decoded as `Other(u8)`.
- Neighbor Discovery option parsing (`source_link_layer_address`,
  `target_link_layer_address`, etc.). Surfaced as the raw option
  bytes; downstream can parse if needed.
- ICMPv4 router discovery messages (types 9, 10). Recognised as
  `RouterAdvertisement` / `RouterSolicitation` but body fields
  not decoded — payload returned raw.
- ICMP echo payload decoding (i.e. interpreting the ID/SEQ
  payload). The values are decoded; the trailing payload bytes
  are exposed raw on `IcmpType::Echo*`.
- Active ping correlation (matching `EchoRequest` to `EchoReply`
  to compute RTT). Belongs in the `correlate` module (plan 81
  RFC), not here.

## Files

- New module `src/icmp/`:
  - `mod.rs` — feature-gated module declaration, re-exports,
    crate-level rustdoc.
  - `types.rs` — `IcmpMessage`, `IcmpType`, `Icmpv4Type`,
    `Icmpv6Type`, code enums, `IcmpInner`.
  - `parser.rs` — stateless message parser
    (`parse_message(payload, family) -> Result<IcmpMessage>`).
  - `datagram.rs` — `IcmpParser` (`DatagramParser` impl).
- `Cargo.toml` — new feature `icmp = ["extractors"]`. Add a
  CI matrix entry so the partial build catches dead-code at PR
  time.
- `src/lib.rs` — `#[cfg(feature = "icmp")] pub mod icmp;`.
- `tests/icmp_parser.rs` — fixture-based unit tests per type.
- `tests/fixtures/icmp/` — hand-crafted packet payloads (echo,
  unreachable, time-exceeded, redirect, ICMPv6 NS/NA).
- `examples/icmp_monitor.rs` — minimal example mirroring the
  existing `dns_lookups.rs` shape.
- `docs/SESSION_GUIDE.md` — new ICMP subsection.
- `docs/OBSERVABILITY.md` — note the `parser_kind = "icmp"`
  label.
- `CHANGELOG.md` — `### Added` entry.

## API

```rust
// src/icmp/mod.rs
//! Passive ICMPv4 / ICMPv6 message parsing.

mod datagram;
mod parser;
mod types;

pub use datagram::IcmpParser;
pub use parser::{parse_message, Error};
pub use types::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Payload was too short or malformed for ICMP framing.
    #[error("invalid ICMP message: {0}")]
    Parse(&'static str),
}
```

```rust
// src/icmp/types.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcmpFamily {
    V4,
    V6,
}

/// One parsed ICMP message. Discriminated by `family`; the
/// `ty` field carries the type-specific payload.
#[derive(Debug, Clone)]
pub struct IcmpMessage {
    pub family: IcmpFamily,
    pub ty: IcmpType,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IcmpType {
    V4(Icmpv4Type),
    V6(Icmpv6Type),
}

// ── ICMPv4 ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Icmpv4Type {
    EchoReply { id: u16, seq: u16 },
    DestinationUnreachable { code: Icmpv4DestUnreachCode, inner: Option<IcmpInner> },
    SourceQuench { inner: Option<IcmpInner> },
    Redirect { code: Icmpv4RedirectCode, gateway: std::net::Ipv4Addr, inner: Option<IcmpInner> },
    EchoRequest { id: u16, seq: u16 },
    RouterAdvertisement,
    RouterSolicitation,
    TimeExceeded { code: Icmpv4TimeExceededCode, inner: Option<IcmpInner> },
    ParameterProblem { pointer: u8, inner: Option<IcmpInner> },
    Timestamp { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    TimestampReply { id: u16, seq: u16, originate: u32, receive: u32, transmit: u32 },
    /// Catch-all for v4 types we don't decode (router discovery
    /// bodies, IPv6 traceroute, etc.). `raw_type` is the on-wire
    /// type byte; the rest of the body is in `raw_body`.
    Other { raw_type: u8, raw_code: u8, raw_body: bytes::Bytes },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4DestUnreachCode {
    Net, Host, Protocol, Port,
    FragmentationNeeded { mtu: Option<u16> },
    SourceRouteFailed,
    DestNetworkUnknown, DestHostUnknown,
    SourceHostIsolated,
    NetworkProhibited, HostProhibited,
    NetworkTos, HostTos,
    CommunicationProhibited,
    HostPrecedenceViolation,
    PrecedenceCutoffInEffect,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4RedirectCode {
    Network, Host, Tos, TosHost,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4TimeExceededCode {
    HopLimitExceeded, FragmentReassemblyTimeExceeded, Other(u8),
}

// ── ICMPv6 ──────────────────────────────────────────────────────

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Icmpv6Type {
    DestinationUnreachable { code: Icmpv6DestUnreachCode, inner: Option<IcmpInner> },
    PacketTooBig { mtu: u32, inner: Option<IcmpInner> },
    TimeExceeded { code: Icmpv6TimeExceededCode, inner: Option<IcmpInner> },
    ParameterProblem { code: Icmpv6ParamProblemCode, pointer: u32, inner: Option<IcmpInner> },
    EchoRequest { id: u16, seq: u16 },
    EchoReply { id: u16, seq: u16 },
    RouterSolicitation,
    RouterAdvertisement,
    NeighborSolicitation { target: std::net::Ipv6Addr },
    NeighborAdvertisement { target: std::net::Ipv6Addr, router: bool, solicited: bool, override_: bool },
    Redirect { target: std::net::Ipv6Addr, destination: std::net::Ipv6Addr },
    MulticastListenerQuery, MulticastListenerReport, MulticastListenerDone,
    Other { raw_type: u8, raw_code: u8, raw_body: bytes::Bytes },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6DestUnreachCode {
    NoRoute, AdminProhibited, BeyondScopeOfSource,
    AddressUnreachable, PortUnreachable,
    SourceAddressFailedIngressPolicy,
    RejectRouteToDestination, Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded, FragmentReassemblyTimeExceeded, Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6ParamProblemCode {
    ErroneousHeaderField, UnrecognizedNextHeaderType,
    UnrecognizedIpv6Option, Other(u8),
}

// ── Embedded original packet (in error messages) ───────────────

/// First-packet correlation slice extracted from the embedded
/// IP header in an ICMP error message. Lets consumers tie an
/// "ICMP unreachable" back to the specific TCP/UDP flow it
/// references — no separate lookup needed.
///
/// `src_port` / `dst_port` are populated when `proto` is TCP
/// (6) or UDP (17), parsed from the first 8 bytes of L4 payload
/// the original packet placed after the IP header. For other
/// protocols (or truncated embeds), they're `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpInner {
    pub src: std::net::IpAddr,
    pub dst: std::net::IpAddr,
    pub proto: crate::L4Proto,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}
```

```rust
// src/icmp/datagram.rs

use crate::{DatagramParser, FlowSide, Timestamp};
use crate::icmp::types::{IcmpMessage, IcmpFamily};

/// Stateless `DatagramParser` over ICMPv4 + ICMPv6 traffic.
///
/// Family discrimination relies on the IP version in the
/// outer frame. The default impl observes both v4 and v6 ICMP
/// — if you only want one, filter on `IcmpMessage::family`.
///
/// Stateless: no per-flow allocation; cheap to clone.
#[derive(Default, Clone)]
pub struct IcmpParser {
    /// When `true`, the parser is operating in ICMPv4-only mode
    /// (default: false; both families parsed).
    only_v4: bool,
    only_v6: bool,
}

impl IcmpParser {
    pub fn new() -> Self { Self::default() }
    pub fn v4_only(mut self) -> Self { self.only_v4 = true; self.only_v6 = false; self }
    pub fn v6_only(mut self) -> Self { self.only_v6 = true; self.only_v4 = false; self }
}

impl DatagramParser for IcmpParser {
    type Message = IcmpMessage;
    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<IcmpMessage> {
        // Family detection: try v4 first, then v6, gated by the
        // only_* flags. The `DatagramParser` contract gives us a
        // raw L4 payload; the upstream extractor already classed
        // it as Icmp or IcmpV6 — but we re-detect for robustness.
        // Implementation TBD per `Implementation steps`.
        vec![]
    }
    fn parser_kind(&self) -> &'static str { "icmp" }
}
```

## Implementation steps

1. **Module skeleton** — create `src/icmp/{mod.rs, types.rs,
   parser.rs, datagram.rs}` with the API shapes above. Cargo
   feature `icmp`. Gate `pub mod icmp` in `lib.rs`.
2. **Wire-level decode in `parser.rs`** using etherparse:
   - For ICMPv4: `etherparse::Icmpv4Slice::from_slice(payload)`
     → match `Icmpv4Type::from_bytes(…)` against our flowscope
     enum. etherparse already decodes codes via
     `DestUnreachableHeader` / `RedirectHeader` /
     `TimeExceededCode`; convert into our flowscope code enums.
   - For ICMPv6: `Icmpv6Slice::from_slice` → `Icmpv6Type`.
   - All `Other(_)` paths preserve the raw bytes via
     `bytes::Bytes::copy_from_slice`.
3. **`IcmpInner` extraction** — for `DestinationUnreachable`,
   `TimeExceeded`, `Redirect`, `ParameterProblem`, `PacketTooBig`,
   `SourceQuench` variants, the body holds the original IP header.
   Steps:
   - Read the inner IP version nibble (first byte top half) to
     classify as v4/v6.
   - Use `etherparse::Ipv4HeaderSlice::from_slice` /
     `Ipv6HeaderSlice` to extract `src`, `dst`, `protocol`.
   - For TCP/UDP `protocol`, parse the next 8 bytes (TCP header
     starts with `src_port:u16, dst_port:u16, seq:u32` — first 8
     bytes give us both ports; UDP header is `src_port:u16,
     dst_port:u16, len:u16, csum:u16` — same).
   - Return `Some(IcmpInner { … })`. Anything malformed →
     `None`. Never panic, never error — the embed is opportunistic
     diagnostics.
4. **Family detection in `IcmpParser::parse`**. The
   `DatagramParser` interface gives us the L4 payload but not
   the L4 protocol number. Options:
   - **A** — heuristic on payload prefix (peek the first type
     byte; the v4 vs v6 type-number spaces overlap on Echo
     (8 vs 128), so this is not reliable alone).
   - **B** — pass the family through. The driver knows the
     `L4Proto` from the extractor; route `Icmp` → `parse_v4`,
     `IcmpV6` → `parse_v6` via two parser instances + a
     facade.
   - **C** — extend the `DatagramParser` trait to surface the
     `L4Proto` to `parse`. Bigger surface change; not in scope
     for this plan.
   - **Pick: A**, with the type-byte heuristic guarded by
     plausibility. The IP layer already classified the payload
     as `Icmp` or `IcmpV6` (the extractor's `L4Proto`); the
     parser can trust this and use whichever decode it tries
     first. The `only_v4` / `only_v6` flags exist precisely to
     let the consumer constrain the parser when they know
     which family they're dealing with.
5. **Tests** — see Tests section. Critical: a real captured
   ICMPv4 destination-unreachable with inner TCP header must
   round-trip through `IcmpInner` with correct src/dst/ports.
6. **Example** `examples/icmp_monitor.rs`:
   ```rust,ignore
   // Print every ICMP error with the original (src:port → dst:port)
   // it references — the use case the embed extraction enables.
   for ev in driver.track(view) {
       if let SessionEvent::Application {
           message: IcmpMessage { ty: IcmpType::V4(Icmpv4Type::DestinationUnreachable {
               code, inner: Some(inner), ..
           }), .. },
           ..
       } = ev {
           println!("dest-unreach({code:?}) referencing {}:{:?} → {}:{:?}",
               inner.src, inner.src_port, inner.dst, inner.dst_port);
       }
   }
   ```
7. **CHANGELOG entry under `### Added`**:
   ```
   - **`flowscope::icmp` module + `icmp` Cargo feature** (plan
     76). `IcmpParser` is a `DatagramParser` over ICMPv4 +
     ICMPv6, emitting a unified `IcmpMessage { family, ty }`.
     Error messages (Unreachable / TimeExceeded / Redirect /
     ParameterProblem / PacketTooBig) extract the embedded
     original-flow header into `IcmpInner` — consumers tie
     ICMP errors back to the specific TCP/UDP flow they
     reference without a separate lookup. Wire decoding
     delegates to `etherparse` 0.16.
   ```
8. **Feature-matrix CI** entry: add `--features icmp` to
   `.github/workflows/rust.yml` so partial-feature build /
   clippy catches dead-code drift.

## Tests

`tests/icmp_parser.rs` (one test per shape):
- **Echo request / reply** (v4 + v6) — `id`, `seq` round-trip.
- **DestinationUnreachable** with a TCP-inner — verify
  `IcmpInner { proto: Tcp, src_port: Some(_), dst_port: Some(_) }`.
- **DestinationUnreachable** with a UDP-inner — same with UDP.
- **DestinationUnreachable** with a truncated inner (only 4
  bytes of L4 after IP header) — `IcmpInner.src_port` is
  `None`, `dst_port` is `None`, but `src`/`dst`/`proto` populated.
- **TimeExceeded** (v4 + v6) — both codes (hop / fragment).
- **Redirect** (v4) — gateway address extracted.
- **PacketTooBig** (v6) — MTU extracted.
- **NeighborSolicitation / NeighborAdvertisement** (v6) —
  target IPv6 address extracted.
- **ParameterProblem** (v4 + v6) — pointer/code extracted.
- **Timestamp** — three timestamp fields round-trip.
- **`Other` catch-all** — feed a type=42 / code=7 packet;
  assert `Other { raw_type: 42, raw_code: 7, raw_body: … }`.
- **Malformed payloads** (1 byte; 8 bytes; trailing garbage)
  proptest-style with `cargo-fuzz`-shaped invariant: parser
  doesn't panic, returns either an `Other` or an `Err`.

`tests/icmp_pcap.rs` (integration via PcapFlowSource):
- Real pcap (synthesised; ships in `tests/fixtures/icmp/`)
  with five flows: ping (echo req/reply), traceroute
  (time-exceeded chain), unreachable (port unreachable),
  redirect, NS/NA. Assert each surfaces as the expected
  `IcmpMessage` variant.

`tests/parser_proptest.rs` — extend with an `IcmpParser`
splitting-invariance proptest (ICMP is one-message-per-payload,
so the splitting axis is "feed a partial payload" — the parser
should return empty `Vec`, never panic).

## Acceptance criteria

- `cargo test --features icmp` clean (full new test file).
- `cargo test --all-features` clean (no regression elsewhere).
- `cargo clippy --features icmp --all-targets -- -D warnings`
  clean.
- Feature-matrix CI green with new `icmp` entry.
- `cargo doc --features icmp --no-deps` documents the module
  cleanly.
- Example `examples/icmp_monitor.rs` runs against the bundled
  pcap fixture and prints expected output.
- `flowscope_anomalies_total{parser_kind="icmp"}` is observable
  (via the parser-kind threading from plan 72).
- SESSION_GUIDE has an ICMP subsection cross-linking the example.

## Risks

- **Family detection ambiguity.** The IP layer above already
  knows the family; passing it through requires either trusting
  the extractor (chosen) or a heuristic (fragile). If a packet
  is misrouted by the extractor (e.g. an IPv6 ICMPv6 packet
  classified as `Icmp` because the extractor stripped a v6
  next-header chain wrong), the parser will try v4 decode and
  produce `Other`. Documented as a known limitation; the
  `only_v4` / `only_v6` flags let consumers force the right
  family.
- **Embedded-IP-header truncation.** RFC 792 mandates "at
  least" 28 bytes of original packet; RFC 4884 extends. In the
  wild some intermediate routers truncate aggressively.
  `IcmpInner` extraction degrades gracefully — `src`/`dst` are
  attempted first, ports are best-effort.
- **etherparse version pin.** etherparse 0.16's ICMPv6 type
  surface is comprehensive but version-locked. If we bump
  etherparse later, the conversion code in `parser.rs` may need
  updates. Mitigated by the test-fixture set covering every
  decoded variant — a breakage surfaces as a test failure.
- **CVE surface.** Parsing ICMP error embeds is a classic
  trust-the-attacker-input vector. The implementation has zero
  `unsafe`, uses `&[u8]` slicing with explicit bounds checks
  via etherparse's safe slice APIs, and returns `Option` on any
  malformed embed. Adding an explicit fuzz target post-merge
  is recommended (out of scope for this plan).

## Effort

~250 LoC types + ~150 LoC parser + ~100 LoC datagram impl +
~200 LoC tests + ~20 lines docs + ~30 lines example.
**~750 LoC total. ~1 day** including CHANGELOG, docs, example,
and feature-matrix CI update.

## Provenance

Round-2 feedback item F1 in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
The author flagged it as the highest-priority item for the
0.7 cycle because ICMP is the most informative protocol for
diagnosing network failures, and the `IcmpInner` extraction is
the cross-protocol correlation primitive the netring
anomaly-correlation roadmap depends on.

The unified-via-`V4(_)/V6(_)`-outer-enum shape (rather than the
author's flat `IcmpType` enum) is documented as a deliberate
deviation: ICMPv6 has Neighbor Discovery types that don't fit
the ICMPv4 type space, and the type-namespace overlap on
ICMPv6 (e.g. `EchoRequest = 128` vs ICMPv4 `8`) makes a single
flat enum harder to evolve. See `docs/0.7-PLAN-OF-RECORD.md` §5
for the rationale.
