# Plan 94 — High-level API surface for 0.9

## Summary

Consolidate the three plans that touched flowscope's public-facing
shape (former 94 driver-builder, 95 Pipeline, 100 layers) into a
single coherent design. After 0.9, the user-facing surface is
organised in three tiers, each with a deliberate audience:

```text
┌─ Tier 1 — flowscope::Pipeline ─────────────────────────────┐
│  One import, one builder chain, one iterator.              │
│  Target: 90% of users; offline + simple online pipelines.  │
└────────────────────────────────────────────────────────────┘
┌─ Tier 2 — flowscope::{FlowSessionDriver, FlowDatagramDriver, FlowDriver} ─┐
│  Typed builders for each driver kind. Per-flow state,                     │
│  per-flow parser factories, custom drainers.                              │
│  Target: power users who need per-flow context.                           │
└──────────────────────────────────────────────────────────────────────────┘
┌─ Tier 3 — flowscope::layers ───────────────────────────────┐
│  Per-packet zero-copy L2/L3/L4 view + dynamic walk.        │
│  Target: anyone wanting raw header access on a frame.      │
└────────────────────────────────────────────────────────────┘
```

Every tier:

- Uses unprefixed builder methods (Rust idiom — `reqwest`,
  `tokio`, `axum`, `prost_build` all converge on this).
- Returns `flowscope::Error` from fallible ops (plan 96 lands
  alongside).
- Carries `#[non_exhaustive]` on every public struct/enum so
  future fields stay additive.
- Has a single `prelude` re-export so consumers write
  `use flowscope::prelude::*;` and have what they need.

The release also drops the **callback-factory L7 APIs**
(`HttpFactory`, `TlsFactory`, `HttpHandler`, `TlsHandler` and
their `HttpReassembler` / `TlsReassembler` wrappers). They predate
the strategic `SessionParser` shape (0.2.0) and have been
maintenance burden since. Their use cases are strictly subsumed
by `SessionParser` + a `for event in driver.run() { match event {
… } }` loop, which is also more idiomatic.

This is the largest behavioural break in 0.9. The migration cost
is concentrated here, in plan 96 (error unification), and in the
MSRV review part of plan 99.

## Status

**Ready to implement.** Targets 0.9.0. Sibling to plans 92
(multi-parser driver — kept separate because it serves the
explicit multi-L7-parser case), 96 (error unification), 99
(idioms). Internal landing order: 96 (errors) → 94 (this plan)
→ 92 (multi-parser builds on the new surface) → 99 (idioms
sweep applies to the final state).

## Prerequisites

- Plan 96 — errors. `Pipeline::run_pcap` returns
  `Result<…, flowscope::Error>`; the unified type is what every
  fallible method in this plan returns.
- Coordination: `netring` updates its async stream adapters
  (`flow_stream`, `session_stream`, `datagram_stream`) to wrap
  the new driver builders. Lockstep release.

## Out of scope

- **Multi-parser composition.** That stays in plan 92
  (`FlowMultiSessionDriver`). `Pipeline` is the single-parser
  convenience surface; multi-parser is a separate type with a
  different design centre. The merged plan documents when to
  pick which.
- **Async APIs in flowscope.** Tokio integration stays in
  `netring`. The sync surface aligned here; `netring` mirrors in
  its own 0.9 release.
- **`no_std` support.** Out of scope for this plan and indeed
  for 0.9. Documented as a non-goal in `docs/concepts.md`.
- **Custom layer dissectors.** Plan 100's "out of scope" line on
  `LayerRegistry` carries forward — users with proprietary
  tunnels re-parse the payload themselves until a consumer
  asks.
- **Mutable / construction-mode packet APIs.** flowscope stays
  passive-observation only. Users wanting Scapy-style packet
  building get pointed at `pnet` or `etherparse`'s own
  builders.
- **Deprecation shim in 0.8.x.** Plan 93 documents the decision
  to take 0.9 as a clean break — no `#[deprecated]` alias cycle.

---

## Tier 1 — `flowscope::Pipeline`

The intended one-import "hello flowscope" program:

```rust,no_run
use flowscope::prelude::*;

# fn main() -> flowscope::Result<()> {
let pipeline = Pipeline::builder(FiveTuple::bidirectional())
    .session(HttpParser::new())
    .build();

for event in pipeline.run_pcap("trace.pcap")? {
    println!("{}", event?);
}
# Ok(()) }
```

### API

```rust
// src/pipeline.rs

pub struct PipelineBuilder<E, S = NoSessionParser, D = NoDatagramParser>
where E: FlowExtractor, /* … */
{ /* … */ }

pub struct Pipeline<E, S, D> { /* … */ }

impl<E: FlowExtractor> Pipeline<E, NoSessionParser, NoDatagramParser> {
    /// Construct a builder. The only public way to create a Pipeline.
    pub fn builder(extractor: E) -> PipelineBuilder<E>;
}

impl<E, S, D> PipelineBuilder<E, S, D> {
    /// Register the single TCP / session parser. Type-state
    /// upgrades `S` from `NoSessionParser` to the concrete parser
    /// type so `Event::Tcp(SessionEvent<K, P::Message>)` is typed.
    pub fn session<P>(self, p: P) -> PipelineBuilder<E, P, D>
        where P: SessionParser + Clone + Send + 'static;

    /// Register the single UDP / datagram parser.
    pub fn datagram<P>(self, p: P) -> PipelineBuilder<E, S, P>
        where P: DatagramParser + Clone + Send + 'static;

    /// Override the tracker config. Default: Suricata-style idle
    /// timeouts + 100k flow LRU.
    pub fn config(self, c: FlowTrackerConfig) -> Self;

    /// Attach a `Layers` view to every event when set to `true`.
    /// Default: `false` — saves the parse cost on the hot path.
    pub fn layers(self, on: bool) -> Self;

    /// Whether to emit `FlowAnomaly` / `TrackerAnomaly` events
    /// inline. Default: `true` (opt-out, not opt-in — anomalies
    /// are signal not noise).
    pub fn emit_anomalies(self, on: bool) -> Self;

    /// Replay-time setting: assume the source feeds packets in
    /// monotonic timestamp order. Default: `true` for `run_pcap`,
    /// `false` for `run_iter`.
    pub fn monotonic(self, on: bool) -> Self;

    /// Apply content-hash dedup before extraction. Default: off.
    pub fn dedup(self, dedup: Dedup) -> Self;

    /// Build. Type-state ensures at least one parser was set
    /// (compile-error otherwise via `S: HasSessionParser
    /// | D: HasDatagramParser` trait bound).
    pub fn build(self) -> Pipeline<E, S, D>;
}

impl<E, S, D> Pipeline<E, S, D> {
    /// Drive the pipeline over a pcap file. Returns an iterator
    /// yielding `Result<Event<E::Key, S::Message, D::Message>, Error>`.
    /// End-of-input flush is folded in automatically.
    pub fn run_pcap(&mut self, path: impl AsRef<Path>) -> Result<EventIter<'_, E, S, D>>;

    /// Drive the pipeline over an arbitrary packet iterator.
    /// Useful for custom sources (eBPF userspace, embedded,
    /// netring's batched recv, synthetic).
    pub fn run_iter<I>(&mut self, iter: I) -> EventIter<'_, E, S, D>
        where I: IntoIterator<Item = PacketView<'static>>;

    /// Reset the underlying tracker / reassemblers. Allows
    /// re-running the same pipeline against multiple sources.
    pub fn reset(&mut self);
}
```

### Unified event

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event<K, SM, DM> {
    Flow(FlowEvent<K>),
    Tcp(SessionEvent<K, SM>),
    Udp(SessionEvent<K, DM>),
}

impl<K, SM, DM> Event<K, SM, DM> {
    pub fn timestamp(&self) -> Timestamp;
    pub fn flow_key(&self) -> Option<&K>;
    pub fn kind(&self) -> EventKind;  // small enum for `match` ergonomics
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    FlowStarted, FlowPacket, FlowEnded, FlowTick,
    FlowAnomaly, TrackerAnomaly,
    TcpApplication, TcpClosed, TcpTick,
    UdpApplication, UdpClosed, UdpTick,
}
```

`SM` defaults to `()` when no session parser is registered;
similarly `DM`. Type-state in the builder makes this transparent
to consumers — they never name `NoSessionParser` directly.

### `Display` for `Event`

`Event` derives `Display` for one-line debugging:

```text
[1717689600.123456789] flow-started flow=192.0.2.1:54321→198.51.100.5:80/tcp
[1717689600.234567890] tcp-application flow=… msg=HttpRequest{method=GET,uri=/index.html}
```

Format is **not** API-stable; documented in `docs/concepts.md`.

---

## Tier 2 — Driver builders

For users who outgrow `Pipeline` (per-flow state, per-flow parser
factories, custom drainers, multi-source feeds, structured
backpressure), the three sync drivers expose typed builders.

The 0.8 surface has **38** constructors across the three driver
files (`new` / `with_config` / `with_factory` / `with_factory_and_config`
/ `with_state` / `with_state_and_config` / `with_state_init` /
`with_state_init_and_config` / `with_state_factory` /
`with_state_factory_and_config` + chainable `with_emit_anomalies`
/ `with_idle_timeout_fn` / `with_dedup` /
`with_monotonic_timestamps`). After 0.9: **zero** free-function
constructors. Only `Driver::builder(extractor)`.

### Builder shape (same across all three drivers)

```rust
pub struct FlowSessionDriverBuilder<E, P, S = ()>
where E: FlowExtractor, /* … */
{ /* … */ }

impl<E> FlowSessionDriverBuilder<E, NoParser, ()>
where E: FlowExtractor, /* … */
{
    fn new(extractor: E) -> Self;
}

impl<E, P, S> FlowSessionDriverBuilder<E, P, S> {
    pub fn config(self, c: FlowTrackerConfig) -> Self;

    pub fn parser(self, p: P) -> Self where P: SessionParser + Clone + Send + 'static;
    pub fn parser_factory<F>(self, f: F) -> Self
        where F: FnMut(&E::Key) -> P + Send + 'static, P: SessionParser + Send + 'static;

    pub fn state<S2>(self, s: S2) -> FlowSessionDriverBuilder<E, P, S2>;
    pub fn state_init<S2, F>(self, init: F) -> FlowSessionDriverBuilder<E, P, S2>
        where F: FnMut(&E::Key) -> S2 + Send + 'static;

    pub fn emit_anomalies(self, on: bool) -> Self;
    pub fn idle_timeout_fn<F>(self, f: F) -> Self where F: Fn(&E::Key) -> Duration + Send + 'static;
    pub fn dedup(self, dedup: Dedup) -> Self;
    pub fn monotonic_timestamps(self, on: bool) -> Self;

    pub fn build(self) -> FlowSessionDriver<E, P, S>;
}

impl<E, P, S> FlowSessionDriver<E, P, S> {
    pub fn builder(extractor: E) -> FlowSessionDriverBuilder<E, NoParser, ()>;
}
```

The type-state on `P: NoParser → P: SessionParser` makes
`builder(ext).build()` (no parser set) a compile error with a
clear "no method named `build`" diagnostic.

`FlowDatagramDriver::builder()` and `FlowDriver::builder()`
mirror the shape (with `DatagramParser` and the
factory-of-reassemblers respectively).

### Why unprefixed methods

`reqwest::ClientBuilder::timeout(d)` not `.with_timeout(d)`.
`tokio::runtime::Builder::worker_threads(n)` not
`.with_worker_threads(n)`. `axum::Router::route(p, h)` not
`.with_route(…)`. `prost_build::Config::bytes(vec!["."])` not
`.with_bytes(…)`.

The Rust convention is: chainable methods *on a builder type*
are unprefixed; `with_` is reserved for chainable setters on a
non-builder type (e.g. today's `Reassembler::with_max_buffer`
which lives on the reassembler itself, not on a builder).

The 0.8 `FlowSessionDriver::with_factory_and_config` is the
"chainable setter on a non-builder" pattern, applied past the
point where it scales. Hoisting to a builder is the canonical
fix.

---

## Tier 3 — `flowscope::layers`

A zero-copy, eagerly-parsed view of a frame with both direct
accessors and a dynamic walk. Built on
`etherparse::SlicedPacket` (already a dep through the
`extractors` feature). Tunnel-aware: walks into VXLAN / GTP-U /
GRE / IP-in-IP.

```rust,no_run
use flowscope::prelude::*;
use flowscope::layers::LayerKind;

fn inspect(pv: PacketView<'_>) -> flowscope::Result<()> {
    let layers = pv.layers()?;

    // Direct accessors — the common case.
    if let Some(tcp)  = layers.tcp()  { println!("seq={} window={}", tcp.seq(), tcp.window()); }
    if let Some(vlan) = layers.vlan() { println!("vid = {}", vlan.vid()); }
    if let Some(ip6)  = layers.ipv6() { println!("flow_label = {:x}", ip6.flow_label()); }

    // Dynamic walk — "show me everything".
    for layer in layers.iter() {
        println!("{:>10} ({}B)", layer.kind(), layer.bytes().len());
    }

    // Tunnel-aware lookup — inner Ipv4 inside a VXLAN frame.
    let inner = layers.find_all(LayerKind::Ipv4).nth(1);

    Ok(())
}
```

### API

```rust
// src/layers/mod.rs

pub struct Layers<'a> { /* … */ }

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Layer<'a> {
    Ethernet(EthernetSlice<'a>),
    Vlan(VlanSlice<'a>),
    Mpls(MplsSlice<'a>),
    Ipv4(Ipv4Slice<'a>),
    Ipv6(Ipv6Slice<'a>),
    Arp(ArpSlice<'a>),
    Tcp(TcpSlice<'a>),
    Udp(UdpSlice<'a>),
    Icmpv4(Icmpv4Slice<'a>),
    Icmpv6(Icmpv6Slice<'a>),
    Gre(GreSlice<'a>),
    Vxlan(VxlanSlice<'a>),
    GtpU(GtpUSlice<'a>),
    Payload(&'a [u8]),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum LayerKind {
    Ethernet, Vlan, Mpls,
    Ipv4, Ipv6, Arp,
    Tcp, Udp, Icmpv4, Icmpv6,
    Gre, Vxlan, GtpU,
    Payload,
}

impl<'a> Layers<'a> {
    pub fn parse_ethernet(frame: &'a [u8]) -> Result<Self>;
    pub fn parse_ip(frame: &'a [u8]) -> Result<Self>;

    pub fn iter(&self) -> impl Iterator<Item = &Layer<'a>>;
    pub fn find(&self, kind: LayerKind) -> Option<&Layer<'a>>;
    pub fn find_all(&self, kind: LayerKind) -> impl Iterator<Item = &Layer<'a>>;

    pub fn payload(&self) -> &'a [u8];
    pub fn depth(&self) -> usize;
    pub fn has_tunnel(&self) -> bool;
    pub fn truncated(&self) -> bool;

    // Direct convenience accessors — first match by kind.
    pub fn ethernet(&self) -> Option<&EthernetSlice<'a>>;
    pub fn vlan(&self) -> Option<&VlanSlice<'a>>;
    pub fn mpls(&self) -> Option<&MplsSlice<'a>>;
    pub fn ipv4(&self) -> Option<&Ipv4Slice<'a>>;
    pub fn ipv6(&self) -> Option<&Ipv6Slice<'a>>;
    pub fn arp(&self) -> Option<&ArpSlice<'a>>;
    pub fn tcp(&self) -> Option<&TcpSlice<'a>>;
    pub fn udp(&self) -> Option<&UdpSlice<'a>>;
    pub fn icmpv4(&self) -> Option<&Icmpv4Slice<'a>>;
    pub fn icmpv6(&self) -> Option<&Icmpv6Slice<'a>>;

    // L-number group — first layer at that OSI level.
    pub fn l2(&self) -> Option<&Layer<'a>>;
    pub fn l3(&self) -> Option<&Layer<'a>>;
    pub fn l4(&self) -> Option<&Layer<'a>>;
}

impl<'a> PacketView<'a> {
    pub fn layers(&self) -> Result<Layers<'a>>;
}
```

### Per-layer slice types

Each layer slice is a small `Copy` struct wrapping `&'a [u8]`
plus a header-length indicator. They expose typed accessors for
the protocol's standard fields. Example for TCP:

```rust
pub struct TcpSlice<'a> { /* … */ }

impl<'a> TcpSlice<'a> {
    pub fn src_port(&self) -> u16;
    pub fn dst_port(&self) -> u16;
    pub fn seq(&self) -> u32;
    pub fn ack(&self) -> u32;
    pub fn window(&self) -> u16;
    pub fn data_offset(&self) -> u8;
    pub fn flags(&self) -> TcpFlagsView;
    pub fn checksum(&self) -> u16;
    pub fn urgent_pointer(&self) -> u16;
    pub fn header(&self) -> &'a [u8];
    pub fn options(&self) -> impl Iterator<Item = TcpOption<'a>>;
    pub fn payload(&self) -> &'a [u8];
}
```

The full slice-type inventory is in
`src/layers/{eth,ip,transport,tunnel}.rs`. Mirrors etherparse's
slice surface with flowscope-shaped names so users never need to
import etherparse to use flowscope.

### Tunnel-following design

`Layers::parse_ethernet` calls `SlicedPacket::from_ethernet`,
pushes each detected layer into a `SmallVec<[Layer<'a>; 6]>`, then
inspects the transport. If it's UDP dst=4789 (VXLAN) or dst=2152
(GTP-U) or proto=GRE or proto=IP-in-IP (4/41), the inner payload
is re-parsed and its layers appended to the stack. On any inner
parse failure, the walk stops cleanly and `truncated()` returns
`true`; the outer layers stay accessible.

### Tier 3 fast path — zero-allocation parsing

`Layers::parse_ethernet` is the ergonomic mode: ~100 ns / packet,
returns a fresh `Layers<'a>` per call (one `SmallVec` allocation
in the common case, none on the hot path when the inline buffer
of 6 layers fits — which it does for ~99 % of frames). For
high-throughput consumers that profile shows the per-frame
allocation as a hot spot, a parallel **zero-allocation API**
mirrors gopacket's `DecodingLayerParser` shape (the dominant
reference for this dual-mode pattern):

```rust
pub struct LayerParser {
    scratch: LayerStack,        // reusable layer slots, owned
    follow_tunnels: bool,
    target_kinds: u32,           // bitmask of LayerKind to populate
}

pub struct LayerStack {
    eth:    Option<EthernetSlice<'static>>,  // 'static is a marker; bytes are reborrowed
    vlan:   Option<VlanSlice<'static>>,
    ipv4:   Option<Ipv4Slice<'static>>,
    ipv6:   Option<Ipv6Slice<'static>>,
    tcp:    Option<TcpSlice<'static>>,
    udp:    Option<UdpSlice<'static>>,
    inner_eth:  Option<EthernetSlice<'static>>,
    inner_ipv4: Option<Ipv4Slice<'static>>,
    inner_ipv6: Option<Ipv6Slice<'static>>,
    inner_tcp:  Option<TcpSlice<'static>>,
    inner_udp:  Option<UdpSlice<'static>>,
    decoded: smallvec::SmallVec<[LayerKind; 12]>,
}

impl LayerParser {
    pub fn new() -> Self;
    pub fn with_tunnels(self, follow: bool) -> Self;

    /// Subscribe to a subset of layer kinds — the parser only
    /// fills those slots, skipping work for the rest. Default:
    /// all kinds.
    pub fn only(self, kinds: &[LayerKind]) -> Self;

    /// Parse into a caller-owned LayerStack. Returns the same
    /// `&mut LayerStack` for chaining and zero-alloc reuse
    /// across a packet loop.
    pub fn parse_ethernet<'b>(&self, frame: &'b [u8], out: &'b mut LayerStack)
        -> Result<&'b LayerStack>;
}

impl LayerStack {
    pub fn new() -> Self;
    pub fn reset(&mut self);  // clear every Option<…>
    // typed accessors mirror Layers' surface, but on Option fields.
    pub fn tcp(&self) -> Option<&TcpSlice<'_>>;
    // … etc.
}
```

Usage:

```rust,no_run
use flowscope::layers::{LayerParser, LayerStack, LayerKind};

let parser = LayerParser::new()
    .with_tunnels(true)
    .only(&[LayerKind::Ipv4, LayerKind::Tcp]);  // skip everything else
let mut stack = LayerStack::new();

for frame in capture {
    stack.reset();
    parser.parse_ethernet(&frame, &mut stack)?;
    if let Some(tcp) = stack.tcp() { /* zero-alloc hot path */ }
}
```

Performance target: < 30 ns / frame on the IPv4+TCP path with
`only(&[Ipv4, Tcp])`. The `Layers::parse_ethernet` ergonomic
shape stays — `LayerParser` is the opt-in for consumers who have
measured and need it.

### Integration with Pipeline

When `PipelineBuilder::layers(true)` is set, the `Event::Flow(FlowEvent::Packet
{ .. })` variant gains a `layers: Layers<'_>` field. Today
`FlowEvent::Packet` carries `frame: &[u8]`; the field is augmented
with the parsed view. Cost: ~100 ns per packet. Off by default
because not every consumer needs it.

Power users who want the zero-alloc path inside `Pipeline` can
use the lower-level driver builders (Tier 2) plus a
`LayerParser` in their packet loop — `Pipeline` itself does not
expose a zero-alloc surface because the type lifetimes
(`LayerStack` borrowing from the frame) don't compose cleanly
with `Pipeline`'s owning iterator. Documented in
`docs/recipes.md` "When you outgrow Pipeline".

---

## Dropping the callback-factory APIs

Removed in 0.9 (clean break):

- `flowscope::http::HttpFactory`, `HttpReassembler`, `HttpHandler`
- `flowscope::tls::TlsFactory`, `TlsReassembler`, `TlsHandler`

Kept (typed-stream APIs — strategic 1.0 shape):

- `flowscope::http::HttpParser` (`SessionParser`)
- `flowscope::tls::TlsParser` (`SessionParser`)
- `flowscope::dns::DnsUdpParser` (`DatagramParser`)
- `flowscope::dns::DnsTcpParser` (`SessionParser`)
- `flowscope::icmp::IcmpParser` (`DatagramParser`)
- All future parsers ship as `SessionParser` / `DatagramParser`.

Migration recipe (in CHANGELOG):

```rust
// 0.8 — callback style
let mut driver = FlowDriver::with_factory(ext, |_| HttpReassembler::new(HttpHandler::new()));

// 0.9 — typed stream
let mut pipeline = Pipeline::builder(ext).session(HttpParser::new()).build();
for event in pipeline.run_pcap("x.pcap")? {
    if let Event::Tcp(SessionEvent::Application { message, .. }) = event? {
        my_handler(message);
    }
}
```

---

## `flowscope::prelude`

```rust
// src/prelude.rs

pub use crate::{
    Pipeline, PipelineBuilder,
    Event, EventKind,
    FlowEvent, FlowSide, FlowStats, EndReason, AnomalyKind,
    SessionEvent,
    FlowTracker, FlowTrackerConfig,
    FlowSessionDriver, FlowDatagramDriver, FlowDriver,
    PacketView, AsPacketView,
    Timestamp,
    Error, Result,
    extract::FiveTuple,
};

#[cfg(feature = "http")]  pub use crate::http::HttpParser;
#[cfg(feature = "tls")]   pub use crate::tls::TlsParser;
#[cfg(feature = "dns")]   pub use crate::dns::{DnsUdpParser, DnsTcpParser};
#[cfg(feature = "icmp")]  pub use crate::icmp::IcmpParser;
#[cfg(feature = "pcap")]  pub use crate::pcap::PcapFlowSource;
```

So consumers can write `use flowscope::prelude::*;` and have the
common types in scope.

---

## Files

```
src/pipeline.rs                # new — Pipeline + PipelineBuilder + Event + EventKind
src/prelude.rs                 # new — re-exports
src/lib.rs                     # rewire module exports
src/driver.rs                  # delete free-function constructors; add builder
src/session_driver.rs          # delete free-function constructors; add builder
src/datagram_driver.rs         # delete free-function constructors; add builder
src/view.rs                    # add PacketView::layers() method
src/layers/mod.rs              # new module
src/layers/parse.rs            # tunnel-aware re-parse loop
src/layers/eth.rs              # EthernetSlice + VlanSlice + MplsSlice
src/layers/ip.rs               # Ipv4Slice + Ipv6Slice + ArpSlice
src/layers/transport.rs        # TcpSlice + UdpSlice + Icmpv4Slice + Icmpv6Slice
src/layers/tunnel.rs           # GreSlice + VxlanSlice + GtpUSlice
src/layers/kind.rs             # LayerKind + Display
src/layers/fast.rs             # LayerParser + LayerStack (zero-alloc fast path)
src/extract/parse.rs           # collapse onto src/layers/parse.rs (single source of truth)
src/http/factory.rs            # DELETED
src/http/types.rs              # remove HttpHandler/HttpConfig.callback path
src/tls/factory.rs             # DELETED
src/tls/types.rs               # remove TlsHandler path

tests/pipeline.rs              # new — Pipeline integration tests
tests/builder.rs               # new — driver-builder axis-combination tests
tests/layers.rs                # new — per-layer fixture tests
tests/layers_tunnels.rs        # new — VXLAN/GTP-U/GRE/IP-in-IP fixtures
tests/layers_proptest.rs       # extend the existing proptest suite
tests/layers_fast.rs           # new — zero-alloc parity + `only()` subset coverage
tests/ui/missing_parser.rs     # new — trybuild negative-compilation test
examples/hello_pipeline.rs     # new — Tier-1 hello-world
examples/inspect_packet.rs     # new — Tier-3 demo
benches/layers.rs              # new — parse + iter + find criterion bench
                                # + zero-alloc fast path vs ergonomic mode comparison

docs/getting-started.md        # rewritten to lead with Pipeline + prelude
docs/concepts.md               # three-tier diagram + format-stability policy
docs/recipes.md                # 4 new sections (see Tests/Acceptance)
CHANGELOG.md                   # 0.9.0 migration recipes
```

## Implementation steps

The plan is large; the steps below land as ~8 PRs.

1. **Errors first (plan 96).** Land `flowscope::Error` so the
   rest of this plan returns the right type.
2. **Layers module.** Create `src/layers/*` (ergonomic mode +
   `LayerParser` / `LayerStack` fast-path mode). Add
   `PacketView::layers()`. Migrate internal `src/extract/parse.rs`
   to call into the new path. The internal extractor uses the
   fast-path mode (caller-owned scratch) for the no-allocation
   FiveTuple extraction path.
3. **Driver builders, one at a time.**
   - `FlowSessionDriver::builder` — new builder type, type-state
     for `NoParser`. Migrate internal callers
     (`PcapFlowSource::sessions`, tests, examples).
   - Delete the 10 free-function constructors + 4 chainable
     `with_*` setters on the driver itself.
   - Repeat for `FlowDriver` (6 + 4 = 10 collapsed) and
     `FlowDatagramDriver` (10 + 4 = 14 collapsed).
4. **Drop callback factories.** Delete `src/http/factory.rs`,
   `src/tls/factory.rs`, `HttpHandler`, `TlsHandler`, the
   reassembler-callback wrappers. Sweep examples / docs that
   reference them.
5. **Pipeline.** Create `src/pipeline.rs`. Build atop the new
   driver builders. Implement `Event<K, SM, DM>`, `EventKind`,
   the type-state `S` / `D` upgrade path, `run_pcap`, `run_iter`,
   `reset`.
6. **Prelude.** Create `src/prelude.rs` with the curated
   re-export list.
7. **Docs sweep.** Rewrite `docs/getting-started.md` to lead
   with `Pipeline`. Update `docs/concepts.md` with the
   three-tier diagram. Add four `docs/recipes.md` sections
   (per-packet introspection / Tier-1 → Tier-2 escape hatch /
   custom packet sources / replacing the callback factories).
8. **Tests + examples + benches.** Per the file list above.
9. **CHANGELOG.** Migration recipes for: driver builders, error
   types (cross-link to plan 96), removed callback factories,
   layers module addition.

## Tests

### `tests/pipeline.rs`

- HTTP-only pipeline vs equivalent `FlowSessionDriver::builder`
  setup produces identical event sequences against the same
  pcap.
- DNS-UDP-only pipeline vs equivalent `FlowDatagramDriver`
  builder.
- Mixed (TCP HTTP + UDP DNS) pipeline drains both paths.
- `Pipeline::reset()` lets the same instance run two pcaps in
  sequence with no event bleed.
- `Pipeline` with no parser set fails to compile (trybuild
  cover).
- `Pipeline::run_iter` over a hand-crafted iterator yields the
  expected events.
- `layers(true)` attaches a `Layers` to every `FlowEvent::Packet`.

### `tests/builder.rs`

- Each driver builder's axis cross-product (parser × parser_factory)
  × (no_state / state / state_init) × (default_config /
  custom_config) — 16 baseline builds per driver, smoke-tested
  with one `.track()` call.
- `state_init` and `parser_factory` closures run exactly once per
  flow.
- Setter chain order is irrelevant (`A.config(c).state(s)` ==
  `A.state(s).config(c)` at runtime).

### `tests/ui/missing_parser.rs`

- `FlowSessionDriver::builder(ext).build()` fails to compile;
  diagnostic includes "no method named `build`".
- `Pipeline::builder(ext).build()` likewise.

### `tests/layers_fast.rs`

- Parity: every fixture in `tests/layers.rs` produces the same
  field values via `LayerParser` + `LayerStack` as via
  `Layers::parse_ethernet`.
- `only(&[Ipv4, Tcp])` populates only those slots; the rest
  stay `None` after `parse_ethernet`.
- `LayerStack::reset()` followed by a second parse on a
  different frame produces clean state (no field carryover).
- Heap allocation count: a million-frame loop with a single
  reused `LayerStack` performs **zero** heap allocations
  (asserted via a counting allocator wired up in the test
  harness).

### `tests/layers.rs`

- Ethernet + IPv4 + TCP fixture → all three slices present;
  `iter()` yields three layers + payload.
- Ethernet + 802.1Q VLAN + IPv4 + UDP → `vlan()` returns Some
  with the expected VID.
- Ethernet + IPv6 + TCP → IPv6 flow label exposed; TCP options
  parsed (MSS, WindowScale, SACKPermitted, Timestamps).
- ARP frame → `arp()` returns Some; no L4.
- ICMPv4 echo / ICMPv6 NS fixtures.

### `tests/layers_tunnels.rs`

- VXLAN-wrapped Eth+IP+TCP → two `Ipv4` layers found.
- GTP-U-wrapped IP+UDP.
- GRE-wrapped IP+TCP.
- IP-in-IP (proto 4 / 41).
- Truncated inner → `truncated() == true`, outer layers still
  accessible.

### `tests/layers_proptest.rs` (extension)

- For arbitrary 64–1500 byte buffers, `Layers::parse_ethernet`
  never panics. Bounded iteration count.

## Acceptance criteria

- Zero free-function constructors on `FlowDriver` /
  `FlowSessionDriver` / `FlowDatagramDriver`. Only `.builder(…)`.
- `examples/hello_pipeline.rs` runs under
  `cargo run --example hello_pipeline --all-features` and
  produces at least one event from `tests/fixtures/http/simple.pcap`.
- `examples/inspect_packet.rs` runs and prints a layered dump.
- `docs/getting-started.md` first code block uses
  `flowscope::prelude::*` + `Pipeline::builder`.
- `docs/concepts.md` shows the three-tier diagram.
- The four `docs/recipes.md` sections ship.
- CHANGELOG mapping tables ship: (a) driver constructor → builder,
  (b) HttpFactory/TlsFactory → SessionParser, (c) per-error-enum
  cross-link to plan 96.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `cargo bench --all-features layers` runs and produces baselines
  for `docs/performance.md`. The fast-path bench shows zero
  per-frame heap allocations and < 30 ns / frame on the
  `only(&[Ipv4, Tcp])` configuration.
- `netring` consumes the new shape in its sibling release; CI on
  both is green.

## Risks

- **Migration burden.** The deletions are large: 38 driver
  constructors gone, both callback-factory APIs gone, every
  example rewritten. Mitigation: detailed CHANGELOG mapping
  tables; `netring` lands in lockstep; the known external
  consumers are coordinated via direct outreach before the
  release.
- **`Box<dyn Any>` rejected for Pipeline's event surface.**
  An earlier draft used type-erased messages so a single
  `PipelineEvent` could carry HTTP + DNS messages
  interchangeably. The merged plan keeps it typed via
  generics `Event<K, SM, DM>`, paying the higher signature cost
  for the better consumer ergonomics (no downcasts). Power
  users wanting type erasure write `let p:
  Pipeline<_, Box<dyn Any + Send>, Box<dyn Any + Send>> = …`
  themselves.
- **Type-state ergonomics in the builder.** `NoParser`
  placeholder types surface in error messages. Verified on rustc
  1.85 stable that diagnostics are clear ("no method `build`
  found"); if user feedback hits, fallback to runtime
  `BuilderError`.
- **Tunnel-walking correctness for VXLAN's L3 mode.** VXLAN
  flags field distinguishes L2 / L3 inner. Fixture set covers
  both; parser branches on the flag.
- **Layers parse overhead on the extractor hot path.** Lifting
  `extract::parse` to `layers::parse` introduces a level of
  indirection. Benchmark before/after; keep an inline fast path
  in the extractor if it loses > 5% on FiveTuple extraction.
- **`netring` async stream signatures.** Async adapters wrap the
  sync drivers; their generics extend. The change is mechanical
  but touches every adapter. Lockstep release.
- **Doc surface growth.** Three tiers means three docs surfaces.
  Mitigation: `docs/concepts.md` is the single map; per-tier
  pages link from there.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| Pipeline + Event + EventKind | ~280 | 6 |
| Three driver builders + delete free constructors | ~480 | 12 |
| Drop callback factories + sweep examples | ~−400 | 4 |
| Layers module + slice types + tunnel walking | ~820 | 16 |
| Fast path (`LayerParser` + `LayerStack` + `only()` mask) | ~240 | 6 |
| Lift `extract/parse.rs` onto `layers/parse.rs` (fast path) | ~80 | 1.5 |
| `prelude.rs` | ~30 | 0.5 |
| Tests (pipeline + builder + layers + tunnels + proptest + UI + fast) | ~820 | 14 |
| Examples (2 new) | ~80 | 1 |
| Bench (layers ergonomic + fast path comparison) | ~120 | 2 |
| Docs (getting-started + concepts + 4 recipes) | ~−400 net delta | 6 |
| CHANGELOG migration recipes | ~150 | 2 |
| **Total** | **~2,260 LoC** | **~71 hours** |

The "−400 docs" entry reflects deleting the callback-factory
examples and `docs/recipes.md` sections that referenced the old
constructor matrix.

This is the largest single plan in the 0.9 cycle. The
implementation lands across ~8 PRs to keep individual reviews
tractable.

## Provenance

Consolidation of the former plans 94 (driver-builder), 95
(Pipeline), 100 (layers), driven by the user's 2026-06-06 ask:

> *"review all our plans. Make sure everything is rust idiomatic,
> that we provide high level API. You are allow to break the
> backward compatibility to make our crate the best of is kind.
> [...] Consolidate our plans."*

Rust idiom references for the consolidated builder shape:

- `reqwest::ClientBuilder` — unprefixed setter methods.
- `tokio::runtime::Builder::worker_threads(n)`,
  `.enable_io()`, `.enable_time()` — unprefixed; type-state
  pattern used for `Multi` vs `Single` thread runtimes.
- `axum::Router::route(p, h)`, `.nest()`, `.layer()` —
  unprefixed; chainable.
- `prost_build::Config::extern_path(…).bytes(…)` —
  unprefixed.
- `bevy::App::new().add_plugins(…).add_systems(…).run()` —
  unprefixed; mirrors Pipeline's overall shape.

For Tier-3 (per-packet introspection):

- **`etherparse::SlicedPacket`** — internal parsing engine.
  Re-shaped for flowscope's surface naming and tunnel
  following.
- **`pnet::packet`** — heavier, trait-per-protocol. Rejected
  for build cost.
- Python **`dpkt`** / **`scapy`** — chained-index pattern
  inspired `find` / `find_all`.
- **Go `gopacket`** — the dual-mode pattern is the dominant
  reference for this surface. `gopacket.NewPacket(data,
  LayerTypeEthernet, gopacket.Default)` is the ergonomic
  shape; `gopacket.DecodingLayerParser` with pre-allocated
  layer structs is the zero-alloc fast path (~10× throughput
  in published benchmarks). Plan 94's `LayerParser` /
  `LayerStack` mirrors this directly. Source:
  https://pkg.go.dev/github.com/google/gopacket

For the `prelude` pattern:

- `serde::prelude` / `tokio::prelude` (deprecated, but the
  pattern persists) / `std::prelude::v1`.

Ecosystem positioning (research 2026-06):

- **`huginn-net`** (2025) occupies the "passive multi-protocol
  fingerprint" niche with JA4 + p0f-style TCP/HTTP
  fingerprints; published 1.25 M pps / TCP, 562 K pps / HTTP,
  84 K pps / TLS. flowscope's differentiation is the layered
  trait stack + sync runtime-free posture + multi-source
  composition, *not* fingerprinting per se. Plan 97 adds JA4
  to keep parity for the case where users want one library
  for both flows and fingerprints, but the library's primary
  audience remains "I want flow + session tracking I can
  plug into anything."
- **`pnet`** / **`etherparse`** / **`pcap-parser`** stay the
  parsing-engine ecosystem; flowscope sits one tier above
  (flow accounting + L7 framing).
- **`netgauze-flow-pkt`** / **`netflow_parser`** /
  **`rustflow`** are the IPFIX/NetFlow export ecosystem.
  Emitting IPFIX from `FlowStats` is a deferred follow-up
  (see `plans/INDEX.md` deferred-items list).

The full audit numbers (38 constructors, 5 error enums, etc.)
remain in `plans/93-api-ergonomics-0_9.md`.
