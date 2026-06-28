# Concepts

flowscope is a layered library. Every layer ships a trait you
can plug into, and a sensible default. You can stop at any
layer and still get something useful — flow lifecycle without
bytes, bytes without typed messages, typed messages without
async.

This document is the conceptual reference: what each layer
does, how they compose, and what the events look like. For an
opinionated decision tree on which layer to reach for, see
[`recipes.md`](recipes.md). For a working hello-world, see
[`getting-started.md`](getting-started.md).

## The two-tier API surface (0.11+)

The library exposes two tiers of API, ranked by how much it
gives you out of the box:

```
┌─ Tier 1 — flowscope::driver::Driver<E> ─────────────────────┐
│  One builder, one typed `SlotHandle<M, K>` per parser,      │
│  zero-allocation `track_into` + `drain` per packet.         │
│  90 % of users; offline + simple online pipelines.          │
│  Slot handles are `Send + Sync` (0.12); the whole driver is │
│  `Send + Sync` (0.13) — `tokio::spawn(driver_task)` on the  │
│  default multi-thread runtime just works.                   │
│  `Driver::builder(ext).session_on_ports(p, [80]).build()`   │
└─────────────────────────────────────────────────────────────┘
┌─ Tier 2 — `FlowDriver` low-level primitive ─────────────────┐
│  Tracker + reassembler, run-to-completion. Emits            │
│  the `FlowEvent` lifecycle stream — you own the loop        │
│  and feed parsers yourself. The low-level primitive         │
│  under the typed `Driver`; use it for custom pipelines.     │
│  `FlowDriver::new(ext, reassembler_factory)`                │
└─────────────────────────────────────────────────────────────┘
┌─ Tier 3 — flowscope::layers ────────────────────────────────┐
│  Per-packet zero-copy L2/L3/L4 view + dynamic walk.         │
│  Anyone wanting raw header access on a frame.               │
│  `pv.layers()?.tcp()` / `.iter()` / `.find(LayerKind::…)`   │
└─────────────────────────────────────────────────────────────┘
```

Tier 1 is the recommended entry point for new programs. Each
tier sits atop the same `FlowExtractor` / `FlowTracker` /
`Reassembler` / `SessionParser` / `DatagramParser` traits — the
layered design below — and exposes a higher-level surface for
common cases.

## The pipeline

```
  ┌────────┐    ┌──────────────┐    ┌──────────────┐    ┌──────────────┐
  │  view  │───▶│  Extractor   │───▶│   Tracker    │───▶│ Reassembler  │
  │  &[u8] │    │  key + L4    │    │  FlowEvent   │    │ per-side     │
  └────────┘    └──────────────┘    └──────────────┘    └──────┬───────┘
                                                              │
                                                              ▼
                                                  ┌──────────────────┐
                                                  │  SessionParser   │
                                                  │  DatagramParser  │
                                                  │  typed messages  │
                                                  └──────────────────┘
                                                              │
                                                              ▼
                                            Event<K> + SlotHandle messages
```

Each arrow is a contract: a packet at the source produces zero or
more events at the sink. A consumer picks the layer that matches
the shape of the question they're asking.

## Layer 1 — `FlowExtractor`

Turn a packet into a flow descriptor. The trait:

```rust,ignore
pub trait FlowExtractor: Send + Sync + 'static {
    type Key: Hash + Eq + Clone + Send + 'static;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>>;
}

pub struct Extracted<K> {
    pub key: K,
    pub orientation: Orientation,     // Forward or Reverse (canonical direction)
    pub l4: Option<L4Proto>,
    pub tcp: Option<TcpInfo>,
}
```

Built-in extractors live behind the `extractors` feature:

| Extractor | Key shape | What it sees |
|-----------|-----------|--------------|
| `FiveTuple` | `(proto, SocketAddr, SocketAddr)` | The 5-tuple over IPv4 / IPv6 |
| `IpPair` | `(IpAddr, IpAddr)` | Just src/dst hosts; useful for ICMP |
| `MacPair` | `([u8; 6], [u8; 6])` | L2 only |

**Decap combinators** wrap an inner extractor:

```rust,ignore
use flowscope::extract::{FiveTuple, StripVlan, InnerVxlan};

let extractor = StripVlan(InnerVxlan::new(FiveTuple::bidirectional()));
//                          strip 802.1Q → strip VXLAN → 5-tuple
```

`AutoDetectEncap` is the *"I have mixed traffic, just figure it
out"* combinator. It costs up to 5× the per-packet parse cost on a
miss; if you know the encap shape, compose explicitly.

`FlowLabel<E>` augments an inner key with the IPv6 flow label (RFC
6437) — useful when MPTCP subflows share a 5-tuple and need to
be distinguished.

**Bring your own extractor.** Custom keys are common — app-level
cookies, BGP communities, tenant IDs in a header. Implement the
trait; the rest of the stack treats your key as opaque.

## Direction, orientation, and capture leg

A packet's "direction" is really **three orthogonal axes**. Conflating
them is the single most common flow-analysis bug (CICFlowMeter's
"sorted endpoint == initiator" assumption is the canonical example).
flowscope keeps all three distinct:

| Axis | Type | Anchored to | Question it answers | Deterministic? |
|------|------|-------------|---------------------|----------------|
| **Logical role** | [`FlowSide`] `Initiator` / `Responder` | arrival order (≈ SYN sender) | *Who started the conversation?* | **no** — first-seen can race |
| **Canonical orientation** | [`Orientation`] `Forward` / `Reverse` | address sort (`key.a < key.b`) | *Which way along the sorted key?* | **yes** |
| **Physical capture leg** | [`RxMetadata::source_idx`] `u32` | NIC / queue / interface | *Which wire did it arrive on?* | n/a (a fact, not inferred) |

These are independent: a single packet has a role, an orientation, and
a capture leg all at once, and knowing one tells you nothing about the
others.

### Why `FlowSide` alone is not enough

`FlowSide::Initiator` binds to whichever endpoint's packet the tracker
saw **first**. On one capture point that is reliably the SYN sender.
But across a **tap-merge** — two NICs (e.g. a TX leg and an RX leg of
the same link), or two RSS queues, feeding one tracker — a scheduling
race can deliver the *response* before the request. When that happens
`Initiator` binds to the server on some flows and the client on others,
**non-deterministically**. Anything keyed on `FlowSide` (per-direction
byte counts, biflow records, dedup across two capture points) then
disagrees between runs or between sensors.

`Orientation` has no such fragility: it is computed purely from the
canonical key ordering (`FiveTupleKey` sorts endpoints so `a < b`), so
the **same wire 5-tuple always yields the same `Orientation`**, no
matter which packet arrived first or which sensor observed it. Use it
whenever two independent observers must agree — Community ID ordering,
IPFIX biflow keying, cross-sensor dedup.

If you specifically need the *role* axis (`FlowSide`) to survive the
race — not just the orientation axis — set
`FlowTrackerConfig::infer_tcp_initiator`. For TCP, the tracker then
reads the handshake: a flow whose first observed packet is a `SYN+ACK`
(the response raced ahead) is flipped so the SYN sender stays
`Initiator`, and `FlowStats::direction_flipped` records that a
correction happened (the analogue of Zeek's `^`). It's opt-in (default
off) because single-tap captures always see the SYN first, where it
would change nothing. Non-TCP / mid-stream flows fall back to arrival
order. (#122)

### Both axes ride on every packet event

`FlowEvent::{Started, Packet}` (and the typed `Event::{Started,
Packet}`) carry **both** `side` and `orientation`. On a finished flow,
[`FlowStats::initiator_orientation`] records which `Orientation` the
initiator had, and `FlowStats::side_for(orientation)` /
`orientation_for(side)` translate between the axes:

```rust,ignore
match ev {
    // "who started it" — fragile under tap-merge
    FlowEvent::Packet { side, .. } => …,
    // deterministic canonical direction — stable across sensors
    FlowEvent::Packet { orientation, .. } => …,
    _ => {}
}

// On Ended, recover side from the canonical axis deterministically:
let side = stats.side_for(Orientation::Forward); // a→b half
```

### Standards mapping

Each axis lines up with an established wire/standard concept:

| flowscope | IPFIX (RFC 7011/5103) | pcapng / libpcap | gopacket | netring |
|-----------|------------------------|------------------|----------|---------|
| `FlowSide` | `biflowDirection` IE 239 | — | — | flow `side` |
| `Orientation` | (implied by sorted biflow key) | — | endpoint `LessThan` ordering | — |
| `RxMetadata::source_idx` | `observationPointId` IE 138 / `ingressInterface` IE 10 | EPB Interface ID | `InterfaceIndex` | `source_idx` |

The capture-leg axis (`source_idx`) is set by the capture layer
(netring, a pcapng reader, a tun device) via
[`PacketView::with_source_idx`]. On a **merged** bidirectional flow the
tracker folds it to a per-canonical-orientation binding —
`FlowStats::source_idx_for(Forward)` / `source_idx_for(Reverse)` —
without splitting the flow (the IPFIX biflow-merge model, RFC 5103:
forward `ingressInterface` + reverse IE). The first non-zero
`source_idx` seen for each direction binds it; a later *different* leg
on the same direction flips `FlowStats::capture_leg_inconsistent` —
the tap-miswire / asymmetric-routing IOC (#120). pcap / synthetic
sources leave `source_idx` at its `0` "unused" sentinel, so the
bindings stay `None`. Per-*packet* leg fidelity (audit tier) is tracked
separately (issue #121).

[`FlowSide`]: https://docs.rs/flowscope/latest/flowscope/enum.FlowSide.html
[`Orientation`]: https://docs.rs/flowscope/latest/flowscope/enum.Orientation.html
[`RxMetadata::source_idx`]: https://docs.rs/flowscope/latest/flowscope/struct.RxMetadata.html
[`FlowStats::initiator_orientation`]: https://docs.rs/flowscope/latest/flowscope/struct.FlowStats.html
[`PacketView::with_source_idx`]: https://docs.rs/flowscope/latest/flowscope/struct.PacketView.html

## Layer 2 — `FlowTracker<E, S>`

Per-flow accounting on top of the extractor. Generic over the
extractor `E` and an optional per-flow user state `S` (defaults to
`()`).

### State machine

TCP flows go through:

```
SynSent ──ack──▶ SynReceived ──ack──▶ Established ──fin──▶ FinWait
   │                                       │                │
   │                                       └──rst──▶ Reset  fin
   └──rst──▶ Reset                                          │
                                                            ▼
                                                      ClosingTcp
                                                            │
                                                          ack
                                                            ▼
                                                         Closed
```

Non-TCP flows skip the SYN states; they go straight to `Active`
and stay there until idle-timeout sweep.

### Lifecycle events

`FlowEvent<K>` is what falls out of `tracker.track(view)`:

| Variant | Fires when |
|---------|-----------|
| `Started { key, side, ts, l4 }` | First sight of a flow |
| `Packet { key, side, len, ts }` | Subsequent packet on a known flow |
| `Established { key, ts, l4 }` | TCP 3WHS complete |
| `StateChange { key, from, to, ts }` | TCP non-Established transition |
| `Ended { key, reason, stats, history, l4 }` | Flow concluded (FIN/RST/idle/etc.) |
| `Tick { key, stats, ts }` | Periodic snapshot; opt-in via `flow_tick_interval` |
| `FlowAnomaly { key, kind, ts }` | Per-flow anomaly; opt-in |
| `TrackerAnomaly { kind, ts }` | Tracker-global anomaly; opt-in |

### Configuration

`FlowTrackerConfig`:

- `idle_timeout_tcp` (default 5 min), `idle_timeout_udp` (60 s),
  `idle_timeout_other` (30 s) — protocol-aware idle classification.
- `max_flows` (default 100k) — LRU eviction kicks in here. Eviction
  emits `Ended { reason: Evicted }`.
- `max_reassembler_buffer`, `overflow_policy` — passed through to
  default reassembler factories.
- `flow_tick_interval` — opt-in periodic `Tick` events.
- `reassembler_high_watermark_pct` — buffer-pressure anomalies.

Per-flow user state `S` is generic — counters, parsers, anything.
Default `()`. Construct with `FlowTracker::new(extractor)` for `S
= ()`, or `with_state(extractor, init_fn)` / `with_state_init(...)`
for a custom `S`.

### Programmatic control

`tracker.force_close(key, now)` ends a specific flow ahead of
FIN/idle and emits `Ended { reason: ForceClosed }`. Use for
resource budgets, test harnesses, rate limiters.

`tracker.iter_active()` yields a snapshot per live flow:

```rust,ignore
for af in tracker.iter_active() {
    println!("{:?} state={:?} l4={:?} bytes={}",
        af.key, af.state, af.l4,
        af.stats.bytes_initiator + af.stats.bytes_responder);
}
```

`ActiveFlow` is `#[non_exhaustive]`; future fields are additive.

## Layer 3 — `Reassembler`

A per-`(flow, side)` byte-stream hook. The trait:

```rust,ignore
pub trait Reassembler: Send + 'static {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp);
    fn fin(&mut self);
    fn rst(&mut self);
    // diagnostic accessors — see rustdoc
}
```

The default `BufferedReassembler` accumulates in-order bytes and
classifies retransmits vs out-of-order segments using wrap-aware
sequence-space comparison. Custom reassemblers (gap-fill,
hole-tolerant, anything else) implement the trait directly.

### Bounded memory

`BufferedReassembler::with_max_buffer(bytes)` caps per-side
buffering. Pair with an `OverflowPolicy`:

- `SlidingWindow` (default) — drop oldest bytes when full. Flow
  stays alive; parser must resync. Stream-shaped protocols only.
- `DropFlow` — poison the reassembler; the driver tears down the
  flow on the next tick via `Ended { reason: BufferOverflow }`.

`with_high_watermark_threshold(pct)` fires a
`ReassemblerHighWatermark` anomaly when occupancy crosses the
threshold — operators see cap pressure building before
`BufferOverflow` bites.

### Diagnostics

`FlowStats` (on every `Ended` event) carries per-side:

- `reassembly_dropped_ooo_*` — OOO segment count
- `reassembly_bytes_dropped_oversize_*` — sliding-window drops
- `reassembler_high_watermark_*` — peak occupancy
- `retransmits_*` — classified TCP retransmits

## Layer 4 — `SessionParser` / `DatagramParser`

Typed L7 messages on top of the bytes. Two trait shapes:

```rust,ignore
pub trait SessionParser: Send + 'static {
    type Message: Send + Debug + 'static;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;

    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}

    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }

    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
    fn is_done(&self) -> bool { false }

    fn parser_kind(&self) -> &'static str { "" }
}

pub trait DatagramParser: Send + 'static {
    type Message: Send + Debug + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp) -> Vec<Self::Message>;
    // mirrors on_tick / is_poisoned / is_done / parser_kind
}
```

Stream-based protocols (HTTP/1.x, TLS, DNS-over-TCP) use
`SessionParser`. Packet-based protocols (DNS-over-UDP, ICMP,
syslog, NTP) use `DatagramParser`.

### Shipped parsers

Each behind its own Cargo feature:

| Feature | Parser | Kind | `parser_kind()` constant |
|---------|--------|------|--------------------------|
| `http` | `HttpParser` | session | `flowscope::http::PARSER_KIND` (`"http/1"`) |
| `tls` | `TlsParser` | session | `flowscope::tls::PARSER_KIND` (`"tls"`) |
| `dns` | `DnsTcpParser` | session | `flowscope::dns::PARSER_KIND_TCP` (`"dns-tcp"`) |
| `dns` | `DnsUdpParser` | datagram | `flowscope::dns::PARSER_KIND_UDP` (`"dns-udp"`) |
| `icmp` | `IcmpParser` | datagram | `flowscope::icmp::PARSER_KIND` (`"icmp"`) |

`l7` umbrella feature enables all four. Use the constants — or
the `flowscope::parser_kinds::*` umbrella module — at match sites
instead of string literals.

### Lifecycle signals

- `is_poisoned()` → driver synthesises `Ended { reason: ParseError }`
- `is_done()` → driver synthesises `Ended { reason: ParserDone }`

Use `is_done()` for protocols with intrinsic completion semantics
(HTTP/1.0 after body, DNS-over-TCP query/response pair, framed
sessions). `is_poisoned()` wins precedence if both fire.

### Convenience accessors

L7 message types ship method-shaped accessors for common header
lookups:

- `HttpRequest::host()`, `user_agent()`, `cookie()`, `header(name)`
- `HttpResponse::content_type()`, `content_length()`, `set_cookie()`
- `TlsClientHello::sni()`
- `IcmpType::is_error()`, `error_inner()` — extract the embedded
  `(src, dst, proto, src_port, dst_port)` from ICMP error
  messages for cross-protocol correlation
- `IcmpMessage::short_kind()` and `AnomalyKind::short_kind()` —
  stable `&'static str` slugs for metric labels

## Drivers

Layers 2–4 stitch together. flowscope ships two sync surfaces:

- **`driver::Driver<E>`** (Tier 1) — the typed driver. Register one
  session/datagram slot per protocol with
  `builder.session_on_ports(parser, ports)` /
  `builder.datagram_on_ports(parser, ports)`; the slot's
  `SlotHandle<M, K>` yields typed L7 messages while the driver emits
  the flow-lifecycle `Event<K>` stream. This is the supported
  single-parser surface — it replaced the per-parser
  `FlowSessionDriver` / `FlowDatagramDriver` in 0.20 (#99).
- **`FlowDriver<E, F, S>`** (Tier 2) — tracker + reassembler factory.
  Emits `FlowEvent`. The low-level building block — use it directly
  when you want flow lifecycle events without per-flow L7 parsing, or
  to build a custom run-to-completion loop. Supports per-flow user
  state via `S`, `force_close(key, now)`, and the underlying tracker
  via `tracker()` / `tracker_mut()`.

The internal session/datagram parser-dispatch engine that the typed
slots and the offline `pcap` source share is no longer a public type.

## Events at the L7 layer

With the typed [`driver::Driver<E>`], L7 output is split in two: the
flow-lifecycle `Event<K>` stream (from `track_into` / `run_pcap`) and
the typed parser messages drained from each protocol's `SlotHandle`.

`Event<K>`:

| Variant | Fires |
|---------|-------|
| `Started { key, ts, l4 }` | First sight of a flow |
| `Established { key, ts, l4 }` | TCP handshake completed |
| `Packet { key, side, len, ts, tcp }` | Per-packet (opt-in) |
| `Ended { key, reason, stats, history, l4, ts }` | Flow concluded |
| `StateChange { key, from, to, ts }` | TCP state transition |
| `ParserClosed { key, parser_kind, reason, ts }` | A slot's parser finished/erred |
| `FlowAnomaly { key, kind, ts }` | Per-flow anomaly (opt-in) |
| `TrackerAnomaly { kind, ts }` | Tracker-global anomaly (opt-in) |
| `Tick { key, stats, ts }` | Periodic snapshot (opt-in) |

Typed messages arrive as `SlotMessage { key, side, message }` from
the per-parser `SlotHandle` returned at registration. Register HTTP
on 80/8080, TLS on 443, DNS on 53; drain each independently.

(The crate-private engine still uses a `SessionEvent` carrier between
parser and slot, but it is not part of the public API since 0.20 —
the two public event enums are `FlowEvent<K>` and `Event<K>`.)

## Async integration

flowscope is **runtime-free**. To get a `Stream<FlowEvent>` or the
async session-event stream, layer on
[`netring`](https://crates.io/crates/netring):

```rust,ignore
let stream = AsyncCapture::open("eth0")?
    .flow_stream(FiveTuple::bidirectional())
    .session_stream(HttpParser::default());
```

netring depends on flowscope, not the other way around. tokio
never reaches the lib crate.

## State invariants

The contracts the library will not violate, in order of how often
they trip people up:

- **Mono-direction never doubles back.** Once a flow's `Initiator`
  side is determined (from the first packet's orientation), it
  stays. The tracker maintains this via an internal canonicalisation
  in the extractor's `Orientation`. Note `Initiator` is *arrival-order*
  relative and can race under a tap-merge; the canonical `Orientation`
  on every event does not — see
  [Direction, orientation, and capture leg](#direction-orientation-and-capture-leg).
- **`fin()` is idempotent.** Multiple FINs on the same side are
  fine.
- **Parser splitting invariance.** Feeding a byte sequence in one
  chunk produces the same messages as feeding it split anywhere.
  Verified by proptest for every shipped parser.
- **No-panic on random bytes.** Garbage input never panics; either
  errors or skips.
- **Per-protocol idle timeouts are independent.** A TCP flow with
  60 s of silence isn't ended; a UDP flow is.
- **LRU eviction is by `last_seen`.** When `max_flows` is hit, the
  oldest-seen flow is evicted.
- **`#[non_exhaustive]` on every public struct/enum that may grow.**
  Construct via `::default()` and mutate; do not rely on
  struct-literal construction from outside the crate.

## Known limitations

- **OOO TCP reassembly with hole-fill** — `BufferedReassembler`
  drops out-of-order segments. Strict drop is fine for most
  protocols (resync on next message); HTTP/2 + HPACK is the
  classic case where a hole desyncs the decoder. RFC tracked in
  `plans/74-rfc-ooo-reassembly.md`.
- **IPv4/IPv6 fragment reassembly** — `etherparse` parses the
  first fragment; subsequent fragments are tracked under their
  fragment-header tuple rather than reassembled into the inner
  flow. Out of scope until a consumer hits a heavy-fragmentation
  workload.
- **Wall-clock vs packet-clock divergence on offline pcaps** —
  live capture sweeps idle flows on a wall clock; offline replay
  only sweeps at EOF. Workaround: call `tracker.sweep(now)`
  yourself driven by packet timestamps. RFC for an opt-in
  packet-clock auto-sweep at `plans/75-rfc-tracker-auto-sweep.md`.
