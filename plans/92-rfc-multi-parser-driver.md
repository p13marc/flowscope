# Plan 92 — `FlowMultiSessionDriver` composite parser driver

## Summary

A composite session driver that runs N L7 parsers against a
single packet stream in one pass. The motivating shape:

```rust,ignore
let driver = FlowMultiSessionDriver::<_, MyL7Message>::new(FiveTuple::bidirectional())
    .with_parser_on_ports(HttpParser::default(), [80, 8080], MyL7Message::Http)
    .with_parser_on_ports(TlsParser::default(),  [443, 8443], MyL7Message::Tls)
    .with_parser_on_ports(DnsTcpParser::default(), [53], MyL7Message::Dns)
    .with_parser_broadcast(IcmpParser::new(), MyL7Message::Icmp);
```

The 0.8 cycle shipped the lighter-version fallback that the
wishlist author proposed: a documented recipe + worked example
(plan 91, `examples/multi_protocol_monitor.rs`) demonstrating the
manual "every parser, every packet" pattern. That pattern is
adequate for offline replay but loads the pcap N times. For live
capture and high-throughput offline pipelines, consumers want
one packet read → routed to each applicable parser → unified
event stream.

This started as an RFC plan published in 0.8.0; for 0.9.0 the
six design questions are locked (see "Design decisions" below)
and the plan promotes to an implementation plan.

The plan ships a `FlowMultiSessionDriver` for stream protocols
plus a `FlowMultiDatagramDriver` mirror for UDP — both follow
the same sum-type / routing shape, sharing as much
implementation as practical.

## Status

**Ready to implement.** Targets 0.9.0 release. Design questions
Q1–Q6 are answered with locked decisions.

## Prerequisites

- Plan 91 — shipped in 0.8.0. Documents the manual dispatch
  pattern this driver absorbs. The example file becomes the
  migration / comparison reference.
- Plan 76 (ICMP parser) — shipped in 0.7.0. ICMP is the
  canonical `broadcast`-routed parser (no ports); its handling
  validates the design covers `DatagramParser` flows.
- Plan 86 (`PARSER_KIND` constants) — shipped in 0.8.0.
  Consumers match composite-emitted events by `parser_kind`
  string; the constants are the routing keys.
- Plan 93 (0.9 API ergonomics audit) — covers how
  `FlowMultiSessionDriver` interacts with the broader
  builder-pattern refactor (plan 94).

## Out of scope

- Cross-parser reassembler state sharing. Each parser owns its
  reassembler; the composite driver coordinates dispatch, not
  storage. Sharing is a follow-up perf optimisation if profiling
  warrants.
- Async / tokio integration. flowscope is sync; netring builds
  the async layer.
- Backpressure semantics across parsers. Same boundary as
  today's single-parser drivers (consumer drains the returned
  `Vec`).
- Per-parser `S` user state. Composite drivers drop the `S`
  parameter entirely — see Q5 below. Consumers who need rich
  per-flow state stay on the bespoke single-parser driver.
- A pre-baked `flowscope::AnyL7Message` enum covering the
  built-in parsers. Wishlist's "Option C" — a convenience shim
  for the common case — is deferred to a follow-up plan once
  this lands and we have real usage data on how often consumers
  reach for the built-in subset vs custom enums.

---

## The use case

### Single-pass multi-parser pipelines

Today, consumers running HTTP + TLS + DNS + ICMP against the
same pcap take one of three paths:

1. **Open the source N times** (plan 91 recipe; readable,
   wasteful — loads the pcap N times from disk / re-runs the
   extractor N times in memory).
2. **Hand-roll a packet-level loop** that demuxes by port + L4
   and routes to N drivers (~80 LoC; performant; couples the
   port↔parser map to the consumer's code).
3. **Spin up N pcap iterators concurrently and merge by
   timestamp** (used by netring's `pcap_replay_multi.rs`;
   readable; loads the pcap N times still).

Approach 2 is the right shape for production pipelines but
shouldn't require every consumer to reimplement it. This RFC
scopes the absorption: a `FlowMultiSessionDriver` that takes a
list of `(parser, port_set)` pairs and routes packets internally.

### Concrete consumer asks

- **netring `pcap_replay_multi.rs`** — refactor to a one-pass
  loop, dropping the timestamp-merge step.
- **netring's `multi_protocol_monitor`** — same shape, but
  running against live AF_PACKET / AF_XDP traffic.
- **simple-nms's mixed-protocol detectors** — DNS + TLS + ICMP
  on the same flow stream, currently running through three
  independent drivers with externally-coordinated event ordering.

---

## Design decisions

Each question is now answered with a locked decision. The "Options"
text is retained as design rationale for future maintainers.

### Q1: Sum-type-of-messages — how do consumers see emitted messages?

The hardest design question. Each registered parser has its own
`Message` type (`HttpMessage`, `TlsMessage`, `DnsMessage`,
`IcmpMessage`). The composite driver must surface them through a
single `SessionEvent<K, M>` stream — `M` has to be one type.

**Option A — User-supplied sum type with lifting closures.**
Consumer defines `enum MyL7Message { Http(HttpMessage), Tls(TlsMessage), … }`
and passes a per-parser lift closure when registering:

```rust,ignore
let mut driver = FlowMultiSessionDriver::<_, MyL7Message>::new(FiveTuple::bidirectional())
    .with_parser(HttpParser::default(), [80, 8080], MyL7Message::Http)
    .with_parser(TlsParser::default(),  [443, 8443], MyL7Message::Tls);
```

- ✅ Static dispatch (parsers stay concrete); zero runtime cost.
- ✅ Consumer controls message-type ergonomics; can leave out
  parsers they never use.
- ❌ Boilerplate per consumer. They define and maintain the enum.
- ❌ The lift closures wrap every emitted message — a small
  branch per dispatch.

**Option B — `Box<dyn ErasedSessionParser<Message = …>>` registry
with type-erased message.**

```rust,ignore
let mut driver = FlowMultiSessionDriver::new(FiveTuple::bidirectional())
    .with_parser(HttpParser::default(), [80, 8080])
    .with_parser(TlsParser::default(),  [443, 8443]);
// Driver emits SessionEvent<K, Box<dyn Any + Send>>; consumer downcasts.
```

- ✅ No consumer-side enum.
- ❌ Type erasure is unergonomic — every consumer match arm
  downcasts.
- ❌ One allocation per emitted message.
- ❌ Loses serde derive on the message type (the consumer's `Any`
  has no derive).

**Option C — Shipped `AnyL7Message` enum covering the built-in
parsers**:

```rust,ignore
pub enum AnyL7Message {
    Http(HttpMessage),
    Tls(TlsMessage),
    DnsUdp(DnsMessage),
    DnsTcp(DnsMessage),
    Icmp(IcmpMessage),
}

let mut driver = FlowMultiSessionDriver::new(FiveTuple::bidirectional())
    .with_http([80, 8080])
    .with_tls([443, 8443])
    .with_dns_tcp([53])
    .with_icmp();
```

- ✅ Drop-in for the common case (built-in parsers).
- ✅ Pre-derived serde works.
- ❌ Locks the parser set to flowscope's built-ins. Custom
  parsers can't compose into the same driver.
- ⚠️ Mixed: a "I want to also include my custom parser" consumer
  falls back to option A anyway.

**Locked decision:** **A** as the primary surface, with **C** as a
follow-up convenience shim. Custom parsers and bring-your-own
enums (option A) are the load-bearing case; the option-C
preset is genuinely just a shortcut over option A and can ship
in the same release.

### Q2: Routing policy — port-based, L4-based, broadcast, or all of the above?

The wishlist proposes per-parser port hints
(`.with_parser(p, [80, 8080])`). Three variants:

**Option I — Port-based only.** Consumer supplies `&[u16]` per
parser. Driver routes a packet to a parser if `dst_port ∈ ports
|| src_port ∈ ports`. Non-matching packets skip the parser.

- ✅ Cheap, predictable, easy to reason about.
- ❌ Some protocols don't have well-known ports (custom
  framing). Consumer has to broadcast.

**Option II — Predicate-based.** `with_parser(p, |pv:
&PacketView<'_>| -> bool)`. Consumer writes the matching
predicate.

- ✅ Maximally flexible.
- ❌ One closure call per packet per parser; cost adds up.

**Option III — Hybrid: port-set OR broadcast.**
`.with_parser_on_ports(p, [80, 8080])` vs
`.with_parser_broadcast(p)`. ICMP gets broadcast (no ports);
HTTP/TLS/DNS get ports.

**Locked decision:** **III** — covers both common cases without
predicate overhead. Predicate-based added if a consumer asks.

### Q3: Reassembly state — per-parser or shared?

Each `SessionParser` owns its own reassembler today. With three
parsers running against the same TCP flow, three reassemblers
buffer the same bytes — 3× memory.

**Option α — Per-parser reassembler (current behaviour).**

- ✅ Parsers stay independent; no coordination needed.
- ❌ 3× per-flow buffer cost.

**Option β — Shared reassembler with multi-consumer drain.**
Single reassembler per flow; each parser pulls bytes
independently. Requires reassembler to track per-parser drain
offsets.

- ✅ 1× per-flow buffer cost.
- ❌ Reassembler trait grows multi-consumer machinery.
  Existing single-driver consumers must opt in or get
  surprised by the new shape.

**Locked decision:** **α** for the first implementation;
optimise later if memory pressure is a real problem in
production deployments. The 3× cost is bounded by
`max_reassembler_buffer` per parser.

### Q4: Event-stream ordering — interleaved or per-parser-batched?

A single packet can produce events from multiple parsers (a
TCP segment with HTTP request bytes triggers HTTP; a
DNS-over-TCP segment triggers `dns-tcp`; both can produce a
message). Two ordering disciplines:

**Option ✚ — Strict timestamp order.** All parsers' emitted
events for one packet land in the returned `Vec` in parser-
registration order (a deterministic but arbitrary ordering).
Consumer pre-sorts if they want timestamp order.

**Option ✛ — Per-parser batched.** Emit all of parser 1's
events for this packet first, then parser 2's, etc.

These are equivalent for single-packet events; the difference
shows up only when multi-message bursts emit. **Locked decision:**
**✚** (registration order) — predictable and easy to test.

### Q5: Per-parser `S` state — supported or not?

Today's single-parser driver supports per-flow user state `S`
(plan 38). For the composite, each parser has its own state.

**Locked decision:** drop `S` entirely from the composite. Custom
state belongs in the consumer's lift closure (option A), not in
the driver. The composite is the high-level convenience; rich
state stays on the bespoke single-parser pipeline.

### Q6: Error propagation across parsers — isolation or shared?

If one parser poisons (`is_poisoned() == true`), what happens
to the others?

**Locked decision:** **isolation** — the poisoned parser tears
down via the existing `SessionEvent::Closed { reason:
ParseError }` synthesis; the other parsers continue.

---

## Proposed minimum API

```rust,ignore
// src/multi_session_driver.rs (new module, opt-in feature?)

pub struct FlowMultiSessionDriver<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    // Single tracker; one reassembler factory per registered parser.
    tracker: FlowTracker<E, ()>,
    parsers: Vec<ParserSlot<E::Key, M>>,
}

struct ParserSlot<K, M> {
    kind: &'static str,                     // parser_kind label
    routing: Routing,                       // ports or broadcast
    reassemblers: HashMap<(K, FlowSide), BufferedReassembler>,
    instances: HashMap<K, Box<dyn ErasedSessionParser<M>>>,
}

enum Routing {
    Ports(SmallVec<[u16; 4]>),
    Broadcast,
}

impl<E, M> FlowMultiSessionDriver<E, M> { /* … */ }

impl<E, M> FlowMultiSessionDriver<E, M>
where M: Send + 'static
{
    pub fn new(extractor: E) -> Self;

    /// Register a parser that fires on a fixed port set. Lift
    /// closure converts the parser's native Message type to the
    /// composite's M.
    pub fn with_parser_on_ports<P, F>(
        self,
        parser: P,
        ports: impl IntoIterator<Item = u16>,
        lift: F,
    ) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    /// Register a parser that fires on every packet (e.g. ICMP).
    pub fn with_parser_broadcast<P, F>(
        self,
        parser: P,
        lift: F,
    ) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    pub fn track(&mut self, view: impl AsPacketView)
        -> Vec<SessionEvent<E::Key, M>>;
    pub fn sweep(&mut self, now: Timestamp)
        -> Vec<SessionEvent<E::Key, M>>;
    pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, M>>;
}
```

---

## Acceptance criteria

- `FlowMultiSessionDriver<E, M>` and `FlowMultiDatagramDriver<E, M>`
  ship behind the existing `session` / no-extra-feature surface
  (no new Cargo feature).
- `with_parser_on_ports` and `with_parser_broadcast` cover ICMP
  (broadcast), HTTP/TLS (port set), and DNS-TCP/UDP (port 53);
  documented in `docs/recipes.md`.
- Per-parser poison isolation: a parser that errors emits
  `SessionEvent::Closed { reason: ParseError }` for that
  `(flow, parser_kind)` pair; other parsers on the same flow
  continue.
- Events for a single packet land in the returned `Vec` in
  parser-registration order (Q4 — deterministic and tested).
- Three integration tests:
  1. Two-parser pcap (HTTP + TLS on the same port range) replays
     to the same event sequence as two single-parser drivers run
     against the same pcap independently.
  2. Three-parser pcap (HTTP + DNS-TCP + ICMP) covers the
     port-set / broadcast mix.
  3. Poison isolation: a deliberately broken parser is registered
     alongside HTTP; HTTP events continue after the broken parser
     synthesises its `Closed`.
- One round-trip proptest extending `tests/round_trip.rs` over a
  two-parser configuration.
- `netring`'s `pcap_replay_multi` example is rewritten as a
  single-pass loop using the new driver; reduces from ~120 LoC
  to ~30.
- `docs/recipes.md` gains a "Multi-protocol monitoring" section
  with the locked example from the Summary.
- `docs/concepts.md` documents the routing model in one
  paragraph.
- Zero clippy warnings, zero rustdoc warnings under
  `--all-features`.

---

## Effort

- Driver shell + registration API (ports / broadcast): ~180 LoC,
  ~4 hours.
- Per-parser reassembler + per-flow parser instance management
  (TCP + UDP variants share helpers): ~260 LoC, ~6 hours.
- Event translation pipeline (FlowEvent → composite
  `SessionEvent<K, M>`, parser_kind on `Application`): ~130 LoC,
  ~3 hours.
- Tests (two-parser, three-parser, poison isolation, round-trip
  proptest): ~340 LoC, ~5 hours.
- Doc + example updates (recipes + concepts + netring example
  refactor): ~3 hours.
- **Total:** ~22 hours, ~910 LoC.

## Provenance

Round-3 wishlist item B2 in netring's 2026-06-06 consolidated
wishlist. Plan 91 shipped the doc-recipe fallback the author
proposed; this plan scopes the full composite driver they
originally asked for. The author was clear that the recipe is a
stopgap (*"netring's `pcap_replay_multi.rs` example uses the
'open twice, merge by timestamp' approach — readable but loads
the pcap 2× from disk"*); the composite driver replaces it.

Target: 0.9.0 release.
