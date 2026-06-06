# Plan 92 — RFC: `FlowMultiSessionDriver` composite parser driver

## Summary

**This is an RFC plan, not an implementation plan.** It scopes
the design space for a composite session driver that runs N L7
parsers against a single packet stream in one pass.

The 0.8 cycle shipped the lighter-version fallback that the
wishlist author proposed: a documented recipe + worked example
(plan 91, `examples/multi_protocol_monitor.rs`) demonstrating the
manual "every parser, every packet" pattern. That pattern is
adequate for offline replay but loads the pcap N times. For live
capture and high-throughput offline pipelines, consumers want
**one packet read → routed to each applicable parser → unified
event stream**.

Implementation is **not in scope for 0.9.0** until reviewer
agreement is reached. The bulk of the work here is in the
sum-type-of-messages design surface — three candidate shapes,
each with real ergonomic costs. The RFC commits to the question
list and the evaluation criteria; the answers wait for input.

## Status

**RFC scope only.** Targets 0.9.0 release as a published RFC
plan; implementation deferred until the design questions below
have answers.

## Prerequisites

- Plan 91 — shipped in 0.8.0. Documents the manual dispatch
  pattern this RFC's driver would absorb. The example file
  becomes the migration / comparison reference.
- Plan 76 (ICMP parser) — shipped in 0.7.0. ICMP is one of the
  parsers a composite driver must route to; its handling
  validates the design covers `DatagramParser` (not just
  `SessionParser`) flows.
- Plan 86 (`PARSER_KIND` constants) — shipped in 0.8.0.
  Consumers match composite-emitted events by `parser_kind`
  string; the constants are the routing keys.

## Out of scope (for this RFC)

- Implementation. The design space is wide enough that we want
  reviewer input before any code lands.
- Cross-parser reassembler state sharing. Each parser owns its
  reassembler; the composite driver coordinates dispatch, not
  storage.
- Async / tokio integration. flowscope is sync; netring builds
  the async layer.
- Backpressure semantics across parsers. Same boundary as
  today's single-parser drivers (consumer drains the returned
  `Vec`).
- A `FlowMultiDatagramDriver` mirror. The session-driver design
  generalises to the datagram side naturally; defer the explicit
  spec to the implementation plan.

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

## Design questions

Each has a tentative pick; the RFC explicitly invites disagreement.

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

**Tentative pick:** **A** as the primary surface, with **C** as a
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

**Tentative pick:** **III** — covers both common cases without
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

**Tentative pick:** **α** for the first implementation;
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
shows up only when multi-message bursts emit. **Tentative pick:**
**✚** (registration order) — predictable and easy to test.

### Q5: Per-parser `S` state — supported or not?

Today's single-parser driver supports per-flow user state `S`
(plan 38). For the composite, each parser has its own state.

**Tentative pick:** drop `S` entirely from the composite. Custom
state belongs in the consumer's lift closure (option A), not in
the driver. The composite is the high-level convenience; rich
state stays on the bespoke single-parser pipeline.

### Q6: Error propagation across parsers — isolation or shared?

If one parser poisons (`is_poisoned() == true`), what happens
to the others?

**Tentative pick:** **isolation** — the poisoned parser tears
down via the existing `SessionEvent::Closed { reason:
ParseError }` synthesis; the other parsers continue.

---

## Proposed minimum API (tentative)

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

## Acceptance criteria for THIS RFC (not the implementation)

- The maintainer (me) and the netring author both agree on the
  answers to Q1–Q6 (or document where they disagree explicitly).
- The chosen sum-type shape (Q1) survives a sanity check against
  a custom parser composing with the built-ins.
- The chosen routing policy (Q2) covers ICMP (no ports), DNS-UDP
  (port 53), and a custom hypothetical "DNS-over-TLS" parser
  needing predicate-based routing.
- The API shape is concrete enough that an implementation plan
  can be written without re-arguing the design.

## Open questions for reviewers

1. **Q1 sum-type shape:** A (user enum + lift) primary, C
   (built-in `AnyL7Message`) shim? Or one of them alone?
2. **Q2 routing:** ports + broadcast (III), or just ports (I)?
3. **Q3 reassembly state:** stay per-parser (α), or share (β)?
4. **Q5 per-parser S:** drop entirely, or thread through as
   `S = ()`?
5. **General:** is `FlowMultiSessionDriver` the right module
   name, or do we go with `MultiParserDriver` /
   `CompositeSessionDriver` / `MultiplexedDriver`?

---

## Effort

**For the RFC itself** (this document): ~600 lines, ~3 hours.

**For the implementation** (deferred — not in this plan):

- Driver shell + registration API: ~150 LoC, 3 hours.
- Per-parser reassembler + per-flow parser instance management:
  ~200 LoC, 5 hours.
- Event translation (FlowEvent → SessionEvent<K, M> via per-
  parser slot): ~120 LoC, 3 hours.
- Tests covering 2-parser, 3-parser, and 4-parser registration;
  routing correctness; poison isolation; event ordering: ~300
  LoC, 4 hours.
- Doc updates (SESSION_GUIDE.md "Multi-protocol monitoring"
  section absorbing the composite-driver flow): ~80 lines, 1
  hour.
- **Implementation total:** ~16 hours, ~770 LoC.

## Provenance

Round-3 wishlist item B2 in netring's 2026-06-06 consolidated
wishlist. Plan 91 shipped the doc-recipe fallback the author
proposed; this RFC scopes the full composite driver they
originally asked for. The author was clear that the recipe is a
stopgap (*"netring's `pcap_replay_multi.rs` example uses the
'open twice, merge by timestamp' approach — readable but loads
the pcap 2× from disk"*); the composite driver replaces it.

Target landing for the RFC: 0.9.0. Target landing for the
implementation: 0.9.0 or 0.10.0, contingent on reviewer
agreement on the design questions.
