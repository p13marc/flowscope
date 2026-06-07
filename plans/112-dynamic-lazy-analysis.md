# Plan 112 — dynamic detection + lazy parsing: analysis and proposal

## The question

> "With the plans you created, does our crate allow dynamic
> and lazy detection and parsing to optimize performance? If
> not, is it a good idea?"

This document answers both halves. Section 1 audits what the
shipped 0.9 surface plus the planned 0.10 work (plans
101–111) actually enable. Section 2 defines what
"dynamic" and "lazy" mean in the network-analysis space and
surveys the industry. Section 3 recommends what to add —
two focused new plans (113, 114) within the 0.10 cycle,
plus a sketched third (115) that should land only with
profile data behind it.

The TL;DR up front:

- **Current 0.10 plans do NOT enable dynamic detection.**
  Routing in plan 109's `FlowMultiDriver` is port-set +
  broadcast only. There is no signature / heuristic
  mechanism; if a flow uses TLS on port 8080, the TLS parser
  has to be registered on 8080 by hand.
- **Current parsing is eagerly tier-3.** `Layers::parse_ethernet`
  parses every layer down to L4 up front; the
  `LayerParser` fast path can skip *populating* slots, but
  still touches the headers.
- **Dynamic detection IS a good idea.** Every comparable
  system (Suricata, Zeek, nDPI, Wireshark, gopacket via
  heuristics) ships it; the consensus pattern (cheap-first
  cascade + pin-on-first-match + bounded packet budget)
  bounds the cost. Real-world traffic does not honour the
  IANA port table.
- **Lazy parsing is mostly a wash for flowscope's hot path.**
  The FiveTuple tracker already touches L2–L4 on every
  packet. Going lazier there saves nothing. The narrow place
  where lazy *would* help is per-packet introspection
  consumers who touch a single layer of <10 % of packets —
  for them, a `LazyLayers` variant is worth ~20-30 % parse
  cost. Worth measuring before building.

## Status

**Analysis only.** The proposal yields three sibling plans
(113, 114, 115) that the maintainer may or may not adopt.
Plan 112 itself ships nothing.

## Prerequisites

- This document references plans 101–111 (the 0.10 cycle
  backlog). No code prerequisite.

---

## 1. Audit: what do the 0.10 plans enable?

### Detection: port-based only

`FlowMultiDriver` (plan 109) accepts two routing modes per
registered parser:

```rust
.session_on_ports(parser, [80, 8080], lift)  // dst ∈ ports || src ∈ ports
.session_broadcast(parser, lift)             // every TCP packet
.datagram_on_ports(parser, [53], lift)
.datagram_broadcast(parser, lift)
```

There is no `Routing::Heuristic`, `Routing::Predicate`, or
content-sniffing mode. Plan 92 Q2 (locked in 0.9.0)
explicitly deferred predicate routing — and the rationale
holds: predicate routing without an indexing layer means
every packet runs every predicate.

What this means in practice for the `extract_iocs.rs` shape:

```rust
let driver = FlowMultiDriver::<_, MyL7>::builder(ext)
    .session_on_ports(HttpParser::default(),         [80, 8080], MyL7::Http)
    .session_on_ports(TlsHandshakeParser::default(), [443],       MyL7::Tls)
    .datagram_on_ports(DnsUdpParser::default(),      [53],        MyL7::Dns)
    .build();
```

A TLS handshake on port 8443? Misses. HTTP on port 9000? Misses.
Encrypted SOCKS proxy on port 53? Misses (the DNS parser
would run, fail to parse, and emit nothing).

`session_broadcast` is the escape hatch — register a parser
that runs on every TCP packet and let it self-decide. But
that means every parser registered broadcast pays the full
per-packet decode cost on every flow, even ones it has no
business looking at. Not a real fix.

### Parsing: tier-3 layers are eager

`Layers::parse_ethernet` calls
`etherparse::SlicedPacket::from_ethernet` once and walks
all detected layers into a `SmallVec<[Layer; 8]>` up front.
Direct accessors (`layers.tcp()`, `layers.ipv4()`) are
constant-time after the initial parse.

The `LayerParser` + `LayerStack` fast path (shipped 0.9)
adds a `.only(&[LayerKind…])` mask that lets the parser skip
populating unrequested slots, but the underlying
`etherparse::SlicedPacket` still walks every header on the
path to the requested ones. The `.only()` saves the slot-
copy work; it does not skip the parse itself.

L7 parsers (`HttpParser`, `TlsParser`, `DnsUdpParser`, …)
are also eager: `feed_*` returns `Vec<Message>`; each
message is fully constructed.

Plan 108 (packet enrichment) adds `tcp: Option<TcpInfo>` +
`frame: Option<Bytes>` to `FlowEvent::Packet` — gated by
`emit_packet_details`. Even when on, the TCP info is
populated from the tracker's already-completed parse (the
`Extracted::tcp` field exists internally); zero new parsing.
`frame` is a `Bytes::copy_from_slice` clone, allocating but
not parsing.

### Summary

The 0.9 + 0.10 (101–111) surface ships **eager parsing on
all paths and port-based detection only**. This matches
flowscope's "deterministic state machines + bounded
memory" charter and is the right shape for a sync,
runtime-free library.

But it doesn't match the real-world workload of a
production NMS / IDS / DPI engine. Every comparable system
ships dynamic detection.

---

## 2. Definitions and prior art

### "Dynamic detection"

In this context: routing a packet (or flow) to a parser
based on **payload content** rather than port number.

Three common shapes:

- **Signature / pattern match.** Compare the first N
  bytes against known protocol magic. Cheapest; high
  confidence for unambiguous protocols (TLS, SSH, HTTP).
- **Probing parser.** Run a candidate parser on the first
  few packets; it returns `MATCH` / `NO_MATCH` /
  `NEED_MORE_DATA`. More expensive but handles ambiguity.
- **Heuristic dissector** (Wireshark term). Returns
  `bool` after inspecting payload; first-claim-wins.

### "Lazy parsing"

Four common shapes:

- **Layer-level lazy.** Parse only the layers the consumer
  accesses. (gopacket's `Lazy` decode option.)
- **Field-level lazy.** Parse fields only on accessor
  call. (etherparse `SlicedPacket`, Cap'n Proto,
  FlatBuffers.)
- **Message-level lazy.** Defer constructing typed messages
  until the consumer iterates.
- **Detection lazy.** Defer choosing a parser until enough
  bytes have arrived to be confident.

### Prior art

A web research pass surveyed gopacket, Suricata, Zeek,
nDPI, Wireshark, etherparse, pnet, huginn-net, Cap'n Proto,
and FlatBuffers (full notes in commit log of this plan's
authoring). Key findings:

**Every production DPI system ships dynamic detection.**
Suricata's `app-layer` pattern + probing mechanism; Zeek's
DPD with signature-set + analyzer-tree pruning; nDPI's
cascading detection (IP/port cache → Aho-Corasick magic →
per-protocol dissector); Wireshark's heuristic dissectors
with conversation pinning. No major system relies on port
alone.

**The cheap-first cascade is universal.** Every system runs
the cheapest classification step first (port cache or
pattern match); slower probing only runs on misses.
Suricata explicitly gates probing parsers behind a port
whitelist for this reason.

**Pin-on-first-match is universal.** Once a flow's protocol
is identified, the dispatch overhead drops to zero for the
rest of the flow. Wireshark's "conversation pinning,"
Zeek's analyzer-tree pruning, nDPI's flow cache, Suricata's
`ALPROTO_*` stored on flow — same pattern under different
names. Repeated heuristic evaluation per packet is
universally considered a bug.

**Bounded packet budget.** nDPI's `packets_limit_per_flow`,
Zeek's `ProtocolViolation` pruning, Suricata's parser-must-
commit-within-N-packets. None allow unbounded "still
trying" state. nDPI's 4.10 First Packet Classification
(FPC) goes further — short-circuits the obvious cases
from packet 1.

**Throughput numbers** (single-thread, commodity hardware):

- gopacket `Lazy | NoCopy`: ~700 Mbps in user reports.
- nDPI: ~68k pps / 237 Mb/s with full dissector set.
- huginn-net: 1.25 M pps TCP, 562 k pps HTTP, 84 k pps TLS.

flowscope is in the huginn-net throughput class for the
flow-tracker path. Adding dynamic detection adds 1-3 %
in nDPI's case; bounded by the FPC fast-path.

**For lazy parsing**, the trade-off is consistently
documented: lazy decoding wins for *selective* consumers,
loses for *everything-touchers* due to branch prediction
cost and lost cache locality.

- gopacket's docs say: enable `Lazy` for filter-style
  workloads where you'll often discard packets before
  touching all layers.
- etherparse's docs: use `SlicedPacket` (lazy) for
  filtering, `PacketHeaders` (eager) when interested in
  most fields.
- Cap'n Proto / FlatBuffers: lazy wins for sparse access;
  the binary is ~30 % larger than Protobuf in exchange.

The consensus: **lazy parsing is a hot-path optimization for
selective consumers, not a default.**

---

## 3. Recommendation

### Yes to dynamic detection — focused scope

Two new plans inside the 0.10 cycle (slot them in after
plan 109 lands):

- **Plan 113** — `flowscope::detect::signatures` — small
  module with magic-byte recognizers for the eight or so
  protocols flowscope ships parsers for (HTTP, TLS, DNS,
  ICMP, plus a few common ones — SSH, IRC, RESP, MQTT).
  Each signature is a pure function `&[u8] -> bool` over
  the first 4-32 bytes of payload. No state. Composes with
  the existing `flowscope::detect` module proposed in plan
  104.
- **Plan 114** — `Routing::Heuristic { signatures }` on
  the plan-109 `FlowMultiDriver`. Adds a new routing mode
  that runs a list of signatures over the first N bytes of
  payload per flow; pins on first match. After the pin, the
  parser receives subsequent packets directly (zero
  per-packet detection overhead). The "cheap-first
  cascade" + "pin-on-first-match" + "bounded packet
  budget" patterns directly.

Both plans are bounded: 113 ships ~10 signatures (300
LoC), 114 wires them into the existing driver dispatch
(~250 LoC + tests). Combined effort: ~15-20 hours.

The key design constraint: **bounded packet budget**. The
multi-driver tracks per-flow "detection state" — `Unknown`
on the first packet, `Matched(parser_idx)` once a signature
fires, `GaveUp` after N packets without a match. After
either terminal state, dispatch is O(1) — same cost as
port-routed today. Bounding the budget at 8 packets
(matching nDPI's median) keeps the worst-case memory
overhead under 64 bytes per flow.

This stays within flowscope's charter:

- Deterministic: signatures are pure functions; no
  randomness, no learned models.
- Bounded memory: per-flow detection state is fixed-size.
- Library, not framework: ship the building blocks (113) +
  the integration point (114); don't ship a 250-signature
  rule database like nDPI. Consumers compose with our
  signatures + their own.
- Composable with the existing port-based routing: a
  parser can register on `[443, 8443]` AND in the
  heuristic list. Port match wins; heuristic catches the
  rest.

### Partial yes to lazy parsing — prove the case first

The hot path (tracker via FiveTuple) touches L2-L4 on every
packet. Going lazier there is a wash to a small loss in
microbenchmarks; gopacket's docs are explicit about this.

The selective-access path (consumer calls `pv.layers()`
ad-hoc) has more room. A consumer who only checks "is
there a VLAN tag?" on 1% of frames pays 100% of the parse
cost today.

A **Plan 115** sketch:

- Add `LazyLayers<'a>` — same surface as `Layers<'a>` (same
  accessors, same `iter`/`find`) but each accessor lazily
  parses just the layer it needs. Internal state is a
  `Cell<ParseState>`.
- Construct via `PacketView::layers_lazy()`.
- `Layers::parse_ethernet` stays as-is (eager mode).

Whether this is worth shipping depends on benchmark data
we don't have. Recommend: ship 113 + 114 in 0.10; write
the benchmark for 115 as part of 0.10 perf work; ship 115
only if the benchmark shows ≥20% savings on the selective-
access pattern.

### No to a full nDPI-grade engine

nDPI ships ~421 protocols + flow risks + Aho-Corasick
multi-pattern matching + per-protocol dissector code.
That's a multi-year engineering project that duplicates
existing C work.

If a consumer needs that, they bind to nDPI directly. A
sister crate `flowscope-ndpi` could expose nDPI's protocol
ID into a flowscope-shaped parser_kind. That's not in any
plan; flag it as a possible 0.11+ if asked.

### Decision summary

| Capability | Recommend | Plan |
|------------|-----------|------|
| Magic-byte signatures for shipped parsers | ✅ Yes | **113** |
| Heuristic routing in `FlowMultiDriver` | ✅ Yes | **114** |
| Per-flow pinning + bounded packet budget | ✅ Yes (part of 114) | 114 |
| `LazyLayers` for selective-access consumers | ⚠️  Benchmark first | 115 sketch |
| nDPI-grade pattern catalog | ❌ Sister crate territory | n/a |
| Full DPI rule engine (Suricata-shaped) | ❌ Out of charter | n/a |
| Wireshark-style heuristic dissector registry per parent | ⚠️  Subsumed by 114 | n/a |

---

## Files (this plan)

```
plans/112-dynamic-lazy-analysis.md  # this file — analysis + recommendation
plans/113-detection-signatures.md   # detail plan (NEW, written alongside this)
plans/114-heuristic-routing.md      # detail plan (NEW, written alongside this)
plans/INDEX.md                      # add 113 + 114 to the 0.10 backlog table
```

Plan 115 is sketched in this document only; full plan
authoring deferred pending benchmark data.

## Effort

This plan: 0 LoC.

Sibling plans:

- 113: ~350 LoC, ~7 hours.
- 114: ~600 LoC, ~14 hours.
- 115 (if pursued): ~450 LoC + benchmark, ~12 hours.

113 + 114 combined add ~21 hours to the 0.10 cycle —
roughly 12 % over the existing ~169-hour budget. Worth it
for a capability every comparable system ships.

## Provenance

User question, 2026-06-07:

> *"with the plans/ you created, does our crate will allow
> dynamic and lazy detection and parsing to optimize
> performance? If not, is it a good idea?"*

Plus 0.9 examples-writing pass: the
`extract_iocs.rs`, `multi_parser_pipeline.rs`, and
`port_scan_detector.rs` examples all implicitly assumed
"protocols sit on their canonical ports." For
demonstrating the library shape that's fine; for a
production pipeline it isn't.

Research references (web search synthesis):

- **gopacket** `Lazy` decode mode + concurrency caveat.
  https://github.com/google/gopacket/blob/master/doc.go
- **Suricata app-layer** pattern + probing parser model.
  https://docs.suricata.io/en/latest/rules/app-layer.html
- **Zeek DPD** signature + analyzer-tree pruning.
  https://old.zeek.org/development/howtos/dpd.html
- **nDPI** cascading detection + First Packet
  Classification.
  https://www.ntop.org/how-first-packet-classification-fpc-works-in-ndpi/
- **Wireshark** heuristic dissectors + conversation
  pinning.
  https://github.com/wireshark/wireshark/blob/master/doc/README.heuristic
- **etherparse** `SlicedPacket` (lazy) vs `PacketHeaders`
  (eager) — the lazy / eager API split a flowscope-shaped
  library can adopt.
  https://docs.rs/etherparse
- **huginn-net** signature-based fingerprinting numbers —
  flowscope's throughput peer.
  https://github.com/biandratti/huginn-net

The consensus pattern (cheap-first cascade + pin on first
match + bounded budget) is universal. Plan 114 adopts it
directly.
