# plans/ — backlog index

This directory holds **forward-looking work items only** —
concrete plans for features that haven't shipped yet.

Reference material that informs the plans (design rationale,
research, consumer feedback) lives in [`../docs/`](../docs/),
which is published as part of the crates.io package.

**Convention**: when an implementation plan ships, **delete the
plan file** in the same PR series. `git log` is the historical
record; `plans/` is the working backlog.

---

## Active

### 0.9.0 cycle

The 0.9 cycle is complete. Every implementation plan shipped
and every plan file is retired — the work lives in commit
history and the CHANGELOG. The umbrella audit's durable
record (38 driver constructors, two duplicated L7 API shapes,
five error enums, no high-level entry, no per-packet layered
view) is absorbed into the 0.9.0 CHANGELOG header.

### 0.10.0 cycle — backlog

Triggered by the 0.9 examples-writing postmortem
([`100-examples-postmortem.md`](./100-examples-postmortem.md)).
Eight DX pain points were catalogued; one detailed plan per
fix.

| Plan | Goal | Theme | Sizing |
|------|------|-------|--------|
| [`100-examples-postmortem.md`](./100-examples-postmortem.md) | Umbrella audit + cycle rationale. | — | doc |
| [`101-emit-module.md`](./101-emit-module.md) | `flowscope::emit` — CSV / NDJSON / Zeek `conn.log` writers. | 8 | ~830 LoC, ~21 h |
| [`102-correlate-extensions.md`](./102-correlate-extensions.md) | `TimeBucketedSet` + `BurstDetector` + `TopK` + `Ewma`. | 5 | ~1,010 LoC, ~20 h |
| [`103-aggregate-module.md`](./103-aggregate-module.md) | `flowscope::aggregate` — `Histogram` + `Percentile`. | 5 | ~440 LoC, ~11 h |
| [`104-detect-module.md`](./104-detect-module.md) | `flowscope::detect` — Shannon entropy + light primitives. | 5 | ~295 LoC, ~6 h |
| [`105-well-known-ports.md`](./105-well-known-ports.md) | `flowscope::well_known` — curated `(proto, port)` → label table. | 5 | ~335 LoC, ~6 h |
| [`106-parser-ergonomics.md`](./106-parser-ergonomics.md) | `AccumulatingSessionParser` + fallible `feed_*` + `BufferedFrameDrain`. | 7 | ~860 LoC, ~20 h |
| [`107-exchange-aggregators.md`](./107-exchange-aggregators.md) | `HttpExchangeParser` + `DnsExchangeParser`. | 5 | ~860 LoC, ~16 h |
| [`108-packet-event-enrichment.md`](./108-packet-event-enrichment.md) | `FlowEvent::Packet` gains `tcp: Option<TcpInfo>` + `frame: Option<Bytes>`. | 2 | ~435 LoC, ~13.5 h |
| **[`109-cross-l4-multi-driver.md`](./109-cross-l4-multi-driver.md)** | **`FlowMultiDriver<E, M>` — shared-tracker, spans TCP+UDP.** | **6** | **~1,330 LoC, ~38 h** |
| [`110-rustdoc-landing-pages.md`](./110-rustdoc-landing-pages.md) | Module-level rustdoc accessor index for http/tls/dns/icmp + 7 new HTTP accessors. | 4 | ~400 LoC, ~7 h |
| [`111-quick-wins.md`](./111-quick-wins.md) | `Timestamp` / `FlowStats` / `EndReason` / `LayerKind` / `Layer` / `LayerStack` / `KeyIndexed` helpers. | 1 + 3 + 4 | ~535 LoC, ~10 h |

Total: ~7,330 LoC, ~169 hours across 11 implementation
plans. Comparable to the 0.9 cycle (~5,880 LoC, ~174 h);
distributed more evenly across multiple smaller plans than
0.9's plan-94-dominated shape.

Cycle theme: "address the next layer of DX after the 0.9
big surface choices."

Canonical landing sequence:

```
111 (quick wins ship first — other plans lean on them)
   ↓
101, 105, 110 (small additive — no dependencies)
   ↓
102, 103, 104 (aggregation primitives — feed plan 107)
   ↓
106 (parser ergonomics — feed plan 107 + plan 109)
   ↓
107 (exchange aggregators)
   ↓
108 (packet enrichment — affects every consumer)
   ↓
109 (cross-L4 driver — the centerpiece; depends on 106)
```

The user-priority plan is **109** — cross-L4 multi-driver.
Land it last in the cycle so the supporting infrastructure
(parser ergonomics, packet enrichment) is in place first.

### Deferred / stale

| Plan | Goal | Status |
|------|------|--------|
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `flowscope-protolens` — protolens bridge as a sister crate | 🛑 stale, deferred |

---

## Deferred items recorded so a future ask doesn't get re-litigated

- **Parser `&mut S` API change** — addressed via the
  `docs/concepts.md` consumer-loop pattern instead of plumbing
  a generic through every shipped parser.
- **Lazy iterator return type on parser `feed_*` / `parse`** —
  declined twice; reconsider only with a third consumer +
  reproducer.
- **Built-in RTP / RTCP / HTTP/2 / RTPS parsers** — accept
  consumer-led upstream PRs after their parsers stabilise;
  don't ship without an out-of-tree maintainer commitment.
- **TLS 1.3 0-RTT classification surface** — small follow-up
  if a consumer asks; not blocking anyone today.
- **IPv4 / IPv6 fragment reassembly** — deferred indefinitely
  per `docs/concepts.md` known-limitations section.
- **`FlowTrackerConfig::with_event_filter(SUPPRESS_PACKET)`** —
  per-flow event-variant suppression at the tracker source.
  Perf-only optimisation; revisit if a profile shows
  `FlowEvent::Packet` allocation as a hot path.
- **`extract::HostPair` / `extract::AppliedFilter`** —
  additional extractor adapters. Add when a consumer asks for
  one specifically; the existing `FiveTuple` / `IpPair` /
  `MacPair` set covers most cases.
- **Pageable reassembler** — writes excess to disk / a
  side-channel on `BufferedReassembler` overflow, preserving
  evidence for forensics. Niche; revisit when a forensics-
  focused consumer asks.
- **`SyntheticFlowDriver` / `pcap_macro!` test fixtures** —
  programmatic `FlowEvent` vec construction + frame-builder
  macro. Useful as `test_helpers` extensions; revisit when a
  downstream consumer asks.
- **Tracker pause/resume for load-shedding** — accept packets
  but don't emit events without losing flow state. Niche;
  revisit when a consumer asks.
- **JA4S / JA4H / JA4L / JA4T / JA4X / JA4SSH** — JA4 family
  variants beyond the client TLS fingerprint shipped by plan
  97. Ship one variant at a time when a consumer asks.
- **`FlowExtractor::extract_batch` for SIMD-shaped parsers** —
  speculative; only matters at 40+ Gbps line rates. No current
  consumer at that scale.
- **IPFIX / NetFlow v9 / sFlow export** — emit
  `flowscope::FlowStats` as IPFIX records to feed the
  `netgauze-flow-pkt` / `netflow_generator` / `rustflow`
  collector ecosystem. Belongs in a sister crate
  (`flowscope-export`) per `docs/design.md`.
- **Passive QUIC parser** — no Rust passive QUIC parser
  exists today (every QUIC crate — `quinn`, `s2n-quic`,
  `quiche`, `tokio-quiche` — is an active endpoint
  implementation). Greenfield opportunity; defer until a
  consumer asks.
- **HTTP/2 passive parser** — same shape as QUIC; smaller
  surface. Defer until a consumer asks.
- **`#[derive(SessionParser)]` macro** — wsdf-style
  declarative dissector generator. Defer to post-1.0; the
  trait shape needs to stabilise before locking a macro API.
- **Composite multi-layer fingerprint** — nDPI 5.0's FPC
  pattern. Interesting but mature/niche; defer.
- **Wirefilter expression filter** — Cloudflare's
  `wirefilter-engine` could plug in as a flow filter. Useful
  for the future CLI sister crate; defer.
- **Shared-tracker optimisation for `FlowMultiSessionDriver`**
  — current 0.9 implementation runs parallel
  `FlowSessionDriver`s (one per parser). Plan 92 spec'd one
  shared tracker driving N parsers; the storage optimisation
  is a follow-up if a high-throughput consumer profiles and
  needs it.

---

## Numbering scheme (for new plans)

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (now mostly in `netring`) |
| 20–29 | Protocol parsers and packet sources |
| 30–39 | Higher-level abstractions (Conversation, SessionParser) |
| 40–49 | Observability + performance |
| 50–59 | Deferred-feature catchup |
| 60–69 | Tooling (CLIs) |
| 70–79 | 0.5.0 production-hardening v2 (simple-nms wishlist) |
| 90–99 | 0.9.0 ergonomics cycle (umbrella + breaks + additions) |
| 100–199 | 0.10.0 DX-polish cycle (postmortem-driven) |

Plan numbers retired (implementation shipped, file removed):
00–04, 12, 20, 22–25, 30–61, 62, 70–73, 74, 75, 76–82, 83–91,
93, 94, 96, 97, 99. Active: 21 (stale-deferred), 100–111
(0.10 cycle). The next free number for a new plan is 112+.

---

## Conventions

These apply to every new plan in this directory.

### `#[non_exhaustive]` on every public struct/enum

Applied project-wide in 0.2.0; future additions are
unconditionally non-breaking. Construct via `::default()` and
mutate; do not rely on struct-literal construction from outside
the crate.

### Pre-1.0 backward-compatibility policy

Pre-1.0, flowscope optimises for the best possible design over
preserving compatibility. When a sharper API shape is better,
we ship it and migrate consumers — `netring` and the known
external consumers update in lockstep. The CHANGELOG documents
every break with a migration recipe. Post-1.0 the trade-off
flips.

### Trait-method overrides for diagnostics

When a trait grows a diagnostic method (e.g.
`Reassembler::high_watermark`), it ships with a default-zero /
default-`None` implementation so existing third-party impls
don't break. A default return means "this implementation doesn't
track that," not "the value is zero / absent."

### Single vocabulary across event stream and metrics

The `AnomalyKind` enum is the single source of truth for both
the `FlowEvent::FlowAnomaly` / `TrackerAnomaly` carriers and
the `flowscope_anomalies_total` metric labels. Adding a new
variant requires a corresponding label arm in
`src/obs.rs::anomaly_label` in the same change.

### Sync / async parity

flowscope is runtime-free. Every async helper in `netring`
(`flow_stream`, `session_stream`, `datagram_stream`) has a sync
mirror in flowscope (`FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver`). The async path is the ergonomic one; the
sync path is what offline-pcap consumers and embedded users
get.

### No `tokio` in flowscope's deps

Hard rule (also stated in CLAUDE.md). Async lives in `netring`,
which depends on flowscope. PRs adding tokio to flowscope are
wrong-shaped.

---

## Plan structure for new plans

Each `NN-*.md` plan has these sections:

1. **Summary** — one paragraph
2. **Status** — Not started / In progress / Done
3. **Prerequisites** — which prior plans must be complete
4. **Out of scope** — what this plan does NOT do
5. **Files** — exact paths to create/modify
6. **API** — concrete type/function signatures to ship
7. **Implementation steps** — numbered, mechanical
8. **Tests** — unit + integration coverage
9. **Acceptance criteria** — what "done" looks like
10. **Risks** — known unknowns specific to this phase
11. **Effort** — LOC and time estimate
12. **Provenance** (when applicable) — context that shaped
    this plan

Update Status as you go. When a plan ships, **delete the file
in the same PR series** that lands the implementation (or in a
follow-up cleanup commit). The CHANGELOG entry plus the
`plan NN: …` commit subject are the durable record.
