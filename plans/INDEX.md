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
Eight DX pain points; **seven implementation plans** after
the consolidation pass (three multi-PR plans group tightly
related work into one cohesive review).

| Plan | Goal | Theme | Sizing |
|------|------|-------|--------|
| [`100-examples-postmortem.md`](./100-examples-postmortem.md) | Umbrella audit + cycle rationale. | — | doc |
| [`101-emit-module.md`](./101-emit-module.md) | `flowscope::emit` — CSV / NDJSON / Zeek `conn.log` writers. | 8 | ~830 LoC, ~21 h |
| [`102-utility-modules.md`](./102-utility-modules.md) | `correlate` extensions + `aggregate` + `detect` + `well_known` modules (4 sub-PRs). | 5 | ~2,080 LoC, ~43 h |
| [`106-parser-ergonomics.md`](./106-parser-ergonomics.md) | `AccumulatingSessionParser` + fallible `feed_*` + `BufferedFrameDrain`. | 7 | ~860 LoC, ~20 h |
| [`107-exchange-aggregators.md`](./107-exchange-aggregators.md) | `HttpExchangeParser` + `DnsExchangeParser`. | 5 | ~860 LoC, ~16 h |
| [`110-dx-polish.md`](./110-dx-polish.md) | Rustdoc landing pages + quick-win helper sweep (2 sub-PRs). | 1 + 3 + 4 | ~935 LoC, ~17 h |
| [`112-dynamic-lazy-analysis.md`](./112-dynamic-lazy-analysis.md) | Analysis: does the 0.10 surface allow dynamic / lazy detection? (no — motivates plan 113.) | — | doc |
| [`113-dynamic-dispatch.md`](./113-dynamic-dispatch.md) | `flowscope::detect::signatures` + `Routing::Heuristic` on the unified `Driver` (2 sub-PRs). Depends on 116. | (new) | ~1,590 LoC, ~25.5 h |
| [`115-strategic-review.md`](./115-strategic-review.md) | Strategic review motivating the driver+event unification (motivates plan 116; replaces prior plans 108 + 109). | — | doc |
| **[`116-driver-event-unification.md`](./116-driver-event-unification.md)** | **`Driver<E, M>` + `Event<K, M>` — collapse 6 drivers and 4 event types into one of each. Absorbs prior plans 108 + 109.** | **2 + 6** | **~700 LoC net, ~52 h** |

Total: ~7,855 LoC net, ~194.5 hours across **7 implementation
plans** (down from 12 pre-consolidation). The cycle work
itself is unchanged — the consolidation grouped four small
utility plans (102+103+104+105 → 102), two DX-polish plans
(110+111 → 110), and the dynamic-detection pair (113+114
→ 113) into multi-PR plans that share their out-of-scope
lists, industry research, and acceptance criteria.

Cycle theme: "address the next layer of DX after the 0.9
big surface choices."

Canonical landing sequence:

```
110 sub-B (quick wins ship first — other plans lean on them)
   ↓
101, 102 (sub-D well-known) (small additive — no dependencies)
   ↓
102 sub-A/B/C (correlate ext + aggregate + detect),
   110 sub-A (rustdoc landing pages)
   ↓
106 (parser ergonomics — feeds plan 107 + plan 116)
   ↓
107 (exchange aggregators)
   ↓
113 sub-A (signatures — standalone use; also feeds 113 sub-B)
   ↓
116 (driver + event unification — the centerpiece;
       absorbs prior plans 108 + 109; depends on 106 + 110 sub-B)
   ↓
113 sub-B (heuristic routing — extends Driver's builder;
            depends on 116 + 113 sub-A)
```

The user-priority plan is **116** — driver + event
unification. Land it as a 5-PR series before 113 sub-B so
the routing surface attaches to the new unified `Driver`.

Plan **112** (dynamic / lazy analysis) is a doc; plan
**113** addresses the "dynamic detection" gap surfaced by
the follow-up audit. Plan **115** (strategic-review doc)
motivates plan 116. A lazy-`Layers` sketch from 112 is
deferred pending benchmark data.

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
93, 94, 96, 97, 99. Subsumed by consolidation:
- 103, 104, 105 → rolled into plan 102 (utility modules)
- 111 → rolled into plan 110 (DX polish)
- 114 → rolled into plan 113 (dynamic dispatch)
- 108, 109 → rolled into plan 116 (driver+event unification)

Active: 21 (stale-deferred), 100, 101, 102, 106, 107, 110, 112,
113, 115, 116 (0.10 cycle). The next free number for a new
plan is 117+.

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
