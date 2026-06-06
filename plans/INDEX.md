# plans/ — backlog index

This directory holds **forward-looking work items only** — concrete
plans for features that haven't shipped yet.

Reference material that informs the plans (design rationale,
research, consumer feedback) lives in [`../docs/`](../docs/),
which is published as part of the crates.io package.

**Convention**: when an implementation plan ships, **delete the
plan file** in the same PR series. `git log` is the historical
record; `plans/` is the working backlog. The previous "keep
shipped plans as records" convention accumulated 28+ files
before we switched.

---

## Backlog

The 0.4 API-ergonomics series (plans 32–37) has shipped; the audit
that drove it is kept at
[`../docs/API-ERGONOMICS-REVIEW.md`](../docs/API-ERGONOMICS-REVIEW.md).

The 0.5.0 release shipped plans 70–73 from a `simple-nms`
upstream wishlist. The 0.6.0 release shipped plans 38, 39, 43,
44, 50, 58, 59, 60, 61 from a `netring` integration feedback
round. The 0.7.0 release shipped plans 62, 76, 77, 78, 79, 80,
82 from a `netring` round-2 retrospective. The 0.8.0 release
shipped plans 83, 84, 85, 86, 87, 88, 89, 90, 91 from a
consolidated `netring` wishlist.

In every cycle the plan files have been retired per the project
convention — `CHANGELOG.md` entries and the `plan NN: …` commit
subjects are the durable record. The upstream-feedback documents
and per-cycle plan-of-record syntheses that drove each release
have also been retired now that every load-bearing item is
either shipped, RFC-scoped, or deferral-noted below.

### Pending RFCs (0.9.0+)

| Plan | Goal | Status |
|------|------|--------|
| [`74-rfc-ooo-reassembly.md`](./74-rfc-ooo-reassembly.md) | RFC scope for OOO TCP reassembly with hole-fill. | 📝 RFC only |
| [`75-rfc-tracker-auto-sweep.md`](./75-rfc-tracker-auto-sweep.md) | RFC scope for `FlowTracker::with_auto_sweep(interval)`. | 📝 RFC only |
| [`81-rfc-correlate-module.md`](./81-rfc-correlate-module.md) | RFC scope for `flowscope::correlate` (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`); upstream author offered to co-author. | 📝 RFC only |
| [`92-rfc-multi-parser-driver.md`](./92-rfc-multi-parser-driver.md) | RFC scope for `FlowMultiSessionDriver` — composite session driver running N parsers in one pass. The 0.8 doc-recipe fallback (plan 91, shipped) forward-points here. | 📝 RFC only |

Deferred items recorded so a future ask doesn't get
re-litigated:

- **`FlowTracker::with_auto_sweep(interval)`** — packet-clock
  auto-sweep for live/offline parity. RFC scoped in plan 75;
  implementation pending reviewer agreement.
- **`flowscope::correlate` module** (`TimeBucketedCounter`,
  `KeyIndexed`, `SequencePattern`) — RFC scoped in plan 81.
  The narrow dns-side primitive shipped separately as
  [`DnsResolutionCache`](./../src/dns/correlate.rs) in 0.8
  (plan 85).
- **OOO TCP reassembly with hole-fill** — RFC scoped in plan 74.
  Driven by HTTP/2 + HPACK desync after segment loss.
- **`FlowMultiSessionDriver` composite parser driver** — RFC
  scoped in plan 92. The doc-recipe fallback shipped in 0.8 as
  [`examples/multi_protocol_monitor.rs`](../examples/multi_protocol_monitor.rs)
  and `docs/SESSION_GUIDE.md` → "Multi-protocol monitoring".
- **`TlsHandshake` aggregator parser** — more design surface
  than initially scoped (resumption / abbreviated handshake /
  failed handshake / renegotiation). Manual ClientHello +
  ServerHello correlation pattern is documented in
  `docs/SESSION_GUIDE.md`. Revisit if a second consumer asks.
- **Parser `&mut S` API change** — addressed via the
  `docs/SESSION_GUIDE.md` consumer-loop pattern instead of
  plumbing a generic through every shipped parser.
- **Lazy iterator return type on parser `feed_*` / `parse`** —
  declined twice; reconsider only with a third consumer +
  reproducer.
- **Built-in RTP / RTCP / HTTP/2 / RTPS parsers** — accept
  consumer-led upstream PRs after their parsers stabilise;
  don't ship without an out-of-tree maintainer commitment.
- **TLS 1.3 0-RTT classification surface** — small follow-up if
  a consumer asks; not blocking anyone today.
- **IPv4 / IPv6 fragment reassembly** — deferred indefinitely
  per `docs/ARCHITECTURE.md` known-limitations section.
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
- **JA4 fingerprint** — modern JA3 successor (weighted-by-
  popularity ordering). Ship behind a `ja4` feature mirroring
  the existing `ja3` feature; revisit when a consumer asks.
- **`FlowExtractor::extract_batch` for SIMD-shaped parsers** —
  speculative; only matters at 40+ Gbps line rates. No current
  consumer at that scale.

### Sister crates

[`../docs/DPI_ARCHITECTURE.md`](../docs/DPI_ARCHITECTURE.md)
recommends some functionality ships as separate sister crates
rather than features of flowscope. Only one such plan is
currently parked here:

| Plan | Goal | Status |
|------|------|--------|
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `flowscope-protolens` — protolens bridge as a sister crate | 🛑 stale, deferred |

### Considered but not in the backlog

A few capability gaps are known but not currently planned. They
live here as a footnote rather than as plan files so the backlog
stays a working set rather than a wish list.

- **NetFlow / IPFIX export** — would integrate with the
  enterprise observability stack (ntopng, Kentik, Splunk
  Stream). Belongs in a sister crate (`flowscope-export`) per
  `DPI_ARCHITECTURE.md`. No current consumer asking.
- **`flow-summary` / `flow-replay` CLIs** — sister crate
  `flowscope-cli`. Useful for "try without writing code" demos
  and CI replay testing. No current consumer asking.
- **IPv6 fragment reassembly** — `etherparse` parses the first
  fragment; subsequent fragments are tracked under their
  fragment-header tuple rather than reassembled. Most flow
  tracking is fine without this; heavy-fragmentation workloads
  would want a `ReassembledFragments<E>` extractor wrapper
  following RFC 8200 / RFC 5722. No current consumer asking.

If any of these surface as real needs, write a fresh plan
against the current codebase — earlier drafts were
pre-consolidation and would need full rewrites.

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

Plan numbers 00–04, 12, 20, 22–25, 30–61, 62, 70–73, 76–80, 82,
83–91 (everything except 21, 74, 75, 81 — which are parked as
stale-deferred or RFC-only) are retired (implementation shipped,
file removed). New plans pick the lowest free number in the
appropriate range — the 0.5.0 series used 70+ to keep the active
set visually distinct from the retired numbers; the 0.7 series
continued that in the 76–82 block; the 0.8 series occupied
83–91.

---

## Conventions

These apply to every new plan in this directory.

### `#[non_exhaustive]` on every public struct/enum

Applied project-wide in 0.2.0; future additions are unconditionally
non-breaking. Construct via `::default()` and mutate; do not rely
on struct-literal construction from outside the crate.

### Pre-1.0 backward-compatibility policy

Pre-1.0, flowscope optimises for the best possible design over
preserving compatibility. When a sharper API shape is better, we
ship it and migrate consumers — `netring` and the known external
consumers update in lockstep. The CHANGELOG documents every break
with a migration recipe. Post-1.0 the trade-off flips.

### Trait-method overrides for diagnostics

When a trait grows a diagnostic method (e.g.
`Reassembler::high_watermark`), it ships with a default-zero /
default-`None` implementation so existing third-party impls don't
break. A default return means "this implementation doesn't track
that," not "the value is zero / absent."

### Single vocabulary across event stream and metrics

The `AnomalyKind` enum is the single source of truth for both
the `FlowEvent::FlowAnomaly` / `TrackerAnomaly` carriers and the
`flowscope_anomalies_total` metric labels. Adding a new variant
requires a corresponding label arm in `src/obs.rs::anomaly_label`
in the same change.

### Sync / async parity

flowscope is runtime-free. Every async helper in `netring`
(`flow_stream`, `session_stream`, `datagram_stream`) has a sync
mirror in flowscope (`FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver`). The async path is the ergonomic one; the
sync path is what offline-pcap consumers and embedded users get.

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
12. **Provenance** (when applicable) — context that shaped this plan

Update Status as you go. When a plan ships, **delete the file in
the same PR series** that lands the implementation (or in a
follow-up cleanup commit). The CHANGELOG entry plus the
`plan NN: …` commit subject are the durable record.
