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

### 0.9.0 cycle — ready to implement

The 0.9 release is the last pre-1.0 cycle where flowscope can
break backwards compatibility freely. The umbrella plan is
[`93-api-ergonomics-0_9.md`](./93-api-ergonomics-0_9.md), which
inventories the friction points and points at the concrete
plans below.

| Plan | Goal | Breaking? |
|------|------|-----------|
| [`93-api-ergonomics-0_9.md`](./93-api-ergonomics-0_9.md) | Umbrella audit: motivation for the 0.9 cycle. | n/a (no code) |
| [`74-rfc-ooo-reassembly.md`](./74-rfc-ooo-reassembly.md) | Out-of-order TCP reassembly with hole-fill (`SegmentBufferReassembler`). | additive |
| [`75-rfc-tracker-auto-sweep.md`](./75-rfc-tracker-auto-sweep.md) | `FlowTracker::with_auto_sweep(interval)` packet-clock sweep. | additive |
| [`81-rfc-correlate-module.md`](./81-rfc-correlate-module.md) | `flowscope::correlate` module (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`). | additive |
| [`92-rfc-multi-parser-driver.md`](./92-rfc-multi-parser-driver.md) | `FlowMultiSessionDriver` / `FlowMultiDatagramDriver` composite drivers. | additive |
| [`94-high-level-api.md`](./94-high-level-api.md) | Three-tier API surface (Tier 1 `Pipeline` + Tier 2 driver builders + Tier 3 `layers` module + drop callback-factory L7 APIs + `prelude`). | **breaking** |
| [`96-error-unification.md`](./96-error-unification.md) | Five module-local `Error` enums collapsed to one `flowscope::Error`. | **breaking** |
| [`97-tls-modernization.md`](./97-tls-modernization.md) | JA4 client fingerprint behind `ja4` feature + `TlsHandshakeParser` aggregator. | additive |
| [`99-rust-2024-idioms.md`](./99-rust-2024-idioms.md) | Rust 2024 idioms sweep + MSRV review. | mostly internal |

Three plans are the breaking ones — 94, 96, and the MSRV piece
of 99 (currently held at 1.85). Their migration recipes are the
bulk of the CHANGELOG entry for 0.9.0.

The 2026-06-06 consolidation merged former plans 94 (driver
builder) + 95 (Pipeline entry point) + 100 (packet layers) into
the new plan 94, and former plans 97 (JA4) + 98 (TLS handshake
aggregator) into the new plan 97 — taking the cycle from 12
plans to 8 (plus the umbrella). The rationale is captured in
plan 93's Provenance section.

Deferred items recorded so a future ask doesn't get
re-litigated:

- **Parser `&mut S` API change** — addressed via the
  `docs/concepts.md` consumer-loop pattern instead of plumbing
  a generic through every shipped parser.
- **Lazy iterator return type on parser `feed_*` / `parse`** —
  declined twice; reconsider only with a third consumer +
  reproducer.
- **Built-in RTP / RTCP / HTTP/2 / RTPS parsers** — accept
  consumer-led upstream PRs after their parsers stabilise;
  don't ship without an out-of-tree maintainer commitment.
- **TLS 1.3 0-RTT classification surface** — small follow-up if
  a consumer asks; not blocking anyone today.
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
  (`flowscope-export`) per `docs/design.md`. Substantial work
  (IE mapping, template management); plan when a consumer
  asks. Research note: `netgauze-flow-pkt` auto-pulls IEs
  from the IANA registry — picking it as the export
  back-end avoids hand-maintained IE tables.
- **Passive QUIC parser** — no Rust passive QUIC parser
  exists today (every QUIC crate — `quinn`, `s2n-quic`,
  `quiche`, `tokio-quiche` — is an active endpoint
  implementation). Greenfield opportunity. nDPI 5.0 (C) added
  QUIC fingerprinting and Encrypted Traffic Analysis in
  2025; the Rust port is unwritten. Track as a high-value
  follow-up but defer until a consumer asks (the spec
  surface is large).
- **HTTP/2 passive parser** — same shape; no obvious
  `SessionParser`-shaped passive HTTP/2 parser on crates.io
  as of 2026-06. Smaller surface than QUIC. Defer until
  a consumer asks.
- **`#[derive(SessionParser)]` macro** — wsdf-style
  declarative dissector generator. The Rust ecosystem is
  moving toward derive-macro-driven protocol descriptions
  (`wsdf`, `pdl-dissector`). flowscope's `SessionParser`
  trait is a candidate target. Defer to post-1.0; the trait
  shape needs to stabilise before locking a macro API on top.
- **Composite multi-layer fingerprint** — nDPI 5.0's FPC
  (Fingerprint-based Protocol Classification) bundles TLS +
  QUIC + behavioural fingerprints into one flow attribute.
  Interesting but mature/niche; defer.
- **Wirefilter expression filter** — Cloudflare's
  `wirefilter-engine` could plug in as a flow filter
  (`Pipeline::filter("ip.src == 10.0.0.0/8 && tcp.dst == 443")`).
  Useful for the CLI sister crate (`flowscope-cli`); defer
  until that ships.

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
| 90–99 | 0.9.0 ergonomics cycle (umbrella + breaks + additions) |

Plan numbers 00–04, 12, 20, 22–25, 30–61, 62, 70–73, 76–80, 82,
83–91 (everything except 21 — parked as stale-deferred — and 74,
75, 81, 92, 93, 94, 96, 97, 99 — the active 0.9 cycle) are
retired (implementation shipped, file removed). New plans pick
the lowest free number in the appropriate range — the 0.5.0
series used 70+ to keep the active set visually distinct from
the retired numbers; the 0.7 series continued that in the 76–82
block; the 0.8 series occupied 83–91; the 0.9 series occupies
92–99 (the consolidation freed numbers 95, 98, 100, which are
available for the 0.10 cycle).

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
