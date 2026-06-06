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

The 0.5.0 release (plans 70–73, simple-nms wishlist) shipped from
its own series in parallel; the 0.6 API-ergonomics series (plans
38, 39, 43, 44, 50, 58, 59, 60, 61) shipped on top of it. Two
feedback streams drove the two series:

- [`../docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md) +
  [`../docs/0.6-PLAN-OF-RECORD.md`](../docs/0.6-PLAN-OF-RECORD.md)
  (§3 documents the substantive disagreement with the netring
  author's "lean toward option B" on plan 38).
- [`../docs/feedback-2026-08-11-simple-nms.md`](../docs/feedback-2026-08-11-simple-nms.md)
  (drove the 0.5.0 release — TCP rich diagnostics, FlowTick,
  parser_kind).
- [`../docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md)
  + [`../docs/0.7-PLAN-OF-RECORD.md`](../docs/0.7-PLAN-OF-RECORD.md) —
  netring's round-2 retrospective after writing four L7
  examples; drives the 0.7 series (plans 62, 76, 77, 78, 79,
  80, 82, plus RFC plan 81).
- [`../docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md)
  + [`../docs/0.8-PLAN-OF-RECORD.md`](../docs/0.8-PLAN-OF-RECORD.md) —
  consolidated netring wishlist; drives the 0.8 series (plans
  83, 84, 85, 86, 87, 88, 89, 90, 91).

The 0.7 implementation batch (plans 62, 76, 77, 78, 79, 80, 82)
has shipped on master. Plan files retired per convention;
CHANGELOG entries are the durable record. Plan-of-record at
[`../docs/0.7-PLAN-OF-RECORD.md`](../docs/0.7-PLAN-OF-RECORD.md).

### Pending (0.8.0)

The 0.8 implementation batch — plan-of-record at
[`../docs/0.8-PLAN-OF-RECORD.md`](../docs/0.8-PLAN-OF-RECORD.md).

| Plan | Goal | Breaking? | Status |
|------|------|-----------|--------|
| [`83-serde-feature.md`](./83-serde-feature.md) | `serde` opt-in feature with `Serialize` + `Deserialize` on every public type; locks the snake_case wire vocabulary from 0.8 forward (wishlist A1). | no (new feature) | 🟢 ready |
| [`84-icmp-helpers.md`](./84-icmp-helpers.md) | `IcmpType::is_error()` + `error_inner()` + `short_kind()` and mirrors on `IcmpMessage` (wishlist A2). | no | 🟢 ready |
| [`85-dns-resolution-cache.md`](./85-dns-resolution-cache.md) | `flowscope::dns::DnsResolutionCache` — TTL'd per-client resolution cache (wishlist A3). | no | 🟢 ready |
| [`86-parser-kind-constants.md`](./86-parser-kind-constants.md) | `PARSER_KIND*` constants per parser module + `flowscope::parser_kinds` umbrella (wishlist B1). | no | 🟢 ready |
| [`87-established-l4.md`](./87-established-l4.md) | `FlowEvent::Established { l4 }` — rounds out the trio (wishlist B3). | **yes** (variant-field) | 🟢 ready |
| [`88-short-kind.md`](./88-short-kind.md) | `AnomalyKind::short_kind() -> &'static str` (wishlist B4). | no | 🟢 ready |
| [`89-force-close.md`](./89-force-close.md) | `FlowTracker::force_close` + driver mirrors + `EndReason::ForceClosed` (wishlist B5). | no (additive variant) | 🟢 ready |
| [`90-iter-active.md`](./90-iter-active.md) | `FlowTracker::iter_active() -> impl Iterator<Item = ActiveFlow<'_, K, S>>` (wishlist B7); deprecates `all_flow_stats`. | minor (deprecation) | 🟢 ready |
| [`91-multi-protocol-monitor.md`](./91-multi-protocol-monitor.md) | Multi-protocol monitor recipe + example (wishlist B2's lighter fallback). | no | 🟢 ready |

### Pending RFCs (0.9.0+)

| Plan | Goal | Status |
|------|------|--------|
| [`74-rfc-ooo-reassembly.md`](./74-rfc-ooo-reassembly.md) | RFC scope for OOO TCP reassembly with hole-fill (F2.4). | 📝 RFC only |
| [`75-rfc-tracker-auto-sweep.md`](./75-rfc-tracker-auto-sweep.md) | RFC scope for `FlowTracker::with_auto_sweep(interval)` (round-1 #2). | 📝 RFC only |
| [`81-rfc-correlate-module.md`](./81-rfc-correlate-module.md) | RFC scope for `flowscope::correlate` (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`); round-2 F6 — netring author offered to co-author. | 📝 RFC only |

Deferred from the three feedback streams (recorded so a future
ask doesn't get re-litigated):

- **#2 `FlowTracker::with_auto_sweep(interval)`** (netring round 1) —
  packet-clock auto-sweep for live/offline parity; RFC scoped in
  [`75-rfc-tracker-auto-sweep.md`](./75-rfc-tracker-auto-sweep.md);
  implementation deferred to 0.8.0+ pending reviewer agreement.
- **#10 `SessionParser::is_done()`** (netring round 1) — the
  round-1 decline (HTTP/1.0 `Connection: close` already triggers
  natural FIN-based close) is **reversed** for 0.7 per
  [`80-session-parser-is-done.md`](./80-session-parser-is-done.md);
  round-2's expanded use case (DNS-over-TCP, framed protocols)
  supplied the missing motivation.
- **F7 `DnsResolutionCache`** (netring round 2) — was deferred
  pending more usage data. Now consumed via plan 85
  ([`85-dns-resolution-cache.md`](./85-dns-resolution-cache.md))
  which ships the focused dns-side primitive; the broader
  `correlate` module (plan 81) remains on the 0.9 RFC track.
- **B2 Multi-parser composite driver** (netring round 3) — full
  driver deferred to a 0.9 RFC. The lighter doc-recipe fallback
  ships as plan 91 ([`91-multi-protocol-monitor.md`](./91-multi-protocol-monitor.md)).
- **B6 TlsHandshake aggregator** (netring round 3) — more design
  surface than the wishlist suggested (resumption / abbreviated
  handshake / failed handshake). Manual ClientHello+ServerHello
  pattern documented in SESSION_GUIDE. Revisit if a second
  consumer asks.
- **F1.4** (simple-nms) — parser `&mut S` API change addressed via
  the SESSION_GUIDE consumer-loop pattern instead of plumbing a
  generic through every parser.
- **F1.6** (simple-nms) — lazy iterator return; declined twice,
  will not reconsider without a third consumer + reproducer.
- **F2.1 / F2.2 / F2.3** (simple-nms) — built-in RTP / HTTP/2 /
  RTPS parsers; accept consumer-led upstream PRs after their
  parsers stabilise.
- **F3.1** (simple-nms) — TLS 1.3 0-RTT, small follow-up if a
  consumer asks.
- **F3.2** (simple-nms) — IP fragment reassembly, deferred
  indefinitely per `docs/ARCHITECTURE.md` known limitations.

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

Plan numbers 00–04, 12, 20, 22–25, 30–61, 62, 70–73, 76–80, 82
(everything except 21, 74, 75, 81, 83–91 — which are parked as
stale-deferred, RFC-only, or pending implementation in 0.8.0)
are retired (implementation shipped, file removed). New plans
pick the lowest free number in the appropriate range — the 0.5.0
series used 70+ to keep the active set visually distinct from the
retired numbers; the 0.7 series continued that in the 76–82
block; the 0.8 series occupies 83–91.

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
