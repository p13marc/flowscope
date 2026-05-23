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

### API ergonomics — 0.5 cycle

Driven by [`../docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
(integration feedback from netring 0.14.0). Plan-of-record at
[`../docs/0.5-PLAN-OF-RECORD.md`](../docs/0.5-PLAN-OF-RECORD.md) —
notably §3 documents the substantive disagreement with the netring
author's "lean toward option B" on plan 38.

| Plan | Goal | Breaking? | Status |
|------|------|-----------|--------|
| [`38-driver-state-restore.md`](./38-driver-state-restore.md) | Restore `S` on the drivers via split constructors (reverses plan 32 option B) | yes | ✅ Implemented (uncommitted) |
| [`39-tracker-convenience.md`](./39-tracker-convenience.md) | `FlowTracker::finish()` + `sweep_with_parsers` / `sweep_with_datagram_parsers` | no | ✅ Implemented (uncommitted) |
| [`43-anomaly-event-split.md`](./43-anomaly-event-split.md) | Split `Anomaly { key: Option<K> }` into `FlowAnomaly` + `TrackerAnomaly` on both `FlowEvent` and `SessionEvent` | yes | ✅ Implemented (uncommitted) |
| [`44-reassembler-watermark-threshold.md`](./44-reassembler-watermark-threshold.md) | `BufferedReassembler::with_high_watermark_threshold` + `AnomalyKind::ReassemblerHighWatermark` | no | ✅ Implemented (uncommitted) |
| [`50-as-packet-view.md`](./50-as-packet-view.md) | `AsPacketView` trait + blanket `From<&T>` for `PacketView` | minor | ✅ Implemented (uncommitted) |
| [`58-driver-factory-ctor.md`](./58-driver-factory-ctor.md) | `FlowSessionDriver::with_factory` / `FlowDatagramDriver::with_factory` (prereq: 38) | no | Not started |
| [`59-test-helpers-parsers.md`](./59-test-helpers-parsers.md) | `flowscope::test_helpers::{NoopSessionParser, NoopDatagramParser, EchoSessionParser}` | no | ✅ Implemented (uncommitted) |
| [`60-l7-umbrella-and-doc-note.md`](./60-l7-umbrella-and-doc-note.md) | `l7` umbrella feature; intra-doc-link recipe for re-exporters | no | ✅ Implemented (uncommitted) |
| [`61-feature-matrix-ci.md`](./61-feature-matrix-ci.md) | Partial-feature CI matrix (catches latent cfg dead-code) | no | ✅ Implemented (uncommitted) |

Deferred from the feedback:
- **#2 `FlowTracker::with_auto_sweep(interval)`** — packet-clock
  auto-sweep for live/offline parity; needs its own RFC (interaction
  with out-of-order timestamps, return-channel for implicit-sweep
  events, monotonic-timestamps prerequisite).
- **#10 `SessionParser::is_done()`** — declined pending a real
  motivating case; HTTP/1.0 `Connection: close` (the example
  use case) already triggers natural FIN-based close.

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

Plan numbers 00–04, 12, 20, 22–25, 30–37, 40–42, 45–49, 51–57
are retired (implementation shipped, file removed). New plans
pick the lowest free number in the appropriate range.

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
