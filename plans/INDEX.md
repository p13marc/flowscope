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

The 30–39 API-ergonomics series (plans 32–37) has shipped; the audit
that drove it is kept at
[`../docs/API-ERGONOMICS-REVIEW.md`](../docs/API-ERGONOMICS-REVIEW.md).

### Targeted for 0.5.0 (driven by simple-nms wishlist)

Five sub-plans address the actionable items in the
[simple-nms upstream wishlist](../docs/feedback-2026-08-11-simple-nms.md).
The wishlist's full analysis (what we're shipping vs declining
vs deferring vs RFC'ing) is documented per-plan in the
"Provenance" sections.

| Plan | Goal | Status |
|------|------|--------|
| [`70-tcp-rich-diagnostics.md`](./70-tcp-rich-diagnostics.md) | `TcpInfo.window` + `Reassembler::segment(ts)` + retransmit classification (F1.1 + F1.2 + F1.3 bundled) | 📋 ready to start |
| [`71-periodic-flow-tick.md`](./71-periodic-flow-tick.md) | Opt-in `FlowEvent::Tick` + `SessionEvent::FlowTick` per interval (F1.5; two-consumer signal — also from des-rs feedback) | 📋 ready to start |
| [`72-parser-kind-identity.md`](./72-parser-kind-identity.md) | `SessionParser::parser_kind()` + field on `SessionEvent::Application` (F1.7) | 📋 ready to start |
| [`73-rich-state-pattern-guide.md`](./73-rich-state-pattern-guide.md) | SESSION_GUIDE walkthrough for the consumer-loop pattern that addresses F1.4 without an API change | 📋 ready to start (doc-only) |
| [`74-rfc-ooo-reassembly.md`](./74-rfc-ooo-reassembly.md) | RFC scope for OOO TCP reassembly with hole-fill (F2.4). Implementation deferred to 0.6.0+. | 📝 RFC only — invites consumer + maintainer agreement before implementation |

**0.5.0 effort**: ~5 days for plans 70–73 plus RFC iteration
for plan 74.

**Wishlist items declined / deferred** (rationale lives in
each plan's "Out of scope" and the wishlist response thread):
F1.4 (parser `&mut S` API change — addressed via doc pattern
in plan 73), F1.6 (lazy iterator return — declined twice;
will not reconsider without a third consumer + reproducer),
F2.1 / F2.2 / F2.3 (built-in RTP / HTTP/2 / RTPS parsers —
accept consumer-led upstream PRs after their parsers
stabilise), F3.1 (TLS 1.3 0-RTT — small follow-up if a
consumer asks), F3.2 (IP fragment reassembly — deferred
indefinitely per `docs/ARCHITECTURE.md` known limitations).

### Sister-crate roadmap

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

Plan numbers 00–04, 12, 20, 22–25, 30–37, 40–42, 45–49, 51–57
are retired (implementation shipped, file removed). New plans
pick the lowest free number in the appropriate range — the
0.5.0 series uses 70+ to keep the active set visually distinct
from the retired numbers.

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
the `FlowEvent::Anomaly` variant and the
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
