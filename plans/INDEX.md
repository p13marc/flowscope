# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`, `DPI_ARCHITECTURE.md`) —
  architecture, rationale, prior-art surveys, decision matrices.
  Source of truth for *why*.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns. Source of truth for
  *how*. Each plan should be executable: pick it up, follow it
  step-by-step, finish.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

Some plans were carried over from the previous `netring-flow`
workspace where they were originally numbered. The numbering is
preserved as historical record; new plans pick up where they left
off. Plans flagged **STALE** below were written pre-consolidation
and need a rewrite pass before execution.

---

## Design docs

| File | Status |
|------|--------|
| [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) | Approved |
| [`high-level-features-design.md`](./high-level-features-design.md) | Approved |
| [`DPI_ARCHITECTURE.md`](./DPI_ARCHITECTURE.md) | Research report |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (now mostly in `netring`) |
| 20–29 | Protocol parsers and packet sources (feature-gated modules) |
| 30–39 | Higher-level abstractions (Conversation, SessionParser) |
| 40–49 | Observability + performance |
| 50–59 | Deferred-feature catchup |
| 60–69 | Tooling (CLIs) |

---

## Foundational history (built inside the netring repo, then migrated here)

| Plan | Goal | Status |
|------|------|--------|
| [`00-workspace-split.md`](./00-workspace-split.md) | Original split of flow types out of netring's main crate | ✅ done (superseded by single-crate consolidation) |
| [`01-flow-extractor.md`](./01-flow-extractor.md) | `FlowExtractor` trait + built-in extractors + decap combinators | ✅ done |
| [`02-flow-tracker.md`](./02-flow-tracker.md) | `FlowTracker` + TCP state machine + idle/eviction | ✅ done |
| [`03-flow-reassembler.md`](./03-flow-reassembler.md) | `Reassembler` trait + `BufferedReassembler` + sync `FlowDriver` | ✅ done |
| [`04-flow-release.md`](./04-flow-release.md) | netring-flow 0.1.0 release prep | ✅ done (rolled into flowscope 0.1.0) |
| [`12-test-infra.md`](./12-test-infra.md) | pcap fixtures, `proptest`, `cargo-fuzz` harness | ✅ done |

## Status snapshot — current

### Active / next-up

| Plan | Goal | Status |
|------|------|--------|
| [`25-binary-protocol-example.md`](./25-binary-protocol-example.md) | `FlowSessionDriver` + length-prefixed binary protocol example | not started — ready to execute |
| [`42-reassembly-observability.md`](./42-reassembly-observability.md) | Buffer cap + `OverflowPolicy` + `FlowStats` diagnostics + `FlowEvent::Anomaly` (0.2.0 bundle) | not started — primary candidate for next minor |
| [`40-observability.md`](./40-observability.md) | `metrics` + `tracing` integration | not started — coordinates with Plan 42 vocabulary |
| [`41-perf-foundations.md`](./41-perf-foundations.md) | Hot-cache fast-path in `FlowTracker` | not started — small, mechanical, no API impact |

### Already shipped (kept as record)

| Plan | Goal | Status |
|------|------|--------|
| [`20-flow-pcap.md`](./20-flow-pcap.md) | pcap source — now `pcap` feature module | ✅ done |
| [`22-flow-http.md`](./22-flow-http.md) | HTTP/1.x — now `http` feature module | ✅ done |
| [`23-flow-tls.md`](./23-flow-tls.md) | TLS observer — now `tls` feature module | ✅ done (JA3; JA4 deferred) |
| [`24-flow-dns.md`](./24-flow-dns.md) | DNS-over-UDP — now `dns` feature module | ✅ done (UDP/53 + DNS-over-TCP) |
| [`30-conversation.md`](./30-conversation.md) | `Conversation<K>` aggregate | ✅ done (lives in `netring`) |
| [`31-session-parser.md`](./31-session-parser.md) | `SessionParser` / `DatagramParser` traits + Stream impls + parser bridges + proptests + migration guide | ✅ done (4 parsers across both trait shapes, 11 proptests, [SESSION_GUIDE.md](../docs/SESSION_GUIDE.md)) |
| [`50-deferred-catchup.md`](./50-deferred-catchup.md) | InnerGre, FlowLabel, AutoDetectEncap, IPv6 frags, etc. | 🚧 50.1, 50.2, 50.3, 50.4 ✅; 50.6 ✅ (lives in netring); 50.5 IPv6 frag reassembly deferred |

### Sister-crate roadmap (pre-consolidation drafts — STALE)

These describe artifacts that should ship as separate sister crates
(`flowscope-protolens`, `flowscope-export`, `flowscope-cli`) per the
`DPI_ARCHITECTURE.md` recommendation. The drafts predate the single-
crate consolidation; each carries a STALE header listing what needs
to change before execution. Pick up only when a real consumer asks.

| Plan | Goal | Status |
|------|------|--------|
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `flowscope-protolens` — protolens bridge as a sister crate | 🛑 stale, deferred |
| [`32-flow-export.md`](./32-flow-export.md) | `flowscope-export` — NetFlow v9 / IPFIX exporter | 🛑 stale, deferred |
| [`60-cli-tools.md`](./60-cli-tools.md) | `flowscope-cli` — `flow-summary` + `flow-replay` binaries | 🛑 stale, deferred |

---

## Project conventions

These conventions are enforced for every plan in this directory.
Listed once here so individual plans can refer back instead of
re-litigating.

### `#[non_exhaustive]` on every public struct/enum

All public structs and `non-trivial` enums in flowscope's API ship
with `#[non_exhaustive]`. This is a one-time minor break that lands
with Plan 42 (0.2.0); thereafter every additive field/variant is
unconditionally non-breaking. Construct via `::default()` and
mutate; do not rely on struct-literal construction from outside the
crate.

### Trait-method overrides for diagnostics

When a trait grows a diagnostic method (e.g.
`Reassembler::dropped_segments`), it ships with a default-zero
implementation so existing third-party impls don't break. Document
the contract: a default-zero return means "this implementation
doesn't track that counter," not "the counter is zero."

### Single vocabulary across event stream and metrics

The `AnomalyKind` enum (Plan 42) is the single source of truth for
both the `FlowEvent::Anomaly` variant and the
`flowscope_anomalies_total` metric labels (Plan 40). Adding a new
variant requires adding the corresponding label arm in the same
PR; a `#[non_exhaustive]` reminder test catches drift.

### Sync vs async parity

flowscope is runtime-free. Every async helper in netring
(`flow_stream`, `session_stream`, `datagram_stream`) has a sync
mirror in flowscope (`FlowDriver`, `FlowSessionDriver`, eventually
`FlowDatagramDriver`). The async path is the ergonomic one; the
sync path is what offline pcap consumers and embedded users get.

### No `tokio` in flowscope's deps

Hard rule (also stated in CLAUDE.md). Async lives in netring, which
depends on flowscope. PRs adding tokio to flowscope are
wrong-shaped.

---

## Plan structure conventions

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
12. **Provenance** (when applicable) — what this plan supersedes
    or what historical context shaped it

Plan files are living documents: update Status as you go. When a
phase ships, the plan stays in `plans/` as a record — don't delete.
When a plan is superseded by a consolidation, the new plan documents
the supersession in its **Provenance** section.
