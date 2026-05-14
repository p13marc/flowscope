# plans/ — index

Two kinds of files live here:

- **Design / research docs** (`*-design.md`, `DPI_ARCHITECTURE.md`,
  feedback reports). Architecture rationale, prior-art surveys,
  consumer feedback. Source of truth for *why*.
- **Backlog plans** (`NN-*.md`, numbered). Each plan is concrete
  and executable — pick it up, follow it step-by-step, finish.

Plans whose implementation has shipped are **deleted** rather
than archived in-place. `git log` is the historical record;
`plans/` is the active backlog. (Previous convention was to
keep shipped plans as records; we changed to deletion when the
directory got crowded enough that it stopped being a useful
working backlog.)

---

## Design / research docs

| File | What |
|------|------|
| [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) | Original design for the flow / session tracking surface. Approved; mostly implemented. Useful for the *why* behind the trait shapes. |
| [`high-level-features-design.md`](./high-level-features-design.md) | High-level features survey (loopback dedup, etc.). Drove the `Dedup` primitive shape. |
| [`DPI_ARCHITECTURE.md`](./DPI_ARCHITECTURE.md) | SOTA-DPI research and crate-split recommendations report (2026). |
| [`flowscope-feedback-2026-05-14.md`](./flowscope-feedback-2026-05-14.md) | External feedback from the `des-rs` team. Drove the 0.3.0 "production hardening" release. Worth re-reading when the next consumer-feedback cycle starts. |

## Backlog — sister-crate roadmap

These three plans describe artifacts that should ship as separate
sister crates (`flowscope-protolens`, `flowscope-export`,
`flowscope-cli`) per [`DPI_ARCHITECTURE.md`](./DPI_ARCHITECTURE.md).
All carry STALE headers — they were drafted pre-consolidation
(when flowscope was a workspace of `netring-flow*` crates) and
need a rewrite pass before execution. Pick up only when a real
consumer asks.

| Plan | Goal | Status |
|------|------|--------|
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `flowscope-protolens` — protolens bridge as a sister crate | 🛑 stale, deferred |
| [`32-flow-export.md`](./32-flow-export.md) | `flowscope-export` — NetFlow v9 / IPFIX exporter | 🛑 stale, deferred |
| [`60-cli-tools.md`](./60-cli-tools.md) | `flowscope-cli` — `flow-summary` + `flow-replay` binaries | 🛑 stale, deferred |

## Backlog — deferred features

| Plan | Goal | Status |
|------|------|--------|
| [`50-deferred-catchup.md`](./50-deferred-catchup.md) | Omnibus of catchup features. 50.1 InnerGre / 50.2 FlowLabel / 50.3 AutoDetectEncap / 50.4 manual_tick / 50.6 broadcast all ✅ shipped. **50.5 IPv6 fragment reassembly** remains deferred indefinitely (no consumer demand yet). |

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

Plan numbers 00–04, 12, 22–25, 30–31, 40–42, 45–49, 51–57 are
all retired (implementation shipped); new plans pick the lowest
free number in the appropriate range.

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

Update Status as you go. When a plan ships and goes to git
history, delete the file in the same PR series that lands the
implementation (or in a follow-up cleanup commit).
