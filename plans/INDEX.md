# plans/ — index

Two kinds of files:

- **Design docs** (`*-design.md`) — architecture, rationale, prior-art
  surveys, decision matrices. The source of truth for *why*.
- **Implementation plans** (`NN-*.md`, numbered) — concrete,
  mechanical, file-by-file work breakdowns. The source of truth for
  *how*. Each plan should be executable: pick it up, follow it
  step-by-step, finish.

If a design doc and a plan disagree, the plan wins for execution
detail; design wins for "why is this even shaped this way."

Some plans were carried over from the previous `netring-flow` workspace
where they were originally numbered. The numbering is preserved as
historical record; new plans pick up where they left off.

---

## Design docs

| File | Status |
|------|--------|
| [`flow-session-tracking-design.md`](./flow-session-tracking-design.md) | Approved |
| [`high-level-features-design.md`](./high-level-features-design.md) | Approved |

## Numbering scheme

| Range | Theme |
|-------|-------|
| 10–19 | Capture-side features (now mostly in `netring`) |
| 20–29 | Protocol parsers and packet sources (now feature-gated modules) |
| 30–39 | Higher-level abstractions (Conversation, SessionParser) |
| 40–49 | Observability + performance |
| 50–59 | Deferred-feature catchup |
| 60–69 | Tooling (CLIs) |

---

## Foundational history (built inside the netring repo, then migrated here)

| Plan | Goal | Status |
|------|------|--------|
| [`00-workspace-split.md`](./00-workspace-split.md) | original split of flow types out of netring's main crate | ✅ done (superseded by single-crate consolidation) |
| [`01-flow-extractor.md`](./01-flow-extractor.md) | `FlowExtractor` trait + built-in extractors + decap combinators | ✅ done |
| [`02-flow-tracker.md`](./02-flow-tracker.md) | `FlowTracker` + TCP state machine + idle/eviction | ✅ done |
| [`03-flow-reassembler.md`](./03-flow-reassembler.md) | `Reassembler` trait + `BufferedReassembler` + sync `FlowDriver` | ✅ done |
| [`04-flow-release.md`](./04-flow-release.md) | netring-flow 0.1.0 release prep | ✅ done (rolled into flowscope 0.1.0) |
| [`12-test-infra.md`](./12-test-infra.md) | pcap fixtures, `proptest`, `cargo-fuzz` harness | ✅ done |

## Status snapshot — current

| Plan | Goal | Status |
|------|------|--------|
| [`20-flow-pcap.md`](./20-flow-pcap.md) | pcap source — now `pcap` feature module | ✅ done |
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `protolens` bridge as a feature module / sub-crate | not started |
| [`22-flow-http.md`](./22-flow-http.md) | HTTP/1.x — now `http` feature module | ✅ done |
| [`23-flow-tls.md`](./23-flow-tls.md) | TLS observer — now `tls` feature module | ✅ done (JA3; JA4 deferred) |
| [`24-flow-dns.md`](./24-flow-dns.md) | DNS-over-UDP — now `dns` feature module | ✅ done (UDP/53 only) |
| [`30-conversation.md`](./30-conversation.md) | `Conversation<K>` aggregate | ✅ done (lives in `netring`) |
| [`31-session-parser.md`](./31-session-parser.md) | `SessionParser` / `DatagramParser` traits + Stream impls + parser bridges + proptests | ✅ phases 1+2+3a done (HTTP, TLS, DNS-UDP, DNS-TCP shipped, 11 splitting-invariance & no-panic proptests). Migration guide (`docs/SESSION_GUIDE.md`) deferred until 1.0 polish. |
| [`32-flow-export.md`](./32-flow-export.md) | NetFlow/IPFIX export via `netgauze-flow-pkt` | not started |
| [`40-observability.md`](./40-observability.md) | `metrics` + `tracing` integration | not started |
| [`41-perf-foundations.md`](./41-perf-foundations.md) | Zero-copy reassembly, LRU hot-cache | not started |
| [`50-deferred-catchup.md`](./50-deferred-catchup.md) | InnerGre, FlowLabel, AutoDetectEncap, IPv6 frags, etc. | not started |
| [`60-cli-tools.md`](./60-cli-tools.md) | `flow-replay` / `flow-summary` CLI binaries | not started |

---

## Conventions

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

Plan files are living documents: update Status as you go. When a
phase ships, the plan stays in `plans/` as a record — don't delete.
