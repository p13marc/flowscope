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

### 0.11.0 cycle — zero-allocation cycle

Driven by the netring 0.19 dependency audit. Consolidated to
**one umbrella + three detailed implementation plans** after a
second-pass review (the first-pass fanout of 6 plans collapsed
several items that didn't earn their separate files). Plan 117
(legacy driver deletion, was queued for next major) is
**absorbed into plan 121** since the slot refactor overlaps —
one wider migration window for consumers beats two.

Total estimated effort: **~16 working days** for the full break
in one coherent 0.11.0 release.

| Plan | Goal | Status |
|------|------|--------|
| [`118-zero-alloc-cycle.md`](./118-zero-alloc-cycle.md) | Umbrella — motivation, sequencing, Phase 0 bench gate (allocation-counting harness + baseline numbers), Phase 4 small wins (`parser_kinds::TLS_HANDSHAKE` + remove `Event::FlowPacket::frame`), Phase 5 release mechanics. | 📋 not started |
| [`119-driver-allocation-elimination.md`](./119-driver-allocation-elimination.md) | Phase 1 — `Driver::track_into`, slot trait + `FlowTracker::track_into` thread `&mut Vec<Event>`, parser methods take `&mut Vec<Self::Message>` (httparse idiom). ≤ 0.5 allocs/packet steady-state; ≤ 0.1 allocs/parser-call. | 📋 queued |
| [`120-bytes-audit-l7-types.md`](./120-bytes-audit-l7-types.md) | Phase 2 — `Vec<u8>` / `String` → `bytes::Bytes` across HTTP / DNS / TLS / ICMP parsed-message types. HTTP request parse ≤ 4 allocs (down from ~24). Serde wire format preserved via `#[serde(with = "serde_bytes")]`. | 📋 queued |
| [`121-typed-slot-drains-and-legacy-deletion.md`](./121-typed-slot-drains-and-legacy-deletion.md) | Phase 3 — typed `SlotHandle<M, K>` drain handles replace closed-`M` Driver. **Absorbs plan 117**: delete `FlowDriver` / `FlowSessionDriver` / `FlowDatagramDriver` / `FlowMultiSessionDriver` / legacy `Pipeline`; rename `driver_unified` → `driver` at crate root. 0 allocs per parsed L7 message. | 📋 queued |

Cycle theme: "ship the zero-allocation contract netring 0.19
needs, collapse the type surface to ~5 driver-shaped types."

**Consolidation decisions** (from second-pass review of the
first-draft 6-plan fanout):

- **Dropped `OutBuf<'_, M>` newtype** — used plain `&mut Vec<M>`
  on parser trait methods. Same perf, fewer concepts, matches
  `httparse` / `nom` / `quiche` ecosystem idioms.
- **Dropped `HttpMethod` enum** — `Bytes` for everything. The
  enum's only win was avoiding 1 alloc/message for known
  methods; `Bytes::from_static(b"GET")` covers that case
  without the variant complexity.
- **Dropped `seq: u64` cross-slot ordering field** — per-
  `track_into` drain provides packet-level ordering for free;
  multi-packet ordering uses the existing `Timestamp`.
- **Dropped `ConcurrentSlotHandle<M>` (Arc<Mutex>) variant** —
  single-threaded slots only; netring's channels handle cross-
  task posting.
- **Dropped compile-time typestate builder** — `SlotId<M>`
  tokens + a builder returning `SlotHandle<P::Message, K>` per
  registration call. Simpler error messages; cfg-feature-gated
  parser registration composes naturally.
- **Dropped static-dispatch slot list** — vtable cost at 5
  slots × 1 Mpps = 0.025% of a core. Not worth the typestate-
  tuple complexity.
- **Absorbed plan 117** — slot refactor in plan 121 inlines
  what `FlowSessionDriver::track_into` did, making the legacy
  types dead code. Deleting them in the same release saves a
  second migration window.

Reference documents (in repo root during the cycle, retire
with the cycle):

- [`../flowscope-deps-for-netring-0.19-2026-06-09.md`](../flowscope-deps-for-netring-0.19-2026-06-09.md)
  — original netring-side dependency audit (~9–12 day estimate).
- [`../flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`](../flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md)
  — flowscope-side counter-analysis with the 4 missing-from-
  original allocations and the alternative architectures. The
  plans above are this document operationalised + consolidated.

### 0.9.0 cycle

The 0.9 cycle is complete. Every implementation plan shipped
and every plan file is retired — the work lives in commit
history and the CHANGELOG. The umbrella audit's durable
record (38 driver constructors, two duplicated L7 API shapes,
five error enums, no high-level entry, no per-packet layered
view) is absorbed into the 0.9.0 CHANGELOG header.

### 0.10.0 cycle — substantially complete

Triggered by the 0.9 examples-writing postmortem
([`100-examples-postmortem.md`](./100-examples-postmortem.md)).
Six implementation plans (101 / 102 / 106 / 107 / 110 / 113)
have shipped and their plan files are retired per project
convention. The driver+event unification centerpiece (plan
**116**) is at PR 1-4 (partial); PR 5 (legacy-type deletion
sweep) is queued for the next major release.

| Plan | Goal | Status |
|------|------|--------|
| [`100-examples-postmortem.md`](./100-examples-postmortem.md) | Umbrella audit + cycle rationale. | doc — retires with cycle release |
| 101 (retired) | `flowscope::emit` — CSV / NDJSON / Zeek `conn.log` writers. | ✅ shipped (commit `8d91261`) |
| 102 (retired) | Utility modules — `correlate` ext + `aggregate` + `detect` + `well_known` (4 sub-PRs). | ✅ shipped (commits `c6236ce` / `829fdc7` / `9da63cb` / `6f9ef95`) |
| 106 (retired) | Parser ergonomics — `AccumulatingSessionParser` + `PerDatagramParser` + `BufferedFrameDrain`. (`FallibleSessionParser` deferred to a future cycle.) | ✅ shipped (commit `792f0f4`) |
| 107 (retired) | `HttpExchangeParser` + `DnsExchangeParser`. | ✅ shipped (commit `2277655`) |
| 110 (retired) | DX polish — rustdoc landing pages + quick-win helper sweep (2 sub-PRs). | ✅ shipped (commits `3e99ff9` / `474d09a`) |
| [`112-dynamic-lazy-analysis.md`](./112-dynamic-lazy-analysis.md) | Analysis motivating plan 113. | doc — retires with cycle release |
| 113 (retired) | `flowscope::detect::signatures` + `Routing::Heuristic` on the unified `Driver` (2 sub-PRs). | ✅ shipped (commits `a13a0a6` / `9685b59` + `ec9fa1b` PipelineBuilder proxies) |
| [`115-strategic-review.md`](./115-strategic-review.md) | Strategic review motivating plan 116. | doc — retires with cycle release |
| [`116-driver-event-unification.md`](./116-driver-event-unification.md) | `Driver<E, M>` + `Event<K, M>` — collapse the 6-driver / 4-event surface into one of each. | ✅ **PR 1-4 fully shipped including all 6 builder knobs** (commits `0b20c05` / `c74a974` / `9685b59` / `97e0852` / `743d191` / `ec9fa1b` / `5fd7a87` / `2b96103` / `720e919` / `d2ce55b`); PR 5 carved into plan 117 |
| ~~117~~ legacy driver deletion | **Absorbed into plan 121 (0.11 cycle).** The slot refactor in 121 inlines `FlowSessionDriver`'s logic directly, making the legacy types dead code. Deleting them in the same release window saves a second migration burden on consumers. | 🔀 absorbed into plan 121 |

Cycle theme: "address the next layer of DX after the 0.9
big surface choices."

Plan 116 status detail — what's in the unified Driver today:

- `Driver<E, M>` + `Event<K, M>` + `DriverBuilder<E, M>`
- `session_on_ports` / `session_broadcast` /
  `session_heuristic[_with_budget]`
- `datagram_on_ports` / `datagram_broadcast` /
  `datagram_heuristic[_with_budget]`
- `config(c)` + `monotonic_timestamps(on)`
- `flowscope::driver_unified::Pipeline<E, M>` +
  `PipelineBuilder<E, M>` with full proxies for all
  registration + knob methods
- `tracker()` / `tracker_mut()` accessors for direct
  introspection / advanced config (e.g.
  `tracker_mut().set_idle_timeout_fn(…)`)

Known follow-ups (documented in the
`flowscope::driver_unified` module rustdoc):

- `emit_anomalies(bool)` / `dedup(Dedup)` /
  `idle_timeout_fn(F)` / `emit_packet_details(bool)`
  builder knobs are not yet plumbed through the unified
  builder; design constraints around the central
  FlowTracker vs slot inner drivers are documented.
- PR 5 (legacy type deletion + full example/test migration
  sweep) — queued for the next major release. Today the
  legacy `FlowSessionDriver` / `FlowDatagramDriver` /
  `FlowMultiSessionDriver` / `flowscope::Pipeline` types
  ship alongside the unified equivalents.

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
93, 94, 96, 97, 99, 101, 102, 106, 107, 110, 113. Subsumed by
consolidation:
- 103, 104, 105 → rolled into plan 102 (utility modules)
- 111 → rolled into plan 110 (DX polish)
- 114 → rolled into plan 113 (dynamic dispatch)
- 108, 109 → rolled into plan 116 (driver+event unification)

Active: 21 (stale-deferred), 100 (postmortem doc), 112
(dynamic-lazy analysis doc), 115 (strategic review doc), 116
(driver+event unification — substantially complete; deletion
sweep absorbed into plan 121), 118 (0.11 cycle umbrella + bench
gate + small wins + release), 119 (driver allocation
elimination), 120 (Bytes audit), 121 (typed slot drains +
legacy deletion — absorbs plan 117). Subsumed:
- 117 → absorbed into 121 (legacy deletion + slot refactor
  overlap; one wider migration window beats two)
The next free number for a new plan is 122+.

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
