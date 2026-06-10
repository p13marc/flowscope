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

### 0.12.0 cycle — Send slot handles + EVE + ergonomics

All 5 implementation plans (122 / 123 / 124 / 126 / 127) plus
Phase 7 small wins shipped to master. Awaiting Phase 8 release
(per-release consent required before `cargo publish`).

| Plan | Status |
|------|--------|
| 127 — `Timestamp` ISO 8601 + chrono interop | ✅ shipped (`781595f`) |
| 126 — `AnomalyFields` trait + impls | ✅ shipped (`c7d8e18`) |
| 122 — `SlotHandle: Send + Sync` (Arc<SegQueue>) | ✅ shipped (`44e68e8`) — pre-1.0 break |
| 124 — `DeferredDriverBuilder<E>` | ✅ shipped (`3723b6a`) |
| 123 — `EveJsonWriter` (Suricata EVE) | ✅ shipped (`99be89d`) |
| 128 §Phase 7 — `correlate::*::new_unbounded` ctors | ✅ shipped |
| 128 §Phase 8 — release mechanics | pending consent |

Cycle theme: "add the Send-by-default slot handle,
Suricata-compatible EVE emit, and the AnomalyFields /
Timestamp / correlate ergonomics that retire netring's
duplicated upstream code."

**Second-pass consolidation decisions** (vs the first draft):

- **Plan 122 consolidated**: wishlist + first draft proposed
  a feature-gated `mt` flag + parallel `MtSlotHandle` +
  `MtDriverBuilder` types. Collapsed to a single always-Send
  `SlotHandle` via `Arc<SegQueue>`. Per-emit cost (~5–10 ns
  extra) is negligible at netring's rates (~0.05% of a core
  at 1 Mpps × 10% L7); the simplification (~400 fewer LoC,
  no feature flag, no parallel builder) is significant. **Pre-1.0
  break**: `SlotHandle: !Send` → `SlotHandle: Send + Sync`.
- **Plan 125 absorbed**: 3 trivial `correlate::*::new_unbounded`
  delegates (5 LoC each) don't earn a separate plan file.
  Folded into plan 128's Phase 7 small-wins section.

**My-analysis corrections** to the wishlist (full list in
`plans/128-cycle-0-12.md` §Provenance):

- **Plan 124**: wishlist proposed `Driver::deferred()` whose
  `build()` panics if no extractor was set — sharpened to a
  distinct `DeferredDriverBuilder<E>` type that only exposes
  `build_with(ext)`. Compile-time guarantee preserved.
- **Plan 126**: wishlist's `AnomalyKind` mapping referenced
  variants that don't exist in shipped flowscope. Corrected
  to the 6 actual variants (`BufferOverflow`,
  `OutOfOrderSegment`, `FlowTableEvictionPressure`,
  `SessionParseError`, `RetransmittedSegment`,
  `ReassemblerHighWatermark`).
- **Plan 127**: wishlist's "½ day" estimate undercounts the
  date algorithm + cross-check tests. Realistic: ~1 day.

Reference document (in repo root during the cycle, retires
with the cycle):

- [`../flowscope-0.12-wishlist.md`](../flowscope-0.12-wishlist.md)
  — netring 0.21's distilled ask list. The plans above are
  this document operationalised + consolidated.

### Stale / deferred

| Plan | Goal | Status |
|------|------|--------|
| [`21-flow-protolens.md`](./21-flow-protolens.md) | `flowscope-protolens` — protolens bridge as a sister crate | 🛑 stale, deferred (no consumer ask) |

---

## Recently shipped

### 0.11.0 cycle — zero-allocation cycle (2026-06)

Shipped to crates.io as `flowscope 0.11.0` (tag `0.11.0`). The
plan files are retired per convention; durable record is in
`CHANGELOG.md`, `docs/migration-0.10-to-0.11.md`, and the
commit history (`git log 0.10.1..0.11.0`).

Highlights:

- **Plan 118** — umbrella + Phase 0 bench gate
  (`benches/zero_alloc.rs` + `benches/support/counting_allocator.rs`)
  + Phase 4 small wins (`parser_kinds::TLS_HANDSHAKE` + dropped
  `Event::FlowPacket::frame`) + Phase 5 release mechanics.
- **Plan 119** — `Driver::track_into` + `SessionParser` /
  `DatagramParser` API break (`&mut Vec<Self::Message>` sink,
  `httparse`-style). `Driver::track_into` with 5 HTTP slots:
  **0.000 allocs/packet** in steady state.
- **Plan 120** — HTTP / DNS / TLS payload-type Bytes audit.
  HTTP/1.1 GET parse: **28 → 7 allocs** (zero-copy `Bytes::slice`
  over one Arc-backed header arena).
- **Plan 121** — typed `Driver<E>` + `SlotHandle<M, K>` drain
  handles replace closed-`M` `Driver<E, M>` + lift closures.
  Deletes `FlowMultiSessionDriver`, legacy `Pipeline`, legacy
  builders. `flowscope::driver_unified` renamed to
  `flowscope::driver` at the crate root.

Deviations from the plan files worth noting (now durable
record):

- **`FlowDriver` / `FlowSessionDriver` / `FlowDatagramDriver`
  kept public** as raw sync primitives (plan 121 spec'd
  deleting them; doing so cleanly would have required inlining
  their logic into the typed `Driver`'s slot impls — substantial
  extra work for marginal API-surface benefit). The 0.9-era
  `FlowMultiSessionDriver` / `FlowSessionDriverBuilder` /
  `FlowDatagramDriverBuilder` / top-level `Pipeline` are gone.
- **`OutBuf<'_, M>` newtype dropped** in favour of plain
  `&mut Vec<Self::Message>` — same idiom as `httparse`, simpler
  API.
- **`HttpMethod` enum dropped** in favour of `Bytes` everywhere
  — interned `Bytes::from_static(b"GET")` covers the zero-alloc
  case for the 8 standard methods without an enum.
- **`seq: u64` cross-slot ordering field dropped** — per-
  `track_into` drain provides packet-level ordering; longer
  spans use the existing `Timestamp`.
- **Typestate-tuple builder dropped** — simple `&mut self`
  builder returning `SlotHandle<P::Message, E::Key>` per
  registration call. Far friendlier error messages; composes
  with cfg-feature-gated parser registration.
- **Plan 117 absorbed** — the legacy deletion sweep originally
  queued for a separate next-major release was rolled into
  plan 121 to avoid asking consumers to migrate twice.

### 0.10.0 cycle — DX polish (2026-06)

Triggered by the 0.9 examples-writing postmortem. Plans 101 /
102 / 106 / 107 / 110 / 113 / 116 (PR 1-4) all shipped in 0.10.
Plan 117 (legacy deletion sweep, originally PR 5 of 116)
absorbed into plan 121 and shipped in 0.11. Plan files retired
per convention.

### 0.9.0 cycle — ergonomics + breaks

Every implementation plan shipped; every plan file retired. The
umbrella audit's durable record (38 driver constructors, two
duplicated L7 API shapes, five error enums, no high-level
entry, no per-packet layered view) is absorbed into the 0.9.0
CHANGELOG header.

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
- **Per-protocol DNS / TLS decoder rewrite** — at 0.11.0 the
  DNS / TLS bench rows didn't move (28 / 14 allocs/parse)
  because the bulk of the allocator pressure lives inside
  `simple-dns` / `tls-parser`. Custom decoders or pre-parse
  `Bytes` slicing would land more allocations. Defer until a
  consumer profiles and asks.
- **Per-slot `Arc<Mutex<…>>` slot bufs (Send slot handles)** —
  the typed `SlotHandle<M, K>` is `Rc<RefCell>`-backed and
  intentionally `!Send`. Cross-task delivery is netring's job
  (drain inside the event loop, post over channels). Revisit
  if a consumer needs a Send variant.

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
| 118+ | 0.11.0 zero-allocation cycle (netring 0.19 driven) |

Plan numbers retired (implementation shipped, file removed):
00–04, 12, 20, 22–25, 30–61, 62, 70–73, 74, 75, 76–82, 83–91,
93, 94, 96, 97, 99, 100, 101, 102, 106, 107, 110, 112, 113,
115, 116, 118, 119, 120, 121. Subsumed by consolidation:
- 103, 104, 105 → rolled into plan 102 (utility modules)
- 111 → rolled into plan 110 (DX polish)
- 114 → rolled into plan 113 (dynamic dispatch)
- 108, 109 → rolled into plan 116 (driver+event unification)
- 117 → absorbed into 121 (legacy deletion + slot refactor
  overlap; one wider migration window beats two)

Active: 21 (stale-deferred), 128 (0.12 cycle umbrella, kept
until Phase 8 release ships). Implementation plans 122, 123,
124, 126, 127 shipped to master; their plan files retired
per convention. Subsumed by consolidation:
- 125 → folded into 128 §Phase 7 (3 trivial `correlate::*::new_unbounded`
  delegates don't earn a separate file)
The next free number for a new plan is 129+.

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
