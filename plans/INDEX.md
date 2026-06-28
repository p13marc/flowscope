# plans/ — backlog index

This directory holds **forward-looking work items only** —
concrete plans for features that haven't shipped yet.

Reference material that informs the plans (design rationale,
research, consumer feedback) lives in [`../docs/`](../docs/),
which is published as part of the crates.io package. The
historical record of what's shipped lives in
[`../CHANGELOG.md`](../CHANGELOG.md) and `git log`.

**Convention**: when an implementation plan ships, **delete the
plan file** in the same PR series. Cycle wishlists and
umbrellas are deleted too once the cycle releases.

---

## Active

No cycle currently in flight. The 0.14.0 cycle shipped to
crates.io on 2026-06-13 (tag `0.14.0`). Durable record in
`CHANGELOG.md` and `git log 0.13.0..0.14.0`.

Next cycle will accrue here as plans land.

### RFCs (design drafts awaiting a go/no-go)

_None active._ The driver/event convergence RFC (issue #84) shipped in
the 0.20 cycle as issues #97–#101 (`Event<K>` emit-readiness → one
builder → delete `Flow{Session,Datagram}Driver` → retire
`SessionEvent` → `SlotDrain` trait); the plan file was retired per
convention. The durable record is `CHANGELOG.md` (0.20, the
`driver-convergence N/5` entries) and `git log`. netring's
coordinated consumer migration is tracked as netring#107.

---

## Deferred items recorded so a future ask doesn't get re-litigated

Items below have been considered and explicitly left out of
the current cycle. Listed so a future consumer ask can find
the prior reasoning instead of re-litigating.

### Capability gaps without active plans

- **JA4+ family completion (JA4S / JA4H / JA4T / JA4L / JA4X /
  JA4SSH)** — JA4 family variants beyond the client TLS
  fingerprint shipped by plan 97. Ship one variant at a time
  when a consumer asks. Caveats: spec drift, `x509-parser`
  dep for cert-side variants, per-flow tracker state.
- **IPFIX / NetFlow v9 / sFlow export** — emit
  `flowscope::FlowStats` as IPFIX records. Future home:
  `flowscope-export` sister crate per `docs/design.md`.
  Caveats: `netgauze-flow-pkt` maturity + enterprise IE
  verification.
- **HTTP/2 passive parser** + Akamai fingerprint — caveats:
  `httlib-hpack` maintenance risk, per-direction dynamic-table
  cost, significant LoC. Defer until a consumer asks.
- **Passive QUIC parser** + JA4-QUIC — no Rust passive QUIC
  parser exists today (every QUIC crate is an active endpoint
  implementation). Greenfield opportunity; caveats:
  `quinn-proto` API churn, ~2 MB compiled size. Defer.

### Smaller deferred items

- **Parser `&mut S` API change** — addressed via the
  `docs/concepts.md` consumer-loop pattern instead.
- **Lazy iterator return type on parser `feed_*` / `parse`** —
  declined twice; reconsider only with a third consumer +
  reproducer.
- **Built-in RTP / RTCP / RTPS parsers** — accept consumer-led
  upstream PRs after their parsers stabilise; don't ship
  without an out-of-tree maintainer commitment.
- **TLS 1.3 0-RTT classification surface** — small follow-up
  if a consumer asks.
- **IPv4 / IPv6 fragment reassembly** — deferred indefinitely
  per `docs/concepts.md` known-limitations section.
- **`FlowTrackerConfig::with_event_filter(SUPPRESS_PACKET)`** —
  per-flow event-variant suppression at the tracker source.
  Perf-only optimisation; revisit if a profile shows
  `FlowEvent::Packet` allocation as a hot path.
- **`extract::HostPair` / `extract::AppliedFilter`** —
  additional extractor adapters. Add when a consumer asks;
  the existing `FiveTuple` / `IpPair` / `MacPair` set covers
  most cases.
- **Pageable reassembler** — writes excess to disk / a
  side-channel on `BufferedReassembler` overflow, preserving
  evidence for forensics. Niche; revisit when a forensics-
  focused consumer asks.
- **Tracker pause/resume for load-shedding** — accept packets
  without emitting events. Niche; revisit when asked.
- **`FlowExtractor::extract_batch` for SIMD-shaped parsers** —
  speculative; only matters at 40+ Gbps line rates.
- **`#[derive(SessionParser)]` macro** — wsdf-style declarative
  dissector generator. Defer to post-1.0; the trait shape
  needs to stabilise before locking a macro API.
- **Composite multi-layer fingerprint** — nDPI 5.0's FPC
  pattern. Interesting but mature/niche; defer.
- **Wirefilter expression filter** — Cloudflare's
  `wirefilter-engine` could plug in as a flow filter. Useful
  for a future CLI sister crate; defer.
- **Per-protocol DNS / TLS decoder rewrite** — bulk of the
  allocator pressure lives inside `simple-dns` /
  `tls-parser`. Defer until a consumer profiles and asks.
- **`flowscope::correlate::RollingRate::with_capacity` LRU
  bound** — current storage shape is per-time-bucket; LRU
  bounding requires ~80 LoC of cross-bucket bookkeeping.
  `evict_expired` already bounds memory to "K cardinality per
  window". Revisit if profiling shows the unbounded-K case
  hits memory.
- **`RollingRate::merge(other)` for sharded aggregation** —
  wait for `ShardedRunner::merge_state` in netring 0.22+ to
  settle first; merge contract should match.
- **`flowscope::correlate::BandwidthByApp` ready-made wrapper**
  around `RollingRate<&'static str, u64>` + `LabelTable` —
  premature; let netring 0.22's `bandwidth_by_app()` primitive
  prove the shape first.
- **`FlowTracker::with_label_table(table)`** — propagate
  `LabelTable` through the tracker. Wait for a real consumer
  ask; the `app_label_with(&table)` call-site pattern is
  workable today.

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
| 70–79 | 0.5.0 production-hardening v2 |
| 90–99 | 0.9.0 ergonomics cycle |
| 100–129 | 0.10.0 DX-polish cycle (postmortem-driven) |
| 118+ | 0.11.0 zero-allocation cycle |
| 122–146 | 0.12.0 cross-thread + structured-output cycle |
| 147–156 | 0.13.0 Send+Sync driver + canonical anomaly cycle |
| 160–174 | 0.14.0 operations-layer ergonomics cycle |
| 175+ | post-0.14 / 1.0-prep |

The next free number for a new plan is **176**.

Per the convention, plan files are deleted in the same PR
series that ships them. Cycle wishlists and umbrellas are
deleted once the cycle releases. CHANGELOG entries and
`git log` are the durable record.

---

## Plan structure for new plans

A new plan file should include:

1. **Cycle / priority / effort / status** — one-line meta
2. **Motivation** — what consumer / friction triggered this
3. **Proposed shape** — concrete API sketch
4. **Files touched** — list
5. **Tests** — coverage plan
6. **Acceptance criteria** — what passes "done"
7. **Non-goals / explicitly deferred** — close the door on
   scope creep
