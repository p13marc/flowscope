# Plan 118 — 0.11.0 zero-allocation cycle (umbrella)

## Summary

Flowscope 0.11.0 — the **zero-allocation cycle**. Triggered by the
netring 0.19 dependency audit
([`../flowscope-deps-for-netring-0.19-2026-06-09.md`](../flowscope-deps-for-netring-0.19-2026-06-09.md))
and the reanalysis report
([`../flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`](../flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md)).
**One coherent breaking release** that:

1. Eliminates per-packet and per-message allocations from the
   `Driver` dispatch path.
2. Migrates every L7 parsed-message type from owned `Vec<u8>` /
   `String` to `bytes::Bytes`.
3. Replaces the closed-`M` sum-type `Driver<E, M>` with typed
   slot drain handles — netring's `Erased = Box<dyn Any>`
   workaround disappears.
4. Deletes the 0.9-era legacy types (`FlowDriver`,
   `FlowSessionDriver`, `FlowDatagramDriver`,
   `FlowMultiSessionDriver`, legacy `Pipeline`) — absorbs plan
   117 in the same release window since the refactors overlap.

Three detailed plans land in sequence:

- [Plan 119](./119-driver-allocation-elimination.md) — drive the
  allocation count to zero through `track_into` + slot threading
  + parser API break.
- [Plan 120](./120-bytes-audit-l7-types.md) — Bytes across every
  L7 type.
- [Plan 121](./121-typed-slot-drains-and-legacy-deletion.md) —
  typed slot drain handles + delete legacy drivers.

This umbrella owns Phase 0 (bench gate), Phase 4 (small wins:
`parser_kinds::TLS_HANDSHAKE` const + remove
`Event::FlowPacket::frame`), and Phase 5 (release mechanics).

## Status

Phase 0 not started. Plans 119 / 120 / 121 queued.

## Prerequisites

- Plan 116 substantially complete (✅ shipped in 0.10).
- 0.10.1 published (✅ done).

## Out of scope

- **No new functionality.** Every gram of effort goes toward
  perf, allocation, API shape, or surface deletion.
- **No `async fn` on parser methods.** Sync stays.
- **No SIMD / batch-extract APIs.** Stays deferred per
  `INDEX.md`.
- **No bumpalo-style arena lifetimes.** Considered in the
  reanalysis report as "Alternative C"; rejected — burdens
  consumers with lifetime threading for marginal extra win past
  what plan 121 delivers.
- **No macro-driven sum-type generation.** Reanalysis
  "Alternative B" was a fallback. Plan 121's typed slot drains
  win, no macro needed.

## The phases

| # | Owner | Scope |
|---|-------|-------|
| 0 | 118 (this) | Allocation-counting bench harness; baseline numbers; gate criteria for every subsequent phase |
| 1 | 119 | `Driver::track_into` + slot trait takes `&mut Vec<Event>` + parser methods take `&mut Vec<Self::Message>`. Every `.collect()` on the dispatch path is gone. |
| 2 | 120 | Owned `Vec<u8>` / `String` across HTTP / DNS / TLS / ICMP parsed-message types → `bytes::Bytes`. |
| 3 | 121 | Typed `SlotHandle<M>` drain handles. The `Erased` workaround disappears. Legacy `FlowSessionDriver` / `FlowDatagramDriver` / `FlowMultiSessionDriver` / legacy `Pipeline` deleted (plan 117 absorbed). |
| 4 | 118 (this) | Small wins: `parser_kinds::TLS_HANDSHAKE` const; remove `Event::FlowPacket::frame` (the 1.5 GB/sec frame-copy cliff). |
| 5 | 118 (this) | Migration guide, CHANGELOG, version bump 0.10.1 → 0.11.0, publish, tag. |

Phase 0 (bench gate) and Phase 4 (small wins) are owned here
because they're each ≤ 1 day of work — not enough to warrant
their own files. Phases 1–3 are each substantial enough to
warrant detailed plans.

## Phase 0 — Bench gate

Every subsequent phase is measured against a baseline captured
in Phase 0. Without this gate, perf claims are hand-arithmetic.

### Files

- `benches/zero_alloc.rs` — new criterion bench file.
- `benches/support/counting_allocator.rs` — new test-only
  `CountingAllocator` global-allocator wrapper. Tracks
  allocation count + bytes since last reset.
- `Cargo.toml` — `[[bench]] name = "zero_alloc"` entry.
- This plan file — Baseline numbers section gets filled in
  during Phase 0 implementation.

### Measurements

1. **`Driver::track_into` steady-state** — 5 registered slots,
   no L7 traffic, 100k packets. Target after Phase 1: ≤ 0.5
   allocs/packet.
2. **Parser `feed_*` steady-state** — repeated calls against a
   100-message HTTP stream. Target after Phase 1: ≤ 0.1
   allocs/call once buffer capacity warms up.
3. **Per-protocol parse cost** — single HTTP/1.1 GET, single
   DNS A query, single TLS 1.3 client-hello, single ICMPv4
   echo. Targets after Phase 2:
   - HTTP: ≤ 4 allocs (baseline ~24).
   - DNS w/ 5 TXT records: ≤ 6 allocs (baseline ~10).
   - TLS client-hello: ≤ 2 allocs.
4. **Per-parsed-message dispatch** — 1 Mpps mixed HTTP + DNS
   traffic with two slots. Target after Phase 3: 0 allocs per
   parsed L7 message in steady state.
5. **`emit_packet_details(true)` mode** — 1 Mpps with packet
   detail enrichment. Target after Phase 4: ≤ 1 alloc/packet
   (baseline: ~1500 bytes of frame-copy/packet).

### Counting allocator sketch

```rust
// benches/support/counting_allocator.rs
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES:  AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(l.size(), Relaxed);
        System.alloc(l)
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) { System.dealloc(p, l) }
}

impl CountingAllocator {
    pub fn reset() { ALLOCS.store(0, Relaxed); BYTES.store(0, Relaxed); }
    pub fn allocs() -> usize { ALLOCS.load(Relaxed) }
    pub fn bytes() -> usize { BYTES.load(Relaxed) }
}

// benches/zero_alloc.rs
#[global_allocator]
static GLOBAL: CountingAllocator = CountingAllocator;
```

### Baseline numbers (0.10.1, captured Phase 0)

Numbers are **allocations / iteration**, measured by the
`CountingAllocator` over an outside-of-Criterion 1k–10k loop on
a release build. Wall-clock from Criterion shown for context.

| Measurement | 0.10.1 baseline | Target | After Phase 1 | After Phase 2 | After Phase 3 | After Phase 4 |
|-------------|----|--------|----|----|----|----|
| `Driver::track_into` steady-state, 0 slots | **1.000** allocs/pkt, 864 B/pkt | ≤ 0.5 | **0.000** allocs/pkt ✅ | 0.000 ✅ | — | — |
| Parser `feed_initiator` steady-state (HTTP) | **13.000** allocs/call, 4868 B/call | ≤ 0.1 | **12.000** allocs/call¹ | **5.000** allocs/call (-62%) | — | — |
| HTTP/1.1 GET parse, fresh parser, 10 headers | **28.000** allocs, 21995 B | ≤ 4 | 28.000² | **7.000** allocs, 5906 B (-75%) | — | — |
| DNS response w/ 5 TXT records | **28.000** allocs, 2384 B | ≤ 6 | 28.000² | 28.000³ | — | — |
| TLS 1.3 ClientHello | **13.000** allocs, 9168 B | ≤ 2 | 13.000² | 14.000³ | — | — |
| Per parsed-L7 dispatch (slot-routed) | (needs slot wiring) | 0 | — | — | — | — |
| `emit_packet_details(true)` mode — frame field removed | ≥ 1 alloc + 1500 B copy | ≤ 1 | — | — | — | **field removed** ✅ |

**Phase 4 delivered (small wins):**

- ✅ `parser_kinds::TLS_HANDSHAKE` constant — consumers can now
  use the stable constant instead of the magic string
  `"tls-handshake"`.
- ✅ `Event::FlowPacket::frame` field removed. Previously, every
  packet under `emit_packet_details(true)` carried an
  `Option<Vec<u8>>` populated by `view.frame.to_vec()` — a full
  64–1500 byte memcpy per packet at ~1.5 GB/sec at 1 Mpps.
  Consumers that need the frame bytes hold onto the source
  `PacketView` they handed to `track_into`.

³ DNS and TLS bench numbers don't move from Phase 2's type changes
alone — the bulk of their allocator pressure lives inside the
parser crates (`simple-dns` and `tls-parser`), which allocate
during the wire-format decode regardless of the public-type
storage. Eliminating those would require either a custom DNS /
TLS decoder or pre-parse `Bytes` slicing — out of plan 120's
documented scope (the plan explicitly carves out DNS
owner-names due to compressed-label complexity). HTTP, where we
control the decoder via httparse + our own snapshot pass, hits
hardest.

¹ The per-call `Vec` return is gone (down 1 alloc); the remaining 12 are the parser's internal allocations for the parsed-message payload (`method`/`path`/`headers` as `String`/`Vec<u8>`). Plan 120 (Bytes audit) addresses these.

² Per-protocol parse cost is unaffected by plan 119 — these rows measure the per-message-payload allocator pressure. Plan 120 lands the per-protocol gate hits.

**Phase 1 delivered:**

- ✅ `Driver::track_into` surface is fully zero-allocation (down from 1 alloc/packet to 0).
- ✅ `SessionParser` + `DatagramParser` API break landed (`&mut Vec<Message>` shape on `feed_initiator` / `feed_responder` / `fin_initiator` / `fin_responder` / `on_tick` / `parse`).
- ✅ Slot trait + every slot impl threaded `&mut Vec<Event>` through dispatch.
- ✅ All 5 shipped parsers migrated (HTTP, TLS, DnsUdp, DnsTcp, Icmp).
- ✅ All parser helpers migrated (`BufferedFrameDrain`, `AccumulatingSessionParser`, `PerDatagramParser`).
- ✅ All in-source test parsers migrated.
- ✅ All integration tests migrated.
- ✅ All examples migrated.
- ✅ All doctests pass.
- ✅ ~430 tests pass, 0 failures.

**Observations from the baseline data:**

1. **DNS parse is 28 allocs, not the ~10 the reanalysis
   estimated.** simple-dns is allocating much more aggressively
   than expected. Plan 120's gain on DNS will be larger than
   forecast.
2. **TLS ClientHello is 13 allocs (9 KB), not ~3.** TLS parser
   buffers the entire record at ingestion and the
   `tls-parser` crate allocates per-extension.
3. **Empty-Driver track is 1 alloc/packet, 864 B/packet.** Even
   with no slots registered, the central tracker returns a
   `Vec<FlowEvent<K>>` per call — exactly what plan 119's
   `track_into` eliminates.
4. **HTTP parse 28 allocs matches the audit's ~24 estimate
   closely.** The audit was directionally right for HTTP but
   under for DNS / TLS.

The "5 slots" version of `track_steady_state` (the actual gate
row for plan 119) requires `SessionParser` impls to register;
Phase 0 leaves it as a TODO and plan 119 wires it in alongside
its other changes. The 0-slot baseline above is the
lower-bound: with slots, each adds `Box<dyn DriverSlot>`
indirection plus internal `Vec` allocs.

### Phase 0 effort

~1 working day:
- 0.3d counting allocator + reset/get API + sanity test.
- 0.4d the 5 bench routines, each isolated, each emitting per-
  iter alloc count via `println!` outside Criterion.
- 0.3d baseline numbers captured + committed to this file.

## Phase 4 — Small wins

Two items that don't belong to plans 119–121:

### `parser_kinds::TLS_HANDSHAKE`

```rust
// src/tls/handshake.rs
pub const PARSER_KIND: &str = "tls-handshake";

// src/lib.rs (existing parser_kinds module)
#[cfg(feature = "tls")] pub use crate::tls::handshake::PARSER_KIND as TLS_HANDSHAKE;
```

5-minute fix. Original audit §3.5.

### Remove `Event::FlowPacket::frame`

Today (`src/driver_unified/mod.rs:155`):

```rust
let (tcp_for_packet, frame_for_packet) = if self.emit_packet_details {
    let tcp = self.extractor.extract(view).and_then(|e| e.tcp);
    (tcp, Some(view.frame.to_vec()))     // ← KB-sized copy per packet
} else { (None, None) };
```

At 1 Mpps with 1500-byte frames that's 1.5 GB/sec of allocator
throughput. Bigger than every other item in the original audit
combined.

**Change:** drop the `frame` field from `Event::FlowPacket`.
Users who want frame bytes hold onto the source `PacketView<'_>`
they handed to `track_into`. The builder knob
`emit_packet_details(true)` stays — it controls whether
`tcp: Option<TcpInfo>` is populated. The frame part disappears.

### Phase 4 effort

~1 working day:
- 0.5h TLS_HANDSHAKE constant.
- 0.5h `Event::FlowPacket::frame` field removal.
- 1h migrate any consumer that reads `frame` (likely just
  `examples/02-forensics/` and `examples/04-observability/`).
- 0.5h post-Phase-4 bench row capture.
- 1h padding for CI iterations.

## Phase 5 — Release

Standard release mechanics, per
`feedback_release_consent.md` (per-release consent required).

1. `Cargo.toml` version `0.10.1` → `0.11.0`.
2. `CHANGELOG.md` 0.11.0 section — lead with a `BREAKING:`
   block listing every break + migration-guide link.
3. `CLAUDE.md` — flip "Implementation Status" entries for the
   0.11 cycle from in-progress to shipped.
4. `docs/migration-0.10-to-0.11.md` finalised with TOC + one
   recipe per break.
5. Pre-publish checklist (`cargo fmt --check`, `cargo clippy
   --all-features --all-targets -- -D warnings`, `cargo test
   --all-features`, `cargo doc --all-features --no-deps`,
   `cargo machete`, `cargo publish --dry-run`, full feature
   matrix from `.github/workflows/rust.yml`).
6. **Stop. Request per-release consent.** Do not proceed past
   step 7 without explicit "yes, release."
7. On consent: `cargo publish`.
8. `git tag 0.11.0 && git push origin master && git push
   origin 0.11.0`.
9. Verify crates.io page renders; verify docs.rs builds clean.

### Phase 5 effort

~1 working day (plus consent latency).

## Sequencing

```
Week 1:    Phase 0 — bench harness + baseline numbers committed.
Week 2-3:  Plan 119 — driver allocation elimination (~5 days).
Week 3:    Plan 120 — Bytes audit (~3 days).
Week 4-5:  Plan 121 — typed slot drains + legacy deletion (~5 days).
Week 5:    Phase 4 + Phase 5 (~2 days).
Week 6+:   netring 0.19 implementation against frozen 0.11.0.
```

Total: ~14–16 working days, single developer.

## Sequencing rationale

The original audit proposed two options:

- **α** — flowscope first, netring after.
- **β** — netring first with `Erased` workaround, flowscope
  after, netring 0.20 to collect benefits.

The reanalysis proposed a third:

- **δ** — one coherent 0.11 break, benchmark-driven (Phase 0
  before any code).

This plan picks **Option δ**, sharpened:

1. **One break, not two.** Splitting items into a 0.10.2 minor
   + 0.11 forces netring + every third-party consumer to
   migrate twice. Patch-then-break is a worse migration story
   than one well-announced break at the version boundary.

2. **Benchmarks before design.** Phase 0 grounds every
   subsequent design choice in measured numbers. If Phase 0
   reveals allocator pressure is already amortized by Vec
   capacity reuse, we can descope. If Phase 0 reveals worse
   problems (cache pressure, hash-function cost), we know
   before committing to a particular shape.

3. **Absorb plan 117 (legacy driver deletion).** The original
   117 was ~37 hours of work for the next major release. Plan
   121's slot refactor overlaps with 117's Phase 2 (internal
   slot refactor: stop wrapping `FlowSessionDriver`). The
   example/test migration in 117 Phase 3+4 overlaps with the
   typed-slot-drains migration we'd be doing anyway. Doing
   them together saves ~12 hours vs. sequential and avoids a
   second migration window for consumers.

## Acceptance criteria (cycle-wide)

- All Phase 0 bench gate rows hit their targets.
- All shipped tests pass under `cargo test --all-features`.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- All 9 CI feature-matrix entries clean.
- `cargo doc --all-features --no-deps` zero warnings.
- 0.11.0 published to crates.io.
- 0.11.0 tag pushed.
- Migration guide complete with cheat-sheet.
- CHANGELOG 0.11.0 entry lists every break.
- All cycle plan files (118 / 119 / 120 / 121) deleted per
  convention; `INDEX.md` updated to mark cycle retired.

## Risks

- **Phase 0 bench numbers reveal the real bottleneck is somewhere
  else.** This is a *good* outcome — we save weeks. Mitigation:
  budget Phase 0 as a hard deliverable with a writeup before
  any code lands. If numbers say `track()` allocation is
  already amortized to near-zero by capacity reuse, descope
  plan 119's parser-API break in favour of items the numbers
  flag (inlining? hash function? cache locality?).
- **Cycle stretches beyond 16 days.** Mitigation: typed slot
  drains (plan 121) is the architectural keystone — if it
  slips, plans 119 + 120 still ship as a coherent intermediate
  0.11.0-rc.1 and 121 lands as 0.11.0 final.
- **netring author wants push-style dispatch, not pull-style.**
  Mitigation: plan 121's `SlotHandle::drain` is the primitive;
  a one-line `on_slot(slot_id, closure)` sugar on the driver
  satisfies push consumers without breaking pull. Reserved for
  a follow-up patch release if asked for.
- **Per-release consent delay.** Mitigation: Phase 5 step 6 is
  the only blocking point. Steps 1-5 + 7-9 are mechanical.

## Effort summary

| Phase | Owner | Days |
|-------|-------|------|
| 0 — Bench gate | 118 | 1 |
| 1 — Driver allocation | 119 | 5 |
| 2 — Bytes audit | 120 | 3 |
| 3 — Typed slot drains + legacy del | 121 | 5 |
| 4 — Small wins | 118 | 1 |
| 5 — Release | 118 | 1 |
| **Total** | | **~16** |

## Provenance

- `../flowscope-deps-for-netring-0.19-2026-06-09.md` (original
  audit, 9–12 day estimate).
- `../flowscope-deps-for-netring-0.19-reanalysis-2026-06-09.md`
  (reanalysis with the 4 items the original missed and the
  shape pushback).
- This umbrella consolidates the reanalysis's 5 implementation
  plans (118 / 119 / 120 / 121 / 122 / 123 in the first pass)
  into 3 detailed plans (119 / 120 / 121) plus this umbrella.
  Absorbs the deferred plan 117 (legacy deletion) into plan
  121's scope since the slot refactor overlaps.

## Cycle-completion checklist

- [ ] Phase 0 — bench harness + baseline numbers captured.
- [ ] Plan 119 — driver allocation elimination shipped.
- [ ] Plan 120 — Bytes audit shipped.
- [ ] Plan 121 — typed slot drains + legacy deletion shipped.
- [ ] Phase 4 — TLS_HANDSHAKE const + frame field removal
      shipped.
- [ ] Phase 5 — 0.11.0 published, tagged, announced.
- [ ] netring 0.19 implementation started against published
      flowscope 0.11.0.
- [ ] Plan files 118 / 119 / 120 / 121 deleted; INDEX.md
      updated.
