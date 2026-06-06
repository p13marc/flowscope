# Plan 93 — 0.9 API ergonomics audit (umbrella)

## Summary

The 0.9.0 release is the last pre-1.0 cycle where flowscope can
break backwards compatibility freely. This plan is the umbrella
audit that motivates the per-area refactor plans. It does not
ship code on its own — every concrete change lives in a sibling
plan — but it is the durable record of *why* we are breaking
what we are breaking and the inventory we are working from.

The thesis: flowscope's traits are right, but the public
*surface* has accreted nine releases of polite-additive surgery.
Four friction points matter enough to break:

1. **38 driver constructors** across three driver structs
   (`new` / `with_config` / `with_factory` / … / chainable
   `with_emit_anomalies` / `with_idle_timeout_fn` / `with_dedup`
   / `with_monotonic_timestamps`). The matrix is unreadable; a
   first-time user has to learn the cross-product to pick one.
2. **No "start here" entry point.** Every example begins `let
   driver = FlowSessionDriver::new(extractor, parser)` —
   which is too deep for a first encounter with the library.
3. **No public per-packet layered view.** `etherparse::SlicedPacket`
   is parsed internally by the FiveTuple extractor and discarded.
   Consumers wanting "TCP window for this frame, VLAN tag, IPv6
   flow label" have to pull `etherparse` in directly.
4. **Two duplicated L7 API shapes.** Every L7 module (`http`,
   `tls`) ships both a callback-style `*Factory` / `*Handler`
   surface (predates 0.2.0) and the strategic
   `SessionParser` / `DatagramParser` typed-stream shape. The
   callback path is maintenance burden with no remaining
   audience.

Plan **94 (high-level API)** is one coherent design covering
all four: a `flowscope::Pipeline` entry point at Tier 1, typed
driver builders at Tier 2, a public `flowscope::layers` module
at Tier 3, and the callback-factory APIs deleted.

Two cross-cutting concerns:

5. **Five separate `Error` enums** (`http::Error`, `tls::Error`,
   `dns::Error`, `pcap::Error`, `icmp::Error`) with no shared
   trait, no unified `source()` chain. Consumers match on five
   types and lose context across module boundaries. Plan **96
   (error unification)** collapses into one
   `flowscope::Error { kind, source }`.
6. **Edition 2024 idioms are partly applied.** The crate is
   `edition = "2024"` but predates several stabilisations
   (let-else everywhere, if-let-chains, `impl Fn` in chainable
   setters). Plan **99 (2024 idioms)** sweeps these and reviews
   the MSRV.

Two protocol additions ride along, bundled as a single plan to
save duplicated provenance:

- Plan **97 (TLS modernization)** — JA4 client fingerprint
  behind a `ja4` feature + `TlsHandshakeParser` aggregating
  ClientHello / ServerHello / Certificate / Alert into one
  `TlsHandshake` message per handshake.

And four RFC plans land as implementations in the same cycle:

- Plan **74** — OOO TCP reassembly with hole-fill
  (`SegmentBufferReassembler`).
- Plan **75** — `FlowTracker::with_auto_sweep(interval)`.
- Plan **81** — `flowscope::correlate` module
  (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`).
- Plan **92** — `FlowMultiSessionDriver` /
  `FlowMultiDatagramDriver` composite drivers.

## Status

**Ready to implement.** The audit numbers were measured against
the 0.8.0 tagged tree on 2026-06-06. Plans 94, 96, 97, 99, plus
the four RFC carry-overs (74, 75, 81, 92) = 8 implementation
plans. Each is independent — they can land in any order, but
the canonical sequence is 96 → 94 → 92 → 99 so the error type
exists before the API consumes it and the idioms sweep runs
over the final code.

## Prerequisites

None. This is the umbrella; sibling plans declare their own.

## Out of scope

- A 1.0 release. 0.9.0 is the last *intentional* breaking-change
  window; 1.0 freezes the surface afterwards. If the audit
  uncovers shape changes too big for one cycle, they slip to a
  0.10 cycle rather than getting crammed in.
- Wire-format changes. The 0.8 serde lock (snake_case + adjacent
  tagging on tuple variants) holds. JSON / on-the-wire formats
  are durable; only Rust APIs break.
- Performance optimisations. Profile-driven work (parser fast
  paths, allocation reduction, SIMD attempts) lives in a
  separate cycle. 0.9 is API-shape only.
- Async APIs. Tokio integration remains in `netring`. The 0.9
  cycle aligns the sync surface; `netring` matches in lockstep.
- New protocol parsers (HTTP/2, QUIC, RTP). The deferred list
  in `plans/INDEX.md` still applies — consumer-led upstream PRs
  are the path.

---

## Inventory (measured 2026-06-06 against 0.8.0)

### Driver constructors

| Driver                | Free-fn constructors | Chainable setters |
|-----------------------|----------------------|-------------------|
| `FlowDriver`          | 6                    | 4                 |
| `FlowSessionDriver`   | 10                   | 4                 |
| `FlowDatagramDriver`  | 10                   | 4                 |
| **Total**             | **26 + 12 = 38**     |                   |

Reproduce with:

```bash
grep -cE '^\s*pub fn (new|with_)' \
  src/driver.rs src/session_driver.rs src/datagram_driver.rs
```

The matrix is the cross-product of four axes — state present?
(×2) × state initialiser? (×2) × parser factory? (×2) ×
config? (×2) = 16 theoretical constructors per driver. The
10-per-driver count is a partial materialisation. Plan 94
collapses to **one** builder per driver, with the same axes
exposed as builder methods.

### Two L7 API shapes

| Module | Strategic (kept)         | Legacy (deleted in 0.9)              |
|--------|--------------------------|--------------------------------------|
| HTTP   | `HttpParser` (`SessionParser`) | `HttpFactory`, `HttpReassembler`, `HttpHandler` |
| TLS    | `TlsParser` (`SessionParser`)  | `TlsFactory`, `TlsReassembler`, `TlsHandler`    |
| DNS    | `DnsUdpParser`, `DnsTcpParser` | — (only ever had typed-stream)        |
| ICMP   | `IcmpParser`              | — (only ever had typed-stream)        |

The callback shape predates the `SessionParser` trait (0.1.0)
and the typed-stream shape supersedes it. Every callback use
case is strictly subsumed by `for event in driver.run() {
match event { … } }`. Plan 94 deletes the legacy column.

### Error types

```
src/dns/mod.rs          pub enum Error
src/http/parser.rs      pub enum Error
src/icmp/parser.rs      pub enum Error
src/pcap/source.rs      pub enum Error
src/tls/parser.rs       pub enum Error
```

Five enums, none implementing a shared trait, none carrying a
`source()` chain from upstream parser errors (`httparse`,
`tls_parser`, `simple_dns`, `pcap_file`). Plan 96 unifies into
`flowscope::Error { kind: ErrorKind, module: Module, source: …}`.

### High-level entry-point gap

`grep "FlowSessionDriver::new" docs/ examples/` returns 11 hits
— every documented use of session parsing. No single "start
here" type that bundles common defaults
(`FiveTuple::bidirectional()` + sensible idle timeouts +
`emit_anomalies(true)` + an iterator over the merged event
stream). Plan 94 (Tier 1) adds `flowscope::Pipeline`.

### Per-packet introspection gap

`grep -r "pub.*SlicedPacket\|pub.*Layer\|pub.*frame_parse" src/`
returns zero hits in the public surface. The parsing happens in
`src/extract/parse.rs` and is `pub(crate)`. Plan 94 (Tier 3)
exposes a `flowscope::layers` module with zero-copy slices,
dynamic walk (`iter` / `find` / `find_all`), and tunnel
following.

### Edition 2024 idiom gaps

Scan over `src/` against the 2024 idiom list:

- `let Some(x) = … else { return None };` reaches for `?` where
  let-else exists today but isn't used.
- `&dyn Fn(...)` parameters in chainable setters that could be
  `impl Fn(...)` for slightly better optimisation in
  monomorphised callers.
- A handful of pre-`if let chains` nested `if let Some(x) = a {
  if let Some(y) = b { … } }` blocks (now stable on MSRV 1.85).

Short list; plan 99 sweeps it.

### Constructor-pattern parity check

`FlowTracker` has `new`, `with_config`, `with_state`,
`with_config_and_state` — already collapsed enough.
`BufferedReassembler` has `new` + 3 chainables — also fine.
The 38-constructor surface is concentrated in the *drivers*;
plan 94 targets only those.

---

## Cycle plan-of-record

| Plan | Area | Breaking? | Risk |
|------|------|-----------|------|
| 74   | OOO TCP reassembly (`SegmentBufferReassembler`) | additive | medium — wide change in reassembler module |
| 75   | `FlowTracker::with_auto_sweep` | additive | low |
| 81   | `flowscope::correlate` module | additive | low — three small standalone primitives |
| 92   | `FlowMultiSessionDriver` / `FlowMultiDatagramDriver` | additive | medium — sum-type design needs proving against real use |
| **94** | High-level API (Pipeline + driver builders + `layers` module + drop callback factories) | **breaking** | high — every consumer's first line changes |
| **96** | Error unification (5 module-local enums → one `flowscope::Error`) | **breaking** | medium — public types referenced in user signatures |
| 97   | TLS modernization (JA4 + handshake aggregator) | additive | low |
| **99** | 2024 idioms sweep + MSRV review | mostly internal | low |

Plus the umbrella (this file, plan 93) — no code.

**Three breaking plans**: 94, 96, and the MSRV piece of 99
(currently held at 1.85). Their migration recipes are the bulk
of the CHANGELOG entry for 0.9.0.

Canonical landing sequence:

```
96 (error type lands) →
94 (high-level API consumes it) →
92 (multi-parser driver builds on the new surface) →
74 / 75 / 81 / 97 (additive — any order) →
99 (idioms sweep over the final state)
```

---

## Acceptance criteria

This umbrella has no code deliverables. It is satisfied when:

- Plans 74, 75, 81, 92, 94, 96, 97, 99 are all individually
  green (or explicitly slipped to 0.10 with a one-line note in
  INDEX.md).
- `CHANGELOG.md` 0.9.0 section calls out each breaking change
  with a before/after migration snippet (driver constructors,
  callback factories, error types).
- `docs/getting-started.md` re-leads with `flowscope::Pipeline`
  + `flowscope::prelude::*`.
- `docs/concepts.md` shows the three-tier diagram from plan 94
  and no longer documents `FlowSessionDriver::new` as the
  recommended entry point.
- `netring` is updated in lockstep; the 0.9 release of flowscope
  ships paired with the matching `netring` release.

---

## Risks

- **Migration burden underestimated.** The driver-builder break
  (plan 94) plus the callback-factory deletion plus the error
  refactor (plan 96) all touch every external consumer.
  Mitigation: detailed CHANGELOG mapping tables; `netring`
  lands in lockstep; the known external consumers are
  coordinated directly. Per pre-1.0 BC policy, the cycle is
  treated as a clean break (no `#[deprecated]` cycle in 0.8.x).
- **Plan-94 internal sequencing.** Plan 94 is large (~1,900 LoC
  net). Land as ~8 PRs so individual reviews stay tractable.
  The plan's "Implementation steps" section spells the
  sub-PR order.
- **Error unification regressions.** Plan 96 reroutes every
  parser module's internal errors. Risk of dropping context.
  Mitigation: a sample of fixtures gets a round-trip test on
  `source()` chain preservation (plan 96's acceptance criteria).

## Effort

This plan: 0 LoC.

Sibling plans (rough roll-up):

| Plan | LoC (net) | Hours |
|------|-----------|-------|
| 74   | ~600 | ~20 |
| 75   | ~290 | ~8 |
| 81   | ~650 | ~22 |
| 92   | ~910 | ~22 |
| 94   | ~2,260 | ~71 |
| 96   | ~360 | ~10 |
| 97   | ~630 | ~16 |
| 99   | ~180 | ~5 |
| **Total** | **~5,880 LoC** | **~174 hours** |

Larger than the 0.8 cycle (9 plans, ~3,800 LoC, ~95 hours). The
extra surface concentrates in plan 94 (~1,900 LoC — three
surfaces in one plan: Pipeline, three driver builders, layers
module, plus deletions).

## Provenance

Triggered by the user's 2026-06-06 directives, in order:

> *"I would like to make a big 0.9.0 release where we are allow
> to break the backward compatibility to make the best API and
> to make sure we are Rust idiomatic and provide high level API.
> Review our plans. Update them and create new one if needed."*

> *"We should provide easy way to access every layer (L2, L3,
> ..., L7). Make it dynamic."*

> *"review all our plans. Make sure everything is rust idiomatic,
> that we provide high level API. You are allow to break the
> backward compatibility to make our crate the best of is kind.
> [...] Consolidate our plans."*

The third pass consolidated the cycle from 12 plans to 8 (plus
the umbrella):

- Plans 94 (driver-builder), 95 (Pipeline), 100 (layers) merged
  into the new plan 94 (high-level API). Justification: all
  three touched the public-facing entry point; designing them
  separately produced naming-convention drift (audit found 94
  using unprefixed methods, 95 using `with_*`) and an unclear
  layering story.
- Plans 97 (JA4), 98 (TLS handshake aggregator) merged into
  the new plan 97 (TLS modernization). Justification: shared
  feature surface, shared spec references; co-shipping avoids
  the awkward "0.9 ships JA4, 0.10 ships the aggregator that
  re-exposes it" cadence.

The cycle deliberately does **not** target every plausible
ergonomic improvement; the deferred list in `plans/INDEX.md`
stays the holding pen for the speculative ones.

---

## Research check (2026-06-06)

A "best of its kind" research pass against the 2026 Rust packet
/ flow analysis ecosystem produced two concrete plan deltas
(both folded into the sibling plans before this writing):

1. **Zero-allocation layer-parsing mode** in plan 94 (Tier 3
   fast path) — mirrors `gopacket.DecodingLayerParser`'s
   pre-allocated layer-struct pattern. ~10× throughput in
   published gopacket benchmarks; flowscope's target is
   < 30 ns / frame on the `only(&[Ipv4, Tcp])` configuration.
2. **MSRV bump 1.85 → 1.88** in plan 99 — let-chains
   stabilised 2025-06-26; the typical "nested `if let`" code
   pattern in the post-cycle codebase reads materially cleaner
   with `if let Some(a) = x && let Some(b) = y`.

And four follow-up items added to `plans/INDEX.md`'s deferred
list (not in 0.9, surfaced by the survey):

- IPFIX / NetFlow export sister crate (`netgauze-flow-pkt` is
  the natural sink).
- Passive QUIC parser (greenfield — no Rust crate today).
- HTTP/2 passive parser (`SessionParser`-shaped).
- `#[derive(SessionParser)]` macro (`wsdf`-style dissector
  generator, post-1.0).
- Composite multi-layer fingerprint (nDPI 5.0 FPC).
- Wirefilter expression filter (for the future CLI sister
  crate).

Positioning vs the rest of the ecosystem:

- **`huginn-net`** (2025) is the closest neighbour — passive
  multi-protocol fingerprint (JA4 + p0f). flowscope and
  huginn-net are *complementary*, not competing: huginn-net is
  fingerprint-first, flowscope is flow-and-session-first.
  Plan 97 ships JA4 to keep parity for the "one library for
  both flows and fingerprints" use case.
- **`etherparse`** / **`pnet`** / **`pcap-parser`** are the
  parsing-engine tier flowscope builds on; the new layers
  module wraps `etherparse::SlicedPacket` with
  flowscope-shaped names + tunnel following + the fast path.
- **`netgauze-flow-pkt`** / **`netflow_parser`** /
  **`rustflow`** are the export-ecosystem tier flowscope
  would feed (via the deferred `flowscope-export` sister
  crate).
- Rust async idiom stabilisation (AFIT 1.75, async closures
  1.85, trait upcasting 1.86, let-chains 1.88) is fully
  available within the new MSRV. `gen fn` is still unstable
  as of 2026-06; the `SessionParser::feed_*` `Vec<Self::Message>`
  return shape stays.
