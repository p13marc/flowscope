# Plan 115 — strategic review + redesign proposal

## The question

> "Review our code. Review all our plans. You are allowed to
> completely redesign flowscope if needed. […] Our API should
> be right."

The brief is permissive — break things, restructure, redesign.
Section 1 is an honest audit of the *current* surface (shipped
0.9 + planned 0.10). Section 2 separates what's load-bearing
from what's accidental. Section 3 proposes the redesign.
Section 4 sizes the work and recommends cycle scheduling.

## Status

**Analysis only.** Yields one new implementation plan (116) and
several modifications to existing 0.10 plans. The maintainer
adopts or rejects.

---

## 1. Audit — what's actually shipped or proposed

### 1.1 Public type sprawl

A grep audit of `pub struct` / `pub enum` in the flow / event /
driver path produced this count:

- **5 driver types**: `FlowDriver`, `FlowSessionDriver`,
  `FlowDatagramDriver`, `FlowMultiSessionDriver`, plus the
  proposed `FlowMultiDriver` (plan 109) = **6 after 0.10**.
- **3 event types**: `FlowEvent<K>`, `SessionEvent<K, M>`,
  plus the proposed `MultiEvent<K, M>` (plan 109). `Pipeline`
  also has its own `Event<K, SM, DM>` (Tier-1 wrapper). So
  **4 event types** the consumer can see.
- **3 builder types**: `FlowSessionDriverBuilder`,
  `FlowDatagramDriverBuilder`, `PipelineBuilder`. Plus
  `FlowMultiDriverBuilder` proposed in plan 109. = **4 after
  0.10**.

That's **14 driver/event/builder types** the user picks among,
plus the underlying `FlowTracker`. The 9-event-payload subtypes
(`AnomalyKind`, `EndReason`, `FlowState`, `FlowStats`,
`FlowSide`, `OverflowPolicy`, `Severity`) bring it to 23.

### 1.2 The driver story

Each driver does roughly the same thing:

```text
extractor → tracker → reassembler → parser → event stream
```

The variation is along two axes:

|              | session (TCP) | datagram (UDP) |
|--------------|--------------:|---------------:|
| 1 parser     | `FlowSessionDriver` | `FlowDatagramDriver` |
| N parsers    | `FlowMultiSessionDriver` | (not shipped) |
| Both, 1 each | `Pipeline` (shipped 0.9) | (same)              |
| Both, N each | (plan 109 proposes `FlowMultiDriver`) | (same) |
| No L7        | `FlowDriver` | (n/a)              |

Five drivers ship; a sixth (`FlowMultiDriver`) is the centerpiece
of the 0.10 cycle and replaces the fifth (`FlowMultiSessionDriver`).
Net after 0.10: **6 driver types** for 4 use cases.

### 1.3 The event story

| Driver | Emits |
|--------|-------|
| `FlowTracker` | `FlowEvent<K>` |
| `FlowDriver` | `FlowEvent<K>` (with reassembler diagnostics interleaved) |
| `FlowSessionDriver`, `FlowDatagramDriver` | `SessionEvent<K, M>` |
| `Pipeline` | `Event<K, SM, DM>` (wraps `FlowEvent` and `SessionEvent`) |
| `FlowMultiSessionDriver` | `SessionEvent<K, M>` (same as single) |
| `FlowMultiDriver` (proposed) | `MultiEvent<K, M>` (new) |

Started/Closed/Anomaly variants appear on three of these. The
overlap matters: a consumer migrating from `Pipeline` to
`FlowMultiDriver` (per plan 109) has to convert from
`Event<K, SM, DM>::Flow(FlowEvent::Started)` to
`MultiEvent<K, M>::Flow(FlowEvent::Started)` to
`SessionEvent::Started` — three different containers for the
same logical event.

### 1.4 The 0.10 plans' relationship to the existing surface

Of 13 plans (101–114):

- **2 are pure additions** that don't touch the driver surface:
  104 (`detect`), 105 (`well_known`).
- **5 are convenience additions** that build on existing types
  without changing their shape: 101 (`emit`), 102 (correlate
  extensions), 103 (`aggregate`), 110 (rustdoc), 111 (quick
  wins).
- **4 modify L7 parsing**: 106 (parser ergonomics), 107
  (exchange aggregators), 113 (signatures), 114 (heuristic
  routing).
- **2 directly affect the driver surface**: 108 (packet
  enrichment — additive field on `FlowEvent::Packet`), 109
  (`FlowMultiDriver` — adds a 6th driver type).

Plan 109 alone is the largest. It does the shared-tracker
optimisation but doesn't collapse the type sprawl — it
*increases* the count by one. Combined with plan 114 (heuristic
routing on the new driver), the cycle adds capability but
doesn't simplify.

### 1.5 The Pipeline / Multi-driver duplication

`Pipeline` wraps both `FlowSessionDriver` and
`FlowDatagramDriver` for the single-parser-per-L4 case. The
proposed `FlowMultiDriver` does the same thing for the N-parser
case. They're **parallel implementations** of the same idea
(one driver + many parsers + merged event stream), differing
only on N=1 vs N>1.

This is the smell. There's no reason these are two types.

---

## 2. What's load-bearing vs accidental

### 2.1 Truly load-bearing

These earn their keep:

- **`FlowTracker`**. Bidirectional flow accounting with TCP
  state machine + LRU + idle timeouts. The core value
  proposition. Nothing else in Rust does this with this
  feature set.
- **`FlowExtractor` trait + `FiveTuple`** + decap combinators
  (`StripVlan` etc.). Right shape. The combinator pattern
  reads weirdly in type signatures but the alternative
  (config-driven) loses type safety.
- **`SessionParser` / `DatagramParser` traits**. Stable since
  0.1.0. The split is awkward (see 2.3) but breaking it
  cascades. Defer to 1.0.
- **`Reassembler` trait + `BufferedReassembler` +
  `SegmentBufferReassembler`**. Two impls, one trait — fine.
  No collapse needed.
- **`flowscope::Error` + `ErrorCode` + `Module`**. Plan 96
  shipped this cleanly. Nothing to change.
- **`flowscope::layers`**. Eager + fast-path is the right
  shape. Plan 115 (lazy variant, sketched in 112) is the
  only addition warranted.
- **`flowscope::correlate` + the plan-102/103/104 extensions**.
  Clean primitives; right shape.
- **`flowscope::prelude`**. Right scope.

### 2.2 Accidental — the redesign opportunity

These are duplicate machinery:

- **`FlowSessionDriver` vs `FlowDatagramDriver`** — same shape,
  different L4. Internally `FlowDatagramDriver` is a special
  case of `FlowSessionDriver` (UDP needs no reassembler;
  payload goes straight to the datagram parser). Could be one
  type parameterised over `Parser` (TCP or UDP).
- **`FlowMultiSessionDriver` (0.9) + `FlowMultiDriver` (plan
  109)** — the 0.10 cycle was already going to delete the
  former. Plan 109 makes the new one a separate type from
  `Pipeline` for no design reason.
- **`Pipeline` vs `FlowMultiDriver`** — the single-parser and
  multi-parser cases are parametrically related. `Pipeline` is
  `FlowMultiDriver<E, P::Message>` with one registered parser.
- **`FlowEvent` + `SessionEvent` + `Event` + `MultiEvent`** —
  four containers for what is conceptually the same event
  stream. The split exists because each driver evolved its
  own wrapper.
- **`FlowSessionDriverBuilder` + `FlowDatagramDriverBuilder` +
  `PipelineBuilder` + `FlowMultiDriverBuilder`** — four
  builders for four types. With unified driver, one builder.

### 2.3 Stable but unsatisfying — defer to 1.0

- **`SessionParser` (feed_initiator + feed_responder) vs
  `DatagramParser` (parse with FlowSide)**. The shapes differ
  pre-1.0 because changing them cascades through every shipped
  parser. A unified `Parser` trait taking `side: FlowSide` is
  cleaner but breaks every consumer. Defer to 1.0.
- **`FlowEvent::StateChange` + `FlowEvent::Established`** —
  two variants for the same "TCP state advanced." Could be
  one with a more flexible `to: FlowState` payload. Minor.
- **`AnomalyKind` variant count** — 6 today; will grow.
  Documented as the single-vocabulary policy; fine.

---

## 3. The redesign proposal

### 3.1 Collapse the drivers — ONE `Driver<E, M>`

Replace these:

- `FlowDriver<E, F, S>`
- `FlowSessionDriver<E, P, S>`
- `FlowDatagramDriver<E, P, S>`
- `FlowMultiSessionDriver<E, M>` (currently shipped, planned to be deleted by 109)
- `FlowMultiDriver<E, M>` (proposed by 109)

with one:

- **`Driver<E, M>`** — accepts zero or more registered session
  parsers + zero or more registered datagram parsers; emits a
  unified `Event<K, M>` stream; one shared tracker; one
  builder. M defaults to `()` for the no-parser case.

The single-parser case (`Pipeline`'s domain) becomes:

```rust
let mut driver = Driver::<_, HttpMessage>::builder(ext)
    .session_on_ports(HttpParser::default(), [80, 8080], identity)
    .build();
```

The multi-parser case (plan 109's domain) becomes:

```rust
let mut driver = Driver::<_, MyL7>::builder(ext)
    .session_on_ports(HttpParser::default(),         [80, 8080], MyL7::Http)
    .session_on_ports(TlsHandshakeParser::default(), [443],       MyL7::Tls)
    .datagram_on_ports(DnsUdpParser::default(),      [53],        MyL7::Dns)
    .session_heuristic(HttpParser::default(), http_request, MyL7::Http)  // plan 114
    .build();
```

The no-L7 case (just flow lifecycle):

```rust
let mut driver = Driver::<_, ()>::builder(ext).build();
```

Same builder, same event type, same dispatch.

### 3.2 Collapse the events — ONE `Event<K, M>`

Replace `FlowEvent` / `SessionEvent` / `MultiEvent` /
Pipeline's `Event` with:

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event<K, M> {
    // Flow lifecycle — emitted once per logical event.
    FlowStarted { key: K, ts: Timestamp, l4: Option<L4Proto> },
    FlowEstablished { key: K, ts: Timestamp, l4: Option<L4Proto> },
    FlowPacket {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        /// Per-packet TCP info when emit_packet_details = true (plan 108).
        tcp: Option<TcpInfo>,
        /// Borrowed frame bytes when emit_packet_details = true.
        frame: Option<Bytes>,
    },
    FlowEnded {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
    },
    FlowTick { key: K, stats: FlowStats, ts: Timestamp },

    // Parser-level events.
    Message {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        parser_kind: &'static str,
    },
    ParserClosed {
        key: K,
        parser_kind: &'static str,
        reason: EndReason,
        ts: Timestamp,
    },

    // Anomalies.
    FlowAnomaly { key: K, kind: AnomalyKind, ts: Timestamp },
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },
}
```

This:

- Renames `Started/Ended/Established/Packet/Tick` to
  `FlowStarted/FlowEnded/etc.` to distinguish from
  `Message/ParserClosed`.
- Folds `FlowEvent::StateChange` into `FlowPacket`'s implicit
  state (since `tcp.flags` reveals the TCP transition).
- Absorbs `SessionEvent::Application` → `Event::Message` and
  `SessionEvent::Closed` → `Event::ParserClosed`.
- Drops `SessionEvent::Started` (was always equal to
  `FlowEvent::Started`; the shared-tracker driver emits once).

### 3.3 `Pipeline` becomes a one-screen wrapper

```rust
pub struct Pipeline<E, M> {
    driver: Driver<E, M>,
}

impl<E, M> Pipeline<E, M> {
    pub fn builder(extractor: E) -> PipelineBuilder<E, M> { … }
    pub fn run_pcap(&mut self, path: impl AsRef<Path>)
        -> crate::Result<PipelineIter<'_, E, M>> { … }
    pub fn run_iter<I>(...) -> PipelineIter<'_, E, M> where ... { ... }
    pub fn reset(&mut self) { ... }
}

pub struct PipelineBuilder<E, M> { … }  // proxies Driver's builder
```

`Pipeline` IS `Driver` with sources attached. Its builder
proxies `Driver`'s builder so the registration API is
identical. Users wanting more control drop to `Driver` and feed
packets themselves.

### 3.4 What this collapses

After the redesign:

| Today (after 0.9 + 0.10 as-currently-planned) | After redesign |
|-----------------------------------------------|----------------|
| 6 driver types | **1** (`Driver`) |
| 4 event types | **1** (`Event<K, M>`) |
| 4 builder types | **1** (`DriverBuilder`) + thin `PipelineBuilder` |
| `Pipeline` separate codepath | `Pipeline` ≈ `Driver` + source |
| `FlowMultiSessionDriver` (deleted by plan 109) | (not introduced) |
| `MultiEvent` (proposed by plan 109) | (not introduced) |

23 driver/event/builder/payload types drops to ~16. The mental
model shrinks to: `FlowTracker` (raw), `Driver` (orchestrated),
`Pipeline` (sourced). Three levels, three names.

### 3.5 What the redesign does NOT change

- `FlowTracker` — unchanged. `Driver` uses it internally.
- `FlowExtractor` + extractor combinators — unchanged.
- `SessionParser` + `DatagramParser` traits — unchanged. (The
  unified `Parser` trait is a 1.0 question.)
- `Reassembler` trait + impls — unchanged.
- `flowscope::layers`, `flowscope::correlate`,
  `flowscope::Error`, `flowscope::prelude` — unchanged.
- `flowscope::detect` (plans 104, 113) — unchanged.
- `flowscope::emit`, `flowscope::aggregate`,
  `flowscope::well_known` (plans 101, 103, 105) — unchanged.

The trait shape is stable. Only the *driver / event* surface
collapses.

---

## 4. Sizing + cycle scheduling

### 4.1 Implementation cost — plan 116

The actual work lives in **plan 116** (separate file). Estimate:

- New `Driver<E, M>` + `Event<K, M>` + `DriverBuilder` types
  — ~700 LoC.
- Internal: type-erasure for session/datagram parser slots,
  shared-tracker dispatch (subsumes plan 109's design). —
  ~600 LoC.
- Delete `FlowDriver`, `FlowSessionDriver`,
  `FlowDatagramDriver`, `FlowMultiSessionDriver`,
  `FlowSessionDriverBuilder`, `FlowDatagramDriverBuilder`. —
  ~−2,000 LoC.
- Rewrite `Pipeline` atop `Driver`. — ~−250 LoC net.
- Delete `FlowEvent` and `SessionEvent`; ship `Event<K, M>`.
  — ~−400 LoC net.
- Migrate every consumer in `src/`, `tests/`, `examples/`.
  — ~+800 LoC of edits across ~50 files.
- Migration guide in CHANGELOG. — ~150 LoC.

**Net:** ~700 LoC net delta in `src/`, but it touches widely.
The work is **~35-45 hours** (comparable to plan 94 in 0.9).

### 4.2 What plan 116 does to the existing 0.10 plans

| Plan | Status after 116 |
|------|------------------|
| 101 — emit | Unchanged (operates on `Event<K, M>`). |
| 102 — correlate ext. | Unchanged. |
| 103 — aggregate | Unchanged. |
| 104 — detect | Unchanged. |
| 105 — well_known | Unchanged. |
| 106 — parser ergonomics | Unchanged (operates on parser traits, not drivers). |
| 107 — exchange aggregators | Unchanged. |
| 108 — packet enrichment | **Absorbed.** The `tcp` / `frame` fields land directly on the unified `Event::FlowPacket`. Plan 108 reduces to a sub-task of 116. |
| **109 — cross-L4 driver** | **Deleted.** Plan 116 subsumes the cross-L4 work + the shared-tracker optimisation. |
| 110 — rustdoc | Unchanged. |
| 111 — quick wins | Unchanged. |
| 112 — dynamic/lazy analysis | Doc only, unchanged. |
| 113 — signatures | Unchanged. |
| 114 — heuristic routing | **Modified.** Hooks into `Driver`'s builder (`session_heuristic` etc.) instead of a separate `FlowMultiDriver` type. Effort drops ~15 %. |

The cycle's plan count drops from 13 to 12 (109 is absorbed
into 116; 108 is folded in). Total effort net delta: **+5
hours** (116 adds work; 109 was already substantial; 108 drops
out as a separate plan).

### 4.3 Scheduling — include or defer?

**For inclusion in 0.10:**

- The pre-1.0 BC freedom expires after 0.10 / 0.11 cycles
  push us toward 1.0. The window to fix the driver surface is
  now.
- The cycle is already breaking (plan 109's
  `FlowMultiSessionDriver` removal). Adding 116 is one more
  break in the same direction — net less migration burden than
  spreading the breaks across two cycles.
- Every 0.10 plan after this can ship against the new shape.
  Documentation lands cohesively.

**For deferring to 0.11:**

- 0.10 is already substantial (~194 hours pre-116, ~199
  post-116 with the redistribution).
- The risk of a bad-shape commit in a large refactor is real;
  delaying lets the maintainer review more carefully.
- Plan 116 lands when the maintainer's bandwidth allows;
  doesn't have to be in the next 6-week window.

**Recommendation: include in 0.10 as a phased PR series.**
Sub-PR 1 lands the new types alongside the old (no deletions);
Sub-PR 2-N migrate consumers; Sub-PR final deletes the old
types. Each PR is independently reviewable; the cycle ends
when the last PR lands.

---

## 5. Other API-rightness considerations (not redesigned)

### 5.1 Parser traits — defer to 1.0

The `SessionParser` / `DatagramParser` split is awkward. They
could merge into one `Parser` trait with a `side: FlowSide`
parameter on a single `feed` method. But the trait shape has
been stable since 0.1.0; breaking it cascades through every
shipped parser implementation (including the JA3/JA4
fingerprint paths). **Recommend: stable at 1.0; revisit then.**

### 5.2 Async story — stays sync

flowscope is sync; netring is async. Hard rule (stated in
CLAUDE.md). Async-in-core proposals will keep surfacing as
backpressure-aware-channel asks; the right answer remains "use
netring's stream adapters." No change.

### 5.3 The `FlowEvent::StateChange` variant

Underused in practice. Most consumers care about `Established`
(now `FlowEstablished`) and `Ended`; the intermediate
`StateChange` events flood the log without adding signal. Plan
116 folds the relevant state info into `FlowPacket`'s
`tcp.flags` (the consumer reconstructs the state transition if
they want it).

### 5.4 The number of `AnomalyKind` variants

6 today. Adding more is permitted under the single-vocabulary
policy. No change.

### 5.5 Documentation surface size

Rustdoc would benefit from `#[doc(hidden)]` on internals that
leak (e.g. `extract::parse::*` test_frames). Plan 110 (rustdoc
landing pages) is the right scope for this — extend its
ambitions to include the hide-internals sweep.

---

## 6. Decision summary

**Recommended:**

- ✅ **Adopt plan 116** — driver + event unification. Major
  pre-1.0 simplification.
- ✅ **Delete plan 109** (cross-L4 driver) — subsumed by 116.
- ✅ **Absorb plan 108** (packet enrichment) into 116 — the
  `tcp` and `frame` fields land on `Event::FlowPacket`
  directly.
- ✅ **Modify plan 114** (heuristic routing) to extend
  `Driver`'s builder instead of plan 109's stand-alone driver.
- ➡️  **Keep plans 101–107, 110, 111, 113** as-is — orthogonal
  to the driver collapse.

**Deferred / not changed:**

- `SessionParser` / `DatagramParser` trait merge — 1.0.
- Async-in-core — never.
- `FlowEvent::StateChange` deprecation — folded into 116.

**Cycle delta:**

| | Pre-115 | Post-115 |
|---|---|---|
| Implementation plans | 13 (101–114) | 12 (101–108, 110–114, 116) |
| Total LoC | ~8,900 | ~9,300 |
| Total hours | ~194 | ~225 |
| Driver types after cycle | 6 | **1** |
| Event types after cycle | 4 | **1** |

The work goes up ~30 hours; the API shrinks dramatically. Net
trade well worth taking pre-1.0.

---

## Files (this plan)

```
plans/115-strategic-review.md       # this file
plans/116-driver-event-unification.md  # the implementation work
plans/109-cross-l4-multi-driver.md   # DELETED (subsumed by 116)
plans/108-packet-event-enrichment.md  # DELETED (absorbed by 116)
plans/114-heuristic-routing.md       # MODIFIED (Driver-based)
plans/INDEX.md                       # backlog table update
```

## Effort

This plan: 0 LoC; the work lives in plan 116.

## Provenance

User question, 2026-06-07:

> *"review our code. review all our plans. You are allow to
> completely redesign flowscope if needed. […] Take your time.
> Our API should be right."*

The "API should be right" framing invited an honest
audit. The driver type sprawl (6 types, 4 event types, 4
builders → 14 user-visible types after 0.10) is the
load-bearing problem. Other concerns (parser trait split,
async, etc.) defer to 1.0 or stay out of scope.

Industry alignment:

- Most network analysis libraries (gopacket, libtins, pnet,
  etherparse) DO NOT have a driver concept — they expose
  primitives and let consumers compose. flowscope's driver
  layer adds value (orchestration, dispatch, lifecycle); 0.10
  collapsing it to one type aligns better with industry while
  keeping the value.
- The closest precedent: **Cap'n Proto's `MessageReader<T>`**
  — one generic over what's inside, instead of N specialised
  readers. **OpenTelemetry's `Tracer<T>`** — same pattern.
  **tower's `Service<R>`** — same pattern. Flowscope's six
  drivers are an anti-pattern by comparison.

The redesign is the right shape; the question was scope and
timing.
