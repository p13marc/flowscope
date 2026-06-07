# Design notes

The opinionated bits of flowscope's shape — why the library is
runtime-free, why parallelism happens outside, why the L7 layer
is a trait pair and not a tagged enum. This document is the
*why*; [`concepts.md`](concepts.md) is the *what*.

## Runtime-free in the core

**Constraint:** flowscope's lib crate has zero dependencies on
tokio, async-trait, futures, or any background tasks. Async
adapters live in [`netring`](https://crates.io/crates/netring),
which depends on flowscope, not the other way around.

**Why:**

- **Sync consumers are real.** Offline pcap replay, embedded
  capture, custom CLI tools, test harnesses — none of these want
  to compile a tokio runtime into their build.
- **Async runtime monoculture is a trap.** Tying flowscope to
  tokio forces every downstream into the same runtime. With the
  sync core, an `async-std` or `smol` consumer wraps the same
  traits in their own adapter.
- **Determinism in tests.** Sync code is easier to reason about
  and reproducible without runtime quirks.
- **Composability with `rayon`, RSS sharding, AF_XDP queues.**
  These deployment models don't need (or want) an async runtime
  in the per-flow worker.

**Consequence:** every consumer that wants async iteration brings
their own adapter. netring is the reference, but it's not the
only possible shape — embedded, real-time, or non-tokio consumers
build their own from the same traits.

## Run-to-completion threading

**Pattern:** shard packets per-flow via NIC RSS or symmetric
kernel hashing, then run the entire pipeline (capture → classify
→ extract → output) on a single core dedicated to that shard.

```
NIC RSS → N AF_XDP queues → N pinned worker threads, each owning
   its own (FlowExtractor, FlowTracker, Reassembler, SessionParser)
   end-to-end.
```

This is what nDPI, Suricata's `workers` runmode, Zeek's cluster,
and modern DPDK / VPP pipelines all converge on. The alternative —
*pipeline stages on separate threads (capture → classify →
extract)* — is anti-pattern for production DPI:

- Per-flow state has to be shared across stages, which means
  locks or message-passing per packet.
- Cache locality is destroyed when each packet bounces between
  cores.
- Backpressure becomes a hard problem; queue depth has to be
  tuned per stage.

flowscope is shaped for the run-to-completion model: per-flow
state is local (one `FlowTracker` per worker), no locks on the
hot path, no atomics required.

**Recommendation when deploying:** one extractor + tracker +
reassembler + parser per worker, fed from one RSS queue, pinned
to one core. Throughput scales linearly with cores until you run
out of NIC queues or memory bandwidth.

## Layered traits, not a tagged enum

**Choice:** each layer ships a trait (`FlowExtractor`,
`Reassembler`, `SessionParser`, `DatagramParser`) plus a default
implementation. Consumers can swap any layer for their own.

**Alternative considered:** ship a single `ParserStack` enum
covering every protocol, with each variant carrying its own
parser state.

**Why traits won:**

- **Custom protocols outnumber shipped ones.** Every consumer has
  at least one in-house protocol (vendor frames, RPC, telemetry,
  config) that flowscope can't anticipate. The trait shape lets
  them compose without forking.
- **Type erasure costs.** A tagged enum forces every variant's
  state into the same struct; cold variants pay for hot ones.
  Per-trait dispatch is monomorphised — only the parsers a
  consumer uses incur their state cost.
- **Stability of the surface.** Adding a shipped parser is
  additive (new feature flag, new type); it doesn't require
  matching `#[non_exhaustive]` enums in every consumer.
- **Composability.** `StripVlan(InnerVxlan(FiveTuple))` is a
  trait composition; tagged enums would force each combinator
  into the variant list.

The trait shapes (`SessionParser` and `DatagramParser`) have been
locked since 0.1.0 — additions stay additive, default methods
extend the surface without breaking existing impls.

## One API shape per L7 protocol

Every shipped L7 module — HTTP, TLS, DNS, ICMP — uses the
typed-stream shape: a `SessionParser` (TCP) or `DatagramParser`
(UDP) implementation that returns `Vec<Message>` from `feed_*`
or `parse`; the consumer iterates `SessionEvent::Application`
arms.

TLS additionally ships `TlsHandshakeParser` — also a
`SessionParser`, but aggregating ClientHello + ServerHello +
Alert into one `TlsHandshake` message per handshake. The
per-message `TlsParser` and the aggregator stand side by side
for the two granularities consumers want.

**Why one shape:**

- Typed parsers compose naturally with `Stream<SessionEvent>`
  async iteration and the sync `FlowSessionDriver` /
  `FlowDatagramDriver` loop alike — the same parser drives
  both paths.
- A consumer who wants callback ergonomics writes a
  `for ev in driver.track(...) { match ev { … } }` loop and
  dispatches inside the arms — no need for a separate
  callback trait.
- Single shape = single docs path, single test fixture, single
  set of guarantees. The legacy callback-factory shape that
  shipped through 0.8 was removed in 0.9 once the
  `SessionParser` story was complete.

## Bounded memory everywhere

Every stateful component has an explicit memory cap:

- `FlowTracker::max_flows` — LRU eviction at the limit.
- `BufferedReassembler::with_max_buffer` — per-side byte cap with
  configurable `OverflowPolicy` (`SlidingWindow` rotates;
  `DropFlow` poisons).
- `dns::Correlator::max_pending` — bounded query/response
  correlation table.
- `DnsResolutionCache::with_capacity` — LRU-bounded resolution
  table.

**Why:** flowscope is a passive observer of attacker-controlled
input. Any cap-less data structure is a denial-of-service vector
— a peer can stretch it indefinitely. The caps are tuneable but
never absent.

## Trait-method overrides for diagnostics

When a trait grows a diagnostic method (e.g.
`Reassembler::high_watermark`, `Reassembler::retransmits`), it
ships with a default-zero / default-`None` implementation.
Existing third-party `Reassembler` impls don't break.

**Convention:** a default return means *"this implementation
doesn't track that"*, not *"the value is zero / absent"*.
Downstream consumers reading these diagnostics get coherent
fallback behaviour from any implementation.

## Single vocabulary across event stream and metrics

`AnomalyKind` is the source of truth for both:

- `FlowEvent::FlowAnomaly` / `FlowEvent::TrackerAnomaly` event
  variants.
- `flowscope_anomalies_total{kind="..."}` metric label.

Adding a new `AnomalyKind` variant requires adding the matching
arm in `src/obs.rs::anomaly_label` in the same PR. The
integration test catches drift.

**Why:** consumers route on the same string in both pipelines.
Drift between event-stream kinds and metric labels would force
every consumer to maintain a translation table.

## Sync / async parity

Every async helper in netring has a sync mirror in flowscope:

| netring (async) | flowscope (sync) |
|-----------------|------------------|
| `flow_stream` | `FlowDriver` |
| `session_stream` | `FlowSessionDriver` |
| `datagram_stream` | `FlowDatagramDriver` |
| `conversation` | (planned; today: drive the reassembler manually) |

The async path is the ergonomic one; the sync path is what
offline-pcap consumers and embedded users get. Functional parity
keeps the documentation and test surface consistent between
modes.

## Locked wire format for serde

Once the `serde` feature ships (0.8.0), the JSON / structured
output vocabulary becomes a stability commitment:

- snake_case field names (`bytes_initiator`, `idle_timeout`, …).
- Internal tagging for all-struct enums (`{"type": "started",
  ...}`).
- Adjacent tagging for tuple-variant enums (`{"kind": "tcp"}` /
  `{"kind": "other", "value": 99}`).
- `Timestamp` → `{"sec": u32, "nsec": u32}`.

Renames require a CHANGELOG-documented breaking change. Golden
file round-trip tests guard against accidental drift.

**Why:** consumers build dashboards on these field names. A
silent rename invalidates queries downstream.

## Pre-1.0 backward-compatibility policy

flowscope is pre-1.0. The policy:

- **When a sharper API shape is better, we ship it and migrate
  consumers.** netring and known external consumers update in
  lockstep.
- **Every break ships with a CHANGELOG migration recipe.** The
  recipe is copy-pastable; the break is mechanical.
- **`#[non_exhaustive]` on every public struct/enum that may
  grow.** Variant-field and variant additions are unconditionally
  non-breaking.
- **Post-1.0 the trade-off flips.** Then we hold the line on the
  shape and additions go through extension traits / new methods
  instead of mutations.

The serde wire format (above) is the first surface to opt out of
this policy early — it locked at 0.8 because downstream dashboards
depend on it.

## What we deliberately don't ship

A few things we get asked for and consistently say no to, because
they belong elsewhere:

- **Live AF_PACKET / AF_XDP / pcap capture.** That's netring's
  job. flowscope is source-agnostic.
- **`tokio` in the dependency tree.** Hard rule, also called out
  in `CLAUDE.md`. Async lives in netring.
- **eBPF in-kernel correlation.** Different architecture; would
  belong in a separate sister crate.
- **ML-based anomaly detection.** Compose with this stack via a
  user-defined `AnomalyRule` that feeds a learned model; shipping
  the ML pipeline isn't flowscope's job.
- **Text-DSL rule language** (Suricata-style). Same reasoning;
  not flowscope's scope.
- **NetFlow / IPFIX export.** Belongs in a sister crate
  (`flowscope-export`); no current consumer asking.
- **CLIs.** `flow-summary` / `flow-replay` etc. belong in
  `flowscope-cli`; no current consumer asking.

## Sister-crate roadmap

Three sister crates are pre-architected but unstarted (no
current consumer asking):

- `flowscope-export` — NetFlow / IPFIX / sFlow output formats.
- `flowscope-cli` — `flow-summary` / `flow-replay` reference
  CLIs for "try without writing code" demos.
- `flowscope-rss` — multi-worker orchestration helpers (RSS
  sharding, AF_XDP queue management). Today consumers wire this
  themselves; the helpers would absorb the common shape.

If you need one of these, file an issue with a concrete use case.
None are blocked on design — they're blocked on demand signal.
