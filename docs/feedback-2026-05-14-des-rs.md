# Feedback for the `flowscope` team

**From:** `des-rs` project — DES protocol capture/decode tooling
([des-rs on GitHub](https://github.com/exail-pl/des-rs), internal)
**Date:** 2026-05-14
**flowscope version tested:** 0.2.0 (with features `extractors`,
`tracker`, `reassembler`, `session`, `pcap`)
**Companion crate:** `netring` 0.11.0 (separate feedback document)

---

## Context (what we're using flowscope for)

We build `des-capture`, a network capture tool for the DES (Data
Exchange Service) protocol — a binary TCP pub/sub used in industrial
robotics. DES has a length-prefixed framing layer (`PSMSG,` with u16
length, or `PSMSG4,` with u32 length for bodies > 65 KiB) over TCP,
carrying string-list bodies that decode into application-level
messages (`$USRINI`, `$PUBDEC`, `$PUBEVT`, etc.).

Our pipeline uses flowscope for everything between "bytes from the
NIC" and "application messages":

```rust
let stream = cap
    .flow_stream(flowscope::extract::FiveTuple::bidirectional())
    .with_dedup(...)
    .with_config(FlowTrackerConfig {
        idle_timeout_tcp: Duration::from_secs(60),
        max_reassembler_buffer: Some(1 << 20),
        overflow_policy: OverflowPolicy::DropFlow,
        ..Default::default()
    })
    .session_stream(DesSessionParser::default());
```

Where `DesSessionParser` is our `flowscope::SessionParser`
implementation that peeks the first 7 bytes (`PSMSG,` vs `PSMSG4,`)
and emits a `DesRecord` per fully-framed message.

The crate has been a substantial step up from what we had before
(hand-rolled TCP reassembly with bugs we kept rediscovering). **This
feedback is "what would help us further" — not "what is broken".**

We verified end-to-end on Linux 6.17 with both real-NIC and `lo`
captures; the `FiveTuple::bidirectional()` canonicalisation (key.a
≤ key.b) is exactly what we wanted for de-duplicating
src/dst pairs across directions.

---

## Wishlist, ordered by value to us

### 1. Expose `FlowStats` on more than just `Ended` events ⭐⭐⭐

**Problem.** `FlowStats { packets_initiator, packets_responder,
bytes_initiator, bytes_responder, reassembly_dropped_ooo_*, ... }`
is rich and exactly what we want for a per-flow rate dashboard.
But it only lands in `SessionEvent::Ended { stats, .. }`, i.e.
when a flow closes. DES publishers commonly live for *hours*, so
we never see those numbers in a production run.

**What we'd like:** a periodic tick event:

```rust
pub enum SessionEvent<K, M> {
    // existing variants ...
    FlowTick { key: K, stats: FlowStats, ts: Timestamp },
}
```

…emitted by the driver every `FlowTrackerConfig::flow_tick_interval`
(new field, `Option<Duration>`, `None` = disabled, default `None`).

Alternative API shape if periodic emission is too prescriptive:

```rust
let snapshot = stream.flow_stats_snapshot();  // HashMap<K, FlowStats>
```

…that a stats task can poll at its own cadence.

**Why it matters:** "did this PUBEVT actually arrive at the
subscriber" is answerable today only by re-implementing the
counters in the consumer. flowscope already maintains them
internally — surfacing them on the stream is a thin pass-through.

---

### 2. Reassembler high-watermark counter ⭐⭐⭐

**Problem.** `FlowStats` records
`reassembly_dropped_ooo_initiator/responder` and
`reassembly_bytes_dropped_oversize_initiator/responder`, but not
the **peak fill level** of the reassembler. The 1 MiB default for
`max_reassembler_buffer` is a guess inherited from our pre-rewrite
code; we have no way to know whether 64 KiB would have sufficed or
4 MiB is needed for our worst-case traffic.

**What we'd like:** two new fields on `FlowStats`:

```rust
pub struct FlowStats {
    // ... existing fields ...
    pub reassembler_high_watermark_initiator: u64,  // bytes
    pub reassembler_high_watermark_responder: u64,  // bytes
}
```

…that hold the peak buffer occupancy ever observed for each side.

Cheap to maintain (one `max(prev, current)` per segment fed in),
extremely useful for tuning.

**Why it matters:** with this we could run `des-capture` against
production traffic for an hour, observe peaks of e.g. 12 KiB on
each side, and confidently dial `max_reassembler_buffer` down to
32 KiB. Today it's "leave the default and hope".

---

### 3. Backpressure on `SessionParser` ⭐⭐⭐

**Problem.** The trait signature:

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + 'static;
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    // ...
}
```

returns owned `Vec<Self::Message>`. If we want to push records into
a bounded channel (e.g. for a downstream task that does I/O), we
can't signal "I'm full, slow down" — the parser must consume the
bytes flowscope hands it and buffer the messages itself.

**What we'd like:** the trait should return an iterator-like type:

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + 'static;
    type Iter<'a>: Iterator<Item = Self::Message> + 'a where Self: 'a;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Self::Iter<'_>;
    fn feed_responder(&mut self, bytes: &[u8]) -> Self::Iter<'_>;
}
```

…so the driver can yield messages lazily and we can stop pulling
when the downstream channel is full. The driver would still hand
the bytes to the parser eagerly (TCP reassembly can't really pause
without growing the reassembler buffer), but the *messages*
produced by the parser would only materialise as consumed.

Alternative: keep the current shape but add a
`feed_initiator_into(&mut self, bytes, sink: &mut impl FnMut(Self::Message))`
method so the parser can push directly and the consumer can stop
draining the `sink` when its channel is full.

**Why it matters:** without backpressure, the only way to handle a
slow downstream is to grow an unbounded queue, which is the
classic "memory leak with extra steps" pattern. We'd rather drop
flows at the reassembler level (which we already configure via
`OverflowPolicy::DropFlow`) than OOM the host.

---

### 4. Per-flow / per-port idle timeouts ⭐⭐

**Problem.** `FlowTrackerConfig::idle_timeout_tcp` is global. In
DES traffic, two very different flow shapes coexist:

- **Mediator control flows** (port `:15987`) — quiet for minutes
  by design; clients send heartbeats every 5 s but no real
  traffic between connect and disconnect. Want a long timeout
  (~60 s) here.
- **DEP data flows** (ephemeral ports) — bursty PUBEVTs at
  rates from 1 Hz to >10 kHz. Idle for >5 s reliably means the
  publisher died. Want a short timeout (~5 s) here.

With one global timeout, we either burn memory on dead data flows
(if timeout is long) or evict live control flows during quiet
periods (if short).

**What we'd like:**

```rust
let cfg = FlowTrackerConfig {
    idle_timeout_tcp: Duration::from_secs(60),
    idle_timeout_tcp_by_port: vec![
        (PortMatch::Either(15987), Duration::from_secs(60)),
        (PortMatch::Other,         Duration::from_secs(5)),
    ],
    ..Default::default()
};
```

…or a predicate API:

```rust
.with_idle_timeout_fn(|key| {
    if key.a.port() == 15987 || key.b.port() == 15987 {
        Duration::from_secs(60)
    } else {
        Duration::from_secs(5)
    }
})
```

The predicate variant is more flexible (we could use it for
loopback-only short timeouts, IPv6-only different timeouts, etc.)
but the by-port form is simpler and covers our case.

**Why it matters:** today we configure one timeout and accept the
trade-off. With per-port, our flow-table memory footprint drops
substantially while still tolerating long-quiet control flows.

---

### 5. Stable / monotonised timestamps on the stream ⭐⭐

**Problem.** `Timestamp { sec, nsec }` is per-packet wall-clock
from the NIC. flowscope makes no guarantee about monotonicity
across the stream — under load and with multi-queue NICs we
observe small (microsecond) backwards-going timestamps in the
output. Every consumer reinvents the same `max(prev, current)`
clamp.

**What we'd like:** either

- a `monotonised_ts: Timestamp` field on `SessionEvent`
  variants, populated by the driver from a running max, alongside
  the raw `ts` field; or
- a documented guarantee that the driver clamps `ts` to be
  non-decreasing across events from a single stream.

**Why it matters:** timeline analysis ("between t=1.234 and
t=1.235, who said what") is currently a footgun because the
timeline can briefly go backwards. Easier to fix once in flowscope
than in every downstream tool.

---

### 6. `with_dedup` on the sync `FlowSessionDriver` ⭐⭐

**Problem.** The async builder chain has
`flow_stream(...).with_dedup(Dedup::loopback())`. The sync driver
constructed via
`FlowSessionDriver::with_config(extractor, parser, cfg)`
has no equivalent. For our offline `des-pcap-decode` binary
processing pcaps captured from `lo`, we'd like to apply the same
dedup the live path applies, but the sync API doesn't expose
it.

**What we'd like:**

```rust
let driver = FlowSessionDriver::with_config(
    FiveTuple::bidirectional(),
    DesSessionParser::default(),
    cfg,
).with_dedup(Dedup::loopback());
```

Symmetry with the async builder.

**Why it matters:** today, pcaps captured by `tcpdump -i lo`
without external dedup get each PUBEVT twice through our offline
decoder; users need to know about netring's auto-dedup vs
flowscope's lack thereof. Closing that asymmetry removes a
gotcha.

---

### 7. Enumerated `SessionEvent::Anomaly` payload ⭐⭐

**Problem.** Per the Explore agent's survey: `Anomaly` is opt-in
and the kinds are not enumerated in the variant. We can see
"something went wrong" but not whether it was a buffer overflow,
an out-of-order drop, or a flow-table eviction. Each implies a
different operator action.

**What we'd like:**

```rust
pub enum AnomalyKind {
    BufferOverflow { side: FlowSide, bytes_dropped: u64 },
    OutOfOrderDrop { side: FlowSide, count: u32 },
    FlowTableEviction { reason: EvictReason },
    UnexpectedFin { side: FlowSide },
    // ... extensible
}

pub enum SessionEvent<K, M> {
    Anomaly { key: K, kind: AnomalyKind, ts: Timestamp },
    // ...
}
```

…with the enum being `#[non_exhaustive]` so adding variants is
non-breaking.

**Why it matters:** turns "anomaly happened" from a binary alert
into a structured diagnostic that can be filtered, counted, and
acted on.

---

### 8. Tracing spans by default on `Application` events ⭐

**Problem.** The `obs` module exists but each call site must
opt-in. For users who already pull in `tracing` (everyone using
tokio's `tracing-subscriber`), the friction-free thing would be
for flowscope to emit a `tracing::trace_span!` automatically on
each `SessionEvent::Application` (gated by a Cargo feature, off by
default if you're concerned about overhead).

**What we'd like:** a `tracing` Cargo feature on flowscope that,
when enabled, emits `trace!` events at session-event boundaries
with structured fields (key, side, ts, message count). No
configuration required at the call site; just turn the feature on
and `RUST_LOG=flowscope=trace cargo run` works.

**Why it matters:** observability "by default" beats "opt-in".

---

### 9. Parser-author guide / example with PSMSG-like framing ⭐

**Problem.** Implementing `SessionParser` for DES took several
iterations to get right. The trait is small but the *contract*
("you'll be called from the driver in arbitrary 1..N byte chunks;
fin_initiator means EOF without RST; etc.") is not exhaustively
documented. We figured it out by reading flowscope's own
HTTP/TLS/DNS parsers, but those aren't in the published crate
features by default.

**What we'd like:** an `examples/length_prefixed_parser.rs` in
the flowscope repo showing:

- a tiny stateful parser that recognises a header marker, peeks
  the length, and yields one message per length-prefixed frame;
- correct handling of partial frames across `feed_initiator`
  calls;
- correct handling of `fin_initiator` (flush partial buffer? drop?)
  and `rst_initiator` (drop state).

Bonus: a fuzz-test target in the examples that proves the parser
doesn't OOM, doesn't loop, doesn't misalign across split points.

**Why it matters:** lowers the barrier for the next protocol
maintainer who wants to use flowscope as their reassembly layer.
PSMSG-like length-prefixed framing is *extremely* common; one
worked example would unblock most users.

---

### 10. Joint with netring: round-trip CI fixture ⭐

**Problem (cross-crate).** Neither crate has a published "capture
this stream, decode it, write it back as pcap, replay, get the
same records" CI test. Our `offline_pcap_regression.rs` is *our*
end-to-end check; a similar test in flowscope's own CI would catch
class of integration bugs that span the netring/flowscope seam.

**What we'd like:** a `flowscope/tests/round_trip.rs` that:

1. Synthesises a known TCP byte stream (e.g. an HTTP request +
   response).
2. Writes it to a pcap via `netring::pcap::CaptureWriter`.
3. Re-reads via `flowscope::pcap::PcapFlowSource`.
4. Drives a `FlowSessionDriver` with a trivial passthrough
   `SessionParser`.
5. Asserts the emitted bytes equal the synthesised bytes.

Roughly 100 LoC, would have caught the
src/dst-canonicalisation drift we hit ourselves (commit
`77ad744` in our repo).

**Why it matters:** flowscope sits in a critical position
(reassembly + session); any regression here is invisible to its
consumers until they hit a specific edge case. A canary at the
flowscope level pays off for every downstream.

---

## Things that already work well (worth keeping)

For balance: these are the flowscope choices we're glad you made.

- **`FiveTuple::bidirectional()` canonicalisation** (`key.a ≤
  key.b` regardless of TCP direction) is exactly what tools need
  for de-duplicating "src/dst" pairs across the two directions of
  a TCP flow. Our previous bespoke code did the same thing
  manually; having it as a one-line option is a clean win.
- **`SessionParser` trait shape** — minimal surface, no
  unnecessary lifetimes, sensible defaults on `fin_*` and `rst_*`.
  Implementing a custom parser was straightforward (~150 LoC of
  state machine + tests in our `des_parser::session` module).
- **`FlowSessionDriver::with_config` + `FlowTrackerConfig` field
  exposure**. The `#[non_exhaustive]` + builder-via-default
  pattern works well; adding a field upstream doesn't break us.
- **`OverflowPolicy::DropFlow`** semantics — exactly right for
  length-prefixed protocols where a mid-buffer sliding window
  would corrupt framing. Documenting *why* DropFlow is the right
  choice for these protocols would help less-experienced users
  not pick `SlidingWindow` by mistake.
- **`SessionEvent::Ended { reason, stats, history }`** — the
  inclusion of `history` (the flag-byte timeline) is gold for
  forensics. We don't use it yet but we plan to.
- **Documentation** — the rustdoc is good; the public-API
  signatures are easy to navigate; the feature flags are
  well-named.

---

## How we'd like to engage

- We can file GitHub issues for each numbered item above if that
  works for you (one issue per item, with this doc as context).
- We can prototype the API changes (especially items 1–4) against
  our `DesSessionParser` and `des-capture` consumer and submit PRs
  once the design is agreed.
- We're available for review on PRs you cut, since `des-capture`
  exercises a real-world chunk of the public surface.
- We'd be happy to be a beta consumer of any pre-1.0 release; our
  test surface (53 unit + 173 parser + 2 integration tests, plus
  Layer-2 netns scenarios) would catch a fair number of
  regressions early.

Feel free to reach out via the project's PR/issue tracker. Thanks
for the great work — flowscope 0.2's chained-builder API is a real
ergonomic improvement over what was around when we started this
project, and the rewrite onto it has been worth it.

— the `des-rs` team
