# 11 — Upstream Wishlist for `flowscope`

A worked-through inventory of upstream asks for `flowscope`, the
flow tracker + reassembler + L7 parser layer `simple-nms` sits on.
Builds on
[`09-upstream-contributions.md`](09-upstream-contributions.md) —
that doc captures the load-bearing commitments; this one is the
full inventory of nice-to-haves and broader ergonomic improvements
status-checked against the current code.

The `netring` companion is
[`10-upstream-wishlist-netring.md`](10-upstream-wishlist-netring.md).
Capture-side asks live there; this doc covers everything from
`FlowExtractor` upward.

**State as of this writing.** flowscope is at **0.4.0** (its own
`Cargo.toml`; netring 0.14's CHANGELOG confirms the bump). flowscope
0.4 added the periodic `on_tick` hook and the parser-side `ts`
threading; 0.3 added per-key idle timeouts, the structured
`AnomalyKind`, and the reassembler high-watermark fields. All three
shipments closed major chunks of the `des-rs` 2026-05-14 feedback.

Status legend:

- ✅ **Shipped** — confirmed present in current source; we just need
  to use it.
- 🟡 **In flight** — there is plan/feedback paper trail, but the
  code isn't there yet.
- 🔴 **Not yet** — neither shipped nor on a visible roadmap; this
  is a new ask from us.

Each ask carries today's state, what we want, why it matters to
`simple-nms` specifically, a local fallback if the upstream stalls,
and rough sizing.

The general policy stays as in doc 09: **ask upstream when broadly
useful; vendor or wrap locally when specific to our use case or we
can't wait.**

---

## Cross-cutting context: where simple-nms sits in flowscope's pipeline

`flowscope` owns the flow tracker, the TCP reassembler, the L7
parser traits, and the built-in HTTP/1, TLS+JA3, and DNS parsers,
plus sync `FlowDriver` / `FlowSessionDriver` mirrors for offline
use. simple-nms drops into this stack by:

1. Defining a custom `Reassembler` that wraps `BufferedReassembler`
   to produce TCP rich stats (retransmits, RTT, zero-window).
2. Hanging a `FlowRichState` user-state off `FlowTracker<E, S>`
   (TCP rich + UDP burst/silence + per-protocol middleware state).
3. Writing new `SessionParser` / `DatagramParser` impls for RTP,
   RTCP, Zenoh, RTPS, HTTP/2, SIP, and our proprietary protocol.
4. Reading `snapshot_flow_stats()` / `tracker_stats()` on each
   tick for the `metrics/flow` Zenoh payload.

Wishlist asks are scoped to changes that **smooth those four
integration points** without forcing us to fork or re-implement
upstream functionality.

---

## Already shipped — items that doc 09 thought were missing

Worth correcting against the current code so we don't propose
work that is already in tree:

- ✅ **Per-key idle timeouts.** `FlowTracker::set_idle_timeout_fn`
  + `IdleTimeoutFn<K>` type alias (flowscope 0.3, `tracker.rs:528`).
  Exposed through netring's `FlowStream::with_idle_timeout_fn`.
  Closes the per-port / per-protocol idle-timeout gap.

- ✅ **Reassembler high-watermark.**
  `BufferedReassembler::high_watermark` +
  `FlowStats::reassembler_high_watermark_{initiator,responder}` +
  `Reassembler::high_watermark` trait method (flowscope 0.3,
  `reassembler.rs:62`). Sets the bar for tuning
  `max_reassembler_buffer`.

- ✅ **Structured `AnomalyKind`.** `BufferOverflow`,
  `OutOfOrderSegment`, `FlowTableEvictionPressure`,
  `SessionParseError` variants on `AnomalyKind`, plus
  `SessionEvent::Anomaly` forwarding when
  `FlowDriver::with_emit_anomalies(true)`. Implementation in
  `event.rs:147` and `driver.rs`.

- ✅ **Monotonised timestamps.** `with_monotonic_timestamps(true)`
  on `FlowStream` / `SessionStream` / `DatagramStream` in netring
  (netring 0.12 plan 19, `flow_stream.rs:334`). The clamp also
  applies to sweep `now` for time-consistent sweeps.

- ✅ **`with_dedup` on the sync session driver.**
  `FlowSessionDriver::with_dedup(Dedup)` (`session_driver.rs:147`).
  Mirrors the async builder; closes the offline-`lo`-capture
  gotcha.

- ✅ **Round-trip CI fixture and length-prefixed parser
  example.** `flowscope/tests/round_trip.rs` and
  `examples/length_prefixed_pcap.rs` exist; `SESSION_GUIDE.md`
  documents the decision flow. simple-nms's proprietary-protocol
  cookbook can cite these directly.

- ✅ **Periodic `on_tick` on parsers.**
  `SessionParser::on_tick(&mut self, now)` and
  `DatagramParser::on_tick` (flowscope 0.4, `session.rs:120`).
  Drives DNS unanswered-query timeouts; simple-nms uses the same
  hook for RTP/RTCP silence detection, Zenoh keep-alive
  staleness, and SIP transaction expiry.

- ✅ **Parser-side poison surface.** `is_poisoned()` +
  `poison_reason()` on both parser traits, drives
  `EndReason::ParseError` + `AnomalyKind::SessionParseError`.
  Exactly the hook simple-nms needs for the per-dissector
  quarantine list ([`02-architecture.md` §"Parser
  poison"](02-architecture.md#failure-modes-the-spec-doesnt-address)).

- ✅ **`Message: Debug` bound and `tracing-messages` feature.**
  `obs::trace_session_message` exists (`obs.rs:237`); flipping the
  feature on at v1 ship time is a one-line operator change.

These items can all be dropped from any new wishlist conversation
— they exist today.

---

## Tier 1 — the load-bearing three (from doc 09)

These are the items doc 09 commits to. They remain genuinely
missing in flowscope 0.4 and are the highest-priority asks.

### F1.1 — `window: u16` (and optionally `window_scale: Option<u8>`) on `TcpInfo` 🔴

- **Today.** `TcpInfo { flags, seq, ack, payload_offset,
  payload_len }` (`extractor.rs:99`). `ParsedTcp` likewise. No
  TCP window, no TCP options.
- **Ask.**

  ```rust
  pub struct TcpInfo {
      pub flags: TcpFlags,
      pub seq: u32,
      pub ack: u32,
      pub payload_offset: usize,
      pub payload_len: usize,
      pub window: u16,                      // ← new
      pub window_scale: Option<u8>,         // ← new, from SYN options
      // (kept additive; #[non_exhaustive] would protect us further)
  }
  ```

  `window` is one shift away in `parse_from_sliced` — etherparse
  exposes `tcp.window_size()`. `window_scale` requires a small
  TCP options walk on SYN; the value can be cached on
  `FlowEntry` so the reassembler can read it later.
- **Why for us.** Zero-window detection is a v2 deliverable
  ([`04-scope-and-phasing.md`](04-scope-and-phasing.md)).
  Window-scale lets us compute the *effective* advertised
  window (`window << wscale`), which is what TCP throughput
  modelling actually wants. Without `wscale` a 65 535-byte
  effective window on a 10 Gbps link is unreadable.
- **Fallback.** Wrap flowscope's extractor in a simple-nms
  `RichTcpExtractor` that re-parses the TCP header for window
  + options. Code duplication and a second parse pass per
  packet; worth ~3 % CPU on a busy NIC. Doable but ugly.
- **Sizing.** A day for `window`; two more for the SYN-options
  walker and the `wscale` storage on `FlowEntry`. Both
  additive to `#[non_exhaustive] TcpInfo`.

### F1.2 — Segment timestamp on `Reassembler::segment` 🔴

- **Today.** `fn segment(&mut self, seq: u32, payload: &[u8])`
  (`reassembler.rs:21`). Parser data methods already take a
  `ts: Timestamp` (flowscope 0.4); the reassembler hook does
  not.
- **Ask.**

  ```rust
  fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp);
  ```

  Default impl forwards to the current method to keep this
  additive (or just bump the trait's minor; reassemblers are a
  narrow surface). `track_with_payload`'s callback already has
  the view's `ts`; threading it into `payload_cb` is trivial.
- **Why for us.** Karn/Jacobson RTT estimation is a v2
  deliverable. Without a per-segment timestamp on the
  reassembler we can't measure `seq → ack` round-trip in the
  reassembler proper, which is where we'd otherwise track
  in-flight seq numbers.
- **Fallback.** Pass `ts` through a side channel:
  `payload_cb(&key, side, seq, payload, ts)` in our own shim
  before flowscope's, then store an `(seq, ts)` table in our
  reassembler. Already 80 % built — just verbose.
- **Sizing.** Hours, including a `Reassembler::segment_at`
  default that calls `segment` if implementors opt out.

### F1.3 — Notify `Reassembler` on duplicate `seq` 🔴

- **Today.** `BufferedReassembler` silently increments
  `dropped_segments` for any `seq != expected_seq`, conflating
  duplicates (retransmits) with out-of-order arrivals.
- **Ask.**

  ```rust
  /// Optional hook. Default: no-op. Called when the reassembler
  /// has seen `[seq, seq+payload.len())` already in this
  /// direction (a retransmit), instead of (or in addition to)
  /// the existing OOO counter.
  fn duplicate(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {}
  ```

  And/or: introduce a `RetransmitKind` returned by the default
  `BufferedReassembler` and surfaced via a new
  `Reassembler::retransmits()` counter alongside
  `dropped_segments()`.
- **Why for us.** "Did we retransmit?" is one of the most
  important TCP signals we ship, and right now we cannot
  cleanly tell apart a retransmit from a real OOO segment.
- **Fallback.** In our custom reassembler, maintain a
  per-direction `[seq, seq+len)` interval tracker (segment
  tree or sorted vec of `(start, end)`); on each `segment`,
  classify against the tracked set. Adds tens of bytes per
  flow and a small CPU cost; correct, just duplicative work.
- **Sizing.** A day for the trait change + default
  `BufferedReassembler` enhancement, plus tests around
  fast-retransmit and OOO-followed-by-fill.

---

## Tier 1 — additional small wins

### F1.4 — `&mut S` user-state plumbed into parsers 🔴

- **Today.** `FlowTracker::get_mut(&E::Key) -> Option<&mut
  FlowEntry<S>>` is `pub` (`tracker.rs:438`), good. But
  `FlowEntry { stats, state, history, user, initiator_orientation, l4 }`
  has all fields `pub`, including `user: S`. Reads fine, but
  the typical "drive a state machine from the on_tick hook"
  pattern still requires the parser to keep its own per-flow
  lookup table because the tracker is generic over `S`, and
  the *parser* doesn't see the tracker.
- **Ask.** Either:
  - Pass `&mut S` (the per-flow user state) into
    `SessionParser::feed_*` / `DatagramParser::parse`, so the
    parser can mutate the flow's rich-state directly without
    a side-channel.
  - Or document the canonical pattern in `SESSION_GUIDE.md`
    (probably "use `tracker.get_mut(key).unwrap().user`
    inside the consumer-side event loop").
- **Why for us.** simple-nms's rich `TcpRichStats` is updated
  by both the reassembler (TCP path) and the L7 parser
  (middleware path). Threading `&mut FlowRichState` through
  the parser would let us consolidate the state on `FlowEntry`
  without a second `HashMap<K, MwState>` in the middleware
  module.
- **Fallback.** Keep the second map. Acceptable cost, but the
  duplicate-lookup pattern shows up in every middleware
  parser.
- **Sizing.** API change with a moderate ripple. Probably an
  RFC-tier discussion despite the small surface — parser
  generic over `S` is a non-trivial extension.

### F1.5 — Periodic `FlowTick` event 🔴

- **Today.** `FlowStats` only lands on `SessionEvent::Ended`.
  `snapshot_flow_stats()` exists, but you have to poll.
- **Ask.** A new variant on `SessionEvent` / `FlowEvent`:

  ```rust
  // SessionEvent<K, M>:
  FlowTick { key: K, stats: FlowStats, ts: Timestamp },
  // FlowEvent<K>:
  Tick { key: K, stats: FlowStats, ts: Timestamp },
  ```

  emitted by the driver every
  `FlowTrackerConfig::flow_tick_interval` (new field,
  `Option<Duration>`, `None` = disabled, default `None`).
  Per-flow opt-in via the `idle_timeout_fn` shape works too.
- **Why for us.** simple-nms publishes 10-second metric
  snapshots to Zenoh. Today we poll `snapshot_flow_stats()`
  every interval and diff against the previous; a push-based
  `FlowTick` would let us emit metrics with the same wakeup as
  the flow's natural lifecycle and remove the per-tick
  full-table walk.
- **Fallback.** Poll `snapshot_flow_stats()` every
  `metrics_interval`. We're going to do that anyway in v1;
  this is a v2 optimisation.
- **Sizing.** Days. Same shape was floated in
  `des-rs/feedback-2026-05-14`, item 1. Worth coordinating.

### F1.6 — Lazy iterator return type on parser `feed_*` / `parse` 🔴

- **Today.** `feed_initiator` returns `Vec<Self::Message>`.
  Each call allocates and surrenders ownership.
- **Ask.** A GAT-shaped return:

  ```rust
  type Iter<'a>: Iterator<Item = Self::Message> + 'a where Self: 'a;
  fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Self::Iter<'_>;
  ```

  …so messages materialise only as consumed. Keeps the
  reassembled bytes ingested eagerly but defers the parsed
  output.
- **Why for us.** simple-nms's RTPS, HTTP/2, and Zenoh
  dissectors will return *many* small messages per segment
  (a single TCP batch can carry dozens of HTTP/2 HEADERS
  frames). The Vec allocation per call is hot path; lazy
  materialisation cuts that.
- **Fallback.** Push owned `Vec`s; accept the allocation.
- **Sizing.** RFC-tier. The current trait shape is one of
  the simpler aspects of the API; replacing it ripples
  through every shipped parser. Probably v2-of-flowscope.

### F1.7 — Parser identity on `SessionEvent::Application` 🔴

- **Today.** `SessionParserFactory<K>::new_parser(&mut self,
  key: &K)` already passes the key. Useful, but parsers can't
  expose their identity (e.g. "I'm the v1 RTP parser, port
  5004") in events without baking it into `Message`.
- **Ask.** Lift the factory's identity into the events:

  ```rust
  pub struct SessionEvent<K, M> {
      // ...
      Application { key: K, side: FlowSide, parser_kind: &'static str, message: M, ts: Timestamp },
  }
  ```

  Default `parser_kind: ""`; parsers that want to set it
  return a const from a new trait method
  `fn parser_kind(&self) -> &'static str { "" }`.
- **Why for us.** simple-nms's metrics namespace is partly
  derived from the parser (`metrics/rtp/...`,
  `metrics/sip/...`). Today we'd plumb the parser identity
  through `Message` itself; the trait-level approach
  centralises it.
- **Fallback.** Bake the kind into `Message`. Already what we
  do for our own dissectors.
- **Sizing.** Small but `#[non_exhaustive]` on `SessionEvent`
  isn't a free lunch — exhaustive `match` consumers (us) have
  to add an arm.

---

## Tier 2 — Larger asks, propose as RFC first

### F2.1 — Built-in RTP / RTCP `DatagramParser` 🔴

- **Today.** Not provided. simple-nms ships its own in v1
  (`rtp-types` + `rtcp-types`).
- **Ask.** A flowscope `rtp` feature gate that wraps
  `rtp-types` + `rtcp-types` into a `DatagramParser` emitting
  per-SSRC `RtpEvent` + `RtcpReport`. Port hint via factory:
  `RtpFactory::with_ports([16384..=32767])`.
- **Why for us.** Our v1 parser is small but every other
  consumer of flowscope will eventually write the same one.
  Moving it upstream after we've shipped v1 reduces drift and
  lets the gst-plugins-rs orbit get involved.
- **Fallback.** Ship in simple-nms first; propose upstream
  after the parser settles.
- **Sizing.** Two weeks for a polished upstream PR, plus
  bikeshed time on the port-pin API.

### F2.2 — Built-in HTTP/2 `SessionParser` with HPACK desync handling 🔴

- **Today.** Only HTTP/1 is shipped (`http` feature).
- **Ask.** New `http2` feature using `fluke-h2-parse` +
  `fluke-hpack`. Per-direction HPACK decoder, stream table,
  `Anomaly::HttpTwoStateLost` on desync, poison + parser
  reset on irrecoverable error.
- **Why for us.** HTTP/2 + gRPC is v2 for simple-nms. We'd
  ship it locally first ([`08-protocol-coverage.md`
  §HTTP/2](08-protocol-coverage.md#http2--grpc)) but the HPACK
  state machine is exactly the sort of thing every consumer
  should share.
- **Fallback.** Ship in simple-nms (already the plan);
  upstream after stabilisation.
- **Sizing.** Multi-week, primarily because HPACK poisoning
  cases are subtle (truncated continuation, table overflow,
  stream-vs-connection scope confusion).

### F2.3 — RTPS / DDS `DatagramParser` 🔴

- **Today.** Not provided. simple-nms vendors and hardens
  `rtps-parser` for v2.
- **Ask.** `rtps` feature flag built on a hardened
  `rtps-parser` (or a `rtps-parser-fork` if we end up
  vendoring it). Emit per-`(participant, writer)` discovery +
  steady-state events.
- **Why for us.** Same reasoning as F2.1 / F2.2 — once we've
  shipped, upstreaming pays back for every flowscope consumer.
  Risk: the upstream `rtps-parser` is young (v0.1.1), so we
  should land coverage improvements there before proposing the
  flowscope integration.
- **Fallback.** Ship in simple-nms (planned). Upstream-only
  once `rtps-parser` (or our fork) is stable.
- **Sizing.** Multi-week.

### F2.4 — Out-of-order TCP reassembly with hole-fill 🔴

- **Today.** `BufferedReassembler` is in-order only. OOO
  segments are counted and dropped.
- **Ask.** A `SegmentBufferReassembler` (or a knob on
  `BufferedReassembler`) that buffers OOO segments up to a
  per-side cap and emits in-order bytes as holes fill. Empty
  on timeout (per-side deadline) to bound memory.
- **Why for us.** HPACK desync (F2.2) is the canonical case
  where an OOO drop is catastrophic. Today we mark the
  connection un-decodable; with hole-fill we'd recover.
- **Fallback.** Stay in-order-only; document the v2 HTTP/2
  limit as "lossy capture is fatal." That's the current
  position in [`08-protocol-coverage.md`](08-protocol-coverage.md).
- **Sizing.** Multi-week. Reassembly is one of the classic
  CVE surfaces; this is the right size of ask to RFC first.

---

## Tier 3 — Speculative / nice-to-have

- 🔴 **F3.1 — TLS 1.3 0-RTT classification surface.** Right now
  we know "this is a TLS handshake" via the `tls` feature; a
  tiny boolean indicating "0-RTT observed" would let
  simple-nms's Zenoh-on-TLS detection distinguish "TLS
  handshake observed" from "encrypted payload with no
  handshake we saw" (resumption).

- 🔴 **F3.2 — Pluggable extractor for IP-fragment reassembly.**
  Currently `parse_eth` skips fragments. Useful for some encap
  scenarios; not for simple-nms v1/v2 (test platforms rarely
  fragment).

- 🔴 **F3.3 — `FlowExtractor::extract_batch` for SIMD-shaped
  parsers.** Speculative. simple-nms doesn't need it; would
  only matter at 40+ Gbps.

---

## Process

For Tier 1 items (F1.1–F1.3) we should open a single PR per item
with tests when v1 implementation hits the relevant code path. They
are all small enough to land before the upstream maintainer's
review queue gets uncomfortable.

For Tier 2 items, open an issue or RFC discussion first. Where the
upstream chooses to own the implementation, we use the documented
local fallback in this doc until the upstream version lands.

[`09-upstream-contributions.md`](09-upstream-contributions.md)
retains the **commitment list** (what we definitely upstream and
when). This document is the **flowscope inventory** — broader and
includes nice-to-have items we may not end up sending unless
someone else asks for them. netring-side asks live in
[`10-upstream-wishlist-netring.md`](10-upstream-wishlist-netring.md).

As doc 09 already specifies, the team should designate **one
engineer as the upstream liaison** for v1 + v2. The hardest part of
these conversations is consistency across rounds, not the patches
themselves.
