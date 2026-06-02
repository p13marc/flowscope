# Plan 75 — RFC: `FlowTracker::with_auto_sweep(interval)`

## Summary

**This is an RFC plan, not an implementation plan.** It scopes
the design space for an optional packet-clock-driven sweep mode
on `FlowTracker`, identifies the load-bearing design questions,
and articulates the cross-API interactions that need answers
before implementation can start.

Implementation is **not in scope for 0.7.0**. Expected landing:
0.8.0 or later, after the RFC drives a maintainer + consumer
agreement on the design.

The motivating case is online-vs-offline divergence in the same
pipeline: live capture today has a wall-clock sweep tick
(`tokio::time::interval` in netring); offline pcap replay has no
such tick. Identical traffic on identical config emits different
event streams between the two paths because mid-stream
idle-timeouts fire live but not offline. The netring author
called this out in
[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
§2 as one of the two items they explicitly flagged as
"deserves its own RFC."

The 0.5.0 release shipped `flow_tick_interval` for periodic
`FlowEvent::Tick` events (plan 71). This RFC is the *sister*:
periodic sweep cadence, not periodic tick emission. The two
features have similar timing surfaces; they must compose cleanly.

## Status

**RFC scope only.** Targets 0.7.0 release as a published RFC;
implementation deferred to 0.8.0+.

## Prerequisites

- **Plan 71** (`flow_tick_interval` + `FlowEvent::Tick`) —
  shipped in 0.5.0. The packet-clock semantics in `FlowDriver`
  (`last_tick_at` + `mark_ticked`) establish the precedent for
  "the tracker knows about its own internal timing." Auto-sweep
  is the natural extension of that pattern.
- **Plan 38** (driver `S` restore via split constructors) —
  shipped in 0.6.0. Per-flow state is back on the drivers; this
  RFC must not regress that.
- **Plan 1** (`sweep_with_parsers`) — shipped in 0.6.0. The
  helper bakes the on_tick → sweep → fin choreography into the
  tracker. Auto-sweep must invoke the same choreography when it
  fires implicitly.
- **Monotonic-timestamp prereq** (`FlowTracker::with_monotonic_timestamps`)
  — already shipped. Auto-sweep needs predictable timestamp
  ordering; the monotonic mode is the obvious safe default for
  consumers that want auto-sweep + offline parity.

## Out of scope (for this RFC)

- Implementation. The point of this document is to surface the
  design questions, not to pre-commit to a shape.
- Replacing the existing explicit `sweep(now)` entry point.
  Auto-sweep is **additive** and opt-in; manual sweep stays as
  the primary surface.
- Wall-clock auto-sweep. Wall-clock belongs in netring (the
  async-runtime crate); this RFC is for packet-clock semantics
  only. The whole point of the proposal is that the tracker
  becomes runtime-free even for periodic work.
- Auto-tick (`FlowEvent::Tick` is already auto-emitted by the
  driver when `flow_tick_interval` is set; this RFC is for
  *sweep*, which is heavier and triggers `Ended` events).
- A new event variant. The implicit-sweep return path is the
  one load-bearing API decision in this RFC, but it does not
  add a new variant — see §4.

---

## The use case

### Live vs offline divergence

`netring::FlowStream` (live AF_PACKET) and `netring::PcapFlowStream`
(offline pcap) share the same `flowscope::FlowTracker` core. They
differ in their sweep cadence:

- **Live** uses `tokio::time::interval(d)` to fire
  `tracker.sweep(now)` every `d` seconds, where `now` is the
  wall clock.
- **Offline** has no timer. The only sweep call is at EOF
  (effectively `tracker.finish()`). Mid-stream idle-timeout-driven
  `Ended` events never fire — every flow lives until EOF.

For an idle-timeout-sensitive pipeline (most NMS use cases — flow
counts, DNS query/response correlation), the same pcap produces
different flow-end timing live vs offline. Operators debugging
captures cannot trust "what the live system would have seen."

### Why it's a flowscope concern, not a consumer concern

Three reasons:

1. **Every consumer needs the same fix.** netring, des-rs,
   simple-nms, any custom consumer all need a way to drive
   sweeps from packet-clock advancement. Solving it once in the
   tracker beats N copies in N consumers.
2. **The tracker is the only authoritative source.** Only
   `FlowTracker` knows when its last sweep ran. Consumers
   tracking `last_sweep_ts` externally are duplicating state
   that's already on the tracker.
3. **`flow_tick_interval` (plan 71) already established the
   precedent.** The tracker already knows about its own internal
   timing for ticks; sweep cadence is the same shape.

### Other affected consumers

- **simple-nms** explicitly flagged offline-pcap idle-timeout
  parity in their wishlist (`docs/feedback-2026-08-11-simple-nms.md`).
  Same concern, different framing.
- **des-rs** offline replay has the same issue (per
  `docs/feedback-2026-05-14-des-rs.md`).

### Not in scope for the use case

- Forcing sweep cadence on every pipeline. Live capture today is
  fine with `tokio::time::interval` — that path doesn't need to
  migrate. Auto-sweep is for pipelines that want a *single
  timing model* across live + offline.
- Replacing the explicit `sweep(now)` entry point. Consumers
  that want fine-grained sweep timing keep manual control.

---

## Design questions

These are the questions the implementation has to answer. Each
has an opinion attached but the RFC explicitly invites
disagreement before any code lands.

### Q1: How does auto-sweep emit `FlowEvent`s?

**The hard question.** `tracker.track(view)` today returns a
`Vec<FlowEvent>`. An implicit sweep produces *more* events
(potentially many `Ended` events) that need to surface to the
caller. Three candidate shapes:

**Option A: Merge into the existing return value.**
`track(view) -> Vec<FlowEvent>` includes both per-packet events
AND any implicit-sweep events synthesised by the auto-sweep
cadence check.

- ✅ Zero new API surface. Drop-in for consumers.
- ✅ Natural fit with the existing per-tick-batch model.
- ⚠️ One `track()` call can now emit dozens of `Ended` events
  if many flows time out at once — surprising for consumers
  expecting "one packet → bounded events."
- ⚠️ Slightly breaks the "tracker is reactive, never spontaneous"
  mental model.

**Option B: Separate accessor.** `track(view) -> Vec<FlowEvent>`
returns per-packet events only; `tracker.drain_pending_sweeps()`
returns auto-sweep events. Consumer calls both each loop.

- ✅ Preserves "tracker is reactive" model.
- ❌ Re-introduces the discoverability problem item 1
  (`sweep_with_parsers`) just fixed: consumers can forget to
  drain.
- ❌ Splits the event stream into two paths the consumer must
  merge anyway.

**Option C: Inverted control flow with a callback.**
`tracker.with_auto_sweep(interval, |evt| ...)` — caller registers
a sink. Auto-sweep events flow through it.

- ❌ Callback-style API doesn't compose with the iterator-based
  driver event loops netring uses.
- ❌ Inconsistent with the rest of flowscope's API.

**Tentative pick:** **Option A**, with a clear note in the
rustdoc and CHANGELOG that opting into auto-sweep changes the
event-rate shape. The "tracker is reactive" model bends but
doesn't break: the trigger is still a `track()` call, just with
fan-out semantics.

### Q2: When does the auto-sweep check fire?

Two candidates:

**Option I: After every `track()` call.** Cheap when packets are
sparse (sweep fires occasionally); expensive when packets are
dense (interval check per packet, ~ns/check).

**Option II: After every Nth `track()` call.** Amortizes the
check; introduces sweep-cadence jitter proportional to N.

**Tentative pick:** **Option I.** The check is a single
timestamp compare and a branch — negligible at the per-packet
level. Plan 71's `flow_tick_interval` check already uses Option
I for the same reason. Consistency wins.

### Q3: What timestamp does the implicit sweep use?

The packet that triggered the check carries its own timestamp.
That timestamp is "now" from the tracker's packet-clock
perspective. So:

```text
implicit_sweep_ts = packet.timestamp
```

This is the standard packet-clock convention. The plan 71 tick
emission already uses it. No design choice to make here — the
RFC just notes it for completeness.

### Q4: How does auto-sweep interact with out-of-order packet timestamps?

A real risk: pcap streams are not guaranteed monotonic. Two
packets `p_a (ts=100)` and `p_b (ts=99)` in arrival order would
trip an auto-sweep at ts=100, then a `track(p_b)` would have
"now" go backwards relative to the last sweep.

**Three mitigations:**

1. **Require monotonic timestamps.** Auto-sweep is only available
   when `with_monotonic_timestamps(true)` is also set.
   `with_auto_sweep` without monotonic-timestamps either panics
   or silently ignores backwards `now`s.
2. **Saturating last-sweep.** `last_sweep_ts =
   max(last_sweep_ts, packet.ts)`. Out-of-order packets don't
   *cause* sweeps but also don't move the clock backwards.
3. **Honour the backwards step.** Treat `now < last_sweep_ts` as
   an intentional rewind — sweep again "going forward" from the
   new `now`. (Very unusual; not recommended.)

**Tentative pick:** **#1 + #2 combined.** Require monotonic
timestamps as a documented prerequisite (compile-time would be
ideal but the type-system overhead isn't worth it); under the
hood, use the saturating-last-sweep guard as a belt-and-braces
safety net for any consumer that ignores the doc.

### Q5: Does auto-sweep also drive `flow_tick_interval`?

Plan 71's flow ticks are *opt-in via* `flow_tick_interval`. They
fire from the driver, not the tracker (`FlowDriver::emit_ticks`
in `driver.rs:329`). Auto-sweep on the tracker would not
automatically synthesise ticks.

**Two shapes:**

**A.** Auto-sweep fires sweeps only. Tick emission stays on the
driver. Direct-tracker consumers get sweeps but no ticks (same
as today).

**B.** Auto-sweep also emits ticks. The tracker grows a
`tick_dispatch` method, the driver delegates to it, and direct
consumers get the same behaviour.

**Tentative pick:** **A** for the initial implementation. The
two features are independent (tick is informational; sweep is
state-changing). Coupling them upfront is premature. If
consumers ask for "auto-sweep + auto-tick", do it as a
follow-up.

### Q6: Does auto-sweep compose with `sweep_with_parsers`?

`sweep_with_parsers` (plan 1, shipped 0.6) bakes the on_tick →
sweep → fin choreography. If the tracker auto-sweeps internally,
who runs the `on_tick`/`fin_*` calls on the parsers?

**The parser map lives on the consumer, not the tracker.** The
tracker can't fire `on_tick` itself because it doesn't own the
parsers. So auto-sweep on the tracker can only synthesise sweep
*events*, not run parser-driven side effects.

**Resolution:** The implementation needs to surface this
clearly. Two API shapes:

**A.** `tracker.track(view)` returns sweep events; consumers
that want parser-aware auto-sweep call
`tracker.track_with_parsers(view, &mut parsers, on_message)` —
mirroring `sweep_with_parsers`. The parser-aware variant runs
`on_tick` on every flow before the auto-sweep fires; sweep
events come back in the return value alongside per-packet
events.

**B.** `tracker.track(view)` returns sweep events; consumers
running parsers manually call
`tracker.sweep_with_parsers(now, ...)` after every `track()`
to mop up. Auto-sweep on the tracker is for direct-tracker
consumers that *don't* run parsers.

**Tentative pick:** **A.** Mirrors the existing
`sweep_with_parsers` shape. The `track_with_parsers` name flags
clearly that auto-sweep is happening in the call.

### Q7: What's the default value, and is the type required?

The proposal text said `with_auto_sweep(interval: Duration)`.
Two follow-ups:

- Is the type `Duration` or a sentinel? The 0.5.0
  `flow_tick_interval: Option<Duration>` precedent is
  `None = disabled`, which is the natural fit. So:
  `pub fn with_auto_sweep(mut self, interval: Option<Duration>) -> Self`
  with `None` resetting back to off (useful for tests / dynamic
  reconfig). Or, simpler, the builder takes `Duration` and the
  field is `Option<Duration>` set by the builder.
- Default: `None` (off). Matches `flow_tick_interval` semantics.

---

## Constraints

### Memory bounded

No new memory per flow. Auto-sweep only needs a single
`last_sweep_ts: Option<Timestamp>` on `FlowTrackerConfig` /
`FlowTracker`. The check is O(1); the actual sweep is the existing
sweep machinery.

### Time bounded

Same as Q2: per-packet check is O(1). The sweep itself iterates
live flows — same cost as a manual sweep. No new amortization
question.

### Compatibility with existing sweep call

Manual `tracker.sweep(now)` stays. Auto-sweep is opt-in; it
**resets** the `last_sweep_ts` when the consumer explicitly
sweeps. (Otherwise, consumers mixing manual + auto sweep would
see surprising double-fires.) Documented as part of the API.

### Compatibility with `tokio::time::interval`

netring's live `FlowStream` currently sweeps on a wall-clock
timer. If `with_auto_sweep` is on, the wall-clock timer becomes
redundant — netring would drop it. **But:** if the packet
arrival rate is very low (sparse capture), wall-clock sweep
would still fire while packet-clock sweep would not, leaving
flows in `FlowState::Established` longer than expected.

**This is a feature, not a bug.** Packet-clock semantics
inherently couple time advancement to packet arrival. Consumers
that want strict wall-clock sweep timing keep using
`tokio::time::interval`. The RFC notes this prominently.

---

## Proposed API shape

The RFC pins one minimum shape so the discussion has something
concrete to react to. Variants are explicitly invited.

### `src/tracker.rs` additions

```rust
impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    /// Enable packet-clock-driven implicit sweeps.
    ///
    /// After each [`track`](Self::track) /
    /// [`track_with_payload`](Self::track_with_payload) call,
    /// if `view.timestamp.saturating_sub(last_sweep_ts) >= interval`,
    /// run an implicit sweep and merge its events into the
    /// returned `Vec<FlowEvent>`.
    ///
    /// Off by default. Pairs naturally with
    /// [`with_monotonic_timestamps`](Self::with_monotonic_timestamps):
    /// without monotonic timestamps, backwards packet times are
    /// guarded against via a saturating last-sweep timestamp.
    ///
    /// Manual [`sweep`](Self::sweep) calls reset
    /// `last_sweep_ts`, so mixing manual + auto sweep is safe
    /// (no double-fires).
    pub fn with_auto_sweep(mut self, interval: Duration) -> Self {
        // …
    }

    /// Parser-aware track. When auto-sweep fires, runs `on_tick`
    /// on every live parser before the sweep, then `fin_*` on
    /// parsers for ending flows. Same choreography as
    /// [`sweep_with_parsers`].
    #[cfg(feature = "session")]
    pub fn track_with_parsers<P, F, H>(
        &mut self,
        view: PacketView<'_>,
        parsers: &mut HashMap<E::Key, P, H>,
        on_message: F,
    ) -> Vec<FlowEvent<E::Key>>
    where
        P: SessionParser,
        F: FnMut(&E::Key, FlowSide, P::Message, Timestamp),
        H: BuildHasher,
    {
        // …
    }
}
```

Mirror on the datagram side:
`track_with_datagram_parsers`.

### `FlowTrackerConfig` addition

```rust
pub struct FlowTrackerConfig {
    // …existing fields…

    /// When `Some(d)`, the tracker runs an implicit sweep after
    /// each `track()` call if `view.ts - last_sweep_ts >= d`.
    /// `None` (default) — sweeps only fire on explicit
    /// [`FlowTracker::sweep`] / [`FlowTracker::finish`] calls.
    ///
    /// Companion to [`flow_tick_interval`](Self::flow_tick_interval),
    /// which controls per-flow tick *emission*; this field
    /// controls *sweep cadence*. The two features are
    /// independent.
    pub auto_sweep_interval: Option<Duration>,
}
```

### Driver changes

Drivers transparently inherit the auto-sweep behaviour via
their existing `tracker_mut()` access. The driver-level
`sweep_with_parsers` choreography is the same; auto-sweep just
fires the sweep earlier sometimes.

Existing tests of `track()` + manual `sweep()` keep passing
because `auto_sweep_interval` defaults to `None`.

---

## What would need to change in netring

If this lands as proposed, netring 0.16's adapters would simplify:

- `PcapFlowStream::poll_next` drops its explicit "sweep at EOF
  only" comment and pretends it's `FlowStream` — same code path.
- `FlowStream::poll_next` drops `tokio::time::interval` (or
  documents that it's now redundant when `auto_sweep_interval`
  is set and recommends the tracker-side config).
- Both adapters use `tracker.track_with_parsers(view, &mut
  parsers, |...|)` instead of the separate
  `tracker.track(view)` + `sweep_with_parsers` calls. Cleaner
  single entry point.

netring would not be *forced* to migrate — the existing manual
sweep path still works. But the recommended pattern shifts.

---

## Acceptance criteria for THIS RFC (not the implementation)

- The maintainer (me) and the netring author both agree on the
  answers to Q1–Q7 (or document where they disagree explicitly).
- simple-nms maintainer reviews the design (they're the other
  affected consumer who would benefit from offline-pcap parity).
- The API shape is concrete enough that an implementation plan
  can be written without re-arguing the design.
- The implementation plan (whoever picks it up) can be written
  in <2 hours from this RFC.

---

## Open questions for reviewers

Phrased as questions reviewers should answer in PR comments /
issues:

1. **Q1 (event surface):** option A, B, or C? Or something
   else?
2. **Q4 (out-of-order):** is the monotonic-timestamp
   prerequisite acceptable, or should we ship without it and
   accept the corner case?
3. **Q6 (parser choreography):** is the
   `track_with_parsers` second entry point a worthy expansion,
   or should we tell consumers to manage parsers themselves
   after auto-sweep events?
4. **General:** is "packet-clock semantics" the right framing,
   or should we widen scope to "tracker-driven timing" more
   generally (which would include monotonic timestamps, flow
   ticks, and sweep cadence as one coherent feature surface)?

---

## Effort

**For the RFC itself** (this document): ~600 lines, ~3 hours.
Includes reading existing related plans (60, 71, 74) for shape
consistency.

**For the implementation** (deferred — not in this plan):

- API plumbing on `FlowTracker` + `FlowTrackerConfig`: ~60 LoC,
  1 hour.
- `track_with_parsers` / `track_with_datagram_parsers`: ~80
  LoC, 1.5 hours.
- Tests (unit + cross-pipeline parity test): ~150 LoC,
  3 hours.
- Doc updates (`SESSION_GUIDE.md`, OBSERVABILITY.md): ~30 lines,
  1 hour.
- **Implementation total:** ~6.5 hours, ~320 LoC.

## Provenance

The netring author flagged this as one of two items deferred
from the 0.6 cycle for "deserves its own RFC" status (the other
being item 6, which we resolved by shipping option A in plan
38). See `docs/feedback-2026-05-22-netring.md` §2 + the
"What I'd ship first" section.

The simple-nms wishlist
(`docs/feedback-2026-08-11-simple-nms.md`) raised the same
underlying problem — online/offline divergence — from a
different angle. Two independent consumers asking for related
fixes is the threshold this RFC was waiting for.

Target landing for the RFC: 0.7.0 (next minor). Target landing
for the implementation: 0.8.0, contingent on reviewer agreement
on the design questions above.
