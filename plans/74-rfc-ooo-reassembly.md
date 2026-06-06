# Plan 74 — Out-of-order TCP reassembly with hole-fill

## Summary

Adds an opt-in `SegmentBufferReassembler` — a sibling of
`BufferedReassembler` — that holds out-of-order TCP segments
until the gap fills (bounded by a per-side cap and a per-segment
deadline) instead of dropping them.

The motivating concrete use case is HTTP/2 + HPACK: a lossy
capture today produces an undecodable HTTP/2 stream because
`BufferedReassembler` drops OOO segments and HPACK state desyncs
at the first gap. The same shape applies to any protocol with
cross-segment state machines (DTLS, QUIC, custom binary protocols
with multi-segment headers).

This started as an RFC plan published in 0.5.0; for 0.9.0 the
eight design questions are locked (see "Design decisions" below)
and the plan promotes to an implementation plan.

## Status

**Ready to implement.** Targets 0.9.0 release. The eight design
questions are answered with locked decisions.

## Prerequisites

- Plan 42 (overflow policy + `is_poisoned`) — shipped in
  0.2.0. The new reassembler must integrate with the existing
  `OverflowPolicy` mechanism cleanly.
- Plan 70 (segment timestamps + duplicate detection) —
  prerequisite for the OOO reassembler too. Age-based eviction
  of held segments needs the segment timestamp.

## Out of scope (for this RFC)

- Implementation. We DO want to ship a design doc; we do NOT
  want to start coding before maintainer + simple-nms (and any
  other interested consumers) sign off on the shape.
- IP-layer fragment reassembly (Plan 50.5 territory).
  Unrelated layer; mentioned only to disambiguate.
- A full TCP state machine reimplementation. The new
  reassembler reuses the existing TCP-state plumbing in
  `FlowTracker`; only segment buffering changes.
- Backward-compatibility with `BufferedReassembler`. The new
  type is a *sibling*, not a replacement — users opt in by
  using the new factory.

---

## The use case

### HTTP/2 + HPACK desync

HTTP/2 carries a per-direction HPACK dynamic table state
shared across HEADERS / CONTINUATION frames. A single missed
TCP segment that contains part of a HEADERS frame leaves the
decoder in an unknown state. Subsequent HEADERS frames
decompress to gibberish or trigger HPACK errors.

Today's `BufferedReassembler` drops OOO segments. For HTTP/2,
that's catastrophic: one drop, and the rest of the
connection is undecodable.

The fix is hole-fill: hold OOO segments until the gap fills
(arrived-out-of-order, but the missing piece eventually
arrives — common with NIC queue reordering), or bound the
wait + tear down the flow as a last resort.

### Other cross-segment state

- **DTLS** (datagram TLS) — record-level state is
  per-direction. Less affected (UDP, no reassembly), but
  related.
- **QUIC** — not TCP; out of scope.
- **Custom framed binary protocols** — many internal
  protocols have multi-segment headers. simple-nms's
  proprietary protocol falls here.

### Not in scope

- Reordering across connections (impossible by definition).
- Recovering from a permanent drop. Eventually we give up;
  the design needs to bound the wait.

---

## Constraints

### Memory bounded

Per-side OOO buffer must have a hard byte cap (same shape as
`max_reassembler_buffer`). Default off; users opt in with a
config knob.

### Time bounded

Held segments expire on age. New per-segment timestamps from
Plan 70 enable this — we deadline each held segment and drop
on expiry. Default deadline: 1 second (HTTP/2 connection
keepalive-friendly; tuneable).

### CVE surface awareness

OOO buffering is a classic attack surface:
- **Tiny-fragment attacks** — flood the buffer with 1-byte
  segments to evade detection.
- **Overlap attacks** (RFC 5722 strict mode) — overlapping
  retransmits with conflicting data. Strict-mode drops both;
  loose-mode picks one.
- **Sequence-number wraparound** — TCP seq numbers wrap at
  2^32. Window-based comparisons must be wrap-safe.

The implementation must follow RFC 5722 strict-mode (drop
overlapping conflicting segments) by default. A loose-mode
flag is out of scope.

### Interaction with `OverflowPolicy`

The existing `OverflowPolicy::DropFlow` poisons the
reassembler. The new OOO reassembler must respect this — when
the OOO buffer fills, behaviour should mirror the in-order
case (SlidingWindow drops oldest held bytes; DropFlow poisons).

### Interaction with `Reassembler::on_duplicate` (Plan 70)

A held OOO segment can later be "duplicated" if the same seq
range arrives again before the hole fills. Strict-mode would
drop the duplicate; loose-mode would replace. We pick strict
+ count as a retransmit via `on_duplicate`.

### Stays minimal

The default `BufferedReassembler` keeps its current
in-order-only semantics — it's the right choice for the
80% case (most protocols resync at message boundaries). The
new `SegmentBufferReassembler` is the opt-in choice for
protocols that need hole-fill.

---

## Proposed API shape

### `src/reassembler/segment_buffer.rs` (new file)

```rust
//! `SegmentBufferReassembler` — OOO-tolerant TCP reassembler
//! sibling of [`BufferedReassembler`].

use std::collections::BTreeMap;
use crate::Timestamp;
use crate::event::{FlowSide, OverflowPolicy};

/// Maximum byte count of held OOO segments per side, before
/// the configured [`OverflowPolicy`] kicks in.
const DEFAULT_MAX_OOO_BUFFER: usize = 256 * 1024;  // 256 KiB
const DEFAULT_OOO_DEADLINE_MS: u64 = 1000;          // 1s

pub struct SegmentBufferReassembler {
    /// In-order accumulator (same shape as BufferedReassembler).
    buffer: Vec<u8>,
    expected_seq: Option<u32>,
    /// Held OOO segments, keyed by `seq`. Each entry carries
    /// the payload + the deadline. Sorted by seq so we can
    /// fill holes in order.
    held: BTreeMap<u32, HeldSegment>,
    /// Total bytes currently held in `held` (sum of payload
    /// lens). Cached so we don't walk the map for every cap
    /// check.
    held_bytes: usize,
    /// Counters (mirror BufferedReassembler + add OOO-specific).
    dropped_segments: u64,
    retransmits: u64,
    bytes_dropped_oversize: u64,
    holes_filled: u64,
    holes_expired: u64,
    high_watermark: u64,
    // Config.
    max_buffer: Option<usize>,         // in-order cap
    max_ooo_buffer: usize,             // OOO cap, default DEFAULT_MAX_OOO_BUFFER
    ooo_deadline: std::time::Duration, // age cap on held segments
    overflow_policy: OverflowPolicy,
    poisoned: bool,
}

struct HeldSegment {
    payload: Vec<u8>,
    deadline: Timestamp,  // drop after `now > deadline`
}

impl SegmentBufferReassembler {
    pub fn new() -> Self { /* defaults */ }
    pub fn with_max_buffer(self, max_bytes: usize) -> Self;
    pub fn with_max_ooo_buffer(self, max_bytes: usize) -> Self;
    pub fn with_ooo_deadline(self, deadline: std::time::Duration) -> Self;
    pub fn with_overflow_policy(self, policy: OverflowPolicy) -> Self;

    pub fn take(&mut self) -> Vec<u8>;
    pub fn holes_filled(&self) -> u64;
    pub fn holes_expired(&self) -> u64;
    // (Plus the existing diagnostic accessors.)
}

pub struct SegmentBufferReassemblerFactory {
    // mirrors BufferedReassemblerFactory's config storage
}

impl<K: Send + 'static> ReassemblerFactory<K>
    for SegmentBufferReassemblerFactory
{
    type Reassembler = SegmentBufferReassembler;
    fn new_reassembler(&mut self, _key: &K, _side: FlowSide)
        -> SegmentBufferReassembler { /* ... */ }
}
```

### Behaviour sketch

```rust
impl Reassembler for SegmentBufferReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        if payload.is_empty() || self.poisoned { return; }
        let expected = match self.expected_seq {
            None => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_with_cap(payload);
                return;
            }
            Some(exp) => exp,
        };
        if seq == expected {
            // In-order — append, then try to merge held
            // segments that now fit.
            self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
            self.append_with_cap(payload);
            self.try_fill_holes();
        } else if seq_lt(seq.wrapping_add(payload.len() as u32), expected) {
            // Fully behind expected — retransmit.
            self.retransmits += 1;
        } else if seq_lt(expected, seq) {
            // Ahead of expected — OOO. Hold.
            self.try_hold(seq, payload, ts);
        } else {
            // Partial overlap with expected — treat as
            // retransmit (we already have those bytes in the
            // in-order buffer or already-acked stream).
            self.retransmits += 1;
        }
    }
    // ... other trait methods ...
}

impl SegmentBufferReassembler {
    /// Walk held segments in seq order; drain any that now
    /// continue from `expected_seq`.
    fn try_fill_holes(&mut self) {
        let mut expected = self.expected_seq.unwrap();
        let mut to_remove = Vec::new();
        for (&seq, held) in self.held.range(expected..) {
            if seq != expected { break; }  // gap remains
            self.append_with_cap(&held.payload);
            self.held_bytes -= held.payload.len();
            expected = expected.wrapping_add(held.payload.len() as u32);
            self.expected_seq = Some(expected);
            self.holes_filled += 1;
            to_remove.push(seq);
        }
        for seq in to_remove { self.held.remove(&seq); }
    }

    fn try_hold(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        // Cap check.
        let projected = self.held_bytes + payload.len();
        if projected > self.max_ooo_buffer {
            match self.overflow_policy {
                OverflowPolicy::DropFlow => {
                    self.poisoned = true;
                    self.bytes_dropped_oversize += payload.len() as u64;
                    return;
                }
                OverflowPolicy::SlidingWindow => {
                    // Drop oldest held segments until the new one fits.
                    while self.held_bytes + payload.len() > self.max_ooo_buffer {
                        let Some((&oldest_seq, _)) = self.held.iter().next() else { break };
                        let dropped = self.held.remove(&oldest_seq).unwrap();
                        self.held_bytes -= dropped.payload.len();
                        self.bytes_dropped_oversize += dropped.payload.len() as u64;
                    }
                }
            }
        }
        // RFC 5722: drop overlapping (strict mode).
        if self.held.contains_key(&seq) {
            // Duplicate held seq — strict-mode drop.
            self.retransmits += 1;
            return;
        }
        self.held.insert(seq, HeldSegment {
            payload: payload.to_vec(),
            deadline: ts + self.ooo_deadline,
        });
        self.held_bytes += payload.len();
    }

    /// Called periodically (driver-side `on_tick`-shaped hook,
    /// or just opportunistically before each `segment` call)
    /// to expire stale held segments.
    pub fn expire_at(&mut self, now: Timestamp) {
        let mut to_remove = Vec::new();
        for (&seq, held) in &self.held {
            if held.deadline < now {
                to_remove.push(seq);
            }
        }
        for seq in to_remove {
            let dropped = self.held.remove(&seq).unwrap();
            self.held_bytes -= dropped.payload.len();
            self.holes_expired += 1;
            self.bytes_dropped_oversize += dropped.payload.len() as u64;
        }
        // If a held segment expired, in-order forward progress
        // is impossible — poison the flow so the driver tears
        // it down.
        if !to_remove.is_empty() && !self.held.is_empty() {
            // Heuristic: if anything timed out, we have a
            // permanent gap. Poison.
            self.poisoned = true;
        }
    }
}
```

### Driver integration

Two options:

- **Option A — explicit driver call.** The driver calls
  `expire_at(now)` on each `on_tick` interval (Plan 71's
  `flow_tick_interval`). Requires the reassembler trait to
  gain a `tick_at(&mut self, now: Timestamp)` method (default
  no-op).
- **Option B — opportunistic.** `expire_at` runs at the top
  of every `segment()` call using the incoming `ts`. No new
  trait surface; cost is one BTreeMap walk per segment.

**Recommendation: Option B**, with consideration of caching
the next-deadline to avoid the walk when no expiry is due.
Cleaner integration.

---

## Design decisions

All eight Qs from the RFC phase are now locked for the 0.9 cycle.
Implementation proceeds directly against these picks.

1. **Default OOO cap: 256 KiB per side.** Tuneable via
   `SegmentBufferReassembler::with_max_ooo_buffer(bytes)`. Sized
   for HTTP/2-with-modest-reorder; HFT-style traffic profiles can
   raise. Documented in rustdoc + `docs/concepts.md`.
2. **Default deadline: 1 second.** Tuneable via
   `with_ooo_deadline(Duration)`. The window is the *"this
   capture is broken"* threshold — operationally calibrated
   against the HTTP/2 ping interval (~10s) and real-world
   reorder-buffer depths.
3. **Strict overlap (RFC 5722).** Conflicting overlapping
   segments → first kept, second classified as retransmit (via
   the existing `on_duplicate` hook). Loose mode is **out of
   scope**; fork the type if you need it.
4. **Poison on expiry.** When a held segment's deadline passes
   without the hole filling, the reassembler poisons. The driver
   tears the flow down with `EndReason::BufferOverflow` (existing
   shape — no new `EndReason` variant). Rationale: consumers who
   opted into OOO reassembly want strict semantics.
5. **Anomaly emission via existing per-tick delta pattern.** Two
   new `AnomalyKind` variants: `OutOfOrderHoleFilled { side,
   count }` and `OutOfOrderHoleExpired { side, count }`. Counts
   accumulate; emission is per-tick delta-coalesced via the
   existing `FlowDriver::with_emit_anomalies(true)` path.
   Consistent with retransmit / OOO-drop anomalies (plan 70).
6. **No `Reassembler::tick_at(now)` trait expansion.**
   Opportunistic expiry inside `segment()` is sufficient; periodic
   maintenance happens lazily on the next packet. Defer the trait
   change unless a second consumer surfaces a need.
7. **OOO config lives on the factory, not `FlowTrackerConfig`.**
   `BufferedReassemblerFactory` and the new
   `SegmentBufferReassemblerFactory` are the configuration
   surface. `FlowTrackerConfig` stays focused on tracker-level
   knobs. Avoids forcing `FlowTrackerConfig` toward
   reassembler-polymorphism.
8. **`FlowStats` field surface.**
   - Existing `reassembly_dropped_ooo_*` keeps its meaning
     (OOO segments dropped because the reassembler couldn't
     hold them — applies to both the legacy in-order reassembler
     and the new segment-buffer one).
   - New: `reassembly_holes_filled_*`, `reassembly_holes_expired_*`.
   - Same per-side `_initiator` / `_responder` pattern as the
     existing fields.

---

## Implementation steps (DEFERRED — sketch only)

Not for 0.5.0. Sketched here so the RFC reader can size the
effort:

1. **Open RFC issue** linking this plan; tag maintainers +
   `simple-nms` team + any HTTP/2-consumer team that surfaces.
   Solicit answers to the open questions.
2. **Settle the open questions** in the RFC thread. Update
   this plan with the agreed-upon answers.
3. **Implementation: split into sub-plans.** Sketch:
   - 74a: `SegmentBufferReassembler` core (no overflow / no
     expiry). Hole-fill via `try_fill_holes`. Basic tests.
   - 74b: Overflow policy integration. Cap + sliding-window /
     drop-flow.
   - 74c: Age-based expiry. `expire_at` opportunistically
     called from `segment()`.
   - 74d: FlowStats / AnomalyKind / metrics integration.
   - 74e: Hardening — strict overlap, fuzz / proptest, CVE
     surface tests.
4. **Reference consumer.** Land at least one shipped or
   blessed consumer using the new reassembler before declaring
   it stable. HTTP/2 in flowscope itself (if F2.2 progresses)
   is the natural candidate.
5. **Performance evaluation.** Criterion benches for the OOO
   reassembler. Compare in-order-throughput against
   `BufferedReassembler` (should be the same — OOO path is
   only taken when needed). Target ≤10 % regression on the
   common path.

---

## Tests (DEFERRED — design sketch)

Test categories the implementation will need:

- **Hole-fill correctness**: seq order A B C with B arriving
  last — final buffer is ABC.
- **OOO cap + sliding window**: many small OOO segments
  exceed cap, oldest dropped.
- **OOO cap + drop-flow**: cap exceeded → poison →
  `EndReason::BufferOverflow` synthesised.
- **Age expiry**: held segment with deadline in the past on
  the next `segment()` call is expired + poison if there are
  others still held.
- **Strict overlap (RFC 5722)**: two segments with same seq
  + different payloads → first held, second dropped + counted
  as retransmit.
- **Seq wraparound**: segments straddling 2^32 boundary
  reassemble correctly.
- **Tiny-fragment attack**: 1-byte OOO segments fill the cap;
  resource accounting is correct.
- **Fuzz harness**: random seq + len + ts triples + cap +
  policy. Invariants: no panic, no infinite loop, in-order
  output is a contiguous subsequence of the input concatenated
  in order, no double-count between dropped/retransmit/holes-
  filled/holes-expired.

---

## Acceptance criteria (FOR THIS RFC PLAN)

- [ ] This file exists at `plans/74-rfc-ooo-reassembly.md`.
- [ ] An RFC issue links to it.
- [ ] Open questions are surfaced; no answers yet.
- [ ] Reference consumers (simple-nms team, des-rs team if
      interested) have at least responded with a thumbs up or
      a substantive question.
- [ ] CHANGELOG mentions the RFC under 0.5.0 "Planning" or
      similar — explicitly NOT under "Shipped."

(Acceptance criteria for the implementation will be defined
in 74a–74e once the RFC settles.)

---

## Risks

1. **RFC stalls.** Without a maintainer-with-bandwidth
   champion, the RFC can sit for months. Mitigation: tie the
   RFC to a concrete consumer milestone — `simple-nms`'s
   HTTP/2 v2 work or `des-rs`'s next iteration.
2. **Scope creep.** OOO reassembly attracts every "what if we
   also..." question. Keep the scope to "in-order resync
   after OOO drops"; defer SACK, advanced retransmit
   detection, etc.
3. **CVE surface.** Reassembly is a classic attack surface.
   Even with RFC 5722 strict mode, we'll need a fuzz harness
   before declaring stable. Cost: ~1 week beyond the
   functional implementation.
4. **`Reassembler` trait surface.** The current trait is
   narrow; adding `tick_at` (Option A) or other methods
   bloats it. The Option B opportunistic-expiry sidesteps
   this; ship Option B unless someone proves Option A is
   needed.
5. **Performance.** The BTreeMap of held segments is `O(log
   n)` per insert and `O(log n + k)` per `try_fill_holes`.
   For typical workloads (held segments ≤ 10) the cost is
   negligible; pathological cases would hit the cap and bail.
   Verify with criterion.

---

## Effort

**Implementation effort (deferred):**

- LOC: ~600 source (SegmentBufferReassembler + factory +
  integration) + ~400 tests + ~200 fuzz harness.
- Time: 3–4 weeks of focused work, including RFC iteration.

**RFC effort (this plan):**

- LOC: ~0 source (RFC is design + this doc).
- Time: ½ day to file the issue + invite reviewers, plus
  whatever discussion takes (typically 2–4 weeks of
  back-and-forth for this kind of design).

---

## Provenance

The original ask came from the `simple-nms` upstream wishlist as
item F2.4. That wishlist correctly tagged the ask as "RFC-tier"
and "right size of ask to RFC first." This plan operationalises
that tag — we shipped the RFC in 0.5.0 so the conversation is in
flight; implementation has been deferred past 0.8.0 pending
reviewer agreement on the design questions above.

The HTTP/2 use case provides a concrete reference protocol;
if `simple-nms`'s v2 work commits to HTTP/2, that becomes
the de facto reference consumer for the implementation.
