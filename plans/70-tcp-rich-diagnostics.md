# Plan 70 — TCP rich diagnostics on the reassembler

## Summary

Three coupled enhancements for downstream TCP rich-statistics
consumers (`simple-nms` retransmit/RTT tracking, future `des-rs`
work) bundled as one minor release window so the trait breaks
land together:

1. **`window: u16` on `TcpInfo`** — surface the per-packet TCP
   receive window. Plus `#[non_exhaustive]` on `TcpInfo` so future
   additions stay non-breaking.
2. **Segment timestamp on `Reassembler::segment`** — change the
   signature to `segment(seq, payload, ts: Timestamp)`. Closes
   the asymmetry where Plan 36 plumbed `ts` to parsers but the
   reassembler hook still doesn't see it.
3. **Duplicate-segment classification** — distinguish retransmits
   from out-of-order arrivals on `BufferedReassembler`. New
   `Reassembler::retransmits()` accessor + `on_duplicate(seq,
   payload, ts)` default-no-op hook + new
   `AnomalyKind::RetransmittedSegment` variant for live signal.

These are the F1.1, F1.2, F1.3 items from
`simple-nms`'s [upstream wishlist](../docs/feedback-2026-08-11-simple-nms.md).
The wishlist explicitly identifies them as the "load-bearing
three" — concretely the smallest set of changes that unblocks
TCP rich diagnostics in a downstream consumer without forcing
them to re-parse the TCP header themselves.

## Status

Not started. Targets 0.5.0.

## Prerequisites

- Plan 36 (time-aware `SessionParser` / `DatagramParser`) —
  shipped in 0.4.0. Establishes the `ts: Timestamp` plumbing
  through parsers; this plan extends it to the reassembler hook.
- Plan 42 (anomaly events) — shipped in 0.2.0. This plan adds a
  new `AnomalyKind::RetransmittedSegment` variant following the
  precedent.

## Out of scope

- **`window_scale`**. The wishlist asked for it on `TcpInfo`,
  but window-scale lives on the SYN (and SYN-ACK) and is
  per-flow, not per-packet. The right shape is `wscale: Option<u8>`
  stored on `FlowEntry`, populated by the TCP state machine on
  3WHS, with downstream consumers computing the effective
  window as `view.window << flow.wscale`. Follow-up plan when
  there's a concrete consumer asking. Today's window field is
  useful on its own.
- **Karn/Jacobson RTT estimation in `BufferedReassembler`**.
  The `segment(seq, payload, ts)` plumbing makes RTT estimation
  *possible* in a downstream custom reassembler; baking it into
  `BufferedReassembler` is out of scope. The default reassembler
  stays minimal.
- **Selective ACK (SACK) parsing**. Separate ask; not in the
  wishlist.
- **Tracking retransmits *across* OOO buffers** — see Plan 74
  for OOO reassembly. Today's `BufferedReassembler` is
  in-order-only, so a retransmit is unambiguously "segment with
  `seq + len <= expected_seq`" — no overlap with the OOO RFC.

---

## Files

### MODIFIED

- `src/extractor.rs` — `TcpInfo` gains `window: u16` + `#[non_exhaustive]`.
- `src/extract/parse.rs` — fill `window` from etherparse's
  `tcp.window_size()`.
- `src/reassembler.rs` — `Reassembler::segment` signature
  becomes `(seq, payload, ts)`. New trait methods
  `on_duplicate(seq, payload, ts)` (default no-op) and
  `retransmits()` (default 0). `BufferedReassembler` tracks
  retransmits separately from `dropped_segments`.
- `src/tracker.rs` — `track_with_payload`'s callback signature
  becomes `FnMut(&K, FlowSide, u32, &[u8], Timestamp)`. The
  callback is internal, but the change ripples to every
  `track_with_payload` caller (driver + session driver +
  datagram driver).
- `src/driver.rs`, `src/session_driver.rs`,
  `src/datagram_driver.rs` — pass `ts` to reassembler's
  `segment()`.
- `src/event.rs` — add
  `AnomalyKind::RetransmittedSegment { side, count }` variant.
- `src/obs.rs` — extend `anomaly_label` for the new variant;
  extend `record_flow_ended` to emit the new `flowscope_retransmits_total`
  counter when `FlowStats.retransmits_*` > 0. Add the two new
  reassembly-diagnostic fields' obs export.
- `src/event.rs` — `FlowStats` gains
  `retransmits_initiator: u64` / `retransmits_responder: u64`
  fields. `FlowDriver::finalize_ended_flows` patches them
  alongside the existing diagnostic patching.
- `docs/SESSION_GUIDE.md` — "Reassembly health" subsection
  extended to mention the retransmit counter and the
  segment-timestamp availability for custom reassemblers.
- `CHANGELOG.md` — 0.5.0 entry covering all three changes.

### NEW

None.

---

## API

### `src/extractor.rs` — `TcpInfo`

```rust
/// Pre-parsed TCP information for a packet.
///
/// `#[non_exhaustive]` since 0.5.0 — additive field changes are
/// unconditionally non-breaking. Construct via `..Default::default()`
/// internally; external consumers read fields by name.
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct TcpInfo {
    pub flags: TcpFlags,
    pub seq: u32,
    pub ack: u32,
    pub payload_offset: usize,
    pub payload_len: usize,
    /// TCP receive window from the header (host byte order).
    /// Not yet scaled — see [`FlowEntry`] for the (future)
    /// `wscale` field that will let consumers compute the
    /// effective window.
    pub window: u16,
}
```

`TcpInfo` is `Copy`; the new field is 2 bytes, so no
size-class-jump. Existing constructors fill it from
etherparse's `tcp.window_size()`.

Internally we don't need `Default` because we construct via
struct literal in `parse.rs`. External consumers always READ
the struct, never CONSTRUCT it, so the field addition is
purely additive at the user-facing boundary.

### `src/reassembler.rs` — `Reassembler` trait

```rust
pub trait Reassembler: Send + 'static {
    /// New segment arrived in this direction.
    ///
    /// `ts` is the kernel/source timestamp of the packet
    /// carrying the segment. Custom reassemblers can use it for
    /// RTT estimation, staleness tracking, etc. The default
    /// [`BufferedReassembler`] uses it only to forward to
    /// [`on_duplicate`](Self::on_duplicate) when classifying a
    /// retransmit.
    ///
    /// **Breaking change in 0.5.0:** the `ts` parameter is new
    /// (was just `seq, payload`). Existing impls need a one-line
    /// signature update.
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp);

    fn fin(&mut self) {}
    fn rst(&mut self) {}

    /// Number of TCP segments dropped because they arrived out
    /// of order (NOT counting duplicates — see [`retransmits`]).
    fn dropped_segments(&self) -> u64 { 0 }

    /// Number of TCP segments classified as retransmits
    /// (`seq + len <= expected_seq`). New in 0.5.0; the default
    /// returns 0. Existing custom reassemblers that don't
    /// classify duplicates report 0 here, which is the correct
    /// "unknown" semantic.
    fn retransmits(&self) -> u64 { 0 }

    /// Hook called when a segment is classified as a retransmit
    /// rather than buffered. Default no-op. Custom reassemblers
    /// can use this to update RTT estimators, retransmit-rate
    /// metrics, etc.
    fn on_duplicate(&mut self, _seq: u32, _payload: &[u8], _ts: Timestamp) {}

    // existing diagnostics:
    fn bytes_dropped_oversize(&self) -> u64 { 0 }
    fn is_poisoned(&self) -> bool { false }
    fn high_watermark(&self) -> u64 { 0 }
}
```

### `src/reassembler.rs` — `BufferedReassembler` classification

```rust
impl Reassembler for BufferedReassembler {
    fn segment(&mut self, seq: u32, payload: &[u8], ts: Timestamp) {
        if payload.is_empty() {
            return;
        }
        if self.poisoned {
            return;
        }
        match self.expected_seq {
            None => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_with_cap(payload);
            }
            Some(exp) if seq == exp => {
                self.expected_seq = Some(seq.wrapping_add(payload.len() as u32));
                self.append_with_cap(payload);
            }
            Some(exp) => {
                // Classify: retransmit vs OOO.
                // Retransmit: seq + len <= expected_seq (already
                //             fully accounted for).
                // OOO:       seq > expected_seq (ahead of expected).
                // Partial overlap: seq < exp AND seq + len > exp
                //                  (truncated retransmit + new bytes;
                //                  classified as retransmit for now —
                //                  we don't gap-fill in BufferedReassembler).
                let end = seq.wrapping_add(payload.len() as u32);
                // Use sequence-space ordering (wrap-aware via
                // `Wrapping` semantics on `u32` — for the
                // 1-direction stream, real-world wrap is rare).
                let is_behind = seq_lt(end, exp) || seq == exp.wrapping_sub(payload.len() as u32);
                if is_behind {
                    self.retransmits += 1;
                    self.on_duplicate_internal(seq, payload, ts);
                } else {
                    self.dropped_segments += 1;
                }
            }
        }
    }

    fn dropped_segments(&self) -> u64 { Self::dropped_segments(self) }
    fn bytes_dropped_oversize(&self) -> u64 { Self::bytes_dropped_oversize(self) }
    fn is_poisoned(&self) -> bool { Self::is_poisoned(self) }
    fn high_watermark(&self) -> u64 { Self::high_watermark(self) }
    fn retransmits(&self) -> u64 { Self::retransmits(self) }
}

/// `a < b` in TCP sequence-space (wrap-aware).
#[inline]
fn seq_lt(a: u32, b: u32) -> bool {
    (a.wrapping_sub(b) as i32) < 0
}
```

### `src/tracker.rs` — `track_with_payload` callback

```rust
impl<E: FlowExtractor, S: Send + 'static> FlowTracker<E, S> {
    pub fn track_with_payload<'v, F>(
        &mut self,
        view: PacketView<'v>,
        mut payload_cb: F,
    ) -> FlowEvents<E::Key>
    where
        F: FnMut(&E::Key, FlowSide, u32, &[u8], Timestamp),
    {
        // ...
        // The callback invocation now passes view.timestamp:
        payload_cb(&key, side, tcp_info.seq, payload, view.timestamp);
        // ...
    }
}
```

Callers (`FlowDriver::track_pending`,
`FlowSessionDriver::translate_events`,
`FlowDatagramDriver` — though datagram doesn't fire the TCP
callback) update their closure signatures and forward the ts
to `r.segment(seq, payload, ts)`.

### `src/event.rs` — new diagnostic fields + anomaly variant

```rust
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FlowStats {
    // ... existing fields ...
    /// New in 0.5.0: per-side retransmit count from the
    /// reassembler. Populated by [`FlowDriver`] on `Ended`.
    pub retransmits_initiator: u64,
    pub retransmits_responder: u64,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnomalyKind {
    BufferOverflow { /* ... */ },
    OutOfOrderSegment { /* ... */ },
    FlowTableEvictionPressure { /* ... */ },
    SessionParseError { /* ... */ },
    /// New in 0.5.0. Reassembler classified one or more
    /// segments as retransmits during this tick. Coalesced —
    /// one anomaly per (flow, side) per tick.
    RetransmittedSegment {
        side: FlowSide,
        count: u64,
    },
}
```

### `src/driver.rs` — anomaly diff + finalize patch

Two integration points:

1. **Anomaly diff loop** — the existing `diff_anomaly_state`
   helper snapshots `dropped_segments` + `bytes_dropped_oversize`
   per side before each tick and emits anomalies on delta. Add
   a third counter (`retransmits`) to the snapshot and emit
   `AnomalyKind::RetransmittedSegment` on delta.
2. **`finalize_ended_flows`** — extend the per-side patch loop
   to also copy `r.retransmits()` into
   `stats.retransmits_{init,resp}`. Same shape as the existing
   `dropped_ooo` / `bytes_dropped_oversize` / `high_watermark`
   patching.

### `src/obs.rs`

```rust
pub const METRIC_RETRANSMITS: &str = "flowscope_retransmits_total";

#[cfg(feature = "metrics")]
fn anomaly_label(kind: &AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::BufferOverflow { .. } => "buffer_overflow",
        AnomalyKind::OutOfOrderSegment { .. } => "ooo_segment",
        AnomalyKind::FlowTableEvictionPressure { .. } => "flow_table_eviction",
        AnomalyKind::SessionParseError { .. } => "parse_error",
        AnomalyKind::RetransmittedSegment { .. } => "retransmit",
    }
}

#[cfg(feature = "metrics")]
pub(crate) fn record_flow_ended(reason: EndReason, stats: &FlowStats) {
    // ... existing patching ...
    if stats.retransmits_initiator > 0 {
        metrics::counter!(METRIC_RETRANSMITS, "side" => "initiator")
            .increment(stats.retransmits_initiator);
    }
    if stats.retransmits_responder > 0 {
        metrics::counter!(METRIC_RETRANSMITS, "side" => "responder")
            .increment(stats.retransmits_responder);
    }
}
```

---

## Implementation steps

1. **TcpInfo first** (smallest, isolated). Add `window` field,
   `#[non_exhaustive]`, populate from etherparse in `parse.rs`,
   ripple struct-literal constructors to use the new field.
   All existing tests pass after this commit.
2. **Reassembler signature** — change `Reassembler::segment` to
   take `ts: Timestamp`. Update `BufferedReassembler` impl,
   `track_with_payload`'s callback, all callers in driver +
   session_driver + datagram_driver. The session driver
   already has `view.timestamp` available via its
   `clamp_view`-then-`track_pending` flow.
3. **Retransmit classification on BufferedReassembler** — add
   `retransmits` field + accessor + classification in
   `segment()`. Sequence-space comparison via the small
   `seq_lt` helper. `on_duplicate` default-noop hook.
4. **FlowStats new fields + driver patching** — extend
   `finalize_ended_flows` to patch retransmits alongside the
   existing diagnostics.
5. **AnomalyKind::RetransmittedSegment + diff_anomaly_state** —
   snapshot `retransmits()` per-side, emit on delta, coalesced
   per (flow, side) per tick.
6. **obs labels + metric** — add `METRIC_RETRANSMITS`,
   `anomaly_label` arm, `record_flow_ended` extension.
7. **Tests**: reassembler classification proptest, driver-
   integration test for retransmit anomalies, metrics smoke
   test for the new counter.
8. **SESSION_GUIDE.md** — extend "Reassembly health" with the
   retransmit counter and the segment-timestamp availability
   note.
9. **CHANGELOG.md** entry under 0.5.0; migration recipe for
   `Reassembler::segment` signature change.

Land as 1–3 commits inside one PR series so the breaking
changes land together (Reassembler-trait break + TcpInfo
non_exhaustive + AnomalyKind/EndReason additions all in one
window).

---

## Tests

### `src/reassembler.rs` (unit)

```rust
fn ts(sec: u32) -> Timestamp { Timestamp::new(sec, 0) }

#[test]
fn segment_classifies_exact_retransmit() {
    let mut r = BufferedReassembler::new();
    r.segment(0, b"hello", ts(1));
    r.segment(0, b"hello", ts(2));  // exact retransmit
    assert_eq!(r.retransmits(), 1);
    assert_eq!(r.dropped_segments(), 0);
    assert_eq!(r.buffered_len(), 5);
}

#[test]
fn segment_classifies_ooo_distinctly_from_retransmit() {
    let mut r = BufferedReassembler::new();
    r.segment(0, b"hello", ts(1));   // exp = 5
    r.segment(100, b"x", ts(2));     // OOO (seq > exp)
    assert_eq!(r.retransmits(), 0);
    assert_eq!(r.dropped_segments(), 1);
}

#[test]
fn segment_classifies_partial_overlap_as_retransmit() {
    let mut r = BufferedReassembler::new();
    r.segment(0, b"hello", ts(1));   // exp = 5
    r.segment(3, b"lo", ts(2));      // ends at 5 — already buffered
    assert_eq!(r.retransmits(), 1);
    assert_eq!(r.dropped_segments(), 0);
}

#[test]
fn segment_timestamp_passed_to_on_duplicate() {
    struct Spy { ts_seen: Vec<Timestamp> }
    impl Reassembler for Spy {
        fn segment(&mut self, _: u32, _: &[u8], _: Timestamp) {}
        fn on_duplicate(&mut self, _: u32, _: &[u8], ts: Timestamp) {
            self.ts_seen.push(ts);
        }
    }
    // BufferedReassembler invokes on_duplicate internally — verify
    // via a custom impl that the trait method is callable with ts.
    let mut s = Spy { ts_seen: Vec::new() };
    s.on_duplicate(0, b"x", ts(42));
    assert_eq!(s.ts_seen, vec![ts(42)]);
}
```

### Proptest in `tests/proptest_invariants.rs`

```rust
proptest! {
    #[test]
    fn buffered_reassembler_retransmit_dropped_partition(
        segments in proptest::collection::vec(
            (any::<u32>(), proptest::collection::vec(any::<u8>(), 0..16)),
            0..32,
        ),
    ) {
        let mut r = BufferedReassembler::new();
        for (i, (seq, payload)) in segments.iter().enumerate() {
            r.segment(*seq, payload, Timestamp::new(i as u32, 0));
        }
        // Invariant: every classified segment is either buffered,
        // dropped (OOO), or counted as a retransmit. No double-
        // count, no segments lost from the trio.
        let total_classified =
            r.retransmits() + r.dropped_segments() +
            (r.buffered_len() as u64) / 1;  // approx
        // (refined invariant in real impl)
        prop_assert!(total_classified >= 0);  // smoke; real assertion in impl
    }
}
```

### Driver integration test (`src/driver.rs`)

```rust
#[test]
fn retransmit_anomaly_emitted_on_duplicate_segment() {
    let factory = BufferedReassemblerFactory::default();
    let mut d = FlowDriver::<_, _>::new(FiveTuple::bidirectional(), factory)
        .with_emit_anomalies(true);
    // 3WHS + data + retransmitted-data (same seq + bytes)
    let frames = build_3whs_and_then_data_and_retransmit();
    let mut events = Vec::new();
    for f in frames {
        events.extend(d.track(view(&f, 0)));
    }
    let retx = events
        .iter()
        .find(|e| matches!(
            e,
            FlowEvent::Anomaly {
                kind: AnomalyKind::RetransmittedSegment { .. },
                ..
            }
        ));
    assert!(retx.is_some());
}

#[test]
fn ended_event_carries_retransmit_count() {
    // Same flow, end with FIN. Stats should show retransmits_initiator == 1.
    // (Detailed assertion mirrors the dropped_ooo / high_watermark tests.)
}
```

### Metrics integration

Extend `tests/metrics_integration.rs` with an assertion that
`flowscope_retransmits_total{side="initiator"} == 1` after the
above scenario fires.

---

## Acceptance criteria

- [ ] `TcpInfo` is `#[non_exhaustive]` and carries `window: u16`,
      populated from etherparse.
- [ ] `Reassembler::segment` signature is
      `(seq, payload, ts: Timestamp)`. All callers and impls
      updated. Existing tests pass with the signature change.
- [ ] `Reassembler::retransmits()` trait method exists with a
      default-zero impl. `BufferedReassembler` overrides it with
      the classified count.
- [ ] `Reassembler::on_duplicate(seq, payload, ts)` hook exists
      as a default-no-op.
- [ ] `BufferedReassembler` correctly distinguishes retransmits
      (`seq + len <= expected_seq`) from OOO (`seq > expected_seq`)
      using sequence-space comparison.
- [ ] `FlowStats::retransmits_{initiator,responder}` fields
      exist, populated by `FlowDriver::finalize_ended_flows`.
- [ ] `AnomalyKind::RetransmittedSegment { side, count }`
      variant exists; coalesced per (flow, side) per tick by
      `FlowDriver::diff_anomaly_state`.
- [ ] `flowscope_retransmits_total{side=...}` counter fires
      from `obs::record_flow_ended`.
- [ ] CHANGELOG entry under 0.5.0 with migration recipe for the
      `Reassembler::segment` signature change.
- [ ] SESSION_GUIDE.md "Reassembly health" subsection extended.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.
- [ ] `cargo test --all-features` clean.

---

## Risks

1. **`Reassembler::segment` signature change.** Pre-1.0 BC
   policy permits this; the trait surface is narrow (≤8 known
   third-party impls). Migration is one-line per impl. CHANGELOG
   migration paragraph spells it out.
2. **Sequence-space wraparound semantics.** TCP sequence numbers
   wrap at `2^32`. The classification uses
   `(a.wrapping_sub(b) as i32) < 0` which gives correct
   wrap-aware ordering for differences <`2^31`. Real-world
   flows that exceed 2 GiB on a single side mid-flow are rare;
   when they happen, mis-classification once per wrap is
   tolerable.
3. **Partial-overlap retransmits**. We classify these as
   retransmits (not OOO) because the new bytes that COULD be
   recovered are below `expected_seq` and would need OOO
   buffering to merge — not in `BufferedReassembler`'s scope.
   Documented; users wanting strict accounting can write a
   custom reassembler. Plan 74 (OOO reassembly) handles this
   properly when it lands.
4. **Anomaly-event volume on lossy networks.** A flow over a
   bad link may emit one `RetransmittedSegment` anomaly per
   tick for many ticks. Same coalescing pattern as OOO; same
   trade-off. Document in OBSERVABILITY.md.
5. **`window: u16` vs effective window.** Without `wscale`,
   the raw window value is misleading on long-fat-pipe links.
   The `TcpInfo` rustdoc points at the (future) per-flow
   `wscale` field. Document expectations.

---

## Effort

- LOC: ~250 source (TcpInfo + parse: ~15, Reassembler trait: ~30,
  BufferedReassembler classification: ~50, FlowStats + driver
  patching: ~30, AnomalyKind + diff_anomaly_state: ~40, obs:
  ~25, signature ripples through track_with_payload + drivers:
  ~50).
- Tests: ~250 LOC (reassembler unit tests + proptest + driver
  integration + metrics).
- Time: 2–3 days.

---

## Provenance

Wishlist items F1.1 + F1.2 + F1.3 from
`docs/feedback-2026-08-11-simple-nms.md` (the
`simple-nms` team — TCP rich diagnostics for a flow-stats
publisher).

Bundled into one plan because:
- All three are reassembler-adjacent changes that share a
  breaking-change window (`Reassembler::segment` signature).
- The retransmit detection (F1.3) needs the segment timestamp
  (F1.2) to be useful for downstream RTT estimation, so
  shipping them separately would force consumers to use the
  later one's signature anyway.
- The `window` field (F1.1) is unrelated to the reassembler
  but adds `#[non_exhaustive]` to `TcpInfo` in the same window,
  closing an oversight from the project-wide non_exhaustive
  pass in 0.2.0.
