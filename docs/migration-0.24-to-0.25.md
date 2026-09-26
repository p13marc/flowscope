# Migrating from 0.24 to 0.25

0.25 replaces the per-slot session engines with **one engine** shared
by the typed `Driver`, the new public `SessionDriver` /
`DatagramDriver`, and the pcap helpers; makes reassembly **gaps
explicit**; and stops **ending (and re-creating) flows** when a parser
or a reassembler gives up. Most code keeps compiling; what changes is
behaviour, and every behaviour change is a fix. Read sections 1–3 if
you consume `Ended.reason`, `ParserClosed`, or reassembly limits.

## 1. Reassembly and parser failures no longer end the flow

Before, three things ended a flow early and `forget()`-ed it — after
which its **next packet started a brand-new flow mid-stream**:

| Trigger | 0.24 | 0.25 |
|---|---|---|
| parser `is_poisoned()` | flow `Ended { ParseError }` (+ re-created) | `ParserClosed { reason: ParseError, detail }`; flow continues |
| parser `is_done()` | flow `Ended { ParserDone }` (+ re-created) | `ParserClosed { reason: ParserDone }`; flow continues |
| per-side cap, `OverflowPolicy::DropFlow` | flow `Ended { BufferOverflow }` (+ re-created) | side stops reassembling; parsers get `ParserClosed { BufferOverflow }`; flow continues |
| memcap, `MemcapPolicy::DropFlow` / `PassThrough` | flow `Ended { BufferOverflow }` | both / one side released; flow continues |

`Ended.reason` is now always a transport reason: `Fin`, `Rst`,
`IdleTimeout`, `Evicted`, `ForceClosed`. If you counted
`Ended { BufferOverflow }` to find oversized flows, read
`FlowStats::reassembly_stop_initiator` / `_responder` (or the
`BufferOverflow` anomaly) instead:

```rust
if let Event::Ended { stats, .. } = &ev {
    if stats.reassembly_stop_initiator.is_some() || stats.reassembly_stop_responder.is_some() {
        // reassembly of this flow was cut short
    }
}
```

A closed parser is never re-created for the same flow; it is dropped
when the flow ends.

## 2. Gaps are reported — and stop parsers by default

A hole in the byte stream that never fills (capture loss, asymmetric
routing) used to wedge the reassembler for the rest of the direction:
every later byte was silently discarded. Now the hole is skipped and
**reported**:

- `SessionParser::on_gap(side, missing, ts, out) -> GapResponse` is
  called where the bytes are missing. The default returns
  `GapResponse::Stop`, which closes the parser with
  `EndReason::StreamGap` (`detail`: "N bytes missing on the … side").
  A parser that resynchronises (line protocols, byte counters) returns
  `GapResponse::Continue` and keeps receiving the bytes after the hole.
- `AnomalyKind::StreamGap { side, gaps, bytes }` (with anomalies on),
  and `FlowStats::reassembly_gaps_*` / `reassembly_gap_bytes_*`.

The session engines use `SegmentBufferReassembler`, which heals
reordering before it becomes a gap: a hole waits up to
`FlowTrackerConfig::reassembly_ooo_deadline` (1 s of packet time) or
until `reassembly_ooo_buffer` (256 KiB per side) is full, and is given
up on at flow end. Set `reassembly_ooo_buffer = 0` to never wait.

`OverflowPolicy::SlidingWindow` drops also reach the parser as a gap
now (they were spliced silently).

## 3. The typed `Driver` honours every builder setting, in any order

Slots no longer run their own flow table, so:

- `config`, `idle_timeout_fn`, `dedup` and `monotonic_timestamps`
  apply to parsing as well as lifecycle, whatever the call order (0.24
  snapshotted `config` at each registration and ignored the others);
- parser state lives exactly as long as the lifecycle flow — an idle
  split gives the parser a fresh instance too;
- with `emit_anomalies(true)` you now also get reassembly anomalies
  (gaps, retransmits, overflows, watermark, overlap inconsistencies)
  and `SessionParseError`, and `Ended.stats` carries the reassembly
  counters;
- a slot emits `ParserClosed` for flows whose parser received data
  (0.24 emitted one for every port-matching flow, data or not), and a
  flow's `ParserClosed` events precede its `Ended`.

`Event::ParserClosed` gained `detail: Option<String>` and is
`#[non_exhaustive]`: add `..` to patterns; build it in tests with
`test_helpers::events::driver::parser_closed[_with]`.
`SlotMessage` gained `orientation`; build it with `SlotMessage::new`.

## 4. Reassembler trait: pull-style output with gaps

If you drain a reassembler yourself:

```rust
// Before
let bytes: Vec<u8> = driver.drain_buffer(&key, side);

// After — keeps the gap markers
let mut chunks = StreamChunks::new();
driver.drain_stream(&key, side, &mut chunks);
for chunk in chunks.iter() {
    match chunk {
        Chunk::Data(bytes) => { /* … */ }
        Chunk::Gap(missing) => { /* … */ }
    }
}
```

`drain_buffer` / `take()` still exist and return bytes only.

Custom `Reassembler` impls compile unchanged (all new methods have
defaults). Implement `drain_into` to be usable by the session engines,
`stop_reason` if you stop for reasons other than overflow, and
`release` to honour the memcap.

`BufferedReassembler` changes: a segment ahead of the expected
sequence number skips the hole (gap) instead of being dropped;
`dropped_segments()` now counts only late segments that arrive after
their hole was skipped; a partially-overlapping segment delivers its
new tail; under `DropFlow` the bytes already buffered stay deliverable.

`SegmentBufferReassembler` changes: expired / over-cap holes are
skipped instead of evicting data; `evict_expired_ooo` returns holes
skipped; `rst()` no longer stops it; `high_watermark()` is a peak.

## 5. Factories take their settings from the tracker config

`ReassemblerFactory::apply_config` (default no-op) is called by
`FlowDriver` on construction and `set_config`. The built-in factories
fill every setting **not set with a `with_*` builder** from the
config. Consequence: `FlowDriver::new(ext, BufferedReassemblerFactory::default())`
is now capped at the default 1 MiB per side (the documented default,
previously not applied); call `.unbounded()` on the factory to opt out.

## 6. Single-parser engines are public again

```rust
use flowscope::session::{SessionDriver, SessionEvent};

let mut d = SessionDriver::new(FiveTuple::bidirectional(), MyParser::default())
    .with_emit_anomalies(true);
for ev in d.track(view) {
    match ev {
        SessionEvent::Application { key, orientation, message, .. } => {}
        SessionEvent::ParserClosed { reason, detail, .. } => {}
        SessionEvent::Closed { reason, stats, .. } => {}
        _ => {}
    }
}
d.finish();
```

`SessionEvent` is public (it was crate-private since 0.20).
`TemplateFactory(parser)` wraps a `Clone`-only parser.

## 7. pcapng

`PcapFlowSource::open` and every `*_from_pcap` helper read pcapng.
`PcapFlowSource::from_reader` now takes `R: BufRead` (wrap a plain
`Read` in `BufReader`). `pcap::CaptureReader` exposes the reader.

## 8. Small additions

- `FlowSide::as_str` / `Display` (`"initiator"` / `"responder"`),
  `FlowState::as_str` / `Display` (snake_case) — same strings as serde.
- `EndReason::StreamGap`, `EndReason::is_graceful()`.
- `FlowTracker::track_with` — a per-packet hook that fires even when
  `FlowEvent::Packet` is suppressed by `EventMask`.
