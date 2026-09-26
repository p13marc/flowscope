# Migrating from 0.24 to 0.25

0.25 replaces the per-slot session engines with **one engine** shared
by the typed `Driver`, the new public `SessionDriver` /
`DatagramDriver`, and the pcap helpers; makes reassembly **gaps
explicit**; and stops **ending (and re-creating) flows** when a parser
or a reassembler gives up. Most code keeps compiling; what changes is
mostly behaviour, and every behaviour change is a fix. Read sections
1–3 if you consume `Ended.reason`, `ParserClosed`, or reassembly
limits; section 9 lists every compile break in one place.

## 1. Reassembly and parser failures no longer end the flow

Before, several things ended a flow early and `forget()`-ed it — after
which its **next packet started a brand-new flow mid-stream**:

| Trigger | 0.24 | 0.25 |
|---|---|---|
| parser `is_poisoned()` | flow `Ended { ParseError }` (+ re-created) | `ParserClosed { reason: ParseError, detail }` (+ `SessionParseError` anomaly); flow continues |
| parser `is_done()` | flow `Ended { ParserDone }` (+ re-created) | `ParserClosed { reason: ParserDone }`; flow continues |
| per-side cap, `OverflowPolicy::DropFlow` | flow `Ended { BufferOverflow }` (+ re-created) | that side stops reassembling (`ReassemblyStop::Overflow`); parsers get `ParserSideStopped { side, reason: BufferOverflow }` and keep parsing the other side; flow continues |
| memcap, `MemcapPolicy::PassThrough` | side's buffer released; its parser silently lost the rest of that side | offending side released (`ReassemblyStop::Memcap`) and its reassembler dropped; parsers get `ParserSideStopped { side, reason: BufferOverflow }`; flow continues |
| memcap, `MemcapPolicy::DropFlow` | flow `Ended { BufferOverflow }` (+ re-created) | **both** sides released (even one without a reassembler yet); parsers get both side stops, then one `ParserClosed` ("both sides stopped"); flow continues |

`Ended.reason` is now always a transport reason: `Fin`, `Rst`,
`IdleTimeout`, `Evicted`, `ForceClosed`. `FlowDriver` never
synthesises `Ended { BufferOverflow }`, and the engine never calls
`FlowTracker::forget`. If you counted `Ended { BufferOverflow }` to
find oversized flows, read `FlowStats::reassembly_stop_initiator` /
`_responder` (or the `BufferOverflow` / `GlobalMemcapHit` anomaly)
instead:

```rust
if let Event::Ended { stats, .. } = &ev {
    if stats.reassembly_stop_initiator.is_some() || stats.reassembly_stop_responder.is_some() {
        // reassembly of this flow was cut short
    }
}
```

Match arms on `Ended { reason: BufferOverflow | ParseError |
ParserDone, .. }` are now dead: move that logic to `ParserClosed` /
`ParserSideStopped`. A closed parser is never re-created for the same
flow; it is dropped when the flow ends.

## 2. Gaps are reported — and stop one side by default

A hole in the byte stream that never fills (capture loss, asymmetric
routing) used to wedge the reassembler for the rest of the direction:
every later byte was silently discarded. Now the hole is skipped and
**reported**:

- `SessionParser::on_gap(side, missing, ts, out) -> GapResponse` is
  called where the bytes are missing:
  - `GapResponse::StopSide` — **the default** — stops feeding that
    side; the other side keeps being parsed. You get
    `ParserSideStopped { key, slot, parser_kind, side, reason:
    StreamGap, detail, ts }` on `driver::Event` (`SessionEvent` and
    `pcap::Pulse` carry it without `slot`). When both sides are stopped
    the parser is closed once: `ParserClosed`, detail
    `"both sides stopped"`.
  - `GapResponse::Continue` — the parser resynchronises (line
    protocols, length-prefixed framing) and keeps receiving the bytes
    after the hole.
  - `GapResponse::Stop` closes the parser (`ParserClosed { reason:
    StreamGap }`) — for protocols whose state spans both directions
    (HTTP/2's HPACK tables, request/response pairing).
- `AnomalyKind::StreamGap { side, gaps, bytes }` (with anomalies on),
  and `FlowStats::reassembly_gaps_*` / `reassembly_gap_bytes_*`.
- At flow end, each side still being read gets `fin_*` (graceful end,
  or that side sent a FIN — `FlowStats::fin_initiator` /
  `fin_responder`) or `rst_*`, independently. A stopped side gets
  neither.

The built-in parsers choose per protocol: FTP / SMTP resume at the
next line; `HttpParser` drops the message in progress and resumes at
the next request / status line; DNP3, SMB and Modbus/TCP resync on
their frame markers; HTTP/2 and `HttpExchangeParser` answer `Stop`;
TLS, DNS-over-TCP, LDAP, Kerberos, RDP and SSH keep `StopSide`.

`OverflowPolicy::SlidingWindow` drops also reach the parser as a gap
now (they were spliced silently), so a parser behind a sliding window
sees its `on_gap` called — and, by default, stops that side.

## 3. Reassembly heals reordering and resists strays

The session engines use `SegmentBufferReassembler`, which heals
reordering before it becomes a gap. These `FlowTrackerConfig` settings
(applied to the built-in factories) decide when a hole is given up on:

| Setting | Default | Meaning |
|---|---|---|
| `reassembly_ooo_buffer` | 256 KiB per side | out-of-order budget, charged by piece capacity + 64 B per piece + 32 B per provenance run; when full, the hole is skipped |
| `reassembly_ooo_deadline` | 1 s of packet time | a hole is skipped this long after the last progress when corroborated (two out-of-order segments or ACK evidence), after four deadlines otherwise |
| `reassembly_ack_grace` | 10 ms | a hole the peer has **acknowledged** (the bytes were sent, the capture missed them) is skipped after this grace |
| `reassembly_max_ahead` | 1 MiB | a segment further ahead than this is a suspected stray: dropped and counted (`AnomalyKind::OutOfWindowSegment`, `FlowStats::reassembly_out_of_window_*`) unless a second segment or an ACK corroborates it — then the stream resyncs with a gap (`reassembly_origin_resets_*`) |

Holes are also skipped at flow end, and a FIN or ACK past the last
received byte makes a lost final segment show up as a trailing gap.
Set `reassembly_ooo_buffer = 0` to never wait. Streams are anchored at
the SYN / SYN-ACK, so reordered first data segments are no longer
taken for retransmits; TCP Fast Open data starts at ISN + 1; RST
payloads are ignored.

New `FlowStats` fields (the struct is `#[serde(default)]`, so older
records still deserialize): `reassembly_gaps_*`,
`reassembly_gap_bytes_*`, `reassembly_stop_*`,
`reassembly_out_of_window_*`, `reassembly_ack_confirmed_gaps_*`,
`reassembly_origin_resets_*`, `fin_initiator`, `fin_responder`.

## 4. The typed `Driver` honours every builder setting, in any order

Slots no longer run their own flow table, so:

- `config`, `idle_timeout_fn`, `dedup` and `monotonic_timestamps`
  apply to parsing as well as lifecycle, whatever the call order (0.24
  snapshotted `config` at each registration and ignored the others);
  `emit_packet_source_idx(true)` survives a later `config(..)`;
- parser state lives exactly as long as the lifecycle flow — an idle
  split gives the parser a fresh instance too;
- with `emit_anomalies(true)` you now also get reassembly anomalies
  (gaps, out-of-window segments, retransmits, overflows, watermark,
  overlap inconsistencies) and `SessionParseError`, and `Ended.stats`
  carries the reassembly counters;
- a slot emits `ParserClosed` for flows whose parser received data
  (0.24 emitted one for every port-matching flow, data or not), and a
  flow's `ParserClosed` / `ParserSideStopped` events precede its
  `Ended`.

Event shapes:

- `Event::ParserClosed` gained `slot: SlotId` and `detail:
  Option<String>` and is `#[non_exhaustive]`: add `..` to patterns;
  build it in tests with
  `test_helpers::events::driver::parser_closed[_with]`. `SlotId`
  (`SlotHandle::slot_id()`, `BroadcastSlotHandle::slot_id()`) tells two
  slots of the same `ParserKind` apart.
- New `Event::ParserSideStopped` (§2); a catch-all arm covers it.
- `AnomalyKind::SessionParseError` gained `parser_kind` and `slot:
  Option<SlotId>` (`None` on the single-parser drivers).
- `SlotMessage` gained `orientation`, `lifecycle_pos` and `seq`; build
  it with `SlotMessage::new(key, side, orientation, message, ts)`
  (`.with_order(pos, seq)` sets the ordering marks).

Merging the two channels: a `SlotMessage` comes right **before**
lifecycle event number `lifecycle_pos` (0-based, counted across every
`track_into` / `sweep_into` / `finish_into` call;
`Driver::lifecycle_seq()` is the running count), and messages with the
same `lifecycle_pos` are ordered by `seq`. Emitting every queued
message with `lifecycle_pos <= n` before lifecycle event `n`
reproduces the engine's order — e.g. a flow's last messages before
its `Ended`.

Parser factories: `DriverBuilder::{session_factory_on_ports,
session_factory_broadcast, datagram_factory_on_ports,
datagram_factory_broadcast}` take a `SessionParserFactory` /
`DatagramParserFactory` (one parser built per flow from its key); the
existing registration methods still take a `Clone` template.

## 5. `tracker_mut` is gone from the engines

`Driver` (and the new `SessionDriver` / `DatagramDriver`) no longer
expose `tracker_mut()`: sweeping, force-closing or forgetting flows
behind the engine skipped its end-of-flow flush and left stale parser
state. Use the targeted setters, or the engine's own methods:

| 0.24 | 0.25 |
|---|---|
| `d.tracker_mut().set_idle_timeout_fn(f)` | `d.set_idle_timeout_fn(f)` |
| `d.tracker_mut().set_config(cfg)` | `d.set_config(cfg)` |
| `d.tracker_mut().pause_events()` / `resume_events()` | `d.pause_events()` / `d.resume_events()` |
| `d.tracker_mut().force_close(..)` / `.sweep(..)` | `d.force_close(..)` / `d.sweep(..)` |

`tracker()` (read-only) stays. `FlowDriver` keeps `tracker_mut()`; the
driver reconciles its own state with what you do through it.

## 6. `FlowDriver` owns its tracker's `Ended`

`FlowDriver` releases a flow's reassemblers and state on every
`Ended`, whether or not the caller sees it: `suppress_events` and
`pause_events` only filter the output (and now also cover
`FLOW_ANOMALY`, `TRACKER_ANOMALY` and `TICK`). Suppressing
`EventMask::ENDED` for load shedding is therefore safe — no leak, and a
new flow with the same key never inherits stale state.
`auto_sweep_interval` runs the driver's full sweep (hole deadlines,
flushes), not just the tracker's.

Ordering: a packet's anomalies come before its own flow's `Ended`;
end-of-flow gap anomalies before the `Ended` they belong to.
`finish()` stamps its output with the latest packet time (never
`Timestamp::MAX`); parsers' `on_tick` sees `Timestamp::MAX` at end of
input, but their messages are stamped with packet time.

New for engine builders: `FlowDriver::track_pending_with(view, want)`
is `track_pending` plus a per-packet `want: FnMut(&PacketContext<'_,
K>) -> bool` predicate, evaluated only when a reassembler would be
created (return `false` to track the flow without reassembling it).
Pre-release builds of 0.25 had it without the predicate; pass
`|_| true` for the old behaviour. `drain_stream`, `discard_stream`,
`discard_side`, `last_packet`, `flow_stats` and `finalize_flow` are the
other pieces the session engines are built from.

## 7. Reassembler trait: pull-style output with gaps

If you drain a reassembler yourself, `FlowDriver::drain_buffer` is
**removed** (it copied the bytes and dropped the gap markers):

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

The inherent `take()` on the built-in reassemblers still returns the
ready bytes only.

Removed:

- `Reassembler::is_poisoned` — use `stop_reason()`
  (`Option<ReassemblyStop>`); `BufferedReassembler::is_poisoned` is
  now `is_stopped()`.
- `SegmentBufferReassembler::holes_expired` → `gaps()`;
  `evict_expired_ooo(now)` → `advance_time(now)` (then drain).

Custom `Reassembler` impls that did not override `is_poisoned` compile
unchanged (every new method has a default). Implement `drain_into` to
be usable by the session engines, `stop_reason` if you stop for
reasons other than overflow, and `release` to honour the memcap (the
driver drops a released side's reassembler anyway). Optional:
`segment_into` (return `SegmentOutcome::Passthrough { skip }` for
in-order bytes so the engine delivers them straight from the frame),
`set_origin`, `peer_ack`, `fin_seen`, and `advance_time` /
`flush_pending` for hole handling.

`BufferedReassembler` changes: it keeps **one** reordered segment;
its hole is skipped (a gap) on a second out-of-order segment, after
the ACK grace, after `with_reorder_deadline` (1 s) or at flow end;
`dropped_segments()` now counts only late segments that arrive after
their hole was skipped; a partially-overlapping segment delivers its
new tail; under `DropFlow` the bytes already buffered stay
deliverable.

`SegmentBufferReassembler` changes: rewritten on 64-bit stream offsets
with coalescing out-of-order pieces; expired / over-budget holes are
skipped instead of evicting data; the overlap policy also applies to
in-order bytes overlapping held ones; `rst()` no longer stops it;
`high_watermark()` is a peak; `holes_filled()` counts only real fills.

## 8. Factories take their settings from the tracker config

`ReassemblerFactory::apply_config` (default no-op) is called by
`FlowDriver` on construction and `set_config`. The built-in factories
fill every setting **not set with a `with_*` builder** from the
config. Consequence: `FlowDriver::new(ext, BufferedReassemblerFactory::default())`
is now capped at the default 1 MiB per side (the documented default,
previously not applied); call `.unbounded()` on the factory to opt out.

## 9. Compile breaks at a glance

| 0.24 | 0.25 |
|---|---|
| `Reassembler::is_poisoned()` | `stop_reason().is_some()` |
| `BufferedReassembler::is_poisoned()` | `is_stopped()` |
| `FlowDriver::drain_buffer(&k, side)` | `drain_stream(&k, side, &mut chunks)` (§7) |
| `SegmentBufferReassembler::holes_expired()` / `evict_expired_ooo(now)` | `gaps()` / `advance_time(now)` |
| `Driver::tracker_mut()` | targeted setters (§5) |
| `tcp_state::transition(state, flags, side)` | `transition(state, flags, side, other_side_fin)` — whether the *other* side already sent a FIN |
| `Event::ParserClosed { key, parser_kind, reason, ts }` | add `slot`, `detail`, or `..` |
| `AnomalyKind::SessionParseError { side, reason }` | add `parser_kind`, `slot`, or `..` |
| `SlotMessage { .. }` struct literal | `SlotMessage::new(..)` |
| `PcapFlowSource::from_reader(R: Read)` | `R: BufRead` (wrap in `BufReader`) |
| custom datagram parser for ICMP / SCTP / … | override `transports()` (§10) — not a compile error, but it stops receiving traffic |

## 10. Datagram parsers declare their transports

Datagram cores used to feed any non-TCP flow to every datagram parser:
UDP parsers parsed ICMP messages and `IcmpParser` parsed UDP payloads.
Now `DatagramParser::transports() -> Transports` (and
`DatagramParserFactory::transports()`) says what a parser reads:
`UDP` (the default), `ICMP`, `ICMPV6`, `SCTP`, `OTHER`, or
`ICMP_ANY`. `IcmpParser` reads `ICMP_ANY`. A custom datagram parser for
anything but UDP must override it:

```rust
impl DatagramParser for MyIcmpProbe {
    // …
    fn transports(&self) -> Transports {
        Transports::ICMP_ANY
    }
}
```

## 11. Extractors report L4 metadata

`Extracted` gained `l4_meta: Option<L4Meta { ports, payload_offset,
payload_len }>`. The built-in extractors fill it, and the engines take
ports (for port-selected slots) and datagram payloads from it. A custom
extractor that leaves it `None` still works — the engine falls back to
parsing the frame as plain Ethernet, which is wrong for tunnelled
traffic — but should set it with
`Extracted::with_l4_meta(L4Meta::new(ports, offset, len))`. A custom
**decapsulating** extractor must rebase the inner extractor's result
onto the outer frame with `Extracted::rebased(delta)`, as the built-in
decap combinators now do: before this fix, every reassembled byte of a
VXLAN / GRE / GTP-U / MPLS TCP flow was sliced from the wrong offset.
`PacketContext` exposes `ports`, `l4_payload` and `l4_meta`.

## 12. Single-parser engines are public again

```rust
use flowscope::session::{SessionDriver, SessionEvent};

let mut d = SessionDriver::new(FiveTuple::bidirectional(), MyParser::default())
    .with_emit_anomalies(true);
for ev in d.track(view) {
    match ev {
        SessionEvent::Application { key, orientation, message, .. } => {}
        SessionEvent::ParserSideStopped { side, reason, detail, .. } => {}
        SessionEvent::ParserClosed { reason, detail, .. } => {}
        SessionEvent::Closed { reason, stats, .. } => {}
        _ => {}
    }
}
d.finish();
```

`SessionEvent` is public (it was crate-private since 0.20).
`TemplateFactory(parser)` wraps a `Clone`-only parser.

## 13. pcap

- `PcapFlowSource::open` and every `*_from_pcap` helper read pcapng
  (`if_tsresol` / `if_tsoffset` honoured, timestamp arithmetic
  saturating). `pcap::CaptureReader` exposes the reader.
- Linux cooked captures (`LINUX_SLL` / `LINUX_SLL2`, i.e.
  `tcpdump -i any`), raw IP (`RAW` / `IPV4` / `IPV6`) and BSD loopback
  (`NULL` / `LOOP`) are normalised to Ethernet
  (`CapturedPacket::into_ethernet`) and tracked; they used to come out
  as "unmatched". Other link types are skipped and counted
  (`ViewIter::unsupported()`).
- `CapturedPacket::direction` (`CaptureDirection`, from the pcapng EPB
  flags or the cooked header).
- New `pcap-reader` feature: `CaptureReader` alone (just `pcap-file`),
  without extractors or the tracker. `pcap` builds on it.
- `Pulse` gained `ParserClosed` and `ParserSideStopped`.

## 14. Metrics and anomaly labels

- `flowscope_flows_ended_total{reason}` only carries transport reasons
  (`fin` / `rst` / `idle` / `evicted` / `force_closed`). Dashboards
  that filtered it on `parse_error` / `parser_done` /
  `buffer_overflow` move to `flowscope_parser_closed_total{parser_kind,
  reason}` and `flowscope_parser_side_stopped_total{parser_kind, side,
  reason}`.
- New: `flowscope_reassembly_gap_bytes_total{side}`.
- New anomaly kinds: `stream_gap` (`AnomalyKind::StreamGap`) and
  `out_of_window_segment` (`AnomalyKind::OutOfWindowSegment`).

## 15. Small additions

- `FlowSide::as_str` / `opposite` / `Display` (`"initiator"` /
  `"responder"`), `FlowState::as_str` / `Display` (snake_case) — same
  strings as serde.
- `EndReason::StreamGap`, `EndReason::is_graceful()`.
- `FlowTracker::track_with` — a per-packet hook that fires even when
  `FlowEvent::Packet` is suppressed by `EventMask`.
- `BroadcastSlotHandle::try_recv` / `poll_recv`: a push wakes the task
  polling the handle.
- A retransmitted FIN no longer ends a TCP flow early: only the second
  side's FIN advances the close (`FlowStats::fin_initiator` /
  `fin_responder`).
