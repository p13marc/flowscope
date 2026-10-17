# Migrating from 0.25 to 0.26

0.26 is the *truncation, orientation & bounded tables* cycle. It makes
flowscope count and parse packets cut by a capture snap length instead
of skipping them, reports byte counts as wire and IP lengths instead of
captured lengths, gates parser lifecycle output by `EventMask` and
pause like every other event, orients every output and detector by the
flow's **initiator** instead of the address-sorted key, and bounds the
per-key rate tables.

Each section below names the issue it comes from, what changed, and
what to do about it.

## 1. Packet sources: report the wire length (#219)

`PacketView` (and `OwnedPacketView`) has a new field, `snap_cut`: the
number of bytes of the original packet missing from the **end** of
`frame` because the capture's snap length cut them. `0` — the default
of `PacketView::new` — means "complete, or unknown", which is what
every view meant before.

If your source captures with a snap length (a pcap `snaplen`, a ring
frame smaller than the packet, `tcpdump -s N`), tell flowscope the
packet's length on the wire:

```rust
// `captured` is the stored prefix, `wire_len` the packet's length.
let view = PacketView::new(captured, ts).with_wire_len(wire_len);
// or, when you already have the difference:
let view = PacketView::new(captured, ts).with_snap_cut(missing_bytes);
assert_eq!(view.wire_len(), wire_len);
```

Pass the length of the frame the view holds *before* you rewrite its
front (strip or synthesise a link header, re-insert a VLAN tag): the
cut is measured at the end, so it stays valid across such rewrites and
`with_frame` keeps it. `PcapFlowSource` does this for every record.

Nothing else is required to keep compiling — both structs are
`#[non_exhaustive]`. What a source gains is described in the sections
below: truncated packets are tracked, counted at their wire length, and
reassembled with a gap where the cut bytes were.

A related pcapng fix: a Simple Packet Block's frame no longer ends in
the block's 32-bit padding, and an Enhanced Packet Block never reports
an original length smaller than what it captured.

## 2. Custom reassemblers: `Reassembler::missing` (#212)

The `Reassembler` trait has a new defaulted method:

```rust
fn missing(&mut self, seq: u32, len: u32, ts: Timestamp) {}
```

`FlowDriver` calls it for a TCP segment the capture truncated: first
`segment(seq, captured)` with the bytes that were captured, then
`missing(seq + captured, wire - captured)` for the rest. Truncated
segments never go through `segment_into`, so they are never let
through.

The built-in reassemblers skip those bytes as a gap at once when the
stream has reached them, so a snap-length capture does not stall on a
hole that can never fill. The default does nothing: a custom
reassembler that ignores it sees a hole after each truncated segment
and handles it as it handles capture loss. Implement it if your
reassembler can do better — a push-style reassembler can, for example,
forward a gap marker immediately.

## 3. Truncated packets are tracked and reassembled (#212)

Before 0.26 the extractors sliced every frame strictly, so a packet
whose IP header claimed more bytes than were captured — anything
longer than the snap length of `tcpdump -s N`, or of a ring whose
frames are smaller than the packets — was skipped: no flow, and a gap
in the stream nobody reported. Now:

- **The packet is extracted and tracked.** Expect flows (and packets)
  that 0.25 did not report for snap-length captures. What is still
  skipped: a malformed packet that was *not* cut short (as before), a
  packet cut inside its IP / TCP / UDP header or IP extension headers
  (no flow key).
- **TCP:** the captured bytes are reassembled and the cut bytes are
  reported as a gap at once, with the packet that carried them
  (`SessionParser::on_gap`, `StreamChunks` gap marks,
  `FlowStats::reassembly_gap_bytes_*`, the `StreamGap` anomaly). A
  parser that keeps the default `GapResponse::StopSide` stops reading
  that side at the first truncated segment — the right thing for
  framed protocols, since its framing is lost. A FIN in a cut segment
  ends the stream after the segment's wire length.
- **Datagrams:** a cut UDP payload / ICMP message is tracked but not
  handed to `DatagramParser`s (counted in
  `flowscope_datagrams_truncated_total`).
- **New fields** say what was cut: `TcpInfo::payload_len` stays the
  number of bytes **captured**; `TcpInfo::wire_payload_len` (and
  `is_truncated()`) is what was on the wire. The same pair is on
  `L4Meta` (`payload_len` / `wire_payload_len`). `Extracted::l3_len` is
  the IP datagram's length on the wire.

Custom extractors keep compiling (`Extracted`, `L4Meta` and `TcpInfo`
are `#[non_exhaustive]`; `L4Meta::new` sets the wire length to the
captured one). If yours knows a datagram was cut, say so —
`L4Meta::new(ports, offset, captured).with_wire_payload_len(on_wire)` —
so the session engines do not parse it; set
`Extracted::with_l3_len(ip_len)` so the tracker can count IP octets
(section 4).

## 4. Byte counters count the wire, and IP octets are separate (#219)

`FlowStats::bytes_initiator` / `bytes_responder` — and everything
derived from them: `total_bytes()`, `bytes_for()`,
`throughput_bps*()`, `direction_skew()`, `mean_pkt_size_for()`, the
`flowscope_bytes_total` / `flowscope_flow_bytes` metrics — plus
`FlowEvent::Packet.len`, the typed `Event::Packet.len` and
`PacketContext::len` now count each packet's **wire length**: the
captured frame plus what a snap length cut from it. Before 0.26 they
counted the captured bytes, so a `tcpdump -s 96` capture reported at
most 96 bytes per packet. For captures without a snap length nothing
changes. `PacketContext::captured_len` is the old `len`.

The wire length is the L2 length: Ethernet header and trailer padding
included. NetFlow / IPFIX octet counters and Zeek's `*_ip_bytes` count
IP octets instead; those are the new `FlowStats::ip_bytes_initiator` /
`ip_bytes_responder` (`total_ip_bytes()`, `ip_bytes_for(side)`), summed
from the IP header's own length (the inner datagram behind a decap
combinator). The exporters switch to them (sections 6–7).

`FlowStats::packets_truncated_initiator` / `_responder` count the
packets that were cut. All new `FlowStats` fields deserialize as 0
from data written by 0.25.

## 5. `EventMask` and pause gate the parser lifecycle (#204)

In 0.25 the session engines (`Driver`, `SessionDriver`,
`DatagramDriver`) emitted parser closes, side stops and parse-error
anomalies regardless of the event mask and of `pause_events()`. Now:

| Event | Shown when |
|---|---|
| typed `Event::ParserClosed` at a flow's end (`reason.is_transport()`) | its flow's `Ended` is shown — `EventMask::ENDED` not masked, not paused |
| early `ParserClosed` (`reason.is_parser()`), `ParserSideStopped` | events are not paused (no mask bit; `EventMask` is unchanged) |
| `FlowAnomaly { kind: SessionParseError }` | anomalies are enabled, `EventMask::FLOW_ANOMALY` is not masked, not paused |

Only the output is filtered: the parser is closed, its state released
and the close counted in `flowscope_parser_closed_total` either way,
and parser *messages* keep flowing during a pause.

If you masked `ENDED` (or paused) and relied on the typed driver's
flow-end `ParserClosed` to learn that a flow ended, unmask `ENDED`
instead — the flow-end close now follows it. If you mask
`FLOW_ANOMALY` and still want to see parse errors, look at the early
`ParserClosed { reason: ParseError, detail, .. }`, which carries the
same reason text.
