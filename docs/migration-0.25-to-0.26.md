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
combinator). The exporters switch to them (section 7).

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

## 6. Flows are reported from their initiator (#217, #218)

A bidirectional `FiveTupleKey` stores its endpoints address-sorted
(`a < b`), and its `KeyFields::src_ip()` is `a`. Through 0.25 every
consumer that reports a flow as *source → destination* used those
accessors directly, so the "source" was the lower address, whoever
opened the connection. 0.26 reads keys from the flow's **initiator**:

| Output | 0.25 `src` | 0.26 `src` |
|---|---|---|
| Zeek `id.orig_*` / `id.resp_*` | lower address | initiator / responder |
| CSV `src_*` / `dst_*` (`Ended`, `Started` rows) | lower address | initiator / responder |
| EVE `flow`, `stats`, analyzed-flow `src_*` / `dest_*` | lower address | initiator (`*_toserver` = its direction) |
| `FlowRecord::from_key_fields` / `from_parts` IPFIX source / destination | lower address | initiator / responder |
| Port-scan, beacon, RITA, flood, exfil detectors | lower address | initiator |
| DGA, DNS-tunnel, NOD detectors | lower address | the DNS query's sender |

Byte and packet counters were always per side (initiator /
responder); now the addresses next to them agree. Community ID and
`stable_hash` are direction-independent and unchanged. EVE `anomaly`
records (a `FlowAnomaly` comes without the flow's stats) still carry
the key as stored.

To do the same in your own code, wrap the key:

```rust
use flowscope::{Directed, KeyFields};
let from_initiator = Directed::initiator(&key, &stats);
let client = from_initiator.src_ip();
// or, with an event's orientation:
let from_sender = Directed::new(&key, msg.orientation);
// raw socket addresses:
let (initiator, responder) = key.oriented(stats.initiator_orientation);
```

`OwnedAnomaly::with_flow(&key, initiator)` fills an anomaly's 5-tuple
from the initiator (`with_key` still copies the key as stored).

**Detector API.** Two hooks gained an orientation argument:

```rust
// Before
fn on_flow_start(&mut self, key: &K, ts: Timestamp, out: &mut Vec<OwnedAnomaly>);
fn on_dns_query(&mut self, key: &K, qname: &str, ts: Timestamp, out: &mut Vec<OwnedAnomaly>);
registry.observe_dns(&msg.key, qname, msg.ts, &mut out);

// After
fn on_flow_start(&mut self, key: &K, initiator: Orientation, ts: Timestamp, out: &mut Vec<OwnedAnomaly>);
fn on_dns_query(&mut self, key: &K, sender: Orientation, qname: &str, ts: Timestamp, out: &mut Vec<OwnedAnomaly>);
registry.observe_dns(&msg.key, msg.orientation, qname, msg.ts, &mut out);
```

The registry passes the initiator's orientation to `on_flow_start`
(also for a flow whose first packet was the responder's); flow-end and
tick hooks read `stats.initiator_orientation`. For `observe_dns`, pass
the orientation of the packet that carried the query — a DNS slot
message's `orientation`. A detector that wants the acting host reads
`Directed::new(key, initiator).src_ip()`.

**`Event::Started.orientation` (#218).** With
`FlowTrackerConfig::infer_tcp_initiator`, a flow whose first captured
packet is the responder's SYN+ACK used to report *that packet's*
orientation on the typed driver's `Started`. It now reports the
initiator's, as documented — equal to `FlowStats::initiator_orientation`.
`FlowEvent::Started` is unchanged: it carries the first packet's
`side` and `orientation` (`side == Responder` in that case).

## 7. Exporters report IP octets (#219)

What each output counts since 0.26 (L2 = the packet's wire length,
Ethernet header and padding included; IP = the IP datagram, header
included):

| Output | Field | 0.25 | 0.26 |
|---|---|---|---|
| `FlowRecord` (IPFIX) | `octet_delta_count_*` (IE 1), `octet_total_count` (IE 85) | captured L2 | **IP octets** (`FlowStats::ip_bytes_*`) |
| `FlowRecord` | `layer2_octet_delta_count_*` (IE 352), `layer2_octet_total_count` (IE 353) | — | **new**: wire L2 (`Option`, set by `from_key_fields`) |
| IPFIX wire export | IE 1 / IE 85 | captured L2 | IP octets (template unchanged) |
| Zeek | `orig_bytes` / `resp_bytes` | captured L2 | wire L2 |
| Zeek | `orig_ip_bytes` / `resp_ip_bytes` | — | **new columns**: IP octets |
| EVE `flow` / `stats` | `bytes_toserver` / `bytes_toclient` | captured L2 | wire L2 |
| EVE `flow` / `stats` | `ip_bytes_toserver` / `ip_bytes_toclient` | — | **new**: IP octets |
| CSV | `bytes_init` / `bytes_resp` | captured L2 | wire L2 |
| CSV | `ip_bytes_init` / `ip_bytes_resp` | — | **new trailing columns**: IP octets |
| `CicFlowFeatures` | byte features | captured L2 | wire L2 (IE 352 / 353, else IE 1 / 85) |

**Zeek column order.** The two new columns sit where Zeek puts them:
`… history orig_pkts orig_ip_bytes resp_pkts resp_ip_bytes`. A reader
that takes `resp_pkts` by position (column 14 in 0.25) finds
`orig_ip_bytes` there now — read by the `#fields` header, which lists
the new names. `orig_bytes` remains flowscope's wire L2 count, not
Zeek's TCP-payload byte count.

**CSV.** `ip_bytes_init` / `ip_bytes_resp` are appended after
`end_reason`; `end_reason` is no longer the last column.

**IPFIX.** Collectors now receive RFC-correct `octetDeltaCount`
values. If you build a `FlowRecord` yourself (`Default` + mutate) and
fill `octet_delta_count_*`, those are IP octets; set the
`layer2_octet_*` fields too if you want the Zeek / CSV / EVE `bytes`
columns to show L2 bytes (they fall back to the IP octets otherwise).

## 8. Bounded rate tables (#220)

Additive: nothing to change to keep compiling. `RollingRate<K, V>` and
`BandwidthByKey<K>` gain a bounded constructor:

```rust
// Before (still available): one entry per key per bucket, unbounded.
let r = RollingRate::<IpAddr, u64>::new_unbounded(window, bucket);
// After: at most 10 000 keys per one-second bucket.
let r = RollingRate::<IpAddr, u64>::new(window, bucket, 10_000);
let bw = BandwidthByKey::<Attribution>::new(window, bucket, 10_000);
```

When a bucket is full, a new key's values go to that bucket's overflow
total instead of a new entry: read it with `other_rate(now)` /
`other_sum(now)` (`other_tx_bps` / `other_rx_bps`), and watch
`overflowed()` — the number of records that were folded. A folded key
is missing from that bucket's `rate`, `sum`, `snapshot` and `top_k`.
If those tables are keyed by anything the network controls
(addresses, ports, owners), switch to `new`.
