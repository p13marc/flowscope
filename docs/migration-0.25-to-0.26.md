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
