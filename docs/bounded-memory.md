# Bounded memory: what flowscope promises

flowscope parses data an attacker controls, often inline. The promise
is therefore narrow and specific:

> **flowscope will not be your unbounded buffer.** Every place it
> accumulates attacker-influenced data has a cap, and exceeding that
> cap has a defined outcome — refuse, drop, or evict — never
> unbounded growth.

That promise has an important qualifier: **several caps are opt-in**,
and the out-of-the-box defaults favour observation over defence
because the passive path historically came first. This page says
exactly which are which, so you can configure the ones your
deployment needs rather than discovering them under load.

Produced by the issue #169 audit; the assertions behind it live in
`tests/bounded_memory.rs`.

## The short version

| If you are… | Do this |
|---|---|
| building an inline proxy | use `HttpProxyParser` (or `Http2Parser` for h2). Every cap is on by default and `push` returns a short count as backpressure. |
| running passive telemetry at scale | set `FlowTrackerConfig::max_reassembler_buffer` — it is `None` (unbounded per side) by default. |
| using load-shedding (`EventMask`) | be aware resource cleanup is currently tied to `Ended` events; see the caveats. |
| using `correlate` primitives directly | prefer the bounded constructors; several types offer only `new_unbounded`. |

## HTTP — bounded by default

| Buffer | Knob | Default | On exceed |
|---|---|---|---|
| head block | `HttpProxyConfig::max_head_bytes` | 64 KiB | poison `HeadOverflow` |
| header count | `max_headers` | 128 | poison |
| chunk-size line | `max_chunk_line_bytes` | 256 B | poison `ChunkLineOverflow` |
| trailer section | `max_trailer_bytes` | 8 KiB | poison `TrailerOverflow` |
| outstanding requests | `max_pipelined` | 64 | poison `PipelineOverflow` |
| unparsed bytes per direction | `max_buffered_bytes` | 256 KiB | `push` accepts fewer bytes — backpressure, not failure |

Message bodies are **never** accumulated by the streaming parser at
any size; they are reported as spans and dropped.

A direction that can no longer parse — desynced, tunnelled, or closed
— stops storing bytes entirely. Without that, a peer that keeps
sending after a poison would grow the buffer for the life of the
connection. (This was a real regression introduced earlier in the
0.23 cycle and caught by this audit; `tests/bounded_memory.rs` guards
it now.)

The passive `HttpParser` does buffer bodies — that is its purpose —
bounded by `HttpConfig::max_buffer` (1 MiB). Past it the body is
dropped and the message is still framed and emitted.

## HTTP/2 — bounded by default

Every cap is on out of the box, and `SETTINGS` from the peer can
lower the effective limits but never raise them past these.

| Buffer | Knob | Default | On exceed |
|---|---|---|---|
| one frame | `Http2Config::max_frame_size` | 1 MiB | `FrameTooLarge` (the protocol allows 16 MiB − 1; this is deliberately tighter) |
| one field block, across `HEADERS` + `CONTINUATION` | `max_header_block_bytes` | 64 KiB | `HeaderListTooLong` |
| HPACK dynamic table | `max_hpack_table_bytes` | 64 KiB | **hard ceiling** — a peer advertising a larger `SETTINGS_HEADER_TABLE_SIZE` is refused with `HpackTableSizeExceeded` |
| concurrent streams tracked | `max_concurrent_streams` | 256 | `TooManyStreams` |
| unparsed bytes per direction | `max_buffered_bytes` | 1 MiB | `push` accepts fewer bytes — backpressure |
| whether the client preface is required | `require_preface` | `true` | `BadPreface`; `Http2Session` sets `false` so a flow joined mid-connection parses |

**The two size caps compose.** `max_buffered_bytes` is the *effective*
frame ceiling: a frame larger than a direction's buffer could never be
held whole, so it is refused with `FrameTooLarge` at its 9-byte header
rather than buffered. Without that composition the two caps contradict
each other and the direction wedges — it fills waiting for a frame that
will never fit, then refuses every later byte for the life of the
connection while reporting no error. A direction that genuinely cannot
progress now fails with `BufferOverflow`. The contract this buys:
**`push` returning 0 always implies `is_failed()` or `is_finished(dir)`**,
which is what makes `Http2Session` safe — the `SessionParser` trait
cannot express a short read, so an adapter must be able to treat a
refusal as terminal.

The HPACK ceiling is the one worth understanding: the dynamic table
is memory *the peer decides the size of*, so the peer's advertised
value is clamped rather than trusted. A failure is fatal to the
connection, not the stream — HPACK state is shared, so once the table
is out of step every later field block decodes to plausible nonsense.

A completed or reset stream frees its slot immediately, so
`max_concurrent_streams` bounds concurrency rather than total streams
on the connection.

## TLS, DNS, QUIC, IP fragments

| Component | Knob | Default | On exceed |
|---|---|---|---|
| TLS per-direction buffer | `TlsConfig::max_buffer` | 64 KiB | desync; the direction stops accumulating |
| DNS correlator pending | `DnsConfig::max_pending` | 10 000 | evict oldest; plus a 30 s `query_timeout` |
| DNS-over-TCP buffer | *(implicit)* | ~64 KiB | bounded by the 16-bit length prefix |
| `dns::NameMap` | `max_ips` / `max_claims_per_ip` / `max_pending` | 16 384 / 8 / 4096 | LRU |
| IP fragment reassembly | `FragmentConfig::max_datagrams` / `max_datagram_bytes` / `timeout` | 4096 / 64 KiB / 30 s | drop oldest datagram / drop / expire |
| QUIC pending Initials | `QuicConfig::max_pending_connections` / `pending_ttl` | 1024 conns / 5 s | evict the entry longest without progress |
| QUIC CRYPTO per connection | `QuicConfig::max_crypto_bytes` / `max_crypto_frames` | 64 KiB / 64 frames | refuse the frame, count it in `pending_dropped()` |

## TCP reassembly

| Buffer | Knob | Default | On exceed |
|---|---|---|---|
| in-order stream | `FlowTrackerConfig::max_reassembler_buffer` | 1 MiB per side | `SlidingWindow` (default) drops oldest bytes, flow survives; `DropFlow` poisons → `Ended { BufferOverflow }` |
| out-of-order segments | `SegmentBufferReassembler::with_max_ooo_buffer` | 256 KiB | evict oldest hole, then drop the arriving segment; 1 s hole deadline |
| cross-flow pool | `reassembly_memcap` + `MemcapPolicy` | **`None` — off** | per policy: `Ignore` (default) reports only; `DropPacket` refuses the segment; `PassThrough` releases the side and keeps the flow; `DropFlow` ends it |

`max_reassembler_buffer` defaulted to `None` before 0.23. It is now
1 MiB per side, so the default configuration is bounded; raise it if
you reassemble larger messages whole, and check
`FlowStats::reassembly_bytes_dropped_oversize_initiator` / `_responder`
if a parser starts seeing gaps. The **cross-flow** pool is still
opt-in.

## Flow table

`FlowTracker` is LRU-bounded by `FlowTrackerConfig::max_flows`
(100 000). Eviction emits `Ended { Evicted }` plus a
`FlowTableEvictionPressure` anomaly, so capacity pressure is
observable rather than silent.

## Per-protocol parser buffers

Each L7 parser bounds its own per-direction buffer, but the
**overflow behaviour is not uniform** — worth knowing before you rely
on it:

| Parser | Cap | On exceed |
|---|---|---|
| LDAP | 256 KiB | poison → flow ends with `ParseError` |
| SMB | 1 MiB | buffer cleared, parsing resynchronises |
| Kerberos | 256 KiB | buffer cleared |
| DNP3 | 64 KiB | buffer cleared |
| Modbus | 64 KiB | buffer cleared |
| SSH | ~256 KiB (packet-length bound) | buffer cleared |
| RDP | 4 KiB | side disabled |
| FTP / SMTP | 4 KiB / 8 KiB per line | line skipped |

`flowscope::BufferedFrameDrain` exists as the shared bounded
accumulator with one defined overflow (`FrameDrainError::BufferFull`),
but the parsers above predate it and each rolls its own. Converging
them is tracked separately.

## Parsed-message queues

`SlotHandle` and `BroadcastSlotHandle` are backed by an **unbounded**
lock-free queue, by design: the driver must never block the capture
path. The bound is your drain rate. Each queued message is fully
owned — a telemetry `HttpMessage` can carry up to `max_buffer` of
body — so a consumer that stops draining while the driver keeps
running will grow memory. `SlotHandle::len()` is the signal; drain in
the same loop, or use `drain_n` to bound per-iteration work.

## `correlate` primitives: check the constructor

Most primitives offer both a bounded and an unbounded constructor.
The unbounded ones are legitimate when the key space is known-small;
they are a hazard when keys come from the network.

| Bounded available | Unbounded only |
|---|---|
| `KeyIndexed`, `FirstSeen`, `NeighborTable`, `TopK`, `BitStore`, `TimeBucketedCounter`*, `TimeBucketedSet`* | `RollingRate`, `BurstDetector`, `Ewma`, `EwmaVar`, `FlowStateMap` |

\* `TimeBucketedCounter` / `TimeBucketedSet` capacity is a **soft**
cap: eviction applies to the oldest bucket, so a burst of unique keys
lands in the newest bucket untouched. Size for
`(window / bucket_width) × keys-per-bucket`.

`Ewma`, `EwmaVar`, and the beacon detectors expose `evict_stale(now,
ttl)` but do not call it themselves — drive it from your tick loop.
`FlowAnalyzer::new` is unbounded; `FlowAnalyzer::with_capacity` is the
one to use in production.

## Known gaps

None outstanding. The #169 audit found five; all are closed, and four
of them changed behaviour in ways worth knowing about:

- **QUIC reassembly is bounded on every axis** ([#184]). CRYPTO
  accumulation had no per-connection byte or frame cap, and the TTL
  was refreshed on *arrival* — so `evict_stale` could never reach a
  DCID that was being actively fed, which is exactly the traffic it
  existed to bound. The TTL now advances only when the contiguous
  reassembled prefix grows, and `QuicConfig` caps bytes, frames, and
  connections. `QuicUdpParser::pending_dropped()` and `tracked()`
  make the bounds observable.
- **`PortScanDetector` is capacity-bounded** ([#187]). Entries were
  released on a verdict, but a source that stayed `Inconclusive`
  persisted forever — one per spoofed address. `with_capacity`
  (default 10 000) evicts the least-recently-touched source, which by
  the detector's own semantics simply restarts it at λ = 0.
- **Cleanup no longer keys off `Ended`** ([#185]). Per-flow
  reassemblers and parsers used to be torn down only when the flow's
  `Ended` event was seen — but that event is gated on
  `EventMask::ENDED` while the tracker reaps the flow either way, so
  a consumer shedding events under load leaked one set per flow.
  Every sweep now reconciles against the tracker and releases
  whatever belongs to a flow that is gone, refunding its memcap
  bytes. Suppressing `Ended` is safe.
- **`max_reassembler_buffer` now defaults to 1 MiB** ([#188]), with
  the existing `SlidingWindow` policy. See
  [the migration guide](migration-0.22-to-0.23.md#5-reassembly-is-bounded-by-default-188)
  if you were relying on unbounded reassembly.

The fifth, [#186], made `MemcapPolicy` behave as each variant
documents — see the next section.

[#184]: https://github.com/p13marc/flowscope/issues/184
[#185]: https://github.com/p13marc/flowscope/issues/185
[#186]: https://github.com/p13marc/flowscope/issues/186
[#187]: https://github.com/p13marc/flowscope/issues/187
[#188]: https://github.com/p13marc/flowscope/issues/188

## Choosing a `MemcapPolicy`

`reassembly_memcap` is off by default. When you turn it on, the policy
decides whether it is a *report* or a *bound*:

| Policy | Bounds memory? | Flow survives? |
|---|---|---|
| `Ignore` (default) | **No** — counts the violation, keeps buffering | yes |
| `DropPacket` | Yes — refuses the segment that would cross the cap | yes |
| `PassThrough` | Yes — releases the offending side's buffer | yes, still tracked |
| `DropFlow` | Yes — ends the flow, freeing both sides | no |

`Ignore` matches Suricata's `memcap-policy: ignore` and is a reporting
mode. If you configured a cap because you need one, pick one of the
other three.

## Testing this yourself

`tests/bounded_memory.rs` is the adversarial suite: slow-drip headers,
endless header blocks, 64 MiB bodies, unterminated chunk framing and
trailers, unbounded pipelining, a caller that never drains, and
post-poison / post-tunnel accumulation. Each asserts a specific cap
holds or a specific refusal happens. Extend it rather than trusting
this page.
