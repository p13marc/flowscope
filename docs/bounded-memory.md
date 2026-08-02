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
| building an inline proxy | use `HttpProxyParser`. Every cap is on by default and `push` returns a short count as backpressure. |
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

## TLS, DNS, QUIC, IP fragments

| Component | Knob | Default | On exceed |
|---|---|---|---|
| TLS per-direction buffer | `TlsConfig::max_buffer` | 64 KiB | desync; the direction stops accumulating |
| DNS correlator pending | `DnsConfig::max_pending` | 10 000 | evict oldest; plus a 30 s `query_timeout` |
| DNS-over-TCP buffer | *(implicit)* | ~64 KiB | bounded by the 16-bit length prefix |
| `dns::NameMap` | `max_ips` / `max_claims_per_ip` / `max_pending` | 16 384 / 8 / 4096 | LRU |
| IP fragment reassembly | `FragmentConfig::max_datagrams` / `max_datagram_bytes` / `timeout` | 4096 / 64 KiB / 30 s | drop oldest datagram / drop / expire |
| QUIC pending Initials | *(internal)* | 1024 conns, 5 s TTL | evict oldest |

## TCP reassembly — caps are opt-in

| Buffer | Knob | Default | On exceed |
|---|---|---|---|
| in-order stream | `FlowTrackerConfig::max_reassembler_buffer` | **`None` — unbounded** | with a cap: `SlidingWindow` (default) drops oldest bytes, flow survives; `DropFlow` poisons → `Ended { BufferOverflow }` |
| out-of-order segments | `SegmentBufferReassembler::with_max_ooo_buffer` | 256 KiB | evict oldest hole, then drop the arriving segment; 1 s hole deadline |
| cross-flow pool | `reassembly_memcap` + `MemcapPolicy` | **`None` — off** | see caveats |

**Set `max_reassembler_buffer` if you track untrusted traffic.** With
the default, one flow whose parser never consumes grows one `Vec<u8>`
per direction without limit.

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

The #169 audit found these still open. They are real, and listed here
rather than quietly left in the code:

| Gap | Impact | Issue |
|---|---|---|
| QUIC CRYPTO reassembly has no per-connection byte cap, and its TTL refreshes on every packet | a peer replaying Initials on one DCID with never-completing CRYPTO frames grows one buffer without limit | [#184](https://github.com/p13marc/flowscope/issues/184) |
| Reassembler and parser cleanup keys off `Ended` events | suppressing `EventMask::ENDED` (load shedding) leaves per-flow reassemblers and parsers resident — precisely during overload | [#185](https://github.com/p13marc/flowscope/issues/185) |
| `MemcapPolicy::Ignore` (the default) and `DropPacket` emit an anomaly but free nothing | `reassembly_memcap` does not actually cap with the default policy; `PassThrough` behaves like `DropFlow` rather than as documented | [#186](https://github.com/p13marc/flowscope/issues/186) |
| `PortScanDetector.sources` has no capacity or TTL | a spoofed-source SYN flood adds one entry per source, forever | [#187](https://github.com/p13marc/flowscope/issues/187) |
| `max_reassembler_buffer` defaults to `None` | the default configuration has no per-flow reassembly bound | [#188](https://github.com/p13marc/flowscope/issues/188) |

Until they are closed, the mitigations are: cap
`max_reassembler_buffer`, avoid `EventMask::ENDED` suppression, drive
`PortScanDetector::forget`, and treat the QUIC parser as
trusted-traffic-only.

## Testing this yourself

`tests/bounded_memory.rs` is the adversarial suite: slow-drip headers,
endless header blocks, 64 MiB bodies, unterminated chunk framing and
trailers, unbounded pipelining, a caller that never drains, and
post-poison / post-tunnel accumulation. Each asserts a specific cap
holds or a specific refusal happens. Extend it rather than trusting
this page.
