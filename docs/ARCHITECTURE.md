# flowscope architecture

A short tour of the layers and how they fit together. For "which API
do I pick" see [`SESSION_GUIDE.md`](SESSION_GUIDE.md). For the
state-of-the-art DPI research that informed the design, see
`plans/DPI_ARCHITECTURE.md` in the repo.

## The pipeline

```
  ┌────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
  │  view  │──▶│  extractor   │──▶│   tracker    │──▶│  reassembler │
  │  &[u8] │   │  (key + L4)  │   │  (FlowEvent) │   │  (per-side)  │
  └────────┘   └──────────────┘   └──────────────┘   └──────┬───────┘
                                                            │
                                  ┌─────────────────────────┴─────────┐
                                  ▼                                   ▼
                        ┌──────────────────┐                ┌──────────────────┐
                        │  Conversation    │                │  SessionParser   │
                        │  (init+resp Bytes│                │  DatagramParser  │
                        │   as one Stream) │                │  (typed messages)│
                        └──────────────────┘                └──────────────────┘
                          (lives in netring)
```

Every layer has a trait the user can plug into. The library ships
sensible defaults (FiveTuple, FlowTracker, BufferedReassembler) but
none are mandatory.

## Layer 1 — `FlowExtractor`

A function from a packet to a flow descriptor:

```rust
trait FlowExtractor: Send + Sync + 'static {
    type Key: Hash + Eq + Clone + Send + Sync + 'static;
    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<Self::Key>>;
}

struct Extracted<K> {
    key: K,
    orientation: Orientation,    // Forward or Reverse (canonicalisation)
    l4: Option<L4Proto>,
    tcp: Option<TcpInfo>,
}
```

Decap combinators wrap an inner extractor:

```rust
StripVlan(InnerVxlan::new(FiveTuple::bidirectional()))
//   strip 802.1Q   then VXLAN UDP/4789   then 5-tuple
```

The same `FlowExtractor` interface is honored for the inner one —
combinators don't grow the trait surface.

`AutoDetectEncap` is the "I have mixed traffic, just figure it out"
combinator. It costs up to 5× the per-packet parse cost on a miss;
manual composition is faster when you know the encap shape.

`FlowLabel<E>` is a key-augmentation combinator: it appends the IPv6
flow label (RFC 6437) to the inner key, so MPTCP subflows that
share a 5-tuple can be distinguished.

## Layer 2 — `FlowTracker<E, S>`

Per-flow accounting on top of the extractor. The state machine is
the centerpiece:

```
SynSent ──ack──▶ SynReceived ──ack──▶ Established ──fin──▶ FinWait
   │                                       │                │
   │                                       └──rst──▶ Reset  fin
   └──rst──▶ Reset                                          │
                                                            ▼
                                                      ClosingTcp
                                                            │
                                                          ack
                                                            ▼
                                                         Closed
```

Non-TCP flows skip the SYN handshake states; they go directly to
`Active` and stay there until idle-timeout sweep.

Idle timeouts default to Suricata's values (TCP 5 min, UDP 60 s, other
30 s) and are configurable. LRU eviction kicks in at `max_flows`
(default 100k). Per-flow user state `S` is generic; default `()`.

`FlowEvent<K>` lifecycle: `Started` → (zero or more `Packet` /
`Established` / `StateChange`) → `Ended { reason, stats, history }`.

## Layer 3 — `Reassembler`

Sync per-`(flow, side)` byte stream hook. The tracker calls
`segment(seq, payload)` for every TCP packet that has data. On flow
end, `fin()` or `rst()`.

The default `BufferedReassembler` accumulates in-order bytes and
drops out-of-order segments (Suricata-style `inline-mode`). Other
reassemblers can provide gap-filling, retransmit-detection, etc. —
[`netring-flow`'s old `protolens` bridge example](https://github.com/p13marc/flowscope/blob/master/plans/21-flow-protolens.md)
showed how to wrap a third-party reassembler.

`ReassemblerFactory<K>::new_reassembler(&key, side)` builds a fresh
instance per `(flow, side)`. The factory is shared; the reassembler
is not.

## Layer 4 — `SessionParser` / `DatagramParser`

Typed L7 messages on top of the bytes. Two trait variants:

- **`SessionParser`** for stream protocols (HTTP/1.x, TLS, DNS-TCP).
  One parser per flow; `feed_initiator(bytes)` and
  `feed_responder(bytes)` each return `Vec<Self::Message>`.
- **`DatagramParser`** for packet protocols (DNS-UDP). One parser
  per flow; `parse(payload, side)` returns `Vec<Self::Message>`.

`SessionEvent<K, M>` ties the parser output to flow lifecycle:
`Started`, `Application { side, message }`, `Closed`.

The `*Factory<K>` companion traits build per-flow parsers; any
`Default + Clone` parser is its own factory via a blanket impl.

### Module bridges

The shipped protocol modules each provide both API shapes:

| Protocol | Callback (`*Factory<H>`)        | Stream (`SessionParser`/`DatagramParser`) |
|----------|---------------------------------|---------------------------------|
| HTTP/1.x | `HttpFactory<H>`                 | `HttpParser`                    |
| TLS      | `TlsFactory<H>`                  | `TlsParser`                     |
| DNS UDP  | `DnsUdpObserver<E, H>`           | `DnsUdpParser`                  |
| DNS TCP  | (use `Reassembler` directly)     | `DnsTcpParser` (length-framed)  |

Both API shapes produce the same events for the same wire bytes;
choose by control flow.

## Tokio integration

flowscope itself is **runtime-free**. To get an async stream of flow
events, use [`netring`](https://crates.io/crates/netring)'s adapters:

- `AsyncCapture::flow_stream(extractor)` — `Stream<FlowEvent>`
- `.session_stream(parser)` — `Stream<SessionEvent<_, M>>` for
  TCP-based parsers
- `.datagram_stream(parser)` — same for UDP-based parsers
- `.broadcast(buffer)` — fan a flow stream out to N subscribers
- `.with_async_reassembler(factory)` — backpressure from consumer →
  capture

These live in netring because they depend on `AsyncCapture` (which
needs `AsyncFd`, which needs tokio).

Other capture sources (pcap files, custom tun-tap) can write their
own adapters that consume flowscope's traits.

## State invariants

### Tracker

- **Mono-direction never doubles back.** Once a flow's `Initiator`
  side is determined (first packet), it stays. The tracker maintains
  this via an internal canonicalisation in the extractor's
  `Orientation`.
- **Per-protocol idle timeouts are independent.** A TCP flow with
  no traffic for 60 s isn't ended; a UDP flow is.
- **`max_flows` evicts oldest by `last_seen`.** When eviction fires,
  the tracker emits `Ended { reason: Evicted, ... }`.

### Reassembler

- **In-order only.** Out-of-order segments are dropped by
  `BufferedReassembler`. Custom reassemblers may differ.
- **`fin()` is idempotent.** Multiple FINs on the same side are fine.

### Parsers

- **Splitting invariance.** Feeding a byte sequence in one chunk
  produces the same messages as feeding it in any random splits.
  Verified by `tests/parser_proptest.rs` for all four parsers.
- **No-panic on random bytes.** Garbage input never panics; either
  errors or skips.
- **DNS-TCP length-prefix recovery.** A garbage body framed by a
  valid 2-byte length prefix consumes `len` bytes and recovers for
  the next message — framing is preserved across malformed payloads.

## Threading

flowscope has no threads of its own. Threading is the consumer's
responsibility. The recommended deployment, per the SOTA DPI
research:

```
NIC RSS → N AF_XDP queues → N pinned worker threads, each owning
   its own (FlowExtractor, FlowTracker, Reassembler, SessionParser)
   end-to-end (run-to-completion per flow).
```

Sharding by RSS gives natural load balancing; per-flow state is
local to each worker, so no locks on the hot path. This is what
nDPI / Suricata `workers` runmode / Zeek cluster all converge on.

A pipeline-stage architecture (separate threads for capture / classify
/ extract) is anti-pattern for SOTA DPI — see
`plans/DPI_ARCHITECTURE.md` for the survey.

## Design constraints

- **Runtime-free.** No tokio, no futures, no background tasks in
  flowscope. Async lives in netring.
- **No `unsafe` in safe-slice code paths.** `Bytes` / `Vec<u8>`
  for buffers; `unsafe` is reserved for the rare zero-copy spots
  that need it.
- **Deterministic.** No global state, no atomics on the hot path,
  no surprises across worker shards.
- **Bounded memory.** Every stateful component has a max:
  `max_flows`, `max_buffer`, `max_pending`.
- **Trait stability lock.** `SessionParser` / `DatagramParser`
  shape is committed as of 0.1.0; additions only.

## See also

- [`SESSION_GUIDE.md`](SESSION_GUIDE.md) — picking the right L7
  parser API for your use case (with migration recipes).
- [`../README.md`](../README.md) — the front-page intro.
- `plans/DPI_ARCHITECTURE.md` (in-repo) — full SOTA-DPI research and
  crate-split recommendations.
- `plans/INDEX.md` (in-repo) — roadmap and per-plan status.
