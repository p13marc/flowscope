# DPI architecture — state of the art and recommendations for `flowscope`

> Research compiled May 2026. Primary sources cited inline; full URL list at the end.

## TL;DR

- The "fast read on many threads → classification thread → extraction thread" mental
  model is a **classic three-stage pipeline**. It is NOT what state-of-the-art
  Deep Packet Inspection engines actually do in 2025–2026.
- All three reference open-source DPI engines (nDPI, Suricata, Zeek) and modern
  high-performance frameworks (DPDK, VPP, AF_XDP-based stacks) converge on the
  same pattern: **shard packets per-flow via NIC RSS or symmetric kernel
  hashing, then run the entire pipeline (capture → classify → extract → output)
  on a single core dedicated to that shard.** This is "run-to-completion per
  flow" (RTC). Pipelines exist as a fallback for offline replay (Suricata
  `autofp`) but are no longer the production design.
- The architectural frontier is **eBPF/XDP prefilters in the kernel** — drop,
  hash, or bypass at L2/L3/L4 before packets reach userspace, and only escalate
  L7 work to userland workers when needed. Suricata 7+, Cilium, Katran, and
  Cloudflare's edge all use this pattern.
- For `flowscope` specifically, the recommendation is:
  1. **Keep the single-crate-with-features layout** that just landed. It maps
     cleanly onto an RTC-per-worker deployment.
  2. **Reject the three-stage pipeline split** (`flowscope-rx` / `-classify` /
     `-extract`) — the research is unambiguous that this is the wrong shape.
  3. **Plan one targeted split at 1.0**: extract `flowscope-core` (traits and
     types only) so third-party protocol parsers can depend on a thin, stable
     surface.
  4. **Add complementary sister crates** as demand surfaces:
     `flowscope-rss` (multi-worker orchestration), `flowscope-prefilter`
     (aya/XDP integration helpers), `flowscope-cli` (the planned CLIs).

The rest of this document defends those four claims.

---

## 1. What "state of the art" actually looks like

### 1.1 Three reference DPI engines

| Engine    | Threading model            | Where flow lookup runs | Where L7 classify runs | Where L7 extract runs |
|-----------|----------------------------|-------------------------|-------------------------|-------------------------|
| **nDPI**  | None — caller-driven       | Caller's thread         | Caller's thread         | Caller's thread         |
| **Suricata** (`workers` runmode) | RTC per RSS queue | Worker | Worker (`FlowWorker`) | Worker (same call) |
| **Zeek** (cluster)               | One process per core | Worker process | Worker process | Worker process |

The convergence is striking. **No production DPI engine in 2026 runs
classification and extraction on different threads.** The reasoning is the
same in all three:

- The flow state record is the working set. Every L7 stage needs it. Moving
  the packet across cores costs an L1/L2 cache miss per stage; moving the
  flow record across cores costs even more (state is bigger and dirties).
- L7 protocol decisions feed back into flow state (e.g., "this flow is
  bypassed", "this flow's app-layer is HTTP/1.1 — set up the parser").
  Pipelining requires a feedback channel that is itself a synchronization
  bottleneck.
- A pipeline thread that's slower than the upstream stage stalls the whole
  chain. RTC per-flow means each worker stalls only its own flows; RSS gives
  natural load balancing.

### 1.2 The Suricata case study

Suricata is the most useful reference because it explicitly ships **both**
designs and lets you choose, which makes the trade-off legible.

```
runmode: workers              runmode: autofp (deprecated for IPS/IDS)
─────────────────              ──────────────────────────────────────
                                                     ┌─→ flow worker 0
[NIC] ─RSS─┬─→ [worker 0]      [NIC] → [decode] ─hash┼─→ flow worker 1
           ├─→ [worker 1]                            ├─→ flow worker 2
           ├─→ [worker 2]                            └─→ flow worker N
           └─→ [worker N]
each worker = capture + decode +    capture+decode in one stage,
              flow lookup + stream  flow lookup + L7 in another;
              reassembly + L7 +     handoff via hash queue.
              detect + output
```

The Suricata user guide (suricata.io performance/runmodes) is explicit:
`workers` is the default and recommended runmode for live IDS/IPS at speed.
`autofp` exists for offline pcap replay (where there's no NIC RSS) and for
NFQ-based inline IPS (where NFQ delivers all traffic to one queue and you
*have* to fan out in software). Both `autofp` use cases share the property
that **you don't have a real RSS shard available**, so software has to
reproduce one. They are not architectural improvements — they are
workarounds.

The 2024 article *Performance characterization of Suricata thread models*
(xbu.me) measured the gap: pure `workers` linearly scaled with cores; `autofp`
hit a synchronization ceiling around 4–6 worker threads when the hash queue
contended.

### 1.3 nDPI: not actually a DPI engine

A subtle but important point. **nDPI is not an engine; it is a per-packet
classification and extraction library.** It does not own packet capture, the
flow table, or threading. The host application (ntopng, nProbe, Suricata via
FFI, PF_RING FT) provides those. nDPI's only thread-safety constraint is that
each `ndpi_flow_struct` must always be accessed from the same thread — which
is automatically true if the host shards by RSS.

This shape — **library, not framework** — is the right frame for `flowscope`.
You stay out of the threading and capture business; the user (or a sister
crate like `netring`) provides those, and you provide the per-flow logic.

### 1.4 Zeek's "scaling = more processes" answer

Zeek is single-threaded **per process**. Multi-core scaling is a cluster of
processes coordinated by Broker pub/sub. AF_PACKET fanout groups (since Zeek
5.2) flow-pin packets to specific worker processes. There is no in-process
worker pool.

This is even further from the user's three-stage mental model: Zeek doesn't
have a pipeline at all — it has many independent single-threaded copies of
itself. The reason is the same one nDPI gives: per-flow state is the
load-bearing data structure; partitioning it via RSS is cheaper than
synchronizing access to a shared one.

### 1.5 The 2024–2026 frontier: eBPF prefilters

The actual architectural change in the last 24 months is **not** at the
threading layer — it is at the kernel boundary.

- **Suricata 7+** ships AF_XDP as a first-class capture, plus per-CPU eBPF
  bypass maps (`flow_table_v4` / `flow_table_v6`). Once a flow is classified
  as "boring" (e.g., elephant TCP that's already been inspected), the kernel
  short-circuits subsequent packets without ever entering Suricata. With
  Netronome SmartNICs the eBPF program runs on the NIC itself.
- **Cilium** uses XDP `prefilter` programs to drop bad-destination traffic
  before the network stack. L7 work is delegated to userspace Envoy.
- **Katran** (Meta) and Cloudflare's edge L4 LBs do all forwarding in XDP at
  line rate; userspace only sees control-plane packets.
- SIGCOMM 2025's **X2DP** paper demonstrated 2.3× throughput gains by
  specializing XDP programs to the kernel data path.

The pattern: **kernel-side L2/L3/L4 fast path; userspace L7 slow path,
escalated only when needed.** This is the inversion of the user's mental
model. Instead of multiple userspace threads reading and one thread
classifying, the *kernel* does the cheap classification and the userspace is
a single per-flow worker.

### 1.6 DPDK and VPP — the throughput playbook

DPDK, the canonical kernel-bypass framework, supports both RTC and pipeline
(`rte_ring`) modes. The 2025 reality from the DPDK Programmer's Guide and
practitioner blogs:

- **RTC dominates** for new builds. Per-RSS-queue lcores keep mbufs hot in L1,
  there is no inter-core handoff, and RSS provides load balancing for free.
- **Pipeline (`rte_ring` HTS / RTS / SORING modes)** is used when stages have
  very asymmetric cost (a slow crypto or DPI stage beside cheap forwarding) or
  when ordering across stages must be enforced. Even then, modern designs
  prefer "fat" RTC workers with software prefetch hiding DRAM latency over
  pipeline handoffs.

VPP is a different beast. Its trick is processing **vectors of ~256 packets**
through a graph of nodes, amortizing L1-instruction-cache misses across the
batch. This is wonderful for **stateless** L2/L3 forwarding — and explicitly
fragile for **stateful DPI**. ipoque (the Phoenix DPI vendor) and the fd.io
docs both note that per-flow state lookups defeat the I-cache amortization
because dispatch diverges per packet. VPP DPI integrations exist, but they
sit awkwardly inside the vector model.

### 1.7 AF_XDP vs DPDK in 2026

The 2024 paper *Understanding Delays in AF_XDP-based Applications* (arxiv
2402.10513) and ntop's positioning blog converged on a clear summary for the
"new build" question:

- DPDK still wins single-core no-touch microbenchmarks.
- AF_XDP plus `SO_PREFER_BUSY_POLL` (Linux ≥5.11) closes most of the gap
  once the application actually touches payload — which DPI always does.
- AF_XDP's operational story is dramatically better: drivers come from
  upstream, kernel observability tools work, NIC sharing with the rest of the
  system is seamless.
- PF_RING ZC (ntop) remains the choice for **appliance-style 100GbE+** where
  every nanosecond and a curated NIC list are acceptable.

Translation: for a Rust DPI library aiming at "portable, deployable in 2026",
AF_XDP is the right primary fast path, and `netring` already targets that.

---

## 2. The Rust ecosystem in this space

A short survey of what already exists, since the question is "where does
flowscope fit."

| Project       | Shape           | Threading | Notes |
|---------------|-----------------|-----------|-------|
| **Retina** (Stanford SIGCOMM '22) | Framework | DPDK lcore RTC, sync | Filter-and-callback API via heavy procedural macros. DPDK-bound. |
| **protolens**  | Library         | Single-threaded sync, callback-driven | Explicit "one instance per thread"; ~80 stars; 0.2.x; HTTP/SMTP/POP3/IMAP/FTP/SIP. |
| **rusticata** (`tls-parser`, `pcap-parser`, `der-parser`, …) | Parser libraries | None | Pure `nom`, fuzzed. Already used by Suricata via FFI. The parser foundation. |
| **aya**        | eBPF userland   | N/A       | The de-facto pure-Rust eBPF stack with BTF/CO-RE. redbpf is effectively deprecated in its favor. |
| **smoltcp**    | Embedded TCP/IP | `no_std`, event-driven | Worth studying for **bounded reassembly state machines**, not for scale. |
| **flowscope** (this project) | Library | Runtime-free; consumer drives threading | The current shape. |

Three takeaways:

1. **Retina is the only "framework-shaped" Rust DPI**, and even Stanford has
   pointed users at its successor "Iris" rather than maintaining it as a
   library others embed. Frameworks demand the user write callbacks inside
   your harness, which doesn't compose.
2. **protolens consciously rejected async**, calling out that Tokio's
   `Send`/`Sync` constraints punish per-packet work. Retina also runs sync
   per-core threads. **The Rust DPI consensus is sync per-flow** — exactly
   what `flowscope` already is.
3. **There is no idiomatic, safe, fast TCP-reassembly building block** in
   crates.io today. `flowscope::Reassembler` + `BufferedReassembler` plus a
   `protolens` bridge fills part of this gap; a zero-copy reassembler with a
   `Bytes`-based output is still an open opportunity.

---

## 3. Reframing the user's mental model

The user's question, paraphrased:

> The fast read is pinned into multiple threads. An algorithm only does
> classification. Another extracts information based on this. How should we
> split flowscope's crates accordingly?

The research is unambiguous: this is **not** how SOTA DPI is structured.
What's actually true:

| User's model                       | SOTA reality                                         |
|------------------------------------|------------------------------------------------------|
| Multiple threads do "fast read"    | NIC does fast read via RSS into N independent queues |
| One thread classifies              | The same per-queue worker classifies                 |
| Another extracts                   | The same per-queue worker extracts                   |
| Stages communicate via queues      | No queues on the hot path — per-flow state is local  |

The user's model **is correct as a description of `autofp`** — the legacy
Suricata mode kept around for offline replay. It is not what production
engines run.

Why does the per-flow RTC model feel so counterintuitive? Two reasons:

- **It looks parallelizable.** Splitting into stages superficially looks like
  three parallel things; in reality, a single long-running worker per flow
  parallelizes better because cache locality dominates.
- **Pipelines are a great pattern in other domains** (ETL, video encoding,
  compilers). What makes them wrong for DPI is that **the data each stage
  needs is the same per-flow record**, and that record is small (~kB).
  Moving it between stages is pure overhead.

The right way to think about parallelism in flowscope is therefore not "which
crate runs on which thread" but **"how many independent per-flow workers do
we run, and how do we shard packets onto them."** That's a deployment
concern, not a library structure concern.

---

## 4. Recommendations for `flowscope`

### 4.1 Don't split the core into pipeline stages

The current single-crate-with-features layout is **architecturally correct**
for SOTA DPI. The strongest evidence is that nDPI, the most-deployed DPI
*library* in the world, is a single library that is invoked synchronously
per packet on a flow that the caller already owns. flowscope is shaped the
same way.

Concretely: do **NOT** create crates like

```
flowscope-rx       # capture + read
flowscope-classify # protocol classification
flowscope-extract  # info extraction
```

This bakes the wrong architecture into the type system. A user who actually
runs SOTA RTC has to import all three and stitch them together; the splits
fight the natural call graph. Suricata's history with `autofp` shows that
even a single project with both designs converges on the unsplit one.

### 4.2 Keep `flowscope` single-crate with feature gates

The recently-landed layout — `flowscope` + features (`http`, `tls`, `ja3`,
`dns`, `pcap`) — matches the way nDPI ships protocols (each in
`src/lib/protocols/foo.c`, all built into one library) and the way Suricata
ships parsers (each app-layer parser in `src/app-layer-foo.c`, all linked
into one binary). It is the smallest viable surface that gives users
opt-in granularity.

The only reason to revisit this would be if **a particular protocol's
dependency tree becomes a problem** for users who don't enable it. So far
that isn't the case: `tls` pulls `tls-parser`, `dns` pulls `simple-dns`,
`http` pulls `httparse`. These are small, fast-compiling crates. Until that
changes, the umbrella crate wins on discoverability and version cadence.

### 4.3 At 1.0, factor out `flowscope-core`

When `SessionParser` / `DatagramParser` lock in (the explicit pre-1.0
gate from plan 31), there is one targeted split worth doing:

```
flowscope-core       # traits + plain types only (no protocol, no pcap, no etherparse)
flowscope            # the library users actually use; depends on -core, adds extractors,
                     # tracker, reassembler, pcap, http, tls, dns
```

The reason is **plugin authors**. A third party who wants to write
`flowscope-quic` or `flowscope-amqp` shouldn't pay the compile cost of every
other module just to depend on the trait shape. tower / tower-http / serde /
serde_derive are the canonical Rust precedents.

`flowscope-core` would contain:
- `PacketView`, `Timestamp`
- `FlowExtractor`, `Extracted`, `Orientation`, `L4Proto`, `TcpFlags`,
  `TcpInfo`
- `FlowSide`, `FlowEvent`, `FlowState`, `EndReason`, `FlowStats`,
  `HistoryString`
- `Reassembler`, `ReassemblerFactory`, `BufferedReassembler` (?)
- `SessionParser`, `SessionParserFactory`, `DatagramParser`,
  `DatagramParserFactory`, `SessionEvent`

Everything else (built-in extractors that need `etherparse`, the tracker that
needs `lru` and `ahash`, every protocol module) stays in `flowscope`.

This is a 1.0 decision because before 1.0, splitting the trait crate from
the implementation crate just doubles the API churn surface. Wait until
`SessionParser` is locked.

### 4.4 Add sister crates as demand surfaces

Three candidates worth pre-planning, **none of them required for 1.0**:

#### 4.4.1 `flowscope-rss` — multi-worker orchestration

The library has no opinion on how many workers run or how to shard packets.
A separate crate can opinionatedly answer "give me N workers each running an
RTC pipeline, with packets RSS-sharded between them." Two implementations
should be possible:

- **Sync, threads-only**: one OS thread per worker, pinned via `core_affinity`,
  packets delivered by a sharded source (e.g. `netring` AF_XDP per-queue
  sockets, one per worker). No async.
- **Tokio-aware**: each worker is a `LocalSet` running on a pinned runtime
  thread; useful if downstream processing benefits from async.

Suricata's `flow.cluster_type = cluster_flow | cluster_qm | cluster_cpu` is
the prior art for the configuration surface. The library decision is **don't
let `flowscope` itself dictate this**; let `flowscope-rss` opt in.

#### 4.4.2 `flowscope-prefilter` — eBPF/XDP integration helpers

The 2024–2026 frontier is kernel-side prefilters. A `flowscope-prefilter`
crate would glue `aya` programs to the userspace `flowscope` worker. Two
concrete primitives:

- **Bypass map plumbing**: read a per-CPU eBPF hash map keyed by 5-tuple,
  call the userspace tracker only on cache miss. Mirrors Suricata's bypass
  pattern.
- **First-packet hint**: an XDP program that classifies a few well-known
  protocols by `dst_port` (and by SNI on the first segment — possible since
  XDP can read the first packet's payload) and tags the AF_XDP frame's
  metadata so userspace can skip the classification stage. Mirrors nDPI's
  First Packet Classification.

This is genuinely future-facing; user demand will determine if/when.

#### 4.4.3 `flowscope-cli` — the planned CLI binaries

Plan 60 (`flow-summary`, `flow-replay`) was always going to be a separate
crate. With the consolidation it now naturally lands as `flowscope-cli` next
to `flowscope`. Standard pattern (`tokio` ↔ `tokio-test` style).

### 4.5 Don't add a pipeline orchestrator inside `flowscope`

A tempting fourth crate — `flowscope-pipeline`, the user's mental model
written down — should **not** exist. Every reason it might exist is better
served by the user's own loop:

- "I want to fan out work" → `flowscope-rss` with per-worker RTC.
- "I want to bridge between sync and async" → that's a `tokio::spawn` call,
  not a library.
- "I want to chain parsers" → that's how `SessionParser` and the next
  parser are composed in user code.

Resist building a framework. flowscope is a library; let the caller own the
loop, as nDPI and rusticata already model.

---

## 5. Concrete proposed layout

```
flowscope/                              ← github.com/p13marc/flowscope (single repo)
├── flowscope-core/         (1.0+)     ← extracted at 1.0 cut
│   └── traits + plain types only
├── flowscope/              (today)    ← the umbrella crate users add
│   ├── core re-exports (or a `pub use flowscope_core::*;`)
│   ├── extractors (FiveTuple, IpPair, MacPair, decap)
│   ├── tracker (FlowTracker, FlowDriver)
│   ├── reassembler (BufferedReassembler, ReassemblerFactory)
│   ├── session/datagram parser glue
│   ├── http/    (feature)
│   ├── tls/     (feature, +ja3)
│   ├── dns/     (feature)
│   └── pcap/    (feature)
├── flowscope-rss/          (post-1.0) ← RSS-sharded multi-worker harness
├── flowscope-prefilter/    (post-1.0) ← aya/XDP integration
└── flowscope-cli/          (post-1.0) ← flow-summary / flow-replay binaries
```

The async stream adapters (`SessionStream`, `DatagramStream`,
`AsyncReassembler`) stay in `netring` because they depend on
`AsyncCapture`. If a non-`netring` async source emerges (e.g. an
`async-pcap` crate), it can offer its own adapters that consume
`flowscope`'s traits.

---

## 6. Migration sequencing

Roughly in order of "should be done", aligned with existing plans:

1. **Stay the course on plan 31 phase 2.** Lock the `SessionParser` shape by
   shipping the TLS and DNS-TCP bridges, property tests, and migration
   guide. This is the gate to 1.0.
2. **Cut 1.0 with `flowscope-core` extraction.** One workspace, two
   published crates: `flowscope-core` and `flowscope`. Users keep using
   `flowscope`; library authors gain a thin trait dep.
3. **Plan 41 (`flowscope-perf-foundations`)**: zero-copy reassembly with
   `BytesMut` pool, LRU hot-cache. The literature is clear that this is the
   throughput differentiator. AF_XDP + zero-copy reassembly is the SOTA
   stack.
4. **Plan 60 → `flowscope-cli`**: ship the CLIs as a separate crate so a
   `cargo install flowscope-cli` works without dragging library deps into
   downstream binaries.
5. **`flowscope-rss`**: build it when the second user asks. Internal
   structure: per-worker pinned thread, MPSC fan-in for output events,
   `core_affinity` + optional NUMA awareness. Take Suricata's
   `cluster_flow` / `cluster_qm` / `cluster_cpu` as the configuration
   vocabulary.
6. **`flowscope-prefilter`**: build it when an eBPF-savvy user can co-design.
   Aya is mature enough; the unknowns are in the userspace API for
   bypass-map mediation.

Each of these is independently shippable. None of them required to call
flowscope SOTA-aligned today.

---

## 7. What "DIP/DPI state of the art" looks like, as one diagram

```
           ┌──────────────────────────────────────────────────────┐
           │                          NIC                         │
           │   RSS hashes 5-tuple → queue 0 / 1 / … / N-1        │
           └─┬──────────────────┬──────────────────┬──────────────┘
             │                  │                  │
        ┌────▼────┐        ┌────▼────┐        ┌────▼────┐
        │XDP prog │        │XDP prog │        │XDP prog │   ← eBPF prefilter
        │drop|hash│        │drop|hash│        │drop|hash│     (aya / Cilium / Katran)
        │ bypass  │        │ bypass  │        │ bypass  │
        └────┬────┘        └────┬────┘        └────┬────┘
             │                  │                  │
        ┌────▼────────┐    ┌────▼────────┐    ┌────▼────────┐
        │AF_XDP socket│    │AF_XDP socket│    │AF_XDP socket│
        │  (queue 0)  │    │  (queue 1)  │    │  (queue N-1)│
        └────┬────────┘    └────┬────────┘    └────┬────────┘
             │                  │                  │
   ┌─────────▼──────────┐  ┌────▼────────────┐  ┌──▼──────────────┐
   │ worker 0           │  │ worker 1        │  │ worker N-1      │
   │ pinned to core 0   │  │ pinned to core 1│  │ pinned to coreN-1
   │                    │  │                 │  │                 │
   │  flow lookup       │  │  flow lookup    │  │  flow lookup    │
   │      ↓             │  │      ↓          │  │      ↓          │
   │  reassembly        │  │  reassembly     │  │  reassembly     │
   │      ↓             │  │      ↓          │  │      ↓          │
   │  classify          │  │  classify       │  │  classify       │
   │      ↓             │  │      ↓          │  │      ↓          │
   │  extract (parse)   │  │  extract (parse)│  │  extract (parse)│
   │      ↓             │  │      ↓          │  │      ↓          │
   │  emit event        │  │  emit event     │  │  emit event     │
   └─────────┬──────────┘  └────────┬────────┘  └─────────┬───────┘
             │                      │                     │
             └──────────────────────┼─────────────────────┘
                                    │  (bounded MPSC, async-friendly)
                              ┌─────▼──────┐
                              │ output     │  ← sink: log writer, IPFIX
                              │ aggregator │     exporter, Kafka, etc.
                              └────────────┘
```

What sits where in this diagram:

- **NIC RSS** — provided by the hardware. Configure via `ethtool -X`.
- **eBPF prefilter** — written with `aya`, deployed via
  `flowscope-prefilter` (future).
- **AF_XDP socket** — provided by `netring`'s capture layer.
- **Per-worker pipeline** — provided by `flowscope` itself, with `flowscope`
  features (`http`, `tls`, `dns`) supplying the parsers.
- **Worker orchestration** — provided by `flowscope-rss` (future).
- **Output aggregator** — provided by user code or `flowscope-cli`.

Every box is replaceable. Critically, no two boxes need to live in the same
crate, but they don't need to live in *different* crates either — the
boundary is up to the user's deployment. The library job is to make the
per-worker box ergonomic, sound, and fast. That's flowscope's scope.

---

## 8. Open questions worth resolving before 1.0

1. **Lock-free shared flow tables.** If two workers ever need to consult each
   other's flow records (e.g., for cross-flow correlation), a shared table
   becomes necessary. `papaya` (lock-free, read-optimized) and `scc` are the
   two viable Rust answers. The research is mixed: production engines avoid
   this entirely by sharding, but analytics use cases (e.g., "find the DNS
   query that resolved this connection's IP") sometimes want it.

2. **The HTTP/2 problem.** SessionParser is a per-flow sync trait that
   assumes one stream per flow. HTTP/2 multiplexes many streams over one
   connection. Plan 31 flagged this; the answer is probably a separate
   `MultiplexedSessionParser` trait when demand emerges.

3. **QUIC.** UDP carrying a TLS-like handshake plus stream multiplexing.
   Probably a `flowscope-quic` crate when dependencies (`quinn-proto` or a
   passive `quic-parser`) mature. **Not for 1.0.**

4. **Hardware offload.** Suricata's Netronome path runs eBPF on the NIC.
   AWS / Azure smart NICs are emerging. Worth tracking but not designing for
   yet.

5. **Should `Reassembler` move to `flowscope-core`?** Right now it's coupled
   to `tracker`. If a user wants to do reassembly without flow tracking,
   they can't. Probably yes — it's a primitive, like the parsers.

---

## 9. Appendix: source list

### DPI engines
- nDPI repository — https://github.com/ntop/nDPI
- nDPI 4.10 release notes (FPC introduced) — https://www.ntop.org/released-ndpi-4-10-421-protocols-55-flow-risks-several-improvements-getting-ready-for-fpc/
- nDPI 4.15 release notes — https://www.ntop.org/introducing-ndpi-4-15-added-qoe-quality-of-experience-and-new-protocols-several-fixes/
- DeepWiki nDPI overview — https://deepwiki.com/ntop/nDPI/1-ndpi-overview
- PF_RING FT (nDPI flow table) — https://www.ntop.org/guides/pf_ring/ft.html
- Suricata 9.0-dev runmodes — https://docs.suricata.io/en/latest/performance/runmodes.html
- Suricata AF_XDP capture — https://docs.suricata.io/en/latest/capture-hardware/af-xdp.html
- Suricata eBPF/XDP bypass — https://docs.suricata.io/en/latest/capture-hardware/ebpf-xdp.html
- Suricata `flow-worker.c` — https://github.com/OISF/suricata/blob/main/src/flow-worker.c
- Suricata `flow-hash.c` — https://github.com/OISF/suricata/blob/master/src/flow-hash.c
- Performance characterization of Suricata thread models — https://xbu.me/article/performance-characterization-of-suricata-thread-models/
- Zeek cluster architecture — https://docs.zeek.org/en/master/cluster/architecture.html
- Zeek packet analysis framework — https://docs.zeek.org/en/master/frameworks/packet-analysis.html
- Zeek Supervisor framework — https://docs.zeek.org/en/master/frameworks/supervisor.html
- Zeek + Spicy — https://docs.zeek.org/en/master/devel/spicy/

### Fast-path frameworks
- DPDK Programmer's Guide — https://doc.dpdk.org/guides/prog_guide/overview.html
- DPDK Ring Library (HTS/RTS/SORING) — https://doc.dpdk.org/guides/prog_guide/ring_lib.html
- DPDK Hash Library (cuckoo `rte_hash`) — https://doc.dpdk.org/guides/prog_guide/hash_lib.html
- DPDK AF_XDP PMD — https://doc.dpdk.org/guides/nics/af_xdp.html
- fd.io VPP scalar vs vector — https://fd.io/docs/vpp/v2101/whatisvpp/scalar-vs-vector-packet-processing
- ipoque on VPP DPI — https://www.ipoque.com/blog/vector-visibility-dpi-a-must-for-vector-packet-processing
- Phoenix DPI on VPP — https://phoenixdpi.com/blog/vector-packet-processing/
- Linux kernel AF_XDP — https://docs.kernel.org/networking/af_xdp.html
- arxiv 2402.10513 — *Understanding Delays in AF_XDP-based Applications* — https://arxiv.org/html/2402.10513v1
- ntop PF_RING ZC vs DPDK — https://www.ntop.org/pf_ring/positioning-pf_ring-zc-vs-dpdk/
- PF_RING AF_XDP module — https://www.ntop.org/guides/pf_ring/modules/af_xdp.html
- ACM 2023 *Survey on mechanisms for fast network packet processing* — https://dl.acm.org/doi/fullHtml/10.1145/3603781.3603792
- Cuckoo++ Hash Tables — https://arxiv.org/pdf/1712.09624

### eBPF / XDP
- Cilium eBPF prefilter — https://docs.cilium.io/en/stable/network/ebpf/intro/
- Katran (Meta) — https://github.com/facebookincubator/katran
- Cloudflare Unimog edge LB — https://blog.cloudflare.com/unimog-cloudflares-edge-load-balancer/
- eunomia eBPF ecosystem 2024–2025 — https://eunomia.dev/blog/2025/02/12/ebpf-ecosystem-progress-in-20242025-a-technical-deep-dive/
- X2DP (SIGCOMM 2025) — https://dl.acm.org/doi/10.1145/3744969.3748399
- aya-rs — https://github.com/aya-rs/aya · book https://aya-rs.dev/book/

### Rust DPI ecosystem
- Retina (Stanford SIGCOMM '22) — https://github.com/stanford-esrg/retina · paper https://zakird.com/papers/retina.pdf
- protolens — https://github.com/chunhuitrue/protolens · https://crates.io/crates/protolens
- rusticata — https://github.com/rusticata
- rustnet — https://github.com/domcyrus/rustnet
- Sniffnet — https://lib.rs/crates/sniffnet
- smoltcp — https://github.com/smoltcp-rs/smoltcp
- dashmap — https://github.com/xacrimon/dashmap
- papaya — https://docs.rs/papaya · https://ibraheem.ca/posts/designing-papaya/
- scc — https://github.com/wvwwvwwv/scalable-concurrent-containers
- parallax — https://github.com/p13marc/parallax

### NUMA / cache
- DPDK Packet Framework — https://doc.dpdk.org/guides/prog_guide/packet_framework.html
- Red Hat OVS-DPDK multi-NUMA — https://developers.redhat.com/blog/2017/06/28/ovs-dpdk-parameters-dealing-with-multi-numa
