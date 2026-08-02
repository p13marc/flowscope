# flowscope docs

Published reference material — ships as part of the crates.io
package. For forward-looking work items, see
[`../plans/`](../plans/) (in-repo only).

## Read in order

| File | What |
|------|------|
| [`getting-started.md`](getting-started.md) | Install + three minimal pipelines (lifecycle / offline HTTP / async live). |
| [`concepts.md`](concepts.md) | The four layers (`FlowExtractor` / `FlowTracker` / `Reassembler` / `SessionParser` / `DatagramParser`) and the event model. |
| [`recipes.md`](recipes.md) | Named patterns: picking an API, writing your own parser, multi-protocol monitoring, cross-protocol correlation, structured output. |
| [`observability.md`](observability.md) | Metric vocabulary, cardinality, tracing targets, severity routing. |
| [`performance.md`](performance.md) | Criterion bench methodology, baseline numbers, regression workflow. |
| [`design.md`](design.md) | Why the library is shaped the way it is — runtime-free, run-to-completion threading, layered traits, locked serde format. |

## Reference, by topic

| File | What |
|------|------|
| [`discoverability.md`](discoverability.md) | One-page tour of the prelude, grouped by "I want to…". Start here when you know the goal but not the type name. |
| [`bounded-memory.md`](bounded-memory.md) | Which buffers are capped, which caps are **opt-in**, and what overflow does. Read before pointing this at untrusted traffic. |
| [`tls-routing.md`](tls-routing.md) | Routing by SNI / ALPN: the degradation ladder, why ECH is advisory-only, post-quantum ClientHello sizes, ALPACA binding. |
| [`eve-format.md`](eve-format.md) | Suricata EVE JSON schema mapping, including the `event_type: "http"` access record. |
| [`tls-ech.md`](tls-ech.md) | What ECH does and does not leave observable. |
| [`detect-patterns.md`](detect-patterns.md) | The named detectors — beaconing, port scan, DGA, and friends. |
| [`file-hash.md`](file-hash.md) | Streaming file hashing and magic-byte classification. |
| [`sharded.md`](sharded.md) | Per-CPU sharded capture. |

## Migrating

One document per breaking cycle; read from your current version
forward.

| File | Cycle |
|------|-------|
| [`migration-0.22-to-0.23.md`](migration-0.22-to-0.23.md) | Inline-proxy cycle: one streaming HTTP engine, `BodyFraming::UntilClose`, and the framing behaviour that changed. |
| [`migration-0.21-to-0.22.md`](migration-0.21-to-0.22.md) | Stateful `QuicUdpParser`, `parser_kinds` removal. |
| [`migration-0.20-to-0.21.md`](migration-0.20-to-0.21.md) | Typed `DetectorKind`, detection architecture. |
| [`migration-0.19-to-0.20.md`](migration-0.19-to-0.20.md) | Driver/event convergence, `ParserKind`. |

Earlier cycles: `migration-0.10-to-0.11.md` through
`migration-0.17-to-0.18.md`.
