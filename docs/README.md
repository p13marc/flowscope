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
