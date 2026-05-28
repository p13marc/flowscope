# flowscope docs

Published reference material — ships as part of the crates.io
package. For forward-looking work items, see
[`../plans/`](../plans/) (in-repo only).

## How-to / reference

| File | What |
|------|------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | High-level architecture overview. Read first. |
| [`SESSION_GUIDE.md`](SESSION_GUIDE.md) | Picking the right L7 parser API: `FlowEvent` / `Reassembler` / `*Factory<H>` / `SessionParser` / `DatagramParser` / `FlowSessionDriver` / `FlowDatagramDriver`. Includes a "Writing your own SessionParser" walkthrough and migration recipes. |
| [`OBSERVABILITY.md`](OBSERVABILITY.md) | Metric vocabulary, cardinality notes, Prometheus / Grafana sample queries, `tracing-subscriber` wiring. |
| [`PERFORMANCE.md`](PERFORMANCE.md) | Criterion bench methodology and baseline numbers. |

## Design / research (background)

| File | What |
|------|------|
| [`DPI_ARCHITECTURE.md`](DPI_ARCHITECTURE.md) | SOTA-DPI research and crate-split recommendations (2026). Why flowscope is shaped the way it is, and where sister crates fit. |
| [`flow-session-tracking-design.md`](flow-session-tracking-design.md) | Original design rationale for the flow / session tracking surface. The *why* behind the `FlowExtractor` / `FlowTracker` / `Reassembler` / `SessionParser` layering. |
| [`high-level-features-design.md`](high-level-features-design.md) | High-level features survey. Drove the `Dedup` primitive shape and other 0.3.0 ergonomics. |

## Feedback records

| File | What |
|------|------|
| [`feedback-2026-05-14-des-rs.md`](feedback-2026-05-14-des-rs.md) | External feedback from the `des-rs` team after migrating onto 0.2.0. Drove the 0.3.0 "production hardening" release (11 sub-plans). Worth re-reading when the next consumer-feedback cycle starts. |
| [`feedback-2026-08-11-simple-nms.md`](feedback-2026-08-11-simple-nms.md) | Upstream wishlist from the `simple-nms` team after migrating onto 0.4.0. Drives the 0.5.0 release plan (plans 70–74). Cross-confirms several `des-rs` requests; the periodic-tick item now has two-consumer demand. |
