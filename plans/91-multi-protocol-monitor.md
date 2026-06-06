# Plan 91 — Multi-protocol monitor recipe + example

## Summary

Wishlist item B2 asks for a `FlowMultiSessionDriver` that runs multiple
L7 parsers on the same packet stream (HTTP + TLS on a single TCP flow
when ports overlap; DNS + TLS in one pcap pass). The plan-of-record
defers the full composite driver to a 0.9 RFC because the
sum-type-of-messages design surface needs real-world usage data
before commit-down.

This plan ships the **lighter-version fallback** the wishlist
suggested: a documented recipe + worked example demonstrating the
manual packet-level loop pattern that demuxes by port. Consumers
needing the multi-parser behaviour right now get a turnkey reference;
the future composite driver remains a clean evolution path.

## Status

Not started.

## Prerequisites

- Plan 76 (`icmp` module) — shipped in 0.7.0. The example
  demonstrates HTTP + TLS + DNS + ICMP in one pass.
- Plan 86 (parser-kind constants) — shipped in this cycle. The
  example matches on `parser_kinds::HTTP` / `TLS` / `DNS_UDP` /
  `ICMP` rather than literals.
- Plan 78 (HTTP accessors) — shipped in 0.7.0. Used in the recipe
  to extract `host()` / `sni()` for the printed output.

## Out of scope

- A `FlowMultiSessionDriver` implementation. That's the 0.9 RFC
  (plan TBD). The recipe stays.
- Per-port automatic dispatch. The example uses an explicit
  per-packet dispatch loop; the consumer is in charge.
- Reassembly state sharing across parsers. Each parser owns its
  own reassembler; the recipe doesn't attempt cross-parser zero-
  copy.

## Files

- `examples/multi_protocol_monitor.rs` — new example. Reads a pcap,
  routes each packet by port to HTTP / TLS / DNS / ICMP parsers,
  prints a unified one-line-per-event summary.
- `docs/SESSION_GUIDE.md` — new top-level section "Multi-protocol
  monitoring" with the recipe.
- `tests/multi_protocol_monitor_smoke.rs` — smoke test that the
  example compiles and runs against a small synthetic pcap fixture.
- `Cargo.toml` — example entry with required features.
- `CHANGELOG.md` — `### Added` entry.

## Recipe shape

```rust,ignore
use flowscope::{FlowEvent, FlowSessionDriver, FlowDatagramDriver};
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::tls::{TlsHandshake, TlsParser};
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::icmp::IcmpParser;

# fn main() -> Result<(), Box<dyn std::error::Error>> {
// Three drivers, three pcap iterators (one per parser kind needed).
// All three consume the same pcap path; the iterator overhead is
// modest compared to actually parsing the per-flow byte streams.
let source = PcapFlowSource::open("trace.pcap")?;

// Session drivers route by destination port via the extractor or
// post-track filter; for the simplest recipe, run every TCP packet
// through each session-eligible parser and let the parser produce
// nothing on non-applicable traffic.
let mut http = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
let mut tls = FlowSessionDriver::new(FiveTuple::bidirectional(), TlsParser::default());

let mut dns = FlowDatagramDriver::new(FiveTuple::bidirectional(), DnsUdpParser::default());
let mut icmp = FlowDatagramDriver::new(FiveTuple::bidirectional(), IcmpParser::new());

// Single pass: each packet goes to the driver matching its port /
// L4. Track returns events; merge into a single chronological stream.
for view in source.views() {
    let view = view?;
    // L4-aware dispatch using the extractor's first-pass classification.
    // (See SESSION_GUIDE for the per-parser port-filter helper.)
    for ev in http.track(&view) { print_event("http", ev); }
    for ev in tls.track(&view) { print_event("tls", ev); }
    for ev in dns.track(&view) { print_event("dns", ev); }
    for ev in icmp.track(&view) { print_event("icmp", ev); }
}
# Ok(()) }
```

The recipe documents the cost-vs-clarity trade-off:

> Running each driver against every packet is simpler than
> implementing port-based dispatch but wastes per-packet extractor
> work. For high-throughput pipelines, you'd write the dispatch
> manually (e.g. matching on
> `FlowEvent::Started { l4: Some(L4Proto::Tcp), .. }` and
> `view.dst_port`). The composite-driver RFC (planned for 0.9)
> will absorb this boilerplate; until then, this recipe is the
> recommended pattern.

## Implementation steps

1. **Write `examples/multi_protocol_monitor.rs`** matching the
   recipe shape. Use the existing pcap fixtures from
   `tests/fixtures/`. The example takes a pcap path as a CLI arg
   for general use, defaulting to the bundled fixture for `cargo
   run --example multi_protocol_monitor`.
2. **Cargo.toml entry**:
   ```toml
   [[example]]
   name = "multi_protocol_monitor"
   required-features = ["pcap", "http", "tls", "dns", "icmp"]
   ```
   (i.e. `l7,pcap` umbrella satisfies this.)
3. **SESSION_GUIDE section** "Multi-protocol monitoring" — three
   subsections:
   - When you need it (overlapping TCP ports; mixed-protocol
     pcaps; cross-protocol correlators).
   - The simple recipe (every-driver-every-packet, ~30 LoC).
   - The performant recipe (manual port-based dispatch, ~80 LoC).
   - Forward pointer: composite driver RFC for 0.9.
4. **Smoke test** in `tests/multi_protocol_monitor_smoke.rs` that
   imports the example's main as a function (via `cfg(test)`-aware
   factoring) and asserts non-zero events.
5. **CHANGELOG entry under `### Added`**:
   ```
   - **Multi-protocol monitor recipe + example** (plan 91).
     `examples/multi_protocol_monitor.rs` demonstrates running
     HTTP + TLS + DNS + ICMP parsers against a single pcap with
     correlated output. SESSION_GUIDE gains a "Multi-protocol
     monitoring" section covering both the simple "every parser
     every packet" pattern and the performant manual-dispatch
     pattern. A composite driver (round-3 wishlist B2) is
     deferred to a 0.9 RFC; this recipe is the recommended
     pattern until then.
   ```

## Tests

`tests/multi_protocol_monitor_smoke.rs`:

- `example_runs_without_panic` — drive the recipe against a
  small synthetic pcap, count events, assert non-zero counts
  for at least one parser (the test fixture is curated to hit
  HTTP).

## Acceptance criteria

- `cargo run --example multi_protocol_monitor --features
  l7,pcap` runs against a bundled fixture and prints expected
  events.
- `cargo test --features l7,pcap --test
  multi_protocol_monitor_smoke` clean.
- SESSION_GUIDE explicitly forward-points to the future composite
  driver RFC.
- The example is referenced from the README's "What you can do"
  section (one line).

## Risks

- **Example becomes a hot-path benchmark.** The "every driver every
  packet" pattern is intentionally suboptimal; documented as
  such. Consumers benchmarking flowscope hit the manual-dispatch
  recipe instead.
- **Recipe staleness when composite driver lands.** When the 0.9
  RFC ships, this recipe gets a deprecation note and a forward
  pointer; the example itself becomes the "manual" reference.

## Effort

~80 LoC example + ~30 LoC test + ~80 lines SESSION_GUIDE.
**~3 hours.**

## Provenance

Round-3 wishlist item B2 in
[`docs/feedback-2026-06-06-netring-wishlist.md`](../docs/feedback-2026-06-06-netring-wishlist.md),
specifically the *"if too heavy, ship a recipe"* fallback the
author proposed. Plan-of-record §5 documents why we go with the
recipe + example for 0.8 and defer the composite driver.
