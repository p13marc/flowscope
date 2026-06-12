# Plan 173 — Example sweep for the 0.14 surface

**Cycle:** 0.14.0 pre-release polish
**Priority:** P0 (DX gate — examples are the discoverability fix)
**Effort:** ~1 day
**Status:** drafted

## Motivation

Audit verdict: ZERO existing examples touch any of the 0.14
surface (`grep -l 'RollingRate|lookup_inner|LabelTable|DestUnreachableKind|drain_expired|app_label|direction_skew' examples/`
returns nothing). Users have rustdoc, recipes in
`docs/recipes.md` §"0.14 patterns", and the migration doc —
but nothing they can `cargo run`.

The wishlist (§16) explicitly says netring 0.22 will build:
- `bandwidth_by_app()` monitor primitive on top of plans 163 + 164
- `IcmpError` typed event on top of plan 161

Shipping the canonical flowscope-side examples NOW gives
netring 0.22 a reference implementation to copy, and lets
flowscope users adopt the patterns without going through
netring.

## Proposed examples

Three new runnable examples under `examples/04-observability/`.

### `bandwidth_by_app.rs`

The canonical pattern. `RollingRate<&'static str, u64>` keyed
on `app_label()`, fed from a pcap source, prints top-10
talkers every second.

```rust
//! Bandwidth-by-app: per-app bytes/sec over a 60-second
//! sliding window, top-10 talkers report.
//!
//! Run: cargo run --features pcap --example bandwidth_by_app -- trace.pcap

use std::time::Duration;
use flowscope::correlate::RollingRate;
use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::well_known::LabelTable;
use flowscope::{PacketView, Timestamp};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: trace.pcap")?;

    // Built-in well-known labels + 2 site-custom services.
    let mut labels = LabelTable::new();
    labels.set(flowscope::extractor::L4Proto::Tcp, 8765, "grpc-internal");
    labels.set(flowscope::extractor::L4Proto::Tcp, 9101, "metrics-scrape");

    let mut bw: RollingRate<&'static str, u64> = RollingRate::new_unbounded(
        Duration::from_secs(60),
        Duration::from_secs(1),
    );

    let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut last_report = Timestamp::from_unix_nanos(0);

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let view = PacketView::from(&owned);
        events.clear();
        driver.track_into(view, &mut events);
        for ev in &events {
            if let Event::FlowPacket { key, len, ts, .. } = ev {
                bw.record(key.app_label_with(&labels), *len as u64, *ts);
                if ts.to_unix_nanos() - last_report.to_unix_nanos() >= 1_000_000_000 {
                    print_top10(&bw, *ts);
                    last_report = *ts;
                }
            }
        }
    }
    Ok(())
}

fn print_top10(bw: &RollingRate<&'static str, u64>, now: Timestamp) {
    // After plan 171 lands: bw.top_k(10, now). Until then: snapshot+sort.
    let mut snap: Vec<_> = bw.snapshot(now).collect();
    snap.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
    println!("--- top-10 talkers at {now:?} ---");
    for (label, rate) in snap.iter().take(10) {
        println!("  {label:<20} {rate:>10.0} B/s");
    }
}
```

### `icmp_explained_drops.rs`

The plan 161 showcase. `FlowTracker::lookup_inner` joins ICMP
errors back to live flows; `DestUnreachableKind` classifies
the error; the result is a "flow X died because of port-unreachable
from host Y" log line — the canonical L4 monitor question
answered in one method call.

```rust
//! ICMP-explained drops: every ICMP error message is joined
//! back to the live flow it concerns (if any) and classified
//! by DestUnreachableKind / MtuSignalKind.
//!
//! Run: cargo run --features pcap,icmp --example icmp_explained_drops -- trace.pcap

use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::icmp::{IcmpInner, IcmpParser, IcmpType};
use flowscope::pcap::PcapFlowSource;
use flowscope::{DestUnreachableKind, PacketView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // … driver builder with icmp parser slot; on each icmp Message:
    //   if let Some(inner) = icmp.error_inner_owned() { … }
    //   if let Some(kind) = icmp.dest_unreachable_kind() { … }
    //   if let Some(mtu_kind) = icmp.mtu_signal() { /* plan 170 */ … }
    //   if let Some((flow_key, stats)) = tracker.stats_for_inner(&inner) {
    //       println!("flow {flow_key:?} hit {kind}: {bytes}B in flight",
    //           bytes = stats.total_bytes());
    //   }
    Ok(())
}
```

(Full implementation in the plan execution; sketch above is
indicative.)

### `direction_skew_anomaly.rs`

The plan 168 showcase. `FlowStats::direction_skew` powers a
simple one-sided-flow detector — flag flows that ended with
|skew| > 0.9 (DoS / scan / asymmetric streaming).

```rust
//! Direction-skew anomaly: flag flows whose bytes are
//! >90% one-sided at end-of-flow.
//!
//! Run: cargo run --features pcap --example direction_skew_anomaly -- trace.pcap

use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSide, PacketView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args().nth(1).ok_or("usage: trace.pcap")?;
    let mut driver = Driver::builder(FiveTuple::bidirectional()).build();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(PacketView::from(&owned), &mut events);
        for ev in &events {
            if let Event::FlowEnded { key, stats, .. } = ev {
                let skew = stats.direction_skew();
                if skew.abs() > 0.9 {
                    let direction = if skew > 0.0 { "upload" } else { "download" };
                    println!(
                        "one-sided {direction} flow {key:?}: \
                         {init}B up / {resp}B down (skew {skew:+.2})",
                        init = stats.bytes_for(FlowSide::Initiator),
                        resp = stats.bytes_for(FlowSide::Responder),
                    );
                }
            }
        }
    }
    Ok(())
}
```

## Files touched

- `examples/04-observability/bandwidth_by_app.rs` — new
- `examples/04-observability/icmp_explained_drops.rs` — new
- `examples/04-observability/direction_skew_anomaly.rs` — new
- `examples/04-observability/README.md` — append three rows
- `examples/Cargo.toml` — register three new `[[example]]` entries
  with correct `required-features` keys
- `examples/README.md` — append three rows to the index table

## Acceptance criteria

- All three examples build under their declared features.
- All three run end-to-end against `tests/data/mixed_short.pcap`
  (or whatever the standard fixture is) and produce non-empty
  output.
- Each example's top doc-comment cites the plan it
  demonstrates (161 / 164 / 168) + the migration doc section
  for the API.
- Listed in `examples/README.md` index.

## Non-goals

- Async / live-capture variants — those belong in netring.
- A combined "all-three-in-one" mega-example — separate is
  clearer.
