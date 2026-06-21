//! Use the `tracing` feature for ad-hoc parser / flow
//! introspection.
//!
//! Enables a [`tracing_subscriber::fmt`] subscriber configured
//! from `RUST_LOG`, walks a pcap through a [`FlowDriver`] with
//! anomaly emission on, and lets the per-flow / per-anomaly /
//! per-tracker events fire to stderr.
//!
//! ## Tracing vocabulary
//!
//! All events live under the `flowscope.*` target hierarchy:
//!
//! - `flowscope.flow` — flow lifecycle (started / ended).
//! - `flowscope.flow.anomaly` — `FlowAnomaly` events.
//! - `flowscope.tracker` — tracker-wide signals (sweep / OOM
//!   reject / unknown packet drop).
//! - `flowscope.parser.*` — per-message decoder events from
//!   the L7 parsers under the relevant feature flags.
//!
//! See `docs/observability.md` for the full table.
//!
//! ## Filtering
//!
//! ```bash
//! # All flowscope events at debug or higher:
//! RUST_LOG=flowscope=debug cargo run ... --example tracing_subscriber
//!
//! # Only flow lifecycle, no per-message noise:
//! RUST_LOG=flowscope.flow=info cargo run ... --example tracing_subscriber
//!
//! # Everything at trace (very noisy — per packet):
//! RUST_LOG=flowscope=trace cargo run ... --example tracing_subscriber
//! ```
//!
//! ## Formatters
//!
//! `tracing_subscriber::fmt` ships three baseline formatters:
//!
//! - `.compact()` — single-line condensed.
//! - `.pretty()` — multi-line with attribute alignment.
//! - `.json()` — structured JSON one-line-per-event (good for
//!   pipe-to-jq investigation).
//!
//! This example uses the default formatter; swap in any of the
//! above for your taste.
//!
//! Per-message tracing is **always on** under the `tracing`
//! feature — there's no separate sub-feature gate (the old
//! `tracing-messages` feature was retired in 0.12 plan 131).
//! Filter at runtime via `EnvFilter` instead.
//!
//! ## Usage
//!
//! ```bash
//! RUST_LOG=flowscope=debug \
//!     cargo run --features "tracing,pcap,extractors,tracker,reassembler" \
//!     --example tracing_subscriber -- trace.pcap
//! ```
//!
//! Closes #47.

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::{FlowDriver, Timestamp};
use tracing_subscriber::EnvFilter;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // Initialize the subscriber once. EnvFilter reads `RUST_LOG`
    // and defaults to flowscope=debug if unset, which is
    // reasonable for exploratory work.
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new("flowscope=debug,info"));
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .init();

    let mut driver = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);

    let mut last_ts = Timestamp { sec: 0, nsec: 0 };
    let mut total_packets = 0u64;
    let mut total_events = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        total_packets += 1;
        last_ts = view.timestamp;
        for _ in driver.track(&view) {
            total_events += 1;
        }
    }
    for _ in driver.sweep(last_ts) {
        total_events += 1;
    }

    tracing::info!(
        target: "flowscope.example",
        total_packets,
        total_events,
        "pcap walk complete"
    );
    Ok(())
}
