//! Export ended flows as CSV — one row per `FlowEvent::Ended`.
//!
//! Uses [`flowscope::emit::FlowEventCsvWriter`] (0.10 — plan 101)
//! to handle the schema, RFC-4180 quoting, and header generation.
//!
//! Suitable for piping into a spreadsheet, a relational DB, or
//! pandas / DuckDB for ad-hoc analysis.
//!
//! ```bash
//! cargo run --features pcap,emit --example flow_csv_export \
//!     -- trace.pcap > flows.csv
//! ```

use std::io::{BufWriter, stdout};

use flowscope::{FlowTracker, emit::FlowEventCsvWriter, extract::FiveTuple, pcap::PcapFlowSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut csv = FlowEventCsvWriter::new(BufWriter::new(stdout().lock()))?;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            csv.write_event(&ev)?;
        }
    }
    for ev in tracker.finish() {
        csv.write_event(&ev)?;
    }
    csv.finish()?;
    Ok(())
}
