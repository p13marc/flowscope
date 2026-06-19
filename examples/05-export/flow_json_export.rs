//! Export every `FlowEvent::Ended` as a newline-delimited JSON
//! object (NDJSON).
//!
//! Uses [`flowscope::emit::FlowEventNdjsonWriter`] (0.10 — plan
//! 101). Per-field shape is the snake_case wire vocabulary locked
//! since 0.8. Drop-in input for Elasticsearch / Loki /
//! ClickHouse / DuckDB.
//!
//! ```bash
//! cargo run --features pcap,emit-ndjson \
//!     --example flow_json_export -- trace.pcap > flows.ndjson
//! ```

use std::io::{stdout, BufWriter};

use flowscope::{
    emit::FlowEventNdjsonWriter, extract::FiveTuple, pcap::PcapFlowSource, FlowTracker,
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut ndjson = FlowEventNdjsonWriter::new(BufWriter::new(stdout().lock()));

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            ndjson.write_event(&ev)?;
        }
    }
    for ev in tracker.finish() {
        ndjson.write_event(&ev)?;
    }
    ndjson.finish()?;
    Ok(())
}
