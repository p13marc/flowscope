//! Export every `FlowEvent::Ended` as a newline-delimited JSON
//! object (NDJSON) — drop-in input for Elasticsearch / Loki /
//! ClickHouse / DuckDB.
//!
//! Uses flowscope's `serde` Cargo feature; the per-field shape
//! is the snake_case wire vocabulary locked since 0.8.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker,serde \
//!     --example flow_json_export -- trace.pcap > flows.ndjson
//! ```

use std::io::{BufWriter, Write};

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            emit(&mut out, &ev);
        }
    }
    for ev in tracker.finish() {
        emit(&mut out, &ev);
    }
    out.flush().ok();
    Ok(())
}

fn emit<W: Write>(out: &mut W, ev: &FlowEvent<flowscope::extract::FiveTupleKey>) {
    if !matches!(ev, FlowEvent::Ended { .. }) {
        return;
    }
    match serde_json::to_string(ev) {
        Ok(s) => {
            writeln!(out, "{s}").ok();
        }
        Err(e) => {
            eprintln!("# serialization failed: {e}");
        }
    }
}
