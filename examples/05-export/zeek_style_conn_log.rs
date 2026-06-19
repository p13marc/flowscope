//! Emit Zeek-style `conn.log` rows.
//!
//! Uses [`flowscope::emit::ZeekConnLogWriter`] (0.10 — plan 101)
//! to produce tab-separated rows with the canonical Zeek column
//! order. Compatible with `zeek-cut` and downstream pipelines that
//! already consume Zeek logs.
//!
//! ```bash
//! cargo run --features pcap,emit --example zeek_style_conn_log
//! ```

use std::io::{BufWriter, stdout};

use flowscope::{FlowTracker, emit::ZeekConnLogWriter, extract::FiveTuple, pcap::PcapFlowSource};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut zeek = ZeekConnLogWriter::new(BufWriter::new(stdout().lock()))?;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            zeek.write_event(&ev)?;
        }
    }
    for ev in tracker.finish() {
        zeek.write_event(&ev)?;
    }
    zeek.finish()?;
    Ok(())
}
