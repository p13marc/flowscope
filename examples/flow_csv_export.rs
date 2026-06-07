//! Export ended flows as CSV — one row per `FlowEvent::Ended`.
//!
//! Suitable for piping into a spreadsheet, a relational DB, or
//! pandas / DuckDB for ad-hoc analysis. The schema:
//!
//! ```text
//! start_sec,end_sec,duration_sec,proto,src_ip,src_port,dst_ip,dst_port,
//! pkts_init,pkts_resp,bytes_init,bytes_resp,end_reason
//! ```
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example flow_csv_export \
//!     -- trace.pcap > flows.csv
//! ```

use std::io::{BufWriter, Write};

use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    writeln!(
        out,
        "start_sec,end_sec,duration_sec,proto,src_ip,src_port,dst_ip,dst_port,\
         pkts_init,pkts_resp,bytes_init,bytes_resp,end_reason"
    )
    .ok();

    let mut last_ts = None;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        last_ts = Some(owned.timestamp);
        for ev in tracker.track(&owned) {
            emit_row(&mut out, &ev);
        }
    }
    if last_ts.is_some() {
        for ev in tracker.finish() {
            emit_row(&mut out, &ev);
        }
    }
    out.flush().ok();
    Ok(())
}

fn emit_row<W: Write>(out: &mut W, ev: &FlowEvent<FiveTupleKey>) {
    let FlowEvent::Ended {
        key,
        reason,
        stats,
        ..
    } = ev
    else {
        return;
    };
    let start = stats.started.sec as f64 + stats.started.nsec as f64 / 1e9;
    let end = stats.last_seen.sec as f64 + stats.last_seen.nsec as f64 / 1e9;
    let dur = (end - start).max(0.0);
    let _ = writeln!(
        out,
        "{start:.6},{end:.6},{dur:.6},{:?},{},{},{},{},{},{},{},{},{:?}",
        key.proto,
        key.a.ip(),
        key.a.port(),
        key.b.ip(),
        key.b.port(),
        stats.packets_initiator,
        stats.packets_responder,
        stats.bytes_initiator,
        stats.bytes_responder,
        reason,
    );
}
