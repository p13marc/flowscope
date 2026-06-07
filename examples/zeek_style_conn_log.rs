//! Emit Zeek-style `conn.log` rows — one row per ended flow,
//! tab-separated, in the canonical column order Zeek users
//! expect:
//!
//! ```text
//! ts  uid  id.orig_h  id.orig_p  id.resp_h  id.resp_p  proto
//! duration  orig_bytes  resp_bytes  conn_state  history
//! orig_pkts  resp_pkts
//! ```
//!
//! Output is compatible with `zeek-cut` and adopt-and-load
//! pipelines that already consume Zeek logs.
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example zeek_style_conn_log
//! ```

use std::io::{BufWriter, Write};

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{EndReason, FlowEvent, FlowTracker};

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let stdout = std::io::stdout();
    let mut out = BufWriter::new(stdout.lock());

    writeln!(
        out,
        "#fields\tts\tuid\tid.orig_h\tid.orig_p\tid.resp_h\tid.resp_p\t\
         proto\tduration\torig_bytes\tresp_bytes\tconn_state\thistory\t\
         orig_pkts\tresp_pkts"
    )
    .ok();

    let mut uid_seq = 0u64;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in tracker.track(&owned) {
            emit(&mut out, &mut uid_seq, &ev);
        }
    }
    for ev in tracker.finish() {
        emit(&mut out, &mut uid_seq, &ev);
    }
    out.flush().ok();
    Ok(())
}

fn emit<W: Write>(out: &mut W, uid_seq: &mut u64, ev: &FlowEvent<flowscope::extract::FiveTupleKey>) {
    let FlowEvent::Ended {
        key,
        reason,
        stats,
        history,
        ..
    } = ev
    else {
        return;
    };

    *uid_seq += 1;
    let uid = format!("C{uid_seq:010x}");
    let ts = stats.started.sec as f64 + stats.started.nsec as f64 / 1e9;
    let end_ts = stats.last_seen.sec as f64 + stats.last_seen.nsec as f64 / 1e9;
    let duration = (end_ts - ts).max(0.0);

    let proto = format!("{:?}", key.proto).to_lowercase();
    let conn_state = match reason {
        EndReason::Fin => "SF",
        EndReason::Rst => "RSTO",
        EndReason::IdleTimeout => "OTH",
        EndReason::BufferOverflow => "S0",
        EndReason::ParseError => "REJ",
        _ => "OTH",
    };

    let _ = writeln!(
        out,
        "{ts:.6}\t{uid}\t{}\t{}\t{}\t{}\t{proto}\t{duration:.6}\t{}\t{}\t{conn_state}\t{}\t{}\t{}",
        key.a.ip(),
        key.a.port(),
        key.b.ip(),
        key.b.port(),
        stats.bytes_initiator,
        stats.bytes_responder,
        history.as_str(),
        stats.packets_initiator,
        stats.packets_responder,
    );
}
