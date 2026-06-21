//! Tail a directory of rotating pcap fragments.
//!
//! Real packet capture tools rotate by time / file size:
//!
//! - `tcpdump -G 300 -W 12` — 12 5-minute fragments.
//! - `dumpcap -b duration:300 -b files:12` — same.
//! - `zeek` writes `current/<protocol>.log` and rotates on
//!   stop / signal.
//!
//! This example polls a directory every N seconds, processes
//! each new `.pcap` file through a [`FlowDriver`] + Suricata
//! EVE writer, then moves it to a `processed/` subdirectory.
//!
//! ## Atomic rename contract
//!
//! Capture tools rename `<name>.pcap.tmp` → `<name>.pcap`
//! atomically when a fragment is complete. This example trusts
//! that contract and only consumes files with the `.pcap`
//! extension. **Don't** point it at a directory where files
//! are written in-place — partial reads will fail or produce
//! garbled output.
//!
//! ## Polling vs notify
//!
//! Uses `std::fs` polling with a configurable interval (3 s
//! default). For sub-second latency, swap in the `notify`
//! crate (intentionally avoided here to keep deps minimal).
//!
//! ## Usage
//!
//! ```bash
//! # Watch /var/spool/pcap, process every fragment that lands:
//! cargo run --features "pcap,extractors,tracker,reassembler,emit-eve" \
//!     --example pcap_dir_tail -- /var/spool/pcap
//!
//! # In another terminal, the rotating capture tool:
//! sudo tcpdump -i any -G 60 -W 60 -w /var/spool/pcap/cap-%Y%m%d-%H%M%S.pcap
//! ```
//!
//! Closes #51.

use std::ffi::OsStr;
use std::fs;
use std::io::BufWriter;
use std::path::{Path, PathBuf};
use std::thread::sleep;
use std::time::Duration;

use flowscope::emit::EveJsonWriter;
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::reassembler::BufferedReassemblerFactory;
use flowscope::{FlowDriver, Timestamp};

const POLL_INTERVAL: Duration = Duration::from_secs(3);
const PROCESSED_SUBDIR: &str = "processed";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args()
        .nth(1)
        .ok_or("usage: pcap_dir_tail <watch-directory>")?;
    let dir = PathBuf::from(dir);
    if !dir.is_dir() {
        return Err(format!("{} is not a directory", dir.display()).into());
    }
    let processed_dir = dir.join(PROCESSED_SUBDIR);
    fs::create_dir_all(&processed_dir)?;

    eprintln!(
        "[tail] watching {} every {:?}",
        dir.display(),
        POLL_INTERVAL
    );
    let mut eve = EveJsonWriter::new(BufWriter::new(std::io::stdout().lock()));
    loop {
        match scan_and_process(&dir, &processed_dir, &mut eve) {
            Ok(0) => {}
            Ok(n) => eprintln!("[tail] processed {n} file(s)"),
            Err(e) => eprintln!("[tail] error: {e}"),
        }
        sleep(POLL_INTERVAL);
    }
}

fn scan_and_process<W: std::io::Write>(
    dir: &Path,
    processed_dir: &Path,
    eve: &mut EveJsonWriter<W>,
) -> Result<usize, Box<dyn std::error::Error>> {
    let mut processed = 0;
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension() != Some(OsStr::new("pcap")) {
            continue;
        }
        // Process: drive the file through a FlowDriver and
        // emit EVE records.
        let (flows, anomalies) = process_one(&path, eve)?;
        eprintln!(
            "[tail] processed: {:<32} [{flows} flows, {anomalies} anomalies]",
            path.file_name().unwrap_or_default().to_string_lossy()
        );
        // Move to processed/ so we don't reprocess it.
        let dest = processed_dir.join(path.file_name().unwrap_or_default());
        fs::rename(&path, &dest)?;
        processed += 1;
    }
    Ok(processed)
}

fn process_one<W: std::io::Write>(
    path: &Path,
    eve: &mut EveJsonWriter<W>,
) -> Result<(u64, u64), Box<dyn std::error::Error>> {
    let mut driver = FlowDriver::new(
        FiveTuple::bidirectional(),
        BufferedReassemblerFactory::default(),
    )
    .with_emit_anomalies(true);

    let mut flows = 0u64;
    let mut anomalies = 0u64;
    let mut last_ts = Timestamp { sec: 0, nsec: 0 };
    for view in PcapFlowSource::open(path)?.views() {
        let view = view?;
        last_ts = view.timestamp;
        for ev in driver.track(&view) {
            use flowscope::FlowEvent::*;
            match ev {
                Ended { .. } => flows += 1,
                FlowAnomaly { .. } | TrackerAnomaly { .. } => anomalies += 1,
                _ => {}
            }
            eve.write_event(&ev)?;
        }
    }
    for ev in driver.sweep(last_ts) {
        if let flowscope::FlowEvent::Ended { .. } = ev {
            flows += 1;
        }
        eve.write_event(&ev)?;
    }
    Ok((flows, anomalies))
}
