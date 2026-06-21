//! Materialise per-flow [`NPrintMatrix`]es into CSV files
//! ready for ML ingestion.
//!
//! nPrint (Holland et al., CCS 2021) is a model-agnostic
//! ternary-bit representation of packet headers: each row is
//! one packet, each column is one header bit (`-1` absent,
//! `0` clear, `1` set). The flowscope `ml-features-nprint`
//! feature exposes this matrix per flow.
//!
//! This example walks a pcap, builds one [`NPrintMatrix`] per
//! [`FiveTupleKey`], and at end-of-file writes each matrix to
//! `nprint_<flow_id>.csv` in the current directory.
//!
//! Each output file is one CSV with one row per packet and the
//! `-1` / `0` / `1` columns from
//! [`NPrintBit::as_raw`](flowscope::nprint::NPrintBit::as_raw)
//! — directly loadable by:
//!
//! - Python: `numpy.loadtxt("nprint_1.csv", delimiter=",")`
//! - Python: `pandas.read_csv("nprint_1.csv", header=None)`
//! - R: `read.csv("nprint_1.csv", header=FALSE)`
//!
//! ## Why CSV instead of npz
//!
//! npz adds a `npyz` dependency that's not currently in flowscope's
//! dev-dependency set. CSV-of-bits is dep-free, human-readable
//! at low cost, and loaded by every ML framework. The downstream
//! pipeline that wants npz can re-pack the CSV in one numpy call.
//!
//! ## Storage cost
//!
//! Default config is Eth + IPv4 + TCP + UDP = 14+20+20+8 bytes
//! header = 496 bits per row. At the default 100-packet cap:
//! ~49,600 bytes per flow CSV (one ASCII char + comma per bit).
//!
//! ## Reference
//!
//! - <https://nprint.github.io/papers/nprint-ccs21.pdf>
//! - <https://github.com/nprint/nprint>
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,ml-features-nprint,extractors,tracker" \
//!     --example nprint_export -- trace.pcap
//! ```
//!
//! Closes #48.

use std::collections::HashMap;
use std::fs::File;
use std::io::{BufWriter, Write};

use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::extractor::FlowExtractor;
use flowscope::nprint::{NPrintConfig, NPrintMatrix};
use flowscope::pcap::PcapFlowSource;
use flowscope::{AsPacketView, PacketView};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let extractor = FiveTuple::bidirectional();
    let cfg = NPrintConfig::default();
    let mut matrices: HashMap<FiveTupleKey, NPrintMatrix> = HashMap::new();
    let mut total_packets = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        total_packets += 1;
        let pv: PacketView<'_> = view.as_packet_view();
        let Some(extracted) = extractor.extract(pv) else {
            continue;
        };
        let key = extracted.key;
        let entry = matrices
            .entry(key)
            .or_insert_with(|| NPrintMatrix::new(cfg));
        let pv2: PacketView<'_> = view.as_packet_view();
        entry.push_view(&pv2);
    }

    let mut written = 0u64;
    let mut total_rows = 0u64;
    for (flow_idx, (key, matrix)) in matrices.iter().enumerate() {
        if matrix.is_empty() {
            continue;
        }
        let filename = format!("nprint_{}.csv", flow_idx + 1);
        let f = File::create(&filename)?;
        let mut w = BufWriter::new(f);
        for row in matrix.rows() {
            let line = row
                .bits
                .iter()
                .map(|b| b.as_raw().to_string())
                .collect::<Vec<_>>()
                .join(",");
            writeln!(w, "{line}")?;
        }
        w.flush()?;
        total_rows += matrix.len() as u64;
        written += 1;
        eprintln!(
            "[nprint] wrote {filename:<24}  {:>4} rows  flow {:?}:{} ↔ {:?}:{}",
            matrix.len(),
            key.a.ip(),
            key.a.port(),
            key.b.ip(),
            key.b.port(),
        );
    }

    eprintln!(
        "\n--- nprint export ---\n  {total_packets} packet(s) processed\n  \
         {written} flow file(s) written\n  {total_rows} total row(s)"
    );
    Ok(())
}
