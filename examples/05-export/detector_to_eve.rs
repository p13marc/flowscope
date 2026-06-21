//! Pipe a detector's scores into Suricata-compatible EVE JSON.
//!
//! Demonstrates the single-detector → SIEM ingest pipeline that
//! plan 147 (0.13.0) was designed for: every detector's score
//! type implements [`flowscope::DetectorScore`], and
//! [`EveJsonWriter::write_owned_anomaly`] consumes the canonical
//! [`OwnedAnomaly`] value it produces. So the entire pipeline is
//! one chain:
//!
//! ```text
//! detector.observe(...) -> Score -> score.into_anomaly(ts) ->
//! EveJsonWriter::write_owned_anomaly(&anomaly) -> stdout
//! ```
//!
//! Output is one EVE JSON line per anomaly, schema-compatible
//! with Suricata 7.x — pipe it to Filebeat / Splunk / Tenzir /
//! ECS-converting ingest.
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features "pcap,extractors,tracker,emit-eve" \
//!     --example detector_to_eve -- trace.pcap | jq .
//! ```
//!
//! For multi-detector composition (BeaconDetector ∧ DgaScorer
//! ∧ low-cipher TLS), see `composite_c2.rs`.
//!
//! Closes #46.

use std::net::IpAddr;

use flowscope::detect::patterns::{PortScanDetector, ScanVerdict};
use flowscope::emit::EveJsonWriter;
use flowscope::layers::TcpFlagsView;
use flowscope::pcap::PcapFlowSource;
use flowscope::{KeyFields, PacketView};

/// Thin newtype that satisfies `KeyFields` so the
/// `PortScanDetector<SrcIpKey>::ScanScore::into_anomaly` path
/// can populate the EVE `src_ip` field. For real consumers,
/// use `FiveTupleKey` (which implements `KeyFields` out of the
/// box).
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct SrcIpKey(IpAddr);

impl KeyFields for SrcIpKey {
    fn src_ip(&self) -> Option<IpAddr> {
        Some(self.0)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let stdout = std::io::stdout().lock();
    let mut eve = EveJsonWriter::new(stdout);

    let mut detector: PortScanDetector<SrcIpKey> = PortScanDetector::default();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        let ts = view.timestamp;
        let pv = PacketView::new(&view.frame, ts);
        let Ok(layers) = pv.layers() else { continue };
        let Some(tcp) = layers.tcp() else { continue };
        let flags: TcpFlagsView = tcp.flags();
        let src: IpAddr = if let Some(v4) = layers.ipv4() {
            IpAddr::V4(v4.source())
        } else if let Some(v6) = layers.ipv6() {
            IpAddr::V6(v6.source())
        } else {
            continue;
        };

        let outcome = if flags.syn && !flags.ack && !flags.rst {
            Some(false)
        } else if flags.syn && flags.ack {
            Some(true)
        } else {
            None
        };
        let Some(success) = outcome else { continue };

        let score = detector.observe(SrcIpKey(src), success);
        if matches!(score.verdict, ScanVerdict::Scanner) {
            let anomaly = score.into_anomaly(ts);
            eve.write_owned_anomaly(&anomaly)?;
        }
    }

    Ok(())
}
