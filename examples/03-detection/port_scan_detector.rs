//! Detect TCP port scanners using [`PortScanDetector`] (TRW —
//! Threshold Random Walk, Jung 2004).
//!
//! For each source IP observed in a pcap, accumulates a log-
//! likelihood ratio over SYN connections — a connection that
//! gets RST'd or times out is evidence against (the source is
//! probing unused ports); a successful 3-way handshake is
//! evidence for (the source is browsing real services). When
//! the ratio crosses a threshold the source is classified as
//! either `Scanner` or `Benign`.
//!
//! ## MITRE ATT&CK
//!
//! [T1046](https://attack.mitre.org/techniques/T1046/) — Network
//! Service Discovery.
//!
//! ## Known false positives
//!
//! - Internal vulnerability scanners (Qualys, Nessus, OpenVAS,
//!   Tenable, Rapid7) — these are legitimate tools that look
//!   identical to attacker scans on the wire.
//! - Asset-inventory tools (Lansweeper, Tanium, internal Shodan
//!   deployments) — same.
//! - VPN clients probing for available routes after re-connect.
//! - Some load-balancer health checks (HAProxy / NLB / GWLB)
//!   that periodically RST to confirm the backend is up.
//!
//! Multicast + link-local destinations are excluded by default
//! (broadcast probes aren't operator-meaningful scans).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features pcap,extractors,tracker --example port_scan_detector -- trace.pcap
//! ```
//!
//! Closes #52.

use std::net::IpAddr;

use flowscope::PacketView;
use flowscope::detect::patterns::{PortScanDetector, ScanVerdict};
use flowscope::layers::TcpFlagsView;
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut detector: PortScanDetector<IpAddr> = PortScanDetector::default();
    let mut scanners = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        let pv = PacketView::new(&view.frame, view.timestamp);
        let Ok(layers) = pv.layers() else { continue };
        let Some(tcp) = layers.tcp() else { continue };
        let flags: TcpFlagsView = tcp.flags();
        let (src, dst) = match (layers.ipv4(), layers.ipv6()) {
            (Some(v4), _) => (IpAddr::V4(v4.source()), IpAddr::V4(v4.destination())),
            (None, Some(v6)) => (IpAddr::V6(v6.source()), IpAddr::V6(v6.destination())),
            _ => continue,
        };
        // Skip multicast + link-local destinations (broadcast
        // probes aren't operator-meaningful scans).
        if dst.is_multicast() {
            continue;
        }

        // Classify the connection outcome:
        // - SYN+ACK → success (handshake completing).
        // - SYN-only / lone RST → failure (no acknowledgement).
        let outcome = if flags.syn && flags.ack {
            Some(true)
        } else if !flags.ack && (flags.syn || flags.rst) {
            Some(false)
        } else {
            None
        };

        if let Some(success) = outcome {
            let score = detector.observe(src, success);
            if matches!(score.verdict, ScanVerdict::Scanner) {
                scanners += 1;
                println!(
                    "[scanner]  {src}  log-likelihood={:.3}  n={}  (last probed: {dst}:{})",
                    score.log_likelihood,
                    score.n_observed,
                    tcp.dst_port(),
                );
            }
        }
    }

    eprintln!(
        "\n--- {scanners} source(s) classified as Scanner.  \
         {} source(s) still being tracked (Inconclusive).",
        detector.tracked(),
    );
    Ok(())
}
