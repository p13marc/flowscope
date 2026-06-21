//! DGA finder — replay a pcap, extract DNS query names, score
//! each SLD via [`flowscope::detect::patterns::DgaScorer`], and
//! print the top suspicious entries.
//!
//! Run with:
//!
//! ```bash
//! cargo run --features pcap,dns,extractors \
//!     --example dga_finder -- trace.pcap
//! ```
//!
//! The DgaScorer treats the leftmost-but-one DNS label as the
//! SLD; consumers wanting strict eTLD+1 handling pair with the
//! `publicsuffix` crate.
//!
//! ## MITRE ATT&CK
//!
//! [T1568.002](https://attack.mitre.org/techniques/T1568/002/)
//! — Dynamic Resolution: Domain Generation Algorithms.
//!
//! ## Known false positives
//!
//! - Akamai / Cloudflare / Fastly CDN edges use entropy-heavy
//!   subdomain hashes that look DGA-shaped on the bigram score.
//! - Some browser telemetry endpoints (Firefox shavar, Chrome
//!   safebrowsing) and Spotify ad delivery use opaque
//!   pseudo-random hostnames.
//! - Internal CI artifact repositories often build hostnames
//!   from commit SHAs.
//!
//! Pair the DGA score with [`flowscope::detect::patterns::BeaconDetector`]
//! and a TLS-version check for high-confidence verdicts —
//! see `composite_c2.rs`.

use std::collections::HashMap;

use flowscope::{
    AsPacketView, DatagramParser, PacketView, Timestamp,
    detect::patterns::{DgaScore, DgaScorer},
    dns::{DnsMessage, DnsUdpParser},
    extract::FiveTuple,
    extractor::FlowExtractor,
    pcap::PcapFlowSource,
};

fn extract_sld(qname: &str) -> Option<String> {
    // Strip trailing dot, split, take the last two labels, drop
    // the rightmost (TLD). For multi-label public suffixes
    // (.co.uk etc.) this is approximate; consumers wanting
    // strict eTLD+1 use publicsuffix.
    let trimmed = qname.trim_end_matches('.');
    let labels: Vec<&str> = trimmed.split('.').collect();
    if labels.len() < 2 {
        return None;
    }
    Some(labels[labels.len() - 2].to_ascii_lowercase())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let scorer = DgaScorer::new();
    let mut parser = DnsUdpParser::default();
    let extractor = FiveTuple::bidirectional();

    let mut counts: HashMap<String, u32> = HashMap::new();
    let mut scores: HashMap<String, DgaScore> = HashMap::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let view: PacketView<'_> = owned.as_packet_view();
        // Filter UDP/53 by destination port; non-DNS UDP frames
        // either fail extract or fall through the parser.
        let Some(ext) = extractor.extract(view) else {
            continue;
        };
        let side = if ext.orientation == flowscope::extractor::Orientation::Forward {
            flowscope::FlowSide::Initiator
        } else {
            flowscope::FlowSide::Responder
        };
        let mut out = Vec::new();
        parser.parse(view.frame, side, Timestamp::new(0, 0), &mut out);
        for m in out {
            let questions = match m {
                DnsMessage::Query(q) | DnsMessage::Unanswered(q) => q.questions,
                DnsMessage::Response(r) => r.questions,
                _ => continue,
            };
            for qry in questions {
                if let Some(sld) = extract_sld(&qry.name) {
                    let sc = scorer.score(&sld);
                    *counts.entry(sld.clone()).or_insert(0) += 1;
                    scores.entry(sld).or_insert(sc);
                }
            }
        }
    }

    let mut entries: Vec<_> = scores.iter().collect();
    entries.sort_by(|a, b| {
        a.1.log_likelihood
            .partial_cmp(&b.1.log_likelihood)
            .unwrap_or(std::cmp::Ordering::Equal)
    });

    println!("# dga_finder — {} unique SLDs", scores.len());
    println!(
        "# fields: log_likelihood, length, vowel_ratio, digit_ratio, max_cons_run, entropy, count, sld"
    );
    for (sld, sc) in entries.iter().take(30) {
        let cnt = counts.get(*sld).copied().unwrap_or(0);
        println!(
            "{:.3}\t{}\t{:.2}\t{:.2}\t{}\t{:.2}\t{}\t{}",
            sc.log_likelihood,
            sc.length,
            sc.vowel_ratio,
            sc.digit_ratio,
            sc.max_consonant_run,
            sc.char_entropy,
            cnt,
            sld,
        );
    }
    Ok(())
}
