//! Log every HTTP request and response observed on a pcap file.
//!
//! Demonstrates the PcapFlowSource + FlowSessionDriver + HttpParser
//! pipeline (typed-stream API).
//!
//! Usage:
//!     cargo run --features http,pcap --example http_log -- trace.pcap

use std::env;

use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: http_log <trace.pcap>")?;

    let mut driver =
        FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());

    let mut reqs = 0u64;
    let mut resps = 0u64;
    let mut closed = 0u64;

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        for ev in driver.track(&view) {
            match ev {
                SessionEvent::Application {
                    message: HttpMessage::Request(req),
                    ..
                } => {
                    reqs += 1;
                    let host = req
                        .headers
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case("host"))
                        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
                        .unwrap_or_default();
                    println!(
                        "→ {} {}{}  ({} bytes)",
                        req.method,
                        host,
                        req.path,
                        req.body.len()
                    );
                }
                SessionEvent::Application {
                    message: HttpMessage::Response(resp),
                    ..
                } => {
                    resps += 1;
                    let ct = resp
                        .headers
                        .iter()
                        .find(|(n, _)| n.eq_ignore_ascii_case("content-type"))
                        .map(|(_, v)| String::from_utf8_lossy(v).to_string())
                        .unwrap_or_else(|| "(none)".into());
                    println!(
                        "← {} {}  ({} bytes, content-type: {})",
                        resp.status,
                        resp.reason,
                        resp.body.len(),
                        ct
                    );
                }
                SessionEvent::Closed { .. } => closed += 1,
                _ => {}
            }
        }
    }
    for ev in driver.finish() {
        if matches!(ev, SessionEvent::Closed { .. }) {
            closed += 1;
        }
    }

    eprintln!("\n--- summary: {reqs} requests, {resps} responses, {closed} flow ends");
    Ok(())
}
