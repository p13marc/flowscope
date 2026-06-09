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

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());

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
                    let host = req.host().unwrap_or("");
                    println!(
                        "→ {} {}{}  ({} bytes)",
                        req.method_str().unwrap_or("?"),
                        host,
                        req.path_str().unwrap_or("?"),
                        req.body.len()
                    );
                }
                SessionEvent::Application {
                    message: HttpMessage::Response(resp),
                    ..
                } => {
                    resps += 1;
                    let ct = resp.content_type().unwrap_or("(none)");
                    println!(
                        "← {} {}  ({} bytes, content-type: {})",
                        resp.status,
                        resp.reason_str().unwrap_or("?"),
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
