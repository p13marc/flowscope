//! Log every HTTP request and response observed on a pcap file.
//!
//! Uses [`PcapFlowSource::sessions`] — the one-call offline
//! pipeline that wraps the tracker + reassembler + per-flow
//! `HttpParser` into a single iterator of [`SessionEvent`]s.
//!
//! Usage:
//!     cargo run --features http,pcap --example http_log -- trace.pcap

use std::env;

use flowscope::SessionEvent;
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: http_log <trace.pcap>")?;

    let mut reqs = 0u64;
    let mut resps = 0u64;
    let mut closed = 0u64;

    for evt in
        PcapFlowSource::open(&path)?.sessions(FiveTuple::bidirectional(), HttpParser::default())
    {
        match evt? {
            SessionEvent::Application { message, .. } => match message {
                HttpMessage::Request(req) => {
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
                HttpMessage::Response(resp) => {
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
                _ => {}
            },
            SessionEvent::Closed { .. } => closed += 1,
            _ => {}
        }
    }

    eprintln!("\n--- summary: {reqs} requests, {resps} responses, {closed} flow ends");
    Ok(())
}
