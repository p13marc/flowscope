//! Log every HTTP request and response observed on a pcap file.
//!
//! Demonstrates the netring-flow-pcap + netring-flow + netring-flow-http
//! pipeline.
//!
//! Usage:
//!     cargo run -p netring-flow-http --example http_log -- trace.pcap

use std::env;

use flowscope::extract::FiveTuple;
use flowscope::http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowDriver, FlowEvent};

struct Logger;

impl HttpHandler for Logger {
    fn on_request(&self, req: &HttpRequest) {
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
    fn on_response(&self, resp: &HttpResponse) {
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
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: http_log <trace.pcap>")?;

    let factory = HttpFactory::with_handler(Logger);
    let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);

    let mut started = 0u64;
    let mut ended = 0u64;

    let src = PcapFlowSource::open(&path)?;
    for view in src.views() {
        let view = view?;
        for ev in driver.track(&view) {
            match ev {
                FlowEvent::Started { .. } => started += 1,
                FlowEvent::Ended { .. } => ended += 1,
                _ => {}
            }
        }
    }
    for ev in driver.finish() {
        if matches!(ev, FlowEvent::Ended { .. }) {
            ended += 1;
        }
    }

    eprintln!("\n--- summary: {started} flows started, {ended} ended");
    Ok(())
}
