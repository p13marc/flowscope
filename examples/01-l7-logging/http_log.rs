//! Log every HTTP request and response observed on a pcap file.
//!
//! Demonstrates the plan-121 typed `Driver` shape: register an
//! `HttpParser` on common HTTP ports and drain the typed
//! `HttpMessage` slot.
//!
//! Usage:
//!     cargo run --features http,pcap --example http_log -- trace.pcap

use std::env;

use flowscope::driver_unified::SlotMessage;
use flowscope::driver_unified::typed::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: http_log <trace.pcap>")?;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    let mut reqs = 0u64;
    let mut resps = 0u64;
    let mut closed = 0u64;

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);

        for ev in &events {
            if matches!(ev, Event::FlowEnded { .. }) {
                closed += 1;
            }
        }
        for m in &msgs {
            match &m.message {
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
            }
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    for ev in &events {
        if matches!(ev, Event::FlowEnded { .. }) {
            closed += 1;
        }
    }

    eprintln!("\n--- summary: {reqs} requests, {resps} responses, {closed} flow ends");
    Ok(())
}
