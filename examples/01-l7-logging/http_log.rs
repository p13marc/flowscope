//! Log every HTTP request and response observed on a pcap file.
//!
//! Uses [`flowscope::driver::Driver::run_pcap`] — the one-call
//! offline driver that yields the flow-lifecycle [`Event`] stream
//! while per-parser typed messages flow through the registered
//! [`SlotHandle`](flowscope::driver::SlotHandle). We pull HTTP
//! messages from the slot and count flow ends off `Event::FlowEnded`.
//!
//! Usage:
//!     cargo run --features http,pcap --example http_log -- trace.pcap

use std::env;

use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: http_log <trace.pcap>")?;

    let mut reqs = 0u64;
    let mut resps = 0u64;
    let mut closed = 0u64;

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_broadcast(HttpParser::default());
    let driver = builder.build();

    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    let handle_msgs = |msgs: &mut Vec<SlotMessage<HttpMessage, FiveTupleKey>>,
                       reqs: &mut u64,
                       resps: &mut u64| {
        for m in msgs.drain(..) {
            match m.message {
                HttpMessage::Request(req) => {
                    *reqs += 1;
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
                    *resps += 1;
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
            }
        }
    };

    for ev in driver.run_pcap(&path)? {
        if matches!(ev?, Event::FlowEnded { .. }) {
            closed += 1;
        }
        msgs.clear();
        http_slot.drain(&mut msgs);
        handle_msgs(&mut msgs, &mut reqs, &mut resps);
    }
    // Drain any messages flushed on the final iteration.
    msgs.clear();
    http_slot.drain(&mut msgs);
    handle_msgs(&mut msgs, &mut reqs, &mut resps);

    eprintln!("\n--- summary: {reqs} requests, {resps} responses, {closed} flow ends");
    Ok(())
}
