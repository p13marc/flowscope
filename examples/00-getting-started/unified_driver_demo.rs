//! Demo of the plan-121 typed `flowscope::driver::Driver<E>`.
//! Shows port-routed HTTP + DNS dispatch + a signature-based
//! heuristic catch-all under one `Driver` and typed slot drain
//! handles.
//!
//! The driver emits flow-lifecycle [`Event<K>`] only; per-parser
//! typed messages drain through `SlotHandle<M, K>` returned at
//! registration time. No closed-`M` sum type, no lift closures,
//! zero per-message Box.
//!
//! ```bash
//! cargo run --features pcap,http,dns,test-helpers --example unified_driver_demo
//! ```

use flowscope::{
    detect::signatures::http_request,
    dns::{DnsMessage, DnsUdpParser},
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
};

fn http_label(m: &HttpMessage) -> String {
    match m {
        HttpMessage::Request(r) => format!(
            "HTTP {} {}",
            r.method_str().unwrap_or("?"),
            r.path_str().unwrap_or("?"),
        ),
        HttpMessage::Response(r) => format!("HTTP {} {}", r.status, r.reason_str().unwrap_or("?"),),
    }
}

fn dns_label(m: &DnsMessage) -> String {
    match m {
        DnsMessage::Query(q) => format!(
            "DNS query   tx={:#06x} q={}",
            q.transaction_id,
            q.questions.first().map(|q| q.name.as_str()).unwrap_or("?"),
        ),
        DnsMessage::Response(r) => format!(
            "DNS resp    tx={:#06x} rcode={:?}",
            r.transaction_id, r.rcode,
        ),
        DnsMessage::Unanswered(q) => format!(
            "DNS timeout tx={:#06x} q={}",
            q.transaction_id,
            q.questions.first().map(|q| q.name.as_str()).unwrap_or("?"),
        ),
        _ => "DNS (other)".to_string(),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // Build the driver. Each .session_*/.datagram_* call returns a
    // typed handle; we collect them up before .build().
    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_port_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut http_heur_slot = builder.session_heuristic(HttpParser::default(), http_request);
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut driver = builder.build();

    let mut http_count = 0usize;
    let mut dns_count = 0usize;
    let mut flow_starts = 0usize;
    let mut flow_ends = 0usize;
    let mut first_messages: Vec<String> = Vec::new();

    // Persistent scratch buffers reused per packet (zero-alloc).
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
    let mut dns_msgs: Vec<SlotMessage<DnsMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;

        events.clear();
        driver.track_into(&owned, &mut events);

        // Drain typed messages from both HTTP slots + the DNS slot.
        http_msgs.clear();
        http_port_slot.drain(&mut http_msgs);
        http_heur_slot.drain(&mut http_msgs);
        dns_msgs.clear();
        dns_slot.drain(&mut dns_msgs);

        for ev in &events {
            match ev {
                Event::FlowStarted { .. } => flow_starts += 1,
                Event::FlowEnded { .. } => flow_ends += 1,
                _ => {}
            }
        }
        for m in &http_msgs {
            http_count += 1;
            if first_messages.len() < 5 {
                first_messages.push(http_label(&m.message));
            }
        }
        for m in &dns_msgs {
            dns_count += 1;
            if first_messages.len() < 5 {
                first_messages.push(dns_label(&m.message));
            }
        }
    }

    // Final flush.
    events.clear();
    driver.finish_into(&mut events);
    http_msgs.clear();
    http_port_slot.drain(&mut http_msgs);
    http_heur_slot.drain(&mut http_msgs);
    dns_msgs.clear();
    dns_slot.drain(&mut dns_msgs);
    for ev in &events {
        if matches!(ev, Event::FlowEnded { .. }) {
            flow_ends += 1;
        }
    }
    http_count += http_msgs.len();
    dns_count += dns_msgs.len();

    println!("=== unified driver demo (typed) ===");
    println!("  flows started: {flow_starts}");
    println!("  flows ended:   {flow_ends}");
    println!("  http messages: {http_count}");
    println!("  dns messages:  {dns_count}");
    if !first_messages.is_empty() {
        println!();
        println!("first {} messages:", first_messages.len());
        for m in &first_messages {
            println!("  - {m}");
        }
    }

    Ok(())
}
