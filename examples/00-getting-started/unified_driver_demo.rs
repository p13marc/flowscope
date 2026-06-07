//! Demo of the unified `flowscope::driver_unified::Driver<E, M>`
//! (plan 116). Shows port-routed HTTP + DNS dispatch + a
//! signature-based heuristic catch-all under one `Driver` and
//! one `Event<K, M>` stream.
//!
//! Compare to the legacy `FlowMultiSessionDriver` (or
//! `Pipeline<E, S, D>`) shape that requires the consumer to
//! handle two distinct event types
//! (`SessionEvent` + `SessionEvent`).
//!
//! ```bash
//! cargo run --features pcap,http,dns,test-helpers --example unified_driver_demo
//! ```

use flowscope::detect::signatures::http_request;
use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver_unified::{Driver, Event};
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;

#[derive(Debug)]
enum L7 {
    Http(HttpMessage),
    Dns(DnsMessage),
}

impl L7 {
    /// One-line label per message — picks something
    /// representative from each protocol's parsed shape.
    fn label(&self) -> String {
        match self {
            L7::Http(HttpMessage::Request(r)) => {
                format!("HTTP {} {}", r.method, r.path)
            }
            L7::Http(HttpMessage::Response(r)) => {
                format!("HTTP {} {}", r.status, r.reason)
            }
            L7::Dns(DnsMessage::Query(q)) => format!(
                "DNS query   tx={:#06x} q={}",
                q.transaction_id,
                q.questions.first().map(|q| q.name.as_str()).unwrap_or("?"),
            ),
            L7::Dns(DnsMessage::Response(r)) => format!(
                "DNS resp    tx={:#06x} rcode={:?}",
                r.transaction_id, r.rcode,
            ),
            L7::Dns(DnsMessage::Unanswered(q)) => format!(
                "DNS timeout tx={:#06x} q={}",
                q.transaction_id,
                q.questions.first().map(|q| q.name.as_str()).unwrap_or("?"),
            ),
            L7::Dns(_) => "DNS (other)".to_string(),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut driver = Driver::<_, L7>::builder(FiveTuple::bidirectional())
        // Port-routed HTTP on the common ports.
        .session_on_ports(HttpParser::default(), [80, 8080], L7::Http)
        // Heuristic HTTP — catches HTTP on unusual ports.
        .session_heuristic(HttpParser::default(), http_request, L7::Http)
        // UDP/53 for DNS queries + responses.
        .datagram_on_ports(DnsUdpParser::default(), [53], L7::Dns)
        .build();

    let mut http_count = 0usize;
    let mut dns_count = 0usize;
    let mut flow_starts = 0usize;
    let mut flow_ends = 0usize;
    let mut first_messages: Vec<String> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for event in driver.track(&owned) {
            match event {
                Event::FlowStarted { .. } => flow_starts += 1,
                Event::FlowEnded { .. } => flow_ends += 1,
                Event::Message { message, .. } => {
                    let is_http = matches!(message, L7::Http(_));
                    if is_http {
                        http_count += 1;
                    } else {
                        dns_count += 1;
                    }
                    if first_messages.len() < 5 {
                        first_messages.push(message.label());
                    }
                }
                _ => {}
            }
        }
    }
    for event in driver.finish() {
        if matches!(event, Event::FlowEnded { .. }) {
            flow_ends += 1;
        }
    }

    println!("=== unified driver demo ===");
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
