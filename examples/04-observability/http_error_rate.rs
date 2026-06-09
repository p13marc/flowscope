//! Per-host HTTP error-rate summary — classic SRE observability
//! readout. Tallies 1xx/2xx/3xx/4xx/5xx counts by `Host` header
//! and prints the top error-rate hosts.
//!
//! ```bash
//! cargo run --features pcap,http --example http_error_rate
//! ```

use std::collections::HashMap;

use flowscope::driver_unified::SlotMessage;
use flowscope::driver_unified::typed::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;

#[derive(Default, Clone, Copy)]
struct Bucket {
    info: u32,       // 1xx
    success: u32,    // 2xx
    redirect: u32,   // 3xx
    client_err: u32, // 4xx
    server_err: u32, // 5xx
}

impl Bucket {
    fn add_status(&mut self, status: u16) {
        match status / 100 {
            1 => self.info += 1,
            2 => self.success += 1,
            3 => self.redirect += 1,
            4 => self.client_err += 1,
            5 => self.server_err += 1,
            _ => {}
        }
    }

    fn total(&self) -> u32 {
        self.info + self.success + self.redirect + self.client_err + self.server_err
    }

    fn error_rate(&self) -> f64 {
        let errs = self.client_err + self.server_err;
        let total = self.total();
        if total == 0 {
            0.0
        } else {
            errs as f64 / total as f64
        }
    }
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

    // Track the most recent Host header per flow; when a response
    // for the same flow arrives, charge the bucket.
    let mut host_per_flow: HashMap<FiveTupleKey, String> = HashMap::new();
    let mut buckets: HashMap<String, Bucket> = HashMap::new();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);
        for m in msgs.drain(..) {
            handle(&mut host_per_flow, &mut buckets, m);
        }
    }

    events.clear();
    driver.finish_into(&mut events);
    msgs.clear();
    http_slot.drain(&mut msgs);
    for m in msgs.drain(..) {
        handle(&mut host_per_flow, &mut buckets, m);
    }

    let mut rows: Vec<_> = buckets.iter().collect();
    rows.sort_by(|(_, a), (_, b)| b.error_rate().partial_cmp(&a.error_rate()).unwrap());
    println!(
        "{:<40} {:>5} {:>5} {:>5} {:>5} {:>5} {:>8}",
        "host", "1xx", "2xx", "3xx", "4xx", "5xx", "err_rate"
    );
    for (host, b) in rows.iter().take(20) {
        println!(
            "{:<40} {:>5} {:>5} {:>5} {:>5} {:>5} {:>7.1}%",
            truncate(host, 40),
            b.info,
            b.success,
            b.redirect,
            b.client_err,
            b.server_err,
            b.error_rate() * 100.0,
        );
    }
    Ok(())
}

fn handle(
    host_per_flow: &mut HashMap<FiveTupleKey, String>,
    buckets: &mut HashMap<String, Bucket>,
    m: SlotMessage<HttpMessage, FiveTupleKey>,
) {
    match m.message {
        HttpMessage::Request(req) => {
            if let Some(host) = req.host() {
                host_per_flow.insert(m.key, host.to_string());
            }
        }
        HttpMessage::Response(resp) => {
            let host = host_per_flow
                .get(&m.key)
                .cloned()
                .unwrap_or_else(|| "(unknown)".to_string());
            buckets.entry(host).or_default().add_status(resp.status);
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.to_string()
    } else {
        format!("{}…", &s[..n - 1])
    }
}
