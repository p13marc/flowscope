//! Per-host HTTP error-rate summary — classic SRE observability
//! readout. Tallies 1xx/2xx/3xx/4xx/5xx counts by `Host` header
//! and prints the top error-rate hosts.
//!
//! ```bash
//! cargo run --features pcap,http --example http_error_rate
//! ```

use std::collections::HashMap;

use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent};

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

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());

    // Track the most recent Host header per flow; when a response
    // for the same flow arrives, charge the bucket.
    let mut host_per_flow: HashMap<flowscope::extract::FiveTupleKey, String> = HashMap::new();
    let mut buckets: HashMap<String, Bucket> = HashMap::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        for ev in driver.track(&owned) {
            handle(&mut host_per_flow, &mut buckets, ev);
        }
    }
    for ev in driver.finish() {
        handle(&mut host_per_flow, &mut buckets, ev);
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
    host_per_flow: &mut HashMap<flowscope::extract::FiveTupleKey, String>,
    buckets: &mut HashMap<String, Bucket>,
    ev: SessionEvent<flowscope::extract::FiveTupleKey, HttpMessage>,
) {
    let SessionEvent::Application { key, message, .. } = ev else {
        return;
    };
    match message {
        HttpMessage::Request(req) => {
            if let Some((_, v)) = req
                .headers
                .iter()
                .find(|(n, _)| n.eq_ignore_ascii_case("host"))
            {
                let host = String::from_utf8_lossy(v).to_string();
                host_per_flow.insert(key, host);
            }
        }
        HttpMessage::Response(resp) => {
            let host = host_per_flow
                .get(&key)
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
