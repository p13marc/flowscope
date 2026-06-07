//! Detect HTTP authentication-bypass patterns: a burst of 401
//! responses followed by a 200 on the same source IP within a
//! short window suggests credential-stuffing or brute force.
//!
//! Uses `flowscope::correlate::KeyIndexed` to remember recent
//! 401 hosts per source, and a simple counter for the burst.
//!
//! ```bash
//! cargo run --features pcap,http --example failed_auth_burst
//! ```

use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::KeyIndexed;
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent, Timestamp};

const WINDOW: Duration = Duration::from_secs(60);
const FAIL_THRESHOLD: u32 = 5;

#[derive(Default)]
struct Counters {
    /// Per-source: recent 401 count + last-seen ts.
    fails: HashMap<IpAddr, (u32, Timestamp)>,
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());
    let mut last_host_per_flow: KeyIndexed<flowscope::extract::FiveTupleKey, String> =
        KeyIndexed::new(WINDOW, 16 * 1024);
    let mut counters = Counters::default();
    let mut reported = std::collections::HashSet::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let ts = owned.timestamp;
        for ev in driver.track(&owned) {
            let SessionEvent::Application { key, message, .. } = ev else {
                continue;
            };
            match message {
                HttpMessage::Request(req) => {
                    if let Some((_, v)) =
                        req.headers.iter().find(|(n, _)| n.eq_ignore_ascii_case("host"))
                    {
                        last_host_per_flow
                            .insert(key, String::from_utf8_lossy(v).to_string(), ts);
                    }
                }
                HttpMessage::Response(resp) => {
                    let host = last_host_per_flow
                        .get(&key, ts)
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());
                    let src = key.a.ip();
                    match resp.status {
                        401 | 403 => {
                            let entry = counters.fails.entry(src).or_insert((0, ts));
                            // Reset counter if last fail was long ago.
                            if ts.to_duration().saturating_sub(entry.1.to_duration()) > WINDOW {
                                entry.0 = 0;
                            }
                            entry.0 += 1;
                            entry.1 = ts;
                            if entry.0 == FAIL_THRESHOLD {
                                println!(
                                    "[{}.{:09}] burst of {} {} from {src} → host {host}",
                                    ts.sec, ts.nsec, entry.0, resp.status
                                );
                            }
                        }
                        200 | 302 => {
                            if let Some(entry) = counters.fails.get(&src)
                                && entry.0 >= FAIL_THRESHOLD
                                && ts.to_duration().saturating_sub(entry.1.to_duration())
                                    < WINDOW
                                && reported.insert(src)
                            {
                                println!(
                                    "[{}.{:09}] *** SUSPECTED CREDENTIAL STUFFING *** \
                                     {src} hit {} from {host} after {} prior 401/403s",
                                    ts.sec, ts.nsec, resp.status, entry.0
                                );
                            }
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    Ok(())
}
