//! Detect HTTP authentication-bypass patterns: a burst of 401 /
//! 403 responses followed by a 200 / 302 on the same source IP
//! within a short window suggests credential stuffing.
//!
//! Migrated to [`flowscope::correlate::BurstDetector`] (0.10) —
//! the canonical "N events of kind X within W, optionally
//! followed by event of kind Y" primitive replaces the
//! hand-rolled counter from the 0.9 version.
//!
//! ```bash
//! cargo run --features pcap,http --example failed_auth_burst
//! ```
//!
//! Plan 102 sub-A migration.

use std::net::IpAddr;
use std::time::Duration;

use flowscope::correlate::{BurstDetector, KeyIndexed};
use flowscope::extract::FiveTuple;
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowSessionDriver, SessionEvent};

const WINDOW: Duration = Duration::from_secs(60);
const FAIL_THRESHOLD: u32 = 5;

#[derive(Clone, PartialEq, Eq)]
enum AuthEvent {
    Fail,
    Success,
}

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(), HttpParser::default());

    // The canonical pattern: ≥5 fails within 60 s, then a success
    // → BurstHit fires once per (source, success) pair.
    let mut detector: BurstDetector<IpAddr, AuthEvent> = BurstDetector::new(
        AuthEvent::Fail,
        FAIL_THRESHOLD,
        WINDOW,
        Some(AuthEvent::Success),
    );

    // Side cache: remember the most recent Host header per flow
    // so we can annotate the alert with the targeted host.
    let mut last_host_per_flow: KeyIndexed<flowscope::extract::FiveTupleKey, String> =
        KeyIndexed::new(WINDOW, 16 * 1024);

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let ts = owned.timestamp;
        for ev in driver.track(&owned) {
            let SessionEvent::Application { key, message, .. } = ev else {
                continue;
            };
            match message {
                HttpMessage::Request(req) => {
                    if let Some(host) = req.host() {
                        last_host_per_flow.insert(key, host.to_string(), ts);
                    }
                }
                HttpMessage::Response(resp) => {
                    let src = key.a.ip();
                    let host = last_host_per_flow
                        .get(&key, ts)
                        .cloned()
                        .unwrap_or_else(|| "?".to_string());
                    let event = match resp.status {
                        401 | 403 => Some(AuthEvent::Fail),
                        200 | 302 => Some(AuthEvent::Success),
                        _ => None,
                    };
                    let Some(event) = event else { continue };
                    if let Some(hit) = detector.observe(&src, &event, ts) {
                        println!(
                            "[{}.{:09}] *** SUSPECTED CREDENTIAL STUFFING *** \
                             {} hit {} from {host} after {} prior 401/403s",
                            ts.sec,
                            ts.nsec,
                            hit.key,
                            resp.status,
                            hit.burst_count,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
