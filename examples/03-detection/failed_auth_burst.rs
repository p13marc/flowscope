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

use std::{net::IpAddr, time::Duration};

use flowscope::{
    correlate::{BurstDetector, KeyIndexed},
    driver::{Driver, Event, SlotMessage},
    extract::{FiveTuple, FiveTupleKey},
    http::{HttpMessage, HttpParser},
    pcap::PcapFlowSource,
};

const WINDOW: Duration = Duration::from_secs(60);
const FAIL_THRESHOLD: u32 = 5;

#[derive(Clone, PartialEq, Eq)]
enum AuthEvent {
    Fail,
    Success,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut driver = builder.build();

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
    let mut last_host_per_flow: KeyIndexed<FiveTupleKey, String> =
        KeyIndexed::new(WINDOW, 16 * 1024);

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        let ts = owned.timestamp;

        events.clear();
        driver.track_into(&owned, &mut events);
        msgs.clear();
        http_slot.drain(&mut msgs);

        for m in msgs.drain(..) {
            match m.message {
                HttpMessage::Request(req) => {
                    if let Some(host) = req.host() {
                        last_host_per_flow.insert(m.key, host.to_string(), ts);
                    }
                }
                HttpMessage::Response(resp) => {
                    let src = m.key.a.ip();
                    let host = last_host_per_flow
                        .get(&m.key, ts)
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
                            ts.sec, ts.nsec, hit.key, resp.status, hit.burst_count,
                        );
                    }
                }
            }
        }
    }
    Ok(())
}
