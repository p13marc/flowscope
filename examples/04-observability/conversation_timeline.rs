//! Print a timeline of a single TCP conversation — every packet,
//! every state transition, every reassembler byte. Useful for
//! debugging "what happened on this connection" investigations
//! (slow handshakes, unexpected RSTs, byte-level desyncs).
//!
//! Filters by `<src>:<port>` / `<dst>:<port>` taken from CLI args
//! (or shows the first flow if no filter is given).
//!
//! ```bash
//! cargo run --features pcap,extractors,reassembler --example conversation_timeline \
//!     -- trace.pcap 10.0.0.1:1234 10.0.0.2:80
//! ```

use std::net::SocketAddr;

use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{FlowEvent, FlowTracker};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = std::env::args().skip(1);
    let path = args
        .next()
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());
    let filter_a: Option<SocketAddr> = args.next().and_then(|s| s.parse().ok());
    let filter_b: Option<SocketAddr> = args.next().and_then(|s| s.parse().ok());

    let mut tracker = FlowTracker::<FiveTuple>::new(FiveTuple::bidirectional());
    let mut frame_no = 0usize;
    let mut started_ts: Option<f64> = None;
    let mut matched_key: Option<flowscope::extract::FiveTupleKey> = None;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        frame_no += 1;
        let evs = tracker.track(&owned);
        for ev in &evs {
            // Lazily lock onto the first flow that matches the
            // filter (or the first flow we see if no filter).
            if matched_key.is_none()
                && let FlowEvent::Started { key, .. } = ev
            {
                {
                    let matches = match (filter_a, filter_b) {
                        (Some(a), Some(b)) => {
                            (key.a == a && key.b == b) || (key.a == b && key.b == a)
                        }
                        _ => true,
                    };
                    if matches {
                        matched_key = Some(*key);
                        started_ts =
                            Some(owned.timestamp.sec as f64 + owned.timestamp.nsec as f64 / 1e9);
                        println!("=== flow ({}) {} <-> {} ===", key.proto, key.a, key.b,);
                    }
                }
            }
        }
        // Print events for the locked flow.
        if let Some(k) = &matched_key {
            for ev in &evs {
                if matches_key(ev, k) {
                    print_event(frame_no, owned.timestamp, started_ts, ev);
                }
            }
        }
    }
    if let Some(k) = matched_key {
        for ev in tracker.finish() {
            if matches_key(&ev, &k) {
                print_event(frame_no, flowscope::Timestamp::default(), started_ts, &ev);
            }
        }
    } else {
        println!("(no matching flow found)");
    }
    Ok(())
}

fn matches_key(
    ev: &FlowEvent<flowscope::extract::FiveTupleKey>,
    k: &flowscope::extract::FiveTupleKey,
) -> bool {
    let evk = match ev {
        FlowEvent::Started { key, .. }
        | FlowEvent::Packet { key, .. }
        | FlowEvent::Established { key, .. }
        | FlowEvent::Ended { key, .. }
        | FlowEvent::Tick { key, .. } => Some(key),
        _ => None,
    };
    evk == Some(k)
}

fn print_event(
    frame_no: usize,
    ts: flowscope::Timestamp,
    started: Option<f64>,
    ev: &FlowEvent<flowscope::extract::FiveTupleKey>,
) {
    let now = ts.sec as f64 + ts.nsec as f64 / 1e9;
    let rel = started.map(|s| now - s).unwrap_or(0.0);
    match ev {
        FlowEvent::Started { .. } => {
            println!("{rel:+8.3}s [#{frame_no:>5}] STARTED");
        }
        FlowEvent::Established { .. } => {
            println!("{rel:+8.3}s [#{frame_no:>5}] ESTABLISHED");
        }
        FlowEvent::Packet { side, len, .. } => {
            let side_s = match side {
                flowscope::FlowSide::Initiator => "→",
                flowscope::FlowSide::Responder => "←",
            };
            println!("{rel:+8.3}s [#{frame_no:>5}] {side_s} {len} B");
        }
        FlowEvent::Ended { reason, stats, .. } => {
            println!(
                "{rel:+8.3}s [#{frame_no:>5}] ENDED reason={reason:?} \
                 pkts={}+{} bytes={}+{}",
                stats.packets_initiator,
                stats.packets_responder,
                stats.bytes_initiator,
                stats.bytes_responder,
            );
        }
        _ => {}
    }
}
