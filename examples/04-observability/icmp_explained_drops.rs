//! ICMP-explained drops: every ICMP error in the trace is
//! classified (port-unreachable / host-unreachable / MTU /
//! …) and joined back to the live flow it concerns. The
//! result is a one-line "flow X died because Y" report.
//!
//! Demonstrates three 0.14 additions:
//!
//! - [`FlowTracker::lookup_inner`] / [`stats_for_inner`] (plan 161) —
//!   join an ICMP error back to a live flow in the tracker
//!   with one method call. Direction-agnostic.
//! - [`DestUnreachableKind`] (plan 162) — unified v4/v6
//!   Destination Unreachable vocabulary.
//! - [`MtuSignalKind`] (plan 170) — unified v4 FragNeeded +
//!   v6 PacketTooBig signal.
//!
//! Recipe: `docs/recipes.md` § "0.14 patterns" /
//! "Joining ICMP errors back to live flows".
//! Migration doc: `docs/migration-0.13-to-0.14.md` §1, §2, §11.
//!
//! ```bash
//! cargo run --features pcap,icmp,extractors,tracker --example icmp_explained_drops
//! ```
//!
//! [`FlowTracker::lookup_inner`]: flowscope::FlowTracker::lookup_inner
//! [`stats_for_inner`]: flowscope::FlowTracker::stats_for_inner
//! [`DestUnreachableKind`]: flowscope::DestUnreachableKind
//! [`MtuSignalKind`]: flowscope::MtuSignalKind

use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::icmp::{IcmpMessage, IcmpParser};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut icmp_slot = builder.datagram_broadcast(IcmpParser::new());
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    let mut icmp_msgs: Vec<SlotMessage<IcmpMessage, FiveTupleKey>> = Vec::new();

    let mut errors_observed = 0usize;
    let mut errors_correlated = 0usize;
    let mut errors_orphaned = 0usize;

    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        events.clear();
        driver.track_into(&owned, &mut events);
        icmp_msgs.clear();
        icmp_slot.drain(&mut icmp_msgs);

        for m in &icmp_msgs {
            if !m.message.is_error() {
                continue;
            }
            errors_observed += 1;

            // Classify across v4 + v6.
            let kind_label: String =
                match (m.message.dest_unreachable_kind(), m.message.mtu_signal()) {
                    (Some(du), _) => format!("DU/{}", du.as_str()),
                    (_, Some(mtu)) => {
                        let mtu_val = mtu
                            .next_hop_mtu()
                            .map(|m| format!(" mtu={m}"))
                            .unwrap_or_default();
                        format!("{}{mtu_val}", mtu.as_str())
                    }
                    _ => m.message.short_kind().to_string(),
                };

            // Join back to the live flow — direction-agnostic.
            let Some((_label, inner)) = m.message.error_inner() else {
                errors_orphaned += 1;
                continue;
            };

            match driver.tracker().stats_for_inner(inner) {
                Some((flow_key, stats)) => {
                    errors_correlated += 1;
                    println!(
                        "{kind_label:<24} flow {flow_key:?} \
                         ({} pkts, {} bytes in flight)",
                        stats.total_packets(),
                        stats.total_bytes(),
                    );
                }
                None => {
                    errors_orphaned += 1;
                    println!("{kind_label:<24} (no live flow — orphan)");
                }
            }
        }
    }

    println!();
    println!("=== summary ===");
    println!("ICMP errors observed:   {errors_observed}");
    println!("Correlated to flows:    {errors_correlated}");
    println!("Orphan (no live flow):  {errors_orphaned}");
    Ok(())
}
