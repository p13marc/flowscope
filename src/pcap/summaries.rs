//! High-level one-call iterator over flow summaries in a pcap.
//!
//! For the "tracker walk → one row per finalized flow" pattern
//! that several observability + low-level examples implement
//! by hand.

use std::path::Path;

use crate::Result;
use crate::event::{EndReason, FlowEvent, FlowStats};
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::tracker::FlowTracker;

/// One finalized-flow summary tuple.
pub type FlowSummary = (FiveTupleKey, FlowStats, EndReason);

/// Iterate every finalized flow in the pcap. Drives a 5-tuple
/// [`FlowTracker`] across the whole file, emits one tuple per
/// flow at `Ended`-time (FIN / RST / idle / eviction), and
/// flushes the in-flight set on EOF.
///
/// The returned iterator collects internally (the tracker's
/// `Ended` events arrive over the course of the walk, but we
/// have to drain the in-flight set on EOF before we know the
/// final shape) — for a streaming version use
/// `PcapFlowSource::open(...).views()` + your own tracker loop.
///
/// ```no_run
/// for (key, stats, reason) in flowscope::pcap::flow_summaries_from_pcap("trace.pcap")? {
///     println!(
///         "{key:?}  {} pkts / {} bytes  ended: {reason:?}",
///         stats.packets_initiator + stats.packets_responder,
///         stats.bytes_initiator + stats.bytes_responder,
///     );
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn flow_summaries_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = FlowSummary>> {
    let mut tracker: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
    let mut out: Vec<FlowSummary> = Vec::new();

    for view in PcapFlowSource::open(path)?.views() {
        let view = view?;
        for ev in tracker.track(&view) {
            if let FlowEvent::Ended {
                key, stats, reason, ..
            } = ev
            {
                out.push((key, stats, reason));
            }
        }
    }
    for ev in tracker.finish() {
        if let FlowEvent::Ended {
            key, stats, reason, ..
        } = ev
        {
            out.push((key, stats, reason));
        }
    }

    Ok(out.into_iter())
}
