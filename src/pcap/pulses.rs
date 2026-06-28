//! Unified single-pass pcap stream — flow lifecycle **and** typed
//! parser messages from one iterator (issue #111).
//!
//! [`session_messages`](crate::pcap::session_messages) yields only the
//! parser's messages; [`Driver::run_pcap`](crate::driver::Driver::run_pcap)
//! yields only the flow lifecycle (messages drain from a separate
//! [`SlotHandle`](crate::driver::SlotHandle), with a trailing-drain
//! footgun — the close-flush batch lands in the slot *after* the event
//! iterator ends). For a single parser, [`session_pulses`] /
//! [`datagram_pulses`] interleave both into one ordered [`Pulse`]
//! stream, so a `Started → Message* → Ended` story arrives in one loop
//! with nothing left buffered.
//!
//! ```no_run
//! use flowscope::pcap::Pulse;
//! use flowscope::tls::TlsParser;
//!
//! for pulse in flowscope::pcap::session_pulses::<TlsParser>("trace.pcap")? {
//!     match pulse {
//!         Pulse::Started { key, .. } => println!("flow up: {key:?}"),
//!         Pulse::Message(m) => println!("  msg on {:?}: {:?}", m.key, m.message),
//!         Pulse::Ended { key, reason, .. } => println!("flow down: {key:?} ({reason:?})"),
//!         _ => {}
//!     }
//! }
//! # Ok::<(), flowscope::Error>(())
//! ```

use std::path::Path;

use crate::driver::SlotMessage;
use crate::event::{EndReason, FlowStats};
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::extractor::L4Proto;
use crate::pcap::PcapFlowSource;
use crate::session::SessionEvent;
use crate::{DatagramParser, Result, SessionParser, Timestamp};

/// One item in a unified [`session_pulses`] / [`datagram_pulses`]
/// stream: either a flow-lifecycle marker or a typed parser message,
/// delivered in wire order for a single parser.
///
/// The lifecycle subset mirrors the offline engine's stream
/// (`Started` / `Ended` / `Tick`); per-packet `Packet` / `Established`
/// events are not surfaced here — reach for
/// [`Driver`](crate::driver::Driver) when you need those. `Message`
/// reuses the same [`SlotMessage`] a driver slot drains, so the
/// message + `side` + `ts` are identical to the typed-driver path.
///
/// `#[non_exhaustive]` — matching should carry a wildcard arm.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Pulse<K, M> {
    /// First packet of a new flow.
    Started {
        /// Flow key.
        key: K,
        /// Observation time of the first packet.
        ts: Timestamp,
    },
    /// A complete typed message the parser produced. Carries the same
    /// `(key, side, message, ts)` a driver [`SlotHandle`] would drain.
    ///
    /// [`SlotHandle`]: crate::driver::SlotHandle
    Message(SlotMessage<M, K>),
    /// Flow ended (FIN / RST / idle / eviction). Any messages the
    /// parser flushed on close arrive as `Message` pulses *before* this.
    Ended {
        /// Flow key.
        key: K,
        /// Why the flow ended.
        reason: EndReason,
        /// Final per-flow statistics.
        stats: FlowStats,
        /// L4 protocol of the flow, when known.
        l4: Option<L4Proto>,
    },
    /// Periodic [`FlowStats`] snapshot — only when the source's
    /// [`flow_tick_interval`](crate::FlowTrackerConfig::flow_tick_interval)
    /// is set.
    Tick {
        /// Flow key.
        key: K,
        /// Stats snapshot at tick time.
        stats: FlowStats,
        /// Tick time.
        ts: Timestamp,
    },
}

fn pulse_from_event<K, M>(ev: SessionEvent<K, M>) -> Option<Pulse<K, M>> {
    match ev {
        SessionEvent::Started { key, ts } => Some(Pulse::Started { key, ts }),
        SessionEvent::Application {
            key,
            side,
            message,
            ts,
            parser_kind: _,
        } => Some(Pulse::Message(SlotMessage {
            key,
            side,
            message,
            ts,
        })),
        SessionEvent::Closed {
            key,
            reason,
            stats,
            l4,
        } => Some(Pulse::Ended {
            key,
            reason,
            stats,
            l4,
        }),
        SessionEvent::Tick { key, stats, ts } => Some(Pulse::Tick { key, stats, ts }),
        // Anomaly pulses are opt-in (`with_emit_anomalies`) and the
        // offline pulse path doesn't enable them; drop if present.
        SessionEvent::FlowAnomaly { .. } | SessionEvent::TrackerAnomaly { .. } => None,
    }
}

/// Replay a pcap through a single [`SessionParser`] `P`, yielding one
/// ordered [`Pulse`] stream of flow lifecycle **and** typed messages
/// (issue #111).
///
/// The TCP counterpart of [`datagram_pulses`]. Where
/// [`session_messages`](crate::pcap::session_messages) yields messages
/// only and [`Driver::run_pcap`](crate::driver::Driver::run_pcap) yields
/// lifecycle only, this delivers both in one loop in wire order —
/// close-flush messages land as `Message` pulses before the flow's
/// `Ended`, so nothing is left buffered when the iterator ends.
///
/// Uses the bidirectional 5-tuple extractor; keys are [`FiveTupleKey`].
/// For multiple parsers at once, stay on
/// [`Driver::run_pcap`](crate::driver::Driver::run_pcap).
///
/// ```no_run
/// use flowscope::pcap::Pulse;
/// use flowscope::http::HttpParser;
///
/// for pulse in flowscope::pcap::session_pulses::<HttpParser>("trace.pcap")? {
///     if let Pulse::Message(m) = pulse {
///         println!("{:?}: {:?}", m.key, m.message);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn session_pulses<P>(
    path: impl AsRef<Path>,
) -> Result<impl Iterator<Item = Pulse<FiveTupleKey, P::Message>>>
where
    P: SessionParser + Default + Clone + Send + Sync + 'static,
{
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), P::default())
        .filter_map(Result::ok)
        .filter_map(pulse_from_event))
}

/// The [`DatagramParser`] (UDP) mirror of [`session_pulses`] — one
/// ordered [`Pulse`] stream of flow lifecycle + typed messages for a
/// single datagram parser (issue #111).
///
/// ```no_run
/// use flowscope::pcap::Pulse;
/// use flowscope::dns::DnsUdpParser;
///
/// for pulse in flowscope::pcap::datagram_pulses::<DnsUdpParser>("trace.pcap")? {
///     if let Pulse::Message(m) = pulse {
///         println!("{:?}: {:?}", m.key, m.message);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn datagram_pulses<P>(
    path: impl AsRef<Path>,
) -> Result<impl Iterator<Item = Pulse<FiveTupleKey, P::Message>>>
where
    P: DatagramParser + Default + Clone + Send + Sync + 'static,
{
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), P::default())
        .filter_map(Result::ok)
        .filter_map(pulse_from_event))
}
