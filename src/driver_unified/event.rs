//! Unified event type emitted by [`super::Driver`].
//!
//! Collapses the 0.9-era `FlowEvent<K>` + `SessionEvent<K, M>`
//! into one enum carried by the new [`super::Driver`] (plan 116).

use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowSide, FlowStats};
use crate::extractor::{L4Proto, TcpInfo};
use crate::history::HistoryString;

/// Single event type emitted by the unified [`super::Driver`].
///
/// Covers the full flow lifecycle (`FlowStarted`, `FlowEnded`,
/// `FlowEstablished`, `FlowTick`), per-packet observability
/// (`FlowPacket`), L7 messages from registered parsers
/// (`Message`), parser closures (`ParserClosed`), and
/// anomalies (`FlowAnomaly` / `TrackerAnomaly`).
///
/// Plan 116 shape: replaces `FlowEvent<K>` + `SessionEvent<K, M>`
/// at the 0.10 driver boundary. The legacy types remain shipped
/// in 0.10 alongside this enum for migration.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event<K, M> {
    /// First packet of a new flow.
    FlowStarted {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// TCP flow reached the `Established` state (3-way handshake
    /// complete). Not emitted for UDP / ICMP flows.
    FlowEstablished {
        key: K,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// Per-packet event on an existing flow.
    ///
    /// The `tcp` field is populated only when
    /// [`super::DriverBuilder::emit_packet_details`] was called
    /// with `true`. flowscope avoids the per-packet TCP-info
    /// re-extraction unless the consumer opts in.
    ///
    /// `tcp` carries the TCP header fields ([`TcpInfo::flags`],
    /// `seq`, `ack`, etc.) for the packet that produced this
    /// event.
    ///
    /// **0.11 break (plan 118 §4):** the `frame: Option<Vec<u8>>`
    /// field was removed. It used to be a per-packet
    /// `view.frame.to_vec()` clone — at 1 Mpps with 1500-byte
    /// frames that was ~1.5 GB/sec of allocator traffic.
    /// Consumers that need the raw frame bytes hold onto the
    /// source [`crate::PacketView`] they handed to `track_into`.
    FlowPacket {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
        /// `Some` only when `emit_packet_details(true)` was set.
        tcp: Option<TcpInfo>,
    },

    /// Flow ended (FIN / RST / idle / eviction / parser close).
    FlowEnded {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
        l4: Option<L4Proto>,
        ts: Timestamp,
    },

    /// Periodic [`FlowStats`] snapshot — emitted when
    /// [`crate::FlowTrackerConfig::flow_tick_interval`] is set.
    FlowTick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },

    /// L7 message emitted by a registered parser. `parser_kind`
    /// distinguishes which parser produced it.
    Message {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        parser_kind: &'static str,
    },

    /// Parser-level close — a registered parser drained its
    /// `fin_*` accumulator. Distinct from [`Self::FlowEnded`]
    /// (which fires once per flow); this fires per
    /// (parser, flow). UDP parsers don't emit this.
    ParserClosed {
        key: K,
        parser_kind: &'static str,
        reason: EndReason,
        ts: Timestamp,
    },

    /// Live per-flow anomaly forwarded from the underlying
    /// tracker. Emitted only when `emit_anomalies(true)` was
    /// set on the builder.
    FlowAnomaly {
        key: K,
        kind: AnomalyKind,
        ts: Timestamp,
    },

    /// Live tracker-global anomaly forwarded from the underlying
    /// tracker.
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },
}

impl<K, M> Event<K, M> {
    /// Borrow the flow key for any per-flow variant. Returns
    /// `None` for [`Self::TrackerAnomaly`] (the only
    /// tracker-global variant).
    pub fn key(&self) -> Option<&K> {
        match self {
            Event::FlowStarted { key, .. }
            | Event::FlowEstablished { key, .. }
            | Event::FlowPacket { key, .. }
            | Event::FlowEnded { key, .. }
            | Event::FlowTick { key, .. }
            | Event::Message { key, .. }
            | Event::ParserClosed { key, .. }
            | Event::FlowAnomaly { key, .. } => Some(key),
            Event::TrackerAnomaly { .. } => None,
        }
    }

    /// Borrow the observed timestamp on the event.
    pub fn timestamp(&self) -> Timestamp {
        match self {
            Event::FlowStarted { ts, .. }
            | Event::FlowEstablished { ts, .. }
            | Event::FlowPacket { ts, .. }
            | Event::FlowEnded { ts, .. }
            | Event::FlowTick { ts, .. }
            | Event::Message { ts, .. }
            | Event::ParserClosed { ts, .. }
            | Event::FlowAnomaly { ts, .. }
            | Event::TrackerAnomaly { ts, .. } => *ts,
        }
    }

    /// Borrow the parser identifier on [`Self::Message`] /
    /// [`Self::ParserClosed`]. Returns `None` for flow-lifecycle
    /// variants.
    pub fn parser_kind(&self) -> Option<&'static str> {
        match self {
            Event::Message { parser_kind, .. } | Event::ParserClosed { parser_kind, .. } => {
                Some(*parser_kind)
            }
            _ => None,
        }
    }

    /// Borrow the anomaly kind if this event is an anomaly
    /// (per-flow or tracker-global).
    pub fn anomaly_kind(&self) -> Option<&AnomalyKind> {
        match self {
            Event::FlowAnomaly { kind, .. } | Event::TrackerAnomaly { kind, .. } => Some(kind),
            _ => None,
        }
    }

    /// `true` if this is one of the flow-lifecycle variants
    /// ([`Self::FlowStarted`] / [`Self::FlowEstablished`] /
    /// [`Self::FlowPacket`] / [`Self::FlowEnded`] /
    /// [`Self::FlowTick`]).
    pub fn is_flow_event(&self) -> bool {
        matches!(
            self,
            Event::FlowStarted { .. }
                | Event::FlowEstablished { .. }
                | Event::FlowPacket { .. }
                | Event::FlowEnded { .. }
                | Event::FlowTick { .. }
        )
    }

    /// `true` if this is a parser-sourced variant
    /// ([`Self::Message`] or [`Self::ParserClosed`]).
    pub fn is_parser_event(&self) -> bool {
        matches!(self, Event::Message { .. } | Event::ParserClosed { .. })
    }
}
