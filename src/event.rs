//! Events emitted by [`crate::FlowTracker`] as packets flow through it.

use crate::Timestamp;
use crate::extractor::L4Proto;
use crate::history::HistoryString;

/// Which side of a flow a packet belongs to.
///
/// Derived from the [`crate::Orientation`] reported by the extractor:
/// - The **first** orientation seen for a flow becomes the
///   `Initiator` direction.
/// - Packets matching that orientation are `Initiator`, packets in
///   the opposite orientation are `Responder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum FlowSide {
    Initiator,
    Responder,
}

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum EndReason {
    /// TCP FIN observed (graceful close).
    Fin,
    /// TCP RST observed (abrupt close).
    Rst,
    /// No packets observed within the configured idle timeout.
    IdleTimeout,
    /// Tracker hit `max_flows` and evicted the oldest flow.
    Evicted,
    /// A reassembler with [`OverflowPolicy::DropFlow`] hit its cap;
    /// the driver tore the flow down rather than dropping bytes.
    /// Synthesised by [`crate::FlowDriver`] (the tracker itself never
    /// emits this reason).
    BufferOverflow,
    /// A [`crate::SessionParser`] or [`crate::DatagramParser`]
    /// returned `true` from `is_poisoned()`. Synthesised by the
    /// session-/datagram-driver — the tracker itself never emits
    /// this reason.
    ParseError,
}

/// What to do when [`crate::BufferedReassembler`]'s in-flight buffer
/// would exceed its configured cap.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub enum OverflowPolicy {
    /// Drop oldest bytes from the front of the buffer until the new
    /// payload fits. The flow stays alive; the parser sees a gap and
    /// must resync. `bytes_dropped_oversize` counts bytes rotated out.
    ///
    /// Default. Best for stream-shaped / append-only protocols (HTTP
    /// body streams, plain TCP) where resync after a gap is well-defined.
    #[default]
    SlidingWindow,
    /// Mark the reassembler as poisoned and signal end-of-flow on the
    /// next driver tick via [`EndReason::BufferOverflow`]. Subsequent
    /// segments are no-ops; the buffer is cleared.
    ///
    /// Best for framed binary protocols (DES PSMSG, TLS records,
    /// length-prefixed wire formats) where a mid-frame gap would
    /// permanently desync the parser.
    DropFlow,
}

/// Aggregate counters maintained per flow.
///
/// `#[non_exhaustive]` to keep future additions purely additive.
/// Construct via `FlowStats::default()` and mutate; do not rely on
/// struct-literal construction from outside the crate.
#[derive(Debug, Clone, Default)]
#[non_exhaustive]
pub struct FlowStats {
    pub packets_initiator: u64,
    pub packets_responder: u64,
    pub bytes_initiator: u64,
    pub bytes_responder: u64,
    pub started: Timestamp,
    pub last_seen: Timestamp,
    /// Per-side reassembly diagnostics, populated by [`crate::FlowDriver`]
    /// when the flow ends. Zero when no driver is in play (i.e. the
    /// consumer used [`crate::FlowTracker`] directly without a
    /// reassembler factory).
    pub reassembly_dropped_ooo_initiator: u64,
    pub reassembly_dropped_ooo_responder: u64,
    /// See [`crate::BufferedReassembler::with_max_buffer`] /
    /// [`crate::OverflowPolicy::SlidingWindow`]. Counts payload bytes
    /// dropped from the per-side reassembler buffer due to overflow.
    pub reassembly_bytes_dropped_oversize_initiator: u64,
    pub reassembly_bytes_dropped_oversize_responder: u64,
    /// Peak buffer occupancy ever observed for the per-side
    /// reassembler. Useful for tuning
    /// [`crate::FlowTrackerConfig::max_reassembler_buffer`].
    /// Populated by [`crate::FlowDriver`] /
    /// [`crate::FlowSessionDriver`] on `Ended` and via live
    /// snapshot accessors. Zero when no reassembler was attached.
    pub reassembler_high_watermark_initiator: u64,
    pub reassembler_high_watermark_responder: u64,
}

/// Lifecycle state of a flow as tracked by [`crate::FlowTracker`].
///
/// Non-TCP flows stay in [`FlowState::Active`] until they end.
/// TCP flows transition through `SynSent → Established → FinWait → Closed`
/// (or `Reset`/`Aborted` on irregular termination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FlowState {
    /// First TCP SYN observed; awaiting SYN-ACK.
    SynSent,
    /// SYN-ACK observed; awaiting initiator's ACK.
    SynReceived,
    /// 3WHS complete (TCP) **or** non-TCP flow seen.
    Established,
    /// One side has FIN'd; the other is still up.
    FinWait,
    /// Both sides FIN'd; awaiting final ACK.
    ClosingTcp,
    /// Non-TCP flow — no state machine engaged.
    Active,
    /// TCP flow closed gracefully.
    Closed,
    /// TCP flow torn down by RST.
    Reset,
    /// TCP flow aborted (idle timeout while open).
    Aborted,
}

impl FlowState {
    /// True if the state means "this flow won't see more packets".
    pub fn is_terminal(self) -> bool {
        matches!(
            self,
            FlowState::Closed | FlowState::Reset | FlowState::Aborted
        )
    }
}

/// Live, in-flight anomaly classifications. Carried by
/// [`FlowEvent::Anomaly`].
///
/// `#[non_exhaustive]` so future kinds are unconditionally additive.
/// Custom protocol parsers should not emit anomalies here — pipe
/// protocol-specific signals through their own `Message` type
/// instead.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnomalyKind {
    /// Reassembler dropped bytes from its buffer because the per-side
    /// cap was hit. `bytes` is the count dropped during this tick
    /// only; running totals live in [`FlowStats`]. `policy` records
    /// which overflow policy was active (sliding-window or drop-flow)
    /// so the consumer can decide how to react.
    BufferOverflow {
        side: FlowSide,
        bytes: u64,
        policy: OverflowPolicy,
    },
    /// Reassembler dropped one or more out-of-order segments during
    /// this tick. Coalesced — at most one anomaly per (flow, side)
    /// per tick, with `count` summing the drops in that tick.
    OutOfOrderSegment { side: FlowSide, count: u64 },
    /// Tracker hit `max_flows` and evicted at least one LRU flow
    /// during this tick. The evicted flow's own
    /// `Ended { reason: Evicted }` is still emitted; this anomaly is
    /// the system-level signal that capacity is the bottleneck.
    /// `evicted_in_tick` is the delta for this tick; `evicted_total`
    /// is the running total since the tracker started, useful for
    /// recovering after dropped events.
    FlowTableEvictionPressure {
        evicted_in_tick: u64,
        evicted_total: u64,
    },
    /// A [`crate::SessionParser`] / [`crate::DatagramParser`] just
    /// returned `true` from `is_poisoned()`. The corresponding
    /// `Ended { reason: ParseError }` follows in the same tick.
    /// `reason` carries `poison_reason()` truncated to ~256 bytes.
    SessionParseError {
        side: FlowSide,
        reason: Option<String>,
    },
}

/// Events emitted by the tracker.
///
/// One packet typically produces one or two events. The `Started`
/// event fires on first sight of a flow and is followed by a
/// `Packet` event for the same packet. Subsequent packets of the
/// same flow produce a single `Packet` event each. TCP-aware events
/// (`Established`, `StateChange`) fire only when the extractor
/// supplied [`crate::TcpInfo`].
#[derive(Debug, Clone)]
pub enum FlowEvent<K> {
    /// First packet of a new flow.
    Started {
        key: K,
        side: FlowSide,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// Subsequent packet on a known flow.
    Packet {
        key: K,
        side: FlowSide,
        len: usize,
        ts: Timestamp,
    },

    /// TCP only — 3WHS completed for this flow.
    Established { key: K, ts: Timestamp },

    /// State machine transitioned. Fires for TCP non-Established
    /// transitions (e.g., `Established → FinWait`).
    StateChange {
        key: K,
        from: FlowState,
        to: FlowState,
        ts: Timestamp,
    },

    /// Flow ended (FIN/RST for TCP, idle/eviction for any flow).
    Ended {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        history: HistoryString,
    },

    /// Live, in-flight anomaly. The flow is still alive (use
    /// `Ended` for end-of-life events). Opt-in: emitted only when
    /// [`crate::FlowDriver::with_emit_anomalies`] is `true`.
    ///
    /// `key` is `None` for tracker-global anomalies (e.g.
    /// [`AnomalyKind::FlowTableEvictionPressure`]); `Some(key)` for
    /// per-flow anomalies.
    Anomaly {
        key: Option<K>,
        kind: AnomalyKind,
        ts: Timestamp,
    },
}

impl<K> FlowEvent<K> {
    /// Borrow the key without moving it. Useful for filter combinators.
    ///
    /// Returns `None` for tracker-global [`FlowEvent::Anomaly`] events
    /// that don't belong to a single flow.
    pub fn key(&self) -> Option<&K> {
        match self {
            FlowEvent::Started { key, .. }
            | FlowEvent::Packet { key, .. }
            | FlowEvent::Established { key, .. }
            | FlowEvent::StateChange { key, .. }
            | FlowEvent::Ended { key, .. } => Some(key),
            FlowEvent::Anomaly { key, .. } => key.as_ref(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_state_terminal() {
        assert!(FlowState::Closed.is_terminal());
        assert!(FlowState::Reset.is_terminal());
        assert!(FlowState::Aborted.is_terminal());
        assert!(!FlowState::Active.is_terminal());
        assert!(!FlowState::Established.is_terminal());
        assert!(!FlowState::SynSent.is_terminal());
    }

    #[test]
    fn flow_event_key_borrow() {
        let evt: FlowEvent<u32> = FlowEvent::Packet {
            key: 7,
            side: FlowSide::Initiator,
            len: 100,
            ts: Timestamp::default(),
        };
        assert_eq!(evt.key().copied(), Some(7));
    }

    #[test]
    fn flow_event_key_returns_none_for_global_anomaly() {
        let evt: FlowEvent<u32> = FlowEvent::Anomaly {
            key: None,
            kind: AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 42,
            },
            ts: Timestamp::default(),
        };
        assert!(evt.key().is_none());
    }

    #[test]
    fn flow_event_key_returns_some_for_per_flow_anomaly() {
        let evt: FlowEvent<u32> = FlowEvent::Anomaly {
            key: Some(7),
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 3,
            },
            ts: Timestamp::default(),
        };
        assert_eq!(evt.key().copied(), Some(7));
    }
}
