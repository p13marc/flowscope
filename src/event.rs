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
    /// New in 0.7.0. A [`crate::SessionParser`] or
    /// [`crate::DatagramParser`] returned `true` from `is_done()`,
    /// signalling clean completion ahead of FIN / idle-timeout.
    /// Synthesised by the session-/datagram-driver — the tracker
    /// itself never emits this reason. Distinct from
    /// [`Self::ParseError`]: a `ParserDone` flow ended successfully;
    /// a `ParseError` flow was torn down due to broken parser state.
    ParserDone,
    /// New in 0.8.0. External orchestration called
    /// [`crate::FlowTracker::force_close`] (or a driver-level
    /// mirror). Used for resource budgets, test harnesses, rate
    /// limiters — anywhere the consumer needs to end a specific
    /// flow ahead of FIN / idle / eviction.
    ForceClosed,
}

impl std::fmt::Display for EndReason {
    /// Lowercase short label matching the
    /// `flowscope_flows_ended_total{reason=…}` metric vocabulary
    /// (`fin` / `rst` / `idle` / `evicted` / `buffer_overflow` /
    /// `parse_error`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::obs::reason_label(*self))
    }
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
    /// New in 0.5.0: per-side count of TCP segments classified as
    /// retransmits by the per-side reassembler. Populated by
    /// [`crate::FlowDriver`] on `Ended`. See
    /// [`crate::Reassembler::retransmits`].
    pub retransmits_initiator: u64,
    pub retransmits_responder: u64,
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
/// [`FlowEvent::FlowAnomaly`] / [`FlowEvent::TrackerAnomaly`].
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

    /// New in 0.5.0. Reassembler classified one or more TCP
    /// segments as retransmits during this tick. Coalesced — at
    /// most one anomaly per (flow, side) per tick, with `count`
    /// summing the delta of [`crate::Reassembler::retransmits`].
    RetransmittedSegment { side: FlowSide, count: u64 },

    /// New in 0.6.0. Reassembler buffer occupancy just crossed the
    /// configured threshold of its cap (see
    /// [`crate::BufferedReassembler::with_high_watermark_threshold`]).
    /// Debounced: one event per below→above transition; occupancy
    /// must drop back below to re-arm.
    ///
    /// `bytes` is occupancy at the moment of the crossing; `cap` is
    /// the configured `max_buffer`; `threshold_pct` is the
    /// configured threshold percent (e.g. `80`).
    ReassemblerHighWatermark {
        side: FlowSide,
        bytes: u64,
        cap: u64,
        threshold_pct: u8,
    },
}

impl AnomalyKind {
    /// Stable variant slug used as a metric label.
    ///
    /// Returns the same string as `<Self as Display>::fmt` produces —
    /// both forward to the same source of truth. Use this method when
    /// intent is *"give me the label"*; use `to_string()` / `format!`
    /// when intent is *"render this"*. New in 0.8.0.
    ///
    /// The slug vocabulary matches `flowscope_anomalies_total{kind=...}`
    /// and is locked from 0.6 forward:
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | [`Self::BufferOverflow`] | `"buffer_overflow"` |
    /// | [`Self::OutOfOrderSegment`] | `"ooo_segment"` |
    /// | [`Self::FlowTableEvictionPressure`] | `"flow_table_eviction"` |
    /// | [`Self::SessionParseError`] | `"parse_error"` |
    /// | [`Self::RetransmittedSegment`] | `"retransmit"` |
    /// | [`Self::ReassemblerHighWatermark`] | `"reassembler_high_watermark"` |
    pub fn short_kind(&self) -> &'static str {
        crate::obs::anomaly_label(self)
    }
}

impl std::fmt::Display for AnomalyKind {
    /// Lowercase short label matching the
    /// `flowscope_anomalies_total{kind=…}` metric vocabulary
    /// (`buffer_overflow` / `ooo_segment` /
    /// `flow_table_eviction` / `parse_error` / `retransmit` /
    /// `reassembler_high_watermark`).
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(crate::obs::anomaly_label(self))
    }
}

/// Severity classification for [`AnomalyKind`] events. Returned
/// by [`AnomalyKind::severity`]; consumers route anomalies on
/// this enum (logs vs metrics vs alerts).
///
/// Ordered ascending: `Info < Warning < Error < Critical`. Use
/// `PartialOrd` / `Ord` for filter thresholds:
///
/// ```rust,ignore
/// if kind.severity() >= Severity::Warning {
///     metrics::counter!("anomalies_high_severity_total").increment(1);
/// }
/// ```
///
/// `#[non_exhaustive]` so future severity bands are additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[non_exhaustive]
pub enum Severity {
    /// Routine, informational — high-volume, log-only.
    /// Default for `OutOfOrderSegment` and `RetransmittedSegment`.
    Info,
    /// Notable but expected — log + count; no immediate action.
    /// Default for cap-pressure / eviction-pressure kinds.
    Warning,
    /// Error-level — operator should investigate.
    /// Default for `SessionParseError`.
    Error,
    /// System-impact — page someone. Reserved for future use; no
    /// [`AnomalyKind`] variant defaults to `Critical` today.
    Critical,
}

impl AnomalyKind {
    /// Default severity for this kind. Consumers free to override
    /// by classifying on their side; this provides a sensible
    /// out-of-the-box mapping for log / metric / alert routing.
    ///
    /// | Kind | Default severity | Rationale |
    /// |------|------------------|-----------|
    /// | [`Self::OutOfOrderSegment`] | [`Severity::Info`] | Routine on lossy / multi-path networks. |
    /// | [`Self::RetransmittedSegment`] | [`Severity::Info`] | Normal TCP behaviour at low rates. |
    /// | [`Self::ReassemblerHighWatermark`] | [`Severity::Warning`] | Cap pressure building; tune [`crate::FlowTrackerConfig::max_reassembler_buffer`]. |
    /// | [`Self::BufferOverflow`] | [`Severity::Warning`] | Bytes dropped (sliding-window) or flow torn down (drop-flow). |
    /// | [`Self::FlowTableEvictionPressure`] | [`Severity::Warning`] | Tracker bottleneck; bump `max_flows` or shorten idle. |
    /// | [`Self::SessionParseError`] | [`Severity::Error`] | Parser is poisoned; flow ended. |
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::OutOfOrderSegment { .. } | AnomalyKind::RetransmittedSegment { .. } => {
                Severity::Info
            }
            AnomalyKind::ReassemblerHighWatermark { .. }
            | AnomalyKind::BufferOverflow { .. }
            | AnomalyKind::FlowTableEvictionPressure { .. } => Severity::Warning,
            AnomalyKind::SessionParseError { .. } => Severity::Error,
        }
    }
}

impl std::fmt::Display for Severity {
    /// Lowercase short label (`info` / `warning` / `error` /
    /// `critical`) matching the metric-vocabulary convention.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Severity::Info => "info",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        })
    }
}

/// Events emitted by the tracker.
///
/// One packet typically produces one or two events. The `Started`
/// event fires on first sight of a flow and is followed by a
/// `Packet` event for the same packet. Subsequent packets of the
/// same flow produce a single `Packet` event each. TCP-aware events
/// (`Established`, `StateChange`) fire only when the extractor
/// supplied [`crate::TcpInfo`].
///
/// `#[non_exhaustive]` since 0.5 — future variants are additive;
/// match with a trailing `_ => {}` arm for forward-compatibility.
#[derive(Debug, Clone)]
#[non_exhaustive]
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
    Established {
        key: K,
        ts: Timestamp,
        /// L4 protocol the flow was tracked under, or `None` if the
        /// extractor never classified one. New in 0.8.0; rounds out
        /// the [`Self::Started`] / [`Self::Ended`] trio (always
        /// `Some(L4Proto::Tcp)` for a real 3WHS-complete event).
        l4: Option<L4Proto>,
    },

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
        /// L4 protocol the flow was tracked under, or `None` if the
        /// extractor never classified one. New in 0.7.0 — mirrors
        /// the `l4` field set on the matching [`Self::Started`]
        /// event for this flow, so consumers no longer carry a
        /// side `HashMap<K, L4Proto>` workaround.
        l4: Option<L4Proto>,
    },

    /// Live, in-flight per-flow anomaly. The flow is still alive
    /// (use `Ended` for end-of-life events). Opt-in: emitted only
    /// when [`crate::FlowDriver::with_emit_anomalies`] is `true`.
    FlowAnomaly {
        key: K,
        kind: AnomalyKind,
        ts: Timestamp,
    },

    /// Live, in-flight tracker-global anomaly (e.g.
    /// [`AnomalyKind::FlowTableEvictionPressure`]) — not tied to a
    /// specific flow. Opt-in like [`Self::FlowAnomaly`].
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },

    /// Periodic [`FlowStats`] snapshot for a live flow. Emitted
    /// only when
    /// [`crate::FlowTrackerConfig::flow_tick_interval`] is `Some`.
    /// New in 0.5.0.
    ///
    /// `stats` is an owned clone — consumers can keep it past the
    /// next `track()` call. Reassembly diagnostic fields (OOO drops,
    /// oversize bytes, watermark, retransmits) are patched in just
    /// like on `Ended`, so each tick is a self-contained snapshot.
    /// Tick timing is driven by packet timestamps; a silent flow
    /// emits no ticks.
    Tick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },
}

impl<K> FlowEvent<K> {
    /// Borrow the key without moving it. Useful for filter combinators.
    ///
    /// Returns `None` for tracker-global events that don't belong to
    /// a single flow (today: [`Self::TrackerAnomaly`]).
    pub fn key(&self) -> Option<&K> {
        match self {
            FlowEvent::Started { key, .. }
            | FlowEvent::Packet { key, .. }
            | FlowEvent::Established { key, .. }
            | FlowEvent::StateChange { key, .. }
            | FlowEvent::Ended { key, .. }
            | FlowEvent::FlowAnomaly { key, .. }
            | FlowEvent::Tick { key, .. } => Some(key),
            FlowEvent::TrackerAnomaly { .. } => None,
        }
    }

    /// Borrow the anomaly kind if this event is an anomaly (either
    /// per-flow or tracker-global). Returns `None` for the
    /// non-anomaly variants. Convenient for drivers and observers
    /// that route on the kind regardless of per-flow vs global.
    pub fn anomaly_kind(&self) -> Option<&AnomalyKind> {
        match self {
            FlowEvent::FlowAnomaly { kind, .. } | FlowEvent::TrackerAnomaly { kind, .. } => {
                Some(kind)
            }
            _ => None,
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
        let evt: FlowEvent<u32> = FlowEvent::TrackerAnomaly {
            kind: AnomalyKind::FlowTableEvictionPressure {
                evicted_in_tick: 1,
                evicted_total: 42,
            },
            ts: Timestamp::default(),
        };
        assert!(evt.key().is_none());
        assert!(evt.anomaly_kind().is_some());
    }

    #[test]
    fn flow_event_key_returns_some_for_per_flow_anomaly() {
        let evt: FlowEvent<u32> = FlowEvent::FlowAnomaly {
            key: 7,
            kind: AnomalyKind::OutOfOrderSegment {
                side: FlowSide::Initiator,
                count: 3,
            },
            ts: Timestamp::default(),
        };
        assert_eq!(evt.key().copied(), Some(7));
    }
}
