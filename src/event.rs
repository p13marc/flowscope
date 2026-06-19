//! Events emitted by [`crate::FlowTracker`] as packets flow through it.

use crate::{Timestamp, extractor::L4Proto, history::HistoryString};

/// Which side of a flow a packet belongs to.
///
/// Derived from the [`crate::Orientation`] reported by the extractor:
/// - The **first** orientation seen for a flow becomes the
///   `Initiator` direction.
/// - Packets matching that orientation are `Initiator`, packets in
///   the opposite orientation are `Responder`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
pub enum FlowSide {
    Initiator,
    Responder,
}

/// Why a flow ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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

impl EndReason {
    /// Snake-case short label for this end reason.
    ///
    /// Matches the `flowscope_flows_ended_total{reason=…}` metric
    /// vocabulary AND the [`Display`](std::fmt::Display) output —
    /// every consumer-facing string surface returns the same slug.
    ///
    /// Vocabulary (locked since 0.6 forward):
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | [`Self::Fin`] | `"fin"` |
    /// | [`Self::Rst`] | `"rst"` |
    /// | [`Self::IdleTimeout`] | `"idle"` |
    /// | [`Self::Evicted`] | `"evicted"` |
    /// | [`Self::BufferOverflow`] | `"buffer_overflow"` |
    /// | [`Self::ParseError`] | `"parse_error"` |
    /// | [`Self::ParserDone`] | `"parser_done"` |
    /// | [`Self::ForceClosed`] | `"force_closed"` |
    ///
    /// New in 0.10.0.
    pub fn as_str(&self) -> &'static str {
        crate::obs::reason_label(*self)
    }

    /// Zeek `conn_state` code for this end reason.
    ///
    /// Maps flowscope's lifecycle vocabulary onto the
    /// connection-state codes Zeek records use:
    ///
    /// | Variant | Zeek code | Meaning |
    /// |---------|-----------|---------|
    /// | [`Self::Fin`] | `"SF"` | Normal close (both sides FIN). |
    /// | [`Self::Rst`] | `"RSTO"` | Reset. |
    /// | [`Self::IdleTimeout`] | `"OTH"` | No clean close. |
    /// | [`Self::Evicted`] | `"OTH"` | Forcibly evicted by capacity. |
    /// | [`Self::BufferOverflow`] | `"S0"` | Buffer cap reached. |
    /// | [`Self::ParseError`] | `"REJ"` | Parser rejected the stream. |
    /// | [`Self::ParserDone`] | `"SF"` | Parser drained cleanly. |
    /// | [`Self::ForceClosed`] | `"OTH"` | External force-close. |
    ///
    /// Documented stable for the 0.10 cycle so downstream Zeek
    /// pipelines can rely on the mapping. Use the
    /// [`crate::emit::ZeekConnLogWriter`] (`emit` feature) to
    /// produce conn.log-shaped output.
    ///
    /// New in 0.10.0.
    pub fn as_zeek_state(&self) -> &'static str {
        match self {
            EndReason::Fin | EndReason::ParserDone => "SF",
            EndReason::Rst => "RSTO",
            EndReason::BufferOverflow => "S0",
            EndReason::ParseError => "REJ",
            EndReason::IdleTimeout | EndReason::Evicted | EndReason::ForceClosed => "OTH",
        }
    }
}

impl std::fmt::Display for EndReason {
    /// Snake-case short label — see [`EndReason::as_str`] for the
    /// vocabulary.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What to do when [`crate::BufferedReassembler`]'s in-flight buffer
/// would exceed its configured cap.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
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

impl FlowStats {
    /// `bytes_initiator + bytes_responder`. New in 0.10.0.
    #[inline]
    pub fn total_bytes(&self) -> u64 {
        self.bytes_initiator + self.bytes_responder
    }

    /// `packets_initiator + packets_responder`. New in 0.10.0.
    #[inline]
    pub fn total_packets(&self) -> u64 {
        self.packets_initiator + self.packets_responder
    }

    /// `retransmits_initiator + retransmits_responder`. New in 0.10.0.
    #[inline]
    pub fn total_retransmits(&self) -> u64 {
        self.retransmits_initiator + self.retransmits_responder
    }

    /// Retransmits as a fraction of [`Self::total_packets`], or
    /// `0.0` when no packets have been observed. New in 0.10.0.
    pub fn retransmit_rate(&self) -> f64 {
        let total = self.total_packets();
        if total == 0 {
            0.0
        } else {
            self.total_retransmits() as f64 / total as f64
        }
    }

    /// `last_seen - started` as a [`std::time::Duration`]. Returns
    /// [`std::time::Duration::ZERO`] if `last_seen` precedes
    /// `started` (clock drift / pre-`Started` snapshots). New in
    /// 0.10.0.
    pub fn duration(&self) -> std::time::Duration {
        self.last_seen.saturating_sub(self.started)
    }

    /// [`Self::duration`] in `f64` seconds — convenient for
    /// dashboard / divisor arithmetic. New in 0.10.0.
    pub fn duration_secs(&self) -> f64 {
        self.duration().as_secs_f64()
    }

    /// Bytes attributed to the given side. Sugar over the
    /// `bytes_initiator` / `bytes_responder` fields for
    /// `FlowSide`-keyed report code.
    ///
    /// Plan 168 (0.14).
    #[inline]
    pub fn bytes_for(&self, side: FlowSide) -> u64 {
        match side {
            FlowSide::Initiator => self.bytes_initiator,
            FlowSide::Responder => self.bytes_responder,
        }
    }

    /// Packets attributed to the given side.
    ///
    /// Plan 168 (0.14).
    #[inline]
    pub fn pkts_for(&self, side: FlowSide) -> u64 {
        match side {
            FlowSide::Initiator => self.packets_initiator,
            FlowSide::Responder => self.packets_responder,
        }
    }

    /// Mean packet size for the given side, in bytes. Returns
    /// `0.0` when the side has zero packets.
    ///
    /// Plan 168 (0.14).
    pub fn mean_pkt_size_for(&self, side: FlowSide) -> f64 {
        let pkts = self.pkts_for(side);
        if pkts == 0 {
            return 0.0;
        }
        self.bytes_for(side) as f64 / pkts as f64
    }

    /// Direction skew. `(bytes_initiator - bytes_responder) /
    /// total_bytes`, clamped to `[-1.0, 1.0]`. Returns `0.0`
    /// for empty flows.
    ///
    /// Positive → initiator-heavy (uploads); negative →
    /// responder-heavy (downloads); zero → balanced.
    ///
    /// Useful for detecting one-sided flows (DoS, scans, CDN
    /// downloads).
    ///
    /// Plan 168 (0.14).
    pub fn direction_skew(&self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            return 0.0;
        }
        let init = self.bytes_initiator as f64;
        let resp = self.bytes_responder as f64;
        (init - resp) / total as f64
    }

    /// Average bytes/second over the flow's lifetime. Returns
    /// `0.0` (not NaN / Infinity) for zero-duration flows
    /// (single-packet or instantaneous). Sibling to
    /// [`Self::total_bytes`] + [`Self::duration_secs`].
    ///
    /// For per-side throughput, see [`Self::throughput_bps_for`].
    /// For sliding-window throughput (last-N-seconds rate, not
    /// flow lifetime), use [`crate::correlate::RollingRate`].
    ///
    /// Plan 173 (0.14).
    pub fn throughput_bps(&self) -> f64 {
        safe_div_u64(self.total_bytes(), self.duration_secs())
    }

    /// Average packets/second over the flow's lifetime. Returns
    /// `0.0` for zero-duration flows. See
    /// [`Self::throughput_pps_for`] for the per-side split.
    ///
    /// Plan 173 (0.14).
    pub fn throughput_pps(&self) -> f64 {
        safe_div_u64(self.total_packets(), self.duration_secs())
    }

    /// Average bytes/second attributed to the given side over
    /// the flow's lifetime. Returns `0.0` for zero-duration
    /// flows. Sibling to [`Self::bytes_for`] (raw bytes) and
    /// [`Self::throughput_bps`] (whole-flow throughput).
    ///
    /// Plan 173 (0.14).
    pub fn throughput_bps_for(&self, side: FlowSide) -> f64 {
        safe_div_u64(self.bytes_for(side), self.duration_secs())
    }

    /// Average packets/second attributed to the given side
    /// over the flow's lifetime. Returns `0.0` for
    /// zero-duration flows. Sibling to [`Self::pkts_for`] (raw
    /// packets) and [`Self::throughput_pps`] (whole-flow rate).
    ///
    /// Plan 173 (0.14).
    pub fn throughput_pps_for(&self, side: FlowSide) -> f64 {
        safe_div_u64(self.pkts_for(side), self.duration_secs())
    }
}

/// Safe division: `num as f64 / den`, returning `0.0` instead
/// of NaN / Infinity when `den <= 0.0` (covers zero-duration
/// flows and time-machine-stamps).
#[inline]
fn safe_div_u64(num: u64, den: f64) -> f64 {
    if den > 0.0 { num as f64 / den } else { 0.0 }
}

/// Lifecycle state of a flow as tracked by [`crate::FlowTracker`].
///
/// Non-TCP flows stay in [`FlowState::Active`] until they end.
/// TCP flows transition through `SynSent → Established → FinWait → Closed`
/// (or `Reset`/`Aborted` on irregular termination).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
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

impl crate::AnomalyFields for AnomalyKind {
    /// EVE `anomaly.type` classification. Per Suricata's
    /// schema:
    /// - Reassembly / TCP-state anomalies → `"stream"`
    /// - Parser-driven anomalies → `"applayer"`
    /// - Tracker-capacity pressure → `"stream"` (closest fit;
    ///   Suricata's schema has no "system" type)
    ///
    /// Adding a new [`AnomalyKind`] variant requires updating
    /// this match. Same convention as
    /// `src/obs.rs::anomaly_label`.
    fn anomaly_type(&self) -> Option<&'static str> {
        Some(match self {
            AnomalyKind::BufferOverflow { .. }
            | AnomalyKind::OutOfOrderSegment { .. }
            | AnomalyKind::RetransmittedSegment { .. }
            | AnomalyKind::ReassemblerHighWatermark { .. } => "stream",
            AnomalyKind::SessionParseError { .. } => "applayer",
            AnomalyKind::FlowTableEvictionPressure { .. } => "stream",
        })
    }

    /// Stable slug — reuses [`Self::short_kind`].
    fn anomaly_event(&self) -> Option<&'static str> {
        Some(self.short_kind())
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "K: serde::Serialize",
        deserialize = "K: serde::de::DeserializeOwned"
    ))
)]
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

    // ── Plan 168 (0.14) — FlowSide-aware accessors ─────────

    fn skewed_stats(init_bytes: u64, init_pkts: u64, resp_bytes: u64, resp_pkts: u64) -> FlowStats {
        FlowStats {
            packets_initiator: init_pkts,
            packets_responder: resp_pkts,
            bytes_initiator: init_bytes,
            bytes_responder: resp_bytes,
            ..FlowStats::default()
        }
    }

    #[test]
    fn bytes_for_returns_per_side_count() {
        let s = skewed_stats(100, 5, 200, 8);
        assert_eq!(s.bytes_for(FlowSide::Initiator), 100);
        assert_eq!(s.bytes_for(FlowSide::Responder), 200);
    }

    #[test]
    fn pkts_for_returns_per_side_count() {
        let s = skewed_stats(100, 5, 200, 8);
        assert_eq!(s.pkts_for(FlowSide::Initiator), 5);
        assert_eq!(s.pkts_for(FlowSide::Responder), 8);
    }

    #[test]
    fn mean_pkt_size_for_zero_packets_returns_zero() {
        let s = skewed_stats(0, 0, 200, 8);
        assert_eq!(s.mean_pkt_size_for(FlowSide::Initiator), 0.0);
        assert_eq!(s.mean_pkt_size_for(FlowSide::Responder), 25.0);
    }

    #[test]
    fn mean_pkt_size_for_balanced_flow() {
        let s = skewed_stats(100, 5, 200, 10);
        assert_eq!(s.mean_pkt_size_for(FlowSide::Initiator), 20.0);
        assert_eq!(s.mean_pkt_size_for(FlowSide::Responder), 20.0);
    }

    #[test]
    fn direction_skew_empty_flow_returns_zero() {
        let s = FlowStats::default();
        assert_eq!(s.direction_skew(), 0.0);
    }

    #[test]
    fn direction_skew_initiator_only_returns_one() {
        let s = skewed_stats(100, 5, 0, 0);
        assert_eq!(s.direction_skew(), 1.0);
    }

    #[test]
    fn direction_skew_responder_only_returns_negative_one() {
        let s = skewed_stats(0, 0, 200, 8);
        assert_eq!(s.direction_skew(), -1.0);
    }

    #[test]
    fn direction_skew_balanced_returns_zero() {
        let s = skewed_stats(100, 5, 100, 5);
        assert_eq!(s.direction_skew(), 0.0);
    }

    #[test]
    fn direction_skew_two_to_one_initiator_heavy() {
        // 200 initiator vs 100 responder; total 300; skew = 100/300 = 0.333…
        let s = skewed_stats(200, 5, 100, 5);
        assert!((s.direction_skew() - 1.0 / 3.0).abs() < 1e-12);
    }

    #[test]
    fn direction_skew_within_unit_range() {
        for (init, resp) in [(1u64, 0u64), (0, 1), (1, 1), (1_000_000, 1), (1, 1_000_000)] {
            let s = skewed_stats(init, 1, resp, 1);
            let skew = s.direction_skew();
            assert!(
                (-1.0..=1.0).contains(&skew),
                "skew {skew} out of [-1, 1] for ({init}, {resp})"
            );
        }
    }

    // ── Plan 173 (0.14) — throughput accessors ────────────

    fn stats_with_duration(
        init_bytes: u64,
        init_pkts: u64,
        resp_bytes: u64,
        resp_pkts: u64,
        secs: u32,
    ) -> FlowStats {
        FlowStats {
            packets_initiator: init_pkts,
            packets_responder: resp_pkts,
            bytes_initiator: init_bytes,
            bytes_responder: resp_bytes,
            started: crate::Timestamp::new(0, 0),
            last_seen: crate::Timestamp::new(secs, 0),
            ..FlowStats::default()
        }
    }

    #[test]
    fn throughput_bps_lifetime_avg() {
        // 1000 bytes init + 500 bytes resp over 10 s = 150 B/s.
        let s = stats_with_duration(1000, 5, 500, 5, 10);
        let bps = s.throughput_bps();
        assert!((bps - 150.0).abs() < 1e-9, "expected 150.0 B/s, got {bps}");
    }

    #[test]
    fn throughput_pps_lifetime_avg() {
        // 5 + 5 = 10 packets over 10 s = 1 pps.
        let s = stats_with_duration(1000, 5, 500, 5, 10);
        assert!((s.throughput_pps() - 1.0).abs() < 1e-9);
    }

    #[test]
    fn throughput_bps_for_split_by_side() {
        // 1000 init / 10s = 100 B/s init; 500 resp / 10s = 50 B/s resp.
        let s = stats_with_duration(1000, 5, 500, 5, 10);
        assert!((s.throughput_bps_for(FlowSide::Initiator) - 100.0).abs() < 1e-9);
        assert!((s.throughput_bps_for(FlowSide::Responder) - 50.0).abs() < 1e-9);
    }

    #[test]
    fn throughput_pps_for_split_by_side() {
        let s = stats_with_duration(1000, 5, 500, 8, 10);
        assert!((s.throughput_pps_for(FlowSide::Initiator) - 0.5).abs() < 1e-9);
        assert!((s.throughput_pps_for(FlowSide::Responder) - 0.8).abs() < 1e-9);
    }

    #[test]
    fn throughput_zero_duration_flow_returns_zero_not_nan() {
        // started == last_seen → duration_secs() == 0.
        // All four throughput accessors must return 0.0, NOT
        // NaN or Infinity.
        let s = FlowStats {
            packets_initiator: 1,
            bytes_initiator: 1500,
            started: crate::Timestamp::new(0, 0),
            last_seen: crate::Timestamp::new(0, 0),
            ..FlowStats::default()
        };
        for v in [
            s.throughput_bps(),
            s.throughput_pps(),
            s.throughput_bps_for(FlowSide::Initiator),
            s.throughput_pps_for(FlowSide::Responder),
        ] {
            assert!(v.is_finite(), "value {v} is not finite");
            assert_eq!(v, 0.0);
        }
    }

    #[test]
    fn throughput_sides_sum_to_total() {
        let s = stats_with_duration(1000, 5, 500, 5, 10);
        let total = s.throughput_bps();
        let by_side =
            s.throughput_bps_for(FlowSide::Initiator) + s.throughput_bps_for(FlowSide::Responder);
        assert!((total - by_side).abs() < 1e-9);
    }
}
