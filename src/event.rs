//! Events emitted by [`crate::FlowTracker`] as packets flow through it.

use bitflags::bitflags;

use crate::{
    Timestamp,
    extractor::{L4Proto, Orientation},
    history::HistoryString,
};

/// Which side of a flow a packet belongs to — the **logical role**
/// direction axis (who started the conversation).
///
/// Derived from the [`crate::Orientation`] reported by the extractor:
/// - The **first** orientation seen for a flow becomes the
///   `Initiator` direction.
/// - Packets matching that orientation are `Initiator`, packets in
///   the opposite orientation are `Responder`.
///
/// # First-seen is arrival-order-relative — not deterministic
///
/// `Initiator` binds to whichever endpoint flowscope saw **first**,
/// which is usually the SYN sender but is ultimately "first packet
/// of this flow to reach the tracker". On a single capture point that
/// is reliable. Across a **tap-merge** (two NICs / two queues feeding
/// one tracker, with a scheduling race) the first-seen packet can be
/// the *response*, so `Initiator` may bind to the server on some flows
/// and the client on others — non-deterministically.
///
/// When you need a direction label two independent captures of the
/// same flow will agree on, use [`crate::Orientation`] (deterministic,
/// address-sorted) instead. flowscope keeps both: the
/// [`FlowEvent::Started`] / [`FlowEvent::Packet`] events carry **both**
/// `side` (this axis) and `orientation` (the canonical axis), and
/// [`FlowStats::initiator_orientation`] records which `Orientation` the
/// initiator's first packet had so you can translate between them on a
/// finished flow. See `docs/concepts.md` →
/// "Direction, orientation, and capture leg".
///
/// Maps to IPFIX `biflowDirection` (IE 239, RFC 5103): `Initiator` ≈
/// `initiator` (value 1), `Responder` ≈ `reverseInitiator` (value 2).
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
#[non_exhaustive]
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

/// TCP overlap-resolution policy — which segment's bytes win
/// the overlap region when two TCP segments cover the same
/// sequence range with different content.
///
/// This is the Ptacek-Newsham (1998) evasion model. Different
/// OS TCP stacks resolve overlap differently; if the analyzer
/// resolves it the wrong way for the target, attackers can
/// smuggle bytes the IDS can't see. flowscope flags any
/// content divergence via
/// [`AnomalyKind::TcpRexmitInconsistency`] regardless of the
/// policy chosen; the policy controls *which* bytes the
/// reassembler hands to the consumer.
///
/// The 4-variant enum collapses Suricata's 15+ `OS_POLICY_*`
/// constants into the operationally-meaningful kernels —
/// most named OS policies actually behave identically and
/// the per-OS divergence is mostly historical drift. The
/// mapping table:
///
/// | flowscope policy | Suricata `OS_POLICY_*` |
/// |---|---|
/// | [`Self::First`] | BSD (default), HPUX10, IRIX, MACOS, WINDOWS, WINDOWS2K3 |
/// | [`Self::Last`] | LAST |
/// | [`Self::LowerSeq`] | BSD_RIGHT, SOLARIS, OLD_SOLARIS, FIRST |
/// | [`Self::HigherSeq`] | VISTA, OLD_LINUX, LINUX, HPUX11 |
///
/// Default is [`Self::First`] — matches Suricata's
/// `OS_POLICY_DEFAULT = OS_POLICY_BSD`.
///
/// `#[non_exhaustive]` — future per-OS variants can land
/// additively.
///
/// New in 0.18.0 (issue #17 close).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TcpOverlapPolicy {
    /// **Default.** First-arriving segment's bytes win the
    /// overlap region. The BSD-family default — the safest
    /// evasion-resistant choice when no per-host knowledge
    /// is available, because it matches what real BSD /
    /// macOS / Windows / IRIX / HP-UX 10 hosts do.
    #[default]
    First,
    /// Last-arriving segment's bytes win the overlap region.
    /// Matches the explicit Suricata `last` policy.
    Last,
    /// The segment with the **lower start sequence** wins
    /// the overlap region. Models Suricata `bsd_right` /
    /// `solaris` / `old_solaris` / `first` behavior — on
    /// truly partial overlaps, the segment whose data
    /// started earlier in the byte stream wins.
    LowerSeq,
    /// The segment with the **higher start sequence** wins.
    /// Models Linux's (Suricata `linux` / `old_linux` /
    /// `hpux11` / `vista`) handling — when a later segment
    /// starts deeper into the stream and overlaps, the
    /// later-starting segment wins the overlap region.
    HigherSeq,
}

impl TcpOverlapPolicy {
    /// Stable slug for metric labels and JSON emission.
    pub fn as_str(&self) -> &'static str {
        match self {
            TcpOverlapPolicy::First => "first",
            TcpOverlapPolicy::Last => "last",
            TcpOverlapPolicy::LowerSeq => "lower_seq",
            TcpOverlapPolicy::HigherSeq => "higher_seq",
        }
    }
}

/// Tracker-wide memcap policy — what to do when the total
/// reassembly buffering across all flows trips the configured
/// memcap. Mirrors Suricata's `stream.reassembly.memcap-policy`
/// vocabulary, collapsed to the four behaviors that make
/// sense for a passive analyzer.
///
/// Set on [`crate::FlowTrackerConfig::reassembly_memcap_policy`];
/// the cap itself is
/// [`crate::FlowTrackerConfig::reassembly_memcap`].
///
/// `#[non_exhaustive]` — additive forever.
///
/// New in 0.18.0 (issue #17 close).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum MemcapPolicy {
    /// **Default.** Silently drop new segments when the cap
    /// is hit. The flow stays alive; the parser sees a gap
    /// and may resync. A single
    /// [`AnomalyKind::GlobalMemcapHit`] fires per tick on the
    /// first violation; subsequent violations in the same
    /// tick are coalesced into the same anomaly's running
    /// count.
    #[default]
    Ignore,
    /// End the violating flow on the next tick — emits
    /// `Ended { reason: BufferOverflow }`. Use when you'd
    /// rather lose one flow than corrupt analysis on it.
    DropFlow,
    /// Discard the segment that would push past the memcap
    /// but keep the flow + existing buffer intact. The
    /// reassembler stays usable; only the offending packet
    /// is dropped.
    DropPacket,
    /// Stop reassembling this flow (poison its reassembler)
    /// but keep tracking flow stats. Parser stops emitting
    /// messages on the affected flow; the flow itself stays
    /// alive in the tracker.
    PassThrough,
}

impl MemcapPolicy {
    /// Stable slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            MemcapPolicy::Ignore => "ignore",
            MemcapPolicy::DropFlow => "drop_flow",
            MemcapPolicy::DropPacket => "drop_packet",
            MemcapPolicy::PassThrough => "pass_through",
        }
    }
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
    /// Populated by [`crate::FlowDriver`] and the typed
    /// [`crate::driver::Driver`] on `Ended` and via live
    /// snapshot accessors. Zero when no reassembler was attached.
    pub reassembler_high_watermark_initiator: u64,
    pub reassembler_high_watermark_responder: u64,
    /// New in 0.5.0: per-side count of TCP segments classified as
    /// retransmits by the per-side reassembler. Populated by
    /// [`crate::FlowDriver`] on `Ended`. See
    /// [`crate::Reassembler::retransmits`].
    pub retransmits_initiator: u64,
    pub retransmits_responder: u64,
    /// New in 0.18.0 (issue #15): per-direction last-seen
    /// timestamps. The whole-flow [`Self::last_seen`] is the
    /// max of the two. Defaults to [`Timestamp::default`]
    /// (zero) when no packet has been observed on that side.
    pub last_seen_initiator: Timestamp,
    pub last_seen_responder: Timestamp,
    /// New in 0.18.0 (issue #15): inter-arrival-time stats
    /// between consecutive packets in either direction.
    /// IAT values are stored as floating-point microseconds.
    /// Empty (`count() == 0`) until the second packet of the
    /// flow arrives.
    pub iat_flow: crate::correlate::WelfordStats,
    /// Per-direction IAT stats — same units (µs), same
    /// "second-packet-on-this-side wins" semantics. Each
    /// receives observations only between consecutive
    /// initiator-side or responder-side packets respectively.
    pub iat_initiator: crate::correlate::WelfordStats,
    pub iat_responder: crate::correlate::WelfordStats,
    /// New in 0.18.0 (issue #15): CICFlowMeter-style
    /// active/idle period stats. Each "active" period is
    /// a stretch where consecutive packets arrived within
    /// [`crate::FlowTrackerConfig::active_idle_threshold`];
    /// any longer gap closes the active period and opens
    /// an idle gap.
    ///
    /// `active_periods` records the *duration* of each
    /// completed active period (µs); `idle_periods`
    /// records the *duration* of each idle gap.
    pub active_periods: crate::correlate::WelfordStats,
    pub idle_periods: crate::correlate::WelfordStats,
    /// First packet of the currently-open active period.
    /// `None` until the first packet arrives. Internal
    /// accounting — useful for consumers that want to
    /// inspect mid-flow state. `Option` to avoid the
    /// "real packet at ts=0 vs sentinel default" trap.
    pub active_period_start: Option<Timestamp>,
    /// New in 0.20.0 (issue #118): the canonical [`Orientation`] the
    /// flow's **initiator** (first-seen packet) had. This is the
    /// bridge between the two direction axes on a finished flow:
    /// a packet whose `orientation == initiator_orientation` is on
    /// the [`FlowSide::Initiator`] side, the opposite orientation is
    /// [`FlowSide::Responder`]. Deterministic — unlike `FlowSide`
    /// itself, it does not depend on packet arrival order.
    ///
    /// Defaults to [`Orientation::Forward`] for a default-constructed
    /// `FlowStats`; a tracked flow always carries the real value.
    pub initiator_orientation: Orientation,
    /// New in 0.20.0 (issue #120): physical capture leg
    /// ([`crate::RxMetadata::source_idx`]) bound to each canonical
    /// [`Orientation`], so a **merged** bidirectional flow can still
    /// report "the `Forward` half arrived on NIC X, the `Reverse` half
    /// on NIC Y" — the IPFIX biflow-merge model (RFC 5103: a forward
    /// `ingressInterface` IE 10 + a reverse one), not a per-packet
    /// drop.
    ///
    /// Bound to `Orientation` (not [`FlowSide`]) so the leg is
    /// arrival-order-stable, like the rest of the #71 fix. Recorded on
    /// the first packet of each orientation that carries a **non-zero**
    /// `source_idx` (`0` is the documented "unused" sentinel), so pcap
    /// / synthetic sources leave these `None`. Use
    /// [`Self::source_idx_for`] for `Orientation`-keyed access.
    pub source_idx_forward: Option<u32>,
    pub source_idx_reverse: Option<u32>,
    /// New in 0.20.0 (issue #120): set when a **second, different**
    /// non-zero `source_idx` is later seen for an
    /// [`Orientation`] already bound to a leg — the tap-miswire /
    /// asymmetric-routing IOC ("one leg per direction" assumption
    /// violated). The original binding is kept; this flag flips.
    pub capture_leg_inconsistent: bool,
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

    /// Translate a canonical [`Orientation`] into the logical
    /// [`FlowSide`] for **this** flow, using
    /// [`Self::initiator_orientation`].
    ///
    /// A packet whose orientation equals the initiator's orientation
    /// is on the [`FlowSide::Initiator`] side; the opposite is
    /// [`FlowSide::Responder`]. This is the deterministic bridge
    /// between the two direction axes — see [`Orientation`] vs
    /// [`FlowSide`]. New in 0.20.0 (issue #118).
    #[inline]
    pub fn side_for(&self, orientation: Orientation) -> FlowSide {
        if orientation == self.initiator_orientation {
            FlowSide::Initiator
        } else {
            FlowSide::Responder
        }
    }

    /// Translate a logical [`FlowSide`] into the canonical
    /// [`Orientation`] for **this** flow — the inverse of
    /// [`Self::side_for`]. New in 0.20.0 (issue #118).
    #[inline]
    pub fn orientation_for(&self, side: FlowSide) -> Orientation {
        match side {
            FlowSide::Initiator => self.initiator_orientation,
            FlowSide::Responder => self.initiator_orientation.flipped(),
        }
    }

    /// The physical capture leg ([`crate::RxMetadata::source_idx`])
    /// bound to the given canonical [`Orientation`], or `None` if no
    /// non-zero `source_idx` was ever seen for that direction (the
    /// pcap / synthetic case). New in 0.20.0 (issue #120).
    ///
    /// Combine with [`Self::side_for`] / [`Self::orientation_for`] to
    /// answer "which NIC did the initiator's traffic arrive on?" on a
    /// merged flow. [`Self::capture_leg_inconsistent`] reports whether
    /// the one-leg-per-direction assumption held.
    #[inline]
    pub fn source_idx_for(&self, orientation: Orientation) -> Option<u32> {
        match orientation {
            Orientation::Forward => self.source_idx_forward,
            Orientation::Reverse => self.source_idx_reverse,
        }
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
#[non_exhaustive]
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

    /// New in 0.18.0 (issue #17 sub-piece). Reassembler observed
    /// one or more TCP segments whose bytes diverged from
    /// already-pending bytes in the same sequence range during
    /// this tick — the classic Ptacek-Newsham TCP-overlap
    /// evasion IOC (Zeek calls this `rexmit_inconsistency`).
    /// Coalesced — at most one anomaly per (flow, side) per
    /// tick, with `count` summing the delta of
    /// [`crate::Reassembler::rexmit_inconsistencies`].
    TcpRexmitInconsistency { side: FlowSide, count: u64 },

    /// New in 0.18.0 (issue #17 close). Tracker-wide
    /// reassembly memcap was hit during this tick and the
    /// configured [`crate::MemcapPolicy`] kicked in.
    /// `bytes_in_flight` is the total reassembly buffering
    /// occupancy at the moment of the trip; `cap` is the
    /// configured memcap; `policy` records how the violation
    /// was handled. Coalesced per tick.
    GlobalMemcapHit {
        bytes_in_flight: u64,
        cap: u64,
        policy: MemcapPolicy,
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
    /// | [`Self::TcpRexmitInconsistency`] | `"tcp_rexmit_inconsistency"` |
    /// | [`Self::GlobalMemcapHit`] | `"global_memcap_hit"` |
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
            | AnomalyKind::TcpRexmitInconsistency { .. }
            | AnomalyKind::ReassemblerHighWatermark { .. } => "stream",
            AnomalyKind::SessionParseError { .. } => "applayer",
            AnomalyKind::FlowTableEvictionPressure { .. } => "stream",
            AnomalyKind::GlobalMemcapHit { .. } => "stream",
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
            // Overlapping bytes that disagree is an evasion IOC,
            // not a benign retransmit — escalate above `Info`.
            AnomalyKind::TcpRexmitInconsistency { .. } => Severity::Error,
            // Hitting the global memcap is a serious capacity
            // problem; operators have to react. Critical so it
            // crosses default alert thresholds.
            AnomalyKind::GlobalMemcapHit { .. } => Severity::Critical,
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

bitflags! {
    /// Selects which [`FlowEvent`] variants a tracker should *not*
    /// emit — a source-level load-shedding knob (issue #79).
    ///
    /// Each bit maps to one [`FlowEvent`] variant. The empty mask
    /// (the [`Default`]) suppresses nothing, so the feature is
    /// inert until a consumer opts in via
    /// [`FlowTrackerConfig::with_event_filter`](crate::FlowTrackerConfig::with_event_filter).
    /// Suppressed events are never *constructed* — the highest-volume
    /// variant ([`Self::PACKET`]) costs nothing under overload, and
    /// the [`FlowStats`] / [`HistoryString`] clones behind
    /// [`Self::ENDED`] / [`Self::TICK`] are skipped entirely.
    ///
    /// Suppression never touches accounting: the TCP state machine,
    /// byte/packet counters and idle bookkeeping all keep running, so
    /// flows still finalize correctly. Only the emission is shed.
    ///
    /// The tracker emits five of these variants itself ([`Self::STARTED`],
    /// [`Self::PACKET`], [`Self::ESTABLISHED`], [`Self::STATE_CHANGE`],
    /// [`Self::ENDED`]); [`Self::TICK`], [`Self::FLOW_ANOMALY`] and
    /// [`Self::TRACKER_ANOMALY`] are produced by the drivers, which honour
    /// the same mask where they emit them (today: `TICK`).
    ///
    /// For a *total* shed over the duration of an overload episode use
    /// [`FlowTracker::pause_events`](crate::FlowTracker::pause_events) /
    /// [`resume_events`](crate::FlowTracker::resume_events) instead, which
    /// gate every variant regardless of the mask.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct EventMask: u8 {
        /// [`FlowEvent::Started`].
        const STARTED         = 1 << 0;
        /// [`FlowEvent::Packet`] — the highest-volume variant.
        const PACKET          = 1 << 1;
        /// [`FlowEvent::Established`].
        const ESTABLISHED     = 1 << 2;
        /// [`FlowEvent::StateChange`].
        const STATE_CHANGE    = 1 << 3;
        /// [`FlowEvent::Ended`].
        const ENDED           = 1 << 4;
        /// [`FlowEvent::FlowAnomaly`] (driver-emitted).
        const FLOW_ANOMALY    = 1 << 5;
        /// [`FlowEvent::TrackerAnomaly`] (driver-emitted).
        const TRACKER_ANOMALY = 1 << 6;
        /// [`FlowEvent::Tick`] (driver-emitted).
        const TICK            = 1 << 7;
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
    ///
    /// Carries **both** direction axes (issue #118): `side` is the
    /// logical role ([`FlowSide::Initiator`] for the first packet),
    /// `orientation` is the deterministic canonical direction
    /// ([`Orientation`]) — equal to the flow's
    /// [`FlowStats::initiator_orientation`].
    Started {
        key: K,
        side: FlowSide,
        /// Canonical (address-sorted) orientation of this packet —
        /// deterministic regardless of arrival order. See
        /// [`Orientation`] and [`FlowSide`] for the distinction.
        orientation: Orientation,
        ts: Timestamp,
        l4: Option<L4Proto>,
    },

    /// Subsequent packet on a known flow.
    ///
    /// Carries **both** direction axes (issue #118): `side` is the
    /// logical role relative to the flow's initiator, `orientation`
    /// is this packet's deterministic canonical direction.
    Packet {
        key: K,
        side: FlowSide,
        /// Canonical (address-sorted) orientation of this packet.
        /// Together with the flow's
        /// [`FlowStats::initiator_orientation`] this recovers `side`
        /// deterministically. See [`Orientation`] vs [`FlowSide`].
        orientation: Orientation,
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
            orientation: Orientation::Forward,
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
