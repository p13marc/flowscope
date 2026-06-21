//! [`CicFlowFeatures`] — the per-flow feature vector.

use super::conn_state::{TcpFlagCounts, count_tcp_flags};
use crate::ipfix::FlowRecord;

/// Per-flow CICFlowMeter-compatible feature vector. Subset of
/// the ~80 features that's derivable from a finalised
/// [`FlowRecord`] alone. See the module docs for what does
/// and does NOT ship.
///
/// **Direction convention.** flowscope's "initiator" maps to
/// CICFlowMeter's "forward"; "responder" maps to "backward".
/// The first packet observed for a flow fixes the forward
/// direction.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct CicFlowFeatures {
    // ── Flow timing ──
    /// Flow duration in microseconds (`flow_end - flow_start`).
    pub flow_duration_us: u64,

    // ── Totals ──
    pub total_fwd_packets: u64,
    pub total_bwd_packets: u64,
    pub total_fwd_bytes: u64,
    pub total_bwd_bytes: u64,

    // ── Per-direction means ──
    /// Mean per-packet length in the forward direction
    /// (`total_fwd_bytes / total_fwd_packets`, 0.0 when no
    /// packets).
    pub fwd_packet_length_mean: f64,
    /// Mean per-packet length in the backward direction.
    pub bwd_packet_length_mean: f64,
    /// Mean per-packet length across both directions.
    pub mean_packet_length: f64,

    // ── Throughput ──
    /// Flow bytes per second (`(fwd+bwd_bytes) /
    /// flow_duration_seconds`, 0.0 when duration is 0).
    pub flow_bytes_per_sec: f64,
    /// Flow packets per second.
    pub flow_packets_per_sec: f64,

    // ── Direction skew ──
    /// Backward / forward bytes ratio. `0.0` when forward is
    /// 0 bytes (avoids inf/NaN). Roughly the "download / upload"
    /// indicator — values > 1 mean responder-heavy (downloads),
    /// < 1 mean initiator-heavy (uploads).
    pub down_up_ratio: f64,

    // ── TCP flag presence ──
    pub tcp_flag_counts: TcpFlagCounts,

    // ── Zeek conn_state ──
    /// Zeek-style 2-letter conn_state — "SF", "S0", "REJ",
    /// "RSTO", "OTH", etc. Derived from the flow's
    /// `end_reason`. See
    /// [`crate::EndReason::as_zeek_state`].
    /// `None` when the record was built without an end reason.
    pub conn_state: Option<&'static str>,

    // ── Inter-arrival time (issue #15 follow-up) ──
    //
    // CICFlowMeter's IAT features. Populated by
    // [`Self::with_iat`] / [`Self::from_flow_stats`] only —
    // FlowRecord doesn't carry per-packet timestamps.
    // Default zero when populated only from a FlowRecord
    // via [`Self::from_flow_record`].
    /// Mean inter-arrival time across all consecutive
    /// packets in the flow (any direction). Units: µs.
    pub flow_iat_mean_us: f64,
    /// Sample standard deviation of the flow IAT distribution.
    pub flow_iat_std_us: f64,
    /// Minimum observed IAT in the flow.
    pub flow_iat_min_us: f64,
    /// Maximum observed IAT in the flow.
    pub flow_iat_max_us: f64,

    /// Mean IAT between consecutive forward packets only.
    pub fwd_iat_mean_us: f64,
    /// Sample std-dev of the forward-only IAT distribution.
    pub fwd_iat_std_us: f64,
    /// Minimum observed forward-only IAT.
    pub fwd_iat_min_us: f64,
    /// Maximum observed forward-only IAT.
    pub fwd_iat_max_us: f64,

    /// Mean IAT between consecutive backward packets only.
    pub bwd_iat_mean_us: f64,
    /// Sample std-dev of the backward-only IAT distribution.
    pub bwd_iat_std_us: f64,
    /// Minimum observed backward-only IAT.
    pub bwd_iat_min_us: f64,
    /// Maximum observed backward-only IAT.
    pub bwd_iat_max_us: f64,
}

impl CicFlowFeatures {
    /// Build a feature vector from a finalised [`FlowRecord`].
    /// The record must have been produced via
    /// [`FlowRecord::from_parts`] (which fills in
    /// `flow_start_milliseconds` / `flow_end_milliseconds` /
    /// `*_delta_count_*` / `*_total_count` / `tcp_control_bits_*`
    /// / `flow_end_reason`).
    pub fn from_flow_record(rec: &FlowRecord) -> Self {
        let fwd_pkts = rec.packet_delta_count_initiator;
        let bwd_pkts = rec.packet_delta_count_responder;
        let fwd_bytes = rec.octet_delta_count_initiator;
        let bwd_bytes = rec.octet_delta_count_responder;
        let total_pkts = rec.packet_total_count;
        let total_bytes = rec.octet_total_count;

        let duration_us = rec
            .flow_end_milliseconds
            .saturating_sub(rec.flow_start_milliseconds)
            .saturating_mul(1000);
        let duration_secs = (duration_us as f64) / 1_000_000.0;

        let fwd_packet_length_mean = safe_div(fwd_bytes as f64, fwd_pkts as f64);
        let bwd_packet_length_mean = safe_div(bwd_bytes as f64, bwd_pkts as f64);
        let mean_packet_length = safe_div(total_bytes as f64, total_pkts as f64);

        let flow_bytes_per_sec = if duration_secs > 0.0 {
            (total_bytes as f64) / duration_secs
        } else {
            0.0
        };
        let flow_packets_per_sec = if duration_secs > 0.0 {
            (total_pkts as f64) / duration_secs
        } else {
            0.0
        };

        let down_up_ratio = safe_div(bwd_bytes as f64, fwd_bytes as f64);

        let conn_state = rec.flow_end_reason.and_then(zeek_state_label);

        Self {
            flow_duration_us: duration_us,
            total_fwd_packets: fwd_pkts,
            total_bwd_packets: bwd_pkts,
            total_fwd_bytes: fwd_bytes,
            total_bwd_bytes: bwd_bytes,
            fwd_packet_length_mean,
            bwd_packet_length_mean,
            mean_packet_length,
            flow_bytes_per_sec,
            flow_packets_per_sec,
            down_up_ratio,
            tcp_flag_counts: count_tcp_flags(rec),
            conn_state,
            flow_iat_mean_us: 0.0,
            flow_iat_std_us: 0.0,
            flow_iat_min_us: 0.0,
            flow_iat_max_us: 0.0,
            fwd_iat_mean_us: 0.0,
            fwd_iat_std_us: 0.0,
            fwd_iat_min_us: 0.0,
            fwd_iat_max_us: 0.0,
            bwd_iat_mean_us: 0.0,
            bwd_iat_std_us: 0.0,
            bwd_iat_min_us: 0.0,
            bwd_iat_max_us: 0.0,
        }
    }

    /// Populate the IAT fields from a [`crate::FlowStats`].
    /// FlowStats carries the per-direction WelfordStats
    /// updated per-packet by the tracker (issue #15
    /// follow-up). Use this when you also hold the original
    /// FlowStats — typically pulled from the
    /// `FlowEvent::Ended { stats, .. }` event.
    ///
    /// Returns `self` for builder chaining:
    ///
    /// ```rust,ignore
    /// let feats = CicFlowFeatures::from_flow_record(&rec)
    ///     .with_iat(&stats);
    /// ```
    pub fn with_iat(mut self, stats: &crate::FlowStats) -> Self {
        self.flow_iat_mean_us = stats.iat_flow.mean();
        self.flow_iat_std_us = stats.iat_flow.std();
        self.flow_iat_min_us = stats.iat_flow.min();
        self.flow_iat_max_us = stats.iat_flow.max();

        self.fwd_iat_mean_us = stats.iat_initiator.mean();
        self.fwd_iat_std_us = stats.iat_initiator.std();
        self.fwd_iat_min_us = stats.iat_initiator.min();
        self.fwd_iat_max_us = stats.iat_initiator.max();

        self.bwd_iat_mean_us = stats.iat_responder.mean();
        self.bwd_iat_std_us = stats.iat_responder.std();
        self.bwd_iat_min_us = stats.iat_responder.min();
        self.bwd_iat_max_us = stats.iat_responder.max();
        self
    }
}

fn safe_div(num: f64, denom: f64) -> f64 {
    if denom > 0.0 { num / denom } else { 0.0 }
}

/// Translate the IPFIX-flavoured [`FlowEndReason`](crate::ipfix::FlowEndReason)
/// back to the underlying [`crate::EndReason`] and then the
/// Zeek `conn_state` string. The mapping is best-effort and
/// loses the granularity of `Evicted` / `ForceClosed` /
/// `ParseError` / `ParserDone` (they coalesce into
/// `LackOfResources` and `EndOfFlowDetected` per RFC 5102 §5.11);
/// for those the Zeek vocabulary doesn't have a direct match
/// either ("OTH" is the catch-all).
fn zeek_state_label(reason: crate::ipfix::FlowEndReason) -> Option<&'static str> {
    use crate::ipfix::FlowEndReason as R;
    Some(match reason {
        R::IdleTimeout => "OTH",   // no clean SF/S0 distinction at this point
        R::ActiveTimeout => "OTH", // same
        R::EndOfFlowDetected => "SF",
        R::ForcedEnd => "OTH",
        R::LackOfResources => "OTH",
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::{FiveTuple, parse::test_frames::ipv4_tcp};
    use crate::ipfix::FlowEndReason;
    use crate::{FlowExtractor, FlowRecord, FlowStats, FlowTracker, PacketView, Timestamp};

    fn build_record(
        fwd_pkts: u64,
        bwd_pkts: u64,
        fwd_bytes: u64,
        bwd_bytes: u64,
        duration_ms: u64,
    ) -> FlowRecord {
        let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
        let frame = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1,
            80,
            1,
            0,
            0x02,
            b"",
        );
        let pv = PacketView::new(&frame, Timestamp::new(0, 0));
        let key = FiveTuple::bidirectional().extract(pv).expect("ext").key;
        t.track(pv);
        let mut stats = t.snapshot_stats(&key).expect("stats");
        // Overwrite the auto-derived counters with our test values.
        stats.packets_initiator = fwd_pkts;
        stats.packets_responder = bwd_pkts;
        stats.bytes_initiator = fwd_bytes;
        stats.bytes_responder = bwd_bytes;
        stats.last_seen = Timestamp::new(0, (duration_ms * 1_000_000) as u32);
        FlowRecord::from_parts(&stats, &key, Some(crate::EndReason::Fin))
    }

    #[test]
    fn totals_mirror_record() {
        let rec = build_record(5, 3, 500, 300, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.total_fwd_packets, 5);
        assert_eq!(f.total_bwd_packets, 3);
        assert_eq!(f.total_fwd_bytes, 500);
        assert_eq!(f.total_bwd_bytes, 300);
    }

    #[test]
    fn fwd_packet_length_mean_safe_div() {
        let rec = build_record(5, 3, 500, 300, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.fwd_packet_length_mean, 100.0);
        assert_eq!(f.bwd_packet_length_mean, 100.0);
    }

    #[test]
    fn mean_packet_length_uses_total() {
        let rec = build_record(2, 2, 400, 400, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.mean_packet_length, 200.0);
    }

    #[test]
    fn zero_packets_does_not_panic_or_nan() {
        let rec = build_record(0, 0, 0, 0, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.fwd_packet_length_mean, 0.0);
        assert_eq!(f.bwd_packet_length_mean, 0.0);
        assert!(!f.fwd_packet_length_mean.is_nan());
    }

    #[test]
    fn down_up_ratio_computed_responder_over_initiator() {
        let rec = build_record(10, 10, 100, 1000, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.down_up_ratio, 10.0, "10× responder bytes");
    }

    #[test]
    fn down_up_ratio_safe_when_initiator_zero() {
        let rec = build_record(0, 10, 0, 1000, 10);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.down_up_ratio, 0.0, "no initiator bytes → 0.0, not inf");
    }

    #[test]
    fn flow_duration_us_subtracts_start_from_end() {
        let rec = build_record(10, 10, 100, 100, 1500); // 1.5s flow
        let f = CicFlowFeatures::from_flow_record(&rec);
        // ipfix milliseconds × 1000 = microseconds. We set
        // last_seen to 1500ms after start_seen=0.
        assert_eq!(f.flow_duration_us, 1_500_000);
    }

    #[test]
    fn throughput_zero_duration_safe() {
        let rec = build_record(10, 10, 100, 100, 0);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.flow_bytes_per_sec, 0.0);
        assert_eq!(f.flow_packets_per_sec, 0.0);
        assert!(!f.flow_bytes_per_sec.is_nan());
        assert!(!f.flow_bytes_per_sec.is_infinite());
    }

    #[test]
    fn throughput_computed_correctly() {
        let rec = build_record(10, 10, 100, 100, 1000); // 1s flow
        let f = CicFlowFeatures::from_flow_record(&rec);
        // 200 bytes total / 1s = 200 B/s.
        assert_eq!(f.flow_bytes_per_sec, 200.0);
        assert_eq!(f.flow_packets_per_sec, 20.0);
    }

    #[test]
    fn conn_state_maps_from_end_reason() {
        let mut rec = build_record(1, 1, 1, 1, 1);
        rec.flow_end_reason = Some(FlowEndReason::EndOfFlowDetected);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.conn_state, Some("SF"));
        rec.flow_end_reason = Some(FlowEndReason::IdleTimeout);
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.conn_state, Some("OTH"));
        rec.flow_end_reason = None;
        let f = CicFlowFeatures::from_flow_record(&rec);
        assert_eq!(f.conn_state, None);
    }

    #[test]
    fn unused_flowstats_default_for_completeness() {
        // Sanity touch — FlowStats default is the all-zero shape.
        let s = FlowStats::default();
        assert_eq!(s.packets_initiator, 0);
    }
}
