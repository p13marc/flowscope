//! TCP flag presence ("count" in CICFlowMeter terms) + Zeek
//! `conn_state` derivation.
//!
//! flowscope's tracker aggregates TCP flag observations into
//! per-side "ever-seen" bitmasks (the IPFIX `tcpControlBits`
//! IE form, RFC 7125). That throws away the per-segment
//! count, so a [`TcpFlagCounts`] derived from a [`FlowRecord`]
//! reports 0/1 per flag, not the true count. The field name
//! matches the CICFlowMeter vocabulary for ergonomics; the
//! semantic difference is documented on each accessor.
//!
//! For true per-segment counts a per-packet feature tracker
//! is required — see the [`crate::detect::fingerprint`]
//! first-N baseline as the existing per-packet path.

use crate::ipfix::FlowRecord;

/// Per-direction TCP flag presence map. Each field is `0` or
/// `1` per flag per direction — the closest information
/// flowscope's `FlowRecord` (bitmask-aggregated) can produce.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TcpFlagCounts {
    pub fwd_fin: u8,
    pub fwd_syn: u8,
    pub fwd_rst: u8,
    pub fwd_psh: u8,
    pub fwd_ack: u8,
    pub fwd_urg: u8,
    pub fwd_ece: u8,
    pub fwd_cwr: u8,
    pub bwd_fin: u8,
    pub bwd_syn: u8,
    pub bwd_rst: u8,
    pub bwd_psh: u8,
    pub bwd_ack: u8,
    pub bwd_urg: u8,
    pub bwd_ece: u8,
    pub bwd_cwr: u8,
}

impl TcpFlagCounts {
    /// Combined fwd+bwd FIN presence (0/1/2).
    pub fn fin_count(&self) -> u8 {
        self.fwd_fin + self.bwd_fin
    }
    /// Combined fwd+bwd SYN presence (0/1/2).
    pub fn syn_count(&self) -> u8 {
        self.fwd_syn + self.bwd_syn
    }
    /// Combined fwd+bwd RST presence (0/1/2).
    pub fn rst_count(&self) -> u8 {
        self.fwd_rst + self.bwd_rst
    }
    /// Combined fwd+bwd PSH presence (0/1/2).
    pub fn psh_count(&self) -> u8 {
        self.fwd_psh + self.bwd_psh
    }
    /// Combined fwd+bwd ACK presence (0/1/2).
    pub fn ack_count(&self) -> u8 {
        self.fwd_ack + self.bwd_ack
    }
    /// Combined fwd+bwd URG presence (0/1/2).
    pub fn urg_count(&self) -> u8 {
        self.fwd_urg + self.bwd_urg
    }
    /// Combined fwd+bwd ECE presence (0/1/2).
    pub fn ece_count(&self) -> u8 {
        self.fwd_ece + self.bwd_ece
    }
    /// Combined fwd+bwd CWR presence (0/1/2).
    pub fn cwr_count(&self) -> u8 {
        self.fwd_cwr + self.bwd_cwr
    }
}

/// Decode the `tcpControlBits_*` fields on a [`FlowRecord`]
/// into a per-direction flag presence map.
///
/// Layout: bit 0 = FIN, 1 = SYN, 2 = RST, 3 = PSH, 4 = ACK,
/// 5 = URG, 6 = ECE, 7 = CWR. Matches RFC 7125 IE 6 wire form
/// and [`crate::ipfix::encode_tcp_control_bits`].
pub fn count_tcp_flags(rec: &FlowRecord) -> TcpFlagCounts {
    let init = rec.tcp_control_bits_initiator.unwrap_or(0);
    let resp = rec.tcp_control_bits_responder.unwrap_or(0);
    TcpFlagCounts {
        fwd_fin: bit(init, 0),
        fwd_syn: bit(init, 1),
        fwd_rst: bit(init, 2),
        fwd_psh: bit(init, 3),
        fwd_ack: bit(init, 4),
        fwd_urg: bit(init, 5),
        fwd_ece: bit(init, 6),
        fwd_cwr: bit(init, 7),
        bwd_fin: bit(resp, 0),
        bwd_syn: bit(resp, 1),
        bwd_rst: bit(resp, 2),
        bwd_psh: bit(resp, 3),
        bwd_ack: bit(resp, 4),
        bwd_urg: bit(resp, 5),
        bwd_ece: bit(resp, 6),
        bwd_cwr: bit(resp, 7),
    }
}

const fn bit(bits: u16, idx: u32) -> u8 {
    ((bits >> idx) & 1) as u8
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfix::encode_tcp_control_bits;
    use crate::{EndReason, FlowRecord, FlowStats, FlowTracker, extract::FiveTuple};

    fn empty_record() -> FlowRecord {
        // Minimal record via from_parts.
        use crate::FlowExtractor;
        let mut t: FlowTracker<FiveTuple, ()> = FlowTracker::new(FiveTuple::bidirectional());
        // Drive a single packet to obtain a (key, stats) snapshot
        // we can pass to from_parts.
        let frame = crate::extract::parse::test_frames::ipv4_tcp(
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
        let pv = crate::PacketView::new(&frame, crate::Timestamp::default());
        let key = FiveTuple::bidirectional().extract(pv).expect("ext").key;
        t.track(pv);
        let stats = t.snapshot_stats(&key).expect("stats");
        FlowRecord::from_parts(&stats, &key, Some(EndReason::Fin))
    }

    #[test]
    fn flag_count_zero_when_no_bits_set() {
        // FlowRecord::from_parts does NOT populate
        // tcp_control_bits — the caller must observe flags
        // explicitly. Default record → zero counts.
        let rec = empty_record();
        let counts = count_tcp_flags(&rec);
        assert_eq!(counts.syn_count(), 0);
        assert_eq!(counts.rst_count(), 0);
        assert_eq!(counts.fin_count(), 0);
    }

    #[test]
    fn flag_count_decodes_individual_bits() {
        let mut rec = empty_record();
        rec.tcp_control_bits_initiator = Some(encode_tcp_control_bits(
            true, true, false, true, true, false, false, false,
        ));
        rec.tcp_control_bits_responder = Some(encode_tcp_control_bits(
            false, true, false, false, true, false, true, false,
        ));
        let counts = count_tcp_flags(&rec);
        assert_eq!(counts.fwd_fin, 1);
        assert_eq!(counts.fwd_syn, 1);
        assert_eq!(counts.fwd_rst, 0);
        assert_eq!(counts.fwd_psh, 1);
        assert_eq!(counts.fwd_ack, 1);
        assert_eq!(counts.fwd_urg, 0);
        assert_eq!(counts.fwd_ece, 0);
        assert_eq!(counts.fwd_cwr, 0);
        assert_eq!(counts.bwd_syn, 1);
        assert_eq!(counts.bwd_ack, 1);
        assert_eq!(counts.bwd_ece, 1);
        assert_eq!(counts.bwd_fin, 0);
        assert_eq!(counts.fin_count(), 1);
        assert_eq!(counts.ack_count(), 2);
    }

    #[test]
    fn flag_count_missing_side_treated_as_zero() {
        let mut rec = empty_record();
        rec.tcp_control_bits_initiator = None;
        rec.tcp_control_bits_responder = None;
        let counts = count_tcp_flags(&rec);
        assert_eq!(counts.syn_count(), 0);
        assert_eq!(counts.fin_count(), 0);
        // Constructed FlowStats default to zero too.
        let _: FlowStats = FlowStats::default();
    }
}
