//! Behavioural fingerprints for encrypted flows.
//!
//! Encrypted protocols (TLS, QUIC, SSH, …) hide the payload,
//! but the **packet-size sequence** and **inter-arrival times**
//! at the start of the flow remain visible and are surprisingly
//! distinctive per application / library / version. This module
//! provides the alloc-free primitives to accumulate those
//! sequences per flow and emit a hashable fingerprint at flow
//! end.
//!
//! ## Prior art
//!
//! - **Cisco Joy** ([github.com/cisco/joy](https://github.com/cisco/joy)) —
//!   the canonical SPLT (Sequence of Packet Lengths and Times)
//!   feature; foundational for encrypted-malware classification.
//! - **Mercury** (Cisco) — Joy's production successor; same
//!   feature shape, mature pipeline.
//! - **JA4L / JA4LS** — FoxIO's length-only client+server pair,
//!   sibling to JA4. Different shape (single-feature
//!   fingerprint, not a sequence), but same goal: visibility
//!   without decryption.
//! - Anderson & McGrew, **"Identifying Encrypted Malware Traffic
//!   with Contextual Flow Data"** (ACM AISec 2016) — the SPLT
//!   methodology paper.
//!
//! ## Privacy footnote
//!
//! Behavioural fingerprints don't decrypt, but they DO let an
//! observer correlate users across sessions, app versions, and
//! sometimes individual user identities. Operators choosing to
//! deploy this module should know what they're enabling.
//!
//! ## Perf
//!
//! The per-packet path is the design constraint: a fixed-size
//! [`arrayvec::ArrayVec`] stores the first N samples. After N
//! observations, additional samples are silently dropped — the
//! fingerprint is bounded. No heap allocation on the record
//! path.
//!
//! Issue #4 (0.17).

use arrayvec::ArrayVec;

/// Maximum packet-length samples retained per flow. Joy uses 30
/// in its default config; we round up to 32.
pub const MAX_SAMPLES: usize = 32;

/// Running per-flow fingerprint accumulator.
///
/// Updated on each packet via [`Self::observe`]; finalised at
/// flow end via [`Self::finish`]. The finalised
/// [`FlowFingerprint`] is hashable + emits a feature vector
/// suitable for ML pipelines.
///
/// Allocates exactly **zero** bytes on the per-packet path —
/// `observe` is a tail-call into `ArrayVec::push` that becomes
/// a no-op once the buffer is full.
#[derive(Debug, Default, Clone)]
pub struct FingerprintBuilder {
    len_seq: ArrayVec<u16, MAX_SAMPLES>,
    iat_seq: ArrayVec<u32, MAX_SAMPLES>,
    last_ts_micros: Option<u64>,
    bytes_init: u64,
    bytes_resp: u64,
    pkts_init: u32,
    pkts_resp: u32,
}

impl FingerprintBuilder {
    /// Construct an empty builder.
    pub fn new() -> Self {
        Self::default()
    }

    /// Observe one packet.
    ///
    /// - `payload_len` is the **L4 payload length** (post-header
    ///   bytes), saturating-clamped to `u16::MAX` for very
    ///   large segments. Joy uses post-IP, post-L4 length.
    /// - `is_initiator` distinguishes client→server (`true`) from
    ///   server→client (`false`).
    /// - `ts_micros` is the packet's microsecond timestamp.
    ///   Inter-arrival times are computed as `ts - prev_ts`,
    ///   saturating-clamped to `u32::MAX` (~71 minutes — any
    ///   gap longer than this is operationally an eternity).
    ///
    /// Once the per-sequence cap is reached, further packets
    /// continue to update aggregate byte / packet counters but
    /// don't push to `len_seq` / `iat_seq`. This is the bounded-
    /// memory contract.
    #[inline]
    pub fn observe(&mut self, payload_len: usize, is_initiator: bool, ts_micros: u64) {
        let len_u16 = payload_len.min(u16::MAX as usize) as u16;
        // Aggregate counters update always (no per-flow cap).
        if is_initiator {
            self.bytes_init = self.bytes_init.saturating_add(payload_len as u64);
            self.pkts_init = self.pkts_init.saturating_add(1);
        } else {
            self.bytes_resp = self.bytes_resp.saturating_add(payload_len as u64);
            self.pkts_resp = self.pkts_resp.saturating_add(1);
        }
        // Sequence tails fill until cap, then become no-ops.
        let _ = self.len_seq.try_push(len_u16);
        let iat = match self.last_ts_micros {
            Some(prev) => ts_micros.saturating_sub(prev).min(u32::MAX as u64) as u32,
            None => 0,
        };
        let _ = self.iat_seq.try_push(iat);
        self.last_ts_micros = Some(ts_micros);
    }

    /// Number of length samples currently retained.
    #[inline]
    pub fn samples(&self) -> usize {
        self.len_seq.len()
    }

    /// `true` if the per-sequence cap is reached and further
    /// `observe` calls won't extend the sequences.
    #[inline]
    pub fn is_saturated(&self) -> bool {
        self.len_seq.is_full()
    }

    /// Finalise into an immutable [`FlowFingerprint`]. The
    /// builder is consumed.
    pub fn finish(self) -> FlowFingerprint {
        FlowFingerprint {
            len_seq: self.len_seq,
            iat_seq: self.iat_seq,
            bytes_init: self.bytes_init,
            bytes_resp: self.bytes_resp,
            pkts_init: self.pkts_init,
            pkts_resp: self.pkts_resp,
        }
    }
}

/// Finalised per-flow fingerprint.
///
/// Provides two distinct downstream surfaces:
///
/// - [`Self::fnv1a`] — a stable `u64` hash for direct equality
///   ("does this flow's fingerprint match a known IOC?").
/// - [`Self::as_features`] — a fixed-size `[f64; 8]` summary
///   for ML pipelines ("feed this to a classifier").
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FlowFingerprint {
    /// First-N L4 payload lengths.
    pub len_seq: ArrayVec<u16, MAX_SAMPLES>,
    /// First-N inter-arrival times in microseconds (first
    /// element always 0).
    pub iat_seq: ArrayVec<u32, MAX_SAMPLES>,
    /// Aggregate initiator-side bytes (counts every packet,
    /// not capped at `MAX_SAMPLES`).
    pub bytes_init: u64,
    /// Aggregate responder-side bytes.
    pub bytes_resp: u64,
    /// Aggregate initiator-side packets.
    pub pkts_init: u32,
    /// Aggregate responder-side packets.
    pub pkts_resp: u32,
}

impl FlowFingerprint {
    /// 64-bit FNV-1a hash over `(len_seq || iat_seq)`. Stable
    /// across runs; two flows that produced the same prefix
    /// sequences hash identically.
    pub fn fnv1a(&self) -> u64 {
        const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
        const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
        let mut h = FNV_OFFSET;
        for v in &self.len_seq {
            for b in v.to_be_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        for v in &self.iat_seq {
            for b in v.to_be_bytes() {
                h ^= b as u64;
                h = h.wrapping_mul(FNV_PRIME);
            }
        }
        h
    }

    /// Fixed-size summary feature vector suitable for ML
    /// pipelines.
    ///
    /// Layout (all `f64`):
    /// 1. `samples` — number of `len_seq` entries
    /// 2. `mean_len` — average packet length over `len_seq`
    /// 3. `mean_iat_us` — average inter-arrival microseconds
    /// 4. `bytes_init`
    /// 5. `bytes_resp`
    /// 6. `pkts_init`
    /// 7. `pkts_resp`
    /// 8. `direction_skew` — `(bytes_init - bytes_resp) /
    ///    (bytes_init + bytes_resp)`, in `[-1, 1]`. `0` when
    ///    both sides are empty.
    pub fn as_features(&self) -> [f64; 8] {
        let samples = self.len_seq.len() as f64;
        let mean_len = if self.len_seq.is_empty() {
            0.0
        } else {
            self.len_seq.iter().map(|&v| v as u64).sum::<u64>() as f64 / samples
        };
        let mean_iat = if self.iat_seq.is_empty() {
            0.0
        } else {
            self.iat_seq.iter().map(|&v| v as u64).sum::<u64>() as f64 / (self.iat_seq.len() as f64)
        };
        let total = self.bytes_init + self.bytes_resp;
        let skew = if total == 0 {
            0.0
        } else {
            (self.bytes_init as f64 - self.bytes_resp as f64) / total as f64
        };
        [
            samples,
            mean_len,
            mean_iat,
            self.bytes_init as f64,
            self.bytes_resp as f64,
            self.pkts_init as f64,
            self.pkts_resp as f64,
            skew,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_builder_finishes_to_empty_fingerprint() {
        let fp = FingerprintBuilder::new().finish();
        assert_eq!(fp.len_seq.len(), 0);
        assert_eq!(fp.iat_seq.len(), 0);
        assert_eq!(fp.bytes_init, 0);
        assert_eq!(fp.bytes_resp, 0);
    }

    #[test]
    fn single_observation_first_iat_is_zero() {
        let mut b = FingerprintBuilder::new();
        b.observe(100, true, 1_000_000);
        let fp = b.finish();
        assert_eq!(fp.len_seq.as_slice(), &[100]);
        assert_eq!(fp.iat_seq.as_slice(), &[0]);
        assert_eq!(fp.bytes_init, 100);
        assert_eq!(fp.pkts_init, 1);
    }

    #[test]
    fn iat_computed_from_consecutive_observations() {
        let mut b = FingerprintBuilder::new();
        b.observe(50, true, 1_000_000);
        b.observe(60, false, 1_000_500); // +500 μs
        b.observe(70, true, 1_002_500); // +2000 μs
        let fp = b.finish();
        assert_eq!(fp.iat_seq.as_slice(), &[0, 500, 2000]);
    }

    #[test]
    fn saturates_at_max_samples() {
        let mut b = FingerprintBuilder::new();
        for i in 0..(MAX_SAMPLES + 10) {
            b.observe(i, true, i as u64);
        }
        assert!(b.is_saturated());
        assert_eq!(b.samples(), MAX_SAMPLES);
        // Aggregate counters keep counting past the cap.
        let fp = b.finish();
        assert_eq!(fp.pkts_init as usize, MAX_SAMPLES + 10);
    }

    #[test]
    fn payload_len_clamps_at_u16_max() {
        let mut b = FingerprintBuilder::new();
        b.observe(usize::MAX, true, 0);
        let fp = b.finish();
        assert_eq!(fp.len_seq[0], u16::MAX);
        assert_eq!(fp.bytes_init, usize::MAX as u64);
    }

    #[test]
    fn direction_split_initiator_vs_responder() {
        let mut b = FingerprintBuilder::new();
        b.observe(100, true, 0);
        b.observe(200, false, 100);
        b.observe(50, true, 200);
        let fp = b.finish();
        assert_eq!(fp.bytes_init, 150);
        assert_eq!(fp.bytes_resp, 200);
        assert_eq!(fp.pkts_init, 2);
        assert_eq!(fp.pkts_resp, 1);
    }

    #[test]
    fn fnv1a_stable_across_identical_fingerprints() {
        let mut a = FingerprintBuilder::new();
        let mut b = FingerprintBuilder::new();
        for i in 0..5 {
            a.observe(100 + i, true, i as u64);
            b.observe(100 + i, true, i as u64);
        }
        assert_eq!(a.finish().fnv1a(), b.finish().fnv1a());
    }

    #[test]
    fn fnv1a_differs_for_distinct_sequences() {
        let mut a = FingerprintBuilder::new();
        let mut b = FingerprintBuilder::new();
        a.observe(100, true, 0);
        b.observe(101, true, 0);
        assert_ne!(a.finish().fnv1a(), b.finish().fnv1a());
    }

    #[test]
    fn fnv1a_differs_when_only_iat_changes() {
        let mut a = FingerprintBuilder::new();
        let mut b = FingerprintBuilder::new();
        a.observe(100, true, 0);
        a.observe(100, true, 1000);
        b.observe(100, true, 0);
        b.observe(100, true, 2000); // different IAT
        assert_ne!(a.finish().fnv1a(), b.finish().fnv1a());
    }

    #[test]
    fn as_features_layout() {
        let mut b = FingerprintBuilder::new();
        b.observe(100, true, 0);
        b.observe(200, false, 1000);
        let f = b.finish().as_features();
        assert_eq!(f[0], 2.0); // samples
        assert_eq!(f[1], 150.0); // mean_len
        assert_eq!(f[2], 500.0); // mean_iat (0 + 1000)/2
        assert_eq!(f[3], 100.0); // bytes_init
        assert_eq!(f[4], 200.0); // bytes_resp
        assert_eq!(f[5], 1.0); // pkts_init
        assert_eq!(f[6], 1.0); // pkts_resp
                               // skew = (100 - 200) / 300 = -1/3
        assert!((f[7] - (-1.0 / 3.0)).abs() < 1e-12);
    }

    #[test]
    fn as_features_empty_returns_all_zero() {
        let fp = FingerprintBuilder::new().finish();
        let f = fp.as_features();
        assert!(f.iter().all(|&v| v == 0.0));
    }

    #[test]
    fn observe_does_not_allocate_after_first_few_packets() {
        // The arrayvec backing means observe never grows past
        // its inline capacity. We can't bench heap usage from a
        // unit test, but we CAN confirm is_full() == true at the
        // cap, so further observe calls must be no-allocating
        // (they hit ArrayVec's try_push fast path).
        let mut b = FingerprintBuilder::new();
        for i in 0..MAX_SAMPLES {
            b.observe(i, true, i as u64);
        }
        assert!(b.is_saturated());
        // Past-cap observe still returns cleanly.
        b.observe(9999, true, 9999);
        assert!(b.is_saturated());
        assert_eq!(b.samples(), MAX_SAMPLES);
    }
}
