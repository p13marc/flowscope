//! `BandwidthByKey<K>` — throughput grouped by an opaque owner
//! key (issue #141).
//!
//! flowscope is deliberately process-unaware — it sees packets and
//! flows, never PIDs or cgroups. But a consumer often *does* have
//! an external attribution for a flow (owning PID from a
//! socket-table / eBPF join, a cgroup id, a security identity) and
//! wants **bandwidth grouped by that owner**, not just by 5-tuple.
//! Today every consumer bolts its own `HashMap<owner, RollingRate>`
//! on the side; this is that primitive, once.
//!
//! Generic over the key `K`, so one implementation serves
//! `K = pid`, `K = cgroup_id`, `K = `[`Attribution`],
//! `K = FiveTupleKey`, or `K = ParserKind`. Built on
//! [`RollingRate`](crate::correlate::RollingRate): per-key tx / rx
//! byte-rate over a sliding window, drainable per tick.
//!
//! # Byte semantics
//!
//! flowscope flows carry **wire** bytes (on-the-wire, including
//! headers and retransmits). An eBPF goodput feed would carry
//! something different. Every aggregate is tagged with its
//! [`ByteSemantics`] so a downstream never silently compares wire
//! bytes against application goodput.

use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;
use crate::correlate::RollingRate;

/// Whether an aggregate's byte counts are on-the-wire bytes or
/// application goodput. Prevents silently comparing the two.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum ByteSemantics {
    /// On-the-wire bytes — headers, padding, retransmits included.
    /// What flowscope flow accounting produces.
    #[default]
    Wire,
    /// Application goodput — payload bytes delivered to the app,
    /// no headers / retransmits. What an eBPF socket feed produces.
    Goodput,
}

impl ByteSemantics {
    /// Stable lowercase slug for logs / labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            ByteSemantics::Wire => "wire",
            ByteSemantics::Goodput => "goodput",
        }
    }
}

/// Opaque per-flow attribution tag — a `u64` the consumer sets
/// from whatever external join it has (PID, cgroup id, security
/// identity). flowscope never interprets it; it's a convenience
/// key type for [`BandwidthByKey`] when the owner is a bare
/// integer. Use any `Hash + Eq + Clone` type as the key instead if
/// you have a richer owner.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Attribution(pub u64);

/// Per-key transmit / receive throughput over a sliding window.
/// See the module-level documentation for byte semantics and
/// keying guidance.
pub struct BandwidthByKey<K>
where
    K: Hash + Eq + Clone,
{
    tx: RollingRate<K, u64>,
    rx: RollingRate<K, u64>,
    semantics: ByteSemantics,
}

impl<K> BandwidthByKey<K>
where
    K: Hash + Eq + Clone,
{
    /// New aggregator with the given `window` and `bucket_width`
    /// (e.g. 60 s window, 1 s buckets — Prometheus `rate()`
    /// defaults). Bytes are tagged [`ByteSemantics::Wire`].
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::with_semantics(window, bucket_width, ByteSemantics::Wire)
    }

    /// Like [`new_unbounded`](Self::new_unbounded) but with an
    /// explicit [`ByteSemantics`] tag.
    pub fn with_semantics(
        window: Duration,
        bucket_width: Duration,
        semantics: ByteSemantics,
    ) -> Self {
        Self {
            tx: RollingRate::new_unbounded(window, bucket_width),
            rx: RollingRate::new_unbounded(window, bucket_width),
            semantics,
        }
    }

    /// Record `bytes` transmitted by `key` at `now`.
    pub fn record_tx(&mut self, key: K, bytes: u64, now: Timestamp) {
        self.tx.record(key, bytes, now);
    }

    /// Record `bytes` received by `key` at `now`.
    pub fn record_rx(&mut self, key: K, bytes: u64, now: Timestamp) {
        self.rx.record(key, bytes, now);
    }

    /// Transmit rate for `key` in bytes/sec over the window.
    pub fn tx_bps(&self, key: &K, now: Timestamp) -> f64 {
        self.tx.rate(key, now)
    }

    /// Receive rate for `key` in bytes/sec over the window.
    pub fn rx_bps(&self, key: &K, now: Timestamp) -> f64 {
        self.rx.rate(key, now)
    }

    /// Combined tx + rx rate for `key` in bytes/sec.
    pub fn total_bps(&self, key: &K, now: Timestamp) -> f64 {
        self.tx.rate(key, now) + self.rx.rate(key, now)
    }

    /// Top `n` keys by combined tx + rx rate (bytes/sec),
    /// descending. Ties broken arbitrarily.
    pub fn top_k(&self, n: usize, now: Timestamp) -> Vec<(K, f64)> {
        use std::collections::HashMap;
        let mut totals: HashMap<K, f64> = HashMap::new();
        for (k, r) in self.tx.snapshot(now) {
            *totals.entry(k).or_default() += r;
        }
        for (k, r) in self.rx.snapshot(now) {
            *totals.entry(k).or_default() += r;
        }
        let mut v: Vec<(K, f64)> = totals.into_iter().collect();
        v.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap_or(std::cmp::Ordering::Equal));
        v.truncate(n);
        v
    }

    /// Drop buckets older than the window on both directions.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.tx.evict_expired(now);
        self.rx.evict_expired(now);
    }

    /// The byte-semantics tag these rates carry.
    pub fn semantics(&self) -> ByteSemantics {
        self.semantics
    }

    /// `true` when no bytes are stored in either direction.
    pub fn is_empty(&self) -> bool {
        self.tx.is_empty() && self.rx.is_empty()
    }

    /// Reset all recorded state (keeps window / semantics config).
    pub fn clear(&mut self) {
        self.tx.clear();
        self.rx.clear();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t(s: u32) -> Timestamp {
        Timestamp::new(s, 0)
    }

    #[test]
    fn tracks_tx_rx_per_key() {
        let mut bw =
            BandwidthByKey::<u32>::new_unbounded(Duration::from_secs(10), Duration::from_secs(1));
        // pid 42 sends 1000 B/s for the window; pid 7 receives 500.
        for s in 0..10 {
            bw.record_tx(42, 1000, t(s));
            bw.record_rx(7, 500, t(s));
        }
        let now = t(9);
        assert!((bw.tx_bps(&42, now) - 1000.0).abs() < 50.0);
        assert!((bw.rx_bps(&7, now) - 500.0).abs() < 50.0);
        // pid 42 received nothing.
        assert_eq!(bw.rx_bps(&42, now), 0.0);
    }

    #[test]
    fn total_and_top_k_rank_by_combined_rate() {
        let mut bw = BandwidthByKey::<Attribution>::new_unbounded(
            Duration::from_secs(10),
            Duration::from_secs(1),
        );
        for s in 0..10 {
            bw.record_tx(Attribution(1), 100, t(s));
            bw.record_rx(Attribution(1), 100, t(s)); // heavy: 200/s
            bw.record_tx(Attribution(2), 50, t(s)); // light: 50/s
        }
        let now = t(9);
        assert!(bw.total_bps(&Attribution(1), now) > bw.total_bps(&Attribution(2), now));
        let top = bw.top_k(2, now);
        assert_eq!(top[0].0, Attribution(1));
        assert_eq!(top[1].0, Attribution(2));
    }

    #[test]
    fn semantics_tag_defaults_to_wire() {
        let bw =
            BandwidthByKey::<u32>::new_unbounded(Duration::from_secs(10), Duration::from_secs(1));
        assert_eq!(bw.semantics(), ByteSemantics::Wire);
        let gp = BandwidthByKey::<u32>::with_semantics(
            Duration::from_secs(10),
            Duration::from_secs(1),
            ByteSemantics::Goodput,
        );
        assert_eq!(gp.semantics(), ByteSemantics::Goodput);
        assert_eq!(gp.semantics().as_str(), "goodput");
    }

    #[test]
    fn evict_and_clear() {
        let mut bw =
            BandwidthByKey::<u32>::new_unbounded(Duration::from_secs(5), Duration::from_secs(1));
        bw.record_tx(1, 1000, t(0));
        assert!(!bw.is_empty());
        // Advance well past the window.
        bw.evict_expired(t(100));
        assert_eq!(bw.tx_bps(&1, t(100)), 0.0);
        bw.record_tx(1, 500, t(100));
        bw.clear();
        assert!(bw.is_empty());
    }
}
