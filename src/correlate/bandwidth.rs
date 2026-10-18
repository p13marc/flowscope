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
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use flowscope::Timestamp;
//! use flowscope::correlate::{BandwidthByKey, Attribution};
//!
//! // Owner key = a PID the consumer joined externally; at most
//! // 4 096 owners per one-second bucket.
//! let mut bw = BandwidthByKey::<Attribution>::new(
//!     Duration::from_secs(10),
//!     Duration::from_secs(1),
//!     4096,
//! );
//! for s in 0..10 {
//!     let now = Timestamp::new(s, 0);
//!     bw.record_tx(Attribution(1234), 1_000, now);
//!     bw.record_rx(Attribution(1234), 500, now);
//! }
//! let now = Timestamp::new(9, 0);
//! assert!((bw.tx_bps(&Attribution(1234), now) - 1_000.0).abs() < 50.0);
//! // Rank owners by combined tx+rx rate.
//! let top = bw.top_k(5, now);
//! assert_eq!(top[0].0, Attribution(1234));
//! ```
//!
//! # Bounded memory
//!
//! Owner keys can be numerous (or chosen by whoever generates the
//! traffic). [`BandwidthByKey::new`] caps the keys each time bucket
//! holds, per direction; bytes of further keys go to an overflow
//! total ([`BandwidthByKey::other_tx_bps`] /
//! [`BandwidthByKey::other_rx_bps`], counted in
//! [`BandwidthByKey::overflowed`]) — see
//! [`RollingRate`](crate::correlate::RollingRate#bounded-memory).
//! [`BandwidthByKey::new_unbounded`] keeps every key. (0.26, #220.)

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
    /// defaults), holding at most `max_keys` keys per time bucket and
    /// direction (see [`RollingRate`](crate::correlate::RollingRate#bounded-memory)). Bytes
    /// are tagged [`ByteSemantics::Wire`]. New in 0.26.0 (#220).
    pub fn new(window: Duration, bucket_width: Duration, max_keys: usize) -> Self {
        Self {
            tx: RollingRate::new(window, bucket_width, max_keys),
            rx: RollingRate::new(window, bucket_width, max_keys),
            semantics: ByteSemantics::Wire,
        }
    }

    /// Unbounded aggregator: [`Self::new`] without a key cap. Only
    /// for key spaces the caller controls.
    pub fn new_unbounded(window: Duration, bucket_width: Duration) -> Self {
        Self::new(window, bucket_width, usize::MAX)
    }

    /// Like [`new_unbounded`](Self::new_unbounded) but with an
    /// explicit [`ByteSemantics`] tag. For a bounded aggregator use
    /// [`Self::new`] and [`Self::with_byte_semantics`].
    pub fn with_semantics(
        window: Duration,
        bucket_width: Duration,
        semantics: ByteSemantics,
    ) -> Self {
        Self::new_unbounded(window, bucket_width).with_byte_semantics(semantics)
    }

    /// Builder — set the [`ByteSemantics`] tag. New in 0.26.0.
    pub fn with_byte_semantics(mut self, semantics: ByteSemantics) -> Self {
        self.semantics = semantics;
        self
    }

    /// `record_tx` / `record_rx` calls whose key went to an overflow
    /// total because its bucket was full (both directions). New in
    /// 0.26.0.
    pub fn overflowed(&self) -> u64 {
        self.tx.overflowed().saturating_add(self.rx.overflowed())
    }

    /// Transmit rate (bytes/sec) of the keys the cap refused,
    /// summed. New in 0.26.0.
    pub fn other_tx_bps(&self, now: Timestamp) -> f64 {
        self.tx.other_rate(now)
    }

    /// Receive rate (bytes/sec) of the keys the cap refused, summed.
    /// New in 0.26.0.
    pub fn other_rx_bps(&self, now: Timestamp) -> f64 {
        self.rx.other_rate(now)
    }

    /// The per-bucket key cap ([`Self::new`]). New in 0.26.0.
    pub fn max_keys(&self) -> usize {
        self.tx.max_keys()
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
        crate::correlate::rolling_rate::top_n(totals.into_iter().collect(), n)
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

    /// Reset all recorded state and the overflow count (keeps
    /// window / cap / semantics config).
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

    #[test]
    fn key_cap_bounds_owners_and_reports_the_rest() {
        let mut bw =
            BandwidthByKey::<u32>::new(Duration::from_secs(10), Duration::from_secs(1), 100);
        for k in 0..10_000u32 {
            bw.record_tx(k, 10, t(0));
            bw.record_rx(k, 5, t(0));
        }
        assert_eq!(bw.max_keys(), 100);
        assert_eq!(bw.overflowed(), 2 * 9_900);
        let now = t(1);
        assert!((bw.other_tx_bps(now) - 99_000.0 / 10.0).abs() < 1e-9);
        assert!((bw.other_rx_bps(now) - 49_500.0 / 10.0).abs() < 1e-9);
        assert_eq!(bw.top_k(1_000, now).len(), 100);
        let gp = BandwidthByKey::<u32>::new(Duration::from_secs(10), Duration::from_secs(1), 1)
            .with_byte_semantics(ByteSemantics::Goodput);
        assert_eq!(gp.semantics(), ByteSemantics::Goodput);
    }
}
