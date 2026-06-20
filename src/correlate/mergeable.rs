//! [`Mergeable`] — combine per-shard state from sharded
//! per-RSS-queue workers.
//!
//! The highest-impact perf pattern for passive analysis (Retina
//! SIGCOMM '22, RSS++ CoNEXT '19) is **lockless RSS-sharded
//! per-core flow tables**: each RX queue / worker owns a thread-
//! local flow table + correlate state, and shards are unioned
//! **off the hot path** — removing locks/atomics from per-packet
//! work.
//!
//! netring already shards capture per RX queue (`XdpShardedRunner`
//! / `ShardedRunner` with the `merge_state` seam). For that to
//! actually work, flowscope's stateful primitives need a `merge`
//! operation. This trait makes the contract explicit.
//!
//! ## Contract
//!
//! Implementations must be **commutative + associative**:
//!
//! ```text
//! a.merge(b).merge(c) == a.merge(c).merge(b)     // commutative
//! (a.merge(b)).merge(c) == a.merge(b.merge(c))   // associative
//! ```
//!
//! This lets consumers union N shards in any order and get the
//! same result — required for the sharded-aggregation pattern
//! where shards finish at different times.
//!
//! ## When the contract is non-obvious
//!
//! - **`Ewma` merge has TWO defensible semantics** (sample-count
//!   weighted vs reset-and-fold). Implementations document which
//!   one is shipped.
//! - **`TimeBucketedCounter` / `RollingRate` require matching
//!   bucket boundaries** — `(bucket_width, window)` must match
//!   across shards. We panic on mismatch rather than silently
//!   realign, which would hide config bugs.
//! - **`TopK` (Misra-Gries / Space-Saving) merge** is from
//!   Metwally et al. PODS '05 — pairwise minimum of counters,
//!   then re-truncate to capacity. Documented in the impl.
//!
//! Issue #19 (Release A).

/// Combine sharded per-RSS-queue state off the hot path.
///
/// **Contract**: implementations MUST be commutative + associative
/// so consumers can union shards in any order. See the module
/// docs for the per-primitive semantics.
///
/// `merge_all` has a default delegating to pairwise [`Self::merge`];
/// primitives with a faster N-way union (HLL sketches, etc.) may
/// override.
pub trait Mergeable {
    /// Combine `other` into `self`. Consumes `other`.
    fn merge(&mut self, other: Self);

    /// Combine all elements of `others` into `self`.
    ///
    /// The default implementation pairwise-merges via
    /// [`Self::merge`]. Primitives with a more efficient bulk
    /// merge (e.g., HLL elementwise `max`) should override.
    fn merge_all(&mut self, others: impl IntoIterator<Item = Self>)
    where
        Self: Sized,
    {
        for o in others {
            self.merge(o);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Compile-time check: the trait can be implemented and the
    /// default `merge_all` works.
    #[test]
    fn default_merge_all_compiles_and_runs() {
        struct AdditiveU64(u64);
        impl Mergeable for AdditiveU64 {
            fn merge(&mut self, other: Self) {
                self.0 += other.0;
            }
        }
        let mut acc = AdditiveU64(1);
        acc.merge_all([AdditiveU64(2), AdditiveU64(3), AdditiveU64(4)]);
        assert_eq!(acc.0, 10);
    }
}
