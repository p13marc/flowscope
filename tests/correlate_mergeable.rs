//! Integration tests for the `Mergeable` trait — verify the
//! commutative + associative contract for each shipped impl.
//!
//! Issue #19 (Release A).

use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::{
    Ewma, Mergeable, RollingRate, TimeBucketedCounter, TimeBucketedSet, TopK,
};

fn ts(secs: u32) -> Timestamp {
    Timestamp::new(secs, 0)
}

// ─── TopK ────────────────────────────────────────────────

#[test]
fn topk_merge_sums_shared_keys() {
    let mut a: TopK<&'static str> = TopK::new(8);
    let mut b: TopK<&'static str> = TopK::new(8);
    a.observe_n("alice", 10);
    a.observe_n("bob", 3);
    b.observe_n("alice", 5);
    b.observe_n("carol", 7);
    a.merge(b);
    assert_eq!(a.estimate(&"alice"), 15);
    assert_eq!(a.estimate(&"bob"), 3);
    assert_eq!(a.estimate(&"carol"), 7);
}

#[test]
fn topk_merge_respects_capacity() {
    // Capacity 2; merged set has 4 keys; must truncate to 2.
    let mut a: TopK<u32> = TopK::new(2);
    let mut b: TopK<u32> = TopK::new(2);
    a.observe_n(1, 100);
    a.observe_n(2, 50);
    b.observe_n(3, 90);
    b.observe_n(4, 10);
    a.merge(b);
    assert!(a.len() <= 2);
    // Heaviest keys (1 and 3) should survive.
    assert!(a.estimate(&1) > 0);
    assert!(a.estimate(&3) > 0);
}

#[test]
#[should_panic(expected = "matching k")]
fn topk_merge_panics_on_capacity_mismatch() {
    let mut a: TopK<u32> = TopK::new(4);
    let b: TopK<u32> = TopK::new(8);
    a.merge(b);
}

#[test]
fn topk_merge_is_commutative() {
    let mut a: TopK<u32> = TopK::new(8);
    let mut b: TopK<u32> = TopK::new(8);
    for &k in &[1u32, 1, 2, 3, 3, 3] {
        a.observe(k);
    }
    for &k in &[2u32, 2, 3, 4] {
        b.observe(k);
    }
    let mut ab = a.clone();
    let mut ba = b.clone();
    ab.merge(b);
    ba.merge(a);
    // Compare via .top() (sorted descending) for stable equality
    let ab_top: Vec<_> = ab.top().into_iter().map(|(k, c)| (*k, c)).collect();
    let ba_top: Vec<_> = ba.top().into_iter().map(|(k, c)| (*k, c)).collect();
    assert_eq!(ab_top, ba_top);
}

// ─── TimeBucketedCounter ─────────────────────────────────

#[test]
fn time_bucketed_counter_merge_sums_aligned_buckets() {
    let mut a: TimeBucketedCounter<&'static str> =
        TimeBucketedCounter::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    let mut b: TimeBucketedCounter<&'static str> =
        TimeBucketedCounter::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    a.bump("ssh", ts(10));
    a.bump("ssh", ts(10));
    b.bump("ssh", ts(10));
    b.bump("http", ts(11));
    a.merge(b);
    assert_eq!(a.count(&"ssh", ts(15)), 3);
    assert_eq!(a.count(&"http", ts(15)), 1);
}

#[test]
#[should_panic(expected = "matching bucket_width")]
fn time_bucketed_counter_merge_panics_on_bucket_width_mismatch() {
    let mut a: TimeBucketedCounter<&'static str> =
        TimeBucketedCounter::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    let b: TimeBucketedCounter<&'static str> =
        TimeBucketedCounter::new_unbounded(Duration::from_secs(60), Duration::from_secs(2));
    a.merge(b);
}

// ─── TimeBucketedSet ─────────────────────────────────────

#[test]
fn time_bucketed_set_merge_unions_values() {
    let mut a: TimeBucketedSet<&'static str, u16> =
        TimeBucketedSet::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    let mut b: TimeBucketedSet<&'static str, u16> =
        TimeBucketedSet::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    a.insert("host-a", 22, ts(0));
    a.insert("host-a", 80, ts(0));
    b.insert("host-a", 443, ts(0));
    b.insert("host-b", 22, ts(0));
    a.merge(b);
    assert_eq!(a.cardinality(&"host-a", ts(5)), 3); // 22, 80, 443
    assert_eq!(a.cardinality(&"host-b", ts(5)), 1);
}

// ─── Ewma ────────────────────────────────────────────────

#[test]
fn ewma_merge_averages_per_key_shared_values() {
    let mut a: Ewma<&'static str> = Ewma::new(1.0);
    let mut b: Ewma<&'static str> = Ewma::new(1.0);
    a.record("latency", 100.0);
    b.record("latency", 200.0);
    a.merge(b);
    // shared-key arithmetic mean: (100 + 200) / 2 = 150
    assert!((a.get(&"latency").unwrap() - 150.0).abs() < 1e-9);
}

#[test]
fn ewma_merge_retains_lone_keys() {
    let mut a: Ewma<&'static str> = Ewma::new(1.0);
    let mut b: Ewma<&'static str> = Ewma::new(1.0);
    a.record("dns", 5.0);
    b.record("http", 10.0);
    a.merge(b);
    assert_eq!(a.get(&"dns"), Some(5.0));
    assert_eq!(a.get(&"http"), Some(10.0));
}

#[test]
#[should_panic(expected = "matching alpha")]
fn ewma_merge_panics_on_alpha_mismatch() {
    let mut a: Ewma<&'static str> = Ewma::new(0.5);
    let b: Ewma<&'static str> = Ewma::new(0.25);
    a.merge(b);
}

// ─── RollingRate ─────────────────────────────────────────

#[test]
fn rolling_rate_merge_sums_aligned_buckets() {
    let mut a: RollingRate<&'static str, u64> =
        RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    let mut b: RollingRate<&'static str, u64> =
        RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    a.record("eth0", 100, ts(0));
    a.record("eth0", 200, ts(1));
    b.record("eth0", 50, ts(0));
    b.record("eth1", 75, ts(0));
    a.merge(b);
    // eth0 sum: 100+200+50 = 350 over 60s window
    assert_eq!(a.sum(&"eth0", ts(5)), 350);
    assert_eq!(a.sum(&"eth1", ts(5)), 75);
}

#[test]
#[should_panic(expected = "matching window")]
fn rolling_rate_merge_panics_on_window_mismatch() {
    let mut a: RollingRate<&'static str, u64> =
        RollingRate::new_unbounded(Duration::from_secs(60), Duration::from_secs(1));
    let b: RollingRate<&'static str, u64> =
        RollingRate::new_unbounded(Duration::from_secs(30), Duration::from_secs(1));
    a.merge(b);
}

// ─── merge_all default ───────────────────────────────────

#[test]
fn merge_all_default_combines_n_shards() {
    let mut acc: TopK<&'static str> = TopK::new(8);
    acc.observe_n("alice", 1);
    let shards = vec![
        {
            let mut s: TopK<&'static str> = TopK::new(8);
            s.observe_n("bob", 2);
            s
        },
        {
            let mut s: TopK<&'static str> = TopK::new(8);
            s.observe_n("alice", 3);
            s.observe_n("carol", 4);
            s
        },
    ];
    acc.merge_all(shards);
    assert_eq!(acc.estimate(&"alice"), 4); // 1 + 3
    assert_eq!(acc.estimate(&"bob"), 2);
    assert_eq!(acc.estimate(&"carol"), 4);
}
