//! Integration tests for the `Mergeable` trait — verify the
//! commutative + associative contract for each shipped impl.
//!
//! Issue #19 (Release A).

use std::time::Duration;

use flowscope::Timestamp;
use flowscope::correlate::{
    DdSketch, Ewma, EwmaVar, FirstSeen, Mergeable, RollingRate, TimeBucketedCounter,
    TimeBucketedSet, TopK, WelfordStats, WindowedQuantiles,
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

// ─── EwmaVar (issue #134) ────────────────────────────────

#[test]
fn ewma_var_merge_pools_mean_and_variance() {
    let mut a: EwmaVar<u32> = EwmaVar::new(0.5);
    let mut b: EwmaVar<u32> = EwmaVar::new(0.5);
    // Shard A settles near 10, shard B near 20 (both zero variance
    // after constant streams).
    for _ in 0..50 {
        a.record(1, 10.0);
        b.record(1, 20.0);
    }
    a.merge(b);
    let v = a.get(&1).unwrap();
    assert!((v.mean - 15.0).abs() < 1e-9, "pooled mean");
    // Cross-term: 0.25 * (10-20)^2 = 25 — merged spread reflects the
    // level difference between the shards.
    assert!((v.variance - 25.0).abs() < 1e-6, "pooled variance");
}

#[test]
fn ewma_var_merge_retains_lone_keys() {
    let mut a: EwmaVar<u32> = EwmaVar::new(0.5);
    let mut b: EwmaVar<u32> = EwmaVar::new(0.5);
    a.record(1, 10.0);
    b.record(2, 20.0);
    a.merge(b);
    assert_eq!(a.get(&1).unwrap().mean, 10.0);
    assert_eq!(a.get(&2).unwrap().mean, 20.0);
}

#[test]
fn ewma_var_merge_is_commutative() {
    let mk = |samples: &[(u32, f64)]| {
        let mut e: EwmaVar<u32> = EwmaVar::new(0.3);
        for (k, v) in samples {
            e.record(*k, *v);
        }
        e
    };
    let mut ab = mk(&[(1, 10.0), (2, 5.0)]);
    ab.merge(mk(&[(1, 30.0), (3, 7.0)]));
    let mut ba = mk(&[(1, 30.0), (3, 7.0)]);
    ba.merge(mk(&[(1, 10.0), (2, 5.0)]));
    for k in [1u32, 2, 3] {
        let x = ab.get(&k).unwrap();
        let y = ba.get(&k).unwrap();
        assert!((x.mean - y.mean).abs() < 1e-9, "key {k} mean");
        assert!((x.variance - y.variance).abs() < 1e-9, "key {k} var");
    }
}

#[test]
#[should_panic(expected = "matching alpha")]
fn ewma_var_merge_panics_on_alpha_mismatch() {
    let mut a: EwmaVar<u32> = EwmaVar::new(0.5);
    let b: EwmaVar<u32> = EwmaVar::new(0.9);
    a.merge(b);
}

// ─── WelfordStats (issue #134) ───────────────────────────

#[test]
fn welford_trait_merge_equals_serial_stream() {
    // Merging two shards through the Mergeable trait must equal
    // one stream that saw all samples (exact parallel merge).
    let all: Vec<f64> = (1..=20).map(|i| i as f64 * 1.5).collect();
    let mut serial = WelfordStats::new();
    for v in &all {
        serial.observe(*v);
    }
    let mut shard_a = WelfordStats::new();
    let mut shard_b = WelfordStats::new();
    for v in &all[..8] {
        shard_a.observe(*v);
    }
    for v in &all[8..] {
        shard_b.observe(*v);
    }
    Mergeable::merge(&mut shard_a, shard_b);
    assert_eq!(shard_a.count(), serial.count());
    assert!((shard_a.mean() - serial.mean()).abs() < 1e-9);
    assert!((shard_a.variance_sample() - serial.variance_sample()).abs() < 1e-9);
    assert_eq!(shard_a.min(), serial.min());
    assert_eq!(shard_a.max(), serial.max());
}

#[test]
fn welford_trait_merge_is_commutative() {
    let mk = |vals: &[f64]| {
        let mut s = WelfordStats::new();
        for v in vals {
            s.observe(*v);
        }
        s
    };
    let mut ab = mk(&[1.0, 2.0, 3.0]);
    Mergeable::merge(&mut ab, mk(&[10.0, 20.0]));
    let mut ba = mk(&[10.0, 20.0]);
    Mergeable::merge(&mut ba, mk(&[1.0, 2.0, 3.0]));
    assert!((ab.mean() - ba.mean()).abs() < 1e-9);
    assert!((ab.variance_sample() - ba.variance_sample()).abs() < 1e-9);
    assert_eq!(ab.count(), ba.count());
}

// ─── FirstSeen (issue #134) ──────────────────────────────

#[test]
fn first_seen_merge_unions_with_min_first_max_last() {
    let mut a: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(100), 64);
    let mut b: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(100), 64);
    a.observe(1, ts(5));
    b.observe(1, ts(2)); // earlier first sighting on shard B
    b.observe(1, ts(9)); // later last sighting on shard B
    b.observe(2, ts(3));
    a.merge(b);
    // Earliest first_seen (2) survives the union.
    assert_eq!(a.first_seen(&1, ts(10)), Some(ts(2)));
    // Lone key from B retained.
    assert!(a.seen(&2, ts(10)));
    // Latest last_seen (9) drives expiry: alive at t=105 (within
    // 100s of 9), dead at t=110.
    assert!(a.seen(&1, ts(105)));
    assert!(!a.seen(&1, ts(110)));
}

#[test]
fn first_seen_merge_is_commutative() {
    let mk = |obs: &[(u32, u32)]| {
        let mut f: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(100), 64);
        for (k, t) in obs {
            f.observe(*k, ts(*t));
        }
        f
    };
    let mut ab = mk(&[(1, 5), (2, 1)]);
    ab.merge(mk(&[(1, 2), (3, 7)]));
    let mut ba = mk(&[(1, 2), (3, 7)]);
    ba.merge(mk(&[(1, 5), (2, 1)]));
    for k in [1u32, 2, 3] {
        assert_eq!(
            ab.first_seen(&k, ts(8)),
            ba.first_seen(&k, ts(8)),
            "key {k}"
        );
    }
}

#[test]
#[should_panic(expected = "matching ttl")]
fn first_seen_merge_panics_on_ttl_mismatch() {
    let mut a: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(1), 64);
    let b: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(2), 64);
    a.merge(b);
}

#[test]
#[should_panic(expected = "matching capacity")]
fn first_seen_merge_panics_on_capacity_mismatch() {
    let mut a: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(1), 64);
    let b: FirstSeen<u32> = FirstSeen::new(Duration::from_secs(1), 128);
    a.merge(b);
}

// ─── DdSketch / WindowedQuantiles (issue #134) ───────────

#[test]
fn ddsketch_merge_equals_serial_stream() {
    let mut serial = DdSketch::new(0.01, 2048);
    let mut a = DdSketch::new(0.01, 2048);
    let mut b = DdSketch::new(0.01, 2048);
    for i in 1..=400 {
        serial.insert(i as f64);
        a.insert(i as f64);
    }
    for i in 401..=800 {
        serial.insert(i as f64);
        b.insert(i as f64);
    }
    a.merge(b);
    assert_eq!(a.count(), serial.count());
    for q in [0.5, 0.9, 0.99] {
        let m = a.quantile(q).unwrap();
        let s = serial.quantile(q).unwrap();
        assert!((m - s).abs() / s <= 0.05, "q={q} merged={m} serial={s}");
    }
}

#[test]
fn ddsketch_merge_is_commutative() {
    let mk = |lo: u32, hi: u32| {
        let mut s = DdSketch::new(0.01, 1024);
        for i in lo..=hi {
            s.insert(i as f64);
        }
        s
    };
    let mut ab = mk(1, 250);
    ab.merge(mk(251, 500));
    let mut ba = mk(251, 500);
    ba.merge(mk(1, 250));
    for q in [0.25, 0.5, 0.95] {
        assert_eq!(ab.quantile(q).unwrap(), ba.quantile(q).unwrap(), "q={q}");
    }
}

#[test]
#[should_panic(expected = "alpha mismatch")]
fn ddsketch_merge_panics_on_alpha_mismatch() {
    let mut a = DdSketch::new(0.01, 1024);
    let b = DdSketch::new(0.05, 1024);
    a.merge(b);
}

#[test]
#[should_panic(expected = "max_bins mismatch")]
fn ddsketch_merge_panics_on_max_bins_mismatch() {
    let mut a = DdSketch::new(0.01, 1024);
    let b = DdSketch::new(0.01, 512);
    a.merge(b);
}

#[test]
fn windowed_quantiles_merge_unions_aligned_buckets() {
    let mk = || WindowedQuantiles::new(Duration::from_secs(60), Duration::from_secs(1), 0.01, 512);
    let mut a = mk();
    let mut b = mk();
    for _ in 0..20 {
        a.record(100.0, ts(5));
        b.record(100.0, ts(5));
        b.record(100.0, ts(7));
    }
    a.merge(b);
    // ts=5 merged in place, ts=7 inserted → 2 live buckets.
    assert_eq!(a.len(), 2);
    let p50 = a.quantile(0.5, ts(7)).unwrap();
    assert!((p50 - 100.0).abs() / 100.0 < 0.05, "p50={p50}");
}

#[test]
#[should_panic(expected = "bucket_width mismatch")]
fn windowed_quantiles_merge_panics_on_bucket_mismatch() {
    let mut a = WindowedQuantiles::new(Duration::from_secs(60), Duration::from_secs(1), 0.01, 512);
    let b = WindowedQuantiles::new(Duration::from_secs(60), Duration::from_secs(2), 0.01, 512);
    a.merge(b);
}
