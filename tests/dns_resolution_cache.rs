//! Plan 85 — DnsResolutionCache covering observe / lookup /
//! sweep / TTL / LRU / multi-client isolation.

#![cfg(feature = "dns")]

use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use flowscope::{
    dns::{DnsFlags, DnsRcode, DnsRdata, DnsRecord, DnsResolutionCache, DnsResponse},
    Timestamp,
};

fn ts(sec: u32) -> Timestamp {
    Timestamp::new(sec, 0)
}

fn flags() -> DnsFlags {
    // 0x8180 = response + RD + RA — standard response. Values
    // aren't load-bearing for the cache.
    DnsFlags(0x8180)
}

fn record_a(name: &str, ip: Ipv4Addr) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        rtype: 1,
        rclass: 1,
        ttl: 300,
        data: DnsRdata::A(ip),
    }
}

fn record_aaaa(name: &str, ip: Ipv6Addr) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        rtype: 28,
        rclass: 1,
        ttl: 300,
        data: DnsRdata::AAAA(ip),
    }
}

fn record_cname(name: &str, target: &str) -> DnsRecord {
    DnsRecord {
        name: name.to_string(),
        rtype: 5,
        rclass: 1,
        ttl: 300,
        data: DnsRdata::CNAME(target.to_string()),
    }
}

fn response_with(question_name: &str, answers: Vec<DnsRecord>) -> DnsResponse {
    DnsResponse {
        transaction_id: 1,
        flags: flags(),
        questions: vec![flowscope::dns::DnsQuestion {
            name: question_name.to_string(),
            qtype: 1,
            qclass: 1,
        }],
        answers,
        authorities: vec![],
        additionals: vec![],
        rcode: DnsRcode::NoError,
        timestamp: ts(0),
        elapsed: None,
    }
}

#[test]
fn observes_a_record() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Addr::new(93, 184, 216, 34);
    let resp = response_with("example.com", vec![record_a("example.com", target)]);
    cache.observe_response(client, &resp, ts(0));
    assert!(cache.was_resolved(client, IpAddr::V4(target), ts(0)));
    assert_eq!(
        cache.lookup_name(client, IpAddr::V4(target), ts(0)),
        Some("example.com")
    );
}

#[test]
fn observes_aaaa_record() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv6Addr::new(0x2606, 0x4700, 0x4700, 0, 0, 0, 0, 0x1111);
    let resp = response_with(
        "cloudflare.com",
        vec![record_aaaa("cloudflare.com", target)],
    );
    cache.observe_response(client, &resp, ts(0));
    assert!(cache.was_resolved(client, IpAddr::V6(target), ts(0)));
}

#[test]
fn skips_cname_only_response() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Addr::new(1, 2, 3, 4);
    let resp = response_with("foo.com", vec![record_cname("foo.com", "bar.com")]);
    cache.observe_response(client, &resp, ts(0));
    assert!(!cache.was_resolved(client, IpAddr::V4(target), ts(0)));
    assert_eq!(cache.len(), 0);
}

#[test]
fn expired_lookups_return_none() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(60));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Addr::new(1, 2, 3, 4);
    let resp = response_with("foo.com", vec![record_a("foo.com", target)]);
    cache.observe_response(client, &resp, ts(0));
    // Within TTL
    assert!(cache.was_resolved(client, IpAddr::V4(target), ts(30)));
    // Past TTL
    assert!(!cache.was_resolved(client, IpAddr::V4(target), ts(120)));
}

#[test]
fn sweep_removes_expired() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(60));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let resp = response_with(
        "foo.com",
        vec![
            record_a("foo.com", Ipv4Addr::new(1, 1, 1, 1)),
            record_a("foo.com", Ipv4Addr::new(2, 2, 2, 2)),
        ],
    );
    cache.observe_response(client, &resp, ts(0));
    assert_eq!(cache.len(), 2);
    let removed = cache.sweep(ts(120));
    assert_eq!(removed, 2);
    assert_eq!(cache.len(), 0);
}

#[test]
fn lru_eviction_at_capacity() {
    let mut cache = DnsResolutionCache::with_capacity(Duration::from_secs(300), 2);
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let r1 = response_with("a.com", vec![record_a("a.com", Ipv4Addr::new(1, 0, 0, 0))]);
    let r2 = response_with("b.com", vec![record_a("b.com", Ipv4Addr::new(2, 0, 0, 0))]);
    let r3 = response_with("c.com", vec![record_a("c.com", Ipv4Addr::new(3, 0, 0, 0))]);
    cache.observe_response(client, &r1, ts(0));
    cache.observe_response(client, &r2, ts(1));
    cache.observe_response(client, &r3, ts(2));
    // Capacity 2 — `a.com` should have been evicted (LRU).
    assert_eq!(cache.len(), 2);
    assert!(!cache.was_resolved(client, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)), ts(2)));
    assert!(cache.was_resolved(client, IpAddr::V4(Ipv4Addr::new(2, 0, 0, 0)), ts(2)));
    assert!(cache.was_resolved(client, IpAddr::V4(Ipv4Addr::new(3, 0, 0, 0)), ts(2)));
}

#[test]
fn multiple_clients_isolated() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
    let alice = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let bob = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
    let target = Ipv4Addr::new(1, 2, 3, 4);
    let resp = response_with("foo.com", vec![record_a("foo.com", target)]);
    cache.observe_response(alice, &resp, ts(0));
    assert!(cache.was_resolved(alice, IpAddr::V4(target), ts(0)));
    // Bob never resolved; cache doesn't bleed.
    assert!(!cache.was_resolved(bob, IpAddr::V4(target), ts(0)));
}

#[test]
fn case_insensitive_canonical_name() {
    let mut cache = DnsResolutionCache::new(Duration::from_secs(300));
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Addr::new(1, 2, 3, 4);
    let resp = response_with("Foo.COM", vec![record_a("Foo.COM", target)]);
    cache.observe_response(client, &resp, ts(0));
    // Stored as lowercase per RFC 1035.
    assert_eq!(
        cache.lookup_name(client, IpAddr::V4(target), ts(0)),
        Some("foo.com")
    );
}

#[test]
fn peek_does_not_promote() {
    let mut cache = DnsResolutionCache::with_capacity(Duration::from_secs(300), 2);
    let client = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
    let r1 = response_with("a.com", vec![record_a("a.com", Ipv4Addr::new(1, 0, 0, 0))]);
    let r2 = response_with("b.com", vec![record_a("b.com", Ipv4Addr::new(2, 0, 0, 0))]);
    cache.observe_response(client, &r1, ts(0));
    cache.observe_response(client, &r2, ts(1));
    // Peek a.com — does not promote.
    let _ = cache.peek_name(client, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)), ts(2));
    // Add c.com — should evict a.com (still LRU since peek didn't
    // promote it).
    let r3 = response_with("c.com", vec![record_a("c.com", Ipv4Addr::new(3, 0, 0, 0))]);
    cache.observe_response(client, &r3, ts(3));
    assert!(!cache.was_resolved(client, IpAddr::V4(Ipv4Addr::new(1, 0, 0, 0)), ts(3)));
}
