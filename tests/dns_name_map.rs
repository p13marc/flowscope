//! Issue #130 — `dns::NameMap` public-surface acceptance tests,
//! exercised from *outside* the crate (proves the
//! `#[non_exhaustive]` types are usable via their constructors /
//! builders).

#![cfg(feature = "dns")]

use std::net::{IpAddr, Ipv4Addr};
use std::time::Duration;

use flowscope::Timestamp;
use flowscope::dns::{
    DnsFlags, DnsQuestion, DnsRcode, DnsRdata, DnsRecord, DnsResponse, NameClaim, NameMap,
    NameMapConfig, Provenance,
};

fn ts(secs: u32) -> Timestamp {
    Timestamp::new(secs, 0)
}

fn response(qname: &str, answers: Vec<DnsRecord>) -> DnsResponse {
    DnsResponse::new(
        1,
        DnsFlags(0x8180),
        vec![DnsQuestion::new(qname, 1, 1)],
        answers,
        vec![],
        vec![],
        DnsRcode::NoError,
        ts(0),
        None,
    )
}

#[test]
fn full_acceptance_scenario() {
    let mut m = NameMap::with_config(NameMapConfig::default());
    let client = IpAddr::from(Ipv4Addr::new(10, 0, 0, 1));
    let target = Ipv4Addr::new(93, 184, 216, 34);
    let ip = IpAddr::V4(target);

    // (1) DNS A answer → forward claim under the queried name.
    m.observe_response(
        client,
        &response(
            "example.com",
            vec![DnsRecord::new(
                "example.com",
                1,
                1,
                300,
                DnsRdata::A(target),
            )],
        ),
        ts(0),
    );

    // (2) A second, distinct-provenance name coexists.
    m.observe_claim(
        ip,
        NameClaim::new("cdn.example.net", Provenance::Sni, ts(1)).with_client(client),
    );

    let names = m.names(ip, ts(2));
    assert_eq!(names.len(), 2, "plural provenance coexists");

    // (3) drain_new yields the two new mappings exactly once.
    let drained = m.drain_new();
    assert_eq!(drained.len(), 2);
    assert!(m.drain_new().is_empty(), "exactly once");

    // (4) client-scoped lookup with global fallback.
    let for_client: Vec<_> = m
        .names_for_client(client, ip, ts(2))
        .map(|c| c.name.clone())
        .collect();
    assert!(for_client.contains(&"example.com".to_string()));

    // (5) answer-TTL-driven expiry. Both claims (A TTL 300, SNI
    // default TTL 300; + 60 s grace) are live at ts(200)…
    assert_eq!(
        m.names(ip, ts(200)).len(),
        2,
        "claims live within TTL+grace"
    );
    // …and swept once well past it.
    let removed = m.sweep(ts(100_000));
    assert!(removed >= 1);
    assert_eq!(m.names(ip, ts(100_000)).len(), 0);
}

#[test]
fn ptr_reverse_claim() {
    let mut m = NameMap::new();
    m.observe_response(
        IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)),
        &response(
            "4.3.2.1.in-addr.arpa",
            vec![DnsRecord::new(
                "4.3.2.1.in-addr.arpa",
                12,
                1,
                300,
                DnsRdata::PTR("host.example".into()),
            )],
        ),
        ts(0),
    );
    let ip = IpAddr::from(Ipv4Addr::new(1, 2, 3, 4));
    let names = m.names(ip, ts(1));
    assert_eq!(names.len(), 1);
    assert_eq!(names[0].name, "host.example");
    assert_eq!(names[0].provenance, Provenance::DnsPtr);
}

#[test]
fn cdn_heavy_bounded_memory() {
    let mut cfg = NameMapConfig::default();
    cfg.max_ips = 128;
    cfg.max_claims_per_ip = 4;
    cfg.max_pending = 256;
    cfg.default_ttl = Duration::from_secs(60);
    cfg.grace = Duration::from_secs(30);
    let mut m = NameMap::with_config(cfg);
    for i in 0..2000u32 {
        let ip = IpAddr::from(Ipv4Addr::from(i.to_be_bytes()));
        for j in 0..8 {
            m.observe_claim(
                ip,
                NameClaim::new(format!("n{j}.cdn.example"), Provenance::Other, ts(i)),
            );
        }
    }
    assert!(m.len() <= 128, "IP cap holds under CDN churn");
}
