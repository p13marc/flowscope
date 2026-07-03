//! Issue #132 — the four upstreamed NDR detectors, driven both
//! directly and through a `DetectorRegistry`.
//!
//! DnsTunnelDetector / NewlyObservedDomainDetector /
//! ConnectionFloodDetector / DataExfilDetector: positive fire,
//! negative quiet, kind + ATT&CK-technique pins, and registry
//! fan-out.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::detect::patterns::{
    ConnectionFloodDetector, DataExfilDetector, DnsTunnelDetector, NewlyObservedDomainDetector,
};
use flowscope::detect::{DetectorRegistry, HostPair, SrcHost};
use flowscope::event::{EndReason, FlowStats, Severity};
use flowscope::extract::FiveTupleKey;
use flowscope::extractor::L4Proto;
use flowscope::history::HistoryString;
use flowscope::{DetectorKind, DetectorScore, FlowEvent, OwnedAnomaly, Timestamp};

fn ip(last: u8) -> IpAddr {
    IpAddr::from(Ipv4Addr::new(10, 0, 0, last))
}

fn t(secs: u32) -> Timestamp {
    Timestamp::new(secs, 0)
}

fn key(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> FiveTupleKey {
    FiveTupleKey::new(
        L4Proto::Tcp,
        SocketAddr::from((Ipv4Addr::from(src), sport)),
        SocketAddr::from((Ipv4Addr::from(dst), dport)),
    )
}

// ─── DNS tunnel ──────────────────────────────────────────────────

#[test]
fn dns_tunnel_kind_and_technique() {
    let mut d = DnsTunnelDetector::new().with_subdomain_threshold(30);
    let mut fired = None;
    for i in 0..40u32 {
        let q = format!("{i:0>54}.tunnel.example");
        if let Some(s) = d.observe(ip(1), &q, t(i)) {
            fired = Some(s);
            break;
        }
    }
    let score = fired.expect("tunnel threshold crossed");
    assert_eq!(score.kind(), DetectorKind::DnsTunnel);
    assert_eq!(
        DetectorKind::DnsTunnel.attack_technique(),
        Some("T1071.004")
    );
    let a = score.into_anomaly(t(100));
    assert_eq!(a.kind, DetectorKind::DnsTunnel);
    assert_eq!(a.severity, Severity::Warning);
}

// ─── newly-observed domain ───────────────────────────────────────

#[test]
fn nod_kind_and_technique() {
    let mut d = NewlyObservedDomainDetector::new().with_warmup(Duration::from_secs(0));
    let s = d
        .observe(Some(ip(1)), "evil.example", t(0))
        .expect("NOD hit");
    assert_eq!(s.kind(), DetectorKind::NewlyObservedDomain);
    assert_eq!(
        DetectorKind::NewlyObservedDomain.attack_technique(),
        Some("T1568")
    );
    // Info severity — NOD is a context signal.
    assert_eq!(s.into_anomaly(t(0)).severity, Severity::Info);
    // Second sight is quiet.
    assert!(d.observe(Some(ip(1)), "evil.example", t(1)).is_none());
}

// ─── connection flood ────────────────────────────────────────────

#[test]
fn conn_flood_kind_and_technique() {
    let mut d =
        ConnectionFloodDetector::with_params(Duration::from_secs(10), Duration::from_secs(1), 50);
    let mut fired = None;
    for i in 0..80 {
        if let Some(s) = d.observe(ip(9), Timestamp::new(0, i)) {
            fired = Some(s);
            break;
        }
    }
    let s = fired.expect("flood threshold crossed");
    assert_eq!(s.kind(), DetectorKind::ConnectionFlood);
    assert_eq!(
        DetectorKind::ConnectionFlood.attack_technique(),
        Some("T1498")
    );
}

// ─── data exfil ──────────────────────────────────────────────────

#[test]
fn data_exfil_kind_and_technique() {
    let mut d = DataExfilDetector::new()
        .with_min_samples(10)
        .with_min_bytes(1_000_000);
    for i in 0..15u32 {
        d.observe(ip(3), 2_000_000 + (i as u64 % 2) * 10_000, t(i));
    }
    let s = d.observe(ip(3), 80_000_000, t(100)).expect("exfil fires");
    assert_eq!(s.kind(), DetectorKind::DataExfil);
    assert_eq!(DetectorKind::DataExfil.attack_technique(), Some("T1048"));
}

// ─── registry fan-out ────────────────────────────────────────────

fn ended(k: FiveTupleKey, ts: Timestamp, bytes_initiator: u64) -> FlowEvent<FiveTupleKey> {
    let mut stats = FlowStats::default();
    stats.last_seen = ts;
    stats.bytes_initiator = bytes_initiator;
    let mut h = HistoryString::new();
    h.push_str("SsDdFf");
    FlowEvent::Ended {
        key: k,
        reason: EndReason::Fin,
        stats,
        history: h,
        l4: Some(L4Proto::Tcp),
    }
}

fn started(k: FiveTupleKey, ts: Timestamp) -> FlowEvent<FiveTupleKey> {
    flowscope::test_helpers::events::started(k, ts)
}

#[test]
fn registry_drives_flood_and_exfil_and_dns() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(ConnectionFloodDetector::with_params(
        Duration::from_secs(10),
        Duration::from_secs(1),
        50,
    ))
    .register(
        DataExfilDetector::new()
            .with_min_samples(5)
            .with_min_bytes(1_000_000),
    )
    .register(DnsTunnelDetector::new().with_subdomain_threshold(20));

    let mut out: Vec<OwnedAnomaly> = Vec::new();

    // Flood: 80 starts from one source in <1 s.
    for i in 0..80 {
        let k = key(
            [10, 0, 0, 9],
            40000 + (i % 20) as u16,
            [203, 0, 113, 1],
            443,
        );
        reg.observe(&started(k, Timestamp::new(0, i)), &mut out);
    }
    assert!(
        out.iter().any(|a| a.kind == DetectorKind::ConnectionFlood),
        "flood fired via registry"
    );

    // Exfil: warm a baseline (with realistic jitter — a
    // zero-variance baseline can't yield a z-score) then spike.
    out.clear();
    for i in 0..8u32 {
        let k = key([10, 0, 0, 5], 5000, [203, 0, 113, 2], 443);
        let bytes = 2_000_000 + (i as u64 % 3) * 25_000;
        reg.observe(&ended(k, t(i), bytes), &mut out);
    }
    let k = key([10, 0, 0, 5], 5000, [203, 0, 113, 2], 443);
    reg.observe(&ended(k, t(50), 90_000_000), &mut out);
    assert!(
        out.iter().any(|a| a.kind == DetectorKind::DataExfil),
        "exfil fired via registry"
    );

    // DNS tunnel via observe_dns.
    out.clear();
    let dk = key([10, 0, 0, 7], 5000, [8, 8, 8, 8], 53);
    for i in 0..30u32 {
        let q = format!("{i:0>54}.tunnel.example");
        reg.observe_dns(&dk, &q, t(i), &mut out);
    }
    assert!(
        out.iter().any(|a| a.kind == DetectorKind::DnsTunnel),
        "dns tunnel fired via registry"
    );
}

#[test]
fn quiet_traffic_produces_no_anomalies() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(ConnectionFloodDetector::with_params(
        Duration::from_secs(10),
        Duration::from_secs(1),
        100,
    ))
    .register(
        DataExfilDetector::new()
            .with_min_samples(10)
            .with_min_bytes(1_000_000),
    );

    let mut out: Vec<OwnedAnomaly> = Vec::new();
    // A dozen benign flows, one per second, modest volume.
    for i in 0..12 {
        let k = key([10, 0, 0, 5], 40000 + i as u16, [203, 0, 113, i as u8], 443);
        reg.observe(&started(k, t(i as u32)), &mut out);
        reg.observe(&ended(k, t(i as u32), 50_000), &mut out);
    }
    assert!(out.is_empty(), "no anomalies on benign traffic: {out:?}");
}

#[test]
fn key_helpers_derive_from_flow_key() {
    let k = key([10, 0, 0, 1], 40000, [203, 0, 113, 7], 443);
    let host = SrcHost::from_key(&k).expect("src host");
    assert_eq!(host.0, ip(1));
    let pair = HostPair::from_key(&k).expect("host pair");
    assert_eq!(pair.dst_port, Some(443));
}
