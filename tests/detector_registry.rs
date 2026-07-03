//! Issue #131 — unified `Detector` trait + `DetectorRegistry`.
//!
//! Covers the event→hook fan-out mapping, the shipped detector
//! impls (beacon threshold + cooldown gating, port-scan
//! success/failure derivation from flow records, DGA
//! suppression), eviction fan-out, and the Send guarantee.

#![cfg(all(feature = "tracker", feature = "extractors"))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use flowscope::{
    Detector, DetectorKind, DetectorRegistry, FlowEvent, HistoryString, OwnedAnomaly, Timestamp,
    detect::patterns::{BeaconDetector, PortScanDetector},
    detect::{DgaDetector, HostPair, SrcHost},
    event::{EndReason, FlowStats},
    extract::FiveTupleKey,
    extractor::L4Proto,
};

fn key(src: [u8; 4], sport: u16, dst: [u8; 4], dport: u16) -> FiveTupleKey {
    FiveTupleKey::new(
        L4Proto::Tcp,
        SocketAddr::from((Ipv4Addr::from(src), sport)),
        SocketAddr::from((Ipv4Addr::from(dst), dport)),
    )
}

/// A finished-flow event with the fields detectors read.
fn ended(
    key: FiveTupleKey,
    last_seen: Timestamp,
    bytes_initiator: u64,
    history: &str,
    responder_packets: u64,
) -> FlowEvent<FiveTupleKey> {
    let mut stats = FlowStats::default();
    stats.last_seen = last_seen;
    stats.bytes_initiator = bytes_initiator;
    stats.packets_responder = responder_packets;
    let mut h = HistoryString::new();
    h.push_str(history);
    FlowEvent::Ended {
        key,
        reason: EndReason::Fin,
        stats,
        history: h,
        l4: Some(L4Proto::Tcp),
    }
}

// ─── fan-out mapping ─────────────────────────────────────────────

/// Probe detector counting which hooks fire.
#[derive(Default)]
struct Probe {
    starts: usize,
    established: usize,
    ends: usize,
    ticks: usize,
    dns: usize,
}

// A probe wrapper so the registry (which owns its detectors) can
// still be inspected: the probe writes into a shared cell.
struct SharedProbe(std::sync::Arc<std::sync::Mutex<Probe>>);

impl<K> Detector<K> for SharedProbe {
    fn kind(&self) -> DetectorKind {
        DetectorKind::Other("test/probe")
    }
    fn on_flow_start(&mut self, _k: &K, _ts: Timestamp, _out: &mut Vec<OwnedAnomaly>) {
        self.0.lock().unwrap().starts += 1;
    }
    fn on_flow_established(&mut self, _k: &K, _ts: Timestamp, _out: &mut Vec<OwnedAnomaly>) {
        self.0.lock().unwrap().established += 1;
    }
    fn on_flow_end(
        &mut self,
        _k: &K,
        _stats: &FlowStats,
        _history: &HistoryString,
        _l4: Option<L4Proto>,
        _ts: Timestamp,
        _out: &mut Vec<OwnedAnomaly>,
    ) {
        self.0.lock().unwrap().ends += 1;
    }
    fn on_flow_tick(
        &mut self,
        _k: &K,
        _stats: &FlowStats,
        _ts: Timestamp,
        _out: &mut Vec<OwnedAnomaly>,
    ) {
        self.0.lock().unwrap().ticks += 1;
    }
    fn on_dns_query(&mut self, _k: &K, _q: &str, _ts: Timestamp, _out: &mut Vec<OwnedAnomaly>) {
        self.0.lock().unwrap().dns += 1;
    }
}

#[test]
fn registry_fans_events_to_the_right_hooks() {
    let cell = std::sync::Arc::new(std::sync::Mutex::new(Probe::default()));
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(SharedProbe(cell.clone()));

    let k = key([10, 0, 0, 1], 40000, [10, 0, 0, 2], 80);
    let ts = Timestamp::new(1, 0);
    let mut out = Vec::new();

    reg.observe(&flowscope::test_helpers::events::started(k, ts), &mut out);
    reg.observe(&ended(k, ts, 100, "SsD", 1), &mut out);
    reg.observe(
        &FlowEvent::Tick {
            key: k,
            stats: FlowStats::default(),
            ts,
        },
        &mut out,
    );
    reg.observe_dns(&k, "example.com", ts, &mut out);

    let p = cell.lock().unwrap();
    assert_eq!(
        (p.starts, p.established, p.ends, p.ticks, p.dns),
        (1, 0, 1, 1, 1)
    );
    drop(p);
    assert_eq!(reg.len(), 1);
    assert_eq!(
        reg.kinds().collect::<Vec<_>>(),
        vec![DetectorKind::Other("test/probe")]
    );
}

// ─── beacon: threshold + cooldown gating ─────────────────────────

#[test]
fn beacon_emits_at_threshold_with_cooldown_dedup() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(
        BeaconDetector::<HostPair>::new()
            .with_window(20)
            .with_anomaly_threshold(0.7)
            .with_cooldown(Duration::from_secs(300)),
    );

    let mut out = Vec::new();
    // 20 flows, perfect 60 s cadence, same (src, dst, port) pair —
    // each flow has a different ephemeral source port, which is
    // exactly why the detector keys on HostPair not the flow key.
    for i in 0..20u32 {
        let k = key([10, 0, 0, 1], 40000 + i as u16, [203, 0, 113, 7], 443);
        reg.observe(
            &ended(k, Timestamp::new(i * 60, 0), 4096, "SsD", 3),
            &mut out,
        );
    }

    // Score threshold reached at n=10 (t=540); cooldown 300 s at a
    // 60 s cadence → re-emissions at t=840 and t=1140. Exactly 3.
    assert_eq!(out.len(), 3, "threshold + cooldown gating");
    assert!(out.iter().all(|a| a.kind == DetectorKind::BeaconCv));
    assert_eq!(
        out[0].src_ip,
        Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(
        out[0].dest_ip,
        Some(IpAddr::from(Ipv4Addr::new(203, 0, 113, 7)))
    );
    assert_eq!(out[0].dest_port, Some(443));
    assert!(reg.tracked() >= 1, "beacon holds per-pair state");
}

// ─── port scan: success derivation from the flow record ─────────

#[test]
fn portscan_flags_unanswered_and_rst_flows() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(PortScanDetector::<SrcHost>::new());

    let mut out = Vec::new();
    // One source sweeping many targets; every attempt refused
    // (RST → 'Sr') or unanswered ('S'). TRW needs ~4 failures.
    for i in 0..8u8 {
        let k = key([10, 0, 0, 9], 40000, [192, 168, 1, i], 445);
        let history = if i % 2 == 0 { "S" } else { "Sr" };
        reg.observe(
            &ended(k, Timestamp::new(i as u32, 0), 60, history, 0),
            &mut out,
        );
    }
    assert!(!out.is_empty(), "scanner verdict emitted");
    assert!(out.iter().all(|a| a.kind == DetectorKind::PortScanTrw));
    assert_eq!(
        out[0].src_ip,
        Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 9))),
        "anomaly keyed by scanning source"
    );
}

#[test]
fn portscan_stays_silent_on_successful_flows() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(PortScanDetector::<SrcHost>::new());

    let mut out = Vec::new();
    // Completed handshakes ('Ss…') — benign browsing pattern.
    for i in 0..12u8 {
        let k = key([10, 0, 0, 5], 40000 + i as u16, [203, 0, 113, i], 443);
        reg.observe(
            &ended(k, Timestamp::new(i as u32, 0), 900, "SsDdFf", 4),
            &mut out,
        );
    }
    assert!(out.is_empty(), "no scanner anomaly for successful flows");
}

// ─── DGA via registry DNS feed ───────────────────────────────────

#[test]
fn dga_via_observe_dns_with_suppression() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(DgaDetector::new());

    let k = key([10, 0, 0, 1], 40000, [8, 8, 8, 8], 53);
    let mut out = Vec::new();
    reg.observe_dns(&k, "kq3v9z7xj2wq.com", Timestamp::new(0, 0), &mut out);
    reg.observe_dns(&k, "kq3v9z7xj2wq.com", Timestamp::new(1, 0), &mut out);
    reg.observe_dns(&k, "www.google.com", Timestamp::new(2, 0), &mut out);
    assert_eq!(out.len(), 1, "one alert per (src, domain)");
    assert_eq!(out[0].kind, DetectorKind::Dga);
    assert!(
        out[0]
            .observations
            .iter()
            .any(|(l, v)| *l == "qname" && v == "kq3v9z7xj2wq.com"),
        "qname observation carried"
    );
}

// ─── eviction fan-out + Send ─────────────────────────────────────

#[test]
fn evict_expired_fans_out_and_bounds_tracked() {
    let mut reg: DetectorRegistry<FiveTupleKey> = DetectorRegistry::new();
    reg.register(BeaconDetector::<HostPair>::new());

    let mut out = Vec::new();
    let k = key([10, 0, 0, 1], 40000, [203, 0, 113, 7], 443);
    reg.observe(&ended(k, Timestamp::new(0, 0), 100, "SsD", 1), &mut out);
    assert_eq!(reg.tracked(), 1);
    // Two days later: the pair's window is stale and reclaimed.
    reg.evict_expired(Timestamp::new(2 * 24 * 3600, 0));
    assert_eq!(reg.tracked(), 0);
}

#[test]
fn registry_is_send() {
    static_assertions::assert_impl_all!(DetectorRegistry<FiveTupleKey>: Send);
    static_assertions::assert_impl_all!(DetectorRegistry<SrcHost>: Send);
}
