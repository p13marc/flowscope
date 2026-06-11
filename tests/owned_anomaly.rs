//! Plan 147 — `OwnedAnomaly` end-to-end: detector score →
//! into_anomaly → write_owned_anomaly on EveJsonWriter +
//! FlowEventNdjsonWriter.
//!
//! Validates the canonical detector → emit flow that netring 0.21
//! adopts as its primary anomaly path.

#![cfg(all(
    feature = "emit-eve",
    feature = "emit-ndjson",
    feature = "extractors",
    feature = "tracker",
))]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use flowscope::detect::patterns::{BeaconDetector, DgaScorer, PortScanDetector};
use flowscope::emit::{EveJsonWriter, FlowEventNdjsonWriter};
use flowscope::event::Severity;
use flowscope::extract::FiveTupleKey;
use flowscope::extractor::L4Proto;
use flowscope::{DetectorScore, OwnedAnomaly, Timestamp};

fn sample_key() -> FiveTupleKey {
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 1), 33000)),
        b: SocketAddr::from((Ipv4Addr::new(10, 0, 0, 2), 80)),
    }
}

#[test]
fn portscan_score_into_anomaly_carries_5tuple_and_metrics() {
    let mut d: PortScanDetector<FiveTupleKey> = PortScanDetector::new();
    let key = sample_key();
    let score = d.observe(key, false);
    assert_eq!(<_ as DetectorScore>::name(&score), "PortScanTRW");

    let anomaly = score.into_anomaly(Timestamp::new(1_700_000_000, 0));
    assert_eq!(anomaly.kind, "PortScanTRW");
    assert_eq!(
        anomaly.src_ip,
        Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert_eq!(anomaly.src_port, Some(33000));
    assert_eq!(anomaly.dest_port, Some(80));
    assert_eq!(anomaly.proto, Some("TCP"));

    // The detector emits a verdict observation + 2 metrics.
    assert!(
        anomaly.observations.iter().any(|(l, _)| *l == "verdict"),
        "verdict observation present"
    );
    assert!(
        anomaly.metrics.iter().any(|(l, _)| *l == "log_likelihood"),
        "log_likelihood metric present"
    );
    assert!(
        anomaly.metrics.iter().any(|(l, _)| *l == "n_observed"),
        "n_observed metric present"
    );
}

#[test]
fn beacon_score_into_anomaly_carries_window_metrics() {
    let mut d: BeaconDetector<FiveTupleKey> =
        BeaconDetector::new().with_window(10).with_interval_range(
            std::time::Duration::from_millis(50),
            std::time::Duration::from_secs(60),
        );
    let key = sample_key();

    // Feed regular observations until the detector emits a score.
    let mut score_opt = None;
    for i in 0..20 {
        let ts = Timestamp::new(1_700_000_000 + i, 0);
        if let Some(s) = d.observe(key, ts, 100) {
            score_opt = Some(s);
            break;
        }
    }
    let score = score_opt.expect("beacon should emit after window fills");
    assert_eq!(<_ as DetectorScore>::name(&score), "BeaconCv");

    let anomaly = score.into_anomaly(Timestamp::new(1_700_000_100, 0));
    assert_eq!(anomaly.kind, "BeaconCv");
    assert_eq!(anomaly.severity, Severity::Warning);
    assert!(anomaly.metrics.iter().any(|(l, _)| *l == "score"));
    assert!(anomaly.metrics.iter().any(|(l, _)| *l == "cv_dt"));
    assert!(
        anomaly
            .metrics
            .iter()
            .any(|(l, _)| *l == "mean_interval_secs")
    );
}

#[test]
fn dga_score_into_anomaly_keyed_inherent_path() {
    let d = DgaScorer::new();
    let score = d.score("xkflpqzvbmqwerty");
    let key = sample_key();
    let anomaly = score.into_anomaly(Timestamp::new(1_700_000_000, 0), Some(&key));
    assert_eq!(anomaly.kind, "DgaScorer");
    assert_eq!(
        anomaly.src_ip,
        Some(IpAddr::from(Ipv4Addr::new(10, 0, 0, 1)))
    );
    assert!(anomaly.metrics.iter().any(|(l, _)| *l == "log_likelihood"));
    assert!(anomaly.metrics.iter().any(|(l, _)| *l == "char_entropy"));
}

#[test]
fn dga_score_via_detectorscore_trait_keyless() {
    let d = DgaScorer::new();
    let score = d.score("github.com");
    let anomaly = <_ as DetectorScore>::into_anomaly(score, Timestamp::new(1_700_000_000, 0));
    assert_eq!(anomaly.kind, "DgaScorer");
    assert!(anomaly.src_ip.is_none(), "DetectorScore impl is keyless");
}

#[test]
fn eve_writer_writes_owned_anomaly_round_trip() {
    let a = OwnedAnomaly::new(
        "PortScanTRW",
        Severity::Warning,
        Timestamp::new(1_700_000_000, 0),
    )
    .with_key(&sample_key())
    .with_observation("verdict", "scanner")
    .with_metric("log_likelihood", 3.7)
    .with_metric("n_observed", 47.0);

    let mut out: Vec<u8> = Vec::new();
    let mut w = EveJsonWriter::new(&mut out);
    w.write_owned_anomaly(&a).expect("write succeeds");

    let line = std::str::from_utf8(&out).unwrap();
    let json: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");

    assert_eq!(json["event_type"], "anomaly");
    assert_eq!(json["src_ip"], "10.0.0.1");
    assert_eq!(json["src_port"], 33000);
    assert_eq!(json["dest_ip"], "10.0.0.2");
    assert_eq!(json["dest_port"], 80);
    assert_eq!(json["proto"], "TCP");
    assert_eq!(json["anomaly"]["event"], "PortScanTRW");
    assert_eq!(json["anomaly"]["type"], "applayer");
    assert_eq!(json["anomaly"]["labels"]["verdict"], "scanner");
    assert_eq!(json["anomaly"]["metrics"]["log_likelihood"], 3.7);
    assert_eq!(json["severity"], 3);
}

#[test]
fn eve_writer_observations_omitted_when_empty() {
    let a = OwnedAnomaly::new("BareKind", Severity::Info, Timestamp::new(0, 0));
    let mut out: Vec<u8> = Vec::new();
    let mut w = EveJsonWriter::new(&mut out);
    w.write_owned_anomaly(&a).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert!(json["anomaly"]["labels"].is_null());
    assert!(json["anomaly"]["metrics"].is_null());
}

#[test]
fn eve_writer_custom_anomaly_type_option_overrides_default() {
    use flowscope::emit::EveOptions;
    let mut options = EveOptions::default();
    options.custom_anomaly_type = "custom-detector";
    let mut out: Vec<u8> = Vec::new();
    let mut w = EveJsonWriter::with_options(&mut out, options);
    let a = OwnedAnomaly::new("Test", Severity::Info, Timestamp::new(0, 0));
    w.write_owned_anomaly(&a).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    assert_eq!(json["anomaly"]["type"], "custom-detector");
}

#[test]
fn eve_writer_flowscope_kind_overrides_custom_anomaly_type() {
    use flowscope::event::{AnomalyKind, FlowSide};
    let kind = AnomalyKind::OutOfOrderSegment {
        side: FlowSide::Initiator,
        count: 1,
    };
    let a = OwnedAnomaly::from_flow_anomaly(&sample_key(), kind, Timestamp::new(0, 0));

    let mut out: Vec<u8> = Vec::new();
    let mut w = EveJsonWriter::new(&mut out);
    w.write_owned_anomaly(&a).unwrap();
    let json: serde_json::Value =
        serde_json::from_str(std::str::from_utf8(&out).unwrap().trim()).unwrap();
    // OOO segment classifies as "stream" via AnomalyFields, overriding the default "applayer".
    assert_eq!(json["anomaly"]["type"], "stream");
    assert_eq!(json["anomaly"]["event"], "ooo_segment");
}

#[test]
fn ndjson_writer_writes_owned_anomaly_emits_valid_json() {
    let a = OwnedAnomaly::new(
        "PortScanTRW",
        Severity::Warning,
        Timestamp::new(1_700_000_000, 0),
    )
    .with_key(&sample_key())
    .with_metric("log_likelihood", 3.7);

    let mut out: Vec<u8> = Vec::new();
    let mut w = FlowEventNdjsonWriter::new(&mut out);
    w.write_owned_anomaly(&a).expect("write succeeds");
    let line = std::str::from_utf8(&out).unwrap();
    let json: serde_json::Value = serde_json::from_str(line.trim()).expect("valid JSON");
    assert_eq!(json["kind"], "PortScanTRW");
    assert_eq!(json["src_ip"], "10.0.0.1");
}

#[test]
fn generic_emit_through_detector_score_trait_compiles_and_routes() {
    // The actual netring-style routing shape: a function generic
    // over `S: DetectorScore` produces an anomaly and writes it
    // through the EVE sink. Validates the trait surface.
    fn emit<S: DetectorScore, W: std::io::Write>(
        sink: &mut EveJsonWriter<W>,
        score: S,
        ts: Timestamp,
    ) -> std::io::Result<()> {
        sink.write_owned_anomaly(&score.into_anomaly(ts))
    }

    let mut out: Vec<u8> = Vec::new();
    let mut w = EveJsonWriter::new(&mut out);
    let mut d: PortScanDetector<FiveTupleKey> = PortScanDetector::new();
    let score = d.observe(sample_key(), false);
    emit(&mut w, score, Timestamp::new(1_700_000_000, 0)).unwrap();
    assert!(!out.is_empty(), "produced output through DetectorScore");
}
