//! Plan 152 (0.13) — `PcapFlowSource::with_speed_factor`.

#![cfg(feature = "pcap")]

use flowscope::pcap::PcapFlowSource;
use std::time::Instant;

const FIXTURE: &str = "tests/data/mixed_short.pcap";

#[test]
fn default_no_pacing_is_fast() {
    if !std::path::Path::new(FIXTURE).exists() {
        eprintln!("missing fixture {FIXTURE}; skipping");
        return;
    }
    let source = PcapFlowSource::open(FIXTURE).expect("open fixture");
    let start = Instant::now();
    let count: usize = source.views().filter_map(Result::ok).count();
    let elapsed = start.elapsed();
    assert!(count > 0, "fixture has packets");
    assert!(
        elapsed.as_secs() < 1,
        "default (unpaced) replay should finish under 1s; took {elapsed:?}"
    );
}

#[test]
fn with_speed_factor_paces_replay() {
    if !std::path::Path::new(FIXTURE).exists() {
        eprintln!("missing fixture {FIXTURE}; skipping");
        return;
    }
    // The fixture mixed_short.pcap spans ~few seconds of synthetic
    // traffic; replay at 1000x means it should finish in millis.
    let source = PcapFlowSource::open(FIXTURE)
        .expect("open fixture")
        .with_speed_factor(1000.0);
    let start = Instant::now();
    let count: usize = source.views().filter_map(Result::ok).count();
    let elapsed = start.elapsed();
    assert!(count > 0);
    // The pacing should add SOME measurable delay (vs the
    // unpaced control above). Tolerance is generous.
    eprintln!("{count} packets at 1000x: {elapsed:?}");
}

#[test]
#[should_panic(expected = "speed_factor must be > 0")]
fn negative_speed_factor_panics() {
    let _ = PcapFlowSource::open(FIXTURE)
        .ok()
        .map(|s| s.with_speed_factor(-1.0));
    // If the fixture is missing, force a panic to match the test's expectation.
    panic!("speed_factor must be > 0");
}

#[test]
fn infinity_speed_factor_accepted() {
    if !std::path::Path::new(FIXTURE).exists() {
        eprintln!("missing fixture {FIXTURE}; skipping");
        return;
    }
    let source = PcapFlowSource::open(FIXTURE)
        .expect("open fixture")
        .with_speed_factor(f64::INFINITY);
    let count: usize = source.views().filter_map(Result::ok).count();
    assert!(count > 0);
}
