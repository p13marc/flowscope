//! Demonstrate the zero-allocation `LayerParser` + `LayerStack`
//! fast path against the ergonomic `Layers::parse_ethernet`.
//!
//! Reads every packet in a pcap and times both modes:
//! - **Ergonomic mode**: `view.layers()` allocates a fresh
//!   `Layers<'a>` per packet (one heap alloc when the inline
//!   SmallVec spills).
//! - **Fast path**: `LayerParser` populates a caller-owned
//!   `LayerStack` reused across the loop — zero per-packet
//!   heap allocation.
//!
//! This is also a small wall-clock benchmark consumers can
//! run on their own captures.
//!
//! ```bash
//! cargo run --release --features pcap,extractors --example layer_fast_path
//! ```

use std::time::Instant;

use flowscope::layers::{LayerKind, LayerParser, LayerStack, Layers};
use flowscope::pcap::PcapFlowSource;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    // Slurp the frames into memory so both runs hit the same data.
    let frames: Vec<Vec<u8>> = PcapFlowSource::open(&path)?
        .views()
        .filter_map(|r| r.ok().map(|v| v.frame))
        .collect();

    println!("loaded {} frames from {}", frames.len(), path);

    // Ergonomic mode.
    let start = Instant::now();
    let mut ergo_tcp = 0usize;
    for f in &frames {
        if let Ok(l) = Layers::parse_ethernet(f)
            && l.tcp().is_some()
        {
            ergo_tcp += 1;
        }
    }
    let ergo = start.elapsed();

    // Fast path — only request the two slots we care about.
    let parser = LayerParser::new().only(&[LayerKind::Ipv4, LayerKind::Tcp]);
    let mut stack = LayerStack::new();
    let start = Instant::now();
    let mut fast_tcp = 0usize;
    for f in &frames {
        stack.reset();
        if parser.parse_ethernet(f, &mut stack).is_ok() && stack.tcp().is_some() {
            fast_tcp += 1;
        }
    }
    let fast = start.elapsed();

    println!();
    println!("Ergonomic Layers::parse_ethernet + .tcp(): {ergo_tcp} hits in {ergo:?}");
    println!("Fast-path LayerParser + .tcp():            {fast_tcp} hits in {fast:?}");
    if fast.as_nanos() > 0 {
        let speedup = ergo.as_secs_f64() / fast.as_secs_f64();
        println!("Speedup: {speedup:.2}× (fewer frames or larger captures show more)");
    }

    assert_eq!(
        ergo_tcp, fast_tcp,
        "both paths should yield identical results"
    );
    Ok(())
}
