//! Verify the "0.000 allocs/packet in steady state" claim.
//!
//! Wraps `std::alloc::System` with a counting allocator,
//! warms up a [`Driver`]-based pipeline, then measures the
//! incremental allocation count over a hot loop. Prints
//! the warmup → steady-state delta.
//!
//! ## How the claim holds
//!
//! Plan 119 (0.11.0) moved `Driver<E>` to a typed-slot drain
//! shape that avoids per-packet `Vec::new()`. Plan 122 (0.12.0)
//! moved `SlotHandle` to a lock-free
//! `Arc<crossbeam_queue::SegQueue>` for cross-thread fan-out.
//! Together they make the **bare driver** steady-state path
//! zero-allocation once the reassembly / hashmap structures
//! are sized.
//!
//! L7 parsers (HTTP / TLS / DNS) intentionally allocate per
//! message — they Arc-clone shared `Bytes` slices into the
//! emitted typed messages so the parser-side owns them past
//! the borrow window. So the "0 allocs/packet" applies to
//! pure tracker / driver throughput, not to a full
//! HTTP-parsed pipeline.
//!
//! See `docs/performance.md` and `benches/extractor.rs` for
//! the criterion-gated numbers (`bench_extract_*` is the
//! one-extractor steady-state measurement).
//!
//! ## Important
//!
//! Run with `--release` — debug builds allocate (and spuriously
//! grow Vec capacities) in ways that obscure the real shape.
//!
//! ```bash
//! cargo run --release \
//!     --features "pcap,extractors,tracker" \
//!     --example allocations_per_packet -- trace.pcap
//! ```
//!
//! Closes #60.

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicU64, Ordering::Relaxed};

use flowscope::driver::{Driver, Event};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::pcap::PcapFlowSource;

struct Counting;

static ALLOCS: AtomicU64 = AtomicU64::new(0);
static BYTES: AtomicU64 = AtomicU64::new(0);

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size() as u64, Relaxed);
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static A: Counting = Counting;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/http_session.pcap".to_string());

    // Bare driver — no L7 parser. L7 parsers Arc-clone Bytes
    // into emitted typed messages; that's by design and would
    // muddle the "tracker steady-state" number.
    let builder = Driver::builder(FiveTuple::bidirectional());
    let mut driver = builder.build();

    let mut events: Vec<Event<FiveTupleKey>> = Vec::with_capacity(64);

    // Load the entire pcap into memory so the I/O path isn't
    // in the measurement window.
    let frames: Vec<_> = PcapFlowSource::open(&path)?
        .views()
        .collect::<Result<Vec<_>, _>>()?;
    println!("loaded {} packet(s) from {path}", frames.len());

    // Warmup — let HashMap / SegQueue / reassembler buffers
    // grow to their steady-state sizes.
    for view in &frames {
        events.clear();
        driver.track_into(view, &mut events);
    }
    let warmup_allocs = ALLOCS.load(Relaxed);
    let warmup_bytes = BYTES.load(Relaxed);
    println!("warmup:      {warmup_allocs:>10} allocs  {warmup_bytes:>12} bytes");

    // Hot loop — same packets, repeated 100x. Steady-state.
    let iters = 100;
    let pre_allocs = ALLOCS.load(Relaxed);
    let pre_bytes = BYTES.load(Relaxed);
    for _ in 0..iters {
        for view in &frames {
            events.clear();
            driver.track_into(view, &mut events);
        }
    }
    let post_allocs = ALLOCS.load(Relaxed);
    let post_bytes = BYTES.load(Relaxed);

    let delta_allocs = post_allocs - pre_allocs;
    let delta_bytes = post_bytes - pre_bytes;
    let total_packets = (frames.len() * iters) as u64;

    println!(
        "hot loop:    {delta_allocs:>10} allocs  {delta_bytes:>12} bytes  ({total_packets} packets)"
    );
    println!();
    println!(
        "===> allocs/packet (steady-state): {:.4}",
        delta_allocs as f64 / total_packets as f64
    );
    println!(
        "===> bytes /packet (steady-state): {:.2}",
        delta_bytes as f64 / total_packets as f64
    );
    Ok(())
}
