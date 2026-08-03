//! The HTTP/2 frame loop must not copy the buffer per frame (#200).
//!
//! This is a performance property, so it needs a mechanical check
//! rather than a timing one. The observable is **allocation volume**:
//! parsing N frames out of one buffer should allocate a small
//! multiple of that buffer, not a copy of the remainder per frame.
//!
//! Before the fix, `drive_inner` did `buf.clone().freeze()` on every
//! iteration. `BytesMut::clone` is a deep copy, so draining N frames
//! copied O(N × buffer) bytes — and each frame's payload events
//! pointed into their own full-size copy, so retaining one small
//! `Body` event pinned a whole copy of the remaining buffer.
//!
//! A counting allocator is the only way to see that from outside, and
//! a `#[global_allocator]` is per-test-binary, so it lives in its own
//! file. The counter is global, so the measurements are taken under a
//! lock and reported from a single test — running them as two
//! `#[test]`s lets cargo interleave them on separate threads and each
//! then sees the other's allocations.

#![cfg(feature = "http2")]

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http2::{Http2Event, Http2Parser, PREFACE};

/// Counts bytes handed out by the allocator while armed.
struct Counting;

static ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static ARMED: AtomicBool = AtomicBool::new(false);
static MEASURING: Mutex<()> = Mutex::new(());

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            ALLOCATED.fetch_add(layout.size(), Ordering::Relaxed);
        }
        unsafe { System.alloc(layout) }
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        if ARMED.load(Ordering::Relaxed) {
            // Only the growth is new memory.
            ALLOCATED.fetch_add(new_size.saturating_sub(layout.size()), Ordering::Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

#[global_allocator]
static A: Counting = Counting;

/// Run `f` with the allocator counting, and return the bytes it
/// allocated. Serialised, since the counter is process-wide.
fn measure<T>(f: impl FnOnce() -> T) -> (T, usize) {
    let _guard = MEASURING.lock().unwrap_or_else(|e| e.into_inner());
    ALLOCATED.store(0, Ordering::Relaxed);
    ARMED.store(true, Ordering::Relaxed);
    let out = f();
    ARMED.store(false, Ordering::Relaxed);
    (out, ALLOCATED.load(Ordering::Relaxed))
}

fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
    let mut v = Vec::new();
    let len = payload.len() as u32;
    v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
    v.push(kind);
    v.push(flags);
    v.extend_from_slice(&stream.to_be_bytes());
    v.extend_from_slice(payload);
    v
}

/// One HEADERS to open the stream, then `n` DATA frames. DATA
/// payloads are pure `Bytes` views, so anything allocated beyond the
/// input is the parser's own doing.
fn stream_of(n: usize, payload: usize) -> Vec<u8> {
    let mut wire = frame(0x1, 0x4, 1, &[0x82]);
    let chunk = vec![b'x'; payload];
    for _ in 0..n {
        wire.extend(frame(0x0, 0, 1, &chunk));
    }
    wire
}

#[test]
fn parsing_allocates_in_proportion_to_the_input_not_the_frame_count() {
    // The property, stated so it does not depend on a magic constant:
    // hold the *total bytes* fixed and vary only how many frames they
    // are split into. Allocation must stay flat. With a per-frame
    // buffer copy it grows with the frame count — quadratically, since
    // each copy is of everything still buffered.
    const TOTAL: usize = 128 * 1024;

    let mut measurements = Vec::new();
    for payload in [8192usize, 1024, 128] {
        let frames = TOTAL / payload;
        let wire = stream_of(frames, payload);
        let input_len = wire.len();

        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        let data = Bytes::from(wire);

        let (bodies, allocated) = measure(|| {
            p.push(FlowSide::Initiator, &data);
            let mut n = 0usize;
            while let Some(ev) = p.next_event() {
                if matches!(ev, Http2Event::Body { .. }) {
                    n += 1;
                }
            }
            n
        });
        assert_eq!(bodies, frames, "every DATA frame must be reported");
        eprintln!(
            "  {frames:>5} frames × {payload:>5} B  input {input_len:>7} B  allocated {allocated:>9} B"
        );
        measurements.push((frames, allocated));
    }

    let (few_frames, coarse) = measurements[0];
    let (many_frames, fine) = measurements[2];
    // Splitting the same bytes into ~64× more frames must not
    // meaningfully change what is allocated. 4× is generous headroom
    // for the event queue, which really does grow with frame count;
    // the per-frame copy costs ~500× here.
    assert!(
        fine <= coarse.max(4096) * 4,
        "same {TOTAL} B split {many_frames} ways allocated {fine} B against \
         {coarse} B when split {few_frames} ways — allocation is tracking the \
         frame count, so the per-frame buffer copy is back"
    );
}

/// The same defect stated as retention: holding every payload alive
/// must pin about one buffer, not one per payload.
#[test]
fn retained_payloads_do_not_pin_a_copy_each() {
    const FRAMES: usize = 512;
    const PAYLOAD: usize = 64;
    let wire = stream_of(FRAMES, PAYLOAD);
    let input_len = wire.len();

    let mut p = Http2Parser::new();
    p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
    let data = Bytes::from(wire);

    let (held, allocated) = measure(|| {
        p.push(FlowSide::Initiator, &data);
        let mut held: Vec<Bytes> = Vec::with_capacity(FRAMES);
        while let Some(ev) = p.next_event() {
            if let Http2Event::Body { data, .. } = ev {
                held.push(data);
            }
        }
        held
    });

    assert_eq!(held.len(), FRAMES);
    assert!(
        held.iter().all(|b| b.len() == PAYLOAD),
        "each payload is its own frame's bytes"
    );
    eprintln!("  retention: input {input_len} B, allocated {allocated} B");
    // Each payload pinning its own copy of the remainder costs
    // ~9 MiB here; one shared allocation plus the event queue is well
    // under 20×.
    assert!(
        allocated <= input_len * 20,
        "holding {FRAMES} payloads allocated {allocated} B against a \
         {input_len} B input — each payload is pinning its own copy"
    );
}
