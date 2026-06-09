//! Test-only global-allocator wrapper that counts allocations
//! and bytes. Used by the `zero_alloc` bench harness to ground
//! plan-118 phase numbers in measured (not estimated) data.
//!
//! Install once at bench-file scope:
//!
//! ```ignore
//! #[global_allocator]
//! static GLOBAL: CountingAllocator = CountingAllocator;
//! ```
//!
//! Drive via:
//!
//! ```ignore
//! CountingAllocator::reset();
//! do_work();
//! let n = CountingAllocator::allocs();
//! ```

use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub struct CountingAllocator;

static ALLOCS: AtomicUsize = AtomicUsize::new(0);
static BYTES: AtomicUsize = AtomicUsize::new(0);

unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size(), Relaxed);
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        ALLOCS.fetch_add(1, Relaxed);
        BYTES.fetch_add(layout.size(), Relaxed);
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        // realloc grows the backing store; count it as one
        // additional alloc + the delta-bytes.
        if new_size > layout.size() {
            ALLOCS.fetch_add(1, Relaxed);
            BYTES.fetch_add(new_size - layout.size(), Relaxed);
        }
        unsafe { System.realloc(ptr, layout, new_size) }
    }
}

impl CountingAllocator {
    /// Reset the counters to zero. Call before the
    /// measured-region of a bench iteration.
    pub fn reset() {
        ALLOCS.store(0, Relaxed);
        BYTES.store(0, Relaxed);
    }

    /// Total allocations since the last `reset`.
    pub fn allocs() -> usize {
        ALLOCS.load(Relaxed)
    }

    /// Total bytes since the last `reset`.
    pub fn bytes() -> usize {
        BYTES.load(Relaxed)
    }

    /// Per-iteration allocation count, given a known iteration
    /// size. Convenience helper for `println!`s inside benches.
    pub fn allocs_per(n: usize) -> f64 {
        Self::allocs() as f64 / n as f64
    }
}
