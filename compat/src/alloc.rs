//! Per-thread counting allocator. Binaries install it with
//! `#[global_allocator] static A: flowscope_compat::alloc::Counting = Counting;`.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

/// Counts blocks and live bytes of the current thread while tracking.
pub struct Counting;

thread_local! {
    static ON: Cell<bool> = const { Cell::new(false) };
    static BLOCKS: Cell<u64> = const { Cell::new(0) };
    static LIVE: Cell<i64> = const { Cell::new(0) };
    static PEAK: Cell<i64> = const { Cell::new(0) };
}

fn on() -> bool {
    ON.try_with(|c| c.get()).unwrap_or(false)
}

fn add(bytes: i64, block: bool) {
    let _ = LIVE.try_with(|l| {
        let v = l.get() + bytes;
        l.set(v);
        let _ = PEAK.try_with(|p| {
            if v > p.get() {
                p.set(v)
            }
        });
    });
    if block {
        let _ = BLOCKS.try_with(|b| b.set(b.get() + 1));
    }
}

unsafe impl GlobalAlloc for Counting {
    unsafe fn alloc(&self, l: Layout) -> *mut u8 {
        if on() {
            add(l.size() as i64, true);
        }
        unsafe { System.alloc(l) }
    }
    unsafe fn alloc_zeroed(&self, l: Layout) -> *mut u8 {
        if on() {
            add(l.size() as i64, true);
        }
        unsafe { System.alloc_zeroed(l) }
    }
    unsafe fn dealloc(&self, p: *mut u8, l: Layout) {
        if on() {
            add(-(l.size() as i64), false);
        }
        unsafe { System.dealloc(p, l) }
    }
    unsafe fn realloc(&self, p: *mut u8, l: Layout, new: usize) -> *mut u8 {
        if on() {
            add(new as i64 - l.size() as i64, true);
        }
        unsafe { System.realloc(p, l, new) }
    }
}

/// Totals of one tracked region.
#[derive(Debug, Clone, Copy)]
pub struct Stats {
    /// Allocations + reallocations.
    pub blocks: u64,
    /// Peak live bytes above the region's start.
    pub peak: u64,
}

/// Tracks the current thread's allocations until `finish`.
pub struct Tracking(());

impl Tracking {
    /// Reset counters and start tracking.
    pub fn start() -> Tracking {
        BLOCKS.with(|c| c.set(0));
        LIVE.with(|c| c.set(0));
        PEAK.with(|c| c.set(0));
        ON.with(|c| c.set(true));
        Tracking(())
    }

    /// Stop tracking and return the totals.
    pub fn finish(self) -> Stats {
        ON.with(|c| c.set(false));
        Stats {
            blocks: BLOCKS.with(|c| c.get()),
            peak: PEAK.with(|c| c.get()).max(0) as u64,
        }
    }
}

/// Live bytes above the tracked region's start, right now.
pub fn live_delta() -> u64 {
    LIVE.with(|c| c.get()).max(0) as u64
}
