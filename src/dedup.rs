//! Content-hash deduplication of packet views.
//!
//! Each [`Dedup`] instance maintains a small ring buffer of
//! `(hash(frame), len, timestamp)` triples. [`Dedup::keep`]
//! returns `false` when the incoming view matches a recent entry
//! within the configured time window — useful for stripping the
//! duplicate halves that loopback captures emit.
//!
//! The match criterion is
//! `hash(frame) == h && len == l && now - seen <= window` —
//! three signals to keep false-positive dedupe rare even under
//! 64-bit hash collisions.
//!
//! # Example
//!
//! ```
//! use std::time::Duration;
//! use flowscope::{Dedup, PacketView, Timestamp};
//!
//! let mut d = Dedup::new(Duration::from_millis(1), 256);
//! let frame = [1u8, 2, 3, 4];
//! assert!(d.keep(PacketView::new(&frame, Timestamp::new(0, 0))));
//! // Same frame 500 µs later — duplicate.
//! assert!(!d.keep(PacketView::new(&frame, Timestamp::new(0, 500_000))));
//! assert_eq!(d.dropped(), 1);
//! ```
//!
//! # Cost
//!
//! Per packet: one hash (~100 ns on a 1500-byte frame with
//! `ahash`) plus a linear scan of up to `capacity` ring entries
//! (~100 ns for 256 entries; cache-friendly). Total well below
//! 1 µs/packet — negligible against typical capture latency.

use std::{
    collections::VecDeque,
    hash::{BuildHasher, Hasher},
    time::Duration,
};

use crate::{Timestamp, view::PacketView};

/// Bounded content-hash dedup. Cheap to construct; cheap per
/// packet.
///
/// No `Default` impl on purpose — "no dedup at all" is the
/// natural default (just don't construct a `Dedup`). Pick an
/// explicit constructor: [`Self::loopback`] for the
/// tuned-for-`tcpdump -i lo` profile, or [`Self::new`] for
/// custom window / capacity.
#[derive(Debug, Clone)]
pub struct Dedup {
    window: Duration,
    capacity: usize,
    ring: VecDeque<Entry>,
    dropped: u64,
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    hash: u64,
    len: u32,
    ts: Timestamp,
}

impl Dedup {
    /// Default ring size for [`Self::loopback`]: 256 entries
    /// × ~24 B = ~6 KiB resident.
    pub const DEFAULT_RING_SIZE: usize = 256;

    /// Default recurrence window for [`Self::loopback`]: 1 ms.
    pub const DEFAULT_LOOPBACK_WINDOW: Duration = Duration::from_millis(1);

    /// Construct a content-hash dedup with explicit window and
    /// ring size. `capacity` is clamped to `>= 1`.
    pub fn new(window: Duration, capacity: usize) -> Self {
        let capacity = capacity.max(1);
        Self {
            window,
            capacity,
            ring: VecDeque::with_capacity(capacity),
            dropped: 0,
        }
    }

    /// Tuned defaults for loopback (`tcpdump -i lo` / AF_PACKET on
    /// `lo`): 1 ms window, 256-entry ring. Tight enough to dedupe
    /// re-injected loopback copies without false-deduping
    /// legitimate retransmits.
    pub fn loopback() -> Self {
        Self::new(Self::DEFAULT_LOOPBACK_WINDOW, Self::DEFAULT_RING_SIZE)
    }

    /// Check this view against the recent ring.
    ///
    /// Returns `true` to keep the view (process normally),
    /// `false` to drop it as a duplicate. Updates the internal
    /// ring either way.
    pub fn keep(&mut self, view: PacketView<'_>) -> bool {
        let hash = hash_frame(view.frame);
        let len = view.frame.len() as u32;
        let is_dup = self.ring.iter().any(|entry| {
            entry.hash == hash
                && entry.len == len
                && view.timestamp.saturating_sub(entry.ts) <= self.window
        });
        self.push_entry(Entry {
            hash,
            len,
            ts: view.timestamp,
        });
        if is_dup {
            self.dropped += 1;
        }
        !is_dup
    }

    /// Number of views dropped as duplicates since construction.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    /// Current ring occupancy.
    pub fn buffered(&self) -> usize {
        self.ring.len()
    }

    fn push_entry(&mut self, e: Entry) {
        if self.ring.len() >= self.capacity {
            self.ring.pop_front();
        }
        self.ring.push_back(e);
    }
}

/// Deterministic content hash. Uses `ahash` (already a tracker
/// dep — no new transitive deps) with fixed zero seeds so
/// behaviour is identical across processes. The hash is purely
/// internal; ports / IPs aren't exposed via labels so flood
/// resistance isn't a concern.
fn hash_frame(frame: &[u8]) -> u64 {
    let state = ahash::RandomState::with_seeds(0, 0, 0, 0);
    let mut hasher = state.build_hasher();
    hasher.write(frame);
    hasher.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(sec: u32, nsec: u32) -> Timestamp {
        Timestamp::new(sec, nsec)
    }

    #[test]
    fn keeps_first_drops_duplicate_within_window() {
        let mut d = Dedup::loopback();
        let frame = [1u8, 2, 3, 4];
        assert!(d.keep(PacketView::new(&frame, ts(0, 0))));
        // 500 µs later — well within 1 ms window.
        assert!(!d.keep(PacketView::new(&frame, ts(0, 500_000))));
        assert_eq!(d.dropped(), 1);
    }

    #[test]
    fn keeps_recurrence_after_window() {
        let mut d = Dedup::new(Duration::from_millis(1), 256);
        let frame = [1u8, 2, 3];
        assert!(d.keep(PacketView::new(&frame, ts(0, 0))));
        // 2 ms later — outside 1 ms window.
        assert!(d.keep(PacketView::new(&frame, ts(0, 2_000_000))));
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn different_frames_pass_through() {
        let mut d = Dedup::loopback();
        let f1 = [1u8, 2, 3];
        let f2 = [4u8, 5, 6];
        assert!(d.keep(PacketView::new(&f1, ts(0, 0))));
        assert!(d.keep(PacketView::new(&f2, ts(0, 100_000))));
        assert_eq!(d.dropped(), 0);
    }

    #[test]
    fn ring_bounded() {
        let mut d = Dedup::new(Duration::from_millis(1), 2);
        let f1 = [1u8];
        let f2 = [2u8];
        let f3 = [3u8];
        d.keep(PacketView::new(&f1, ts(0, 0)));
        d.keep(PacketView::new(&f2, ts(0, 100_000)));
        d.keep(PacketView::new(&f3, ts(0, 200_000)));
        assert_eq!(d.buffered(), 2);
        // f1 has aged out of the ring; a duplicate of it now is NOT
        // detected — documented behaviour (false negative under
        // capacity pressure).
        assert!(d.keep(PacketView::new(&f1, ts(0, 300_000))));
    }

    #[test]
    fn capacity_clamped_to_one() {
        let mut d = Dedup::new(Duration::from_millis(1), 0);
        let f = [1u8];
        assert!(d.keep(PacketView::new(&f, ts(0, 0))));
        assert!(!d.keep(PacketView::new(&f, ts(0, 100_000))));
    }

    #[test]
    fn same_hash_different_len_kept() {
        // Different lengths can't collide on the (hash, len) tuple
        // check — even if hashes happened to match by coincidence,
        // length mismatch means "different frame."
        let mut d = Dedup::loopback();
        let f1 = [1u8, 2];
        let f2 = [1u8, 2, 3];
        assert!(d.keep(PacketView::new(&f1, ts(0, 0))));
        assert!(d.keep(PacketView::new(&f2, ts(0, 100_000))));
        assert_eq!(d.dropped(), 0);
    }
}
