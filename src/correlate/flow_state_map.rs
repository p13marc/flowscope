//! [`FlowStateMap`] — per-flow typed state, layered over
//! [`KeyIndexed<K, T>`] with automatic eviction on
//! [`FlowEvent::Ended`] + TTL sweep.
//!
//! Plan 154 (0.13).
//!
//! Consumers typically:
//!
//! ```rust,ignore
//! use flowscope::correlate::FlowStateMap;
//! use std::time::Duration;
//!
//! #[derive(Default)]
//! struct MyStats { packets: u64, bytes: u64 }
//!
//! let mut state: FlowStateMap<MyStats> = FlowStateMap::new(Duration::from_secs(60));
//! for event in driver_events {
//!     state.feed(&event);
//!     if let FlowEvent::Packet { key, len, ts, .. } = event {
//!         let s = state.get_or_default(&key, ts);
//!         s.packets += 1;
//!         s.bytes += len as u64;
//!     }
//! }
//! // From the consumer's tick handler:
//! state.sweep(now);
//! ```

use std::{hash::Hash, time::Duration};

use super::indexed::KeyIndexed;
use crate::{event::FlowEvent, Timestamp};

/// Per-flow typed state, keyed by `FiveTupleKey` (default) or
/// any `K: Hash + Eq + Clone`.
///
/// Each slot stores a `T: Default`. Lifecycle:
/// - First access via [`Self::get_or_default`] lazily constructs
///   `T::default()`.
/// - [`Self::feed`] updates last-seen for any event carrying the
///   key; [`FlowEvent::Ended`] evicts.
/// - [`Self::sweep`] removes entries past `idle_timeout`.
///
/// Backed by [`KeyIndexed<K, T>`] — TTL + LRU machinery is
/// shared with the rest of `flowscope::correlate`.
pub struct FlowStateMap<T, K = crate::extract::FiveTupleKey>
where
    K: Hash + Eq + Clone,
    T: Default,
{
    inner: KeyIndexed<K, T>,
    idle_timeout: Duration,
}

impl<T, K> FlowStateMap<T, K>
where
    K: Hash + Eq + Clone,
    T: Default,
{
    /// New empty map. `idle_timeout` should match the
    /// consumer's `FlowTrackerConfig::idle_timeout` by
    /// convention; sweep relies on this for eviction cadence.
    pub fn new(idle_timeout: Duration) -> Self {
        Self {
            inner: KeyIndexed::new_unbounded(idle_timeout),
            idle_timeout,
        }
    }

    /// Lazy access. If `key` is new, inserts `T::default()`
    /// and returns `&mut` to the new slot. If existing,
    /// refreshes the last-seen timestamp and returns `&mut`
    /// to the slot.
    pub fn get_or_default(&mut self, key: &K, now: Timestamp) -> &mut T {
        // KeyIndexed doesn't expose &mut access today; emulate
        // lazy-create via insert + remove dance to refresh the
        // entry. The hot path is "key is present" — that's an
        // existing-replace which is O(1) in lru::LruCache.
        if self.inner.peek(key, now).is_none() {
            self.inner.insert(key.clone(), T::default(), now);
        } else {
            // Refresh the insertion timestamp so the entry
            // ages from `now` going forward.
            if let Some(value) = self.inner.remove(key) {
                self.inner.insert(key.clone(), value, now);
            }
        }
        // SAFETY-ish: the entry is freshly inserted/replaced
        // above; this getter is guaranteed to find it.
        // KeyIndexed::get returns Option<&V>, not &mut V, so
        // we have to go through the internal LruCache here.
        self.inner
            .get_mut(key, now)
            .expect("entry just inserted is present")
    }

    /// Read-only lookup at `now`. Returns `None` if the entry
    /// is absent or has aged past `idle_timeout`. Does NOT bump
    /// last-seen.
    pub fn get(&self, key: &K, now: Timestamp) -> Option<&T> {
        self.inner.peek(key, now)
    }

    /// Drive the lifecycle. Inspects each event:
    /// - [`FlowEvent::Ended`] → evict the slot.
    /// - Any other variant carrying a key → refresh last-seen.
    /// - Variants without a key (e.g. [`FlowEvent::TrackerAnomaly`]) → no-op.
    pub fn feed(&mut self, event: &FlowEvent<K>) {
        match event {
            FlowEvent::Ended { key, .. } => {
                self.inner.remove(key);
            }
            FlowEvent::Started { key, ts, .. }
            | FlowEvent::Packet { key, ts, .. }
            | FlowEvent::Established { key, ts, .. }
            | FlowEvent::Tick { key, ts, .. }
            | FlowEvent::FlowAnomaly { key, ts, .. } => {
                // Refresh last-seen if present; do NOT auto-create.
                if let Some(value) = self.inner.remove(key) {
                    self.inner.insert(key.clone(), value, *ts);
                }
            }
            FlowEvent::TrackerAnomaly { .. } | FlowEvent::StateChange { .. } => {
                // Either keyless, or doesn't carry a per-flow update.
            }
        }
    }

    /// Drop entries past `idle_timeout`. Consumer drives from
    /// their tick handler (typically once per second).
    pub fn sweep(&mut self, now: Timestamp) {
        self.inner.evict_expired(now);
    }

    /// Active entry count.
    pub fn len(&self) -> usize {
        self.inner.len()
    }

    /// True if no entries are active.
    pub fn is_empty(&self) -> bool {
        self.inner.is_empty()
    }

    /// Configured idle-timeout.
    pub fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Debug)]
    struct PerFlow {
        packets: u32,
    }

    #[test]
    fn lazy_creates_on_get_or_default() {
        let mut m: FlowStateMap<PerFlow, u32> = FlowStateMap::new(Duration::from_secs(60));
        assert_eq!(m.len(), 0);
        let slot = m.get_or_default(&42, Timestamp::new(0, 0));
        slot.packets += 1;
        assert_eq!(m.len(), 1);
        assert_eq!(m.get_or_default(&42, Timestamp::new(0, 0)).packets, 1);
    }

    #[test]
    fn feed_ended_evicts_entry() {
        let mut m: FlowStateMap<PerFlow, u32> = FlowStateMap::new(Duration::from_secs(60));
        m.get_or_default(&42, Timestamp::new(0, 0)).packets = 5;
        assert_eq!(m.len(), 1);
        let ev: FlowEvent<u32> = FlowEvent::Ended {
            key: 42,
            reason: crate::event::EndReason::IdleTimeout,
            stats: crate::event::FlowStats::default(),
            history: Default::default(),
            l4: None,
        };
        m.feed(&ev);
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn sweep_evicts_idle() {
        let mut m: FlowStateMap<PerFlow, u32> = FlowStateMap::new(Duration::from_secs(60));
        m.get_or_default(&42, Timestamp::new(0, 0));
        // Sweep 2 minutes later — entry idle past ttl.
        m.sweep(Timestamp::new(120, 0));
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn feed_packet_refreshes_last_seen() {
        let mut m: FlowStateMap<PerFlow, u32> = FlowStateMap::new(Duration::from_secs(60));
        m.get_or_default(&42, Timestamp::new(0, 0));
        // Feed a packet event at t=50, then sweep at t=70.
        let ev: FlowEvent<u32> = FlowEvent::Packet {
            key: 42,
            side: crate::FlowSide::Initiator,
            len: 100,
            ts: Timestamp::new(50, 0),
        };
        m.feed(&ev);
        m.sweep(Timestamp::new(70, 0));
        assert_eq!(
            m.len(),
            1,
            "entry refreshed by Packet at t=50, sweep at t=70 within 60s TTL"
        );
        // But sweep at t=120 (>= 50 + 60) evicts.
        m.sweep(Timestamp::new(120, 0));
        assert_eq!(m.len(), 0);
    }
}
