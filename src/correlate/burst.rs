//! [`BurstDetector`] — N events of kind X within a window,
//! optionally followed by an event of kind Y.

use std::collections::{HashMap, VecDeque};
use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;

/// "Burst pattern" detector.
///
/// Two modes:
///
/// - **Pure burst** (`trigger_kind = None`) — fire when the
///   `burst_kind` event count for a given key crosses
///   `threshold` within `window`. Common pattern: "5 SYN-only
///   packets in 1s → SYN flood candidate."
/// - **Burst-then-trigger** (`trigger_kind = Some(K)`) — fire
///   when a `trigger_kind` event arrives for a key that already
///   has `threshold` burst events within the window. Common
///   pattern: "5 failed auth attempts followed by success →
///   suspicious login."
///
/// Fires AT MOST ONCE per (key, qualifying-event); call
/// [`Self::observe`] for every event in the stream.
#[derive(Debug)]
pub struct BurstDetector<K, E> {
    burst_kind: E,
    threshold: u32,
    window: Duration,
    trigger_kind: Option<E>,
    state: HashMap<K, VecDeque<Timestamp>>,
}

/// One hit emitted by [`BurstDetector::observe`].
#[derive(Debug, Clone)]
pub struct BurstHit<K> {
    pub key: K,
    pub burst_count: u32,
    pub trigger_ts: Timestamp,
}

impl<K, E> BurstDetector<K, E>
where
    K: Hash + Eq + Clone,
    E: Eq + Clone,
{
    pub fn new(
        burst_kind: E,
        threshold: u32,
        window: Duration,
        trigger_kind: Option<E>,
    ) -> Self {
        Self {
            burst_kind,
            threshold,
            window,
            trigger_kind,
            state: HashMap::new(),
        }
    }

    /// Observe one event for `key`. Returns `Some(BurstHit)` when
    /// the firing condition is met.
    pub fn observe(&mut self, key: &K, event: &E, now: Timestamp) -> Option<BurstHit<K>> {
        // First, advance the per-key ring buffer by dropping
        // timestamps older than the window.
        if let Some(q) = self.state.get_mut(key) {
            drop_expired(q, now, self.window);
        }

        if *event == self.burst_kind {
            let q = self.state.entry(key.clone()).or_default();
            q.push_back(now);
            // After push: check pure-burst firing condition.
            if self.trigger_kind.is_none() && q.len() as u32 == self.threshold {
                let burst_count = q.len() as u32;
                // Pop to disarm — we've fired.
                q.clear();
                return Some(BurstHit {
                    key: key.clone(),
                    burst_count,
                    trigger_ts: now,
                });
            }
        } else if let Some(trigger) = &self.trigger_kind
            && *event == *trigger
        {
            // Trigger event: only fire if a primed burst is still
            // within the window.
            if let Some(q) = self.state.get_mut(key)
                && q.len() as u32 >= self.threshold
            {
                let burst_count = q.len() as u32;
                q.clear();
                return Some(BurstHit {
                    key: key.clone(),
                    burst_count,
                    trigger_ts: now,
                });
            }
        }
        None
    }

    /// Drop stale per-key state. Safe to call periodically — the
    /// state ages out lazily on every [`Self::observe`] call too.
    pub fn evict_expired(&mut self, now: Timestamp) {
        self.state.retain(|_, q| {
            drop_expired(q, now, self.window);
            !q.is_empty()
        });
    }
}

fn drop_expired(q: &mut VecDeque<Timestamp>, now: Timestamp, window: Duration) {
    let cutoff_dur = now.to_duration().saturating_sub(window);
    let cutoff =
        Timestamp::new(cutoff_dur.as_secs() as u32, cutoff_dur.subsec_nanos());
    while let Some(&t) = q.front() {
        if t < cutoff {
            q.pop_front();
        } else {
            break;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, PartialEq, Eq, Debug)]
    enum Auth {
        Fail,
        Success,
    }

    #[test]
    fn pure_burst_fires_at_threshold() {
        let mut d: BurstDetector<u32, Auth> =
            BurstDetector::new(Auth::Fail, 3, Duration::from_secs(60), None);
        assert!(d.observe(&1, &Auth::Fail, Timestamp::new(0, 0)).is_none());
        assert!(d.observe(&1, &Auth::Fail, Timestamp::new(1, 0)).is_none());
        let hit = d.observe(&1, &Auth::Fail, Timestamp::new(2, 0));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().burst_count, 3);
    }

    #[test]
    fn burst_then_trigger_fires_only_on_trigger() {
        let mut d: BurstDetector<u32, Auth> = BurstDetector::new(
            Auth::Fail,
            3,
            Duration::from_secs(60),
            Some(Auth::Success),
        );
        for t in [0, 1, 2] {
            assert!(d.observe(&1, &Auth::Fail, Timestamp::new(t, 0)).is_none());
        }
        // Burst is primed but no trigger yet → no fire.
        let hit = d.observe(&1, &Auth::Success, Timestamp::new(3, 0));
        assert!(hit.is_some());
        assert_eq!(hit.unwrap().burst_count, 3);
    }

    #[test]
    fn burst_past_window_does_not_fire() {
        let mut d: BurstDetector<u32, Auth> = BurstDetector::new(
            Auth::Fail,
            3,
            Duration::from_secs(10),
            Some(Auth::Success),
        );
        for t in [0, 1, 2] {
            d.observe(&1, &Auth::Fail, Timestamp::new(t, 0));
        }
        // Trigger arrives outside the window — primed state is gone.
        assert!(
            d.observe(&1, &Auth::Success, Timestamp::new(100, 0))
                .is_none()
        );
    }

    #[test]
    fn per_key_isolation() {
        let mut d: BurstDetector<u32, Auth> = BurstDetector::new(
            Auth::Fail,
            3,
            Duration::from_secs(60),
            Some(Auth::Success),
        );
        d.observe(&1, &Auth::Fail, Timestamp::new(0, 0));
        d.observe(&1, &Auth::Fail, Timestamp::new(1, 0));
        d.observe(&2, &Auth::Fail, Timestamp::new(2, 0));
        // Source 1 has 2 fails (not enough). Source 2 has 1.
        assert!(d.observe(&1, &Auth::Success, Timestamp::new(3, 0)).is_none());
        assert!(d.observe(&2, &Auth::Success, Timestamp::new(3, 0)).is_none());
    }
}
