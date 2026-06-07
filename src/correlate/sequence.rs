//! [`SequencePattern`] — generic FSM trait for cross-event
//! pattern detectors.

use std::hash::Hash;

use smallvec::SmallVec;

use crate::Timestamp;

/// Generic finite-state machine trait for event-stream pattern
/// detectors (port scans, "auth-failure-then-success", retry
/// storms, …).
///
/// Implementations own per-key state (so multiple flows / hosts
/// can be tracked independently). Consumers call
/// [`Self::observe`] for each incoming event and
/// [`Self::on_tick`] periodically to drain time-bounded
/// anomalies.
///
/// For patterns without a per-key dimension (global rate-
/// limits etc.), implement [`KeylessSequencePattern`] instead
/// — a blanket impl makes it satisfy `SequencePattern<Key = ()>`.
pub trait SequencePattern: Send + 'static {
    /// Per-key dimension. Use `()` for global patterns.
    type Key: Hash + Eq + Clone + Send + 'static;
    /// The event type the FSM accepts.
    type Event;
    /// The anomaly type emitted on detection.
    type Anomaly;

    /// Observe one event for `key` at `now`. Returns 0..N
    /// anomalies — `SmallVec<[…; 1]>` keeps the no-anomaly path
    /// allocation-free.
    fn observe(
        &mut self,
        key: &Self::Key,
        event: &Self::Event,
        now: Timestamp,
    ) -> SmallVec<[Self::Anomaly; 1]>;

    /// Periodic tick. Implementations expire stale state, fire
    /// time-bounded anomalies (e.g. "no response within N
    /// seconds"). Bounded to 4 inline slots — patterns expecting
    /// burstier tick output should heap-allocate.
    fn on_tick(&mut self, now: Timestamp) -> SmallVec<[Self::Anomaly; 4]>;
}

/// Adapter trait for patterns that don't carry a per-key
/// dimension. Implement this and get `SequencePattern<Key = ()>`
/// for free.
pub trait KeylessSequencePattern: Send + 'static {
    type Event;
    type Anomaly;

    fn observe(&mut self, event: &Self::Event, now: Timestamp) -> SmallVec<[Self::Anomaly; 1]>;

    fn on_tick(&mut self, now: Timestamp) -> SmallVec<[Self::Anomaly; 4]>;
}

impl<T: KeylessSequencePattern> SequencePattern for T {
    type Key = ();
    type Event = T::Event;
    type Anomaly = T::Anomaly;

    fn observe(
        &mut self,
        _key: &(),
        event: &T::Event,
        now: Timestamp,
    ) -> SmallVec<[Self::Anomaly; 1]> {
        KeylessSequencePattern::observe(self, event, now)
    }

    fn on_tick(&mut self, now: Timestamp) -> SmallVec<[Self::Anomaly; 4]> {
        KeylessSequencePattern::on_tick(self, now)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Sample implementation: emit an anomaly when an "auth
    /// failure" event is followed by a "success" within a tick.
    struct AuthFlip {
        last_failure: Option<Timestamp>,
    }

    #[derive(Debug, Clone, PartialEq)]
    enum AuthEvent {
        Fail,
        Succeed,
    }

    #[derive(Debug, Clone, PartialEq)]
    struct SuspiciousFlip(Timestamp);

    impl KeylessSequencePattern for AuthFlip {
        type Event = AuthEvent;
        type Anomaly = SuspiciousFlip;

        fn observe(&mut self, event: &AuthEvent, now: Timestamp) -> SmallVec<[SuspiciousFlip; 1]> {
            match event {
                AuthEvent::Fail => {
                    self.last_failure = Some(now);
                    SmallVec::new()
                }
                AuthEvent::Succeed => {
                    if let Some(_prev) = self.last_failure.take() {
                        let mut v = SmallVec::new();
                        v.push(SuspiciousFlip(now));
                        v
                    } else {
                        SmallVec::new()
                    }
                }
            }
        }

        fn on_tick(&mut self, _now: Timestamp) -> SmallVec<[SuspiciousFlip; 4]> {
            SmallVec::new()
        }
    }

    #[test]
    fn keyless_blanket_impl() {
        let mut p = AuthFlip { last_failure: None };
        // Observe via SequencePattern trait (blanket).
        let v: SmallVec<[SuspiciousFlip; 1]> =
            SequencePattern::observe(&mut p, &(), &AuthEvent::Fail, Timestamp::new(0, 0));
        assert!(v.is_empty());

        let v: SmallVec<[SuspiciousFlip; 1]> =
            SequencePattern::observe(&mut p, &(), &AuthEvent::Succeed, Timestamp::new(1, 0));
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], SuspiciousFlip(Timestamp::new(1, 0)));
    }

    #[test]
    fn no_flip_when_no_prior_failure() {
        let mut p = AuthFlip { last_failure: None };
        let v = KeylessSequencePattern::observe(&mut p, &AuthEvent::Succeed, Timestamp::new(0, 0));
        assert!(v.is_empty());
    }
}
