//! Nanosecond-precision timestamp shared across the netring family.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

/// Nanosecond-precision kernel timestamp.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct Timestamp {
    /// Seconds since epoch.
    pub sec: u32,
    /// Nanoseconds within the second.
    pub nsec: u32,
}

impl Timestamp {
    /// The maximum representable timestamp — `u32::MAX` seconds plus
    /// the largest valid nanosecond value. Past any real capture
    /// time; pass to [`sweep`](crate::FlowTracker::sweep), or use
    /// [`FlowDriver::finish`](crate::FlowDriver::finish), to force
    /// every live flow to its idle-timeout end.
    pub const MAX: Timestamp = Timestamp {
        sec: u32::MAX,
        nsec: 999_999_999,
    };

    /// Create a new timestamp.
    #[inline]
    pub const fn new(sec: u32, nsec: u32) -> Self {
        Self { sec, nsec }
    }

    /// Convert to [`SystemTime`].
    #[inline]
    pub fn to_system_time(self) -> SystemTime {
        UNIX_EPOCH + Duration::new(self.sec as u64, self.nsec)
    }

    /// Convert to [`Duration`] since epoch.
    #[inline]
    pub fn to_duration(self) -> Duration {
        Duration::new(self.sec as u64, self.nsec)
    }

    /// Saturating duration from `other` to `self`. Returns
    /// [`Duration::ZERO`] when `self` precedes `other`.
    ///
    /// Used by [`crate::Dedup`] and any consumer that wants the
    /// elapsed-since-X without panicking on backwards-ordered
    /// timestamps.
    #[inline]
    pub fn saturating_sub(self, other: Timestamp) -> Duration {
        self.to_duration().saturating_sub(other.to_duration())
    }

    /// Unix epoch seconds with nanosecond precision. Inverse of
    /// [`Self::from_unix_f64`].
    ///
    /// New in 0.10.0. Floating-point precision is enough for
    /// dashboard-style "seconds since" rendering; round-trip
    /// fidelity isn't guaranteed beyond ~microseconds for `sec`
    /// values past 2³².
    #[inline]
    pub fn to_unix_f64(self) -> f64 {
        self.sec as f64 + self.nsec as f64 / 1e9
    }

    /// Construct from Unix epoch seconds. Truncates the fractional
    /// part to a `u32` nanosecond count; clamps negative inputs to
    /// the epoch.
    ///
    /// New in 0.10.0.
    pub fn from_unix_f64(secs: f64) -> Self {
        if !secs.is_finite() || secs <= 0.0 {
            return Self::default();
        }
        let whole = secs.trunc();
        let sec = if whole >= u32::MAX as f64 {
            u32::MAX
        } else {
            whole as u32
        };
        let nsec = ((secs.fract() * 1e9).round() as i64).clamp(0, 999_999_999) as u32;
        Self::new(sec, nsec)
    }

    /// Signed delta in seconds: `self - other`. Negative if `self`
    /// is earlier than `other`. Useful for relative-time displays
    /// like Zeek-style `dur` values.
    ///
    /// New in 0.10.0.
    pub fn relative_to(self, other: Timestamp) -> f64 {
        self.to_unix_f64() - other.to_unix_f64()
    }

    /// Construct from a [`SystemTime`]. Clamps pre-epoch values to
    /// the epoch and truncates overflowing seconds to `u32::MAX`.
    ///
    /// New in 0.10.0.
    pub fn from_system_time(ts: SystemTime) -> Self {
        let dur = ts.duration_since(UNIX_EPOCH).unwrap_or(Duration::ZERO);
        let sec = u32::try_from(dur.as_secs()).unwrap_or(u32::MAX);
        Self::new(sec, dur.subsec_nanos())
    }
}

impl From<Timestamp> for SystemTime {
    fn from(ts: Timestamp) -> Self {
        ts.to_system_time()
    }
}

impl From<Timestamp> for Duration {
    fn from(ts: Timestamp) -> Self {
        ts.to_duration()
    }
}

impl std::fmt::Display for Timestamp {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{:09}", self.sec, self.nsec)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamp_new() {
        let ts = Timestamp::new(1234, 567890);
        assert_eq!(ts.sec, 1234);
        assert_eq!(ts.nsec, 567890);
    }

    #[test]
    fn timestamp_to_system_time() {
        let ts = Timestamp::new(1_000_000_000, 500_000_000);
        let st = ts.to_system_time();
        let expected = UNIX_EPOCH + Duration::new(1_000_000_000, 500_000_000);
        assert_eq!(st, expected);
    }

    #[test]
    fn timestamp_to_duration() {
        let ts = Timestamp::new(5, 123456789);
        let d = ts.to_duration();
        assert_eq!(d, Duration::new(5, 123456789));
    }

    #[test]
    fn timestamp_display() {
        let ts = Timestamp::new(1234, 1);
        assert_eq!(ts.to_string(), "1234.000000001");
    }

    #[test]
    fn timestamp_ordering() {
        let a = Timestamp::new(1, 0);
        let b = Timestamp::new(1, 1);
        let c = Timestamp::new(2, 0);
        assert!(a < b);
        assert!(b < c);
    }

    #[test]
    fn timestamp_default_is_zero() {
        let ts = Timestamp::default();
        assert_eq!(ts.sec, 0);
        assert_eq!(ts.nsec, 0);
    }

    #[test]
    fn timestamp_max() {
        // Greater than any timestamp built from observed values.
        for &(sec, nsec) in &[
            (0u32, 0u32),
            (2_000_000_000, 500),
            (u32::MAX - 1, 999_999_999),
        ] {
            assert!(Timestamp::MAX > Timestamp::new(sec, nsec));
        }
        assert_eq!(Timestamp::MAX.sec, u32::MAX);
        assert_eq!(Timestamp::MAX.nsec, 999_999_999);
    }
}
