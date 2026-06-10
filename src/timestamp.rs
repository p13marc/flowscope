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

    /// Write the timestamp as RFC 3339 / ISO 8601 (UTC,
    /// 9-digit fractional second). Hand-rolled — no chrono
    /// dependency, zero allocations.
    ///
    /// Output shape: `"YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ"` (always
    /// 30 ASCII bytes; no timezone offset, always UTC).
    ///
    /// `Timestamp::sec` is a `u32`, so the rendered range is
    /// 1970-01-01T00:00:00Z to 2106-02-07T06:28:15Z.
    ///
    /// New in 0.12.0.
    pub fn write_iso8601<W: std::fmt::Write>(&self, w: &mut W) -> std::fmt::Result {
        // Civil-from-days (Howard Hinnant's algorithm).
        let days = (self.sec / 86_400) as i32;
        let secs_of_day = self.sec % 86_400;
        let (y, m, d) = civil_from_days(days);
        let h = secs_of_day / 3600;
        let mi = (secs_of_day % 3600) / 60;
        let s = secs_of_day % 60;

        // Fixed-width writes — branch-free for the digit
        // counts.
        write!(
            w,
            "{y:04}-{m:02}-{d:02}T{h:02}:{mi:02}:{s:02}.{nsec:09}Z",
            nsec = self.nsec
        )
    }

    /// Allocating wrapper around [`Self::write_iso8601`]. Returns
    /// a freshly-allocated string. Equivalent to
    /// `let mut s = String::with_capacity(30);
    ///  ts.write_iso8601(&mut s).unwrap(); s`.
    ///
    /// New in 0.12.0.
    pub fn to_iso8601(&self) -> String {
        let mut s = String::with_capacity(30);
        self.write_iso8601(&mut s).unwrap();
        s
    }
}

/// Compute the (year, month, day) calendar fields from a count
/// of days since 1970-01-01 (Unix epoch). Implements Howard
/// Hinnant's `civil_from_days` algorithm
/// (<https://howardhinnant.github.io/date_algorithms.html>),
/// adapted to return `(year, month, day)` directly.
///
/// `days` is permitted to be negative for pre-1970 inputs, but
/// `Timestamp::sec` is `u32` so `days >= 0` in practice.
#[inline]
fn civil_from_days(days: i32) -> (i32, u32, u32) {
    let z = days + 719_468;
    let era = (if z >= 0 { z } else { z - 146_096 }) / 146_097;
    let doe = (z - era * 146_097) as u32;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i32 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = y + if m <= 2 { 1 } else { 0 };
    (y, m, d)
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

// ── Optional chrono interop (plan 127) ─────────────────────────

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for Timestamp {
    /// Lossy when `dt`'s timestamp falls outside the
    /// `u32`-seconds range (1970-01-01 to 2106-02-07). Pre-epoch
    /// inputs clamp to `Timestamp { sec: 0, nsec: dt.timestamp_subsec_nanos() }`;
    /// post-`u32::MAX` inputs clamp to [`Timestamp::MAX`].
    fn from(dt: chrono::DateTime<chrono::Utc>) -> Self {
        let secs = dt.timestamp();
        let nsec = dt.timestamp_subsec_nanos();
        if secs < 0 {
            Self::new(0, nsec)
        } else if secs > i64::from(u32::MAX) {
            Self::MAX
        } else {
            Self::new(secs as u32, nsec)
        }
    }
}

/// Error returned when a [`Timestamp`] can't be represented as
/// a [`chrono::DateTime<chrono::Utc>`] — in practice never
/// triggered for `u32`-second timestamps (chrono's range
/// vastly exceeds ours).
#[cfg(feature = "chrono")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChronoOutOfRange;

#[cfg(feature = "chrono")]
impl std::fmt::Display for ChronoOutOfRange {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Timestamp out of representable chrono::DateTime range")
    }
}

#[cfg(feature = "chrono")]
impl std::error::Error for ChronoOutOfRange {}

#[cfg(feature = "chrono")]
impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = ChronoOutOfRange;

    fn try_from(ts: Timestamp) -> Result<Self, Self::Error> {
        chrono::DateTime::<chrono::Utc>::from_timestamp(i64::from(ts.sec), ts.nsec)
            .ok_or(ChronoOutOfRange)
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

    // ── ISO 8601 / RFC 3339 rendering (plan 127) ─────────────

    #[test]
    fn iso8601_epoch_zero() {
        let s = Timestamp::new(0, 0).to_iso8601();
        assert_eq!(s, "1970-01-01T00:00:00.000000000Z");
    }

    #[test]
    fn iso8601_known_date() {
        // 2024-06-09T11:34:56.123456789Z = 1717932896 + 123456789 ns
        let s = Timestamp::new(1_717_932_896, 123_456_789).to_iso8601();
        assert_eq!(s, "2024-06-09T11:34:56.123456789Z");
    }

    #[test]
    fn iso8601_one_second_after_epoch() {
        let s = Timestamp::new(1, 0).to_iso8601();
        assert_eq!(s, "1970-01-01T00:00:01.000000000Z");
    }

    #[test]
    fn iso8601_one_minute_after_epoch() {
        let s = Timestamp::new(60, 0).to_iso8601();
        assert_eq!(s, "1970-01-01T00:01:00.000000000Z");
    }

    #[test]
    fn iso8601_one_hour_after_epoch() {
        let s = Timestamp::new(3600, 0).to_iso8601();
        assert_eq!(s, "1970-01-01T01:00:00.000000000Z");
    }

    #[test]
    fn iso8601_one_day_after_epoch() {
        let s = Timestamp::new(86_400, 0).to_iso8601();
        assert_eq!(s, "1970-01-02T00:00:00.000000000Z");
    }

    #[test]
    fn iso8601_leap_day_2024() {
        // 2024-02-29T00:00:00Z = days since epoch:
        // 2024-02-29 is day-of-epoch 19_782; * 86400 = 1_709_164_800.
        let s = Timestamp::new(1_709_164_800, 0).to_iso8601();
        assert_eq!(s, "2024-02-29T00:00:00.000000000Z");
    }

    #[test]
    fn iso8601_non_leap_year_century() {
        // 2100 is NOT a leap year (divisible by 100, not 400).
        // 4_107_456_000 lands on Feb 28; one day later is March 1.
        let feb28 = Timestamp::new(4_107_456_000, 0).to_iso8601();
        assert_eq!(feb28, "2100-02-28T00:00:00.000000000Z");
        // March 1 is 86_400 seconds later — confirming Feb 29
        // doesn't exist in 2100 (would be needed for a Feb 29 to
        // appear before March 1).
        let mar1 = Timestamp::new(4_107_542_400, 0).to_iso8601();
        assert_eq!(mar1, "2100-03-01T00:00:00.000000000Z");
    }

    #[test]
    fn iso8601_y2038_safe() {
        // Y2038 (signed-i32 epoch wraparound) = 2147483647.
        // We're u32, so we're fine through 2106.
        let s = Timestamp::new(2_147_483_647, 0).to_iso8601();
        assert_eq!(s, "2038-01-19T03:14:07.000000000Z");
    }

    #[test]
    fn iso8601_u32_max() {
        // u32::MAX seconds: 4294967295 / 86400 = 49710 days
        // since epoch = 2106-02-07T06:28:15Z.
        let s = Timestamp::new(u32::MAX, 0).to_iso8601();
        assert_eq!(s, "2106-02-07T06:28:15.000000000Z");
    }

    #[test]
    fn iso8601_max_nsec() {
        let s = Timestamp::new(0, 999_999_999).to_iso8601();
        assert_eq!(s, "1970-01-01T00:00:00.999999999Z");
    }

    #[test]
    fn to_iso8601_matches_write_iso8601() {
        let ts = Timestamp::new(1_717_932_896, 123_456_789);
        let allocating = ts.to_iso8601();
        let mut buf = String::with_capacity(30);
        ts.write_iso8601(&mut buf).unwrap();
        assert_eq!(allocating, buf);
    }

    #[test]
    fn to_iso8601_pre_allocates_30_bytes() {
        // Inspection-only — string content already covered.
        let s = Timestamp::new(0, 0).to_iso8601();
        assert_eq!(s.len(), 30);
        assert_eq!(s.capacity(), 30);
    }

    // ── Cross-check against chrono (plan 127) ────────────────

    #[cfg(feature = "chrono")]
    #[test]
    fn iso8601_matches_chrono_to_rfc3339() {
        use chrono::SecondsFormat;
        for sec in [
            0u32,
            1,
            60,
            3600,
            86_400,
            1_000_000_000,
            1_717_932_896,
            2_147_483_647,
            4_107_456_000,
            4_107_542_400,
            u32::MAX,
        ] {
            for nsec in [0u32, 1, 123_456_789, 999_999_999] {
                let ts = Timestamp::new(sec, nsec);
                let ours = ts.to_iso8601();
                let theirs = chrono::DateTime::<chrono::Utc>::from_timestamp(sec.into(), nsec)
                    .unwrap()
                    .to_rfc3339_opts(SecondsFormat::Nanos, true);
                assert_eq!(ours, theirs, "mismatch at sec={sec}, nsec={nsec}",);
            }
        }
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_roundtrip_preserves_nanos() {
        for sec in [0u32, 1_000_000_000, 1_717_932_896, u32::MAX] {
            for nsec in [0u32, 123_456_789, 999_999_999] {
                let ts = Timestamp::new(sec, nsec);
                let dt: chrono::DateTime<chrono::Utc> = ts.try_into().unwrap();
                let back: Timestamp = dt.into();
                assert_eq!(back, ts, "round-trip at sec={sec}, nsec={nsec}");
            }
        }
    }

    #[cfg(feature = "chrono")]
    #[test]
    fn chrono_from_pre_epoch_clamps_to_zero_sec() {
        let pre = chrono::DateTime::<chrono::Utc>::from_timestamp(-100, 500).unwrap();
        let ts: Timestamp = pre.into();
        assert_eq!(ts.sec, 0);
        assert_eq!(ts.nsec, 500);
    }
}
