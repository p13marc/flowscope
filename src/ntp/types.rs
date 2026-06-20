//! NTP message types.

use std::net::Ipv4Addr;

/// Offset between the NTP epoch (1900-01-01 00:00:00 UTC) and
/// the Unix epoch (1970-01-01 00:00:00 UTC), in seconds. NTP
/// 64-bit timestamps count seconds from the NTP epoch.
pub const REF_TIMESTAMP_EPOCH: u32 = 2_208_988_800;

/// One parsed NTP / SNTP header (RFC 5905 §7.3, 48 bytes).
/// Optional extension fields, KOD, MAC are not surfaced.
///
/// Issue #14 (Tier-2 sub-piece).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NtpMessage {
    /// 2-bit Leap Indicator.
    pub leap: NtpLeapIndicator,
    /// 3-bit Version Number (3 or 4 in modern traffic).
    pub version: u8,
    /// 3-bit Mode field. The most operationally-interesting bit.
    pub mode: NtpMode,
    /// 0 = unspecified / kiss-of-death; 1 = primary (e.g. GPS);
    /// 2..15 = secondary; 16 = unsynchronised; 17..255 = reserved.
    pub stratum: u8,
    /// Signed log2 seconds — maximum interval between successive
    /// messages.
    pub poll: i8,
    /// Signed log2 seconds — precision of the local clock.
    pub precision: i8,
    /// Root-delay field as a 32-bit NTP short-format value
    /// (16.16 fixed point seconds).
    pub root_delay_raw: u32,
    /// Root-dispersion field as a 32-bit NTP short-format value.
    pub root_dispersion_raw: u32,
    /// Reference identifier — 4 bytes. Semantics depend on
    /// `stratum`:
    ///
    /// - stratum = 0: 4-byte ASCII kiss-of-death code.
    /// - stratum = 1: 4-byte ASCII reference clock id (e.g.
    ///   `b"GPS\0"`, `b"PPS\0"`, `b"DCF\0"`).
    /// - stratum >= 2: IPv4 address of the upstream server.
    pub ref_id: [u8; 4],
    /// Reference timestamp — time the local clock was last
    /// set / corrected.
    pub ref_timestamp: NtpTimestamp,
    /// Origin timestamp — time at the client when the request
    /// departed.
    pub origin_timestamp: NtpTimestamp,
    /// Receive timestamp — time at the server when the request
    /// arrived.
    pub recv_timestamp: NtpTimestamp,
    /// Transmit timestamp — time at the server when the
    /// response departed.
    pub transmit_timestamp: NtpTimestamp,
}

impl NtpMessage {
    /// `true` if this datagram looks like an NTP-amplification
    /// vector — mode 6 (control) or mode 7 (private /
    /// `monlist`). Historically the dominant NTP-amp source
    /// (US-CERT TA14-013A); modern operators almost never need
    /// these on the public internet.
    #[inline]
    pub fn is_amplification_risk(&self) -> bool {
        matches!(self.mode, NtpMode::Control | NtpMode::Private)
    }

    /// Decode the reference id as an upstream IPv4 address.
    /// Only valid when `stratum >= 2` per RFC 5905 §7.3 — for
    /// stratum 0 / 1 the field is an ASCII code.
    #[inline]
    pub fn ref_id_as_ipv4(&self) -> Option<Ipv4Addr> {
        if self.stratum >= 2 {
            Some(Ipv4Addr::new(
                self.ref_id[0],
                self.ref_id[1],
                self.ref_id[2],
                self.ref_id[3],
            ))
        } else {
            None
        }
    }

    /// Decode the reference id as an ASCII reference-clock or
    /// kiss-of-death code. Only valid when `stratum <= 1`.
    /// Trims trailing NULs. Returns `None` for stratum >= 2
    /// (the field is an IP there) or non-printable bytes.
    pub fn ref_id_as_str(&self) -> Option<&str> {
        if self.stratum > 1 {
            return None;
        }
        let end = self
            .ref_id
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(self.ref_id.len());
        std::str::from_utf8(&self.ref_id[..end]).ok()
    }
}

/// 2-bit Leap Indicator (RFC 5905 §7.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum NtpLeapIndicator {
    /// `0` — no warning.
    NoWarning,
    /// `1` — last minute of the day has 61 seconds.
    AddSecond,
    /// `2` — last minute of the day has 59 seconds.
    DeleteSecond,
    /// `3` — clock unsynchronised.
    Unsynchronised,
}

impl NtpLeapIndicator {
    /// Decode the 2-bit field.
    pub fn from_raw(b: u8) -> Self {
        match b & 0x03 {
            0 => NtpLeapIndicator::NoWarning,
            1 => NtpLeapIndicator::AddSecond,
            2 => NtpLeapIndicator::DeleteSecond,
            _ => NtpLeapIndicator::Unsynchronised,
        }
    }
}

/// 3-bit Mode field (RFC 5905 §7.3 + RFC 1305 §3.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum NtpMode {
    /// `0` — reserved.
    Reserved,
    /// `1` — symmetric active.
    SymmetricActive,
    /// `2` — symmetric passive.
    SymmetricPassive,
    /// `3` — client request.
    Client,
    /// `4` — server reply.
    Server,
    /// `5` — broadcast.
    Broadcast,
    /// `6` — NTP control message (RFC 1305 §3.2.2) — used by
    /// `ntpq`. Carries the NTP-amplification risk historically.
    Control,
    /// `7` — reserved for private use (RFC 1305 Appendix B) —
    /// the `monlist` query rides this mode. Universally
    /// considered an amplification IOC on the public
    /// internet.
    Private,
}

impl NtpMode {
    /// Decode the 3-bit field.
    pub fn from_raw(b: u8) -> Self {
        match b & 0x07 {
            0 => NtpMode::Reserved,
            1 => NtpMode::SymmetricActive,
            2 => NtpMode::SymmetricPassive,
            3 => NtpMode::Client,
            4 => NtpMode::Server,
            5 => NtpMode::Broadcast,
            6 => NtpMode::Control,
            7 => NtpMode::Private,
            _ => unreachable!("u8 & 0x07 fits in 0..8"),
        }
    }

    /// IANA / RFC 5905 numeric value.
    pub fn as_u8(self) -> u8 {
        match self {
            NtpMode::Reserved => 0,
            NtpMode::SymmetricActive => 1,
            NtpMode::SymmetricPassive => 2,
            NtpMode::Client => 3,
            NtpMode::Server => 4,
            NtpMode::Broadcast => 5,
            NtpMode::Control => 6,
            NtpMode::Private => 7,
        }
    }

    /// Stable slug for metric labels.
    pub fn as_str(self) -> &'static str {
        match self {
            NtpMode::Reserved => "reserved",
            NtpMode::SymmetricActive => "symmetric_active",
            NtpMode::SymmetricPassive => "symmetric_passive",
            NtpMode::Client => "client",
            NtpMode::Server => "server",
            NtpMode::Broadcast => "broadcast",
            NtpMode::Control => "control",
            NtpMode::Private => "private",
        }
    }
}

/// NTP 64-bit timestamp — 32-bit seconds since the NTP epoch
/// (1900-01-01) + 32-bit fraction-of-second.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct NtpTimestamp {
    /// Seconds since 1900-01-01 00:00:00 UTC.
    pub seconds: u32,
    /// Fraction of a second (units of 2^-32 sec).
    pub fraction: u32,
}

impl NtpTimestamp {
    /// `true` if all 64 bits are zero — NTP's "no timestamp"
    /// sentinel.
    #[inline]
    pub fn is_zero(self) -> bool {
        self.seconds == 0 && self.fraction == 0
    }

    /// Convert to seconds since the Unix epoch as `f64`. Loses
    /// some precision for the fractional part — use the raw
    /// `seconds` + `fraction` for full fidelity.
    ///
    /// Returns `None` for the zero sentinel (no useful Unix
    /// time) and for timestamps before the Unix epoch (i.e.
    /// before 1970-01-01).
    pub fn to_unix_f64(self) -> Option<f64> {
        if self.is_zero() {
            return None;
        }
        let secs = self.seconds.checked_sub(REF_TIMESTAMP_EPOCH)?;
        let frac = (self.fraction as f64) / (u32::MAX as f64 + 1.0);
        Some(secs as f64 + frac)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn leap_indicator_decoding() {
        assert_eq!(NtpLeapIndicator::from_raw(0), NtpLeapIndicator::NoWarning);
        assert_eq!(NtpLeapIndicator::from_raw(1), NtpLeapIndicator::AddSecond);
        assert_eq!(
            NtpLeapIndicator::from_raw(2),
            NtpLeapIndicator::DeleteSecond
        );
        assert_eq!(
            NtpLeapIndicator::from_raw(3),
            NtpLeapIndicator::Unsynchronised
        );
        // Upper bits are masked off.
        assert_eq!(
            NtpLeapIndicator::from_raw(0xfc | 1),
            NtpLeapIndicator::AddSecond
        );
    }

    #[test]
    fn mode_round_trip_u8() {
        for n in 0..=7u8 {
            let mode = NtpMode::from_raw(n);
            assert_eq!(mode.as_u8(), n);
        }
    }

    #[test]
    fn mode_slugs_locked() {
        assert_eq!(NtpMode::Client.as_str(), "client");
        assert_eq!(NtpMode::Server.as_str(), "server");
        assert_eq!(NtpMode::Control.as_str(), "control");
        assert_eq!(NtpMode::Private.as_str(), "private");
    }

    #[test]
    fn amplification_predicate_fires_on_modes_6_and_7() {
        let mut m = NtpMessage {
            leap: NtpLeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay_raw: 0,
            root_dispersion_raw: 0,
            ref_id: [0; 4],
            ref_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            recv_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        };
        assert!(!m.is_amplification_risk());
        m.mode = NtpMode::Control;
        assert!(m.is_amplification_risk());
        m.mode = NtpMode::Private;
        assert!(m.is_amplification_risk());
    }

    #[test]
    fn ref_id_decodes_as_ipv4_when_stratum_high() {
        let m = NtpMessage {
            stratum: 3,
            ref_id: [10, 0, 0, 1],
            ..nz()
        };
        assert_eq!(m.ref_id_as_ipv4(), Some(Ipv4Addr::new(10, 0, 0, 1)));
        assert_eq!(m.ref_id_as_str(), None);
    }

    #[test]
    fn ref_id_decodes_as_string_at_stratum_one() {
        let m = NtpMessage {
            stratum: 1,
            ref_id: *b"GPS\0",
            ..nz()
        };
        assert_eq!(m.ref_id_as_str(), Some("GPS"));
        assert_eq!(m.ref_id_as_ipv4(), None);
    }

    #[test]
    fn ntp_timestamp_unix_epoch_offset() {
        // NTP epoch = 1900-01-01 → Unix epoch = 1970-01-01.
        // Diff = 2_208_988_800 seconds.
        let ts = NtpTimestamp {
            seconds: REF_TIMESTAMP_EPOCH,
            fraction: 0,
        };
        assert_eq!(ts.to_unix_f64(), Some(0.0));
        let ts = NtpTimestamp {
            seconds: REF_TIMESTAMP_EPOCH + 3600,
            fraction: 0,
        };
        assert_eq!(ts.to_unix_f64(), Some(3600.0));
    }

    #[test]
    fn ntp_timestamp_zero_returns_none() {
        let ts = NtpTimestamp::default();
        assert!(ts.is_zero());
        assert_eq!(ts.to_unix_f64(), None);
    }

    /// Test helper: NtpMessage with the non-tested fields zeroed.
    fn nz() -> NtpMessage {
        NtpMessage {
            leap: NtpLeapIndicator::NoWarning,
            version: 4,
            mode: NtpMode::Client,
            stratum: 0,
            poll: 0,
            precision: 0,
            root_delay_raw: 0,
            root_dispersion_raw: 0,
            ref_id: [0; 4],
            ref_timestamp: NtpTimestamp::default(),
            origin_timestamp: NtpTimestamp::default(),
            recv_timestamp: NtpTimestamp::default(),
            transmit_timestamp: NtpTimestamp::default(),
        }
    }
}
