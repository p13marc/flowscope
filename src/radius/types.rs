//! Public types for the RADIUS parser.

use std::net::Ipv4Addr;

/// One parsed RADIUS message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RadiusMessage {
    /// Decoded RFC 2865 §3 code.
    pub code: RadiusCodeKind,
    /// The 1-byte identifier — matches requests with their
    /// responses.
    pub identifier: u8,
    /// Authenticator length (always 16 octets — included
    /// for round-trip completeness).
    pub authenticator_len: usize,
    /// User-Name attribute (RFC 2865 §5.1). Cleartext.
    pub username: Option<String>,
    /// Calling-Station-Id (RFC 2865 §5.31) — typically a
    /// MAC address for wireless, or a calling phone number
    /// for dial-up. Cleartext.
    pub calling_station_id: Option<String>,
    /// Called-Station-Id (RFC 2865 §5.30) — typically NAS
    /// MAC + SSID for wireless.
    pub called_station_id: Option<String>,
    /// NAS-IP-Address (RFC 2865 §5.4) — the
    /// network-access-server's IP.
    pub nas_ip_address: Option<Ipv4Addr>,
    /// Framed-IP-Address (RFC 2865 §5.8) — the IP
    /// assigned to the user after authentication.
    pub framed_ip_address: Option<Ipv4Addr>,
    /// `true` when a User-Password attribute (RFC 2865
    /// §5.2) was present. The bytes are not surfaced —
    /// they're MD5(shared_secret || authenticator)-XOR'd
    /// per the RFC; cleartext recovery requires the
    /// shared secret which a passive observer doesn't
    /// have.
    pub has_user_password: bool,
}

/// RADIUS message code vocabulary per RFC 2865 §3.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RadiusCodeKind {
    AccessRequest,
    AccessAccept,
    AccessReject,
    AccessChallenge,
    AccountingRequest,
    AccountingResponse,
    StatusServer,
    StatusClient,
    Other(u8),
}

impl RadiusCodeKind {
    pub(crate) fn from_raw(code: u8) -> Self {
        match code {
            1 => Self::AccessRequest,
            2 => Self::AccessAccept,
            3 => Self::AccessReject,
            4 => Self::AccountingRequest,
            5 => Self::AccountingResponse,
            11 => Self::AccessChallenge,
            12 => Self::StatusServer,
            13 => Self::StatusClient,
            n => Self::Other(n),
        }
    }

    /// Stable slug for metric labels / logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::AccessRequest => "access_request",
            Self::AccessAccept => "access_accept",
            Self::AccessReject => "access_reject",
            Self::AccessChallenge => "access_challenge",
            Self::AccountingRequest => "accounting_request",
            Self::AccountingResponse => "accounting_response",
            Self::StatusServer => "status_server",
            Self::StatusClient => "status_client",
            Self::Other(_) => "other",
        }
    }
}
