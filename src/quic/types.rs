//! Public QUIC message types.

use std::fmt;

/// QUIC version, decoded from the long-header version
/// field. RFC-named versions get dedicated variants;
/// IETF drafts and unknowns preserve the raw u32 for
/// forensics.
///
/// **Why a typed enum:** routing decisions on
/// "is this RFC 9000 v1 traffic vs RFC 9369 v2 vs a
/// draft" are stronger than `version == 0x00000001`
/// magic-number checks at consumer call sites.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum QuicVersion {
    /// QUIC v1 — RFC 9000 (`0x00000001`).
    V1,
    /// QUIC v2 — RFC 9369 (`0x6b3343cf`).
    V2,
    /// IETF draft version (`0xff000000..=0xff00007f`).
    /// Carries the draft number (`raw & 0xFF`).
    Draft(u8),
    /// Any other version. Raw u32 preserved.
    Other(u32),
}

impl QuicVersion {
    /// Classify a raw u32 version.
    #[inline]
    pub fn from_raw(value: u32) -> Self {
        match value {
            0x0000_0001 => Self::V1,
            0x6b33_43cf => Self::V2,
            v if (0xff00_0000..=0xff00_007f).contains(&v) => Self::Draft((v & 0xff) as u8),
            other => Self::Other(other),
        }
    }

    /// Wire-format u32 version number.
    #[inline]
    pub fn as_u32(&self) -> u32 {
        match self {
            Self::V1 => 0x0000_0001,
            Self::V2 => 0x6b33_43cf,
            Self::Draft(n) => 0xff00_0000 | (*n as u32),
            Self::Other(v) => *v,
        }
    }

    /// `true` for the RFC-9000 standard version.
    #[inline]
    pub fn is_v1(&self) -> bool {
        matches!(self, Self::V1)
    }

    /// `true` for the RFC-9369 v2.
    #[inline]
    pub fn is_v2(&self) -> bool {
        matches!(self, Self::V2)
    }

    /// `true` for any IETF-draft version.
    #[inline]
    pub fn is_draft(&self) -> bool {
        matches!(self, Self::Draft(_))
    }
}

impl From<u32> for QuicVersion {
    #[inline]
    fn from(value: u32) -> Self {
        Self::from_raw(value)
    }
}

impl From<QuicVersion> for u32 {
    #[inline]
    fn from(value: QuicVersion) -> Self {
        value.as_u32()
    }
}

impl fmt::Display for QuicVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::V1 => f.write_str("v1"),
            Self::V2 => f.write_str("v2"),
            Self::Draft(n) => write!(f, "draft-{n:02}"),
            Self::Other(v) => write!(f, "0x{v:08x}"),
        }
    }
}

/// One decoded QUIC Initial packet with its TLS ClientHello
/// extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct QuicInitial {
    /// QUIC version. Use [`QuicVersion::is_v1`] /
    /// [`QuicVersion::is_v2`] for routing.
    pub version: QuicVersion,
    pub dcid: Vec<u8>,
    pub scid: Vec<u8>,
    /// `true` when a Retry token was attached.
    pub token_present: bool,
    /// Server Name Indication extracted from the TLS
    /// ClientHello extension. `None` when the ClientHello
    /// was present but lacked an SNI extension.
    pub sni: Option<String>,
    /// ALPN protocol identifiers from the TLS ClientHello
    /// extension (e.g. `["h3", "h3-29"]`). Empty when the
    /// extension was absent.
    pub alpn: Vec<String>,
    /// The full TLS ClientHello recovered from the Initial's
    /// CRYPTO stream — present only when the `tls` feature is also
    /// enabled (issue #82). Carries the cipher / extension /
    /// version lists JA4 needs; feed it to [`crate::tls::ja4_quic`]
    /// or use the [`crate::quic::ja4`] convenience. `None` when the
    /// CRYPTO stream held no parseable ClientHello.
    #[cfg(feature = "tls")]
    pub client_hello: Option<crate::tls::TlsClientHello>,
}
