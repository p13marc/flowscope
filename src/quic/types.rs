//! Public QUIC message types.

/// One decoded QUIC Initial packet with its TLS ClientHello
/// extracted.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct QuicInitial {
    /// QUIC version number (e.g. `0x00000001` = v1 / RFC 9000,
    /// `0x6b3343cf` = v2 / RFC 9369).
    pub version: u32,
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
}
