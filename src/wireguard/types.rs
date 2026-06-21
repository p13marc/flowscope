//! Public types for the WireGuard detector.

/// One parsed WireGuard datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct WireGuardMessage {
    /// Decoded message type.
    pub kind: WireGuardKind,
    /// The sender's session index (handshake messages only;
    /// `None` for `CookieReply` and `TransportData` where
    /// only the receiver index is present).
    pub sender_index: Option<u32>,
    /// The receiver's session index (handshake response,
    /// cookie reply, transport data).
    pub receiver_index: Option<u32>,
    /// Encrypted-payload length for transport data; `None`
    /// for handshake messages.
    pub payload_length: Option<u32>,
}

/// WireGuard message-type vocabulary per Donenfeld 2017
/// (the WireGuard whitepaper) §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum WireGuardKind {
    /// Type 1 — initiator's Noise IK initiation. 148 bytes.
    HandshakeInitiation,
    /// Type 2 — responder's reply. 92 bytes.
    HandshakeResponse,
    /// Type 3 — DoS-mitigation cookie reply. 64 bytes.
    CookieReply,
    /// Type 4 — encrypted application data. 16 + N bytes.
    TransportData,
}

impl WireGuardKind {
    /// Stable label for metrics / logging.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::HandshakeInitiation => "handshake_initiation",
            Self::HandshakeResponse => "handshake_response",
            Self::CookieReply => "cookie_reply",
            Self::TransportData => "transport_data",
        }
    }

    /// `true` for handshake initiation / response. These two
    /// messages are the strongest passive WG signal.
    pub fn is_handshake(&self) -> bool {
        matches!(self, Self::HandshakeInitiation | Self::HandshakeResponse)
    }
}
