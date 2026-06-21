//! Public types for the STUN parser.

use std::net::SocketAddr;

/// One parsed STUN datagram.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct StunMessage {
    /// Message class (request / indication / success / error).
    pub class: StunClass,
    /// 12-bit method (Binding = 1, TURN allocations etc. as
    /// Other(u16) when not the standard Binding).
    pub method: u16,
    /// 96-bit transaction identifier (12 raw bytes).
    pub transaction_id: [u8; 12],
    /// Decoded MAPPED-ADDRESS / XOR-MAPPED-ADDRESS. The
    /// XOR variant is normalized back to the cleartext
    /// address.
    pub mapped_address: Option<SocketAddr>,
    /// USERNAME attribute value (UTF-8 lossy decoded).
    pub username: Option<String>,
    /// SOFTWARE attribute — vendor banner.
    pub software: Option<String>,
}

/// RFC 5389 §6 message class.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum StunClass {
    Request,
    Indication,
    SuccessResponse,
    ErrorResponse,
}

impl StunClass {
    /// Decode the 2-bit class field embedded in the message
    /// type per RFC 5389 §6 (bits C0 and C1).
    pub fn from_type_bits(type_word: u16) -> Self {
        // Class bits are at positions 4 (C0) and 8 (C1).
        let c0 = (type_word >> 4) & 0x01;
        let c1 = (type_word >> 8) & 0x01;
        match (c1, c0) {
            (0, 0) => Self::Request,
            (0, 1) => Self::Indication,
            (1, 0) => Self::SuccessResponse,
            (1, 1) => Self::ErrorResponse,
            _ => unreachable!(),
        }
    }

    /// Stable slug for metric labels / logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Request => "request",
            Self::Indication => "indication",
            Self::SuccessResponse => "success_response",
            Self::ErrorResponse => "error_response",
        }
    }
}

/// Extract the 12-bit method per RFC 5389 §6.
pub(crate) fn extract_method(type_word: u16) -> u16 {
    // Method bits are at positions 0..4, 5..8, 9..14 (12 bits total,
    // interleaved with the class bits).
    let m0 = type_word & 0x000f;
    let m4 = (type_word >> 5) & 0x0007; // 3 bits
    let m7 = (type_word >> 9) & 0x001f; // 5 bits
    (m7 << 7) | (m4 << 4) | m0
}
