//! Public types for the RDP X.224 negotiation parser.

use bitflags::bitflags;

/// One parsed RDP X.224 frame.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "event", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RdpMessage {
    /// X.224 Connection Request from the initiator. The
    /// `cookie_username` and `routing_token` come from the
    /// X.224 user-data area; the `requested_protocols` from
    /// the RDP Negotiation Request structure (when present).
    ConnectionRequest {
        cookie_username: Option<String>,
        routing_token: Option<String>,
        requested_protocols: Option<RdpProtocols>,
    },
    /// X.224 Connection Confirm from the responder.
    ConnectionConfirm {
        selected_protocol: Option<RdpProtocols>,
        negotiation_failure: Option<RdpFailureCode>,
    },
}

bitflags! {
    /// RDP negotiation `requestedProtocols` / `selectedProtocol`
    /// bitmask per MS-RDPBCGR §2.2.1.1.1 / §2.2.1.2.1.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct RdpProtocols: u32 {
        /// 0x00 — legacy Standard RDP Security (no SSL).
        const RDP = 0x00;
        /// 0x01 — TLS upgrade.
        const SSL = 0x01;
        /// 0x02 — CredSSP / NLA upgrade.
        const HYBRID = 0x02;
        /// 0x04 — RDSTLS (Remote Desktop STS).
        const RDSTLS = 0x04;
        /// 0x08 — CredSSP-Ex (Hybrid Ex).
        const HYBRID_EX = 0x08;
        /// 0x10 — RDSAAD (Remote Desktop with Azure AD).
        const RDSAAD = 0x10;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RdpProtocols {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RdpProtocols {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(RdpProtocols::from_bits_truncate(bits))
    }
}

/// RDP Negotiation Failure code (MS-RDPBCGR §2.2.1.2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RdpFailureCode {
    /// 1 — SSL_REQUIRED_BY_SERVER.
    SslRequiredByServer,
    /// 2 — SSL_NOT_ALLOWED_BY_SERVER.
    SslNotAllowedByServer,
    /// 3 — SSL_CERT_NOT_ON_SERVER.
    SslCertNotOnServer,
    /// 4 — INCONSISTENT_FLAGS.
    InconsistentFlags,
    /// 5 — HYBRID_REQUIRED_BY_SERVER.
    HybridRequiredByServer,
    /// 6 — SSL_WITH_USER_AUTH_REQUIRED_BY_SERVER.
    SslWithUserAuthRequiredByServer,
    Other(u32),
}

impl RdpFailureCode {
    pub fn from_raw(code: u32) -> Self {
        match code {
            1 => Self::SslRequiredByServer,
            2 => Self::SslNotAllowedByServer,
            3 => Self::SslCertNotOnServer,
            4 => Self::InconsistentFlags,
            5 => Self::HybridRequiredByServer,
            6 => Self::SslWithUserAuthRequiredByServer,
            n => Self::Other(n),
        }
    }
}
