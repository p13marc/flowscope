//! Public types for the SNMP parser.

/// One parsed SNMP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SnmpMessage {
    pub version: SnmpVersion,
    /// Community string (UTF-8 lossy) — cleartext
    /// credential. Common defaults: `"public"` (RO),
    /// `"private"` (RW).
    pub community: String,
    pub pdu_kind: SnmpPduKind,
    /// Request / response correlation ID (v1/v2c). `0` if
    /// the PDU doesn't carry one (rare; mostly v1 Trap).
    pub request_id: i32,
    /// Variable-binding OIDs as dotted-decimal strings,
    /// e.g. `"1.3.6.1.2.1.1.1.0"`. Empty for malformed
    /// PDUs.
    pub varbind_oids: Vec<String>,
}

/// SNMP protocol version per the ASN.1 INTEGER tag in the
/// outer SEQUENCE.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SnmpVersion {
    /// 0 — SNMPv1 (RFC 1157).
    V1,
    /// 1 — SNMPv2c (RFC 1905).
    V2c,
    /// 3 — SNMPv3 (RFC 3411 series). The parser does NOT
    /// decode v3 messages (USM + privacy encryption); this
    /// variant surfaces only the wire-version field.
    V3,
    Other(i64),
}

/// SNMP PDU type vocabulary per RFC 1905.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum SnmpPduKind {
    GetRequest,
    GetNextRequest,
    GetResponse,
    SetRequest,
    GetBulkRequest,
    InformRequest,
    /// v1 Trap (RFC 1157, distinct from TrapV2).
    TrapV1,
    /// v2c+ Trap (RFC 1905 §3.3).
    TrapV2,
    Report,
    Other,
}

impl SnmpPduKind {
    /// Stable slug for metric labels / logs.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::GetRequest => "get_request",
            Self::GetNextRequest => "get_next_request",
            Self::GetResponse => "get_response",
            Self::SetRequest => "set_request",
            Self::GetBulkRequest => "get_bulk_request",
            Self::InformRequest => "inform_request",
            Self::TrapV1 => "trap_v1",
            Self::TrapV2 => "trap_v2",
            Self::Report => "report",
            Self::Other => "other",
        }
    }
}
