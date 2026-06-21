//! Public types for NetBIOS Name Service.

use std::net::Ipv4Addr;

use smallvec::SmallVec;

/// One parsed NetBIOS Name Service message. Fields are
/// populated on best-effort — the question section is
/// always decoded if present; the answer section is walked
/// only for the first NB resource record.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NbnsMessage {
    /// RFC 1002 §4.2.1.1 `NAME_TRN_ID` — for query/response
    /// correlation.
    pub transaction_id: u16,
    /// Decoded `OPCODE` field.
    pub opcode: NbnsOpcode,
    /// `true` when the QR bit is set in the flags word.
    pub is_response: bool,
    /// The first question's NetBIOS name, decoded from the
    /// 32-byte "compressed" form, whitespace-trimmed, with
    /// the trailing suffix byte stripped. `None` when no
    /// question is present or the encoding was malformed.
    pub queried_name: Option<String>,
    /// The suffix byte (last raw byte of the NetBIOS name).
    /// `0x00` = workstation, `0x20` = file server, `0x03` =
    /// messenger, `0x1d` = master browser, etc. `None` when
    /// `queried_name` is `None`.
    pub name_suffix: Option<u8>,
    /// IPv4 addresses carried in `NB` (type 0x0020) resource
    /// records in the answer section. Empty for queries and
    /// for responses whose answer section was not parseable.
    /// SmallVec inline 1 — modal case is a single A record.
    pub answer_addresses: SmallVec<[Ipv4Addr; 1]>,
}

/// RFC 1002 §4.2.1.1 OPCODE vocabulary.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum NbnsOpcode {
    /// 0 — name query.
    Query,
    /// 5 — name registration.
    Registration,
    /// 6 — name release.
    Release,
    /// 7 — "wait for acknowledgement" (server-to-client).
    Wack,
    /// 8 — name refresh.
    Refresh,
    /// Any opcode not in the standard vocabulary. The numeric
    /// value is preserved.
    Other(u8),
}

impl NbnsOpcode {
    pub(crate) fn from_bits(opcode: u8) -> Self {
        match opcode {
            0 => Self::Query,
            5 => Self::Registration,
            6 => Self::Release,
            7 => Self::Wack,
            8 => Self::Refresh,
            n => Self::Other(n),
        }
    }

    /// Stable slug used for metric labels / log filtering.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Query => "query",
            Self::Registration => "registration",
            Self::Release => "release",
            Self::Wack => "wack",
            Self::Refresh => "refresh",
            Self::Other(_) => "other",
        }
    }
}
