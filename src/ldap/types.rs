//! Public LDAP message types.

/// LDAP protocol operation kind — matches the
/// `ProtocolOp` tag from RFC 4511. We don't carry the
/// per-op payload (rusticata's `ProtocolOp` enum borrows
/// from the wire buffer); the `LdapMessage` flattens the
/// fields we care about.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LdapOperation {
    BindRequest,
    BindResponse,
    UnbindRequest,
    SearchRequest,
    SearchResultEntry,
    SearchResultDone,
    SearchResultReference,
    ModifyRequest,
    ModifyResponse,
    AddRequest,
    AddResponse,
    DelRequest,
    DelResponse,
    ModDnRequest,
    ModDnResponse,
    CompareRequest,
    CompareResponse,
    AbandonRequest,
    ExtendedRequest,
    ExtendedResponse,
    IntermediateResponse,
    Unknown(u32),
}

impl LdapOperation {
    /// Stable lowercase slug for metric labels / log fields.
    pub fn as_str(&self) -> &'static str {
        match self {
            LdapOperation::BindRequest => "bind_request",
            LdapOperation::BindResponse => "bind_response",
            LdapOperation::UnbindRequest => "unbind_request",
            LdapOperation::SearchRequest => "search_request",
            LdapOperation::SearchResultEntry => "search_result_entry",
            LdapOperation::SearchResultDone => "search_result_done",
            LdapOperation::SearchResultReference => "search_result_reference",
            LdapOperation::ModifyRequest => "modify_request",
            LdapOperation::ModifyResponse => "modify_response",
            LdapOperation::AddRequest => "add_request",
            LdapOperation::AddResponse => "add_response",
            LdapOperation::DelRequest => "del_request",
            LdapOperation::DelResponse => "del_response",
            LdapOperation::ModDnRequest => "mod_dn_request",
            LdapOperation::ModDnResponse => "mod_dn_response",
            LdapOperation::CompareRequest => "compare_request",
            LdapOperation::CompareResponse => "compare_response",
            LdapOperation::AbandonRequest => "abandon_request",
            LdapOperation::ExtendedRequest => "extended_request",
            LdapOperation::ExtendedResponse => "extended_response",
            LdapOperation::IntermediateResponse => "intermediate_response",
            LdapOperation::Unknown(_) => "unknown",
        }
    }
}

/// LDAP search scope per RFC 4511 §4.5.1.2.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LdapSearchScope {
    BaseObject,
    SingleLevel,
    WholeSubtree,
    Other(u32),
}

impl LdapSearchScope {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::BaseObject,
            1 => Self::SingleLevel,
            2 => Self::WholeSubtree,
            other => Self::Other(other),
        }
    }
    pub fn as_raw(&self) -> u32 {
        match self {
            Self::BaseObject => 0,
            Self::SingleLevel => 1,
            Self::WholeSubtree => 2,
            Self::Other(v) => *v,
        }
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::BaseObject => "base_object",
            Self::SingleLevel => "single_level",
            Self::WholeSubtree => "whole_subtree",
            Self::Other(_) => "other",
        }
    }
}

impl std::fmt::Display for LdapSearchScope {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// LDAP `resultCode` per RFC 4511 §4.1.9.
///
/// Only the most operationally-relevant codes are spelled out
/// — the rest fall through to [`Self::Other`] preserving the
/// raw value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LdapResultCode {
    Success,
    OperationsError,
    ProtocolError,
    TimeLimitExceeded,
    SizeLimitExceeded,
    StrongerAuthRequired,
    Referral,
    NoSuchObject,
    InvalidDnSyntax,
    InvalidCredentials,
    InsufficientAccessRights,
    Busy,
    Unavailable,
    UnwillingToPerform,
    Other(u32),
}

impl LdapResultCode {
    pub fn from_raw(raw: u32) -> Self {
        match raw {
            0 => Self::Success,
            1 => Self::OperationsError,
            2 => Self::ProtocolError,
            3 => Self::TimeLimitExceeded,
            4 => Self::SizeLimitExceeded,
            8 => Self::StrongerAuthRequired,
            10 => Self::Referral,
            32 => Self::NoSuchObject,
            34 => Self::InvalidDnSyntax,
            49 => Self::InvalidCredentials,
            50 => Self::InsufficientAccessRights,
            51 => Self::Busy,
            52 => Self::Unavailable,
            53 => Self::UnwillingToPerform,
            other => Self::Other(other),
        }
    }
    pub fn as_raw(&self) -> u32 {
        match self {
            Self::Success => 0,
            Self::OperationsError => 1,
            Self::ProtocolError => 2,
            Self::TimeLimitExceeded => 3,
            Self::SizeLimitExceeded => 4,
            Self::StrongerAuthRequired => 8,
            Self::Referral => 10,
            Self::NoSuchObject => 32,
            Self::InvalidDnSyntax => 34,
            Self::InvalidCredentials => 49,
            Self::InsufficientAccessRights => 50,
            Self::Busy => 51,
            Self::Unavailable => 52,
            Self::UnwillingToPerform => 53,
            Self::Other(v) => *v,
        }
    }
    pub fn is_success(&self) -> bool {
        matches!(self, Self::Success)
    }
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::OperationsError => "operations_error",
            Self::ProtocolError => "protocol_error",
            Self::TimeLimitExceeded => "time_limit_exceeded",
            Self::SizeLimitExceeded => "size_limit_exceeded",
            Self::StrongerAuthRequired => "stronger_auth_required",
            Self::Referral => "referral",
            Self::NoSuchObject => "no_such_object",
            Self::InvalidDnSyntax => "invalid_dn_syntax",
            Self::InvalidCredentials => "invalid_credentials",
            Self::InsufficientAccessRights => "insufficient_access_rights",
            Self::Busy => "busy",
            Self::Unavailable => "unavailable",
            Self::UnwillingToPerform => "unwilling_to_perform",
            Self::Other(_) => "other",
        }
    }
}

impl std::fmt::Display for LdapResultCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// LDAP Bind authentication choice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum LdapAuthKind {
    /// `Simple` bind — cleartext password (or empty for
    /// anonymous bind). `creds_present` is `true` when the
    /// credentials octet string was non-empty.
    Simple { creds_present: bool },
    /// `SASL` bind — `mechanism` is the SASL mechanism
    /// identifier (e.g. `"GSSAPI"`, `"GSS-SPNEGO"`).
    Sasl { mechanism: String },
}

/// One decoded LDAP message.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LdapMessage {
    pub message_id: u32,
    pub operation: LdapOperation,

    pub bind_name: Option<String>,
    pub bind_auth_kind: Option<LdapAuthKind>,

    pub search_base: Option<String>,
    pub search_scope: Option<LdapSearchScope>,
    /// Requested attribute list.
    pub search_attributes: Vec<String>,
    /// `true` when the requested attribute list includes
    /// `servicePrincipalName` (Kerberoast / BloodHound
    /// enumeration signal).
    pub search_attributes_spn_query: bool,

    /// LDAP `resultCode` on response operations. `None`
    /// on requests / non-result ops.
    pub result_code: Option<LdapResultCode>,
    /// Matched DN on response operations (where present).
    pub result_matched_dn: Option<String>,
}

impl LdapMessage {
    /// Construct a request shell with operation + message_id.
    pub(crate) fn new(message_id: u32, operation: LdapOperation) -> Self {
        Self {
            message_id,
            operation,
            bind_name: None,
            bind_auth_kind: None,
            search_base: None,
            search_scope: None,
            search_attributes: Vec::new(),
            search_attributes_spn_query: false,
            result_code: None,
            result_matched_dn: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn search_scope_round_trip_canonical() {
        for raw in [0u32, 1, 2, 99] {
            assert_eq!(LdapSearchScope::from_raw(raw).as_raw(), raw);
        }
        assert_eq!(LdapSearchScope::from_raw(0), LdapSearchScope::BaseObject);
        assert_eq!(LdapSearchScope::from_raw(2), LdapSearchScope::WholeSubtree);
        assert!(matches!(
            LdapSearchScope::from_raw(99),
            LdapSearchScope::Other(99)
        ));
    }

    #[test]
    fn result_code_round_trip_named_variants() {
        let cases = [0u32, 1, 2, 8, 10, 32, 34, 49, 50, 51, 52, 53, 1234];
        for raw in cases {
            assert_eq!(LdapResultCode::from_raw(raw).as_raw(), raw);
        }
        assert!(LdapResultCode::from_raw(0).is_success());
        assert!(!LdapResultCode::from_raw(49).is_success());
        assert_eq!(
            LdapResultCode::from_raw(49),
            LdapResultCode::InvalidCredentials
        );
        assert_eq!(
            LdapResultCode::from_raw(50),
            LdapResultCode::InsufficientAccessRights
        );
    }
}
