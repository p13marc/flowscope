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
    /// 0 = baseObject, 1 = singleLevel, 2 = wholeSubtree.
    pub search_scope: Option<u32>,
    /// Requested attribute list.
    pub search_attributes: Vec<String>,
    /// `true` when the requested attribute list includes
    /// `servicePrincipalName` (Kerberoast / BloodHound
    /// enumeration signal).
    pub search_attributes_spn_query: bool,

    /// LDAP `resultCode` on response operations. `None`
    /// on requests / non-result ops.
    pub result_code: Option<u32>,
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
