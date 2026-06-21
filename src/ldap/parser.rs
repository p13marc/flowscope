//! LDAP wire decoder.

use ldap_parser::ldap::{AuthenticationChoice, ProtocolOp};
#[allow(deprecated)]
use ldap_parser::parse_ldap_message;

use super::types::{LdapAuthKind, LdapMessage, LdapOperation, LdapResultCode, LdapSearchScope};

pub const PARSER_KIND_STR: &str = "ldap";

pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

const SPN_ATTRIBUTE_LOWER: &str = "serviceprincipalname";

/// Failure mode for [`parse`] / [`parse_with_len`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// The rusticata ASN.1 decoder failed — buffer didn't
    /// begin with a valid LDAPMessage SEQUENCE, or the
    /// SEQUENCE contained malformed fields.
    AsnDecode,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::AsnDecode => f.write_str("LDAP ASN.1 decode failed"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Decode one LDAP message from the front of `payload`.
pub fn parse(payload: &[u8]) -> Result<LdapMessage, ParseError> {
    #[allow(deprecated)]
    let (_, msg) = parse_ldap_message(payload).map_err(|_| ParseError::AsnDecode)?;
    Ok(from_parsed(&msg))
}

/// Decode one LDAP message AND report how many bytes the
/// LDAPMessage actually consumed, so a streaming session
/// parser can advance past it.
pub fn parse_with_len(payload: &[u8]) -> Result<(LdapMessage, usize), ParseError> {
    #[allow(deprecated)]
    let (rest, msg) = parse_ldap_message(payload).map_err(|_| ParseError::AsnDecode)?;
    let consumed = payload.len() - rest.len();
    Ok((from_parsed(&msg), consumed))
}

fn from_parsed(msg: &ldap_parser::ldap::LdapMessage<'_>) -> LdapMessage {
    let op = classify_op(&msg.protocol_op);
    let mut out = LdapMessage::new(msg.message_id.0, op);
    match &msg.protocol_op {
        ProtocolOp::BindRequest(req) => {
            out.bind_name = Some(req.name.0.to_string());
            out.bind_auth_kind = Some(match &req.authentication {
                AuthenticationChoice::Simple(creds) => LdapAuthKind::Simple {
                    creds_present: !creds.is_empty(),
                },
                AuthenticationChoice::Sasl(sasl) => LdapAuthKind::Sasl {
                    mechanism: sasl.mechanism.0.to_string(),
                },
            });
        }
        ProtocolOp::BindResponse(rep) => {
            out.result_code = Some(LdapResultCode::from_raw(rep.result.result_code.0));
            out.result_matched_dn = Some(rep.result.matched_dn.0.to_string());
        }
        ProtocolOp::SearchRequest(req) => {
            out.search_base = Some(req.base_object.0.to_string());
            out.search_scope = Some(LdapSearchScope::from_raw(req.scope.0));
            out.search_attributes = req.attributes.iter().map(|a| a.0.to_string()).collect();
            out.search_attributes_spn_query = out
                .search_attributes
                .iter()
                .any(|a| a.eq_ignore_ascii_case(SPN_ATTRIBUTE_LOWER));
        }
        ProtocolOp::SearchResultDone(result)
        | ProtocolOp::AddResponse(result)
        | ProtocolOp::DelResponse(result)
        | ProtocolOp::ModDnResponse(result)
        | ProtocolOp::CompareResponse(result) => {
            out.result_code = Some(LdapResultCode::from_raw(result.result_code.0));
            out.result_matched_dn = Some(result.matched_dn.0.to_string());
        }
        ProtocolOp::ModifyResponse(rep) => {
            out.result_code = Some(LdapResultCode::from_raw(rep.result.result_code.0));
            out.result_matched_dn = Some(rep.result.matched_dn.0.to_string());
        }
        ProtocolOp::ExtendedResponse(rep) => {
            out.result_code = Some(LdapResultCode::from_raw(rep.result.result_code.0));
            out.result_matched_dn = Some(rep.result.matched_dn.0.to_string());
        }
        _ => {}
    }
    out
}

fn classify_op(op: &ProtocolOp<'_>) -> LdapOperation {
    use LdapOperation as O;
    use ProtocolOp as P;
    match op {
        P::BindRequest(_) => O::BindRequest,
        P::BindResponse(_) => O::BindResponse,
        P::UnbindRequest => O::UnbindRequest,
        P::SearchRequest(_) => O::SearchRequest,
        P::SearchResultEntry(_) => O::SearchResultEntry,
        P::SearchResultDone(_) => O::SearchResultDone,
        P::SearchResultReference(_) => O::SearchResultReference,
        P::ModifyRequest(_) => O::ModifyRequest,
        P::ModifyResponse(_) => O::ModifyResponse,
        P::AddRequest(_) => O::AddRequest,
        P::AddResponse(_) => O::AddResponse,
        P::DelRequest(_) => O::DelRequest,
        P::DelResponse(_) => O::DelResponse,
        P::ModDnRequest(_) => O::ModDnRequest,
        P::ModDnResponse(_) => O::ModDnResponse,
        P::CompareRequest(_) => O::CompareRequest,
        P::CompareResponse(_) => O::CompareResponse,
        P::AbandonRequest(_) => O::AbandonRequest,
        P::ExtendedRequest(_) => O::ExtendedRequest,
        P::ExtendedResponse(_) => O::ExtendedResponse,
        P::IntermediateResponse(_) => O::IntermediateResponse,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_simple_bind_request_anonymous() {
        // LDAPMessage SEQUENCE { messageID 1, BindRequest {
        //   version 3, name "", authentication: Simple "" } }
        // Hand-crafted minimal BER.
        // 30 0c 02 01 01 60 07 02 01 03 04 00 80 00
        // SEQ(12) INT(1)=1 [APP 0]BindReq(7) INT(1)=3 OCTSTR(0)
        // [0]Simple(0) (empty)
        let buf = [
            0x30, 0x0C, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00,
        ];
        let msg = parse(&buf).expect("parse");
        assert_eq!(msg.message_id, 1);
        assert_eq!(msg.operation, LdapOperation::BindRequest);
        assert_eq!(
            msg.bind_auth_kind,
            Some(LdapAuthKind::Simple {
                creds_present: false
            })
        );
    }

    #[test]
    fn rejects_garbage() {
        assert_eq!(parse(&[]).unwrap_err(), ParseError::AsnDecode);
        assert_eq!(parse(&[0xFF; 8]).unwrap_err(), ParseError::AsnDecode);
    }

    #[test]
    fn operation_slugs_stable() {
        assert_eq!(LdapOperation::BindRequest.as_str(), "bind_request");
        assert_eq!(LdapOperation::SearchRequest.as_str(), "search_request");
        assert_eq!(
            LdapOperation::SearchResultDone.as_str(),
            "search_result_done"
        );
        assert_eq!(LdapOperation::Unknown(99).as_str(), "unknown");
    }
}
