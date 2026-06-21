//! Kerberos wire decoder — peek at the outer
//! APPLICATION-tagged byte and dispatch to the rusticata
//! `kerberos-parser` parse function.

use kerberos_parser::krb5::{KdcRep, KdcReq, KrbError};
use kerberos_parser::krb5_parser as kp;

use super::types::{KerberosErrorCode, KerberosEtype, KerberosMessage, KerberosMessageKind};

pub const PARSER_KIND_STR: &str = "kerberos";

/// Parser kind for the slot / event vocabulary.
pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

/// Failure mode for [`parse`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Payload was empty — no outer ASN.1 tag byte.
    Empty,
    /// First byte wasn't a known Kerberos APPLICATION tag.
    /// Recognized tags: 0x6A..=0x6F (AS/TGS-REQ/REP, AP-REQ/REP)
    /// and 0x7E (KRB-ERROR).
    UnknownTag(u8),
    /// Outer tag was recognized but the rusticata ASN.1
    /// decoder failed on the body.
    AsnDecode,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Empty => f.write_str("empty payload"),
            Self::UnknownTag(b) => write!(f, "unknown Kerberos APPLICATION tag: 0x{b:02x}"),
            Self::AsnDecode => f.write_str("Kerberos ASN.1 decode failed"),
        }
    }
}

impl std::error::Error for ParseError {}

/// Decode one Kerberos message from the front of `payload`.
pub fn parse(payload: &[u8]) -> Result<KerberosMessage, ParseError> {
    // Kerberos messages start with a constructed
    // application-class ASN.1 tag (binary 01_1x_xxxx with
    // the constructed bit set). APP tags 10..=15 map to
    // 0x6A..=0x6F; APP tag 30 (KRB-ERROR) maps to 0x7E.
    let first = *payload.first().ok_or(ParseError::Empty)?;
    match first {
        0x6A => {
            let (_, req) = kp::parse_as_req(payload).map_err(|_| ParseError::AsnDecode)?;
            Ok(from_kdc_req(req, KerberosMessageKind::AsReq))
        }
        0x6B => {
            let (_, rep) = kp::parse_as_rep(payload).map_err(|_| ParseError::AsnDecode)?;
            Ok(from_kdc_rep(rep, KerberosMessageKind::AsRep))
        }
        0x6C => {
            let (_, req) = kp::parse_tgs_req(payload).map_err(|_| ParseError::AsnDecode)?;
            Ok(from_kdc_req(req, KerberosMessageKind::TgsReq))
        }
        0x6D => {
            let (_, rep) = kp::parse_tgs_rep(payload).map_err(|_| ParseError::AsnDecode)?;
            Ok(from_kdc_rep(rep, KerberosMessageKind::TgsRep))
        }
        0x6E => Ok(simple_ap_message(KerberosMessageKind::ApReq)),
        0x6F => Ok(simple_ap_message(KerberosMessageKind::ApRep)),
        0x7E => {
            #[allow(deprecated)]
            let (_, err): (_, KrbError<'_>) =
                kp::parse_krb_error(payload).map_err(|_| ParseError::AsnDecode)?;
            Ok(from_krb_error(err))
        }
        other => Err(ParseError::UnknownTag(other)),
    }
}

fn from_kdc_req(req: KdcReq<'_>, kind: KerberosMessageKind) -> KerberosMessage {
    let realm = req.req_body.realm.0.clone();
    let mut msg = KerberosMessage::new(kind, req.pvno, realm);
    msg.cname = req.req_body.cname.as_ref().map(|p| p.name_string.join("/"));
    msg.sname = req.req_body.sname.as_ref().map(|p| p.name_string.join("/"));
    msg.etypes = req
        .req_body
        .etype
        .iter()
        .map(|e| KerberosEtype::from_raw(e.0))
        .collect();
    msg.padata_types = req.padata.iter().map(|p| p.padata_type.0).collect();
    msg.kerberoast_suspect =
        matches!(kind, KerberosMessageKind::TgsReq) && msg.etypes.iter().any(KerberosEtype::is_rc4);
    msg
}

fn from_kdc_rep(rep: KdcRep<'_>, kind: KerberosMessageKind) -> KerberosMessage {
    let realm = rep.crealm.0.clone();
    let mut msg = KerberosMessage::new(kind, rep.pvno, realm);
    msg.cname = Some(rep.cname.name_string.join("/"));
    msg.sname = Some(rep.ticket.sname.name_string.join("/"));
    msg.padata_types = rep.padata.iter().map(|p| p.padata_type.0).collect();
    msg
}

fn from_krb_error(err: KrbError<'_>) -> KerberosMessage {
    let realm = err.crealm.as_ref().map(|r| r.0.clone()).unwrap_or_default();
    let mut msg = KerberosMessage::new(KerberosMessageKind::KrbError, err.pvno, realm);
    msg.cname = err.cname.as_ref().map(|p| p.name_string.join("/"));
    msg.sname = Some(err.sname.name_string.join("/"));
    msg.error_code = Some(KerberosErrorCode::from_raw(err.error_code.0));
    msg
}

fn simple_ap_message(kind: KerberosMessageKind) -> KerberosMessage {
    KerberosMessage::new(kind, 5, String::new())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dispatcher_rejects_unknown_first_byte() {
        assert_eq!(parse(&[0x00]).unwrap_err(), ParseError::UnknownTag(0x00));
        assert_eq!(parse(&[]).unwrap_err(), ParseError::Empty);
        // 0x6A is AS-REQ but the body is bogus; rusticata
        // surfaces the AsnDecode variant.
        assert_eq!(
            parse(&[0x6A, 0x01, 0x00]).unwrap_err(),
            ParseError::AsnDecode
        );
    }

    #[test]
    fn ap_req_and_ap_rep_recognised_as_kind() {
        let req = parse(&[0x6E]).expect("ap_req");
        assert_eq!(req.kind, KerberosMessageKind::ApReq);
        let rep = parse(&[0x6F]).expect("ap_rep");
        assert_eq!(rep.kind, KerberosMessageKind::ApRep);
    }

    #[test]
    fn kind_as_str_stable() {
        assert_eq!(KerberosMessageKind::AsReq.as_str(), "as_req");
        assert_eq!(KerberosMessageKind::TgsRep.as_str(), "tgs_rep");
        assert_eq!(KerberosMessageKind::KrbError.as_str(), "krb_error");
        assert_eq!(KerberosMessageKind::Unknown(99).as_str(), "unknown");
    }
}
