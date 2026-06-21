//! Kerberos wire decoder — peek at the outer
//! APPLICATION-tagged byte and dispatch to the rusticata
//! `kerberos-parser` parse function.

use kerberos_parser::krb5::{KdcRep, KdcReq, KrbError};
use kerberos_parser::krb5_parser as kp;

use super::types::{KerberosEtype, KerberosMessage, KerberosMessageKind};

pub const PARSER_KIND_STR: &str = "kerberos";

/// Parser kind for the slot / event vocabulary.
pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

/// Decode one Kerberos message from the front of `payload`.
/// Returns `None` if the outer tag isn't a known Kerberos
/// message or the ASN.1 decode fails.
pub fn parse(payload: &[u8]) -> Option<KerberosMessage> {
    // Kerberos messages start with a constructed
    // application-class ASN.1 tag (binary 01_1x_xxxx with
    // the constructed bit set). APP tags 10..=15 map to
    // 0x6A..=0x6F; APP tag 30 (KRB-ERROR) maps to 0x7E.
    let first = *payload.first()?;
    match first {
        0x6A => {
            let (_, req) = kp::parse_as_req(payload).ok()?;
            Some(from_kdc_req(req, KerberosMessageKind::AsReq))
        }
        0x6B => {
            let (_, rep) = kp::parse_as_rep(payload).ok()?;
            Some(from_kdc_rep(rep, KerberosMessageKind::AsRep))
        }
        0x6C => {
            let (_, req) = kp::parse_tgs_req(payload).ok()?;
            Some(from_kdc_req(req, KerberosMessageKind::TgsReq))
        }
        0x6D => {
            let (_, rep) = kp::parse_tgs_rep(payload).ok()?;
            Some(from_kdc_rep(rep, KerberosMessageKind::TgsRep))
        }
        0x6E => Some(simple_ap_message(KerberosMessageKind::ApReq)),
        0x6F => Some(simple_ap_message(KerberosMessageKind::ApRep)),
        0x7E => {
            #[allow(deprecated)]
            let (_, err): (_, KrbError<'_>) = kp::parse_krb_error(payload).ok()?;
            Some(from_krb_error(err))
        }
        _ => None,
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
    msg.error_code = Some(err.error_code.0);
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
        assert!(parse(&[0x00]).is_none());
        assert!(parse(&[]).is_none());
        // 0x6A is AS-REQ but the body is bogus; should return
        // None from the rusticata parse error.
        assert!(parse(&[0x6A, 0x01, 0x00]).is_none());
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
