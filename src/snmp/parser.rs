//! SNMP wire-format parsing via the rusticata snmp-parser.

use super::types::{SnmpMessage, SnmpPduKind, SnmpVersion};

/// Parse one SNMP UDP datagram. Returns `None` on malformed
/// input (ASN.1 BER failure, truncated payload, unknown
/// version).
pub fn parse(payload: &[u8]) -> Option<SnmpMessage> {
    // snmp-parser exposes `parse_snmp_generic_message` which
    // handles v1/v2c/v3 outer envelopes. We dispatch on the
    // version it returns.
    let (_rem, generic) = snmp_parser::parse_snmp_generic_message(payload).ok()?;
    match generic {
        snmp_parser::SnmpGenericMessage::V1(msg) | snmp_parser::SnmpGenericMessage::V2(msg) => {
            decode_v1_v2c(msg)
        }
        snmp_parser::SnmpGenericMessage::V3(msg) => Some(SnmpMessage {
            version: SnmpVersion::V3,
            community: String::new(),
            pdu_kind: SnmpPduKind::Other,
            request_id: msg.header_data.msg_id as i32,
            varbind_oids: Vec::new(),
        }),
    }
}

fn decode_v1_v2c(msg: snmp_parser::SnmpMessage<'_>) -> Option<SnmpMessage> {
    let version = match msg.version {
        0 => SnmpVersion::V1,
        1 => SnmpVersion::V2c,
        n => SnmpVersion::Other(n as i64),
    };
    let community = msg.community.clone();

    let (pdu_kind, request_id, varbind_oids) = match &msg.pdu {
        snmp_parser::SnmpPdu::Generic(g) => (
            map_pdu_type(g.pdu_type),
            g.req_id as i32,
            g.var.iter().map(|v| v.oid.to_id_string()).collect(),
        ),
        snmp_parser::SnmpPdu::Bulk(b) => (
            SnmpPduKind::GetBulkRequest,
            b.req_id as i32,
            b.var.iter().map(|v| v.oid.to_id_string()).collect(),
        ),
        snmp_parser::SnmpPdu::TrapV1(t) => (
            SnmpPduKind::TrapV1,
            0,
            t.var.iter().map(|v| v.oid.to_id_string()).collect(),
        ),
    };

    Some(SnmpMessage {
        version,
        community,
        pdu_kind,
        request_id,
        varbind_oids,
    })
}

fn map_pdu_type(t: snmp_parser::PduType) -> SnmpPduKind {
    use snmp_parser::PduType;
    match t {
        PduType::GetRequest => SnmpPduKind::GetRequest,
        PduType::GetNextRequest => SnmpPduKind::GetNextRequest,
        PduType::Response => SnmpPduKind::GetResponse,
        PduType::SetRequest => SnmpPduKind::SetRequest,
        PduType::GetBulkRequest => SnmpPduKind::GetBulkRequest,
        PduType::InformRequest => SnmpPduKind::InformRequest,
        PduType::TrapV2 => SnmpPduKind::TrapV2,
        PduType::Report => SnmpPduKind::Report,
        _ => SnmpPduKind::Other,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // RFC 1157 §A.2 GetRequest example, hex-edited to use
    // community "public" and OID 1.3.6.1.2.1.1.1.0
    // (sysDescr.0).
    //
    // Generated via `snmpget -v 1 -c public 127.0.0.1
    // 1.3.6.1.2.1.1.1.0` and captured. Reproduced here as
    // a constant so the test is hermetic.
    const SAMPLE_V1_GETREQUEST: &[u8] = &[
        0x30, 0x29, 0x02, 0x01, 0x00, // SEQUENCE | version INTEGER 0 (v1)
        0x04, 0x06, b'p', b'u', b'b', b'l', b'i', b'c', // community
        0xa0, 0x1c, // GetRequest [0]
        0x02, 0x04, 0x12, 0x34, 0x56, 0x78, // request-id 0x12345678
        0x02, 0x01, 0x00, // error-status 0
        0x02, 0x01, 0x00, // error-index 0
        0x30, 0x0e, // var-bindings SEQUENCE OF
        0x30, 0x0c, // var-bind SEQUENCE
        0x06, 0x08, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, // OID 1.3.6.1.2.1.1.1.0
        0x05, 0x00, // value NULL
    ];

    #[test]
    fn parses_v1_get_request() {
        let msg = parse(SAMPLE_V1_GETREQUEST).expect("parse");
        assert_eq!(msg.version, SnmpVersion::V1);
        assert_eq!(msg.community, "public");
        assert_eq!(msg.pdu_kind, SnmpPduKind::GetRequest);
        assert_eq!(msg.request_id, 0x12345678);
        assert_eq!(msg.varbind_oids.len(), 1);
        assert_eq!(msg.varbind_oids[0], "1.3.6.1.2.1.1.1.0");
    }

    #[test]
    fn rejects_truncated_payload() {
        assert!(parse(&SAMPLE_V1_GETREQUEST[..5]).is_none());
    }

    #[test]
    fn rejects_non_snmp_payload() {
        assert!(parse(b"this is not SNMP").is_none());
    }

    #[test]
    fn pdu_kind_slugs_match() {
        assert_eq!(SnmpPduKind::GetRequest.as_str(), "get_request");
        assert_eq!(SnmpPduKind::GetResponse.as_str(), "get_response");
        assert_eq!(SnmpPduKind::TrapV2.as_str(), "trap_v2");
        assert_eq!(SnmpPduKind::GetBulkRequest.as_str(), "get_bulk_request");
        assert_eq!(SnmpPduKind::Report.as_str(), "report");
    }
}
