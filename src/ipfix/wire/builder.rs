//! [`MessageBuilder`] — assembles RFC 7011 IPFIX Messages.

use bytes::{BufMut, BytesMut};

use super::constants::{
    IPFIX_VERSION, MESSAGE_HEADER_LEN, SET_HEADER_LEN, SET_ID_TEMPLATE, TEMPLATE_HEADER_LEN,
};
use super::templates::{TemplateDefinition, TemplateRegistry};
use crate::FlowRecord;

/// Errors produced by [`MessageBuilder`].
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum EncodeError {
    /// `add_data_record` was called for a template the
    /// registry doesn't know about.
    UnknownTemplate(u16),
    /// `add_data_record_from_flow_record` was given a
    /// FlowRecord whose IP family doesn't match the
    /// template (e.g. IPv4-only template fed an IPv6 record).
    AddressFamilyMismatch,
    /// The total message length would exceed RFC 7011's
    /// 65535-octet maximum (Message Header `Length` field
    /// is 16 bits).
    MessageTooLarge,
}

impl std::fmt::Display for EncodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTemplate(id) => {
                write!(f, "unknown template id {id} — register it first")
            }
            Self::AddressFamilyMismatch => write!(
                f,
                "address family mismatch — IPv4-only template fed IPv6 (or vice versa)"
            ),
            Self::MessageTooLarge => {
                write!(f, "message would exceed 65535 octets — split records")
            }
        }
    }
}

impl std::error::Error for EncodeError {}

/// Build one RFC 7011 IPFIX Message.
///
/// A `MessageBuilder` accumulates zero-or-more Template Sets
/// and Data Sets, then produces a single Message buffer on
/// [`Self::finalize`]. Each call to `add_data_record` for
/// the same `template_id` extends a single Data Set (the
/// builder coalesces consecutive same-template records).
///
/// Per RFC 7011 §3, a Message is:
/// ```text
/// Message Header (16) | Set | Set | ...
/// ```
///
/// Use one MessageBuilder per outgoing UDP datagram or SCTP
/// chunk. Sequence-number bookkeeping (incrementing the
/// `sequence_number` by data-record-count per message,
/// resetting on observation-domain re-init) is the
/// caller's responsibility.
pub struct MessageBuilder<'a> {
    registry: &'a TemplateRegistry,
    sequence_number: u32,
    export_time: u32,
    sets: Vec<SetBuffer>,
}

#[derive(Debug, Clone)]
enum SetBuffer {
    Template {
        templates: Vec<TemplateDefinition>,
    },
    Data {
        template_id: u16,
        records: BytesMut,
        record_count: u32,
    },
}

impl<'a> MessageBuilder<'a> {
    pub fn new(registry: &'a TemplateRegistry, sequence_number: u32, export_time: u32) -> Self {
        Self {
            registry,
            sequence_number,
            export_time,
            sets: Vec::new(),
        }
    }

    /// Borrow the observation domain ID this builder will
    /// emit. Lifted from the registry.
    pub fn observation_domain_id(&self) -> u32 {
        self.registry.observation_domain_id
    }

    /// Emit a Template Set carrying the named templates.
    /// Returns `EncodeError::UnknownTemplate(id)` if any
    /// `template_id` isn't registered.
    pub fn add_template_set(&mut self, template_ids: &[u16]) -> Result<(), EncodeError> {
        let mut templates = Vec::with_capacity(template_ids.len());
        for &id in template_ids {
            let def = self
                .registry
                .get(id)
                .ok_or(EncodeError::UnknownTemplate(id))?
                .clone();
            templates.push(def);
        }
        self.sets.push(SetBuffer::Template { templates });
        Ok(())
    }

    /// Append a Data Record built against `template_id`.
    /// The encoder uses the Template Definition to walk the
    /// FlowRecord and emit each field in order.
    pub fn add_data_record(
        &mut self,
        rec: &FlowRecord,
        template_id: u16,
    ) -> Result<(), EncodeError> {
        let template = self
            .registry
            .get(template_id)
            .ok_or(EncodeError::UnknownTemplate(template_id))?;
        let mut record_buf = BytesMut::with_capacity(template.fixed_record_length().unwrap_or(64));
        encode_flow_record_into(rec, template, &mut record_buf)?;
        self.append_to_data_set(template_id, &record_buf);
        Ok(())
    }

    fn append_to_data_set(&mut self, template_id: u16, record: &[u8]) {
        // Coalesce with the previous Data Set if it's the
        // same template. Otherwise start a new one.
        let same = match self.sets.last() {
            Some(SetBuffer::Data {
                template_id: tid, ..
            }) => *tid == template_id,
            _ => false,
        };
        if same {
            if let Some(SetBuffer::Data {
                records,
                record_count,
                ..
            }) = self.sets.last_mut()
            {
                records.extend_from_slice(record);
                *record_count += 1;
            }
        } else {
            let mut records = BytesMut::new();
            records.extend_from_slice(record);
            self.sets.push(SetBuffer::Data {
                template_id,
                records,
                record_count: 1,
            });
        }
    }

    /// Number of Sets currently accumulated.
    pub fn set_count(&self) -> usize {
        self.sets.len()
    }

    /// Total length the finalised Message would be, if
    /// called now. Useful for MTU-aware batching.
    pub fn current_length(&self) -> usize {
        let mut total = MESSAGE_HEADER_LEN;
        for set in &self.sets {
            total += set_length(set);
        }
        total
    }

    /// Total number of Data Records this builder will emit.
    /// Useful for sequence-number bookkeeping in the next
    /// message (RFC 7011 §3.1: `sequenceNumber` increments
    /// by data-record-count, not message-count).
    pub fn data_record_count(&self) -> u32 {
        self.sets
            .iter()
            .map(|s| match s {
                SetBuffer::Data { record_count, .. } => *record_count,
                _ => 0,
            })
            .sum()
    }

    /// Produce the complete RFC 7011 Message bytes. Consumes
    /// the builder.
    pub fn finalize(self) -> Result<Vec<u8>, EncodeError> {
        let total = self.current_length();
        if total > u16::MAX as usize {
            return Err(EncodeError::MessageTooLarge);
        }
        let mut out = BytesMut::with_capacity(total);
        // Message Header.
        out.put_u16(IPFIX_VERSION);
        out.put_u16(total as u16);
        out.put_u32(self.export_time);
        out.put_u32(self.sequence_number);
        out.put_u32(self.registry.observation_domain_id);
        // Sets.
        for set in &self.sets {
            write_set(set, &mut out);
        }
        Ok(out.to_vec())
    }
}

fn set_length(set: &SetBuffer) -> usize {
    match set {
        SetBuffer::Template { templates } => {
            let mut total = SET_HEADER_LEN;
            for t in templates {
                total += TEMPLATE_HEADER_LEN;
                for f in &t.fields {
                    total += f.wire_length();
                }
            }
            total
        }
        SetBuffer::Data { records, .. } => SET_HEADER_LEN + records.len(),
    }
}

fn write_set(set: &SetBuffer, out: &mut BytesMut) {
    let len = set_length(set) as u16;
    match set {
        SetBuffer::Template { templates } => {
            out.put_u16(SET_ID_TEMPLATE);
            out.put_u16(len);
            for t in templates {
                out.put_u16(t.template_id);
                out.put_u16(t.fields.len() as u16);
                for f in &t.fields {
                    if let Some(en) = f.enterprise_number {
                        // High bit of IE ID set = enterprise.
                        out.put_u16(f.information_element_id | 0x8000);
                        out.put_u16(f.length);
                        out.put_u32(en);
                    } else {
                        out.put_u16(f.information_element_id);
                        out.put_u16(f.length);
                    }
                }
            }
        }
        SetBuffer::Data {
            template_id,
            records,
            ..
        } => {
            out.put_u16(*template_id);
            out.put_u16(len);
            out.extend_from_slice(records);
        }
    }
}

/// Encode one FlowRecord into `out` per `template`. Each
/// FieldSpec is matched against a FlowRecord accessor; any
/// unmappable field emits zeros of the declared length.
fn encode_flow_record_into(
    rec: &FlowRecord,
    template: &TemplateDefinition,
    out: &mut BytesMut,
) -> Result<(), EncodeError> {
    use super::constants::FIELD_LENGTH_VARIABLE;
    for f in &template.fields {
        let len = f.length as usize;
        if f.length == FIELD_LENGTH_VARIABLE {
            // Variable-length: 1-byte short form. Always
            // emit zero-length (we don't surface variable
            // values for FlowRecord today).
            out.put_u8(0);
            continue;
        }
        match f.information_element_id {
            4 => put_padded_u64(out, rec.protocol_identifier as u64, len),
            7 => put_padded_u64(out, rec.source_transport_port as u64, len),
            8 => match rec.source_ipv4_address {
                Some(v4) => out.extend_from_slice(&v4.octets()),
                None => return Err(EncodeError::AddressFamilyMismatch),
            },
            11 => put_padded_u64(out, rec.destination_transport_port as u64, len),
            12 => match rec.destination_ipv4_address {
                Some(v4) => out.extend_from_slice(&v4.octets()),
                None => return Err(EncodeError::AddressFamilyMismatch),
            },
            27 => match rec.source_ipv6_address {
                Some(v6) => out.extend_from_slice(&v6.octets()),
                None => return Err(EncodeError::AddressFamilyMismatch),
            },
            28 => match rec.destination_ipv6_address {
                Some(v6) => out.extend_from_slice(&v6.octets()),
                None => return Err(EncodeError::AddressFamilyMismatch),
            },
            1 => put_padded_u64(out, rec.octet_delta_count_initiator, len),
            2 => put_padded_u64(out, rec.packet_delta_count_initiator, len),
            85 => put_padded_u64(out, rec.octet_total_count, len),
            86 => put_padded_u64(out, rec.packet_total_count, len),
            152 => put_padded_u64(out, rec.flow_start_milliseconds, len),
            153 => put_padded_u64(out, rec.flow_end_milliseconds, len),
            6 => put_padded_u64(out, rec.tcp_control_bits_initiator.unwrap_or(0) as u64, len),
            136 => put_padded_u64(out, rec.flow_end_reason.map(|r| r as u64).unwrap_or(0), len),
            5 => put_padded_u64(out, rec.ip_class_of_service.unwrap_or(0) as u64, len),
            56 => match rec.source_mac_address {
                Some(mac) if len == 6 => out.extend_from_slice(&mac),
                _ => {
                    for _ in 0..len {
                        out.put_u8(0);
                    }
                }
            },
            80 => match rec.destination_mac_address {
                Some(mac) if len == 6 => out.extend_from_slice(&mac),
                _ => {
                    for _ in 0..len {
                        out.put_u8(0);
                    }
                }
            },
            10 => put_padded_u64(out, rec.ingress_interface.unwrap_or(0) as u64, len),
            14 => put_padded_u64(out, rec.egress_interface.unwrap_or(0) as u64, len),
            58 => put_padded_u64(out, rec.vlan_id.unwrap_or(0) as u64, len),
            // Unknown IE — emit zeros of the declared length.
            _ => {
                for _ in 0..len {
                    out.put_u8(0);
                }
            }
        }
    }
    Ok(())
}

/// Emit `value` big-endian into the low `len` bytes of
/// `out`. Asserts `len <= 8`.
fn put_padded_u64(out: &mut BytesMut, value: u64, len: usize) {
    assert!(len <= 8, "padded u64 emit needs len <= 8, got {len}");
    let be = value.to_be_bytes();
    out.extend_from_slice(&be[8 - len..]);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipfix::wire::{
        FLOWSCOPE_TEMPLATE_FLOW_IPV4, FLOWSCOPE_TEMPLATE_FLOW_IPV6, FieldSpec,
        TEMPLATE_ID_FLOW_IPV4, TEMPLATE_ID_FLOW_IPV6,
    };
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn empty_record_ipv4() -> FlowRecord {
        FlowRecord {
            protocol_identifier: 6,
            source_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 1)),
            destination_ipv4_address: Some(Ipv4Addr::new(10, 0, 0, 2)),
            source_transport_port: 1234,
            destination_transport_port: 80,
            octet_delta_count_initiator: 1500,
            octet_delta_count_responder: 2100,
            packet_delta_count_initiator: 10,
            packet_delta_count_responder: 12,
            octet_total_count: 3600,
            packet_total_count: 22,
            flow_start_milliseconds: 1_700_000_000_000,
            flow_end_milliseconds: 1_700_000_005_000,
            tcp_control_bits_initiator: Some(0x18),
            flow_end_reason: Some(crate::ipfix::FlowEndReason::EndOfFlowDetected),
            ..FlowRecord::default()
        }
    }

    fn empty_record_ipv6() -> FlowRecord {
        let mut r = empty_record_ipv4();
        r.source_ipv4_address = None;
        r.destination_ipv4_address = None;
        r.source_ipv6_address = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1));
        r.destination_ipv6_address = Some(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2));
        r
    }

    fn registry_with_default() -> TemplateRegistry {
        let mut reg = TemplateRegistry::new(0xDEAD_BEEF);
        reg.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
        reg.register(FLOWSCOPE_TEMPLATE_FLOW_IPV6.clone());
        reg
    }

    #[test]
    fn message_header_shape() {
        let reg = registry_with_default();
        let msg = MessageBuilder::new(&reg, 1, 1_700_000_000)
            .finalize()
            .expect("finalize");
        // Empty message = just the 16-byte header.
        assert_eq!(msg.len(), MESSAGE_HEADER_LEN);
        assert_eq!(u16::from_be_bytes([msg[0], msg[1]]), IPFIX_VERSION);
        assert_eq!(u16::from_be_bytes([msg[2], msg[3]]), 16);
        assert_eq!(
            u32::from_be_bytes([msg[4], msg[5], msg[6], msg[7]]),
            1_700_000_000
        );
        assert_eq!(u32::from_be_bytes([msg[8], msg[9], msg[10], msg[11]]), 1);
        assert_eq!(
            u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]),
            0xDEAD_BEEF
        );
    }

    #[test]
    fn template_set_shape() {
        let reg = registry_with_default();
        let mut b = MessageBuilder::new(&reg, 1, 1_700_000_000);
        b.add_template_set(&[TEMPLATE_ID_FLOW_IPV4]).expect("add");
        let msg = b.finalize().expect("finalize");
        // Header (16) + set header (4) + template header (4) + 13 specifiers * 4 = 76
        assert_eq!(msg.len(), 16 + 4 + 4 + 13 * 4);
        // Set ID at offset 16 should be SET_ID_TEMPLATE.
        assert_eq!(u16::from_be_bytes([msg[16], msg[17]]), SET_ID_TEMPLATE);
        // Set length at 18..20 must match (set header + body).
        assert_eq!(u16::from_be_bytes([msg[18], msg[19]]), 4 + 4 + 13 * 4);
        // First template's ID at offset 20.
        assert_eq!(
            u16::from_be_bytes([msg[20], msg[21]]),
            TEMPLATE_ID_FLOW_IPV4
        );
        // Field count at 22.
        assert_eq!(u16::from_be_bytes([msg[22], msg[23]]), 13);
    }

    #[test]
    fn data_set_ipv4_round_trip_via_template_walk() {
        let reg = registry_with_default();
        let rec = empty_record_ipv4();
        let mut b = MessageBuilder::new(&reg, 2, 1_700_000_001);
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).expect("add");
        let msg = b.finalize().expect("finalize");
        // Header (16) + Set header (4) + 64-byte record.
        assert_eq!(msg.len(), 16 + 4 + 64);
        // Set ID == template id.
        assert_eq!(
            u16::from_be_bytes([msg[16], msg[17]]),
            TEMPLATE_ID_FLOW_IPV4
        );
        // Walk the data: first byte = protocolIdentifier.
        assert_eq!(msg[20], 6);
        // sourceTransportPort at 21..23.
        assert_eq!(u16::from_be_bytes([msg[21], msg[22]]), 1234);
        // sourceIPv4Address at 23..27.
        assert_eq!(&msg[23..27], &[10, 0, 0, 1]);
    }

    #[test]
    fn multiple_records_coalesce_into_one_set() {
        let reg = registry_with_default();
        let rec = empty_record_ipv4();
        let mut b = MessageBuilder::new(&reg, 1, 1_700_000_000);
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).expect("a");
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).expect("b");
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).expect("c");
        assert_eq!(b.set_count(), 1, "3 same-template records → 1 set");
        assert_eq!(b.data_record_count(), 3);
        let msg = b.finalize().expect("finalize");
        // Header + Set header + 3 * 64.
        assert_eq!(msg.len(), 16 + 4 + 3 * 64);
    }

    #[test]
    fn ipv6_template_encodes_16_byte_addresses() {
        let reg = registry_with_default();
        let rec = empty_record_ipv6();
        let mut b = MessageBuilder::new(&reg, 1, 0);
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV6).expect("add");
        let msg = b.finalize().expect("finalize");
        // Header (16) + Set header (4) + 88-byte record.
        assert_eq!(msg.len(), 16 + 4 + 88);
    }

    #[test]
    fn address_family_mismatch_returns_error() {
        let reg = registry_with_default();
        // IPv4 record fed to IPv6 template → mismatch.
        let rec = empty_record_ipv4();
        let mut b = MessageBuilder::new(&reg, 1, 0);
        let err = b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV6).unwrap_err();
        assert_eq!(err, EncodeError::AddressFamilyMismatch);
    }

    #[test]
    fn unknown_template_returns_error() {
        let reg = registry_with_default();
        let rec = empty_record_ipv4();
        let mut b = MessageBuilder::new(&reg, 1, 0);
        let err = b.add_data_record(&rec, 0x9999).unwrap_err();
        assert_eq!(err, EncodeError::UnknownTemplate(0x9999));
    }

    #[test]
    fn data_record_count_tracks_appends() {
        let reg = registry_with_default();
        let rec = empty_record_ipv4();
        let mut b = MessageBuilder::new(&reg, 1, 0);
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).unwrap();
        b.add_data_record(&rec, TEMPLATE_ID_FLOW_IPV4).unwrap();
        assert_eq!(b.data_record_count(), 2);
    }

    #[test]
    fn enterprise_field_emits_8_byte_specifier() {
        let mut tmpl = FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone();
        // Inject a synthetic enterprise field at the end.
        tmpl.fields.push(FieldSpec {
            information_element_id: 0x0001,
            length: 4,
            enterprise_number: Some(0x1234_5678),
        });
        let mut reg = TemplateRegistry::new(0);
        reg.register(tmpl);
        let mut b = MessageBuilder::new(&reg, 1, 0);
        b.add_template_set(&[TEMPLATE_ID_FLOW_IPV4]).unwrap();
        let msg = b.finalize().unwrap();
        // Walk to find the enterprise spec. The set body
        // starts at 20: template_id(2) + count(2) + 13*4 +
        // 8 = (16 + 4 + 4 + 13*4 + 8) total.
        assert_eq!(msg.len(), 16 + 4 + 4 + 13 * 4 + 8);
        // Last 8 bytes are the enterprise spec: IE id (high
        // bit set) + length + enterprise number.
        let n = msg.len();
        let ie = u16::from_be_bytes([msg[n - 8], msg[n - 7]]);
        assert_eq!(ie, 0x0001 | 0x8000);
        let en = u32::from_be_bytes([msg[n - 4], msg[n - 3], msg[n - 2], msg[n - 1]]);
        assert_eq!(en, 0x1234_5678);
    }

    #[test]
    fn observation_domain_id_propagates() {
        let reg = TemplateRegistry::new(0xCAFE_BABE);
        let b = MessageBuilder::new(&reg, 1, 0);
        assert_eq!(b.observation_domain_id(), 0xCAFE_BABE);
        let msg = b.finalize().unwrap();
        assert_eq!(
            u32::from_be_bytes([msg[12], msg[13], msg[14], msg[15]]),
            0xCAFE_BABE
        );
    }
}
