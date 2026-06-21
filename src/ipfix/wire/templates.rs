//! Template / TemplateRegistry definitions.

use std::collections::HashMap;

use super::constants::SET_ID_DATA_MIN;

/// One Field Specifier per RFC 7011 §3.2.
///
/// `length` is in octets. `0xFFFF` (`FIELD_LENGTH_VARIABLE`)
/// indicates variable-length encoding — a length-prefix is
/// emitted before each value.
///
/// `enterprise_number` is set for IEs in the IANA private-
/// enterprise space (high bit of `information_element_id`
/// becomes 1 on the wire when present).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct FieldSpec {
    pub information_element_id: u16,
    pub length: u16,
    pub enterprise_number: Option<u32>,
}

impl FieldSpec {
    /// Fixed-length IANA IE: no enterprise number, no length
    /// prefix on the wire.
    pub const fn new(ie_id: u16, length: u16) -> Self {
        Self {
            information_element_id: ie_id,
            length,
            enterprise_number: None,
        }
    }

    /// Length of the field-specifier when encoded on the
    /// wire — 4 bytes for IANA IEs, 8 bytes when an
    /// enterprise number is present.
    pub const fn wire_length(&self) -> usize {
        if self.enterprise_number.is_some() {
            8
        } else {
            4
        }
    }
}

/// One Template Record per RFC 7011 §3.4.1. Identifies the
/// data layout for subsequent Data Sets whose Set ID
/// matches `template_id`.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct TemplateDefinition {
    pub template_id: u16,
    pub fields: Vec<FieldSpec>,
}

impl TemplateDefinition {
    /// Construct a new template. Panics in debug if
    /// `template_id < 256` (Set IDs 0..256 are reserved per
    /// RFC 7011 §3.4.3).
    pub fn new(template_id: u16, fields: Vec<FieldSpec>) -> Self {
        debug_assert!(template_id >= SET_ID_DATA_MIN, "template_id must be >= 256");
        Self {
            template_id,
            fields,
        }
    }

    /// Total wire length of one Data Record built against
    /// this template (sum of every fixed-length field). If
    /// any field is variable-length the result is `None`
    /// (callers must compute per-record).
    pub fn fixed_record_length(&self) -> Option<usize> {
        let mut total = 0;
        for f in &self.fields {
            if f.length == super::FIELD_LENGTH_VARIABLE {
                return None;
            }
            total += f.length as usize;
        }
        Some(total)
    }
}

/// Catalog of templates the encoder has emitted on a given
/// observation domain. The wire protocol requires every
/// Data Record to be preceded by the matching Template
/// Record at least once before the collector can decode the
/// data; this struct tracks which templates the producer
/// has emitted so the [`super::MessageBuilder`] can refuse
/// to emit Data for unregistered templates.
#[derive(Debug, Clone)]
pub struct TemplateRegistry {
    pub observation_domain_id: u32,
    templates: HashMap<u16, TemplateDefinition>,
}

impl TemplateRegistry {
    pub fn new(observation_domain_id: u32) -> Self {
        Self {
            observation_domain_id,
            templates: HashMap::new(),
        }
    }

    /// Register a template definition. Replaces any existing
    /// entry with the same `template_id`.
    pub fn register(&mut self, def: TemplateDefinition) {
        self.templates.insert(def.template_id, def);
    }

    pub fn get(&self, template_id: u16) -> Option<&TemplateDefinition> {
        self.templates.get(&template_id)
    }

    pub fn len(&self) -> usize {
        self.templates.len()
    }

    pub fn is_empty(&self) -> bool {
        self.templates.is_empty()
    }
}

// ─── Default templates for FlowRecord ─────────────────────

/// IANA template ID for flowscope's IPv4 flow template.
/// Producer-chosen value in the 256..0xFFFF range; downstream
/// collectors learn it from the emitted Template Record so
/// the exact number is arbitrary but stable.
pub const TEMPLATE_ID_FLOW_IPV4: u16 = 0x0100;
/// IANA template ID for flowscope's IPv6 flow template.
pub const TEMPLATE_ID_FLOW_IPV6: u16 = 0x0101;

/// Default IPv4 flow template. Covers the IEs the typed
/// [`crate::FlowRecord`] populates today:
///
/// | IE | Name                       | Octets |
/// |---:|----------------------------|-------:|
/// |  4 | protocolIdentifier         |      1 |
/// |  7 | sourceTransportPort        |      2 |
/// |  8 | sourceIPv4Address          |      4 |
/// | 11 | destinationTransportPort   |      2 |
/// | 12 | destinationIPv4Address     |      4 |
/// |  1 | octetDeltaCount (init)     |      8 |
/// |  2 | packetDeltaCount (init)    |      8 |
/// | 85 | octetTotalCount            |      8 |
/// | 86 | packetTotalCount           |      8 |
/// |152 | flowStartMilliseconds      |      8 |
/// |153 | flowEndMilliseconds        |      8 |
/// |  6 | tcpControlBits             |      2 |
/// |136 | flowEndReason              |      1 |
///
/// = 64 octets per Data Record. Reasonable for most
/// downstream collectors; consumers needing additional
/// IEs (MAC addresses, interfaces, VLAN, etc.) define
/// their own template via [`TemplateDefinition::new`].
pub static FLOWSCOPE_TEMPLATE_FLOW_IPV4: std::sync::LazyLock<TemplateDefinition> =
    std::sync::LazyLock::new(|| {
        TemplateDefinition::new(
            TEMPLATE_ID_FLOW_IPV4,
            vec![
                FieldSpec::new(4, 1),   // protocolIdentifier
                FieldSpec::new(7, 2),   // sourceTransportPort
                FieldSpec::new(8, 4),   // sourceIPv4Address
                FieldSpec::new(11, 2),  // destinationTransportPort
                FieldSpec::new(12, 4),  // destinationIPv4Address
                FieldSpec::new(1, 8),   // octetDeltaCount
                FieldSpec::new(2, 8),   // packetDeltaCount
                FieldSpec::new(85, 8),  // octetTotalCount
                FieldSpec::new(86, 8),  // packetTotalCount
                FieldSpec::new(152, 8), // flowStartMilliseconds
                FieldSpec::new(153, 8), // flowEndMilliseconds
                FieldSpec::new(6, 2),   // tcpControlBits
                FieldSpec::new(136, 1), // flowEndReason
            ],
        )
    });

/// IPv6 sibling of [`FLOWSCOPE_TEMPLATE_FLOW_IPV4`].
/// Replaces IE 8/12 with IE 27/28 (16-octet addresses);
/// otherwise identical IE list. 88 octets per Data Record.
pub static FLOWSCOPE_TEMPLATE_FLOW_IPV6: std::sync::LazyLock<TemplateDefinition> =
    std::sync::LazyLock::new(|| {
        TemplateDefinition::new(
            TEMPLATE_ID_FLOW_IPV6,
            vec![
                FieldSpec::new(4, 1),
                FieldSpec::new(7, 2),
                FieldSpec::new(27, 16), // sourceIPv6Address
                FieldSpec::new(11, 2),
                FieldSpec::new(28, 16), // destinationIPv6Address
                FieldSpec::new(1, 8),
                FieldSpec::new(2, 8),
                FieldSpec::new(85, 8),
                FieldSpec::new(86, 8),
                FieldSpec::new(152, 8),
                FieldSpec::new(153, 8),
                FieldSpec::new(6, 2),
                FieldSpec::new(136, 1),
            ],
        )
    });

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ipv4_template_total_octets() {
        let t = &FLOWSCOPE_TEMPLATE_FLOW_IPV4;
        assert_eq!(t.fixed_record_length(), Some(64));
    }

    #[test]
    fn ipv6_template_total_octets() {
        let t = &FLOWSCOPE_TEMPLATE_FLOW_IPV6;
        assert_eq!(t.fixed_record_length(), Some(88));
    }

    #[test]
    fn template_registry_register_get() {
        let mut reg = TemplateRegistry::new(0x1234_5678);
        reg.register(FLOWSCOPE_TEMPLATE_FLOW_IPV4.clone());
        assert_eq!(reg.len(), 1);
        assert!(reg.get(TEMPLATE_ID_FLOW_IPV4).is_some());
        assert!(reg.get(0x9999).is_none());
    }

    #[test]
    fn field_spec_wire_length() {
        let f = FieldSpec::new(4, 1);
        assert_eq!(f.wire_length(), 4);
        let mut f = FieldSpec::new(0x8001, 4);
        f.enterprise_number = Some(0x1234);
        assert_eq!(f.wire_length(), 8);
    }
}
