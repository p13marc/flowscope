//! Vocabulary types for the IPFIX module.

/// RFC 7012 §3.1 abstract data types. The IANA registry maps
/// every IE id to one of these.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum IeAbstractType {
    Unsigned8,
    Unsigned16,
    Unsigned32,
    Unsigned64,
    Signed8,
    Signed16,
    Signed32,
    Signed64,
    Float32,
    Float64,
    Boolean,
    MacAddress,
    OctetArray,
    String,
    DateTimeSeconds,
    DateTimeMilliseconds,
    DateTimeMicroseconds,
    DateTimeNanoseconds,
    Ipv4Address,
    Ipv6Address,
    /// Information element identifier of nested IE (used for
    /// templates).
    BasicList,
    SubTemplateList,
    SubTemplateMultiList,
}

impl IeAbstractType {
    /// Stable slug used as a metric / JSON label.
    pub fn as_str(&self) -> &'static str {
        match self {
            IeAbstractType::Unsigned8 => "unsigned8",
            IeAbstractType::Unsigned16 => "unsigned16",
            IeAbstractType::Unsigned32 => "unsigned32",
            IeAbstractType::Unsigned64 => "unsigned64",
            IeAbstractType::Signed8 => "signed8",
            IeAbstractType::Signed16 => "signed16",
            IeAbstractType::Signed32 => "signed32",
            IeAbstractType::Signed64 => "signed64",
            IeAbstractType::Float32 => "float32",
            IeAbstractType::Float64 => "float64",
            IeAbstractType::Boolean => "boolean",
            IeAbstractType::MacAddress => "macAddress",
            IeAbstractType::OctetArray => "octetArray",
            IeAbstractType::String => "string",
            IeAbstractType::DateTimeSeconds => "dateTimeSeconds",
            IeAbstractType::DateTimeMilliseconds => "dateTimeMilliseconds",
            IeAbstractType::DateTimeMicroseconds => "dateTimeMicroseconds",
            IeAbstractType::DateTimeNanoseconds => "dateTimeNanoseconds",
            IeAbstractType::Ipv4Address => "ipv4Address",
            IeAbstractType::Ipv6Address => "ipv6Address",
            IeAbstractType::BasicList => "basicList",
            IeAbstractType::SubTemplateList => "subTemplateList",
            IeAbstractType::SubTemplateMultiList => "subTemplateMultiList",
        }
    }
}

/// One IPFIX Information Element registry entry.
///
/// Construction is private to this crate — use the
/// [`crate::ipfix::IES`] const array and the
/// [`crate::ipfix::lookup_by_id`] / [`crate::ipfix::lookup_by_name`]
/// accessors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct InformationElement {
    /// IANA-assigned IE id.
    pub id: u16,
    /// Canonical IANA name (e.g. `"sourceTransportPort"`).
    pub name: &'static str,
    /// RFC 7012 §3.1 abstract type.
    pub abstract_type: IeAbstractType,
    /// Optional unit (e.g. `"octets"`, `"packets"`,
    /// `"milliseconds"`). `None` when the IE doesn't carry one.
    pub units: Option<&'static str>,
    /// One-line description suitable for tooltips / docs.
    pub description: &'static str,
}

/// IPFIX [`flowEndReason`](https://www.iana.org/assignments/ipfix/ipfix.xhtml#ipfix-flow-end-reason)
/// (IE 136) — RFC 7012 §5.11.7. The canonical 5-state IPFIX
/// termination cause used by Suricata, nProbe, goflow2, etc.
///
/// flowscope's [`crate::EndReason`] maps onto this via the
/// `From` impl in the same module so a flow exporter can emit
/// the IANA value directly.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum FlowEndReason {
    /// `1` — idle timeout.
    IdleTimeout,
    /// `2` — active timeout (flow held open past the active
    /// cap).
    ActiveTimeout,
    /// `3` — end of flow detected (FIN seen on a TCP flow).
    EndOfFlowDetected,
    /// `4` — forced end (administrative tear-down).
    ForcedEnd,
    /// `5` — lack of resources (LRU eviction, memcap).
    LackOfResources,
}

impl FlowEndReason {
    /// IANA numeric value.
    pub fn as_u8(self) -> u8 {
        match self {
            FlowEndReason::IdleTimeout => 1,
            FlowEndReason::ActiveTimeout => 2,
            FlowEndReason::EndOfFlowDetected => 3,
            FlowEndReason::ForcedEnd => 4,
            FlowEndReason::LackOfResources => 5,
        }
    }

    /// Decode the IANA numeric value. `None` for reserved /
    /// unknown values (0, 6..255).
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => FlowEndReason::IdleTimeout,
            2 => FlowEndReason::ActiveTimeout,
            3 => FlowEndReason::EndOfFlowDetected,
            4 => FlowEndReason::ForcedEnd,
            5 => FlowEndReason::LackOfResources,
            _ => return None,
        })
    }
}

#[cfg(feature = "tracker")]
impl From<crate::EndReason> for FlowEndReason {
    /// Map flowscope's lifecycle [`crate::EndReason`] onto the
    /// IPFIX-canonical [`FlowEndReason`]:
    ///
    /// - `Fin` / `Rst` → `EndOfFlowDetected`
    /// - `IdleTimeout` → `IdleTimeout`
    /// - `Evicted` → `LackOfResources`
    /// - `BufferOverflow` / `ParseError` / `ParserDone` /
    ///   `ForceClosed` → `ForcedEnd`
    fn from(r: crate::EndReason) -> Self {
        use crate::EndReason as E;
        match r {
            E::Fin | E::Rst => FlowEndReason::EndOfFlowDetected,
            E::IdleTimeout => FlowEndReason::IdleTimeout,
            E::Evicted => FlowEndReason::LackOfResources,
            E::BufferOverflow | E::ParseError | E::ParserDone | E::ForceClosed => {
                FlowEndReason::ForcedEnd
            }
        }
    }
}

/// Encode TCP flag bits into the IPFIX [`tcpControlBits`](https://www.iana.org/assignments/ipfix/ipfix.xhtml)
/// (IE 6) cumulative form per RFC 7125: `u16` bitmask with the
/// 8 RFC 793 flags plus the two ECN flags. Each set bit means
/// the flag was observed on at least one segment in the flow.
///
/// Argument: the 8 RFC 793 flags plus ECN/CWR. Bit layout
/// matches the standard `TcpFlagsView` shape and the RFC 7125
/// IE 6 wire form (which uses the same TCP-header byte order).
#[allow(clippy::too_many_arguments)]
pub fn encode_tcp_control_bits(
    fin: bool,
    syn: bool,
    rst: bool,
    psh: bool,
    ack: bool,
    urg: bool,
    ece: bool,
    cwr: bool,
) -> u16 {
    let mut bits: u16 = 0;
    if fin {
        bits |= 1 << 0;
    }
    if syn {
        bits |= 1 << 1;
    }
    if rst {
        bits |= 1 << 2;
    }
    if psh {
        bits |= 1 << 3;
    }
    if ack {
        bits |= 1 << 4;
    }
    if urg {
        bits |= 1 << 5;
    }
    if ece {
        bits |= 1 << 6;
    }
    if cwr {
        bits |= 1 << 7;
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn abstract_type_slugs_locked() {
        // Pinned: downstream emitters depend on these.
        assert_eq!(IeAbstractType::Unsigned32.as_str(), "unsigned32");
        assert_eq!(IeAbstractType::Ipv4Address.as_str(), "ipv4Address");
        assert_eq!(
            IeAbstractType::DateTimeMilliseconds.as_str(),
            "dateTimeMilliseconds"
        );
    }

    #[test]
    fn flow_end_reason_round_trip_u8() {
        for r in [
            FlowEndReason::IdleTimeout,
            FlowEndReason::ActiveTimeout,
            FlowEndReason::EndOfFlowDetected,
            FlowEndReason::ForcedEnd,
            FlowEndReason::LackOfResources,
        ] {
            assert_eq!(FlowEndReason::from_u8(r.as_u8()), Some(r));
        }
        assert_eq!(FlowEndReason::from_u8(0), None);
        assert_eq!(FlowEndReason::from_u8(99), None);
    }

    #[test]
    fn flow_end_reason_iana_numeric_values() {
        assert_eq!(FlowEndReason::IdleTimeout.as_u8(), 1);
        assert_eq!(FlowEndReason::ActiveTimeout.as_u8(), 2);
        assert_eq!(FlowEndReason::EndOfFlowDetected.as_u8(), 3);
        assert_eq!(FlowEndReason::ForcedEnd.as_u8(), 4);
        assert_eq!(FlowEndReason::LackOfResources.as_u8(), 5);
    }

    #[cfg(feature = "tracker")]
    #[test]
    fn end_reason_maps_to_ipfix_canonical() {
        use crate::EndReason;
        assert_eq!(
            FlowEndReason::from(EndReason::Fin),
            FlowEndReason::EndOfFlowDetected
        );
        assert_eq!(
            FlowEndReason::from(EndReason::Rst),
            FlowEndReason::EndOfFlowDetected
        );
        assert_eq!(
            FlowEndReason::from(EndReason::IdleTimeout),
            FlowEndReason::IdleTimeout
        );
        assert_eq!(
            FlowEndReason::from(EndReason::Evicted),
            FlowEndReason::LackOfResources
        );
        assert_eq!(
            FlowEndReason::from(EndReason::ForceClosed),
            FlowEndReason::ForcedEnd
        );
        assert_eq!(
            FlowEndReason::from(EndReason::BufferOverflow),
            FlowEndReason::ForcedEnd
        );
    }

    #[test]
    fn encode_tcp_control_bits_layout() {
        // All flags off.
        assert_eq!(
            encode_tcp_control_bits(false, false, false, false, false, false, false, false),
            0
        );
        // Just SYN.
        assert_eq!(
            encode_tcp_control_bits(false, true, false, false, false, false, false, false),
            0x02
        );
        // SYN + ACK.
        assert_eq!(
            encode_tcp_control_bits(false, true, false, false, true, false, false, false),
            0x12
        );
        // All 8 flags.
        assert_eq!(
            encode_tcp_control_bits(true, true, true, true, true, true, true, true),
            0xff
        );
    }
}
