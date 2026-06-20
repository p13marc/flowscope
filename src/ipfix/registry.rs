//! IANA IPFIX Information Element registry (operationally-
//! common subset).
//!
//! Source: <https://www.iana.org/assignments/ipfix/ipfix.xhtml>.
//! Each entry's `description` is paraphrased from the IANA
//! registry. Coverage is intentionally narrow — every IE that
//! mainstream flow tools (Zeek conn.log, Suricata EVE flow,
//! goflow2, nProbe) actually reference, plus a handful of
//! commonly-missing ones from issue #16. Patch in new IEs as
//! needed.

use super::types::{IeAbstractType, InformationElement};

/// Build a const IE entry without restating the field
/// keywords each time.
const fn ie(
    id: u16,
    name: &'static str,
    abstract_type: IeAbstractType,
    units: Option<&'static str>,
    description: &'static str,
) -> InformationElement {
    InformationElement {
        id,
        name,
        abstract_type,
        units,
        description,
    }
}

/// The operationally-common IPFIX IE registry, sorted by id.
///
/// Coverage at a glance:
///
/// | Category | IEs |
/// |----------|-----|
/// | Per-direction counters | 1, 2, 23, 24, 85, 86 |
/// | L3/L4 keys | 4, 5, 7, 11, 8, 12, 27, 28, 56, 80 |
/// | TCP state | 6 (tcpControlBits) |
/// | Timing | 152, 153, 154, 155 |
/// | Termination | 136 (flowEndReason) |
/// | Interface | 10, 14 |
/// | Application | 95 (applicationId), 96 (applicationName) |
/// | VLAN / VXLAN | 58, 59, 351 |
pub const IES: &[InformationElement] = &[
    ie(
        1,
        "octetDeltaCount",
        IeAbstractType::Unsigned64,
        Some("octets"),
        "Number of octets observed for this Flow since the previous report.",
    ),
    ie(
        2,
        "packetDeltaCount",
        IeAbstractType::Unsigned64,
        Some("packets"),
        "Number of incoming packets observed for this Flow since the previous report.",
    ),
    ie(
        4,
        "protocolIdentifier",
        IeAbstractType::Unsigned8,
        None,
        "IPv4/IPv6 protocol number (e.g. 6 = TCP, 17 = UDP).",
    ),
    ie(
        5,
        "ipClassOfService",
        IeAbstractType::Unsigned8,
        None,
        "IPv4 TOS byte or the equivalent IPv6 Traffic Class field.",
    ),
    ie(
        6,
        "tcpControlBits",
        IeAbstractType::Unsigned16,
        None,
        "Cumulative OR of all TCP-header control flags observed in the Flow (RFC 7125).",
    ),
    ie(
        7,
        "sourceTransportPort",
        IeAbstractType::Unsigned16,
        None,
        "Source TCP/UDP/SCTP port number.",
    ),
    ie(
        8,
        "sourceIPv4Address",
        IeAbstractType::Ipv4Address,
        None,
        "Source IPv4 address.",
    ),
    ie(
        10,
        "ingressInterface",
        IeAbstractType::Unsigned32,
        None,
        "Index of the IP interface where the packets were received.",
    ),
    ie(
        11,
        "destinationTransportPort",
        IeAbstractType::Unsigned16,
        None,
        "Destination TCP/UDP/SCTP port number.",
    ),
    ie(
        12,
        "destinationIPv4Address",
        IeAbstractType::Ipv4Address,
        None,
        "Destination IPv4 address.",
    ),
    ie(
        14,
        "egressInterface",
        IeAbstractType::Unsigned32,
        None,
        "Index of the IP interface where the packets were sent.",
    ),
    ie(
        23,
        "postOctetDeltaCount",
        IeAbstractType::Unsigned64,
        Some("octets"),
        "Octets observed after egress processing (post-NAT, post-traffic-shaper).",
    ),
    ie(
        24,
        "postPacketDeltaCount",
        IeAbstractType::Unsigned64,
        Some("packets"),
        "Packets observed after egress processing.",
    ),
    ie(
        27,
        "sourceIPv6Address",
        IeAbstractType::Ipv6Address,
        None,
        "Source IPv6 address.",
    ),
    ie(
        28,
        "destinationIPv6Address",
        IeAbstractType::Ipv6Address,
        None,
        "Destination IPv6 address.",
    ),
    ie(
        56,
        "sourceMacAddress",
        IeAbstractType::MacAddress,
        None,
        "L2 source MAC address (incoming).",
    ),
    ie(
        58,
        "vlanId",
        IeAbstractType::Unsigned16,
        None,
        "VLAN identifier observed on the ingress side (802.1Q).",
    ),
    ie(
        59,
        "postVlanId",
        IeAbstractType::Unsigned16,
        None,
        "VLAN identifier observed on the egress side after any 802.1Q rewrite.",
    ),
    ie(
        80,
        "destinationMacAddress",
        IeAbstractType::MacAddress,
        None,
        "L2 destination MAC address (incoming).",
    ),
    ie(
        85,
        "octetTotalCount",
        IeAbstractType::Unsigned64,
        Some("octets"),
        "Total octets observed for this Flow over its lifetime.",
    ),
    ie(
        86,
        "packetTotalCount",
        IeAbstractType::Unsigned64,
        Some("packets"),
        "Total packets observed for this Flow over its lifetime.",
    ),
    ie(
        95,
        "applicationId",
        IeAbstractType::OctetArray,
        None,
        "Vendor-defined application identifier (Cisco NBAR2, Palo Alto App-ID, etc.).",
    ),
    ie(
        96,
        "applicationName",
        IeAbstractType::String,
        None,
        "Human-readable application name corresponding to applicationId.",
    ),
    ie(
        136,
        "flowEndReason",
        IeAbstractType::Unsigned8,
        None,
        "Reason the Flow ended: 1=idle, 2=active, 3=end-detected, 4=forced, 5=resources.",
    ),
    ie(
        152,
        "flowStartMilliseconds",
        IeAbstractType::DateTimeMilliseconds,
        Some("ms"),
        "Absolute timestamp of the Flow's first packet.",
    ),
    ie(
        153,
        "flowEndMilliseconds",
        IeAbstractType::DateTimeMilliseconds,
        Some("ms"),
        "Absolute timestamp of the Flow's last packet.",
    ),
    ie(
        154,
        "flowStartMicroseconds",
        IeAbstractType::DateTimeMicroseconds,
        Some("us"),
        "Absolute timestamp of the Flow's first packet (microsecond precision).",
    ),
    ie(
        155,
        "flowEndMicroseconds",
        IeAbstractType::DateTimeMicroseconds,
        Some("us"),
        "Absolute timestamp of the Flow's last packet (microsecond precision).",
    ),
    ie(
        239,
        "biflowDirection",
        IeAbstractType::Unsigned8,
        None,
        "Direction marker for a biflow (RFC 5103): 1=initiator, 2=reverseInitiator, 3=perimeter.",
    ),
    ie(
        351,
        "layer2SegmentId",
        IeAbstractType::Unsigned64,
        None,
        "L2 segment identifier (RFC 7637; VxLAN VNI, NVGRE VSID, etc.).",
    ),
];

/// Look up the registry entry for a given IANA IE id. `O(log n)`
/// — the registry is sorted by id.
pub fn lookup_by_id(id: u16) -> Option<&'static InformationElement> {
    IES.binary_search_by_key(&id, |e| e.id)
        .ok()
        .map(|i| &IES[i])
}

/// Look up the registry entry for a given IE name. Case-
/// sensitive (IANA names use lowerCamelCase).
pub fn lookup_by_name(name: &str) -> Option<&'static InformationElement> {
    IES.iter().find(|e| e.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn registry_is_sorted_by_id() {
        // binary_search depends on this; assert it loudly so a
        // future patch can't add an out-of-order entry without
        // CI catching it.
        let mut prev: i32 = -1;
        for ie in IES.iter() {
            assert!(
                (ie.id as i32) > prev,
                "IE registry not sorted at id {}",
                ie.id
            );
            prev = ie.id as i32;
        }
    }

    #[test]
    fn lookup_by_id_finds_known_entries() {
        let port = lookup_by_id(7).unwrap();
        assert_eq!(port.name, "sourceTransportPort");
        assert_eq!(port.abstract_type, IeAbstractType::Unsigned16);

        let v4 = lookup_by_id(8).unwrap();
        assert_eq!(v4.name, "sourceIPv4Address");
        assert_eq!(v4.abstract_type, IeAbstractType::Ipv4Address);

        let cause = lookup_by_id(136).unwrap();
        assert_eq!(cause.name, "flowEndReason");
    }

    #[test]
    fn lookup_by_id_misses_unknown() {
        assert!(lookup_by_id(0).is_none());
        assert!(lookup_by_id(9999).is_none());
    }

    #[test]
    fn lookup_by_name_finds_known() {
        assert_eq!(lookup_by_name("octetTotalCount").map(|e| e.id), Some(85));
        assert_eq!(lookup_by_name("tcpControlBits").map(|e| e.id), Some(6));
    }

    #[test]
    fn lookup_by_name_is_case_sensitive() {
        // IANA names are lowerCamelCase. Case mismatch must miss.
        assert!(lookup_by_name("OctetTotalCount").is_none());
        assert!(lookup_by_name("octettotalcount").is_none());
    }

    #[test]
    fn iana_required_ies_present() {
        // Issue #16 calls out these as "commonly-missing-yet-
        // standard" — they must be in the registry.
        for required in &[6, 136] {
            assert!(
                lookup_by_id(*required).is_some(),
                "IE {} missing from registry",
                required
            );
        }
    }

    #[test]
    fn unit_field_on_counter_ies() {
        assert_eq!(lookup_by_id(1).unwrap().units, Some("octets"));
        assert_eq!(lookup_by_id(2).unwrap().units, Some("packets"));
        assert_eq!(lookup_by_id(85).unwrap().units, Some("octets"));
    }
}
