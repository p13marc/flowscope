//! LLDP message types.
//!
//! Wire reference: IEEE 802.1AB-2016 §8.

use std::net::IpAddr;

use bitflags::bitflags;
use bytes::Bytes;

use crate::MacAddr;

/// One parsed LLDPDU. The three mandatory TLVs (chassis-ID,
/// port-ID, TTL) are always populated; everything else is
/// optional.
///
/// Issue #23 (0.18).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LldpMessage {
    /// Chassis ID TLV (type 1, mandatory).
    pub chassis_id: ChassisId,
    /// Port ID TLV (type 2, mandatory).
    pub port_id: PortId,
    /// Time-to-live in seconds (TLV type 3, mandatory). `0`
    /// is the IEEE 802.1AB §8.5.5 "shutdown announce" marker —
    /// purge any cached entry for this neighbor.
    pub ttl_seconds: u16,
    /// Port Description (TLV type 4) — free-form string.
    pub port_description: Option<Bytes>,
    /// System Name (TLV type 5) — typically the host name.
    pub system_name: Option<Bytes>,
    /// System Description (TLV type 6) — free-form, often
    /// includes OS / version.
    pub system_description: Option<Bytes>,
    /// System Capabilities (TLV type 7) — what the device can
    /// do and what it currently is doing.
    pub capabilities: Option<SystemCapabilities>,
    /// Management Addresses (TLV type 8). Bounded at 4 — real
    /// LLDPDUs rarely carry more than 2.
    pub management_addresses: Vec<LldpManagementAddress>,
    /// Organizationally Specific TLVs (TLV type 127). Bounded
    /// at 8 — defense against memory blowup on adversarial
    /// input.
    pub vendor_tlvs: Vec<LldpVendorTlv>,
}

impl LldpMessage {
    /// `true` if this LLDPDU is the IEEE 802.1AB §8.5.5
    /// shutdown announce — a real neighbor sends it when its
    /// LLDP agent is shutting down so the peer purges the
    /// cache entry immediately rather than waiting for the
    /// previous TTL.
    ///
    /// A forged shutdown announce from an attacker on the L2
    /// segment is a denial-of-service signal — the receiver
    /// loses its cached neighbor binding.
    #[inline]
    pub fn is_shutdown_announce(&self) -> bool {
        self.ttl_seconds == 0
    }

    /// `true` if the chassis-ID is a MAC address and matches
    /// `src` (the source MAC of the frame this LLDPDU rode in
    /// on). Real devices announce their own MAC; a mismatch is
    /// a rogue-device IOC.
    ///
    /// Returns `false` for non-MAC chassis IDs (interface
    /// alias / locally assigned / network address) — those
    /// can't be cross-checked against the L2 src.
    #[inline]
    pub fn chassis_id_matches_src(&self, src: MacAddr) -> bool {
        matches!(&self.chassis_id, ChassisId::MacAddress(m) if *m == src)
    }
}

/// Chassis ID TLV value. Subtypes per IEEE 802.1AB §8.5.2.2.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum ChassisId {
    /// Subtype 1.
    ChassisComponent(Bytes),
    /// Subtype 2.
    InterfaceAlias(Bytes),
    /// Subtype 3.
    PortComponent(Bytes),
    /// Subtype 4 — the common case.
    MacAddress(MacAddr),
    /// Subtype 5.
    NetworkAddress(IpAddr),
    /// Subtype 6.
    InterfaceName(Bytes),
    /// Subtype 7.
    Local(Bytes),
    /// Reserved / unknown subtype.
    Other { subtype: u8, value: Bytes },
}

/// Port ID TLV value. Subtypes per IEEE 802.1AB §8.5.3.2.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum PortId {
    /// Subtype 1.
    InterfaceAlias(Bytes),
    /// Subtype 2.
    PortComponent(Bytes),
    /// Subtype 3.
    MacAddress(MacAddr),
    /// Subtype 4.
    NetworkAddress(IpAddr),
    /// Subtype 5 — common on Cisco / Juniper / Arista.
    InterfaceName(Bytes),
    /// Subtype 6.
    AgentCircuitId(Bytes),
    /// Subtype 7.
    Local(Bytes),
    /// Reserved / unknown subtype.
    Other { subtype: u8, value: Bytes },
}

/// System Capabilities TLV. Each field is a bitmask of
/// [`CapabilityBits`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct SystemCapabilities {
    /// What the device is *capable of* doing.
    pub system: CapabilityBits,
    /// What the device is *currently doing*.
    pub enabled: CapabilityBits,
}

bitflags! {
    /// IEEE 802.1AB system-capability bit vocabulary.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CapabilityBits: u16 {
        const OTHER              = 1 << 0;
        const REPEATER           = 1 << 1;
        const BRIDGE             = 1 << 2;
        const WLAN_AP            = 1 << 3;
        const ROUTER             = 1 << 4;
        const TELEPHONE          = 1 << 5;
        const DOCSIS_CABLE       = 1 << 6;
        const STATION_ONLY       = 1 << 7;
        const C_VLAN             = 1 << 8;
        const S_VLAN             = 1 << 9;
        const TWO_PORT_MAC_RELAY = 1 << 10;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CapabilityBits {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u16(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CapabilityBits {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u16 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(CapabilityBits::from_bits_truncate(bits))
    }
}

/// Management Address TLV (type 8). Often the device's
/// management-plane IP — useful for asset discovery.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LldpManagementAddress {
    /// IANA address-family subtype (e.g. 1 = IPv4, 2 = IPv6,
    /// 6 = MAC). When the family is IP, decoded into [`Self::ip`].
    pub address_family: u8,
    /// Decoded IP address when the family is v4 or v6. `None`
    /// for non-IP families or malformed values.
    pub ip: Option<IpAddr>,
    /// Raw address bytes — populated for all families,
    /// including non-IP.
    pub raw_address: Bytes,
}

/// Organizationally Specific TLV (type 127). OUI identifies
/// the standards body (00-80-c2 = IEEE 802.1, 00-12-0f = IEEE
/// 802.3, 00-12-bb = TIA LLDP-MED, 00-01-42 = Cisco).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct LldpVendorTlv {
    /// 3-byte Organizationally Unique Identifier.
    pub oui: [u8; 3],
    /// Vendor-defined subtype.
    pub subtype: u8,
    /// Raw payload bytes (after OUI + subtype).
    pub value: Bytes,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shutdown_announce_predicate() {
        let m = LldpMessage {
            chassis_id: ChassisId::Local(Bytes::new()),
            port_id: PortId::Local(Bytes::new()),
            ttl_seconds: 0,
            port_description: None,
            system_name: None,
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            vendor_tlvs: Vec::new(),
        };
        assert!(m.is_shutdown_announce());

        let m = LldpMessage {
            ttl_seconds: 120,
            ..m
        };
        assert!(!m.is_shutdown_announce());
    }

    #[test]
    fn chassis_id_matches_src_only_for_mac_form() {
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let m = LldpMessage {
            chassis_id: ChassisId::MacAddress(mac),
            port_id: PortId::Local(Bytes::new()),
            ttl_seconds: 60,
            port_description: None,
            system_name: None,
            system_description: None,
            capabilities: None,
            management_addresses: Vec::new(),
            vendor_tlvs: Vec::new(),
        };
        assert!(m.chassis_id_matches_src(mac));
        assert!(!m.chassis_id_matches_src(MacAddr([0; 6])));

        // Non-MAC chassis IDs always return false — no
        // cross-check possible.
        let m = LldpMessage {
            chassis_id: ChassisId::Local(Bytes::from_static(b"sw-01")),
            ..m
        };
        assert!(!m.chassis_id_matches_src(mac));
    }

    #[test]
    fn capability_bits_match_spec() {
        // Spot-check a few bit positions against the IEEE
        // 802.1AB §8.5.8.1 vocabulary.
        assert_eq!(CapabilityBits::BRIDGE.bits(), 0x0004);
        assert_eq!(CapabilityBits::ROUTER.bits(), 0x0010);
        assert_eq!(CapabilityBits::TELEPHONE.bits(), 0x0020);
        assert_eq!(CapabilityBits::WLAN_AP.bits(), 0x0008);
    }
}
