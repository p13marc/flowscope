//! CDP message types.

use std::net::IpAddr;

use bitflags::bitflags;
use bytes::Bytes;

/// One parsed CDPDU. Almost every CDPDU carries Device-ID;
/// the rest of the TLVs are optional. Bounded at the
/// operationally-interesting field set — vendor / experimental
/// TLVs aren't surfaced (file follow-ups if needed).
///
/// Issue #25 (0.18).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct CdpMessage {
    /// CDP version byte (0x02 on modern devices).
    pub version: u8,
    /// Time-to-live in seconds — the receiver purges its cache
    /// entry for this neighbor after this many seconds without
    /// a refresh.
    pub ttl_seconds: u8,
    /// TLV 0x0001 — Device-ID. Usually the hostname.
    pub device_id: Option<Bytes>,
    /// TLV 0x0002 — Addresses. Each entry decodes the embedded
    /// IP (v4 or v6) when the IETF/NLPID address-encoding
    /// recognises it.
    pub addresses: Vec<CdpAddress>,
    /// TLV 0x0003 — Port-ID. The local port name on the sender
    /// (e.g. `GigabitEthernet0/1`).
    pub port_id: Option<Bytes>,
    /// TLV 0x0004 — Capabilities bitmask. What the device does.
    pub capabilities: Option<CdpCapabilities>,
    /// TLV 0x0005 — Software-Version. The IOS / NX-OS / etc.
    /// banner string.
    pub software_version: Option<Bytes>,
    /// TLV 0x0006 — Platform. Hardware model (e.g.
    /// `cisco WS-C2960X-24TS-L`).
    pub platform: Option<Bytes>,
    /// TLV 0x000a — Native VLAN.
    pub native_vlan: Option<u16>,
    /// TLV 0x000b — Duplex (0 = half, 1 = full).
    pub duplex: Option<u8>,
    /// TLV 0x0009 — VTP Management Domain.
    pub vtp_domain: Option<Bytes>,
    /// TLV 0x0016 — Management Addresses (typically the
    /// switch's mgmt-plane IPs).
    pub management_addresses: Vec<CdpAddress>,
}

/// One decoded CDP address-block entry.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct CdpAddress {
    /// Protocol-type byte from the address record (1 = NLPID,
    /// 2 = 802.2). Most CDPDUs use the 802.2 / SNAP form for
    /// IPv4 / IPv6.
    pub protocol_type: u8,
    /// Decoded IP address when the protocol-type + protocol-id
    /// identifies IPv4 (`0xcc`) or IPv6 (`0x86dd`). `None` for
    /// non-IP families or malformed values.
    pub ip: Option<IpAddr>,
    /// Raw address bytes (the wire value, before IP decoding).
    pub raw_address: Bytes,
}

bitflags! {
    /// CDP capability bits (TLV 0x0004). Source: Cisco's
    /// public CDP technical reference.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct CdpCapabilities: u32 {
        /// Router.
        const ROUTER          = 1 << 0;
        /// Transparent bridge.
        const BRIDGE          = 1 << 1;
        /// Source-route bridge.
        const SOURCE_BRIDGE   = 1 << 2;
        /// Switch (provides L2 + L3 switching).
        const SWITCH          = 1 << 3;
        /// Host.
        const HOST            = 1 << 4;
        /// IGMP-capable.
        const IGMP            = 1 << 5;
        /// Repeater.
        const REPEATER        = 1 << 6;
        /// VoIP phone / VoIP-capable device.
        const PHONE           = 1 << 7;
        /// Remotely-managed device.
        const REMOTELY_MANAGED = 1 << 8;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CdpCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CdpCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(CdpCapabilities::from_bits_truncate(bits))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn capability_bits_layout() {
        assert_eq!(CdpCapabilities::ROUTER.bits(), 0x01);
        assert_eq!(CdpCapabilities::SWITCH.bits(), 0x08);
        assert_eq!(CdpCapabilities::PHONE.bits(), 0x80);
    }
}
