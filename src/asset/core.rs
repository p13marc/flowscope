//! `Asset` + supporting types.

use std::net::{Ipv4Addr, Ipv6Addr};

use bitflags::bitflags;

use crate::{MacAddr, Timestamp};

/// One inventory record per MAC address. Fields are populated
/// opportunistically as parsers contribute; absent data stays
/// `None` / empty.
///
/// `#[non_exhaustive]` — fields land additively forever.
///
/// Issue #27 (0.18).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Asset {
    /// L2 address — the inventory's primary key.
    pub mac: MacAddr,
    /// IPv4 addresses ever observed bound to `mac`. Bounded
    /// at 4 entries; the oldest is evicted when full.
    pub ipv4: Vec<Ipv4Addr>,
    /// IPv6 addresses ever observed bound to `mac`. Bounded
    /// at 4 entries; oldest-evicted-when-full.
    pub ipv6: Vec<Ipv6Addr>,
    /// Hostname — sourced from DHCP option 12 ("hostname")
    /// or LLDP / CDP "system name" TLV.
    pub hostname: Option<String>,
    /// Fully-qualified domain name — sourced from DHCP
    /// option 81 ("client FQDN"). May contain the hostname
    /// as the leftmost label.
    pub fqdn: Option<String>,
    /// Vendor / OS banner — sourced from DHCP option 60
    /// (`"MSFT 5.0"`), LLDP system-description, CDP
    /// software-version, or SSDP `SERVER`. The most
    /// discriminating fingerprint surface.
    pub vendor_banner: Option<String>,
    /// Hardware platform — sourced from LLDP / CDP "platform"
    /// TLV. Examples: `"cisco WS-C2960X-24TS-L"`,
    /// `"Cisco IP Phone 7960"`.
    pub platform: Option<String>,
    /// Capability bitmask — union over every parser's
    /// reported set.
    pub capabilities: AssetCapabilities,
    /// Per-parser fingerprints — populated when the source
    /// surfaced one. Each is `Option<String>` so a partial
    /// inventory doesn't lie about what it has.
    pub fingerprints: AssetFingerprints,
    /// Which parsers have contributed to this record.
    pub seen_via: AssetSourceSet,
    /// Most-recent observation timestamp.
    pub last_seen: Timestamp,
}

impl Asset {
    /// Construct a bare `Asset` for the given MAC. All
    /// observation fields are empty / default. Use the
    /// `from_*` adapter functions when you have a parsed
    /// message in hand.
    pub fn new(mac: MacAddr) -> Self {
        Self {
            mac,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            hostname: None,
            fqdn: None,
            vendor_banner: None,
            platform: None,
            capabilities: AssetCapabilities::empty(),
            fingerprints: AssetFingerprints::default(),
            seen_via: AssetSourceSet::empty(),
            last_seen: Timestamp::default(),
        }
    }

    /// Merge `other`'s fields into `self`. Non-empty / `Some`
    /// fields on `other` overwrite `self`. `last_seen` takes
    /// the later of the two. `seen_via` and `capabilities`
    /// bitwise-OR.
    pub fn merge(&mut self, other: &Asset) {
        // MAC mismatch is a usage error — assets are keyed by
        // MAC, so the inventory should never call merge on
        // two different MACs.
        debug_assert_eq!(self.mac, other.mac, "merge across different MAC keys");
        for ip in &other.ipv4 {
            if !self.ipv4.contains(ip) {
                push_bounded(&mut self.ipv4, *ip, MAX_IPS_PER_ASSET);
            }
        }
        for ip in &other.ipv6 {
            if !self.ipv6.contains(ip) {
                push_bounded(&mut self.ipv6, *ip, MAX_IPS_PER_ASSET);
            }
        }
        if other.hostname.is_some() {
            self.hostname = other.hostname.clone();
        }
        if other.fqdn.is_some() {
            self.fqdn = other.fqdn.clone();
        }
        if other.vendor_banner.is_some() {
            self.vendor_banner = other.vendor_banner.clone();
        }
        if other.platform.is_some() {
            self.platform = other.platform.clone();
        }
        self.capabilities |= other.capabilities;
        self.fingerprints.merge_from(&other.fingerprints);
        self.seen_via |= other.seen_via;
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
    }
}

/// Maximum number of IPs (v4 or v6) we'll remember per asset.
/// Devices roaming between IPs on the same MAC accumulate
/// state; bound the growth.
const MAX_IPS_PER_ASSET: usize = 4;

fn push_bounded<T: Clone>(v: &mut Vec<T>, item: T, cap: usize) {
    if v.len() >= cap {
        v.remove(0); // oldest goes first
    }
    v.push(item);
}

bitflags! {
    /// Device-capability bitmask. Combines the
    /// LLDP / CDP / SSDP capability vocabularies into a
    /// unified set.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AssetCapabilities: u32 {
        /// Layer 2 bridge / switch.
        const BRIDGE          = 1 << 0;
        /// Layer 3 router.
        const ROUTER          = 1 << 1;
        /// Multi-port switch (covers Suricata-style
        /// SWITCH capability).
        const SWITCH          = 1 << 2;
        /// IEEE 802.11 access point.
        const WLAN_AP         = 1 << 3;
        /// VoIP phone / IP phone.
        const PHONE           = 1 << 4;
        /// IGMP-capable.
        const IGMP            = 1 << 5;
        /// Repeater / hub.
        const REPEATER        = 1 << 6;
        /// DOCSIS cable modem.
        const DOCSIS_CABLE    = 1 << 7;
        /// Source-route bridge.
        const SOURCE_BRIDGE   = 1 << 8;
        /// Station-only (host, not infrastructure).
        const HOST            = 1 << 9;
        /// Remotely managed device.
        const REMOTELY_MANAGED = 1 << 10;
        /// UPnP / DLNA media device — IoT / consumer.
        const UPNP            = 1 << 11;
        /// 802.1Q customer / service VLAN tagging.
        const C_VLAN          = 1 << 12;
        const S_VLAN          = 1 << 13;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AssetCapabilities {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AssetCapabilities {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(AssetCapabilities::from_bits_truncate(bits))
    }
}

bitflags! {
    /// Which parsers have contributed to this asset record.
    /// Useful for both ranking confidence and for surfacing
    /// per-protocol freshness in dashboards.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
    pub struct AssetSourceSet: u32 {
        const ARP   = 1 << 0;
        const NDP   = 1 << 1;
        const DHCP  = 1 << 2;
        const LLDP  = 1 << 3;
        const CDP   = 1 << 4;
        const SSDP  = 1 << 5;
        /// Reserved for future parsers — mDNS, NetBIOS-NS,
        /// SNMP-asset-discovery, etc.
        const OTHER = 1 << 31;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for AssetSourceSet {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for AssetSourceSet {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(AssetSourceSet::from_bits_truncate(bits))
    }
}

/// Per-parser fingerprints surfaced for this asset. Each is
/// `Option<String>` (rather than e.g. `Vec`) — devices have
/// at most one of each kind, and historical drift across
/// observations is recorded by overwrite (the most-recent
/// fingerprint wins).
#[derive(Debug, Clone, Default, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct AssetFingerprints {
    /// DHCP option-55 + option-60 (Fingerbank-style)
    /// fingerprint. Sourced from
    /// [`crate::dhcp::DhcpMessage::fingerprint`].
    pub dhcp: Option<String>,
    /// p0f-style TCP/IP fingerprint signature. Sourced from
    /// [`crate::tcp_fingerprint::TcpFingerprint::to_p0f_signature`].
    /// Consumers populate this themselves when they hold a
    /// TCP-fingerprint capture.
    pub p0f: Option<String>,
    /// HASSH client SSH fingerprint. From
    /// [`crate::ssh::SshKexInit::hassh`] (`from_client = true`).
    pub hassh: Option<String>,
    /// JA3 TLS-client fingerprint.
    pub ja3: Option<String>,
    /// JA4 TLS-client fingerprint.
    pub ja4: Option<String>,
}

impl AssetFingerprints {
    fn merge_from(&mut self, other: &AssetFingerprints) {
        if other.dhcp.is_some() {
            self.dhcp = other.dhcp.clone();
        }
        if other.p0f.is_some() {
            self.p0f = other.p0f.clone();
        }
        if other.hassh.is_some() {
            self.hassh = other.hassh.clone();
        }
        if other.ja3.is_some() {
            self.ja3 = other.ja3.clone();
        }
        if other.ja4.is_some() {
            self.ja4 = other.ja4.clone();
        }
    }
}

// ─── Per-parser adapter functions ────────────────────────────
//
// Each adapter takes a single parser-emitted message and
// returns a fresh `Asset` populated with whatever fields the
// message contributed. The caller absorbs it into an
// `Inventory` via `Inventory::absorb`, which merges by MAC.

#[cfg(feature = "arp")]
impl Asset {
    /// Build an `Asset` from one parsed ARP message. Uses
    /// `arp.sender` as the keying MAC and `arp.sender_ip` as
    /// the bound IPv4. The target side is intentionally NOT
    /// recorded — for ARP requests we don't know the target's
    /// MAC, and for replies the ARP-spoof case would lie.
    pub fn from_arp(arp: &crate::arp::ArpMessage) -> Self {
        let mut a = Self::new(arp.sender);
        a.ipv4.push(arp.sender_ip);
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::ARP;
        a
    }
}

#[cfg(feature = "ndp")]
impl Asset {
    /// Build an `Asset` from one NDP NS / NA message. Requires
    /// the message to carry a Link-Layer Address option;
    /// returns `None` when the lladdr is absent (NS without
    /// SLLA / NA without TLLA).
    pub fn from_ndp(ndp: &crate::ndp::NdpMessage) -> Option<Self> {
        let mac = ndp.lladdr?;
        let mut a = Self::new(mac);
        a.ipv6.push(ndp.target);
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::NDP;
        Some(a)
    }
}

#[cfg(feature = "dhcp")]
impl Asset {
    /// Build an `Asset` from one parsed DHCP message. Returns
    /// `None` when the message has no client-MAC (non-
    /// Ethernet htype/hlen — uncommon in practice). Pulls:
    ///
    /// - `client_mac` (chaddr) — primary key.
    /// - `ciaddr` and `yiaddr` — IPv4 bindings if non-zero.
    /// - `hostname` (opt 12) and `client_fqdn` (opt 81).
    /// - `vendor_class` (opt 60) → vendor_banner.
    /// - Fingerbank `fingerprint()` → fingerprints.dhcp.
    pub fn from_dhcp(dhcp: &crate::dhcp::DhcpMessage) -> Option<Self> {
        let mac = dhcp.client_mac?;
        let mut a = Self::new(mac);
        if !dhcp.ciaddr.is_unspecified() {
            a.ipv4.push(dhcp.ciaddr);
        }
        if !dhcp.yiaddr.is_unspecified() && !a.ipv4.contains(&dhcp.yiaddr) {
            a.ipv4.push(dhcp.yiaddr);
        }
        a.hostname = dhcp.hostname.clone();
        a.fqdn = dhcp.client_fqdn.clone();
        a.vendor_banner = dhcp.vendor_class.clone();
        a.fingerprints.dhcp = dhcp.fingerprint();
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::DHCP;
        Some(a)
    }
}

#[cfg(feature = "lldp")]
impl Asset {
    /// Build an `Asset` from one parsed LLDP message. The
    /// keying MAC comes from the Chassis-ID TLV when it's a
    /// MAC subtype; falls back to `None` for non-MAC chassis
    /// IDs (interface-name / network-address / locally-
    /// assigned). Pulls system-name → hostname,
    /// system-description → vendor_banner, capabilities,
    /// management-addresses → ipv4/ipv6.
    pub fn from_lldp(lldp: &crate::lldp::LldpMessage) -> Option<Self> {
        let mac = match &lldp.chassis_id {
            crate::lldp::ChassisId::MacAddress(m) => *m,
            _ => return None,
        };
        let mut a = Self::new(mac);
        if let Some(name) = &lldp.system_name
            && let Ok(s) = std::str::from_utf8(name)
        {
            a.hostname = Some(s.to_string());
        }
        if let Some(desc) = &lldp.system_description
            && let Ok(s) = std::str::from_utf8(desc)
        {
            a.vendor_banner = Some(s.to_string());
        }
        if let Some(caps) = &lldp.capabilities {
            a.capabilities |= lldp_caps_to_asset(caps.system);
        }
        for mgmt in &lldp.management_addresses {
            if let Some(std::net::IpAddr::V4(v4)) = mgmt.ip {
                if !a.ipv4.contains(&v4) {
                    push_bounded(&mut a.ipv4, v4, MAX_IPS_PER_ASSET);
                }
            } else if let Some(std::net::IpAddr::V6(v6)) = mgmt.ip
                && !a.ipv6.contains(&v6)
            {
                push_bounded(&mut a.ipv6, v6, MAX_IPS_PER_ASSET);
            }
        }
        a.seen_via |= AssetSourceSet::LLDP;
        Some(a)
    }
}

#[cfg(feature = "cdp")]
impl Asset {
    /// Build an `Asset` from one parsed CDP message. CDP
    /// doesn't carry a MAC in its TLVs (the SNAP source MAC
    /// is the device); the caller must provide
    /// `source_mac`.
    pub fn from_cdp(cdp: &crate::cdp::CdpMessage, source_mac: MacAddr) -> Self {
        let mut a = Self::new(source_mac);
        if let Some(devid) = &cdp.device_id
            && let Ok(s) = std::str::from_utf8(devid)
        {
            a.hostname = Some(s.to_string());
        }
        if let Some(sw) = &cdp.software_version
            && let Ok(s) = std::str::from_utf8(sw)
        {
            a.vendor_banner = Some(s.to_string());
        }
        if let Some(plat) = &cdp.platform
            && let Ok(s) = std::str::from_utf8(plat)
        {
            a.platform = Some(s.to_string());
        }
        if let Some(caps) = cdp.capabilities {
            a.capabilities |= cdp_caps_to_asset(caps);
        }
        for addr in cdp.management_addresses.iter().chain(cdp.addresses.iter()) {
            match addr.ip {
                Some(std::net::IpAddr::V4(v4)) if !a.ipv4.contains(&v4) => {
                    push_bounded(&mut a.ipv4, v4, MAX_IPS_PER_ASSET);
                }
                Some(std::net::IpAddr::V6(v6)) if !a.ipv6.contains(&v6) => {
                    push_bounded(&mut a.ipv6, v6, MAX_IPS_PER_ASSET);
                }
                _ => {}
            }
        }
        a.seen_via |= AssetSourceSet::CDP;
        a
    }
}

#[cfg(feature = "ssdp")]
impl Asset {
    /// Build an `Asset` from one parsed SSDP message. SSDP
    /// payloads carry no MAC and no IP (the LOCATION URL has
    /// one inside the URL but parsing it is fragile); the
    /// caller provides `source_mac`.
    pub fn from_ssdp(ssdp: &crate::ssdp::SsdpMessage, source_mac: MacAddr) -> Self {
        let mut a = Self::new(source_mac);
        a.vendor_banner = ssdp.server.clone();
        a.capabilities |= AssetCapabilities::UPNP | AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::SSDP;
        a
    }
}

#[cfg(feature = "lldp")]
fn lldp_caps_to_asset(c: crate::lldp::CapabilityBits) -> AssetCapabilities {
    use crate::lldp::CapabilityBits as L;
    let mut out = AssetCapabilities::empty();
    if c.contains(L::BRIDGE) {
        out |= AssetCapabilities::BRIDGE;
    }
    if c.contains(L::ROUTER) {
        out |= AssetCapabilities::ROUTER;
    }
    if c.contains(L::WLAN_AP) {
        out |= AssetCapabilities::WLAN_AP;
    }
    if c.contains(L::TELEPHONE) {
        out |= AssetCapabilities::PHONE;
    }
    if c.contains(L::REPEATER) {
        out |= AssetCapabilities::REPEATER;
    }
    if c.contains(L::DOCSIS_CABLE) {
        out |= AssetCapabilities::DOCSIS_CABLE;
    }
    if c.contains(L::STATION_ONLY) {
        out |= AssetCapabilities::HOST;
    }
    if c.contains(L::C_VLAN) {
        out |= AssetCapabilities::C_VLAN;
    }
    if c.contains(L::S_VLAN) {
        out |= AssetCapabilities::S_VLAN;
    }
    out
}

#[cfg(feature = "cdp")]
fn cdp_caps_to_asset(c: crate::cdp::CdpCapabilities) -> AssetCapabilities {
    use crate::cdp::CdpCapabilities as C;
    let mut out = AssetCapabilities::empty();
    if c.contains(C::ROUTER) {
        out |= AssetCapabilities::ROUTER;
    }
    if c.contains(C::BRIDGE) {
        out |= AssetCapabilities::BRIDGE;
    }
    if c.contains(C::SOURCE_BRIDGE) {
        out |= AssetCapabilities::SOURCE_BRIDGE;
    }
    if c.contains(C::SWITCH) {
        out |= AssetCapabilities::SWITCH;
    }
    if c.contains(C::HOST) {
        out |= AssetCapabilities::HOST;
    }
    if c.contains(C::IGMP) {
        out |= AssetCapabilities::IGMP;
    }
    if c.contains(C::REPEATER) {
        out |= AssetCapabilities::REPEATER;
    }
    if c.contains(C::PHONE) {
        out |= AssetCapabilities::PHONE;
    }
    if c.contains(C::REMOTELY_MANAGED) {
        out |= AssetCapabilities::REMOTELY_MANAGED;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_asset_starts_empty() {
        let a = Asset::new(MacAddr([1, 2, 3, 4, 5, 6]));
        assert_eq!(a.mac, MacAddr([1, 2, 3, 4, 5, 6]));
        assert!(a.ipv4.is_empty());
        assert!(a.ipv6.is_empty());
        assert_eq!(a.seen_via, AssetSourceSet::empty());
    }

    #[test]
    fn merge_unions_capabilities_and_seen_via() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::DHCP;
        let mut b = Asset::new(mac);
        b.capabilities |= AssetCapabilities::ROUTER;
        b.seen_via |= AssetSourceSet::LLDP;
        a.merge(&b);
        assert!(a.capabilities.contains(AssetCapabilities::HOST));
        assert!(a.capabilities.contains(AssetCapabilities::ROUTER));
        assert!(a.seen_via.contains(AssetSourceSet::DHCP));
        assert!(a.seen_via.contains(AssetSourceSet::LLDP));
    }

    #[test]
    fn merge_dedupes_ips_and_caps_at_bound() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.ipv4 = vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
        ];
        let mut b = Asset::new(mac);
        b.ipv4 = vec![
            Ipv4Addr::new(10, 0, 0, 2), // dup
            Ipv4Addr::new(10, 0, 0, 4),
            Ipv4Addr::new(10, 0, 0, 5), // pushes past MAX
        ];
        a.merge(&b);
        // De-duped, bounded at MAX_IPS_PER_ASSET = 4.
        assert_eq!(a.ipv4.len(), MAX_IPS_PER_ASSET);
        assert!(
            !a.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 1)),
            "oldest should have been evicted to make room"
        );
        assert!(a.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn fingerprints_overwrite_on_merge() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.fingerprints.dhcp = Some("OLD".into());
        let mut b = Asset::new(mac);
        b.fingerprints.dhcp = Some("NEW".into());
        a.merge(&b);
        assert_eq!(a.fingerprints.dhcp.as_deref(), Some("NEW"));
    }

    #[test]
    fn fingerprints_keep_when_other_is_none() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.fingerprints.dhcp = Some("ORIGINAL".into());
        let b = Asset::new(mac);
        a.merge(&b);
        assert_eq!(a.fingerprints.dhcp.as_deref(), Some("ORIGINAL"));
    }
}
