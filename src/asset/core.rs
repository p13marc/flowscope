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
    /// Primary hostname — the most-recently observed. Sourced
    /// from DHCP option 12 ("hostname") or LLDP / CDP "system
    /// name" TLV. See [`hostnames`](Self::hostnames) for the full
    /// set a roaming / multi-named device has published.
    pub hostname: Option<String>,
    /// Every distinct hostname ever bound to `mac` (bounded,
    /// oldest-evicted). A device may publish several names across
    /// DHCP / LLDP / mDNS / NBNS; a single `hostname` is lossy for
    /// the correlation entity model. `hostname` mirrors the most
    /// recent entry. Issue #137 (0.22).
    pub hostnames: Vec<String>,
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
    /// X.509 leaf-certificate subject CN presented by this asset
    /// (when acting as a TLS server). Populated by
    /// [`from_tls_handshake`](Self::from_tls_handshake) under the
    /// `ja4plus` feature. Issue #137 (0.22).
    pub x509_subject: Option<String>,
    /// X.509 leaf-certificate Subject Alternative Names (DNS
    /// entries) presented by this asset. A cert-based pivot for
    /// entity resolution. Populated under `ja4plus`. Bounded,
    /// oldest-evicted. Issue #137 (0.22).
    pub x509_sans: Vec<String>,
    /// Which parsers have contributed to this record.
    pub seen_via: AssetSourceSet,
    /// First observation timestamp — set when the record is
    /// created and preserved (min) across merges. Issue #137 (0.22).
    pub first_seen: Timestamp,
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
            hostnames: Vec::new(),
            fqdn: None,
            vendor_banner: None,
            platform: None,
            capabilities: AssetCapabilities::empty(),
            fingerprints: AssetFingerprints::default(),
            x509_subject: None,
            x509_sans: Vec::new(),
            seen_via: AssetSourceSet::empty(),
            first_seen: Timestamp::default(),
            last_seen: Timestamp::default(),
        }
    }

    /// Set the primary hostname and record it in the plural
    /// [`hostnames`](Self::hostnames) set (deduped, bounded).
    /// Internal helper used by the parser adapters.
    fn set_hostname(&mut self, name: String) {
        if !self.hostnames.contains(&name) {
            push_bounded(&mut self.hostnames, name.clone(), MAX_HOSTNAMES_PER_ASSET);
        }
        self.hostname = Some(name);
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
        for name in &other.hostnames {
            if !self.hostnames.contains(name) {
                push_bounded(&mut self.hostnames, name.clone(), MAX_HOSTNAMES_PER_ASSET);
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
        if other.x509_subject.is_some() {
            self.x509_subject = other.x509_subject.clone();
        }
        for san in &other.x509_sans {
            if !self.x509_sans.contains(san) {
                push_bounded(&mut self.x509_sans, san.clone(), MAX_HOSTNAMES_PER_ASSET);
            }
        }
        self.capabilities |= other.capabilities;
        self.fingerprints.merge_from(&other.fingerprints);
        self.seen_via |= other.seen_via;
        // first_seen is the earliest non-default observation.
        if self.first_seen == Timestamp::default()
            || (other.first_seen != Timestamp::default() && other.first_seen < self.first_seen)
        {
            self.first_seen = other.first_seen;
        }
        if other.last_seen > self.last_seen {
            self.last_seen = other.last_seen;
        }
    }

    /// Number of distinct parser sources that have contributed to
    /// this record — a coarse confidence signal (a MAC seen via
    /// ARP + DHCP + LLDP + TLS is far more trustworthy than one
    /// seen via a single spoofable source). Issue #137 (0.22).
    pub fn source_count(&self) -> u32 {
        self.seen_via.bits().count_ones()
    }

    /// Best-guess device role derived from the capability bitmask.
    /// Infrastructure roles win over host; see [`AssetRole`].
    /// Issue #137 (0.22).
    pub fn role(&self) -> AssetRole {
        let c = self.capabilities;
        if c.intersects(AssetCapabilities::ROUTER) {
            AssetRole::Router
        } else if c.intersects(AssetCapabilities::SWITCH | AssetCapabilities::BRIDGE) {
            AssetRole::Switch
        } else if c.intersects(AssetCapabilities::WLAN_AP) {
            AssetRole::AccessPoint
        } else if c.intersects(AssetCapabilities::PHONE) {
            AssetRole::Phone
        } else if c.intersects(AssetCapabilities::UPNP) {
            AssetRole::Iot
        } else if c.intersects(AssetCapabilities::HOST) {
            AssetRole::Host
        } else {
            AssetRole::Unknown
        }
    }
}

/// Maximum number of IPs (v4 or v6) we'll remember per asset.
/// Devices roaming between IPs on the same MAC accumulate
/// state; bound the growth. Lifted 4 → 16 in issue #137 —
/// multi-homed servers and roaming clients routinely exceed 4.
const MAX_IPS_PER_ASSET: usize = 16;

/// Maximum number of distinct hostnames / x509 SANs per asset.
const MAX_HOSTNAMES_PER_ASSET: usize = 8;

/// Coarse device role derived from an [`Asset`]'s capability
/// bitmask. Issue #137 (0.22).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum AssetRole {
    /// Layer 3 router.
    Router,
    /// Layer 2 switch / bridge.
    Switch,
    /// 802.11 access point.
    AccessPoint,
    /// VoIP / IP phone.
    Phone,
    /// UPnP / DLNA consumer / IoT device.
    Iot,
    /// General host / station.
    Host,
    /// No capability signal yet.
    #[default]
    Unknown,
}

impl AssetRole {
    /// Stable lowercase slug for logs / dashboards.
    pub fn as_str(&self) -> &'static str {
        match self {
            AssetRole::Router => "router",
            AssetRole::Switch => "switch",
            AssetRole::AccessPoint => "access-point",
            AssetRole::Phone => "phone",
            AssetRole::Iot => "iot",
            AssetRole::Host => "host",
            AssetRole::Unknown => "unknown",
        }
    }
}

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
        const MDNS  = 1 << 6;
        const NBNS  = 1 << 7;
        /// TLS handshake (JA3 / JA4 / x509). Issue #137 (0.22).
        const TLS   = 1 << 8;
        /// SSH KEXINIT (HASSH). Issue #137 (0.22).
        const SSH   = 1 << 9;
        /// p0f-style passive TCP/IP fingerprint. Issue #137 (0.22).
        const P0F   = 1 << 10;
        /// Reserved for future parsers — SNMP-asset-discovery, etc.
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
    /// JA4X x509-certificate fingerprint of the leaf cert this
    /// asset presented (as a TLS server). Populated under
    /// `ja4plus`. Issue #137 (0.22).
    pub ja4x: Option<String>,
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
        if other.ja4x.is_some() {
            self.ja4x = other.ja4x.clone();
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
        if let Some(h) = dhcp.hostname.clone() {
            a.set_hostname(h);
        }
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
            a.set_hostname(s.to_string());
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
            a.set_hostname(s.to_string());
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

#[cfg(feature = "mdns")]
impl Asset {
    /// Build an `Asset` from one parsed mDNS [`crate::dns::DnsResponse`].
    /// mDNS payloads carry no MAC; the caller must provide
    /// `source_mac` (typically the Ethernet source of the
    /// frame that carried the response). Returns `None` when
    /// the response contains nothing inventory-relevant —
    /// no `.local` A/AAAA bindings and no service-discovery
    /// PTRs.
    ///
    /// Pulls:
    ///
    /// - A / AAAA records whose name ends in `.local` →
    ///   `hostname` (set from the leftmost label of the first
    ///   matching record) + ipv4/ipv6 bindings.
    /// - Service-discovery PTR records (RFC 6763) →
    ///   `AssetCapabilities::UPNP | HOST`. The full
    ///   service vocabulary stays on the parsed `ServiceRecord`s
    ///   themselves; the inventory just records the device
    ///   class.
    pub fn from_mdns(resp: &crate::dns::DnsResponse, source_mac: MacAddr) -> Option<Self> {
        let mut a = Self::new(source_mac);
        let mut populated = false;

        // Walk every answer + additional looking for A / AAAA
        // bindings on `.local` names — those are the host's
        // direct address publications.
        let all_records = resp.answers.iter().chain(resp.additionals.iter());
        for rr in all_records {
            // DNS is case-insensitive (RFC 1035 §2.3.3) so
            // the suffix match needs to be too; but hostnames
            // are operationally display-relevant, so keep the
            // original case for the extracted value.
            let original = rr.name.strip_suffix('.').unwrap_or(&rr.name);
            let lower = original.to_ascii_lowercase();
            let Some(_) = lower.strip_suffix(".local") else {
                continue;
            };
            let hostname_orig = &original[..original.len() - ".local".len()];
            // hostname_label may itself contain dots (sub-
            // domain.local); take everything before any dot
            // as the leftmost label.
            let leftmost = hostname_orig.split('.').next().unwrap_or(hostname_orig);
            match &rr.data {
                crate::dns::DnsRdata::A(v4) => {
                    if !a.ipv4.contains(v4) {
                        push_bounded(&mut a.ipv4, *v4, MAX_IPS_PER_ASSET);
                    }
                    if a.hostname.is_none() && !leftmost.is_empty() {
                        a.set_hostname(leftmost.to_string());
                    }
                    populated = true;
                }
                crate::dns::DnsRdata::AAAA(v6) => {
                    if !a.ipv6.contains(v6) {
                        push_bounded(&mut a.ipv6, *v6, MAX_IPS_PER_ASSET);
                    }
                    if a.hostname.is_none() && !leftmost.is_empty() {
                        a.set_hostname(leftmost.to_string());
                    }
                    populated = true;
                }
                _ => {}
            }
        }

        // Walk service-discovery PTR records — every one
        // implies UPNP-class IoT capability.
        let services = crate::mdns::extract_services(resp);
        if !services.is_empty() {
            a.capabilities |= AssetCapabilities::UPNP | AssetCapabilities::HOST;
            populated = true;
        } else if populated {
            // Pure A/AAAA contribution — still a host.
            a.capabilities |= AssetCapabilities::HOST;
        }

        if populated {
            a.seen_via |= AssetSourceSet::MDNS;
            Some(a)
        } else {
            None
        }
    }
}

#[cfg(feature = "netbios-ns")]
impl Asset {
    /// Build an `Asset` from one parsed NetBIOS Name Service
    /// message. NBNS payloads carry no L2 — the caller must
    /// supply `source_mac` (the Ethernet source of the frame
    /// that carried the datagram). Returns `None` when the
    /// message has neither a `queried_name` nor any
    /// `answer_addresses` — nothing inventory-relevant.
    ///
    /// Pulls:
    ///
    /// - `queried_name` → `hostname` (the decoded NetBIOS
    ///   name, suffix-stripped).
    /// - Every address in `answer_addresses` → `ipv4`
    ///   bindings.
    /// - `AssetCapabilities::HOST` (NBNS is a station
    ///   protocol).
    /// - `AssetSourceSet::NBNS`.
    pub fn from_netbios_ns(
        nb: &crate::netbios_ns::NbnsMessage,
        source_mac: MacAddr,
    ) -> Option<Self> {
        if nb.queried_name.is_none() && nb.answer_addresses.is_empty() {
            return None;
        }
        let mut a = Self::new(source_mac);
        if let Some(name) = nb.queried_name.as_deref() {
            a.set_hostname(name.to_string());
        }
        for v4 in nb.answer_addresses.iter() {
            if !a.ipv4.contains(v4) {
                push_bounded(&mut a.ipv4, *v4, MAX_IPS_PER_ASSET);
            }
        }
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::NBNS;
        Some(a)
    }
}

#[cfg(feature = "tls")]
impl Asset {
    /// Build an `Asset` from a completed TLS handshake. TLS carries
    /// no L2, so the caller supplies `source_mac` (the Ethernet
    /// source of the frame that carried the handshake). Pulls the
    /// JA3 / JA4 client fingerprints, and — under `ja4plus` — the
    /// JA4X leaf fingerprint plus the leaf certificate's subject CN
    /// and DNS SANs for cert-based pivoting. Issue #137 (0.22).
    pub fn from_tls_handshake(hs: &crate::tls::TlsHandshake, source_mac: MacAddr) -> Self {
        let mut a = Self::new(source_mac);
        a.fingerprints.ja3 = hs.ja3.clone();
        a.fingerprints.ja4 = hs.ja4.clone();
        #[cfg(feature = "ja4plus")]
        {
            a.fingerprints.ja4x = hs.ja4x.clone();
            if let Some(leaf) = hs.certificate_chain.first() {
                extract_x509_identity(leaf, &mut a);
            }
        }
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::TLS;
        a
    }
}

#[cfg(feature = "ssh")]
impl Asset {
    /// Build an `Asset` from an SSH KEXINIT. SSH carries no L2, so
    /// the caller supplies `source_mac`. Records the HASSH
    /// fingerprint (client HASSH for `from_client`, HASSHServer
    /// otherwise). Issue #137 (0.22).
    pub fn from_ssh_kexinit(kex: &crate::ssh::SshKexInit, source_mac: MacAddr) -> Self {
        let mut a = Self::new(source_mac);
        if !kex.hassh.is_empty() {
            a.fingerprints.hassh = Some(kex.hassh.clone());
        }
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::SSH;
        a
    }
}

#[cfg(feature = "tcp_fingerprint")]
impl Asset {
    /// Build an `Asset` from a passive p0f-style TCP/IP
    /// fingerprint. The caller supplies `source_mac` (the Ethernet
    /// source of the SYN / SYN+ACK). Records the p0f-3 signature
    /// string. Issue #137 (0.22).
    pub fn from_tcp_fingerprint(
        fp: &crate::tcp_fingerprint::TcpFingerprint,
        source_mac: MacAddr,
    ) -> Self {
        let mut a = Self::new(source_mac);
        a.fingerprints.p0f = Some(fp.to_p0f_signature());
        a.capabilities |= AssetCapabilities::HOST;
        a.seen_via |= AssetSourceSet::P0F;
        a
    }
}

/// Pull the leaf certificate's subject CN + DNS SANs into the
/// asset. Best-effort — a cert that fails to parse contributes
/// nothing. Issue #137 (0.22).
#[cfg(all(feature = "tls", feature = "ja4plus"))]
fn extract_x509_identity(der: &[u8], a: &mut Asset) {
    use x509_parser::prelude::{FromDer, X509Certificate};

    let Ok((_, cert)) = X509Certificate::from_der(der) else {
        return;
    };
    // Subject common name.
    if let Some(cn) = cert.subject().iter_common_name().next()
        && let Ok(s) = cn.as_str()
    {
        a.x509_subject = Some(s.to_string());
    }
    // DNS SANs.
    if let Ok(Some(san)) = cert.subject_alternative_name() {
        for name in &san.value.general_names {
            if let x509_parser::extensions::GeneralName::DNSName(dns) = name
                && !a.x509_sans.contains(&dns.to_string())
            {
                push_bounded(&mut a.x509_sans, dns.to_string(), MAX_HOSTNAMES_PER_ASSET);
            }
        }
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
    fn merge_dedupes_ips() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.ipv4 = vec![
            Ipv4Addr::new(10, 0, 0, 1),
            Ipv4Addr::new(10, 0, 0, 2),
            Ipv4Addr::new(10, 0, 0, 3),
        ];
        let mut b = Asset::new(mac);
        b.ipv4 = vec![
            Ipv4Addr::new(10, 0, 0, 2), // dup — dropped
            Ipv4Addr::new(10, 0, 0, 4),
            Ipv4Addr::new(10, 0, 0, 5),
        ];
        a.merge(&b);
        assert_eq!(a.ipv4.len(), 5, "deduped union of both sets");
        assert!(a.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 5)));
    }

    #[test]
    fn ipv4_bounded_at_max() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        // Push MAX + 5 distinct IPs; oldest evicted, len capped.
        let mut b = Asset::new(mac);
        for i in 0..(MAX_IPS_PER_ASSET as u32 + 5) {
            b.ipv4.push(Ipv4Addr::from(0x0a00_0000 + i));
        }
        a.merge(&b);
        assert_eq!(a.ipv4.len(), MAX_IPS_PER_ASSET);
        // The very first pushed IP has been evicted.
        assert!(!a.ipv4.contains(&Ipv4Addr::from(0x0a00_0000)));
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

    #[test]
    fn role_derives_from_capabilities() {
        let mut a = Asset::new(MacAddr([0xaa; 6]));
        assert_eq!(a.role(), AssetRole::Unknown);
        a.capabilities |= AssetCapabilities::HOST;
        assert_eq!(a.role(), AssetRole::Host);
        // Infrastructure wins over host.
        a.capabilities |= AssetCapabilities::ROUTER;
        assert_eq!(a.role(), AssetRole::Router);
    }

    #[test]
    fn source_count_is_popcount_of_seen_via() {
        let mut a = Asset::new(MacAddr([0xaa; 6]));
        assert_eq!(a.source_count(), 0);
        a.seen_via |= AssetSourceSet::ARP | AssetSourceSet::DHCP | AssetSourceSet::TLS;
        assert_eq!(a.source_count(), 3);
    }

    #[test]
    fn plural_hostnames_accumulate_and_dedupe() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.set_hostname("laptop".into());
        a.set_hostname("laptop".into()); // dup — no growth
        a.set_hostname("laptop-vpn".into());
        assert_eq!(a.hostname.as_deref(), Some("laptop-vpn")); // primary = latest
        assert_eq!(a.hostnames.len(), 2);
        assert!(a.hostnames.contains(&"laptop".to_string()));
    }

    #[test]
    fn merge_keeps_earliest_first_seen() {
        let mac = MacAddr([0xaa; 6]);
        let mut a = Asset::new(mac);
        a.first_seen = Timestamp::new(100, 0);
        let mut b = Asset::new(mac);
        b.first_seen = Timestamp::new(50, 0);
        a.merge(&b);
        assert_eq!(a.first_seen, Timestamp::new(50, 0));
    }

    #[cfg(feature = "tls")]
    #[test]
    #[allow(clippy::field_reassign_with_default)] // TlsHandshake is #[non_exhaustive]
    fn tls_handshake_contributes_ja3_ja4_and_tls_source() {
        let mut hs = crate::tls::TlsHandshake::default();
        hs.ja3 = Some("deadbeef".into());
        hs.ja4 = Some("t13d1516h2_deadbeef_cafef00d".into());
        let a = Asset::from_tls_handshake(&hs, MacAddr([0xbb; 6]));
        assert_eq!(a.fingerprints.ja3.as_deref(), Some("deadbeef"));
        assert!(a.fingerprints.ja4.is_some());
        assert!(a.seen_via.contains(AssetSourceSet::TLS));
    }

    #[cfg(feature = "tcp_fingerprint")]
    #[test]
    fn tcp_fingerprint_contributes_p0f() {
        use crate::tcp_fingerprint::{Quirks, TcpDirection, TcpFingerprint};
        let fp = TcpFingerprint {
            direction: TcpDirection::Syn,
            ip_version: 4,
            observed_ttl: 64,
            guessed_initial_ttl: 64,
            options_length: 0,
            df: true,
            window_size: 65535,
            mss: Some(1460),
            window_scale: Some(7),
            sack_permitted: true,
            timestamps: true,
            option_layout: "mss,sok,ts,nop,ws".into(),
            quirks: Quirks::empty(),
        };
        let a = Asset::from_tcp_fingerprint(&fp, MacAddr([0xcc; 6]));
        assert!(a.fingerprints.p0f.is_some());
        assert!(a.seen_via.contains(AssetSourceSet::P0F));
    }
}
