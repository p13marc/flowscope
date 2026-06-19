//! [`RxMetadata`] — per-packet hardware-provided metadata from the
//! NIC's receive path.
//!
//! Modern NICs (especially via AF_XDP + bpf_xdp_metadata kfuncs)
//! can attach metadata to each packet without re-parsing it:
//! the RSS hash, hardware timestamp, VLAN tag, checksum status.
//! flowscope surfaces this through [`crate::PacketView::rx_metadata`]
//! so extractors and trackers can use it as a fast path (e.g.,
//! the NIC already hashed the 5-tuple — reuse it instead of
//! rehashing).
//!
//! Every field is **optional and independent**: a NIC may
//! provide the RSS hash but not the hardware timestamp; another
//! may give the VLAN tag but not the checksum status. Per-field
//! `Option` mirrors the kfunc `-EOPNOTSUPP` / `-ENODATA` reality.
//!
//! `RxMetadata::default()` is **all-absent**, so callers that
//! don't fill it in (pcap replay, synthetic test fixtures,
//! AF_PACKET COPY-mode capture) get a `PacketView` with no
//! metadata — the same shape `PacketView` had before this type
//! existed.
//!
//! Issue: #2 (0.17).

use crate::Timestamp;

/// Per-packet metadata from the NIC's receive path.
///
/// Fields are independently optional; a `Default` instance is
/// all-absent. [`PacketView`](crate::PacketView) carries one of
/// these per packet; live-capture sources fill it from the
/// driver, replay / synthetic sources leave it default.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RxMetadata {
    /// Hardware-provided receive timestamp. `None` when the
    /// driver returned `-ENODATA` or the source didn't query it.
    pub hw_timestamp: Option<Timestamp>,

    /// RSS hash + hash type as reported by the NIC. `None` when
    /// unsupported or unqueried. When present, the hash was
    /// computed by the NIC over the indicated header set and is
    /// directly reusable as a flow-key accelerator.
    pub rx_hash: Option<RxHash>,

    /// VLAN tag stripped from the frame by the NIC. `None` when
    /// no VLAN was stripped (frame was untagged, or VLAN
    /// stripping is disabled).
    pub vlan: Option<VlanTag>,

    /// Hardware checksum status. Default [`ChecksumStatus::Unknown`]
    /// means the driver didn't tell us — not a positive
    /// indication of correctness.
    pub checksum: ChecksumStatus,

    /// Caller-supplied source index, typically the NIC / capture
    /// channel identifier. Stays `0` when unused. Pairs with
    /// [`crate::extract::Tagged`] for per-source attribution
    /// without bolting source into the key path.
    pub source_idx: u32,
}

impl RxMetadata {
    /// `true` if no fields have been populated (every Option is
    /// `None`, checksum is `Unknown`, source_idx is `0`).
    ///
    /// Implemented as `*self == Self::default()` so future field
    /// additions don't silently make this return `true` for
    /// populated metadata — `Default + PartialEq` keep the check
    /// honest.
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }
}

/// RSS hash plus the type indicating which headers the NIC
/// hashed.
///
/// `#[non_exhaustive]` — future fields (seed, queue index, …)
/// will be additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct RxHash {
    /// 32-bit RSS hash value.
    pub value: u32,
    /// Which headers the NIC hashed over.
    pub ty: RssHashType,
}

impl RxHash {
    /// Construct an `RxHash` from its value + type.
    #[inline]
    pub fn new(value: u32, ty: RssHashType) -> Self {
        Self { value, ty }
    }
}

/// Which header set the NIC's RSS hash covers.
///
/// Mirrors Linux's `XDP_RSS_TYPE_*` enumeration so the
/// netring-side translation is a 1:1 enum mapping.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum RssHashType {
    /// L2 only (MAC src/dst).
    L2,
    /// IPv4 src/dst.
    L3Ipv4,
    /// IPv6 src/dst.
    L3Ipv6,
    /// 4-tuple over IPv4 TCP.
    L4TcpIpv4,
    /// 4-tuple over IPv4 UDP.
    L4UdpIpv4,
    /// 4-tuple over IPv4 SCTP.
    L4SctpIpv4,
    /// 4-tuple over IPv6 TCP.
    L4TcpIpv6,
    /// 4-tuple over IPv6 UDP.
    L4UdpIpv6,
    /// 4-tuple over IPv6 SCTP.
    L4SctpIpv6,
    /// NIC didn't report a specific type / type is opaque.
    Unknown,
}

/// VLAN tag stripped by the NIC.
///
/// `#[non_exhaustive]` — future fields (inner-tag TCI for QinQ,
/// drop count, …) will be additive.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct VlanTag {
    /// Tag Control Information (16 bits — PCP 3 / DEI 1 / VID 12).
    pub tci: u16,
    /// EtherType / TPID identifying the tag protocol.
    pub proto: VlanProto,
}

impl VlanTag {
    /// Construct a `VlanTag` from its raw TCI + protocol.
    #[inline]
    pub fn new(tci: u16, proto: VlanProto) -> Self {
        Self { tci, proto }
    }
}

impl VlanTag {
    /// VLAN ID — low 12 bits of the TCI.
    #[inline]
    pub fn vid(&self) -> u16 {
        self.tci & 0x0FFF
    }

    /// Priority Code Point — top 3 bits of the TCI.
    #[inline]
    pub fn pcp(&self) -> u8 {
        ((self.tci >> 13) & 0x07) as u8
    }

    /// Drop Eligible Indicator — bit 12 of the TCI.
    #[inline]
    pub fn dei(&self) -> bool {
        (self.tci >> 12) & 0x1 != 0
    }
}

/// VLAN tag protocol identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum VlanProto {
    /// 802.1Q — EtherType 0x8100.
    Dot1Q,
    /// 802.1ad ("QinQ") — EtherType 0x88A8.
    Dot1Ad,
    /// Other / vendor-specific. Holds the raw EtherType.
    Other(u16),
}

/// Hardware checksum status reported by the NIC.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum ChecksumStatus {
    /// Driver did not report a status. Default. **Not** a
    /// statement about correctness — the driver may have skipped
    /// the check entirely.
    #[default]
    Unknown,
    /// NIC validated the L3 + L4 checksum and it's correct.
    /// Equivalent to Linux's `CHECKSUM_UNNECESSARY`.
    Unnecessary,
    /// NIC computed the 16-bit one's-complement Internet
    /// Checksum (RFC 1071) over the L3 + L4 region; the
    /// receiver verifies pseudo-header inclusion. Equivalent to
    /// Linux's `CHECKSUM_COMPLETE`. Value is in network byte
    /// order.
    Complete(u16),
    /// NIC reported the checksum is bad. Caller may drop the
    /// packet, log it, or proceed depending on policy.
    Bad,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_empty() {
        let m = RxMetadata::default();
        assert!(m.is_empty());
        assert!(m.hw_timestamp.is_none());
        assert!(m.rx_hash.is_none());
        assert!(m.vlan.is_none());
        assert!(matches!(m.checksum, ChecksumStatus::Unknown));
        assert_eq!(m.source_idx, 0);
    }

    #[test]
    fn populated_is_not_empty() {
        let m = RxMetadata {
            source_idx: 1,
            ..RxMetadata::default()
        };
        assert!(!m.is_empty());
    }

    #[test]
    fn is_empty_flips_for_every_field_independently() {
        // Guard against the failure mode where is_empty becomes
        // stale on field addition: any single populated field
        // must flip is_empty to false. Implemented via
        // *self == Self::default(), so adding a future field
        // can't silently leave is_empty returning true.
        let with_ts = RxMetadata {
            hw_timestamp: Some(crate::Timestamp::default()),
            ..RxMetadata::default()
        };
        assert!(!with_ts.is_empty());

        let with_hash = RxMetadata {
            rx_hash: Some(RxHash::new(1, RssHashType::Unknown)),
            ..RxMetadata::default()
        };
        assert!(!with_hash.is_empty());

        let with_vlan = RxMetadata {
            vlan: Some(VlanTag::new(100, VlanProto::Dot1Q)),
            ..RxMetadata::default()
        };
        assert!(!with_vlan.is_empty());

        let with_chk = RxMetadata {
            checksum: ChecksumStatus::Unnecessary,
            ..RxMetadata::default()
        };
        assert!(!with_chk.is_empty());

        let with_src = RxMetadata {
            source_idx: 42,
            ..RxMetadata::default()
        };
        assert!(!with_src.is_empty());
    }

    #[test]
    fn rx_hash_carries_type() {
        let m = RxMetadata {
            rx_hash: Some(RxHash {
                value: 0xdeadbeef,
                ty: RssHashType::L4TcpIpv4,
            }),
            ..RxMetadata::default()
        };
        let h = m.rx_hash.unwrap();
        assert_eq!(h.value, 0xdeadbeef);
        assert!(matches!(h.ty, RssHashType::L4TcpIpv4));
    }

    #[test]
    fn vlan_tag_decomposes_tci() {
        // PCP=5 (binary 101), DEI=1, VID=100 (binary 0000 0110 0100)
        // TCI = (5 << 13) | (1 << 12) | 100 = 0xB064
        let tag = VlanTag {
            tci: 0xB064,
            proto: VlanProto::Dot1Q,
        };
        assert_eq!(tag.vid(), 100);
        assert_eq!(tag.pcp(), 5);
        assert!(tag.dei());
    }

    #[test]
    fn vlan_tag_zero_dei() {
        let tag = VlanTag {
            tci: 0x0064, // VID = 100, PCP/DEI = 0
            proto: VlanProto::Dot1Q,
        };
        assert_eq!(tag.vid(), 100);
        assert_eq!(tag.pcp(), 0);
        assert!(!tag.dei());
    }

    #[test]
    fn checksum_default_is_unknown() {
        let c = ChecksumStatus::default();
        assert!(matches!(c, ChecksumStatus::Unknown));
    }

    #[test]
    fn checksum_complete_carries_value() {
        let c = ChecksumStatus::Complete(0xABCD);
        match c {
            ChecksumStatus::Complete(v) => assert_eq!(v, 0xABCD),
            _ => panic!("expected Complete"),
        }
    }

    #[test]
    fn rx_metadata_is_send_sync_copy() {
        fn assert_traits<T: Send + Sync + Copy + 'static>() {}
        assert_traits::<RxMetadata>();
    }
}
