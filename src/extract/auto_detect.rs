//! [`AutoDetectEncap`] — combinator that tries plain extraction
//! first, then each enabled decap variant, picking the first match.
//!
//! Convenient for mixed traffic where some flows are plain and
//! others are wrapped in VLAN / VXLAN / GTP-U / MPLS / GRE. For
//! homogeneous traffic, manual composition (e.g.
//! `StripVlan(InnerVxlan::new(...))`) is faster — `AutoDetectEncap`
//! pays up to 5× the per-packet parse cost on a miss.

use crate::extractor::{Extracted, FlowExtractor};
use crate::view::PacketView;

use super::{InnerGre, InnerGtpU, InnerVxlan, StripMpls, StripVlan};

/// Toggle which decap variants `AutoDetectEncap` tries.
///
/// Order is fixed: plain → VLAN → MPLS → VXLAN → GTP-U → GRE. The
/// first match wins.
#[derive(Debug, Clone, Copy)]
pub struct AutoEncapVariants {
    /// Try `StripVlan(...)`.
    pub vlan: bool,
    /// Try `StripMpls(...)`.
    pub mpls: bool,
    /// Try `InnerVxlan::new(...)` (UDP/4789).
    pub vxlan: bool,
    /// Try `InnerGtpU::new(...)` (UDP/2152).
    pub gtp_u: bool,
    /// Try `InnerGre::new(...)` (IP proto 47).
    pub gre: bool,
}

impl AutoEncapVariants {
    /// Enable every variant.
    pub fn all() -> Self {
        Self {
            vlan: true,
            mpls: true,
            vxlan: true,
            gtp_u: true,
            gre: true,
        }
    }

    /// Enable no variants — only plain extraction is tried.
    pub fn none() -> Self {
        Self {
            vlan: false,
            mpls: false,
            vxlan: false,
            gtp_u: false,
            gre: false,
        }
    }
}

impl Default for AutoEncapVariants {
    fn default() -> Self {
        Self::all()
    }
}

/// Run `extractor` over plain frames first, then over the enabled
/// decap variants, returning the first match.
#[derive(Debug, Clone)]
pub struct AutoDetectEncap<E> {
    /// The wrapped extractor that processes the (possibly decapped) frame.
    pub extractor: E,
    /// Which encapsulations to try. Default: all.
    pub variants: AutoEncapVariants,
}

impl<E> AutoDetectEncap<E> {
    /// Construct with all variants enabled.
    pub fn new(extractor: E) -> Self {
        Self {
            extractor,
            variants: AutoEncapVariants::all(),
        }
    }

    /// Construct with explicit variants.
    pub fn with_variants(extractor: E, variants: AutoEncapVariants) -> Self {
        Self {
            extractor,
            variants,
        }
    }
}

impl<E: FlowExtractor + Clone> FlowExtractor for AutoDetectEncap<E> {
    type Key = E::Key;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<E::Key>> {
        // 1. Plain.
        if let Some(e) = self.extractor.extract(view) {
            return Some(e);
        }
        // 2. VLAN.
        if self.variants.vlan
            && let Some(e) = StripVlan(self.extractor.clone()).extract(view)
        {
            return Some(e);
        }
        // 3. MPLS.
        if self.variants.mpls
            && let Some(e) = StripMpls(self.extractor.clone()).extract(view)
        {
            return Some(e);
        }
        // 4. VXLAN (UDP/4789).
        if self.variants.vxlan
            && let Some(e) = InnerVxlan::new(self.extractor.clone()).extract(view)
        {
            return Some(e);
        }
        // 5. GTP-U (UDP/2152).
        if self.variants.gtp_u
            && let Some(e) = InnerGtpU::new(self.extractor.clone()).extract(view)
        {
            return Some(e);
        }
        // 6. GRE (IP proto 47).
        if self.variants.gre
            && let Some(e) = InnerGre::new(self.extractor.clone()).extract(view)
        {
            return Some(e);
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::extract::FiveTuple;
    use crate::extract::parse::test_frames::ipv4_tcp;

    #[test]
    fn plain_traffic_works() {
        let bytes = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0,
            0x02,
            b"",
        );
        let v = PacketView::new(&bytes, Timestamp::default());
        let e = AutoDetectEncap::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_some());
    }

    #[test]
    fn variants_none_falls_back_to_plain_only() {
        let bytes = ipv4_tcp(
            [0; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            80,
            0,
            0,
            0x02,
            b"",
        );
        let v = PacketView::new(&bytes, Timestamp::default());
        let e =
            AutoDetectEncap::with_variants(FiveTuple::bidirectional(), AutoEncapVariants::none());
        assert!(e.extract(v).is_some());
    }

    #[test]
    fn unknown_traffic_returns_none() {
        // ARP frame — not handled by FiveTuple regardless of decap.
        let bytes: Vec<u8> = vec![0u8; 14]; // empty Ethernet, no L3
        let v = PacketView::new(&bytes, Timestamp::default());
        let e = AutoDetectEncap::new(FiveTuple::bidirectional());
        assert!(e.extract(v).is_none());
    }

    #[test]
    fn variants_default_is_all() {
        let v = AutoEncapVariants::default();
        assert!(v.vlan && v.mpls && v.vxlan && v.gtp_u && v.gre);
    }
}
