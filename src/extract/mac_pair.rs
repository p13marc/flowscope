//! [`MacPair`] — L2 MAC pair extractor.

use crate::MacAddr;
use crate::extractor::{Extracted, FlowExtractor, Orientation};
use crate::view::PacketView;

/// Extracts a MAC-pair flow key from the L2 Ethernet header.
/// Works on any frame regardless of L3 — useful for ARP, BPDU,
/// LLDP, link-local conversations.
///
/// Bidirectional: src↔dst MAC is one flow.
#[derive(Debug, Clone, Copy, Default)]
pub struct MacPair;

/// Bidirectional MAC pair (canonical ordering: `a < b`).
///
/// Issue #1 (0.17): migrated from raw `[u8; 6]` to the
/// [`MacAddr`] newtype for proper Display, predicates, and
/// type safety. Marked `#[non_exhaustive]` so a future
/// EtherType / VLAN-context field can be added additively.
#[derive(Debug, Clone, Copy, Hash, Eq, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct MacPairKey {
    pub a: MacAddr,
    pub b: MacAddr,
}

impl MacPairKey {
    /// Construct a key from `a` + `b`.
    ///
    /// Does NOT enforce canonical ordering — callers that want
    /// bidirectional equality should sort the pair before
    /// constructing.
    #[inline]
    pub fn new(a: MacAddr, b: MacAddr) -> Self {
        Self { a, b }
    }
}

impl FlowExtractor for MacPair {
    type Key = MacPairKey;

    fn extract(&self, view: PacketView<'_>) -> Option<Extracted<MacPairKey>> {
        if view.frame.len() < 14 {
            return None;
        }
        let mut dst = [0u8; 6];
        let mut src = [0u8; 6];
        dst.copy_from_slice(&view.frame[0..6]);
        src.copy_from_slice(&view.frame[6..12]);
        let (a, b, orientation) = if src > dst {
            (MacAddr(dst), MacAddr(src), Orientation::Reverse)
        } else {
            (MacAddr(src), MacAddr(dst), Orientation::Forward)
        };
        Some(Extracted {
            key: MacPairKey { a, b },
            orientation,
            l4: None,
            tcp: None,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;

    #[test]
    fn extracts_mac_pair() {
        let mut f = vec![0u8; 64];
        f[0..6].copy_from_slice(&[0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        f[6..12].copy_from_slice(&[0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
        let e = MacPair
            .extract(PacketView::new(&f, Timestamp::default()))
            .unwrap();
        // src < dst so a=src, b=dst, orientation=forward
        assert_eq!(e.key.a, MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        assert_eq!(e.key.b, MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]));
        assert_eq!(e.orientation, Orientation::Forward);
    }

    #[test]
    fn truncated_returns_none() {
        let f = [0u8; 8];
        assert!(
            MacPair
                .extract(PacketView::new(&f, Timestamp::default()))
                .is_none()
        );
    }

    #[test]
    fn bidirectional_canonical() {
        let mut fwd = vec![0u8; 14];
        fwd[0..6].copy_from_slice(&[1; 6]);
        fwd[6..12].copy_from_slice(&[2; 6]);
        let mut rev = vec![0u8; 14];
        rev[0..6].copy_from_slice(&[2; 6]);
        rev[6..12].copy_from_slice(&[1; 6]);
        let e_fwd = MacPair
            .extract(PacketView::new(&fwd, Timestamp::default()))
            .unwrap();
        let e_rev = MacPair
            .extract(PacketView::new(&rev, Timestamp::default()))
            .unwrap();
        assert_eq!(e_fwd.key, e_rev.key);
        assert_ne!(e_fwd.orientation, e_rev.orientation);
    }
}
