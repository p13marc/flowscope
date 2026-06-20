//! NDP message types.

use std::net::Ipv6Addr;

use crate::MacAddr;

/// One parsed NDP message — NS (Neighbor Solicitation) or NA
/// (Neighbor Advertisement).
///
/// Issue #6 (0.18).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct NdpMessage {
    /// Whether this is a Neighbor Solicitation or Advertisement.
    pub kind: NdpKind,
    /// The Target Address field from the message header — the
    /// IPv6 address being asked about (NS) or advertised (NA).
    pub target: Ipv6Addr,
    /// Source LL Address option (NS) or Target LL Address option
    /// (NA), if present. NS may carry it to tell the recipient
    /// "use this MAC for replies"; NA carries it to bind
    /// target → MAC in the recipient's neighbor cache.
    pub lladdr: Option<MacAddr>,
    /// (NA only) `R` flag — the sender is a router. Ignored on NS.
    pub router_flag: bool,
    /// (NA only) `S` flag — this advertisement is in response to
    /// a Neighbor Solicitation (solicited). Unsolicited NAs are
    /// gratuitous announcements and the typical NDP-spoof vector.
    pub solicited_flag: bool,
    /// (NA only) `O` flag — override. Tells the recipient to
    /// replace any existing cache entry for `target`. The
    /// SLAAC-poisoning attack rides O=1, S=0 (unsolicited
    /// override).
    pub override_flag: bool,
}

impl NdpMessage {
    /// `true` if this is an unsolicited override Neighbor
    /// Advertisement — the wire shape NDP-spoofing / SLAAC-
    /// poisoning attacks use to overwrite a victim's neighbor
    /// cache without any prior solicitation.
    ///
    /// Legitimate hosts may also emit this on first-hop / IP-
    /// change announcements; the predicate is not a
    /// classifier on its own. Combine with
    /// [`crate::correlate::NeighborTable`] for IP↔MAC
    /// stability change detection.
    #[inline]
    pub fn is_unsolicited_override(&self) -> bool {
        matches!(self.kind, NdpKind::Advertisement) && self.override_flag && !self.solicited_flag
    }

    /// `true` if the message looks like an NDP-spoof binding
    /// announcement: an unsolicited override NA carrying a
    /// Target LL Address option (without the lladdr the
    /// announcement can't poison a binding).
    ///
    /// Mirrors `ArpMessage::is_likely_spoof` for IPv6. The
    /// predicate is intentionally conservative — false
    /// positives on legitimate gratuitous announcements are
    /// expected. For accuracy, gate on a
    /// [`crate::correlate::NeighborTable`] binding-changed
    /// signal.
    #[inline]
    pub fn is_likely_spoof(&self) -> bool {
        self.is_unsolicited_override() && self.lladdr.is_some()
    }
}

/// NDP message kind. Currently NS and NA — Router
/// Solicitation / Advertisement / Redirect aren't decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum NdpKind {
    /// ICMPv6 Type 135 — Neighbor Solicitation.
    Solicitation,
    /// ICMPv6 Type 136 — Neighbor Advertisement.
    Advertisement,
}

impl NdpKind {
    /// Stable slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            NdpKind::Solicitation => "solicitation",
            NdpKind::Advertisement => "advertisement",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn na(
        target: [u8; 16],
        lladdr: Option<[u8; 6]>,
        router: bool,
        solicited: bool,
        ov: bool,
    ) -> NdpMessage {
        NdpMessage {
            kind: NdpKind::Advertisement,
            target: Ipv6Addr::from(target),
            lladdr: lladdr.map(MacAddr),
            router_flag: router,
            solicited_flag: solicited,
            override_flag: ov,
        }
    }

    #[test]
    fn ndp_kind_slugs() {
        assert_eq!(NdpKind::Solicitation.as_str(), "solicitation");
        assert_eq!(NdpKind::Advertisement.as_str(), "advertisement");
    }

    #[test]
    fn unsolicited_override_classification() {
        // O=1, S=0 — the spoof shape.
        let m = na([0; 16], Some([0x11; 6]), false, false, true);
        assert!(m.is_unsolicited_override());

        // Solicited override — legitimate reply.
        let m = na([0; 16], Some([0x11; 6]), false, true, true);
        assert!(!m.is_unsolicited_override());

        // Unsolicited but no override — not the spoof shape.
        let m = na([0; 16], Some([0x11; 6]), false, false, false);
        assert!(!m.is_unsolicited_override());
    }

    #[test]
    fn solicitation_never_unsolicited_override() {
        // The flag predicate is NA-specific; NS gets `false`
        // regardless of the override field.
        let m = NdpMessage {
            kind: NdpKind::Solicitation,
            target: Ipv6Addr::UNSPECIFIED,
            lladdr: Some(MacAddr([0; 6])),
            router_flag: false,
            solicited_flag: false,
            override_flag: true,
        };
        assert!(!m.is_unsolicited_override());
    }

    #[test]
    fn likely_spoof_requires_lladdr() {
        // Override + unsolicited without an lladdr can't bind
        // anything — not a spoof.
        let m = na([0; 16], None, false, false, true);
        assert!(m.is_unsolicited_override());
        assert!(!m.is_likely_spoof());

        let m = na([0; 16], Some([0x11; 6]), false, false, true);
        assert!(m.is_likely_spoof());
    }
}
