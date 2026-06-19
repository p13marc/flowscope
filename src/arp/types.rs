//! ARP message types.

use std::net::Ipv4Addr;

use crate::MacAddr;

/// One parsed ARP message.
///
/// flowscope rejects ARP messages that aren't Ethernet/IPv4
/// (htype != 1 || ptype != 0x0800 || hlen != 6 || plen != 4) —
/// `ArpMessage` is always IPv4 over Ethernet.
///
/// Issue #1 (0.17).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ArpMessage {
    /// Operation code (request / reply / RARP).
    pub oper: ArpOp,
    /// Sender's MAC address (from the ARP payload, NOT the
    /// Ethernet header's src — they can differ in spoofing).
    pub sender: MacAddr,
    /// Sender's IPv4 address.
    pub sender_ip: Ipv4Addr,
    /// Target's MAC address. Zero for requests where the target
    /// is unknown.
    pub target: MacAddr,
    /// Target's IPv4 address.
    pub target_ip: Ipv4Addr,
}

impl ArpMessage {
    /// `true` if this is a gratuitous announcement
    /// (`sender_ip == target_ip`). Hosts use these on boot or
    /// IP-change to refresh peers' ARP caches; spoofers use them
    /// to overwrite caches.
    #[inline]
    pub fn is_gratuitous(&self) -> bool {
        self.sender_ip == self.target_ip
    }

    /// `true` if this looks like an ARP-spoof announcement: a
    /// gratuitous reply where the target MAC differs from the
    /// sender's MAC and isn't a placeholder.
    ///
    /// Excludes the legitimate "I-just-booted" patterns:
    /// - `target == sender` (the canonical gratuitous form).
    /// - `target.is_zero()` (some stacks zero the target hw
    ///   address on broadcast announcements).
    /// - `target.is_broadcast()` (broadcast hw address as the
    ///   target — also a normal announcement).
    ///
    /// Returns `false` for requests even when gratuitous; the
    /// spoof pattern is specifically the gratuitous *reply*.
    #[inline]
    pub fn is_likely_spoof(&self) -> bool {
        matches!(self.oper, ArpOp::Reply)
            && self.is_gratuitous()
            && self.target != self.sender
            && !self.target.is_zero()
            && !self.target.is_broadcast()
    }
}

/// ARP operation code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum ArpOp {
    /// `OP=1`. "Who has X? Tell Y."
    Request,
    /// `OP=2`. "X is at MAC M."
    Reply,
    /// `OP=3`. RARP request — find my own IP given my MAC.
    RarpRequest,
    /// `OP=4`. RARP reply.
    RarpReply,
    /// Any other OP code (vendor / experimental).
    Other(u16),
}

impl ArpOp {
    /// Stable slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            ArpOp::Request => "request",
            ArpOp::Reply => "reply",
            ArpOp::RarpRequest => "rarp_request",
            ArpOp::RarpReply => "rarp_reply",
            ArpOp::Other(_) => "other",
        }
    }
}

impl From<u16> for ArpOp {
    fn from(op: u16) -> Self {
        match op {
            1 => ArpOp::Request,
            2 => ArpOp::Reply,
            3 => ArpOp::RarpRequest,
            4 => ArpOp::RarpReply,
            other => ArpOp::Other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make(
        oper: ArpOp,
        sender: [u8; 6],
        target: [u8; 6],
        sip: [u8; 4],
        tip: [u8; 4],
    ) -> ArpMessage {
        ArpMessage {
            oper,
            sender: MacAddr(sender),
            sender_ip: Ipv4Addr::new(sip[0], sip[1], sip[2], sip[3]),
            target: MacAddr(target),
            target_ip: Ipv4Addr::new(tip[0], tip[1], tip[2], tip[3]),
        }
    }

    #[test]
    fn arp_op_from_u16() {
        assert!(matches!(ArpOp::from(1), ArpOp::Request));
        assert!(matches!(ArpOp::from(2), ArpOp::Reply));
        assert!(matches!(ArpOp::from(3), ArpOp::RarpRequest));
        assert!(matches!(ArpOp::from(4), ArpOp::RarpReply));
        assert!(matches!(ArpOp::from(99), ArpOp::Other(99)));
    }

    #[test]
    fn arp_op_slugs() {
        assert_eq!(ArpOp::Request.as_str(), "request");
        assert_eq!(ArpOp::Reply.as_str(), "reply");
        assert_eq!(ArpOp::RarpRequest.as_str(), "rarp_request");
        assert_eq!(ArpOp::RarpReply.as_str(), "rarp_reply");
        assert_eq!(ArpOp::Other(99).as_str(), "other");
    }

    #[test]
    fn gratuitous_detection() {
        let msg = make(
            ArpOp::Request,
            [1; 6],
            [0; 6],
            [10, 0, 0, 1],
            [10, 0, 0, 1], // same as sender
        );
        assert!(msg.is_gratuitous());

        let msg = make(ArpOp::Request, [1; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2]);
        assert!(!msg.is_gratuitous());
    }

    #[test]
    fn likely_spoof_detection() {
        // Legitimate gratuitous reply — target MAC matches sender.
        let msg = make(
            ArpOp::Reply,
            [1; 6],
            [1; 6], // target == sender
            [10, 0, 0, 1],
            [10, 0, 0, 1],
        );
        assert!(msg.is_gratuitous());
        assert!(!msg.is_likely_spoof());

        // Spoof — target MAC differs from sender's claim.
        let msg = make(
            ArpOp::Reply,
            [1; 6],
            [2; 6], // attacker overwrites cache for host 2
            [10, 0, 0, 1],
            [10, 0, 0, 1],
        );
        assert!(msg.is_likely_spoof());

        // Requests aren't spoof signals even when gratuitous.
        let msg = make(ArpOp::Request, [1; 6], [2; 6], [10, 0, 0, 1], [10, 0, 0, 1]);
        assert!(!msg.is_likely_spoof());
    }

    #[test]
    fn broadcast_target_is_not_spoof() {
        // Broadcast announcement — host saying "I'm here, refresh
        // your cache." Target hardware address is all-ones; this
        // is the normal pattern, not a spoof.
        let msg = make(
            ArpOp::Reply,
            [1; 6],
            [0xff; 6], // broadcast target
            [10, 0, 0, 1],
            [10, 0, 0, 1],
        );
        assert!(msg.is_gratuitous());
        assert!(!msg.is_likely_spoof());
    }
}
