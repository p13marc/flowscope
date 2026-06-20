//! DHCP message + enums.

use std::net::Ipv4Addr;

use crate::MacAddr;

/// One parsed DHCP message — the BOOTP fixed header plus the
/// most operationally-interesting RFC 2132 options.
///
/// Issue #11 (0.18).
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DhcpMessage {
    /// BOOTP op: request (client→server) or reply (server→client).
    pub op: DhcpOp,
    /// DHCP option 53 message type, when present. Absent for
    /// pure BOOTP (legacy) — DHCP messages always carry it.
    pub msg_type: Option<DhcpMessageType>,
    /// Transaction ID — pairs a client request with its server
    /// reply.
    pub xid: u32,
    /// Client hardware address from the BOOTP `chaddr` field,
    /// decoded only when `htype = 1` (Ethernet) and `hlen = 6`.
    /// Non-Ethernet captures land here as `None`.
    pub client_mac: Option<MacAddr>,
    /// `ciaddr` — client's current IP (set by the client when
    /// renewing).
    pub ciaddr: Ipv4Addr,
    /// `yiaddr` — server's assigned IP (set by the server in
    /// OFFER / ACK).
    pub yiaddr: Ipv4Addr,
    /// `siaddr` — next server in the boot sequence.
    pub siaddr: Ipv4Addr,
    /// `giaddr` — relay-agent IP, set by a DHCP relay.
    pub giaddr: Ipv4Addr,
    /// Option 12 — hostname the client advertised.
    pub hostname: Option<String>,
    /// Option 50 — requested IP (typically on REQUEST).
    pub requested_ip: Option<Ipv4Addr>,
    /// Option 51 — lease time in seconds.
    pub lease_time: Option<u32>,
    /// Option 54 — server identifier (the DHCP server's IP).
    pub server_id: Option<Ipv4Addr>,
    /// Option 55 — Parameter Request List, ordered as the
    /// client sent it. The ordering matters for the
    /// Fingerbank fingerprint.
    pub param_request_list: Vec<u8>,
    /// Option 60 — Vendor Class Identifier (e.g.
    /// `"MSFT 5.0"` for modern Windows).
    pub vendor_class: Option<String>,
    /// Option 81 — Client FQDN, when present.
    pub client_fqdn: Option<String>,
}

impl DhcpMessage {
    /// Fingerbank-style DHCP fingerprint:
    /// `<option-55 list>|<option-60 string>`.
    ///
    /// The option-55 list is comma-separated decimal integers
    /// in the order the client requested them. The
    /// option-60 string is the raw Vendor Class Identifier
    /// (empty when not sent).
    ///
    /// Returns `None` when neither option is present — without
    /// at least one of the two there's no discriminating
    /// signal.
    ///
    /// ```
    /// use flowscope::dhcp::{DhcpMessage, DhcpOp};
    /// let mut msg = DhcpMessage::default();
    /// msg.param_request_list = vec![1, 3, 6, 15, 33, 253];
    /// msg.vendor_class = Some("MSFT 5.0".into());
    /// assert_eq!(
    ///     msg.fingerprint().as_deref(),
    ///     Some("1,3,6,15,33,253|MSFT 5.0"),
    /// );
    /// ```
    pub fn fingerprint(&self) -> Option<String> {
        if self.param_request_list.is_empty() && self.vendor_class.is_none() {
            return None;
        }
        let mut s = String::new();
        for (i, opt) in self.param_request_list.iter().enumerate() {
            if i > 0 {
                s.push(',');
            }
            s.push_str(&opt.to_string());
        }
        s.push('|');
        if let Some(vc) = &self.vendor_class {
            s.push_str(vc);
        }
        Some(s)
    }
}

impl Default for DhcpMessage {
    fn default() -> Self {
        Self {
            op: DhcpOp::BootRequest,
            msg_type: None,
            xid: 0,
            client_mac: None,
            ciaddr: Ipv4Addr::UNSPECIFIED,
            yiaddr: Ipv4Addr::UNSPECIFIED,
            siaddr: Ipv4Addr::UNSPECIFIED,
            giaddr: Ipv4Addr::UNSPECIFIED,
            hostname: None,
            requested_ip: None,
            lease_time: None,
            server_id: None,
            param_request_list: Vec::new(),
            vendor_class: None,
            client_fqdn: None,
        }
    }
}

/// BOOTP op code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DhcpOp {
    /// `Op = 1` — client → server.
    BootRequest,
    /// `Op = 2` — server → client.
    BootReply,
    /// Any other op code.
    Other(u8),
}

impl DhcpOp {
    /// Stable slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpOp::BootRequest => "boot_request",
            DhcpOp::BootReply => "boot_reply",
            DhcpOp::Other(_) => "other",
        }
    }
}

impl From<u8> for DhcpOp {
    fn from(op: u8) -> Self {
        match op {
            1 => DhcpOp::BootRequest,
            2 => DhcpOp::BootReply,
            other => DhcpOp::Other(other),
        }
    }
}

/// DHCP message type (option 53) — RFC 2132 §9.6.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DhcpMessageType {
    /// 1 — DHCPDISCOVER (client broadcasting for a server).
    Discover,
    /// 2 — DHCPOFFER (server proposing a lease).
    Offer,
    /// 3 — DHCPREQUEST (client committing to an offer).
    Request,
    /// 4 — DHCPDECLINE (client rejecting after conflict).
    Decline,
    /// 5 — DHCPACK (server confirming a lease).
    Ack,
    /// 6 — DHCPNAK (server denying a request).
    Nak,
    /// 7 — DHCPRELEASE (client releasing a lease).
    Release,
    /// 8 — DHCPINFORM (client requesting only configuration).
    Inform,
    /// Any other message-type byte value.
    Other(u8),
}

impl DhcpMessageType {
    /// Stable slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            DhcpMessageType::Discover => "discover",
            DhcpMessageType::Offer => "offer",
            DhcpMessageType::Request => "request",
            DhcpMessageType::Decline => "decline",
            DhcpMessageType::Ack => "ack",
            DhcpMessageType::Nak => "nak",
            DhcpMessageType::Release => "release",
            DhcpMessageType::Inform => "inform",
            DhcpMessageType::Other(_) => "other",
        }
    }
}

impl From<u8> for DhcpMessageType {
    fn from(b: u8) -> Self {
        match b {
            1 => DhcpMessageType::Discover,
            2 => DhcpMessageType::Offer,
            3 => DhcpMessageType::Request,
            4 => DhcpMessageType::Decline,
            5 => DhcpMessageType::Ack,
            6 => DhcpMessageType::Nak,
            7 => DhcpMessageType::Release,
            8 => DhcpMessageType::Inform,
            other => DhcpMessageType::Other(other),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dhcp_op_slugs_and_from_u8() {
        assert_eq!(DhcpOp::from(1), DhcpOp::BootRequest);
        assert_eq!(DhcpOp::from(2), DhcpOp::BootReply);
        assert_eq!(DhcpOp::from(99), DhcpOp::Other(99));
        assert_eq!(DhcpOp::BootRequest.as_str(), "boot_request");
        assert_eq!(DhcpOp::BootReply.as_str(), "boot_reply");
    }

    #[test]
    fn dhcp_msg_type_slugs() {
        assert_eq!(DhcpMessageType::Discover.as_str(), "discover");
        assert_eq!(DhcpMessageType::Ack.as_str(), "ack");
        assert_eq!(DhcpMessageType::Nak.as_str(), "nak");
        assert_eq!(DhcpMessageType::from(1), DhcpMessageType::Discover);
        assert_eq!(DhcpMessageType::from(99), DhcpMessageType::Other(99));
    }

    #[test]
    fn fingerprint_combines_opt55_and_opt60() {
        let msg = DhcpMessage {
            param_request_list: vec![1, 3, 6, 15, 33, 253],
            vendor_class: Some("MSFT 5.0".into()),
            ..DhcpMessage::default()
        };
        assert_eq!(
            msg.fingerprint().as_deref(),
            Some("1,3,6,15,33,253|MSFT 5.0")
        );
    }

    #[test]
    fn fingerprint_with_only_opt55() {
        let msg = DhcpMessage {
            param_request_list: vec![1, 3],
            ..DhcpMessage::default()
        };
        assert_eq!(msg.fingerprint().as_deref(), Some("1,3|"));
    }

    #[test]
    fn fingerprint_with_only_opt60() {
        let msg = DhcpMessage {
            vendor_class: Some("android-dhcp-14".into()),
            ..DhcpMessage::default()
        };
        assert_eq!(msg.fingerprint().as_deref(), Some("|android-dhcp-14"));
    }

    #[test]
    fn fingerprint_none_when_neither_present() {
        let msg = DhcpMessage::default();
        assert_eq!(msg.fingerprint(), None);
    }
}
