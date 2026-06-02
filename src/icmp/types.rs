//! Type definitions for parsed ICMPv4 / ICMPv6 messages.

use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::extractor::L4Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum IcmpFamily {
    V4,
    V6,
}

/// One parsed ICMP message. Discriminated by [`Self::ty`]'s
/// `V4(_)` / `V6(_)` outer variant; the inner enum carries
/// type-specific payload. The [`Self::family`] field is
/// redundant with the outer variant but cheap to keep and saves
/// consumers a pattern match when they only need to route on
/// family.
#[derive(Debug, Clone)]
pub struct IcmpMessage {
    pub family: IcmpFamily,
    pub ty: IcmpType,
}

/// Outer ICMP type discriminant. Split per IP version because
/// the type-number spaces don't align (`EchoRequest = 8` on
/// v4 vs `128` on v6) and the v6-specific Neighbor Discovery
/// types don't appear in v4 at all.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum IcmpType {
    V4(Icmpv4Type),
    V6(Icmpv6Type),
}

// ── ICMPv4 ──────────────────────────────────────────────────────

/// Parsed ICMPv4 type. Coverage focuses on the operationally
/// relevant types; rarely-seen / obsolete types collapse into
/// [`Self::Other`] with the raw type byte and code preserved.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Icmpv4Type {
    /// Type 0.
    EchoReply { id: u16, seq: u16 },
    /// Type 3. `inner` carries the embedded original IP header +
    /// first 8 bytes of L4 payload — the cross-protocol
    /// correlation primitive. `None` when the embed is truncated
    /// or unparseable.
    DestinationUnreachable {
        code: Icmpv4DestUnreachCode,
        inner: Option<IcmpInner>,
    },
    /// Type 5.
    Redirect {
        code: Icmpv4RedirectCode,
        gateway: Ipv4Addr,
        inner: Option<IcmpInner>,
    },
    /// Type 8.
    EchoRequest { id: u16, seq: u16 },
    /// Type 11.
    TimeExceeded {
        code: Icmpv4TimeExceededCode,
        inner: Option<IcmpInner>,
    },
    /// Type 12.
    ParameterProblem {
        pointer: u8,
        inner: Option<IcmpInner>,
    },
    /// Type 13 / 14 — id/seq plus three 32-bit timestamps.
    Timestamp {
        id: u16,
        seq: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    /// Type 14.
    TimestampReply {
        id: u16,
        seq: u16,
        originate: u32,
        receive: u32,
        transmit: u32,
    },
    /// Catch-all for types we don't decode (Source Quench /
    /// Router Advertisement / Router Solicitation / Address Mask
    /// / Traceroute / vendor extensions). `raw_type` is the
    /// on-wire type byte, `raw_code` the code byte, `raw_body`
    /// the remainder of the L4 payload.
    Other {
        raw_type: u8,
        raw_code: u8,
        raw_body: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4DestUnreachCode {
    Net,
    Host,
    Protocol,
    Port,
    FragmentationNeeded { mtu: Option<u16> },
    SourceRouteFailed,
    DestNetworkUnknown,
    DestHostUnknown,
    SourceHostIsolated,
    NetworkProhibited,
    HostProhibited,
    NetworkTos,
    HostTos,
    CommunicationProhibited,
    HostPrecedenceViolation,
    PrecedenceCutoffInEffect,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4RedirectCode {
    Network,
    Host,
    Tos,
    TosHost,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv4TimeExceededCode {
    HopLimitExceeded,
    FragmentReassemblyTimeExceeded,
    Other(u8),
}

// ── ICMPv6 ──────────────────────────────────────────────────────

/// Parsed ICMPv6 type. Coverage includes error messages, echo,
/// and the two most common Neighbor Discovery messages (NS, NA);
/// MLD, RS, RA, Redirect collapse into [`Self::Other`].
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Icmpv6Type {
    /// Type 1.
    DestinationUnreachable {
        code: Icmpv6DestUnreachCode,
        inner: Option<IcmpInner>,
    },
    /// Type 2.
    PacketTooBig { mtu: u32, inner: Option<IcmpInner> },
    /// Type 3.
    TimeExceeded {
        code: Icmpv6TimeExceededCode,
        inner: Option<IcmpInner>,
    },
    /// Type 4.
    ParameterProblem {
        code: Icmpv6ParamProblemCode,
        pointer: u32,
        inner: Option<IcmpInner>,
    },
    /// Type 128.
    EchoRequest { id: u16, seq: u16 },
    /// Type 129.
    EchoReply { id: u16, seq: u16 },
    /// Type 135 — Neighbor Solicitation (RFC 4861).
    NeighborSolicitation { target: Ipv6Addr },
    /// Type 136 — Neighbor Advertisement (RFC 4861). Flag bits
    /// from the message header.
    NeighborAdvertisement {
        target: Ipv6Addr,
        router: bool,
        solicited: bool,
        override_: bool,
    },
    /// Catch-all for v6 types we don't decode (Router
    /// Solicitation / Router Advertisement / Redirect / MLD /
    /// vendor extensions).
    Other {
        raw_type: u8,
        raw_code: u8,
        raw_body: Bytes,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6DestUnreachCode {
    NoRoute,
    AdminProhibited,
    BeyondScopeOfSource,
    AddressUnreachable,
    PortUnreachable,
    SourceAddressFailedIngressPolicy,
    RejectRouteToDestination,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded,
    FragmentReassemblyTimeExceeded,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum Icmpv6ParamProblemCode {
    ErroneousHeaderField,
    UnrecognizedNextHeaderType,
    UnrecognizedIpv6Option,
    Other(u8),
}

// ── Embedded original packet (in error messages) ───────────────

/// First-packet correlation slice extracted from the embedded
/// IP header in an ICMP error message. Lets consumers tie an
/// "ICMP unreachable" back to the specific TCP/UDP flow it
/// references — no separate lookup needed.
///
/// `src_port` / `dst_port` are populated when `proto` is TCP
/// (6) or UDP (17), parsed from the first 8 bytes of L4 payload
/// the original packet placed after the IP header. For other
/// protocols (or truncated embeds), they're `None`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcmpInner {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: L4Proto,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}
