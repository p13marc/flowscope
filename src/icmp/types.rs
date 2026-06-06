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

// ── Convenience accessors (plan 84) ─────────────────────────────

impl IcmpType {
    /// `true` if this is an error-class type — one that carries an
    /// `inner: Option<IcmpInner>` field (Destination Unreachable,
    /// Redirect, Time Exceeded, Parameter Problem on v4; the v6
    /// counterparts plus Packet Too Big).
    ///
    /// Non-error types (Echo*, Timestamp*, Neighbor*, Other) return
    /// `false`.
    pub fn is_error(&self) -> bool {
        matches!(
            self,
            IcmpType::V4(
                Icmpv4Type::DestinationUnreachable { .. }
                    | Icmpv4Type::Redirect { .. }
                    | Icmpv4Type::TimeExceeded { .. }
                    | Icmpv4Type::ParameterProblem { .. },
            ) | IcmpType::V6(
                Icmpv6Type::DestinationUnreachable { .. }
                    | Icmpv6Type::PacketTooBig { .. }
                    | Icmpv6Type::TimeExceeded { .. }
                    | Icmpv6Type::ParameterProblem { .. },
            )
        )
    }

    /// `(short label, &IcmpInner)` for any error variant whose inner
    /// was successfully parsed. `None` for non-error types or
    /// truncated / unparseable embeds.
    ///
    /// The short label is the same slug [`Self::short_kind`] returns
    /// for error variants — stable, zero-allocation, suitable as a
    /// metric label.
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)> {
        let (label, inner) = match self {
            IcmpType::V4(Icmpv4Type::DestinationUnreachable { inner, .. }) => {
                ("dest_unreachable", inner.as_ref())
            }
            IcmpType::V4(Icmpv4Type::Redirect { inner, .. }) => ("redirect", inner.as_ref()),
            IcmpType::V4(Icmpv4Type::TimeExceeded { inner, .. }) => {
                ("time_exceeded", inner.as_ref())
            }
            IcmpType::V4(Icmpv4Type::ParameterProblem { inner, .. }) => {
                ("parameter_problem", inner.as_ref())
            }
            IcmpType::V6(Icmpv6Type::DestinationUnreachable { inner, .. }) => {
                ("dest_unreachable", inner.as_ref())
            }
            IcmpType::V6(Icmpv6Type::PacketTooBig { inner, .. }) => {
                ("packet_too_big", inner.as_ref())
            }
            IcmpType::V6(Icmpv6Type::TimeExceeded { inner, .. }) => {
                ("time_exceeded", inner.as_ref())
            }
            IcmpType::V6(Icmpv6Type::ParameterProblem { inner, .. }) => {
                ("parameter_problem", inner.as_ref())
            }
            _ => return None,
        };
        inner.map(|i| (label, i))
    }

    /// Stable variant slug. Zero-allocation `&'static str`; suitable
    /// as a metric label. v4 / v6 variants with the same semantic
    /// meaning share the same slug (`"echo_request"` etc.); use
    /// [`IcmpMessage::family`] to disambiguate.
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | v4/v6 EchoRequest | `"echo_request"` |
    /// | v4/v6 EchoReply | `"echo_reply"` |
    /// | v4/v6 DestinationUnreachable | `"dest_unreachable"` |
    /// | v4 Redirect | `"redirect"` |
    /// | v6 PacketTooBig | `"packet_too_big"` |
    /// | v4/v6 TimeExceeded | `"time_exceeded"` |
    /// | v4/v6 ParameterProblem | `"parameter_problem"` |
    /// | v4 Timestamp | `"timestamp"` |
    /// | v4 TimestampReply | `"timestamp_reply"` |
    /// | v6 NeighborSolicitation | `"neighbor_solicitation"` |
    /// | v6 NeighborAdvertisement | `"neighbor_advertisement"` |
    /// | Other | `"other"` |
    pub fn short_kind(&self) -> &'static str {
        match self {
            IcmpType::V4(t) => match t {
                Icmpv4Type::EchoReply { .. } => "echo_reply",
                Icmpv4Type::DestinationUnreachable { .. } => "dest_unreachable",
                Icmpv4Type::Redirect { .. } => "redirect",
                Icmpv4Type::EchoRequest { .. } => "echo_request",
                Icmpv4Type::TimeExceeded { .. } => "time_exceeded",
                Icmpv4Type::ParameterProblem { .. } => "parameter_problem",
                Icmpv4Type::Timestamp { .. } => "timestamp",
                Icmpv4Type::TimestampReply { .. } => "timestamp_reply",
                Icmpv4Type::Other { .. } => "other",
            },
            IcmpType::V6(t) => match t {
                Icmpv6Type::DestinationUnreachable { .. } => "dest_unreachable",
                Icmpv6Type::PacketTooBig { .. } => "packet_too_big",
                Icmpv6Type::TimeExceeded { .. } => "time_exceeded",
                Icmpv6Type::ParameterProblem { .. } => "parameter_problem",
                Icmpv6Type::EchoRequest { .. } => "echo_request",
                Icmpv6Type::EchoReply { .. } => "echo_reply",
                Icmpv6Type::NeighborSolicitation { .. } => "neighbor_solicitation",
                Icmpv6Type::NeighborAdvertisement { .. } => "neighbor_advertisement",
                Icmpv6Type::Other { .. } => "other",
            },
        }
    }
}

impl IcmpMessage {
    /// See [`IcmpType::is_error`].
    pub fn is_error(&self) -> bool {
        self.ty.is_error()
    }

    /// See [`IcmpType::error_inner`].
    pub fn error_inner(&self) -> Option<(&'static str, &IcmpInner)> {
        self.ty.error_inner()
    }

    /// See [`IcmpType::short_kind`].
    pub fn short_kind(&self) -> &'static str {
        self.ty.short_kind()
    }
}
