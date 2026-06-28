//! Type definitions for parsed ICMPv4 / ICMPv6 messages.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use bytes::Bytes;

use crate::extractor::L4Proto;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct IcmpMessage {
    pub family: IcmpFamily,
    pub ty: IcmpType,
}

impl IcmpMessage {
    /// Construct an ICMP message from its family + type.
    pub fn new(family: IcmpFamily, ty: IcmpType) -> Self {
        Self { family, ty }
    }
}

/// Outer ICMP type discriminant. Split per IP version because
/// the type-number spaces don't align (`EchoRequest = 8` on
/// v4 vs `128` on v6) and the v6-specific Neighbor Discovery
/// types don't appear in v4 at all.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "family", content = "ty", rename_all = "snake_case")
)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Icmpv4RedirectCode {
    Network,
    Host,
    Tos,
    TosHost,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum Icmpv6TimeExceededCode {
    HopLimitExceeded,
    FragmentReassemblyTimeExceeded,
    Other(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
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
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct IcmpInner {
    pub src: IpAddr,
    pub dst: IpAddr,
    pub proto: L4Proto,
    pub src_port: Option<u16>,
    pub dst_port: Option<u16>,
}

impl IcmpInner {
    /// Construct an embedded inner-packet correlation slice.
    pub fn new(
        src: IpAddr,
        dst: IpAddr,
        proto: L4Proto,
        src_port: Option<u16>,
        dst_port: Option<u16>,
    ) -> Self {
        Self {
            src,
            dst,
            proto,
            src_port,
            dst_port,
        }
    }
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

    /// Classify a Destination Unreachable into the unified
    /// v4/v6 [`DestUnreachableKind`] vocabulary. Returns
    /// `None` for non-DU types (Echo, TimeExceeded,
    /// ParameterProblem, Redirect, PacketTooBig, etc.).
    ///
    /// Use this when a consumer wants a single match arm
    /// covering both ICMPv4 and ICMPv6 unreachable codes.
    /// Match on the concrete `Icmpv4DestUnreachCode` /
    /// `Icmpv6DestUnreachCode` instead if you need the exact
    /// code or, for v4 `FragmentationNeeded`, the MTU.
    ///
    /// **MTU events**: v4 `FragmentationNeeded` and v6
    /// `PacketTooBig` (the latter is type 2, not a DU code)
    /// are unified under [`Self::mtu_signal`].
    ///
    /// Plan 162 (0.14).
    pub fn dest_unreachable_kind(&self) -> Option<DestUnreachableKind> {
        use DestUnreachableKind::*;
        match self {
            IcmpType::V4(Icmpv4Type::DestinationUnreachable { code, .. }) => Some(match code {
                Icmpv4DestUnreachCode::Host
                | Icmpv4DestUnreachCode::DestHostUnknown
                | Icmpv4DestUnreachCode::SourceHostIsolated => Host,
                Icmpv4DestUnreachCode::Port => Port,
                Icmpv4DestUnreachCode::Net | Icmpv4DestUnreachCode::DestNetworkUnknown => Network,
                Icmpv4DestUnreachCode::Protocol => Protocol,
                Icmpv4DestUnreachCode::NetworkProhibited
                | Icmpv4DestUnreachCode::HostProhibited
                | Icmpv4DestUnreachCode::CommunicationProhibited
                | Icmpv4DestUnreachCode::PrecedenceCutoffInEffect => AdministrativelyProhibited,
                Icmpv4DestUnreachCode::FragmentationNeeded { .. } => FragmentationNeeded,
                _ => Other,
            }),
            IcmpType::V6(Icmpv6Type::DestinationUnreachable { code, .. }) => Some(match code {
                Icmpv6DestUnreachCode::AddressUnreachable => Host,
                Icmpv6DestUnreachCode::PortUnreachable => Port,
                Icmpv6DestUnreachCode::NoRoute => Network,
                Icmpv6DestUnreachCode::AdminProhibited
                | Icmpv6DestUnreachCode::RejectRouteToDestination
                | Icmpv6DestUnreachCode::SourceAddressFailedIngressPolicy => {
                    AdministrativelyProhibited
                }
                _ => Other,
            }),
            _ => None,
        }
    }
}

/// Unified v4/v6 vocabulary for ICMP Destination Unreachable
/// codes. Maps the ~17 v4 [`Icmpv4DestUnreachCode`] variants
/// and the ~8 v6 [`Icmpv6DestUnreachCode`] variants down to
/// the operationally-distinguishable set.
///
/// Match on the concrete v4 / v6 code enums instead if you
/// need the exact code or, for v4 [`Icmpv4DestUnreachCode::FragmentationNeeded`],
/// the MTU. For the v4/v6 unified MTU signal, see
/// [`MtuSignalKind`] (which folds v4 FragNeeded and v6
/// PacketTooBig into one classification).
///
/// Plan 162 (0.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DestUnreachableKind {
    /// v4: `Host` / `DestHostUnknown` / `SourceHostIsolated`.
    /// v6: `AddressUnreachable`.
    Host,
    /// v4: `Port`. v6: `PortUnreachable`.
    Port,
    /// v4: `Net` / `DestNetworkUnknown`. v6: `NoRoute`.
    Network,
    /// v4: `Protocol`. v6: no equivalent.
    Protocol,
    /// v4: `NetworkProhibited` / `HostProhibited` /
    /// `CommunicationProhibited` / `PrecedenceCutoffInEffect`.
    /// v6: `AdminProhibited` / `RejectRouteToDestination` /
    /// `SourceAddressFailedIngressPolicy`.
    AdministrativelyProhibited,
    /// v4: `FragmentationNeeded { mtu }` (MTU lost in the
    /// canonical mapping — match `Icmpv4Type` directly when you
    /// need the MTU). v6: no exact equivalent (`PacketTooBig`
    /// is ICMPv6 type 2, not a code under DU).
    FragmentationNeeded,
    /// Anything else (v4 `SourceRouteFailed`, `NetworkTos`,
    /// `HostTos`, `HostPrecedenceViolation`, `Other`;
    /// v6 `BeyondScopeOfSource`, `Other`).
    Other,
}

impl DestUnreachableKind {
    /// Stable short slug suitable as a metric label.
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | `Host` | `"host_unreachable"` |
    /// | `Port` | `"port_unreachable"` |
    /// | `Network` | `"network_unreachable"` |
    /// | `Protocol` | `"protocol_unreachable"` |
    /// | `AdministrativelyProhibited` | `"administratively_prohibited"` |
    /// | `FragmentationNeeded` | `"fragmentation_needed"` |
    /// | `Other` | `"dest_unreachable_other"` |
    pub fn as_str(&self) -> &'static str {
        match self {
            DestUnreachableKind::Host => "host_unreachable",
            DestUnreachableKind::Port => "port_unreachable",
            DestUnreachableKind::Network => "network_unreachable",
            DestUnreachableKind::Protocol => "protocol_unreachable",
            DestUnreachableKind::AdministrativelyProhibited => "administratively_prohibited",
            DestUnreachableKind::FragmentationNeeded => "fragmentation_needed",
            DestUnreachableKind::Other => "dest_unreachable_other",
        }
    }
}

/// Unified v4/v6 PMTU-mismatch signal. Folds ICMPv4
/// Destination Unreachable code 4 (Fragmentation Needed) and
/// ICMPv6 type 2 (Packet Too Big) into one operationally-
/// equivalent vocabulary.
///
/// Sibling to [`DestUnreachableKind`] — covers the MTU signal
/// that [`DestUnreachableKind::FragmentationNeeded`] loses
/// (and that v6 splits into a separate type).
///
/// Plan 170 (0.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum MtuSignalKind {
    /// ICMPv4 Destination Unreachable, code 4
    /// ("Fragmentation needed and DF set"). The `next_hop_mtu`
    /// field carries RFC 1191 / RFC 1981 next-hop MTU when the
    /// sender is RFC 1191-conformant; older senders may omit
    /// it (`None`).
    FragmentationNeeded { next_hop_mtu: Option<u16> },
    /// ICMPv6 type 2 (Packet Too Big). The MTU field is
    /// mandatory in v6 — never 0, never `None`.
    PacketTooBig { next_hop_mtu: u32 },
}

impl MtuSignalKind {
    /// Stable short slug suitable as a metric label.
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | `FragmentationNeeded` | `"fragmentation_needed"` |
    /// | `PacketTooBig` | `"packet_too_big"` |
    pub fn as_str(&self) -> &'static str {
        match self {
            MtuSignalKind::FragmentationNeeded { .. } => "fragmentation_needed",
            MtuSignalKind::PacketTooBig { .. } => "packet_too_big",
        }
    }

    /// Unified MTU accessor — returns the next-hop MTU as `u32`
    /// for both v4 (when present) and v6 (always). `None` for
    /// v4 senders that omit the RFC 1191 field.
    pub fn next_hop_mtu(&self) -> Option<u32> {
        match self {
            MtuSignalKind::FragmentationNeeded { next_hop_mtu } => next_hop_mtu.map(u32::from),
            MtuSignalKind::PacketTooBig { next_hop_mtu } => Some(*next_hop_mtu),
        }
    }
}

impl IcmpType {
    /// Classify a PMTU signal across v4/v6 boundaries. Returns
    /// `Some` for ICMPv4 Destination Unreachable code 4 and for
    /// ICMPv6 type 2 (Packet Too Big). Returns `None` for any
    /// other type.
    ///
    /// Sibling to [`Self::dest_unreachable_kind`] for non-MTU
    /// classification.
    ///
    /// Plan 170 (0.14).
    pub fn mtu_signal(&self) -> Option<MtuSignalKind> {
        match self {
            IcmpType::V4(Icmpv4Type::DestinationUnreachable {
                code: Icmpv4DestUnreachCode::FragmentationNeeded { mtu },
                ..
            }) => Some(MtuSignalKind::FragmentationNeeded { next_hop_mtu: *mtu }),
            IcmpType::V6(Icmpv6Type::PacketTooBig { mtu, .. }) => {
                Some(MtuSignalKind::PacketTooBig { next_hop_mtu: *mtu })
            }
            _ => None,
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

    /// See [`IcmpType::dest_unreachable_kind`].
    pub fn dest_unreachable_kind(&self) -> Option<DestUnreachableKind> {
        self.ty.dest_unreachable_kind()
    }

    /// See [`IcmpType::mtu_signal`].
    pub fn mtu_signal(&self) -> Option<MtuSignalKind> {
        self.ty.mtu_signal()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn du_v4(code: Icmpv4DestUnreachCode) -> IcmpType {
        IcmpType::V4(Icmpv4Type::DestinationUnreachable { code, inner: None })
    }

    fn du_v6(code: Icmpv6DestUnreachCode) -> IcmpType {
        IcmpType::V6(Icmpv6Type::DestinationUnreachable { code, inner: None })
    }

    // ── Plan 162 (0.14) — DestUnreachableKind tests ────────

    #[test]
    fn dest_unreachable_kind_returns_none_for_echo_request() {
        let t = IcmpType::V4(Icmpv4Type::EchoRequest { id: 1, seq: 1 });
        assert_eq!(t.dest_unreachable_kind(), None);
    }

    #[test]
    fn dest_unreachable_kind_returns_none_for_time_exceeded() {
        let t = IcmpType::V4(Icmpv4Type::TimeExceeded {
            code: Icmpv4TimeExceededCode::HopLimitExceeded,
            inner: None,
        });
        assert_eq!(t.dest_unreachable_kind(), None);
    }

    #[test]
    fn dest_unreachable_kind_returns_none_for_v6_packet_too_big() {
        // v6 PacketTooBig is type 2, not a code under DU.
        let t = IcmpType::V6(Icmpv6Type::PacketTooBig {
            mtu: 1500,
            inner: None,
        });
        assert_eq!(t.dest_unreachable_kind(), None);
    }

    #[test]
    fn v4_host_codes_map_to_host_kind() {
        for code in [
            Icmpv4DestUnreachCode::Host,
            Icmpv4DestUnreachCode::DestHostUnknown,
            Icmpv4DestUnreachCode::SourceHostIsolated,
        ] {
            assert_eq!(
                du_v4(code).dest_unreachable_kind(),
                Some(DestUnreachableKind::Host),
            );
        }
    }

    #[test]
    fn v4_port_maps_to_port_kind() {
        assert_eq!(
            du_v4(Icmpv4DestUnreachCode::Port).dest_unreachable_kind(),
            Some(DestUnreachableKind::Port),
        );
    }

    #[test]
    fn v4_network_codes_map_to_network_kind() {
        for code in [
            Icmpv4DestUnreachCode::Net,
            Icmpv4DestUnreachCode::DestNetworkUnknown,
        ] {
            assert_eq!(
                du_v4(code).dest_unreachable_kind(),
                Some(DestUnreachableKind::Network),
            );
        }
    }

    #[test]
    fn v4_protocol_maps_to_protocol_kind() {
        assert_eq!(
            du_v4(Icmpv4DestUnreachCode::Protocol).dest_unreachable_kind(),
            Some(DestUnreachableKind::Protocol),
        );
    }

    #[test]
    fn v4_prohibited_codes_map_to_administratively_prohibited() {
        for code in [
            Icmpv4DestUnreachCode::NetworkProhibited,
            Icmpv4DestUnreachCode::HostProhibited,
            Icmpv4DestUnreachCode::CommunicationProhibited,
            Icmpv4DestUnreachCode::PrecedenceCutoffInEffect,
        ] {
            assert_eq!(
                du_v4(code).dest_unreachable_kind(),
                Some(DestUnreachableKind::AdministrativelyProhibited),
            );
        }
    }

    #[test]
    fn v4_fragmentation_needed_maps_to_fragmentation_needed_kind() {
        let code = Icmpv4DestUnreachCode::FragmentationNeeded { mtu: Some(1400) };
        assert_eq!(
            du_v4(code).dest_unreachable_kind(),
            Some(DestUnreachableKind::FragmentationNeeded),
        );
    }

    #[test]
    fn v4_other_codes_map_to_other_kind() {
        for code in [
            Icmpv4DestUnreachCode::SourceRouteFailed,
            Icmpv4DestUnreachCode::NetworkTos,
            Icmpv4DestUnreachCode::HostTos,
            Icmpv4DestUnreachCode::HostPrecedenceViolation,
            Icmpv4DestUnreachCode::Other(42),
        ] {
            assert_eq!(
                du_v4(code).dest_unreachable_kind(),
                Some(DestUnreachableKind::Other),
            );
        }
    }

    #[test]
    fn v6_address_unreachable_maps_to_host_kind() {
        assert_eq!(
            du_v6(Icmpv6DestUnreachCode::AddressUnreachable).dest_unreachable_kind(),
            Some(DestUnreachableKind::Host),
        );
    }

    #[test]
    fn v6_port_unreachable_maps_to_port_kind() {
        assert_eq!(
            du_v6(Icmpv6DestUnreachCode::PortUnreachable).dest_unreachable_kind(),
            Some(DestUnreachableKind::Port),
        );
    }

    #[test]
    fn v6_no_route_maps_to_network_kind() {
        assert_eq!(
            du_v6(Icmpv6DestUnreachCode::NoRoute).dest_unreachable_kind(),
            Some(DestUnreachableKind::Network),
        );
    }

    #[test]
    fn v6_prohibited_codes_map_to_administratively_prohibited() {
        for code in [
            Icmpv6DestUnreachCode::AdminProhibited,
            Icmpv6DestUnreachCode::RejectRouteToDestination,
            Icmpv6DestUnreachCode::SourceAddressFailedIngressPolicy,
        ] {
            assert_eq!(
                du_v6(code).dest_unreachable_kind(),
                Some(DestUnreachableKind::AdministrativelyProhibited),
            );
        }
    }

    #[test]
    fn v6_beyond_scope_maps_to_other_kind() {
        assert_eq!(
            du_v6(Icmpv6DestUnreachCode::BeyondScopeOfSource).dest_unreachable_kind(),
            Some(DestUnreachableKind::Other),
        );
    }

    #[test]
    fn as_str_returns_stable_slugs() {
        // Regression-pin the slugs — downstream metric pipelines depend on them.
        assert_eq!(DestUnreachableKind::Host.as_str(), "host_unreachable");
        assert_eq!(DestUnreachableKind::Port.as_str(), "port_unreachable");
        assert_eq!(DestUnreachableKind::Network.as_str(), "network_unreachable");
        assert_eq!(
            DestUnreachableKind::Protocol.as_str(),
            "protocol_unreachable"
        );
        assert_eq!(
            DestUnreachableKind::AdministrativelyProhibited.as_str(),
            "administratively_prohibited",
        );
        assert_eq!(
            DestUnreachableKind::FragmentationNeeded.as_str(),
            "fragmentation_needed",
        );
        assert_eq!(
            DestUnreachableKind::Other.as_str(),
            "dest_unreachable_other"
        );
    }

    #[test]
    fn types_module_is_publicly_reachable() {
        // Plan 166 (folded into 162): verify `mod types` is now `pub`.
        // Construct a value via the explicit `types::` path —
        // pre-fix this would fail with "private module".
        let _: crate::icmp::types::Icmpv6DestUnreachCode =
            crate::icmp::types::Icmpv6DestUnreachCode::NoRoute;
    }

    // ── Plan 170 (0.14) — MtuSignalKind tests ──────────────

    #[test]
    fn mtu_signal_returns_none_for_echo() {
        let t = IcmpType::V4(Icmpv4Type::EchoRequest { id: 1, seq: 1 });
        assert_eq!(t.mtu_signal(), None);
    }

    #[test]
    fn mtu_signal_returns_none_for_non_fragneeded_du() {
        for code in [
            Icmpv4DestUnreachCode::Host,
            Icmpv4DestUnreachCode::Port,
            Icmpv4DestUnreachCode::Net,
        ] {
            assert_eq!(du_v4(code).mtu_signal(), None);
        }
        for code in [
            Icmpv6DestUnreachCode::AddressUnreachable,
            Icmpv6DestUnreachCode::PortUnreachable,
            Icmpv6DestUnreachCode::NoRoute,
        ] {
            assert_eq!(du_v6(code).mtu_signal(), None);
        }
    }

    #[test]
    fn mtu_signal_v4_fragneeded_with_mtu() {
        let t = du_v4(Icmpv4DestUnreachCode::FragmentationNeeded { mtu: Some(1492) });
        assert_eq!(
            t.mtu_signal(),
            Some(MtuSignalKind::FragmentationNeeded {
                next_hop_mtu: Some(1492)
            }),
        );
        assert_eq!(t.mtu_signal().unwrap().next_hop_mtu(), Some(1492));
    }

    #[test]
    fn mtu_signal_v4_fragneeded_without_mtu() {
        // RFC 1191 non-conformant sender — mtu field is 0/absent.
        let t = du_v4(Icmpv4DestUnreachCode::FragmentationNeeded { mtu: None });
        assert_eq!(
            t.mtu_signal(),
            Some(MtuSignalKind::FragmentationNeeded { next_hop_mtu: None }),
        );
        assert_eq!(t.mtu_signal().unwrap().next_hop_mtu(), None);
    }

    #[test]
    fn mtu_signal_v6_packet_too_big() {
        let t = IcmpType::V6(Icmpv6Type::PacketTooBig {
            mtu: 1500,
            inner: None,
        });
        assert_eq!(
            t.mtu_signal(),
            Some(MtuSignalKind::PacketTooBig { next_hop_mtu: 1500 }),
        );
        assert_eq!(t.mtu_signal().unwrap().next_hop_mtu(), Some(1500));
    }

    #[test]
    fn mtu_signal_as_str_stable_slugs() {
        assert_eq!(
            MtuSignalKind::FragmentationNeeded {
                next_hop_mtu: Some(1492)
            }
            .as_str(),
            "fragmentation_needed",
        );
        assert_eq!(
            MtuSignalKind::FragmentationNeeded { next_hop_mtu: None }.as_str(),
            "fragmentation_needed",
        );
        assert_eq!(
            MtuSignalKind::PacketTooBig { next_hop_mtu: 1280 }.as_str(),
            "packet_too_big",
        );
    }

    #[test]
    fn mtu_signal_proxies_via_icmp_message() {
        // Verify the IcmpMessage proxy method.
        let msg = IcmpMessage {
            family: IcmpFamily::V4,
            ty: du_v4(Icmpv4DestUnreachCode::FragmentationNeeded { mtu: Some(576) }),
        };
        assert_eq!(
            msg.mtu_signal(),
            Some(MtuSignalKind::FragmentationNeeded {
                next_hop_mtu: Some(576)
            }),
        );
    }
}
