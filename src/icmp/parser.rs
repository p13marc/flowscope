//! Stateless ICMP message parsing. Wraps `etherparse`'s
//! `Icmpv4Slice` / `Icmpv6Slice` to translate into flowscope's
//! [`IcmpMessage`] shape. Adds `IcmpInner` extraction (etherparse
//! doesn't parse the inner header for error messages).

use bytes::Bytes;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::extractor::L4Proto;
use crate::icmp::types::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid ICMP message: {0}")]
    Parse(&'static str),
}

/// Parse a raw ICMPv4 payload into an [`IcmpMessage`].
pub fn parse_v4(payload: &[u8]) -> Result<IcmpMessage, Error> {
    let slice = etherparse::Icmpv4Slice::from_slice(payload)
        .map_err(|_| Error::Parse("malformed ICMPv4 header"))?;
    let ty = translate_v4(&slice);
    Ok(IcmpMessage {
        family: IcmpFamily::V4,
        ty: IcmpType::V4(ty),
    })
}

/// Parse a raw ICMPv6 payload into an [`IcmpMessage`].
pub fn parse_v6(payload: &[u8]) -> Result<IcmpMessage, Error> {
    let slice = etherparse::Icmpv6Slice::from_slice(payload)
        .map_err(|_| Error::Parse("malformed ICMPv6 header"))?;
    let ty = translate_v6(&slice, payload);
    Ok(IcmpMessage {
        family: IcmpFamily::V6,
        ty: IcmpType::V6(ty),
    })
}

// ── ICMPv4 translation ──────────────────────────────────────────

fn translate_v4(slice: &etherparse::Icmpv4Slice) -> Icmpv4Type {
    use etherparse::Icmpv4Type as E;
    let body = slice.payload();
    match slice.icmp_type() {
        E::EchoReply(h) => Icmpv4Type::EchoReply {
            id: h.id,
            seq: h.seq,
        },
        E::EchoRequest(h) => Icmpv4Type::EchoRequest {
            id: h.id,
            seq: h.seq,
        },
        E::DestinationUnreachable(code) => {
            let code = map_v4_dest_unreach(code);
            Icmpv4Type::DestinationUnreachable {
                code,
                inner: parse_inner_v4(body),
            }
        }
        E::Redirect(h) => Icmpv4Type::Redirect {
            code: map_v4_redirect(h.code),
            gateway: Ipv4Addr::from(h.gateway_internet_address),
            inner: parse_inner_v4(body),
        },
        E::TimeExceeded(code) => Icmpv4Type::TimeExceeded {
            code: map_v4_time_exceeded(code),
            inner: parse_inner_v4(body),
        },
        E::ParameterProblem(h) => Icmpv4Type::ParameterProblem {
            pointer: match h {
                etherparse::icmpv4::ParameterProblemHeader::PointerIndicatesError(p) => p,
                _ => 0,
            },
            inner: parse_inner_v4(body),
        },
        E::TimestampRequest(h) => Icmpv4Type::Timestamp {
            id: h.id,
            seq: h.seq,
            originate: h.originate_timestamp,
            receive: h.receive_timestamp,
            transmit: h.transmit_timestamp,
        },
        E::TimestampReply(h) => Icmpv4Type::TimestampReply {
            id: h.id,
            seq: h.seq,
            originate: h.originate_timestamp,
            receive: h.receive_timestamp,
            transmit: h.transmit_timestamp,
        },
        E::Unknown {
            type_u8,
            code_u8,
            bytes5to8,
        } => Icmpv4Type::Other {
            raw_type: type_u8,
            raw_code: code_u8,
            raw_body: combine_unknown_body(&bytes5to8, body),
        },
    }
}

fn map_v4_dest_unreach(code: etherparse::icmpv4::DestUnreachableHeader) -> Icmpv4DestUnreachCode {
    use etherparse::icmpv4::DestUnreachableHeader as D;
    match code {
        D::Network => Icmpv4DestUnreachCode::Net,
        D::Host => Icmpv4DestUnreachCode::Host,
        D::Protocol => Icmpv4DestUnreachCode::Protocol,
        D::Port => Icmpv4DestUnreachCode::Port,
        D::FragmentationNeeded { next_hop_mtu } => Icmpv4DestUnreachCode::FragmentationNeeded {
            mtu: Some(next_hop_mtu),
        },
        D::SourceRouteFailed => Icmpv4DestUnreachCode::SourceRouteFailed,
        D::NetworkUnknown => Icmpv4DestUnreachCode::DestNetworkUnknown,
        D::HostUnknown => Icmpv4DestUnreachCode::DestHostUnknown,
        D::Isolated => Icmpv4DestUnreachCode::SourceHostIsolated,
        D::NetworkProhibited => Icmpv4DestUnreachCode::NetworkProhibited,
        D::HostProhibited => Icmpv4DestUnreachCode::HostProhibited,
        D::TosNetwork => Icmpv4DestUnreachCode::NetworkTos,
        D::TosHost => Icmpv4DestUnreachCode::HostTos,
        D::FilterProhibited => Icmpv4DestUnreachCode::CommunicationProhibited,
        D::HostPrecedenceViolation => Icmpv4DestUnreachCode::HostPrecedenceViolation,
        D::PrecedenceCutoff => Icmpv4DestUnreachCode::PrecedenceCutoffInEffect,
    }
}

fn map_v4_redirect(code: etherparse::icmpv4::RedirectCode) -> Icmpv4RedirectCode {
    use etherparse::icmpv4::RedirectCode as R;
    match code {
        R::RedirectForNetwork => Icmpv4RedirectCode::Network,
        R::RedirectForHost => Icmpv4RedirectCode::Host,
        R::RedirectForTypeOfServiceAndNetwork => Icmpv4RedirectCode::Tos,
        R::RedirectForTypeOfServiceAndHost => Icmpv4RedirectCode::TosHost,
    }
}

fn map_v4_time_exceeded(code: etherparse::icmpv4::TimeExceededCode) -> Icmpv4TimeExceededCode {
    use etherparse::icmpv4::TimeExceededCode as T;
    match code {
        T::TtlExceededInTransit => Icmpv4TimeExceededCode::HopLimitExceeded,
        T::FragmentReassemblyTimeExceeded => Icmpv4TimeExceededCode::FragmentReassemblyTimeExceeded,
    }
}

// ── ICMPv6 translation ──────────────────────────────────────────

fn translate_v6(slice: &etherparse::Icmpv6Slice, full_payload: &[u8]) -> Icmpv6Type {
    use etherparse::Icmpv6Type as E;
    let body = slice.payload();
    match slice.icmp_type() {
        E::DestinationUnreachable(code) => Icmpv6Type::DestinationUnreachable {
            code: map_v6_dest_unreach(code),
            inner: parse_inner_v6(body),
        },
        E::PacketTooBig { mtu } => Icmpv6Type::PacketTooBig {
            mtu,
            inner: parse_inner_v6(body),
        },
        E::TimeExceeded(code) => Icmpv6Type::TimeExceeded {
            code: map_v6_time_exceeded(code),
            inner: parse_inner_v6(body),
        },
        E::ParameterProblem(h) => Icmpv6Type::ParameterProblem {
            code: map_v6_param_problem(h.code),
            pointer: h.pointer,
            inner: parse_inner_v6(body),
        },
        E::EchoRequest(h) => Icmpv6Type::EchoRequest {
            id: h.id,
            seq: h.seq,
        },
        E::EchoReply(h) => Icmpv6Type::EchoReply {
            id: h.id,
            seq: h.seq,
        },
        E::Unknown {
            type_u8,
            code_u8,
            bytes5to8,
        } => {
            // Special-case NS / NA before falling back to Other.
            if let Some(parsed) = parse_v6_neighbor_message(type_u8, code_u8, &bytes5to8, body) {
                return parsed;
            }
            let _ = full_payload;
            Icmpv6Type::Other {
                raw_type: type_u8,
                raw_code: code_u8,
                raw_body: combine_unknown_body(&bytes5to8, body),
            }
        }
    }
}

fn map_v6_dest_unreach(code: etherparse::icmpv6::DestUnreachableCode) -> Icmpv6DestUnreachCode {
    use etherparse::icmpv6::DestUnreachableCode as D;
    match code {
        D::NoRoute => Icmpv6DestUnreachCode::NoRoute,
        D::Prohibited => Icmpv6DestUnreachCode::AdminProhibited,
        D::BeyondScope => Icmpv6DestUnreachCode::BeyondScopeOfSource,
        D::Address => Icmpv6DestUnreachCode::AddressUnreachable,
        D::Port => Icmpv6DestUnreachCode::PortUnreachable,
        D::SourceAddressFailedPolicy => Icmpv6DestUnreachCode::SourceAddressFailedIngressPolicy,
        D::RejectRoute => Icmpv6DestUnreachCode::RejectRouteToDestination,
    }
}

fn map_v6_time_exceeded(code: etherparse::icmpv6::TimeExceededCode) -> Icmpv6TimeExceededCode {
    use etherparse::icmpv6::TimeExceededCode as T;
    match code {
        T::HopLimitExceeded => Icmpv6TimeExceededCode::HopLimitExceeded,
        T::FragmentReassemblyTimeExceeded => Icmpv6TimeExceededCode::FragmentReassemblyTimeExceeded,
    }
}

fn map_v6_param_problem(code: etherparse::icmpv6::ParameterProblemCode) -> Icmpv6ParamProblemCode {
    use etherparse::icmpv6::ParameterProblemCode as P;
    match code {
        P::ErroneousHeaderField => Icmpv6ParamProblemCode::ErroneousHeaderField,
        P::UnrecognizedNextHeader => Icmpv6ParamProblemCode::UnrecognizedNextHeaderType,
        P::UnrecognizedIpv6Option => Icmpv6ParamProblemCode::UnrecognizedIpv6Option,
        // The rest (SR Upper-layer Header Error, etc.) aren't operationally relevant for
        // most NMS use cases — surface as Other.
        _ => Icmpv6ParamProblemCode::Other(code.code_u8()),
    }
}

/// Decode types 135 / 136 manually since etherparse classes
/// Neighbor Solicitation / Advertisement as Unknown.
///
/// - Type 135 NS: header is `reserved (4 bytes)`; body starts
///   with `target_address (16 bytes)`. etherparse hands us
///   `bytes5to8` (the reserved field, ignored) plus `body` (the
///   target address + options).
/// - Type 136 NA: header is `flags+reserved (4 bytes)` where the
///   top 3 bits of byte 0 are router / solicited / override;
///   body starts with `target_address (16 bytes)`.
fn parse_v6_neighbor_message(
    type_u8: u8,
    _code_u8: u8,
    bytes5to8: &[u8; 4],
    body: &[u8],
) -> Option<Icmpv6Type> {
    if body.len() < 16 {
        return None;
    }
    let target = {
        let mut raw = [0u8; 16];
        raw.copy_from_slice(&body[..16]);
        Ipv6Addr::from(raw)
    };
    match type_u8 {
        135 => Some(Icmpv6Type::NeighborSolicitation { target }),
        136 => {
            let flags = bytes5to8[0];
            Some(Icmpv6Type::NeighborAdvertisement {
                target,
                router: flags & 0x80 != 0,
                solicited: flags & 0x40 != 0,
                override_: flags & 0x20 != 0,
            })
        }
        _ => None,
    }
}

// ── Inner header extraction ─────────────────────────────────────

/// Extract the embedded `(src, dst, proto, src_port, dst_port)`
/// from an ICMPv4 error-message body. The body is the original
/// IP header + at least 8 bytes of L4 payload (RFC 792). Returns
/// `None` on any malformed / truncated embed — the extraction is
/// opportunistic diagnostics.
fn parse_inner_v4(body: &[u8]) -> Option<IcmpInner> {
    let hdr = etherparse::Ipv4HeaderSlice::from_slice(body).ok()?;
    let src = IpAddr::V4(Ipv4Addr::from(hdr.source()));
    let dst = IpAddr::V4(Ipv4Addr::from(hdr.destination()));
    let proto = ip_proto_to_l4(hdr.protocol().0);
    let l4_payload = body.get(hdr.slice().len()..).unwrap_or(&[]);
    let (src_port, dst_port) = extract_ports(proto, l4_payload);
    Some(IcmpInner {
        src,
        dst,
        proto,
        src_port,
        dst_port,
    })
}

/// Same as [`parse_inner_v4`] for ICMPv6.
fn parse_inner_v6(body: &[u8]) -> Option<IcmpInner> {
    let hdr = etherparse::Ipv6HeaderSlice::from_slice(body).ok()?;
    let src = IpAddr::V6(Ipv6Addr::from(hdr.source()));
    let dst = IpAddr::V6(Ipv6Addr::from(hdr.destination()));
    let proto = ip_proto_to_l4(hdr.next_header().0);
    let l4_payload = body.get(hdr.slice().len()..).unwrap_or(&[]);
    let (src_port, dst_port) = extract_ports(proto, l4_payload);
    Some(IcmpInner {
        src,
        dst,
        proto,
        src_port,
        dst_port,
    })
}

/// First 4 bytes of TCP/UDP headers are `src_port:u16,
/// dst_port:u16`. Anything else returns `(None, None)`.
fn extract_ports(proto: L4Proto, payload: &[u8]) -> (Option<u16>, Option<u16>) {
    if payload.len() < 4 || !matches!(proto, L4Proto::Tcp | L4Proto::Udp) {
        return (None, None);
    }
    let sp = u16::from_be_bytes([payload[0], payload[1]]);
    let dp = u16::from_be_bytes([payload[2], payload[3]]);
    (Some(sp), Some(dp))
}

fn ip_proto_to_l4(p: u8) -> L4Proto {
    match p {
        6 => L4Proto::Tcp,
        17 => L4Proto::Udp,
        1 => L4Proto::Icmp,
        58 => L4Proto::IcmpV6,
        132 => L4Proto::Sctp,
        other => L4Proto::Other(other),
    }
}

fn combine_unknown_body(bytes5to8: &[u8; 4], body: &[u8]) -> Bytes {
    let mut buf = Vec::with_capacity(4 + body.len());
    buf.extend_from_slice(bytes5to8);
    buf.extend_from_slice(body);
    Bytes::from(buf)
}
