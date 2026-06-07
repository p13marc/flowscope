//! Passive ICMPv4 / ICMPv6 message parsing (plan 76).
//!
//! [`IcmpParser`] is the integration point — a
//! [`DatagramParser`](crate::DatagramParser) impl yielding a
//! typed [`IcmpMessage`] stream. Pair it with
//! [`crate::FlowDatagramDriver`],
//! [`crate::pcap::PcapFlowSource::datagrams`], or netring's
//! `datagram_stream`.
//!
//! The killer feature for network monitoring is **`IcmpInner`**:
//! ICMP error messages (Destination Unreachable, Time Exceeded,
//! Redirect, Packet Too Big, Parameter Problem) embed the
//! original IP header + first 8 bytes of L4 payload. flowscope
//! extracts the `(src, dst, proto, src_port, dst_port)` into
//! [`IcmpInner`] so consumers can correlate the error back to
//! the specific TCP/UDP flow it references — no separate lookup
//! needed.
//!
//! # Quick start (stateless message parsing)
//!
//! ```no_run
//! use flowscope::icmp::{parse_v4, Icmpv4Type, IcmpType};
//!
//! let payload: &[u8] = b"";  // your ICMPv4 L4 payload
//! match parse_v4(payload) {
//!     Ok(msg) => match msg.ty {
//!         IcmpType::V4(Icmpv4Type::EchoRequest { id, seq }) => {
//!             println!("ping id={id} seq={seq}");
//!         }
//!         _ => {}
//!     },
//!     Err(_) => {}  // malformed — ignore
//! }
//! ```
//!
//! # Scope
//!
//! - Decoded v4 types: EchoReply, EchoRequest, Destination
//!   Unreachable, Redirect, Time Exceeded, Parameter Problem,
//!   Timestamp / TimestampReply. Other types surface as
//!   `Icmpv4Type::Other { raw_type, raw_code, raw_body }` with
//!   the on-wire bytes preserved.
//! - Decoded v6 types: EchoRequest, EchoReply, Destination
//!   Unreachable, Packet Too Big, Time Exceeded, Parameter
//!   Problem, Neighbor Solicitation, Neighbor Advertisement.
//!   Other types (Router Solicitation / Router Advertisement /
//!   Redirect / MLD) surface as `Icmpv6Type::Other`.
//! - Embedded packet (`IcmpInner`): IP version detection,
//!   src/dst, protocol number, TCP/UDP src+dst ports. Anything
//!   malformed in the embed returns `None` (best-effort, never
//!   panics).
//!
//! # Convenience accessors
//!
//! ## [`IcmpMessage`]
//!
//! | Method | Returns | Notes |
//! |--------|---------|-------|
//! | [`is_error`](IcmpMessage::is_error) | `bool` | `true` for Unreachable / Time Exceeded / Redirect / Parameter Problem |
//! | [`error_inner`](IcmpMessage::error_inner) | `Option<(&str, &IcmpInner)>` | embedded `(src, dst, proto, sport, dport)` |
//! | [`short_kind`](IcmpMessage::short_kind) | `&'static str` | label suitable for metric vocab |
//!
//! ## [`IcmpType`]
//!
//! | Method | Returns | Notes |
//! |--------|---------|-------|
//! | [`is_error`](IcmpType::is_error) | `bool` | mirror of `IcmpMessage::is_error` |
//! | [`error_inner`](IcmpType::error_inner) | `Option<(&str, &IcmpInner)>` | mirror |
//! | [`short_kind`](IcmpType::short_kind) | `&'static str` | mirror |

mod datagram;
mod parser;
mod types;

pub use datagram::IcmpParser;
pub use parser::{parse_v4, parse_v6};
pub use types::*;

/// Slug returned by [`IcmpParser`]'s `parser_kind()`. See
/// `flowscope::parser_kinds::ICMP`.
///
/// Stability: locked from 0.8 forward.
pub const PARSER_KIND: &str = "icmp";
