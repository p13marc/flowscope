//! NDP wire parser. RFC 4861 §4.3 / §4.4.
//!
//! NDP rides ICMPv6 over IPv6 — there's no 5-tuple flow concept
//! and the parser is a **stateless free function**. Two entry
//! points:
//!
//! - [`parse_icmpv6`] — caller already has the ICMPv6 message
//!   body (post the 4-byte ICMPv6 type / code / checksum
//!   header). This is the recommended path when iterating
//!   [`crate::layers::Icmpv6Slice`] or driving the always-on
//!   [`crate::icmp`] parser.
//! - [`parse`] — caller has just the NDP-specific payload (the
//!   bytes after the 4-byte type/code/checksum header). Useful
//!   when the consumer has already routed by ICMPv6 type.
//!
//! Issue #6 (0.18).

use std::net::Ipv6Addr;

use super::types::{NdpKind, NdpMessage};
use crate::MacAddr;

/// ICMPv6 Type 135 — Neighbor Solicitation.
const ICMPV6_NS: u8 = 135;
/// ICMPv6 Type 136 — Neighbor Advertisement.
const ICMPV6_NA: u8 = 136;

/// NDP option type 1 — Source Link-Layer Address.
const OPT_SOURCE_LLADDR: u8 = 1;
/// NDP option type 2 — Target Link-Layer Address.
const OPT_TARGET_LLADDR: u8 = 2;

/// NDP NA flag bits (high nibble of the first reserved byte).
const NA_FLAG_ROUTER: u8 = 0x80;
const NA_FLAG_SOLICITED: u8 = 0x40;
const NA_FLAG_OVERRIDE: u8 = 0x20;

/// Failure mode for the `parse*` functions (issue #85).
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    /// Buffer shorter than the bytes required at this stage.
    Truncated {
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        have: usize,
    },
    /// ICMPv6 type isn't an NDP type this module decodes
    /// (not 135 Neighbor Solicitation or 136 Neighbor
    /// Advertisement).
    NotNdp,
}

impl std::fmt::Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { need, have } => {
                write!(f, "truncated NDP message: need {need}, have {have}")
            }
            Self::NotNdp => f.write_str("not an NDP message (ICMPv6 type isn't 135/136)"),
        }
    }
}

impl std::error::Error for ParseError {}

impl From<ParseError> for crate::Error {
    fn from(e: ParseError) -> Self {
        use crate::error::{ErrorCode, Module};
        let code = match &e {
            ParseError::Truncated { .. } => ErrorCode::Truncated,
            ParseError::NotNdp => ErrorCode::Parse,
        };
        crate::Error::with_code(Module::Ndp, code, e.to_string())
    }
}

/// Parse a full ICMPv6 message, returning `Ok` only for the NDP
/// types this module decodes (135 NS / 136 NA).
///
/// `icmpv6` is the full ICMPv6 message starting at the 4-byte
/// type / code / checksum header — i.e., the ICMPv6 *layer*
/// payload, not the ICMPv6 *message body*.
///
/// Returns `Err` for:
/// - Truncated buffers (< 4 bytes for the header) →
///   [`ParseError::Truncated`].
/// - ICMPv6 type that isn't NS or NA → [`ParseError::NotNdp`].
/// - Anything [`parse`] rejects on the message-body payload.
///
/// Issue #6 (0.18). Signature changed to `Result` in issue #85.
pub fn parse_icmpv6(icmpv6: &[u8]) -> Result<NdpMessage, ParseError> {
    if icmpv6.len() < 4 {
        return Err(ParseError::Truncated {
            need: 4,
            have: icmpv6.len(),
        });
    }
    let ty = icmpv6[0];
    if ty != ICMPV6_NS && ty != ICMPV6_NA {
        return Err(ParseError::NotNdp);
    }
    // code byte (1) + checksum (2) ignored — checksum is
    // validated upstream by the IP / ICMPv6 layer if at all.
    let body = &icmpv6[4..];
    parse_body(ty, body)
}

/// Parse the NDP message body — the bytes *after* the 4-byte
/// ICMPv6 type / code / checksum header. The caller must
/// supply the ICMPv6 type byte alongside (NS=135, NA=136).
///
/// This is the lower-level entry. Most consumers want
/// [`parse_icmpv6`] which handles the type byte and the
/// truncation check.
///
/// Signature changed to `Result` in issue #85.
pub fn parse(icmpv6_type: u8, body: &[u8]) -> Result<NdpMessage, ParseError> {
    parse_body(icmpv6_type, body)
}

fn parse_body(icmpv6_type: u8, body: &[u8]) -> Result<NdpMessage, ParseError> {
    // Both NS and NA have a 4-byte reserved/flags field + 16-byte
    // target = 20 bytes minimum.
    if body.len() < 20 {
        return Err(ParseError::Truncated {
            need: 20,
            have: body.len(),
        });
    }
    let (kind, router_flag, solicited_flag, override_flag, expected_opt) = match icmpv6_type {
        ICMPV6_NS => (
            NdpKind::Solicitation,
            false,
            false,
            false,
            OPT_SOURCE_LLADDR,
        ),
        ICMPV6_NA => {
            let flag_byte = body[0];
            (
                NdpKind::Advertisement,
                flag_byte & NA_FLAG_ROUTER != 0,
                flag_byte & NA_FLAG_SOLICITED != 0,
                flag_byte & NA_FLAG_OVERRIDE != 0,
                OPT_TARGET_LLADDR,
            )
        }
        _ => return Err(ParseError::NotNdp),
    };

    let mut target_octets = [0u8; 16];
    target_octets.copy_from_slice(&body[4..20]);
    let target = Ipv6Addr::from(target_octets);

    let lladdr = parse_lladdr_option(&body[20..], expected_opt);

    Ok(NdpMessage {
        kind,
        target,
        lladdr,
        router_flag,
        solicited_flag,
        override_flag,
    })
}

/// Walk the TLV option list looking for a LL Address option of
/// the expected type (Source for NS, Target for NA). Returns the
/// first valid one found, or `None`.
///
/// Each option header is 2 bytes (type, length-in-units-of-8B).
/// A Source/Target LL Address option for Ethernet has length=1
/// (total 8 bytes: type+len+6B MAC).
///
/// Options with length=0 are malformed (RFC 4861 §4.6 reserves
/// length=0 as an error condition) and stop the walk.
fn parse_lladdr_option(mut opts: &[u8], expected_opt: u8) -> Option<MacAddr> {
    // Cap the walk to a sane bound so malformed payloads can't
    // burn unbounded CPU on a pathological loop. 16 options is
    // far past anything seen in practice.
    for _ in 0..16 {
        if opts.len() < 2 {
            return None;
        }
        let opt_type = opts[0];
        let opt_len_units = opts[1];
        if opt_len_units == 0 {
            // Malformed per RFC 4861 §4.6.
            return None;
        }
        let opt_len = (opt_len_units as usize) * 8;
        if opts.len() < opt_len {
            return None;
        }
        if opt_type == expected_opt && opt_len >= 8 {
            // Ethernet LL Address: type+len (2B) + 6B MAC = 8B.
            let mut mac = [0u8; 6];
            mac.copy_from_slice(&opts[2..8]);
            return Some(MacAddr(mac));
        }
        opts = &opts[opt_len..];
    }
    None
}

/// Stateless NDP "parser" tag — provided so consumers wiring up
/// ndp slots / event hooks can pass it as a marker. Calling
/// [`parse_icmpv6`] / [`parse`] directly is also fully
/// supported.
#[derive(Debug, Clone, Copy, Default)]
pub struct NdpParser;

impl NdpParser {
    /// See [`parse_icmpv6`].
    #[inline]
    pub fn parse_icmpv6(&self, icmpv6: &[u8]) -> Result<NdpMessage, ParseError> {
        parse_icmpv6(icmpv6)
    }

    /// See [`parse`].
    #[inline]
    pub fn parse(&self, icmpv6_type: u8, body: &[u8]) -> Result<NdpMessage, ParseError> {
        parse(icmpv6_type, body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ns_body(target: [u8; 16], lladdr: Option<[u8; 6]>) -> Vec<u8> {
        let mut b = Vec::new();
        b.extend_from_slice(&[0; 4]); // reserved
        b.extend_from_slice(&target);
        if let Some(mac) = lladdr {
            b.push(OPT_SOURCE_LLADDR);
            b.push(1); // length in units of 8 → 8 bytes total
            b.extend_from_slice(&mac);
        }
        b
    }

    fn na_body(target: [u8; 16], lladdr: Option<[u8; 6]>, flags: u8) -> Vec<u8> {
        let mut b = Vec::new();
        b.push(flags);
        b.extend_from_slice(&[0; 3]); // reserved
        b.extend_from_slice(&target);
        if let Some(mac) = lladdr {
            b.push(OPT_TARGET_LLADDR);
            b.push(1);
            b.extend_from_slice(&mac);
        }
        b
    }

    fn icmpv6(ty: u8, body: &[u8]) -> Vec<u8> {
        let mut m = vec![ty, 0, 0, 0]; // type, code, checksum (zeros)
        m.extend_from_slice(body);
        m
    }

    #[test]
    fn parses_neighbor_solicitation() {
        let body = ns_body(
            [0x20, 0x01, 0xdb, 0x08, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1],
            None,
        );
        let m = parse_icmpv6(&icmpv6(135, &body)).unwrap();
        assert_eq!(m.kind, NdpKind::Solicitation);
        assert_eq!(m.target.octets()[15], 1);
        assert_eq!(m.lladdr, None);
    }

    #[test]
    fn parses_neighbor_solicitation_with_source_lladdr() {
        let body = ns_body([0; 16], Some([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]));
        let m = parse_icmpv6(&icmpv6(135, &body)).unwrap();
        assert_eq!(m.kind, NdpKind::Solicitation);
        assert_eq!(
            m.lladdr,
            Some(MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]))
        );
    }

    #[test]
    fn parses_neighbor_advertisement_solicited_override() {
        let flags = NA_FLAG_SOLICITED | NA_FLAG_OVERRIDE;
        let body = na_body([0; 16], Some([0xaa; 6]), flags);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert_eq!(m.kind, NdpKind::Advertisement);
        assert!(m.solicited_flag);
        assert!(m.override_flag);
        assert!(!m.router_flag);
        assert_eq!(m.lladdr, Some(MacAddr([0xaa; 6])));
    }

    #[test]
    fn parses_neighbor_advertisement_router_flag() {
        let body = na_body([0; 16], None, NA_FLAG_ROUTER);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert!(m.router_flag);
    }

    #[test]
    fn na_unsolicited_override_classifies_as_spoof() {
        // The SLAAC-poisoning shape: O=1, S=0, lladdr present.
        let body = na_body([0; 16], Some([0xbb; 6]), NA_FLAG_OVERRIDE);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert!(m.is_unsolicited_override());
        assert!(m.is_likely_spoof());
    }

    #[test]
    fn rejects_truncated_icmpv6_header() {
        assert!(parse_icmpv6(&[]).is_err());
        assert!(parse_icmpv6(&[135, 0, 0]).is_err());
    }

    #[test]
    fn rejects_truncated_body() {
        // type=135 but body shorter than 20 bytes.
        let mut m = vec![135, 0, 0, 0];
        m.extend_from_slice(&[0; 5]);
        assert!(parse_icmpv6(&m).is_err());
    }

    #[test]
    fn rejects_non_ndp_type() {
        // ICMPv6 Echo Request = 128 — not NDP.
        let mut m = vec![128, 0, 0, 0];
        m.extend_from_slice(&[0; 24]);
        assert!(parse_icmpv6(&m).is_err());
    }

    #[test]
    fn lladdr_option_length_zero_is_rejected() {
        // RFC 4861 §4.6: option length 0 is invalid.
        let mut body = na_body([0; 16], None, 0);
        body.push(OPT_TARGET_LLADDR);
        body.push(0); // length 0 → malformed
        body.extend_from_slice(&[0xaa; 6]);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert_eq!(m.lladdr, None);
    }

    #[test]
    fn unknown_option_is_skipped_to_find_lladdr() {
        // Walk past an unknown option to find a Target LL Address.
        let mut body = vec![0; 20]; // flags+reserved+target zeros
        // Unknown option type 99, length 1 (8 bytes).
        body.extend_from_slice(&[99, 1, 0, 0, 0, 0, 0, 0]);
        // Target LL Address option (type 2), length 1.
        body.extend_from_slice(&[OPT_TARGET_LLADDR, 1, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert_eq!(
            m.lladdr,
            Some(MacAddr([0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]))
        );
    }

    #[test]
    fn option_walker_caps_iterations() {
        // 17+ tiny options can't make us loop forever. With
        // length=1 (8B per option), 17 options = 136 bytes; the
        // walker stops at 16 and returns None for the lladdr
        // even if it's the 17th option.
        let mut body = vec![0; 20];
        for _ in 0..16 {
            body.extend_from_slice(&[99, 1, 0, 0, 0, 0, 0, 0]);
        }
        body.extend_from_slice(&[OPT_TARGET_LLADDR, 1, 0xcc, 0xdd, 0xee, 0xff, 0x00, 0x11]);
        let m = parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert_eq!(m.lladdr, None);
    }

    #[test]
    fn ndp_parser_marker_delegates() {
        let body = na_body([0; 16], Some([0xaa; 6]), NA_FLAG_OVERRIDE);
        let p = NdpParser;
        let m = p.parse_icmpv6(&icmpv6(136, &body)).unwrap();
        assert!(m.is_likely_spoof());
        let m2 = p.parse(136, &body).unwrap();
        assert!(m2.is_likely_spoof());
    }
}
