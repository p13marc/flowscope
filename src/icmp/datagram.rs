//! `IcmpParser` — `DatagramParser` impl over ICMPv4 + ICMPv6.

use crate::icmp::parser;
use crate::icmp::types::{IcmpFamily, IcmpMessage};
use crate::{DatagramParser, FlowSide, Timestamp};

/// Stateless `DatagramParser` over ICMPv4 + ICMPv6 traffic.
///
/// # Family detection
///
/// ICMPv4 and ICMPv6 **share the low type-number space** — an
/// ICMPv6 Destination Unreachable is type 1, Time Exceeded is
/// type 3 (which is *Destination Unreachable* in ICMPv4), and so
/// on — so the outer type byte alone cannot tell the families
/// apart. The parser resolves it by:
///
/// 1. **type ≥ 128 ⇒ ICMPv6** (all ICMPv6 informational + NDP
///    types are ≥ 128; ICMPv4 never is), then
/// 2. for the ambiguous **error** types (1–4), the version nibble
///    of the **embedded inner IP header** (offset 8) — an ICMPv6
///    error quotes an IPv6 header, an ICMPv4 error an IPv4 header.
/// 3. Any remaining low type is ICMPv4 (echo 0/8, dest-unreach 3,
///    redirect 5, time-exceeded 11, timestamp 13/14).
///
/// When you already know the family (the upstream extractor's
/// `L4Proto` is authoritative — `Icmp` vs `IcmpV6`), constrain the
/// parser with [`v4_only`](Self::v4_only) / [`v6_only`](Self::v6_only):
/// a payload detected as the other family is then skipped, so a
/// single `datagram_broadcast` slot per family stays clean.
///
/// Stateless: no per-flow allocation; cheap to clone.
#[derive(Debug, Default, Clone)]
pub struct IcmpParser {
    only: Option<IcmpFamily>,
}

impl IcmpParser {
    pub fn new() -> Self {
        Self::default()
    }
    /// Restrict the parser to ICMPv4. Calls to `parse` that look
    /// like ICMPv6 return an empty `Vec`.
    pub fn v4_only(mut self) -> Self {
        self.only = Some(IcmpFamily::V4);
        self
    }
    /// Restrict the parser to ICMPv6.
    pub fn v6_only(mut self) -> Self {
        self.only = Some(IcmpFamily::V6);
        self
    }
}

impl DatagramParser for IcmpParser {
    type Message = IcmpMessage;

    fn parse(
        &mut self,
        payload: &[u8],
        _side: FlowSide,
        _ts: Timestamp,
        out: &mut Vec<IcmpMessage>,
    ) {
        // Detect the family from content (type range + inner IP
        // version), then honour any `only` constraint by skipping
        // the other family. Parsing the *wrong* family would
        // silently misclassify — e.g. an ICMPv6 Destination
        // Unreachable (type 1) decoded as ICMPv4 becomes an
        // unrecognised `Other`, so the error is lost entirely.
        let Some(detected) = detect_family(payload) else {
            return;
        };
        if let Some(want) = self.only
            && want != detected
        {
            return;
        }
        let parsed = match detected {
            IcmpFamily::V4 => parser::parse_v4(payload),
            IcmpFamily::V6 => parser::parse_v6(payload),
        };
        if let Ok(m) = parsed {
            out.push(m);
        }
    }

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Icmp
    }
}

/// Best-effort ICMP family detection from payload content — see
/// [`IcmpParser`]'s "Family detection" docs. Returns `None` only
/// for an empty payload.
fn detect_family(payload: &[u8]) -> Option<IcmpFamily> {
    let ty = *payload.first()?;
    // All ICMPv6 informational + NDP types are >= 128; ICMPv4 has
    // no assigned type that high.
    if ty >= 128 {
        return Some(IcmpFamily::V6);
    }
    // Types 1..=4 collide between the two families' error messages
    // (v6 DestUnreach=1 / PacketTooBig=2 / TimeExceeded=3 /
    // ParamProblem=4 vs v4 unassigned=1,2 / DestUnreach=3 /
    // SourceQuench=4). Both quote the original IP header at offset
    // 8 — its version nibble is the reliable discriminator.
    if (1..=4).contains(&ty)
        && let Some(&inner0) = payload.get(8)
    {
        return Some(if inner0 >> 4 == 6 {
            IcmpFamily::V6
        } else {
            IcmpFamily::V4
        });
    }
    // Remaining low types are ICMPv4 (echo 0/8, dest-unreach 3 with
    // no inner, redirect 5, time-exceeded 11, timestamp 13/14, …).
    Some(IcmpFamily::V4)
}
