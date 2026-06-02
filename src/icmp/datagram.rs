//! `IcmpParser` — `DatagramParser` impl over ICMPv4 + ICMPv6.

use crate::icmp::parser;
use crate::icmp::types::{IcmpFamily, IcmpMessage, IcmpType};
use crate::{DatagramParser, FlowSide, Timestamp};

/// Stateless `DatagramParser` over ICMPv4 + ICMPv6 traffic.
///
/// Family detection is by-prefix: the parser tries ICMPv4 first,
/// then falls back to ICMPv6 if the v4 decode fails. The upstream
/// extractor's L4Proto classification is the authoritative source
/// — pair with `IcmpParser::v4_only()` / `v6_only()` to constrain
/// to one family when you know which is in play.
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

    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<IcmpMessage> {
        let want_v4 = matches!(self.only, None | Some(IcmpFamily::V4));
        let want_v6 = matches!(self.only, None | Some(IcmpFamily::V6));

        if want_v4 {
            if let Ok(m) = parser::parse_v4(payload) {
                // Reject any v4 decode whose type maps to "Other"
                // with the same raw_type byte as a likely v6 type
                // — type bytes >= 128 are reserved on v4 and
                // overwhelmingly indicate the payload is actually
                // ICMPv6. Fall through to the v6 path in that case.
                if let IcmpType::V4(crate::icmp::types::Icmpv4Type::Other { raw_type, .. }) = &m.ty
                {
                    if *raw_type >= 128 && want_v6 {
                        if let Ok(m6) = parser::parse_v6(payload) {
                            return vec![m6];
                        }
                    }
                }
                return vec![m];
            }
        }
        if want_v6 {
            if let Ok(m) = parser::parse_v6(payload) {
                return vec![m];
            }
        }
        Vec::new()
    }

    fn parser_kind(&self) -> &'static str {
        "icmp"
    }
}
