//! [`MdnsParser`] — thin newtype wrapper around
//! [`crate::dns::DnsUdpParser`] for mDNS-port dispatch.

use crate::Timestamp;
use crate::dns::{DnsMessage, DnsUdpParser};
use crate::event::FlowSide;
use crate::session::DatagramParser;

/// Stable identifier returned by `MdnsParser::parser_kind()`.
pub const PARSER_KIND: &str = "mdns";

/// `DatagramParser` for UDP/5353 mDNS traffic. Behaves
/// identically to [`crate::dns::DnsUdpParser`] for the wire
/// format; the distinction is only at the dispatch + metric-
/// label layer.
///
/// Consumers wiring up multi-port DNS / mDNS handling should
/// route 5353 traffic here so anomaly counters / log labels
/// disambiguate.
#[derive(Debug, Clone, Default)]
pub struct MdnsParser {
    inner: DnsUdpParser,
}

impl MdnsParser {
    pub fn new() -> Self {
        Self {
            inner: DnsUdpParser::default(),
        }
    }
}

impl DatagramParser for MdnsParser {
    type Message = DnsMessage;

    fn parser_kind(&self) -> &'static str {
        PARSER_KIND
    }

    fn parse(
        &mut self,
        payload: &[u8],
        side: FlowSide,
        ts: Timestamp,
        out: &mut Vec<Self::Message>,
    ) {
        self.inner.parse(payload, side, ts, out);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parser_kind_label() {
        let p = MdnsParser::default();
        assert_eq!(p.parser_kind(), "mdns");
    }
}
