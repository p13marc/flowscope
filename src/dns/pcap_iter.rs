//! High-level one-call iterators over DNS messages in a pcap.

use std::path::Path;

use crate::dns::datagram::{DnsMessage, DnsUdpParser};
use crate::dns::exchange::{DnsExchange, DnsExchangeParser};
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::{Result, SessionEvent};

/// Iterate every [`DnsMessage`] in the pcap (UDP path only),
/// paired with the [`FiveTupleKey`] of the flow it was seen on.
///
/// ```no_run
/// for (key, msg) in flowscope::dns::messages_from_pcap("trace.pcap")? {
///     println!("{key:?} {msg:?}");
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
///
/// For TCP-only DNS (RFC 1035 §4.2.2 length-framed), use
/// `PcapFlowSource::sessions` with the [`crate::dns::DnsTcpParser`]
/// directly — this helper only covers the UDP common case.
pub fn messages_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, DnsMessage)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), DnsUdpParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}

/// Iterate every aggregated [`DnsExchange`] (query + response
/// pair) in the pcap. One event per resolution.
pub fn exchanges_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, DnsExchange)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), DnsExchangeParser::new())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
