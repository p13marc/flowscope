//! High-level one-call iterators over HTTP messages in a pcap.

use std::path::Path;

use crate::Result;
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::http::exchange::{HttpExchange, HttpExchangeParser};
use crate::http::session::{HttpMessage, HttpParser};
use crate::http::types::{HttpRequest, HttpResponse};
use crate::pcap::PcapFlowSource;
use crate::session::SessionEvent;

/// Iterate every [`HttpRequest`] in the pcap, paired with the
/// [`FiveTupleKey`] of the flow it was seen on.
///
/// ```no_run
/// for (key, req) in flowscope::http::requests_from_pcap("trace.pcap")? {
///     println!("{key:?} {} {}{}", req.method_str().unwrap_or("?"), req.host().unwrap_or(""), req.path_str().unwrap_or("?"));
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn requests_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, HttpRequest)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), HttpParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application {
                key,
                message: HttpMessage::Request(req),
                ..
            } => Some((key, req)),
            _ => None,
        }))
}

/// Iterate every [`HttpResponse`] in the pcap, paired with the
/// [`FiveTupleKey`] of the flow it was seen on.
pub fn responses_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, HttpResponse)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), HttpParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application {
                key,
                message: HttpMessage::Response(resp),
                ..
            } => Some((key, resp)),
            _ => None,
        }))
}

/// Iterate every aggregated [`HttpExchange`] (request + response
/// pair) in the pcap. One event per access-log row.
///
/// ```no_run
/// for (key, ex) in flowscope::http::exchanges_from_pcap("trace.pcap")? {
///     let status = ex.response.as_ref().map(|r| r.status).unwrap_or(0);
///     println!("{key:?} {status} {:?}", ex.outcome);
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn exchanges_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, HttpExchange)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), HttpExchangeParser::new())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
