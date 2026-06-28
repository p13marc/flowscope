//! High-level one-call iterators over TLS messages in a pcap.
//!
//! The strongly-typed front door over the generic
//! [`crate::pcap::session_messages`] building block: these compose
//! the offline pcap pipeline + [`TlsParser`] / [`TlsHandshakeParser`]
//! and pre-filter to the specific message type (e.g.
//! [`TlsClientHello`]) so the common "open a pcap, look at every
//! ClientHello" path is one call — no Driver builder + slot handle +
//! drain loop. For an arbitrary `SessionParser`, reach for
//! [`crate::pcap::session_messages::<P>`](crate::pcap::session_messages).

use std::path::Path;

use crate::Result;
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::session::SessionEvent;
use crate::tls::handshake::{TlsHandshake, TlsHandshakeParser};
use crate::tls::session::{TlsMessage, TlsParser};
use crate::tls::types::TlsClientHello;

/// Iterate every [`TlsClientHello`] in the pcap, paired with
/// the [`FiveTupleKey`] of the flow it was seen on. Wraps
/// the full pcap → tracker → reassembler → TlsParser path
/// in one call.
///
/// ```no_run
/// for (key, hello) in flowscope::tls::client_hellos_from_pcap("trace.pcap")? {
///     let sni = hello.sni.as_deref().unwrap_or("(none)");
///     println!("{key:?}  SNI={sni}");
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
///
/// Iterator stops on the first pcap-decode error.
pub fn client_hellos_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, Box<TlsClientHello>)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), TlsParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application {
                key,
                message: TlsMessage::ClientHello(h),
                ..
            } => Some((key, h)),
            _ => None,
        }))
}

/// Iterate every aggregated [`TlsHandshake`] in the pcap,
/// paired with the [`FiveTupleKey`] of the flow it was
/// seen on. One event per handshake (ClientHello +
/// ServerHello + outcome rolled into a single value),
/// rather than one per TLS record.
///
/// ```no_run
/// for (key, hs) in flowscope::tls::handshakes_from_pcap("trace.pcap")? {
///     println!("{key:?}  sni={:?} ja4={:?} outcome={:?}", hs.sni, hs.ja4, hs.outcome);
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn handshakes_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, TlsHandshake)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), TlsHandshakeParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
