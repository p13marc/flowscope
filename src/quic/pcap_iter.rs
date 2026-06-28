//! High-level one-call iterator over QUIC Initial packets
//! in a pcap.

use std::path::Path;

use crate::Result;
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::quic::datagram::QuicUdpParser;
use crate::quic::types::QuicInitial;
use crate::session::SessionEvent;

/// Iterate every [`QuicInitial`] in the pcap, paired with
/// the [`FiveTupleKey`] of the UDP flow it was seen on.
/// Wraps the full pcap → tracker → QuicUdpParser pipeline
/// (which derives the Initial keys, AEAD-decrypts the
/// payload, reassembles CRYPTO frames, and extracts the
/// TLS ClientHello SNI / ALPN) in one call.
///
/// ```no_run
/// for (key, init) in flowscope::quic::initials_from_pcap("trace.pcap")? {
///     let sni = init.sni.as_deref().unwrap_or("(none)");
///     println!("{key:?}  {} sni={sni}", init.version);
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn initials_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, QuicInitial)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), QuicUdpParser)
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
