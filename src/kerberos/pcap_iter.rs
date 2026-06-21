//! High-level one-call iterator over Kerberos messages in a pcap.

use std::path::Path;

use crate::extract::{FiveTuple, FiveTupleKey};
use crate::kerberos::datagram::KerberosUdpParser;
use crate::kerberos::types::KerberosMessage;
use crate::pcap::PcapFlowSource;
use crate::{Result, SessionEvent};

/// Iterate every [`KerberosMessage`] in the pcap (UDP/88 path),
/// paired with the [`FiveTupleKey`] of the flow it was seen on.
///
/// ```no_run
/// for (key, msg) in flowscope::kerberos::messages_from_pcap("trace.pcap")? {
///     if msg.kerberoast_suspect {
///         println!("{key:?} Kerberoast: {}", msg.realm);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
///
/// For TCP/88 Kerberos (which carries a 4-byte length prefix per
/// RFC 4120 §7.2.2), use `PcapFlowSource::sessions` with
/// [`crate::kerberos::KerberosTcpParser`] directly.
pub fn messages_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, KerberosMessage)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), KerberosUdpParser)
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
