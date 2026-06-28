//! High-level one-call iterator over SSH handshakes in a pcap.

use std::path::Path;

use crate::Result;
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::session::SessionEvent;
use crate::ssh::session::SshParser;
use crate::ssh::types::SshMessage;

/// Iterate every [`SshMessage`] in the pcap (banner + KEXINIT —
/// the unencrypted portion of the SSH handshake), paired with the
/// [`FiveTupleKey`] of the flow it was seen on. The KEXINIT
/// variant carries the HASSH client fingerprint.
///
/// ```no_run
/// use flowscope::ssh::SshMessage;
/// for (key, msg) in flowscope::ssh::messages_from_pcap("trace.pcap")? {
///     if let SshMessage::KexInit(kex) = msg {
///         println!("{key:?} HASSH={:?}", kex.hassh);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn messages_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, SshMessage)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), SshParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
