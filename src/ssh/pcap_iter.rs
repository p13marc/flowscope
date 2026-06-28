//! High-level one-call iterator over SSH handshakes in a pcap.

use std::path::Path;

use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::ssh::session::SshParser;
use crate::ssh::types::SshMessage;
use crate::{Result, SessionEvent};

/// Iterate every [`SshMessage`] in the pcap (banner + KEXINIT —
/// the unencrypted portion of the SSH handshake), paired with the
/// [`FiveTupleKey`] of the flow it was seen on. The KEXINIT
/// variant carries the HASSH client fingerprint.
///
/// ```no_run
/// # #![allow(deprecated)]
/// use flowscope::ssh::SshMessage;
/// for (key, msg) in flowscope::ssh::messages_from_pcap("trace.pcap")? {
///     if let SshMessage::KexInit(kex) = msg {
///         println!("{key:?} HASSH={:?}", kex.hassh);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
#[deprecated(
    since = "0.20.0",
    note = "use flowscope::pcap::session_messages::<P>() / datagram_messages::<P>() (issue #86)"
)]
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
