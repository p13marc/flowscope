//! High-level one-call iterator over SMB2/3 messages in a
//! pcap.

use std::path::Path;

use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::smb::session::SmbParser;
use crate::smb::types::SmbMessage;
use crate::{Result, SessionEvent};

/// Iterate every [`SmbMessage`] in the pcap, paired with the
/// [`FiveTupleKey`] of the flow it was seen on. Wraps the
/// full pcap → tracker → reassembler → SmbParser pipeline
/// in one call.
///
/// ```no_run
/// for (key, msg) in flowscope::smb::messages_from_pcap("trace.pcap")? {
///     if msg.create_is_admin_named_pipe {
///         println!("{key:?}  admin-pipe CREATE on {:?}", msg.create_path);
///     }
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn messages_from_pcap<P: AsRef<Path>>(
    path: P,
) -> Result<impl Iterator<Item = (FiveTupleKey, SmbMessage)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), SmbParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
