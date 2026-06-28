//! High-level one-call iterator over LDAP messages in a pcap.

use std::path::Path;

use crate::Result;
use crate::extract::{FiveTuple, FiveTupleKey};
use crate::ldap::session::LdapParser;
use crate::ldap::types::LdapMessage;
use crate::pcap::PcapFlowSource;
use crate::session::SessionEvent;

/// Iterate every [`LdapMessage`] in the pcap, paired with the
/// [`FiveTupleKey`] of the flow it was seen on.
///
/// ```no_run
/// # #![allow(deprecated)]
/// for (key, msg) in flowscope::ldap::messages_from_pcap("trace.pcap")? {
///     if msg.search_attributes_spn_query {
///         println!("{key:?} GetUserSPNs / BloodHound: base={:?}", msg.search_base);
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
) -> Result<impl Iterator<Item = (FiveTupleKey, LdapMessage)>> {
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), LdapParser::default())
        .filter_map(|evt| evt.ok())
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
