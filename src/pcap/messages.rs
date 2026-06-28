//! Generic one-call pcap → typed-message iterators (issue #86).
//!
//! Two generic entries replace the 13 hand-written per-parser
//! `*_from_pcap` helpers: [`session_messages`] for any
//! [`SessionParser`] (TCP) and [`datagram_messages`] for any
//! [`DatagramParser`] (UDP). Both use the bidirectional 5-tuple
//! extractor and key every message by its [`FiveTupleKey`], so every
//! parser — current and future — is equally first-class with zero
//! per-parser code.
//!
//! (One unified `messages::<P>()` isn't possible coherence-safely:
//! `SessionParser` and `DatagramParser` are distinct traits, and two
//! overlapping blanket impls over `P` are rejected by Rust's coherence
//! rules. Splitting by transport keeps the API blanket and
//! registration-free.)
//!
//! The multi-parser case stays [`crate::driver::Driver::run_pcap`].

use std::path::Path;

use crate::extract::{FiveTuple, FiveTupleKey};
use crate::pcap::PcapFlowSource;
use crate::{DatagramParser, Result, SessionEvent, SessionParser};

/// Iterate every application message a [`SessionParser`] `P` produces
/// over the TCP flows in a pcap, paired with the [`FiveTupleKey`] of
/// the flow it was seen on (issue #86).
///
/// Works for any `SessionParser` with a `Default` instance — no
/// per-parser wrapper needed. For UDP parsers use
/// [`datagram_messages`]; for multiple parsers at once use
/// [`crate::driver::Driver::run_pcap`].
///
/// ```no_run
/// use flowscope::tls::TlsParser;
/// for (key, msg) in flowscope::pcap::session_messages::<TlsParser>("trace.pcap")? {
///     let _ = (key, msg);
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn session_messages<P>(
    path: impl AsRef<Path>,
) -> Result<impl Iterator<Item = (FiveTupleKey, P::Message)>>
where
    P: SessionParser + Default + Clone + Send + Sync + 'static,
{
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .sessions(FiveTuple::bidirectional(), P::default())
        .filter_map(Result::ok)
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}

/// The [`DatagramParser`] (UDP) mirror of [`session_messages`] — every
/// message a `P` produces over a pcap, keyed by [`FiveTupleKey`]
/// (issue #86).
///
/// ```no_run
/// use flowscope::dns::DnsUdpParser;
/// for (key, msg) in flowscope::pcap::datagram_messages::<DnsUdpParser>("trace.pcap")? {
///     let _ = (key, msg);
/// }
/// # Ok::<(), flowscope::Error>(())
/// ```
pub fn datagram_messages<P>(
    path: impl AsRef<Path>,
) -> Result<impl Iterator<Item = (FiveTupleKey, P::Message)>>
where
    P: DatagramParser + Default + Clone + Send + Sync + 'static,
{
    let source = PcapFlowSource::open(path)?;
    Ok(source
        .datagrams(FiveTuple::bidirectional(), P::default())
        .filter_map(Result::ok)
        .filter_map(|evt| match evt {
            SessionEvent::Application { key, message, .. } => Some((key, message)),
            _ => None,
        }))
}
