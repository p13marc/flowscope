use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

use crate::tracker::FlowEvents;
#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
use crate::{DatagramParser, FlowDatagramDriver};
use crate::{FlowEvent, FlowExtractor, FlowTracker, Timestamp};
#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::{FlowSessionDriver, SessionEvent, SessionParser};

use pcap_file::pcap::PcapReader;

use crate::error::{Error, Module};

/// A pcap-backed source of [`crate::PacketView`]s.
///
/// Wraps [`PcapReader`] from `pcap-file` and exposes ergonomic
/// iterators that hand off to `netring-flow`.
pub struct PcapFlowSource<R: Read> {
    reader: PcapReader<R>,
}

impl PcapFlowSource<BufReader<File>> {
    /// Open a pcap file from disk.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        let file = File::open(path).map_err(|e| Error::io(Module::Pcap, e))?;
        let reader = PcapReader::new(BufReader::new(file))
            .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcap header", e))?;
        Ok(Self { reader })
    }
}

impl<R: Read> PcapFlowSource<R> {
    /// Wrap any `Read` (e.g., `Cursor<&[u8]>` for tests).
    pub fn from_reader(reader: R) -> crate::Result<Self> {
        Ok(Self {
            reader: PcapReader::new(reader)
                .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcap header", e))?,
        })
    }

    /// Iterate raw [`crate::PacketView`]s. Each call yields the next packet
    /// or `Err` on a malformed record.
    ///
    /// Note: each [`OwnedPacketView`] owns its data (we copy from
    /// the pcap reader because the underlying buffer is reused
    /// across `next_packet` calls). One alloc per packet — fine for
    /// offline analysis; not appropriate for sustained 1+ Gbps live
    /// replay.
    pub fn views(self) -> ViewIter<R> {
        ViewIter {
            reader: self.reader,
        }
    }

    /// One-step pipeline: feed every view through `extractor` and
    /// emit [`FlowEvent`]s.
    ///
    /// Constructs an internal [`FlowTracker`] with default config
    /// and `()` for per-flow user state. For non-default config or
    /// custom user state, drop down to the manual pattern:
    ///
    /// ```no_run
    /// use flowscope::pcap::PcapFlowSource;
    /// use flowscope::{FlowTracker, FlowTrackerConfig};
    /// use flowscope::extract::FiveTuple;
    /// use std::time::Duration;
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let mut config = FlowTrackerConfig::default();
    /// config.idle_timeout_tcp = Duration::from_secs(60);
    /// let mut tracker = FlowTracker::<FiveTuple>::with_config(
    ///     FiveTuple::bidirectional(),
    ///     config,
    /// );
    /// for view in PcapFlowSource::open("trace.pcap")?.views() {
    ///     let view = view?;
    ///     for _evt in tracker.track(&view) {
    ///         // process
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    pub fn with_extractor<E: FlowExtractor>(self, extractor: E) -> EventIter<R, E>
    where
        E::Key: Clone,
    {
        EventIter {
            views: self.views(),
            tracker: FlowTracker::new(extractor),
            pending: std::collections::VecDeque::new(),
            sweep_done: false,
        }
    }

    /// One-step offline TCP-session pipeline: every packet flows
    /// through `extractor` + a per-flow `parser`, yielding typed L7
    /// [`SessionEvent`]s. The end-of-input flush is automatic — when
    /// the pcap is exhausted the iterator drains every still-open
    /// flow via [`FlowSessionDriver::finish`].
    ///
    /// ```no_run
    /// use flowscope::extract::FiveTuple;
    /// use flowscope::pcap::PcapFlowSource;
    /// use flowscope::{SessionEvent, SessionParser, Timestamp};
    ///
    /// #[derive(Default, Clone)]
    /// struct Echo;
    /// impl SessionParser for Echo {
    ///     type Message = Vec<u8>;
    ///     fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
    ///         out.push(b.to_vec());
    ///     }
    ///     fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Vec<u8>>) {
    ///         out.push(b.to_vec());
    ///     }
    /// }
    ///
    /// # fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// for evt in PcapFlowSource::open("trace.pcap")?
    ///     .sessions(FiveTuple::bidirectional(), Echo::default())
    /// {
    ///     if let SessionEvent::Application { message, .. } = evt? {
    ///         println!("{} bytes", message.len());
    ///     }
    /// }
    /// # Ok(()) }
    /// ```
    #[cfg(all(feature = "session", feature = "reassembler"))]
    pub fn sessions<E, P>(self, extractor: E, parser: P) -> SessionIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: SessionParser + Clone + Send + 'static,
    {
        SessionIter {
            views: self.views(),
            driver: FlowSessionDriver::new(extractor, parser),
            pending: std::collections::VecDeque::new(),
            finished: false,
        }
    }

    /// One-step offline UDP-datagram pipeline — the
    /// [`DatagramParser`] mirror of [`Self::sessions`]. The
    /// end-of-input flush is automatic.
    #[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> DatagramIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
        P: DatagramParser + Clone + Send + 'static,
    {
        DatagramIter {
            views: self.views(),
            driver: FlowDatagramDriver::new(extractor, parser),
            pending: std::collections::VecDeque::new(),
            finished: false,
        }
    }
}

pub use crate::view::OwnedPacketView;

/// Iterator yielding `crate::Result<OwnedPacketView>`.
pub struct ViewIter<R: Read> {
    reader: PcapReader<R>,
}

impl<R: Read> Iterator for ViewIter<R> {
    type Item = crate::Result<OwnedPacketView>;

    fn next(&mut self) -> Option<Self::Item> {
        let pkt = self.reader.next_packet()?;
        match pkt {
            Ok(p) => {
                let ts = Timestamp::new(p.timestamp.as_secs() as u32, p.timestamp.subsec_nanos());
                Some(Ok(OwnedPacketView {
                    frame: p.data.into_owned(),
                    timestamp: ts,
                }))
            }
            Err(e) => Some(Err(Error::parse_with(
                Module::Pcap,
                "malformed pcap record",
                e,
            ))),
        }
    }
}

/// Iterator yielding `crate::Result<FlowEvent<E::Key>>`.
///
/// Drives an internal [`FlowTracker`] over the pcap stream. After
/// the underlying pcap is exhausted, runs one final sweep at
/// [`Timestamp::MAX`] to flush remaining flows as
/// [`FlowEvent::Ended { reason: IdleTimeout, .. }`](FlowEvent::Ended).
pub struct EventIter<R: Read, E: FlowExtractor>
where
    E::Key: Clone,
{
    views: ViewIter<R>,
    tracker: FlowTracker<E, ()>,
    pending: std::collections::VecDeque<FlowEvent<E::Key>>,
    sweep_done: bool,
}

impl<R: Read, E: FlowExtractor> Iterator for EventIter<R, E>
where
    E::Key: Clone,
{
    type Item = crate::Result<FlowEvent<E::Key>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }

            // Pull the next packet view, push events.
            match self.views.next() {
                Some(Ok(view)) => {
                    let evts: FlowEvents<E::Key> = self.tracker.track(&view);
                    for ev in evts {
                        self.pending.push_back(ev);
                    }
                    // Loop to drain
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    // Pcap exhausted. Run one final sweep at the max
                    // timestamp to flush every remaining flow.
                    if !self.sweep_done {
                        self.sweep_done = true;
                        for ev in self.tracker.sweep(Timestamp::MAX) {
                            self.pending.push_back(ev);
                        }
                        // Loop to drain
                    } else {
                        return None;
                    }
                }
            }
        }
    }
}

/// Iterator yielding `crate::Result<SessionEvent<E::Key, P::Message>>`.
///
/// Produced by [`PcapFlowSource::sessions`]. Drives an internal
/// [`FlowSessionDriver`] over the pcap stream; after the pcap is
/// exhausted, one `finish()` flushes every still-open flow.
#[cfg(all(feature = "session", feature = "reassembler"))]
pub struct SessionIter<R: Read, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
{
    views: ViewIter<R>,
    driver: FlowSessionDriver<E, P>,
    pending: std::collections::VecDeque<SessionEvent<E::Key, P::Message>>,
    finished: bool,
}

#[cfg(all(feature = "session", feature = "reassembler"))]
impl<R: Read, E, P> Iterator for SessionIter<R, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
{
    type Item = crate::Result<SessionEvent<E::Key, P::Message>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }
            match self.views.next() {
                Some(Ok(view)) => {
                    for ev in self.driver.track(&view) {
                        self.pending.push_back(ev);
                    }
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    if self.finished {
                        return None;
                    }
                    self.finished = true;
                    for ev in self.driver.finish() {
                        self.pending.push_back(ev);
                    }
                }
            }
        }
    }
}

/// Iterator yielding `crate::Result<SessionEvent<E::Key, P::Message>>`.
///
/// Produced by [`PcapFlowSource::datagrams`] — the UDP mirror of
/// [`SessionIter`].
#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
pub struct DatagramIter<R: Read, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    views: ViewIter<R>,
    driver: FlowDatagramDriver<E, P>,
    pending: std::collections::VecDeque<SessionEvent<E::Key, P::Message>>,
    finished: bool,
}

#[cfg(all(feature = "session", feature = "reassembler", feature = "extractors"))]
impl<R: Read, E, P> Iterator for DatagramIter<R, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    type Item = crate::Result<SessionEvent<E::Key, P::Message>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }
            match self.views.next() {
                Some(Ok(view)) => {
                    for ev in self.driver.track(&view) {
                        self.pending.push_back(ev);
                    }
                }
                Some(Err(e)) => return Some(Err(e)),
                None => {
                    if self.finished {
                        return None;
                    }
                    self.finished = true;
                    for ev in self.driver.finish() {
                        self.pending.push_back(ev);
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Plan 34: `&OwnedPacketView` converts to a `PacketView`, so it
    /// can be passed straight to `track()` without `as_view()`.
    #[test]
    fn owned_view_converts_to_packet_view() {
        let owned = OwnedPacketView {
            frame: vec![1, 2, 3, 4],
            timestamp: Timestamp::new(7, 42),
        };
        let pv: crate::PacketView<'_> = (&owned).into();
        assert_eq!(pv.frame, &[1, 2, 3, 4]);
        assert_eq!(pv.timestamp, Timestamp::new(7, 42));
    }
}
