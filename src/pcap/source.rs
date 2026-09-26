use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;

#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::session::SessionEvent;
#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::session::{DatagramDriver, SessionDriver, TemplateFactory};
use crate::tracker::FlowEvents;
#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::{DatagramParser, SessionParser};
use crate::{FlowEvent, FlowExtractor, FlowTracker, Timestamp};

use super::reader::{CaptureFormat, CaptureReader};

/// A capture-file source of [`crate::PacketView`]s — classic pcap
/// or pcapng, detected automatically (see [`CaptureReader`]).
pub struct PcapFlowSource<R: Read> {
    reader: CaptureReader<R>,
    /// Pace replay at `speed_factor × real-time` between
    /// consecutive packets. `None` (default) = as-fast-as-possible.
    /// Plan 152 (0.13).
    speed_factor: Option<f64>,
}

impl PcapFlowSource<BufReader<File>> {
    /// Open a pcap or pcapng file from disk.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        Ok(Self {
            reader: CaptureReader::open(path)?,
            speed_factor: None,
        })
    }
}

impl<R: BufRead> PcapFlowSource<R> {
    /// Wrap any buffered reader (e.g. `Cursor<&[u8]>` for tests).
    pub fn from_reader(reader: R) -> crate::Result<Self> {
        Ok(Self {
            reader: CaptureReader::new(reader)?,
            speed_factor: None,
        })
    }
}

impl<R: Read> PcapFlowSource<R> {
    /// The detected capture format.
    pub fn format(&self) -> CaptureFormat {
        self.reader.format()
    }

    /// Pace packet emission at `factor × real-time`.
    ///
    /// `1.0` = original timing; `2.0` = double speed;
    /// `f64::INFINITY` = as-fast-as-possible (default — equivalent
    /// to not calling this method).
    ///
    /// Sleeps `std::thread::sleep(dt / factor)` between
    /// consecutive packets, where `dt` is the pcap-recorded
    /// inter-arrival time. Precision is bounded by the OS scheduler
    /// (~1 ms on Linux, ~15 ms on Windows). Suitable for demos and
    /// behaviour-realistic offline replay; **not** for microsecond-
    /// precise traffic regeneration.
    ///
    /// # Tokio caveat
    ///
    /// `std::thread::sleep` blocks the current thread. Iterating a
    /// paced source inside a tokio task without `spawn_blocking`
    /// will monopolise the worker. Either:
    /// - Iterate inside `tokio::task::spawn_blocking`, or
    /// - Run on `#[tokio::main(flavor = "current_thread")]` with a
    ///   dedicated thread for the source.
    ///
    /// Panics if `factor <= 0` or NaN.
    ///
    /// Plan 152 (0.13).
    pub fn with_speed_factor(mut self, factor: f64) -> Self {
        assert!(
            factor > 0.0 && factor.is_finite() || factor == f64::INFINITY,
            "speed_factor must be > 0 (got {factor})",
        );
        self.speed_factor = Some(factor);
        self
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
            unsupported: 0,
            speed_factor: self.speed_factor,
            prev_pcap_ts: None,
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
    /// through `extractor` + a per-flow clone of `parser`
    /// ([`SessionDriver`]), yielding its [`SessionEvent`]s. The
    /// end-of-input flush is automatic. The per-parser
    /// `*_from_pcap` helpers and [`crate::pcap::session_messages`] are
    /// built on this.
    #[cfg(all(feature = "session", feature = "reassembler"))]
    pub fn sessions<E, P>(self, extractor: E, parser: P) -> SessionIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
        P: SessionParser + Clone + Send + Sync + 'static,
    {
        SessionIter {
            views: self.views(),
            driver: SessionDriver::new(extractor, TemplateFactory(parser)),
            pending: std::collections::VecDeque::new(),
            finished: false,
        }
    }

    /// One-step offline UDP-datagram pipeline — the
    /// [`DatagramParser`] mirror of [`Self::sessions`].
    #[cfg(all(feature = "session", feature = "reassembler"))]
    pub fn datagrams<E, P>(self, extractor: E, parser: P) -> DatagramIter<R, E, P>
    where
        E: FlowExtractor,
        E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
        P: DatagramParser + Clone + Send + Sync + 'static,
    {
        DatagramIter {
            views: self.views(),
            driver: DatagramDriver::new(extractor, TemplateFactory(parser)),
            pending: std::collections::VecDeque::new(),
            finished: false,
        }
    }
}

pub use crate::view::OwnedPacketView;

/// Iterator yielding `crate::Result<OwnedPacketView>`.
///
/// Every packet is normalised to Ethernet
/// ([`CapturedPacket::into_ethernet`](super::CapturedPacket::into_ethernet)):
/// Linux cooked, raw-IP and loopback captures work like Ethernet
/// ones. Packets of other link types are skipped and counted
/// ([`Self::unsupported`]).
pub struct ViewIter<R: Read> {
    reader: CaptureReader<R>,
    unsupported: u64,
    /// `Some(factor)` paces replay; `None` = as-fast-as-possible.
    speed_factor: Option<f64>,
    /// Capture timestamp of the previously-emitted packet, used to
    /// compute inter-arrival sleeps when `speed_factor.is_some()`.
    prev_pcap_ts: Option<std::time::Duration>,
}

impl<R: Read> Iterator for ViewIter<R> {
    type Item = crate::Result<OwnedPacketView>;

    fn next(&mut self) -> Option<Self::Item> {
        let (timestamp, frame) = loop {
            let p = match self.reader.next_packet()? {
                Ok(p) => p,
                Err(e) => return Some(Err(e)),
            };
            let timestamp = p.timestamp;
            match p.into_ethernet() {
                Ok(frame) => break (timestamp, frame),
                Err(_) => self.unsupported += 1,
            }
        };
        // Plan 152: pace emission via std::thread::sleep when
        // speed_factor is set.
        if let Some(factor) = self.speed_factor
            && factor.is_finite()
        {
            if let Some(prev) = self.prev_pcap_ts {
                let dt = timestamp.saturating_sub(prev);
                let nanos = (dt.as_nanos() as f64 / factor) as u64;
                if nanos > 0 {
                    std::thread::sleep(std::time::Duration::from_nanos(nanos));
                }
            }
            self.prev_pcap_ts = Some(timestamp);
        }
        let ts = Timestamp::new(timestamp.as_secs() as u32, timestamp.subsec_nanos());
        Some(Ok(OwnedPacketView::new(frame, ts)))
    }
}

impl<R: Read> ViewIter<R> {
    /// Packets skipped so far because their link type cannot be
    /// turned into Ethernet.
    pub fn unsupported(&self) -> u64 {
        self.unsupported
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
/// Produced by [`PcapFlowSource::sessions`]. Drives a
/// [`SessionDriver`] over the capture; after the file is exhausted,
/// one `finish()` flushes every still-open flow.
#[cfg(all(feature = "session", feature = "reassembler"))]
pub struct SessionIter<R: Read, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
{
    views: ViewIter<R>,
    driver: SessionDriver<E, TemplateFactory<P>>,
    pending: std::collections::VecDeque<SessionEvent<E::Key, P::Message>>,
    finished: bool,
}

#[cfg(all(feature = "session", feature = "reassembler"))]
impl<R: Read, E, P> Iterator for SessionIter<R, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
    P: SessionParser + Clone + Send + Sync + 'static,
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
#[cfg(all(feature = "session", feature = "reassembler"))]
pub struct DatagramIter<R: Read, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
    P: DatagramParser + Clone + Send + Sync + 'static,
{
    views: ViewIter<R>,
    driver: DatagramDriver<E, TemplateFactory<P>>,
    pending: std::collections::VecDeque<SessionEvent<E::Key, P::Message>>,
    finished: bool,
}

#[cfg(all(feature = "session", feature = "reassembler"))]
impl<R: Read, E, P> Iterator for DatagramIter<R, E, P>
where
    E: FlowExtractor,
    E::Key: std::hash::Hash + Eq + Clone + Send + Sync + 'static,
    P: DatagramParser + Clone + Send + Sync + 'static,
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
        let owned = OwnedPacketView::new(vec![1, 2, 3, 4], Timestamp::new(7, 42));
        let pv: crate::PacketView<'_> = (&owned).into();
        assert_eq!(pv.frame, &[1, 2, 3, 4]);
        assert_eq!(pv.timestamp, Timestamp::new(7, 42));
    }
}
