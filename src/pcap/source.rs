use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::Duration;

#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::session::SessionEvent;
#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::session::{DatagramDriver, SessionDriver, TemplateFactory};
use crate::tracker::FlowEvents;
#[cfg(all(feature = "session", feature = "reassembler"))]
use crate::{DatagramParser, SessionParser};
use crate::{FlowEvent, FlowExtractor, FlowTracker, Timestamp};

use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;

use crate::error::{Error, Module};

/// On-disk capture format, detected from the file's magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureFormat {
    /// Classic libpcap (any byte order, µs or ns resolution).
    Pcap,
    /// pcapng (Wireshark / dumpcap default).
    PcapNg,
}

/// One packet read from a capture file.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CapturedPacket {
    /// Capture timestamp since the Unix epoch. For pcapng, the
    /// interface's `if_tsresol` / `if_tsoffset` are applied.
    pub timestamp: Duration,
    /// Captured bytes (possibly truncated to the snap length).
    pub data: Vec<u8>,
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// Link type of the interface the packet was captured on.
    pub datalink: DataLink,
}

/// Per-interface state of a pcapng section.
#[derive(Debug, Clone, Copy)]
struct PcapNgInterface {
    datalink: DataLink,
    /// Timestamp units per second.
    units_per_sec: u64,
    /// `if_tsoffset`, seconds added to every timestamp.
    offset_secs: i64,
}

impl PcapNgInterface {
    fn timestamp(&self, raw: u64) -> Duration {
        let units = self.units_per_sec.max(1);
        let secs = (raw / units) as i64 + self.offset_secs;
        let frac = u128::from(raw % units);
        let nanos = (frac * 1_000_000_000 / u128::from(units)) as u32;
        Duration::new(secs.max(0) as u64, nanos)
    }
}

enum ReaderInner<R: Read> {
    Pcap(PcapReader<R>),
    PcapNg {
        reader: PcapNgReader<R>,
        interfaces: Vec<PcapNgInterface>,
    },
}

/// Reads classic pcap **and** pcapng, detecting the format from the
/// magic number.
///
/// pcapng timestamps honour each interface's `if_tsresol` (default
/// microseconds) and `if_tsoffset`; Enhanced and Simple Packet
/// Blocks are returned, every other block is skipped.
pub struct CaptureReader<R: Read> {
    inner: ReaderInner<R>,
}

impl CaptureReader<BufReader<File>> {
    /// Open a capture file.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        let file = File::open(path).map_err(|e| Error::io(Module::Pcap, e))?;
        Self::new(BufReader::new(file))
    }
}

impl<R: BufRead> CaptureReader<R> {
    /// Wrap a buffered reader positioned at the start of a capture.
    pub fn new(mut reader: R) -> crate::Result<Self> {
        let magic = {
            let buf = reader.fill_buf().map_err(|e| Error::io(Module::Pcap, e))?;
            let mut m = [0u8; 4];
            let n = buf.len().min(4);
            m[..n].copy_from_slice(&buf[..n]);
            (n == 4).then_some(u32::from_le_bytes(m))
        };
        let inner = match magic {
            Some(0x0a0d_0d0a) => ReaderInner::PcapNg {
                reader: PcapNgReader::new(reader)
                    .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcapng header", e))?,
                interfaces: Vec::new(),
            },
            _ => ReaderInner::Pcap(
                PcapReader::new(reader)
                    .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcap header", e))?,
            ),
        };
        Ok(Self { inner })
    }
}

impl<R: Read> CaptureReader<R> {
    /// The detected format.
    pub fn format(&self) -> CaptureFormat {
        match self.inner {
            ReaderInner::Pcap(_) => CaptureFormat::Pcap,
            ReaderInner::PcapNg { .. } => CaptureFormat::PcapNg,
        }
    }

    /// Next packet, `None` at end of file.
    pub fn next_packet(&mut self) -> Option<crate::Result<CapturedPacket>> {
        match &mut self.inner {
            ReaderInner::Pcap(reader) => {
                let datalink = reader.header().datalink;
                Some(
                    reader
                        .next_packet()?
                        .map(|p| CapturedPacket {
                            timestamp: p.timestamp,
                            original_len: p.orig_len,
                            data: p.data.into_owned(),
                            datalink,
                        })
                        .map_err(|e| Error::parse_with(Module::Pcap, "malformed pcap record", e)),
                )
            }
            ReaderInner::PcapNg { reader, interfaces } => {
                use pcap_file::pcapng::Block;
                loop {
                    let block = match reader.next_block()? {
                        Ok(b) => b,
                        Err(e) => {
                            return Some(Err(Error::parse_with(
                                Module::Pcap,
                                "malformed pcapng block",
                                e,
                            )));
                        }
                    };
                    match block {
                        Block::SectionHeader(_) => interfaces.clear(),
                        Block::InterfaceDescription(idb) => {
                            let mut iface = PcapNgInterface {
                                datalink: idb.linktype,
                                units_per_sec: 1_000_000,
                                offset_secs: 0,
                            };
                            for opt in &idb.options {
                                match opt {
                                    InterfaceDescriptionOption::IfTsResol(v) => {
                                        iface.units_per_sec = if v & 0x80 == 0 {
                                            10u64.checked_pow(u32::from(*v)).unwrap_or(u64::MAX)
                                        } else {
                                            1u64.checked_shl(u32::from(v & 0x7f))
                                                .unwrap_or(u64::MAX)
                                        };
                                    }
                                    InterfaceDescriptionOption::IfTsOffset(o) => {
                                        iface.offset_secs = *o as i64;
                                    }
                                    _ => {}
                                }
                            }
                            interfaces.push(iface);
                        }
                        Block::EnhancedPacket(epb) => {
                            // pcap-file hands back the raw 64-bit tick
                            // count as nanoseconds; rescale it with the
                            // interface's resolution.
                            let iface = interfaces
                                .get(epb.interface_id as usize)
                                .copied()
                                .unwrap_or(PcapNgInterface {
                                    datalink: DataLink::ETHERNET,
                                    units_per_sec: 1_000_000,
                                    offset_secs: 0,
                                });
                            let raw = epb.timestamp.as_nanos() as u64;
                            return Some(Ok(CapturedPacket {
                                timestamp: iface.timestamp(raw),
                                original_len: epb.original_len,
                                data: epb.data.into_owned(),
                                datalink: iface.datalink,
                            }));
                        }
                        Block::SimplePacket(spb) => {
                            let datalink = interfaces
                                .first()
                                .map_or(DataLink::ETHERNET, |i| i.datalink);
                            return Some(Ok(CapturedPacket {
                                timestamp: Duration::ZERO,
                                original_len: spb.original_len,
                                data: spb.data.into_owned(),
                                datalink,
                            }));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl<R: Read> Iterator for CaptureReader<R> {
    type Item = crate::Result<CapturedPacket>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet()
    }
}

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
pub struct ViewIter<R: Read> {
    reader: CaptureReader<R>,
    /// `Some(factor)` paces replay; `None` = as-fast-as-possible.
    speed_factor: Option<f64>,
    /// Capture timestamp of the previously-emitted packet, used to
    /// compute inter-arrival sleeps when `speed_factor.is_some()`.
    prev_pcap_ts: Option<std::time::Duration>,
}

impl<R: Read> Iterator for ViewIter<R> {
    type Item = crate::Result<OwnedPacketView>;

    fn next(&mut self) -> Option<Self::Item> {
        let p = match self.reader.next_packet()? {
            Ok(p) => p,
            Err(e) => return Some(Err(e)),
        };
        // Plan 152: pace emission via std::thread::sleep when
        // speed_factor is set.
        if let Some(factor) = self.speed_factor
            && factor.is_finite()
        {
            if let Some(prev) = self.prev_pcap_ts {
                let dt = p.timestamp.saturating_sub(prev);
                let nanos = (dt.as_nanos() as f64 / factor) as u64;
                if nanos > 0 {
                    std::thread::sleep(std::time::Duration::from_nanos(nanos));
                }
            }
            self.prev_pcap_ts = Some(p.timestamp);
        }
        let ts = Timestamp::new(p.timestamp.as_secs() as u32, p.timestamp.subsec_nanos());
        Some(Ok(OwnedPacketView::new(p.data, ts)))
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
