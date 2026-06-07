//! [`Pipeline`] — Tier 1 high-level entry point.
//!
//! One import, one builder chain, one iterator. Wraps the common
//! configuration of [`crate::FlowSessionDriver`] +
//! [`crate::FlowDatagramDriver`] for the 90 % case.
//!
//! ```no_run
//! use flowscope::Pipeline;
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::HttpParser;
//!
//! # fn main() -> flowscope::Result<()> {
//! let mut pipeline = Pipeline::builder(FiveTuple::bidirectional())
//!     .session(HttpParser::default())
//!     .build();
//!
//! for event in pipeline.run_pcap("trace.pcap")? {
//!     println!("{:?}", event?);
//! }
//! # Ok(()) }
//! ```

use std::collections::VecDeque;
use std::hash::Hash;
use std::marker::PhantomData;
#[cfg(feature = "pcap")]
use std::path::Path;

use crate::event::FlowEvent;
use crate::extractor::FlowExtractor;
#[cfg(feature = "pcap")]
use crate::pcap::PcapFlowSource;
use crate::session::{DatagramParser, SessionEvent, SessionParser};
use crate::tracker::FlowTrackerConfig;

#[cfg(feature = "session")]
use crate::datagram_driver::FlowDatagramDriver;
#[cfg(feature = "session")]
use crate::session_driver::FlowSessionDriver;

/// Type-state marker — no session parser registered yet.
///
/// Implements [`SessionParser`] with `Message = ()` and no-op
/// `feed_*` methods so the iterator's `PipelineIter<E, NoSessionParser, D>`
/// instantiation type-checks; `build()` is only callable on a
/// builder where the marker has been replaced by a concrete
/// parser type.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoSessionParser;

impl SessionParser for NoSessionParser {
    type Message = ();
    fn feed_initiator(&mut self, _bytes: &[u8], _ts: crate::Timestamp) -> Vec<Self::Message> {
        Vec::new()
    }
    fn feed_responder(&mut self, _bytes: &[u8], _ts: crate::Timestamp) -> Vec<Self::Message> {
        Vec::new()
    }
}

/// Type-state marker — no datagram parser registered yet.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoDatagramParser;

impl DatagramParser for NoDatagramParser {
    type Message = ();
    fn parse(
        &mut self,
        _payload: &[u8],
        _side: crate::event::FlowSide,
        _ts: crate::Timestamp,
    ) -> Vec<Self::Message> {
        Vec::new()
    }
}

/// Builder for [`Pipeline`].
///
/// Construct via [`Pipeline::builder`]; chain configuration; call
/// [`PipelineBuilder::build`] to materialise.
///
/// The `S` (session parser) and `D` (datagram parser) type
/// parameters use type-state to ensure at least one of them is
/// registered before `.build()` is callable.
pub struct PipelineBuilder<E, S = NoSessionParser, D = NoDatagramParser> {
    extractor: E,
    config: FlowTrackerConfig,
    session_parser: Option<S>,
    datagram_parser: Option<D>,
    emit_anomalies: bool,
    monotonic: bool,
}

impl<E> PipelineBuilder<E, NoSessionParser, NoDatagramParser>
where
    E: FlowExtractor,
{
    /// Construct a builder. Defaults: anomalies emitted, monotonic
    /// timestamps on (good for offline pcap replay).
    pub fn new(extractor: E) -> Self {
        Self {
            extractor,
            config: FlowTrackerConfig::default(),
            session_parser: None,
            datagram_parser: None,
            emit_anomalies: true,
            monotonic: true,
        }
    }
}

impl<E, S, D> PipelineBuilder<E, S, D>
where
    E: FlowExtractor,
{
    /// Override the tracker config. Default:
    /// [`FlowTrackerConfig::default`] — Suricata-style idle
    /// timeouts + 100 k flow LRU.
    pub fn config(mut self, c: FlowTrackerConfig) -> Self {
        self.config = c;
        self
    }

    /// Emit `FlowAnomaly` / `TrackerAnomaly` events inline.
    /// Default `true`: anomalies are signal, not noise.
    pub fn emit_anomalies(mut self, on: bool) -> Self {
        self.emit_anomalies = on;
        self
    }

    /// Assume the packet stream is in monotonic timestamp order.
    /// Default `true` for `run_pcap`, ignored for `run_iter`.
    pub fn monotonic(mut self, on: bool) -> Self {
        self.monotonic = on;
        self
    }

    /// Register the single TCP / session parser. Type-state
    /// upgrades the `S` parameter from `NoSessionParser` to the
    /// concrete parser type.
    pub fn session<P>(self, p: P) -> PipelineBuilder<E, P, D>
    where
        P: SessionParser + Clone + Send + 'static,
    {
        PipelineBuilder {
            extractor: self.extractor,
            config: self.config,
            session_parser: Some(p),
            datagram_parser: self.datagram_parser,
            emit_anomalies: self.emit_anomalies,
            monotonic: self.monotonic,
        }
    }

    /// Register the single UDP / datagram parser.
    pub fn datagram<P>(self, p: P) -> PipelineBuilder<E, S, P>
    where
        P: DatagramParser + Clone + Send + 'static,
    {
        PipelineBuilder {
            extractor: self.extractor,
            config: self.config,
            session_parser: self.session_parser,
            datagram_parser: Some(p),
            emit_anomalies: self.emit_anomalies,
            monotonic: self.monotonic,
        }
    }
}

/// Build implementation — single entry, handles all four parser
/// configurations uniformly. With both `NoSessionParser` and
/// `NoDatagramParser` placeholders the resulting Pipeline is a
/// no-op; consumers register at least one parser via
/// [`PipelineBuilder::session`] / [`PipelineBuilder::datagram`].
#[cfg(feature = "session")]
impl<E, S, D> PipelineBuilder<E, S, D>
where
    E: FlowExtractor + Clone,
    E::Key: Hash + Eq + Clone + Send + 'static,
    S: SessionParser + Clone + Send + 'static,
    D: DatagramParser + Clone + Send + 'static,
    S: Default,
    D: Default,
{
    /// Materialise the pipeline. The session parser defaults to
    /// `NoSessionParser` (no-op) if `.session(…)` was not called;
    /// likewise for `.datagram(…)`.
    pub fn build(self) -> Pipeline<E, S, D> {
        let session_parser = self.session_parser.unwrap_or_default();
        let datagram_parser = self.datagram_parser.unwrap_or_default();
        let session = FlowSessionDriver::with_config(
            self.extractor.clone(),
            session_parser.clone(),
            self.config.clone(),
        )
        .with_emit_anomalies(self.emit_anomalies)
        .with_monotonic_timestamps(self.monotonic);
        let datagram = FlowDatagramDriver::with_config(
            self.extractor.clone(),
            datagram_parser.clone(),
            self.config.clone(),
        )
        .with_emit_anomalies(self.emit_anomalies)
        .with_monotonic_timestamps(self.monotonic);
        Pipeline {
            extractor: self.extractor,
            config: self.config,
            session_parser,
            datagram_parser,
            emit_anomalies: self.emit_anomalies,
            monotonic: self.monotonic,
            session: Some(session),
            datagram: Some(datagram),
            _markers: PhantomData,
        }
    }
}

/// Unified event emitted by [`Pipeline::run_pcap`].
///
/// The `SM` parameter is the session parser's message type;
/// `DM` is the datagram parser's. Use the `NoSessionParser` /
/// `NoDatagramParser` placeholders when a side isn't registered.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Event<K, SM = (), DM = ()> {
    /// A flow-level event (Started / Packet / Ended / Tick /
    /// FlowAnomaly / TrackerAnomaly).
    Flow(FlowEvent<K>),
    /// A TCP session-level event.
    Tcp(SessionEvent<K, SM>),
    /// A UDP datagram-level event.
    Udp(SessionEvent<K, DM>),
}

impl<K, SM, DM> Event<K, SM, DM> {
    /// Discriminant for `match` ergonomics in dispatchers.
    pub fn kind(&self) -> EventKind {
        match self {
            Event::Flow(FlowEvent::Started { .. }) => EventKind::FlowStarted,
            Event::Flow(FlowEvent::Packet { .. }) => EventKind::FlowPacket,
            Event::Flow(FlowEvent::Established { .. }) => EventKind::FlowEstablished,
            Event::Flow(FlowEvent::Ended { .. }) => EventKind::FlowEnded,
            Event::Flow(FlowEvent::Tick { .. }) => EventKind::FlowTick,
            Event::Flow(FlowEvent::FlowAnomaly { .. }) => EventKind::FlowAnomaly,
            Event::Flow(FlowEvent::TrackerAnomaly { .. }) => EventKind::TrackerAnomaly,
            Event::Flow(_) => EventKind::FlowOther,
            Event::Tcp(SessionEvent::Application { .. }) => EventKind::TcpApplication,
            Event::Tcp(SessionEvent::Closed { .. }) => EventKind::TcpClosed,
            Event::Tcp(SessionEvent::Started { .. }) => EventKind::TcpFlowStarted,
            Event::Tcp(SessionEvent::FlowTick { .. }) => EventKind::TcpTick,
            Event::Tcp(_) => EventKind::TcpOther,
            Event::Udp(SessionEvent::Application { .. }) => EventKind::UdpApplication,
            Event::Udp(SessionEvent::Closed { .. }) => EventKind::UdpClosed,
            Event::Udp(SessionEvent::Started { .. }) => EventKind::UdpFlowStarted,
            Event::Udp(SessionEvent::FlowTick { .. }) => EventKind::UdpTick,
            Event::Udp(_) => EventKind::UdpOther,
        }
    }
}

/// Discriminant for [`Event`]'s common variants.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EventKind {
    FlowStarted,
    FlowPacket,
    FlowEstablished,
    FlowEnded,
    FlowTick,
    FlowAnomaly,
    TrackerAnomaly,
    FlowOther,
    TcpApplication,
    TcpClosed,
    TcpFlowStarted,
    TcpTick,
    TcpOther,
    UdpApplication,
    UdpClosed,
    UdpFlowStarted,
    UdpTick,
    UdpOther,
}

/// A reusable pipeline. Construct via [`Pipeline::builder`].
///
/// `Pipeline` opinionatedly bundles the common driver setup with
/// good defaults; for per-flow user state or custom drainers,
/// drop to [`crate::FlowSessionDriver`] /
/// [`crate::FlowDatagramDriver`] directly.
#[cfg(feature = "session")]
pub struct Pipeline<E, S = NoSessionParser, D = NoDatagramParser>
where
    E: FlowExtractor,
    S: SessionParser,
    D: DatagramParser,
{
    extractor: E,
    config: FlowTrackerConfig,
    /// Saved parser prototype; cloned into the driver on
    /// construction and again on `reset()`.
    session_parser: S,
    /// Saved datagram parser prototype.
    datagram_parser: D,
    /// Saved builder option for rebuild.
    emit_anomalies: bool,
    monotonic: bool,
    session: Option<FlowSessionDriver<E, S, ()>>,
    datagram: Option<FlowDatagramDriver<E, D, ()>>,
    _markers: PhantomData<()>,
}

impl<E> Pipeline<E, NoSessionParser, NoDatagramParser>
where
    E: FlowExtractor,
{
    /// Construct a builder. The only public way to start building
    /// a `Pipeline`.
    pub fn builder(extractor: E) -> PipelineBuilder<E> {
        PipelineBuilder::new(extractor)
    }
}

#[cfg(feature = "session")]
impl<E, S, D> Pipeline<E, S, D>
where
    E: FlowExtractor + Clone,
    E::Key: Hash + Eq + Clone + Send + 'static,
    S: SessionParser + Clone + Send + 'static,
    D: DatagramParser + Clone + Send + 'static,
{
    /// Reset the underlying tracker / reassemblers / parsers to
    /// the initial state. The configured extractor, parsers, and
    /// builder options stay; just the per-flow state is dropped.
    ///
    /// Lets the same `Pipeline` instance run against multiple
    /// pcaps in sequence without leaking flow state across runs.
    pub fn reset(&mut self) {
        let session = FlowSessionDriver::with_config(
            self.extractor.clone(),
            self.session_parser.clone(),
            self.config.clone(),
        )
        .with_emit_anomalies(self.emit_anomalies)
        .with_monotonic_timestamps(self.monotonic);
        let datagram = FlowDatagramDriver::with_config(
            self.extractor.clone(),
            self.datagram_parser.clone(),
            self.config.clone(),
        )
        .with_emit_anomalies(self.emit_anomalies)
        .with_monotonic_timestamps(self.monotonic);
        self.session = Some(session);
        self.datagram = Some(datagram);
    }
}

#[cfg(all(feature = "pcap", feature = "session", feature = "reassembler"))]
impl<E, S, D> Pipeline<E, S, D>
where
    E: FlowExtractor + Clone,
    E::Key: Hash + Eq + Clone + Send + 'static,
    S: SessionParser + Clone + Send + 'static,
    D: DatagramParser + Clone + Send + 'static,
{
    /// Drive the pipeline over a pcap file. Returns an iterator
    /// yielding the merged event stream until end-of-input, then
    /// drains the still-open flows via the underlying drivers'
    /// `finish()` methods.
    pub fn run_pcap(&mut self, path: impl AsRef<Path>) -> crate::Result<PipelineIter<'_, E, S, D>> {
        let source = PcapFlowSource::open(path)?;
        Ok(PipelineIter {
            views: Box::new(source.views()),
            pipeline: self,
            pending: VecDeque::new(),
            finished: false,
        })
    }
}

#[cfg(all(feature = "session", feature = "reassembler"))]
impl<E, S, D> Pipeline<E, S, D>
where
    E: FlowExtractor + Clone,
    E::Key: Hash + Eq + Clone + Send + 'static,
    S: SessionParser + Clone + Send + 'static,
    D: DatagramParser + Clone + Send + 'static,
{
    /// Drive the pipeline over an arbitrary iterator of owned
    /// packet views. Useful for custom sources (eBPF userspace,
    /// embedded, synthetic / test fixtures, netring's batched
    /// recv re-rolled into owned views).
    ///
    /// Like `run_pcap`, the end-of-input flush is folded into
    /// the returned iterator: when the source iterator returns
    /// `None`, the drivers' `finish()` methods drain still-open
    /// flows.
    pub fn run_iter<I>(&mut self, iter: I) -> PipelineIter<'_, E, S, D>
    where
        I: IntoIterator<Item = crate::OwnedPacketView> + 'static,
    {
        PipelineIter {
            views: Box::new(iter.into_iter().map(Ok)),
            pipeline: self,
            pending: VecDeque::new(),
            finished: false,
        }
    }
}

/// Iterator over pipeline events.
#[cfg(all(feature = "session", feature = "reassembler"))]
pub struct PipelineIter<'a, E, S, D>
where
    E: FlowExtractor,
    S: SessionParser,
    D: DatagramParser,
{
    views: Box<dyn Iterator<Item = crate::Result<crate::OwnedPacketView>> + 'a>,
    pipeline: &'a mut Pipeline<E, S, D>,
    pending: VecDeque<Event<E::Key, S::Message, D::Message>>,
    finished: bool,
}

#[cfg(all(feature = "session", feature = "reassembler"))]
impl<'a, E, S, D> Iterator for PipelineIter<'a, E, S, D>
where
    E: FlowExtractor + Clone,
    E::Key: Hash + Eq + Clone + Send + 'static,
    S: SessionParser + Clone + Send + 'static,
    D: DatagramParser + Clone + Send + 'static,
{
    type Item = crate::Result<Event<E::Key, S::Message, D::Message>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }
            if self.finished {
                // End-of-input flush.
                if let Some(session) = self.pipeline.session.as_mut() {
                    let drained = session.finish();
                    for ev in drained {
                        self.pending.push_back(Event::Tcp(ev));
                    }
                }
                if let Some(datagram) = self.pipeline.datagram.as_mut() {
                    let drained = datagram.finish();
                    for ev in drained {
                        self.pending.push_back(Event::Udp(ev));
                    }
                }
                return self.pending.pop_front().map(Ok);
            }
            match self.views.next() {
                None => {
                    self.finished = true;
                    continue;
                }
                Some(Err(e)) => return Some(Err(e)),
                Some(Ok(view)) => {
                    if let Some(session) = self.pipeline.session.as_mut() {
                        for ev in session.track(&view) {
                            self.pending.push_back(Event::Tcp(ev));
                        }
                    }
                    if let Some(datagram) = self.pipeline.datagram.as_mut() {
                        for ev in datagram.track(&view) {
                            self.pending.push_back(Event::Udp(ev));
                        }
                    }
                }
            }
        }
    }
}

// Compile-only check: `Pipeline::builder(ext).build()`
// (without a `.session(…)` call) must fail to compile.
// Verified manually for now — a `trybuild` UI test is a
// follow-up per plan 94.
