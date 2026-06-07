//! [`Pipeline<E, M>`] — high-level wrapper around the unified
//! [`super::Driver`].
//!
//! Mirrors the 0.9 `flowscope::Pipeline` shape, but the event
//! stream is the unified [`super::Event<K, M>`] rather than the
//! legacy `Pipeline::Event<K, SM, DM>`. Users register parsers
//! via the same `session_*` / `datagram_*` chainable methods as
//! [`super::DriverBuilder`].
//!
//! ```ignore
//! use flowscope::driver_unified::{Event, Pipeline};
//! use flowscope::extract::FiveTuple;
//! use flowscope::http::{HttpMessage, HttpParser};
//!
//! let mut pipeline = Pipeline::<_, HttpMessage>::builder(FiveTuple::bidirectional())
//!     .session_broadcast(HttpParser::default(), |m| m)
//!     .build();
//!
//! for event in pipeline.run_pcap("trace.pcap")? {
//!     if let Event::Message { message, .. } = event? {
//!         println!("{message:?}");
//!     }
//! }
//! ```

use std::collections::VecDeque;
use std::hash::Hash;
#[cfg(feature = "pcap")]
use std::path::Path;

use crate::OwnedPacketView;
use crate::extractor::FlowExtractor;
#[cfg(feature = "pcap")]
use crate::pcap::PcapFlowSource;
use crate::session::{DatagramParser, SessionParser};
use crate::tracker::FlowTrackerConfig;

use super::{Driver, DriverBuilder, Event};

/// Source-wrapped high-level entry point around [`Driver`].
///
/// Holds the configured driver plus parser/extractor metadata so
/// [`Self::reset`] can rebuild the driver between runs without
/// the caller re-registering parsers.
pub struct Pipeline<E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    driver: Driver<E, M>,
    /// Closure capturing the parser registrations so `reset()` can
    /// rebuild a fresh `Driver` from the same set.
    rebuild: Box<dyn Fn() -> Driver<E, M> + 'static>,
}

impl<E, M> Pipeline<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Construct a [`PipelineBuilder`] for the given extractor.
    pub fn builder(extractor: E) -> PipelineBuilder<E, M> {
        PipelineBuilder {
            extractor,
            config: FlowTrackerConfig::default(),
            register: Vec::new(),
        }
    }

    /// Reset the driver to its initial state. Existing flow /
    /// parser state is dropped; the registered parsers + tracker
    /// config are rebuilt.
    pub fn reset(&mut self) {
        self.driver = (self.rebuild)();
    }

    /// Borrow the underlying driver for direct access.
    pub fn driver(&self) -> &Driver<E, M> {
        &self.driver
    }

    /// Mutable borrow of the underlying driver.
    pub fn driver_mut(&mut self) -> &mut Driver<E, M> {
        &mut self.driver
    }

    /// Drive the pipeline over a pcap file. Returns an iterator
    /// yielding the merged event stream until end-of-input, then
    /// drains live flows via the driver's `finish()`.
    #[cfg(feature = "pcap")]
    pub fn run_pcap(
        &mut self,
        path: impl AsRef<Path>,
    ) -> crate::Result<PipelineIter<'_, E, M>> {
        let source = PcapFlowSource::open(path)?;
        Ok(PipelineIter {
            views: Box::new(source.views()),
            driver: &mut self.driver,
            pending: VecDeque::new(),
            finished: false,
        })
    }

    /// Drive the pipeline over an arbitrary iterator of owned
    /// packet views.
    pub fn run_iter<I>(&mut self, iter: I) -> PipelineIter<'_, E, M>
    where
        I: IntoIterator<Item = OwnedPacketView> + 'static,
    {
        PipelineIter {
            views: Box::new(iter.into_iter().map(Ok)),
            driver: &mut self.driver,
            pending: VecDeque::new(),
            finished: false,
        }
    }
}

/// Builder for [`Pipeline<E, M>`].
///
/// Proxies the parser-registration chain into the eventual
/// `Driver` build; `reset()` replays the same chain to get a
/// fresh driver. The boxed closures store the parser + lift +
/// routing for replay.
type RegisterStep<E, M> =
    Box<dyn Fn(DriverBuilder<E, M>) -> DriverBuilder<E, M> + 'static>;

pub struct PipelineBuilder<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    extractor: E,
    config: FlowTrackerConfig,
    register: Vec<RegisterStep<E, M>>,
}

impl<E, M> PipelineBuilder<E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    /// Override the tracker config.
    pub fn config(mut self, c: FlowTrackerConfig) -> Self {
        self.config = c;
        self
    }

    /// Proxy of [`DriverBuilder::session_on_ports`].
    pub fn session_on_ports<P, I, F>(mut self, parser: P, ports: I, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        I: IntoIterator<Item = u16> + Clone + 'static,
        F: Fn(P::Message) -> M + Clone + Send + 'static,
    {
        self.register.push(Box::new(move |b| {
            b.session_on_ports(parser.clone(), ports.clone(), lift.clone())
        }));
        self
    }

    /// Proxy of [`DriverBuilder::session_broadcast`].
    pub fn session_broadcast<P, F>(mut self, parser: P, lift: F) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        P::Message: Send + 'static,
        F: Fn(P::Message) -> M + Clone + Send + 'static,
    {
        self.register.push(Box::new(move |b| {
            b.session_broadcast(parser.clone(), lift.clone())
        }));
        self
    }

    /// Proxy of [`DriverBuilder::datagram_on_ports`].
    pub fn datagram_on_ports<D, I, F>(mut self, parser: D, ports: I, lift: F) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        I: IntoIterator<Item = u16> + Clone + 'static,
        F: Fn(D::Message) -> M + Clone + Send + 'static,
    {
        self.register.push(Box::new(move |b| {
            b.datagram_on_ports(parser.clone(), ports.clone(), lift.clone())
        }));
        self
    }

    /// Proxy of [`DriverBuilder::datagram_broadcast`].
    pub fn datagram_broadcast<D, F>(mut self, parser: D, lift: F) -> Self
    where
        D: DatagramParser + Clone + Send + 'static,
        D::Message: Send + 'static,
        F: Fn(D::Message) -> M + Clone + Send + 'static,
    {
        self.register.push(Box::new(move |b| {
            b.datagram_broadcast(parser.clone(), lift.clone())
        }));
        self
    }

    /// Materialise the pipeline.
    pub fn build(self) -> Pipeline<E, M> {
        let extractor = self.extractor;
        let config = self.config;
        let register: std::rc::Rc<[RegisterStep<E, M>]> =
            self.register.into_iter().collect::<Vec<_>>().into();

        let rebuild_extractor = extractor.clone();
        let rebuild_config = config.clone();
        let rebuild_register = register.clone();
        let rebuild: Box<dyn Fn() -> Driver<E, M> + 'static> = Box::new(move || {
            let mut b: DriverBuilder<E, M> =
                Driver::builder(rebuild_extractor.clone()).config(rebuild_config.clone());
            for step in rebuild_register.iter() {
                b = step(b);
            }
            b.build()
        });

        let driver = rebuild();
        Pipeline { driver, rebuild }
    }
}

/// Iterator over [`Pipeline`]'s merged event stream.
pub struct PipelineIter<'a, E, M>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    views: Box<dyn Iterator<Item = crate::Result<OwnedPacketView>> + 'a>,
    driver: &'a mut Driver<E, M>,
    pending: VecDeque<Event<E::Key, M>>,
    finished: bool,
}

impl<'a, E, M> Iterator for PipelineIter<'a, E, M>
where
    E: FlowExtractor + Clone + Send + 'static,
    E::Key: Hash + Eq + Clone + Send + 'static,
    M: Send + 'static,
{
    type Item = crate::Result<Event<E::Key, M>>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(ev) = self.pending.pop_front() {
                return Some(Ok(ev));
            }
            if self.finished {
                for ev in self.driver.finish() {
                    self.pending.push_back(ev);
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
                    for ev in self.driver.track(&view) {
                        self.pending.push_back(ev);
                    }
                }
            }
        }
    }
}
