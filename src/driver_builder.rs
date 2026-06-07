//! Driver builders — discoverable construction surface for the
//! three sync drivers.
//!
//! Existing free-function constructors (`Driver::new(...)`,
//! `Driver::with_factory(...)`, etc.) stay; this module adds an
//! orthogonal `Driver::builder(extractor)` entry point that
//! chains the configuration. Both styles work.
//!
//! ```no_run
//! use flowscope::extract::FiveTuple;
//! use flowscope::FlowSessionDriver;
//!
//! #[derive(Default, Clone)]
//! struct EchoParser;
//! impl flowscope::SessionParser for EchoParser {
//!     type Message = ();
//!     fn feed_initiator(&mut self, _b: &[u8], _ts: flowscope::Timestamp) -> Vec<()> { vec![] }
//!     fn feed_responder(&mut self, _b: &[u8], _ts: flowscope::Timestamp) -> Vec<()> { vec![] }
//! }
//!
//! let _driver = FlowSessionDriver::<_, EchoParser, ()>::builder(FiveTuple::bidirectional())
//!     .parser(EchoParser)
//!     .emit_anomalies(true)
//!     .build();
//! ```
//!
//! For per-flow user state `S` or per-flow parser factories,
//! use the existing constructors:
//!
//! - `FlowSessionDriver::with_state_init(ext, parser, init_fn)`
//! - `FlowSessionDriver::with_factory(ext, factory)`
//! - `FlowSessionDriver::with_factory_and_config(ext, factory, config)`
//!
//! The plan-94 Tier 2 spec calls for collapsing all 38 driver
//! constructors into one builder; that consolidation is
//! deferred — this Tier 2 cut ships the most-discoverable
//! `.builder()` entry point alongside the existing
//! constructors, both to demonstrate the shape and to give
//! consumers a path to migrate at their own pace.

use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;
use crate::extractor::FlowExtractor;
use crate::session::{DatagramParser, SessionParser};
use crate::tracker::FlowTrackerConfig;

/// Boxed per-key idle-timeout predicate. Aliased to keep the
/// builder field shape readable.
type IdleTimeoutFn<K> =
    Box<dyn Fn(&K, Option<crate::L4Proto>) -> Option<Duration> + Send + 'static>;

#[cfg(feature = "session")]
use crate::session_driver::FlowSessionDriver;

#[cfg(all(feature = "extractors", feature = "session"))]
use crate::datagram_driver::FlowDatagramDriver;

/// Builder for [`FlowSessionDriver`].
///
/// Construct via [`FlowSessionDriver::builder`] (in this
/// module's `impl` block). Chainable axes mirror the existing
/// `with_*` constructors but with a single discoverable entry
/// point.
#[cfg(feature = "session")]
pub struct FlowSessionDriverBuilder<E, P>
where
    E: FlowExtractor,
    P: SessionParser + Clone,
{
    extractor: E,
    parser: Option<P>,
    config: FlowTrackerConfig,
    emit_anomalies: bool,
    monotonic_timestamps: bool,
    dedup: Option<crate::dedup::Dedup>,
    idle_timeout_fn: Option<IdleTimeoutFn<E::Key>>,
}

#[cfg(feature = "session")]
impl<E, P> FlowSessionDriverBuilder<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
{
    /// Internal — public entry point is `FlowSessionDriver::builder`.
    pub(crate) fn new(extractor: E) -> Self {
        Self {
            extractor,
            parser: None,
            config: FlowTrackerConfig::default(),
            emit_anomalies: false,
            monotonic_timestamps: false,
            dedup: None,
            idle_timeout_fn: None,
        }
    }

    /// Register the parser. Required — `build()` panics if no
    /// parser has been set.
    pub fn parser(mut self, parser: P) -> Self {
        self.parser = Some(parser);
        self
    }

    /// Override the tracker config.
    pub fn config(mut self, config: FlowTrackerConfig) -> Self {
        self.config = config;
        self
    }

    /// Emit `FlowAnomaly` / `TrackerAnomaly` events inline.
    pub fn emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    /// Assume strictly non-decreasing timestamps.
    pub fn monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_timestamps = enable;
        self
    }

    /// Filter incoming views through a content-hash dedup.
    pub fn dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Set a per-key idle-timeout override.
    pub fn idle_timeout_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&E::Key, Option<crate::L4Proto>) -> Option<Duration> + Send + 'static,
    {
        self.idle_timeout_fn = Some(Box::new(f));
        self
    }

    /// Materialise the driver.
    ///
    /// # Panics
    ///
    /// Panics if no parser was set via [`Self::parser`].
    pub fn build(self) -> FlowSessionDriver<E, P, ()> {
        let parser = self.parser.expect("FlowSessionDriverBuilder: parser not set");
        let mut driver = FlowSessionDriver::with_config(self.extractor, parser, self.config)
            .with_emit_anomalies(self.emit_anomalies)
            .with_monotonic_timestamps(self.monotonic_timestamps);
        if let Some(dedup) = self.dedup {
            driver = driver.with_dedup(dedup);
        }
        if let Some(f) = self.idle_timeout_fn {
            driver = driver.with_idle_timeout_fn(move |k, l4| f(k, l4));
        }
        driver
    }
}

#[cfg(feature = "session")]
impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Clone + Send + 'static,
    S: Send + 'static,
{
    /// Construct a builder. Single discoverable entry point that
    /// chains tracker / parser / behaviour configuration.
    ///
    /// For per-flow user state `S` or per-flow parser factories,
    /// use the existing constructors
    /// ([`Self::with_state_init`] / [`Self::with_factory`]).
    pub fn builder(extractor: E) -> FlowSessionDriverBuilder<E, P> {
        FlowSessionDriverBuilder::new(extractor)
    }
}

// ─── FlowDatagramDriver builder ────────────────────────────────

/// Builder for [`FlowDatagramDriver`].
#[cfg(all(feature = "extractors", feature = "session"))]
pub struct FlowDatagramDriverBuilder<E, P>
where
    E: FlowExtractor,
    P: DatagramParser + Clone,
{
    extractor: E,
    parser: Option<P>,
    config: FlowTrackerConfig,
    emit_anomalies: bool,
    monotonic_timestamps: bool,
    dedup: Option<crate::dedup::Dedup>,
}

#[cfg(all(feature = "extractors", feature = "session"))]
impl<E, P> FlowDatagramDriverBuilder<E, P>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
{
    pub(crate) fn new(extractor: E) -> Self {
        Self {
            extractor,
            parser: None,
            config: FlowTrackerConfig::default(),
            emit_anomalies: false,
            monotonic_timestamps: false,
            dedup: None,
        }
    }

    pub fn parser(mut self, parser: P) -> Self {
        self.parser = Some(parser);
        self
    }

    pub fn config(mut self, config: FlowTrackerConfig) -> Self {
        self.config = config;
        self
    }

    pub fn emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    pub fn monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_timestamps = enable;
        self
    }

    pub fn dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    pub fn build(self) -> FlowDatagramDriver<E, P, ()> {
        let parser = self.parser.expect("FlowDatagramDriverBuilder: parser not set");
        let mut driver = FlowDatagramDriver::with_config(self.extractor, parser, self.config)
            .with_emit_anomalies(self.emit_anomalies)
            .with_monotonic_timestamps(self.monotonic_timestamps);
        if let Some(dedup) = self.dedup {
            driver = driver.with_dedup(dedup);
        }
        driver
    }
}

#[cfg(all(feature = "extractors", feature = "session"))]
impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Clone + Send + 'static,
    S: Send + 'static,
{
    /// Construct a builder for the datagram driver.
    pub fn builder(extractor: E) -> FlowDatagramDriverBuilder<E, P> {
        FlowDatagramDriverBuilder::new(extractor)
    }
}

// Quiet unused-import warnings when one of the feature combos is off.
#[allow(unused_imports)]
use Timestamp as _UseTimestamp;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::extract::FiveTuple;

    #[derive(Default, Clone)]
    struct NoopParser;

    impl SessionParser for NoopParser {
        type Message = ();
        fn feed_initiator(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
            Vec::new()
        }
        fn feed_responder(&mut self, _b: &[u8], _ts: Timestamp) -> Vec<()> {
            Vec::new()
        }
    }

    #[derive(Default, Clone)]
    struct NoopDatagram;

    impl DatagramParser for NoopDatagram {
        type Message = ();
        fn parse(
            &mut self,
            _b: &[u8],
            _side: crate::event::FlowSide,
            _ts: Timestamp,
        ) -> Vec<()> {
            Vec::new()
        }
    }

    #[test]
    #[cfg(feature = "session")]
    fn session_builder_yields_working_driver() {
        let _d = FlowSessionDriver::<_, NoopParser, ()>::builder(FiveTuple::bidirectional())
            .parser(NoopParser)
            .emit_anomalies(true)
            .monotonic_timestamps(true)
            .build();
    }

    #[test]
    #[cfg(all(feature = "extractors", feature = "session"))]
    fn datagram_builder_yields_working_driver() {
        let _d = FlowDatagramDriver::<_, NoopDatagram, ()>::builder(FiveTuple::bidirectional())
            .parser(NoopDatagram)
            .emit_anomalies(true)
            .build();
    }

    #[test]
    #[cfg(feature = "session")]
    #[should_panic(expected = "parser not set")]
    fn missing_parser_panics_on_build() {
        let _ = FlowSessionDriver::<_, NoopParser, ()>::builder(FiveTuple::bidirectional()).build();
    }
}
