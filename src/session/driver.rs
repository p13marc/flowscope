//! [`SessionDriver`] / [`DatagramDriver`] — one parser type over a
//! capture, with an ordered [`SessionEvent`] output.

use std::hash::Hash;
use std::time::Duration;

use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};
use crate::extractor::{FlowExtractor, L4Proto, Orientation, TcpInfo};
use crate::flow_driver::FlowDriver;
use crate::parser_kind::ParserKind;
use crate::reassembler::StreamChunks;
use crate::segment_reassembler::SegmentBufferReassemblerFactory;
use crate::session::core::{Ctx, DatagramCore, Output, Ports, Selector, SessionCore};
use crate::session::engine::{Dispatch, Engine};
use crate::session::{
    DatagramParser, DatagramParserFactory, SessionEvent, SessionParser, SessionParserFactory,
};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;

impl<K: Clone, M: std::fmt::Debug> Output<K, M> for Vec<SessionEvent<K, M>> {
    fn message(
        &mut self,
        key: &K,
        side: FlowSide,
        orientation: Orientation,
        message: M,
        ts: Timestamp,
        parser_kind: ParserKind,
    ) {
        crate::obs::trace_session_message(side, &message);
        self.push(SessionEvent::Application {
            key: key.clone(),
            side,
            orientation,
            message,
            ts,
            parser_kind,
        });
    }

    fn parser_closed(
        &mut self,
        key: &K,
        parser_kind: ParserKind,
        reason: EndReason,
        detail: Option<String>,
        ts: Timestamp,
        at_flow_end: bool,
    ) {
        // A close that is just the flow ending is `Closed`'s job.
        if !at_flow_end {
            self.push(SessionEvent::ParserClosed {
                key: key.clone(),
                parser_kind,
                reason,
                detail,
                ts,
            });
        }
    }

    fn anomaly(&mut self, key: &K, kind: AnomalyKind, ts: Timestamp) {
        crate::obs::record_anomaly(&kind);
        crate::obs::trace_anomaly(&kind);
        self.push(SessionEvent::FlowAnomaly {
            key: key.clone(),
            kind,
            ts,
        });
    }
}

/// Translate a flow-driver event into the session vocabulary.
fn lifecycle<K, M>(ev: FlowEvent<K>, out: &mut Vec<SessionEvent<K, M>>) {
    out.push(match ev {
        FlowEvent::Started {
            key,
            side,
            orientation,
            ts,
            l4,
        } => SessionEvent::Started {
            key,
            side,
            orientation,
            ts,
            l4,
        },
        FlowEvent::Ended {
            key,
            reason,
            stats,
            l4,
            ..
        } => {
            let ts = stats.last_seen;
            SessionEvent::Closed {
                key,
                reason,
                stats,
                l4,
                ts,
            }
        }
        FlowEvent::FlowAnomaly { key, kind, ts } => SessionEvent::FlowAnomaly { key, kind, ts },
        FlowEvent::TrackerAnomaly { kind, ts } => SessionEvent::TrackerAnomaly { kind, ts },
        FlowEvent::Tick { key, stats, ts } => SessionEvent::Tick { key, stats, ts },
        FlowEvent::Packet { .. }
        | FlowEvent::Established { .. }
        | FlowEvent::StateChange { .. } => {
            return;
        }
    });
}

impl<K, F> Dispatch<K> for SessionCore<K, F>
where
    K: Hash + Eq + Clone,
    F: SessionParserFactory<K>,
{
    type Out = Vec<SessionEvent<K, <F::Parser as SessionParser>::Message>>;

    fn needs_ports(&self) -> bool {
        self.selector().needs_ports()
    }
    fn wants_stream(&self, ports: Ports) -> bool {
        self.wants(ports)
    }
    fn wants_datagram(&self, _ports: Ports) -> bool {
        false
    }
    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &StreamChunks,
        out: &mut Self::Out,
    ) {
        SessionCore::on_stream(self, cx, ports, chunks, out);
    }
    fn stream_done(&self, key: &K, ports: Ports) -> bool {
        SessionCore::stream_done(self, key, ports)
    }
    fn on_datagram(
        &mut self,
        _cx: &Ctx<'_, K>,
        _ports: Ports,
        _payload: &[u8],
        _out: &mut Self::Out,
    ) {
    }
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        anomalies: bool,
        out: &mut Self::Out,
    ) {
        SessionCore::on_flow_end(self, key, reason, stats, finals, anomalies, out);
    }
    fn on_tick(
        &mut self,
        now: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut Self::Out,
    ) {
        SessionCore::on_tick(self, now, orientation_of, anomalies, out);
    }
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        SessionCore::retain(self, alive);
    }
    fn lifecycle(&mut self, ev: FlowEvent<K>, _tcp: Option<TcpInfo>, out: &mut Self::Out) {
        lifecycle(ev, out);
    }
}

impl<K, F> Dispatch<K> for DatagramCore<K, F>
where
    K: Hash + Eq + Clone,
    F: DatagramParserFactory<K>,
{
    type Out = Vec<SessionEvent<K, <F::Parser as DatagramParser>::Message>>;

    fn needs_ports(&self) -> bool {
        self.selector().needs_ports()
    }
    fn wants_stream(&self, _ports: Ports) -> bool {
        false
    }
    fn wants_datagram(&self, ports: Ports) -> bool {
        self.wants(ports)
    }
    fn on_stream(
        &mut self,
        _cx: &Ctx<'_, K>,
        _ports: Ports,
        _chunks: &StreamChunks,
        _out: &mut Self::Out,
    ) {
    }
    fn stream_done(&self, _key: &K, _ports: Ports) -> bool {
        true
    }
    fn on_datagram(&mut self, cx: &Ctx<'_, K>, ports: Ports, payload: &[u8], out: &mut Self::Out) {
        DatagramCore::on_datagram(self, cx, ports, payload, out);
    }
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        _finals: [&StreamChunks; 2],
        _anomalies: bool,
        out: &mut Self::Out,
    ) {
        DatagramCore::on_flow_end(self, key, reason, stats, out);
    }
    fn on_tick(
        &mut self,
        now: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut Self::Out,
    ) {
        DatagramCore::on_tick(self, now, orientation_of, anomalies, out);
    }
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        DatagramCore::retain(self, alive);
    }
    fn lifecycle(&mut self, ev: FlowEvent<K>, _tcp: Option<TcpInfo>, out: &mut Self::Out) {
        lifecycle(ev, out);
    }
}

macro_rules! shared_driver_api {
    () => {
        /// Emit [`SessionEvent::FlowAnomaly`] / [`SessionEvent::TrackerAnomaly`]
        /// (reassembly gaps, overflows, retransmits, parser poison,
        /// eviction pressure, …). Default: off.
        pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
            self.engine.flow.set_emit_anomalies(enable);
            self
        }

        /// In-place variant of [`Self::with_emit_anomalies`].
        pub fn set_emit_anomalies(&mut self, enable: bool) {
            self.engine.flow.set_emit_anomalies(enable);
        }

        /// Drop duplicate packets (content hash) before tracking — see
        /// [`crate::Dedup`]. Applies to the flow table and to the
        /// parser alike.
        pub fn with_dedup(mut self, dedup: crate::Dedup) -> Self {
            self.engine.flow.set_dedup(Some(dedup));
            self
        }

        /// In-place variant of [`Self::with_dedup`]; `None` removes it.
        pub fn set_dedup(&mut self, dedup: Option<crate::Dedup>) {
            self.engine.flow.set_dedup(dedup);
        }

        /// Clamp packet timestamps (and sweep times) to a running max
        /// so time never goes backwards. Default: off.
        pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
            self.engine.flow.set_monotonic_timestamps(enable);
            self
        }

        /// In-place variant of [`Self::with_monotonic_timestamps`].
        pub fn set_monotonic_timestamps(&mut self, enable: bool) {
            self.engine.flow.set_monotonic_timestamps(enable);
        }

        /// Per-flow idle-timeout override (see
        /// [`FlowTracker::set_idle_timeout_fn`]). The parser's life is
        /// bound to the flow's, so this also decides when parser state
        /// is reset.
        pub fn with_idle_timeout_fn<G>(mut self, f: G) -> Self
        where
            G: Fn(&E::Key, Option<L4Proto>) -> Option<Duration> + Send + Sync + 'static,
        {
            self.engine.flow.tracker_mut().set_idle_timeout_fn(f);
            self
        }

        /// Replace the config (tracker and reassembly limits alike).
        pub fn set_config(&mut self, config: FlowTrackerConfig) {
            self.engine.flow.set_config(config);
        }

        /// Current config.
        pub fn config(&self) -> &FlowTrackerConfig {
            self.engine.flow.tracker().config()
        }

        /// Borrow the flow table.
        pub fn tracker(&self) -> &FlowTracker<E, ()> {
            self.engine.flow.tracker()
        }

        /// Borrow the flow table mutably. Use [`Self::set_config`]
        /// rather than `tracker_mut().set_config(..)` so reassembly
        /// limits follow.
        pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, ()> {
            self.engine.flow.tracker_mut()
        }

        /// Borrow the underlying flow driver (reassembly state, memcap
        /// accounting).
        pub fn flow_driver(&self) -> &FlowDriver<E, SegmentBufferReassemblerFactory, ()> {
            &self.engine.flow
        }

        /// Live `(key, stats)` of every tracked flow, reassembly
        /// diagnostics included.
        pub fn snapshot_flow_stats(&self) -> impl Iterator<Item = (E::Key, FlowStats)> + '_ {
            self.engine.flow.snapshot_flow_stats()
        }

        /// Live stats of one flow, reassembly diagnostics included.
        pub fn flow_stats(&self, key: &E::Key) -> Option<FlowStats> {
            self.engine.flow.flow_stats(key)
        }

        /// Track one packet, appending the resulting events to `out`.
        pub fn track_into<'v>(
            &mut self,
            view: impl Into<PacketView<'v>>,
            out: &mut Vec<SessionEvent<E::Key, M>>,
        ) {
            self.engine.track(view, &mut self.core, out);
        }

        /// Track one packet and return the resulting events.
        pub fn track<'v>(
            &mut self,
            view: impl Into<PacketView<'v>>,
        ) -> Vec<SessionEvent<E::Key, M>> {
            let mut out = Vec::new();
            self.track_into(view, &mut out);
            out
        }

        /// Run the periodic hooks (`on_tick`, out-of-order hole
        /// deadlines) and end idle flows.
        pub fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<SessionEvent<E::Key, M>>) {
            self.engine.sweep(now, &mut self.core, out);
        }

        /// [`Self::sweep_into`] returning a fresh `Vec`.
        pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, M>> {
            let mut out = Vec::new();
            self.sweep_into(now, &mut out);
            out
        }

        /// End of input: end every flow (`sweep(Timestamp::MAX)`).
        pub fn finish_into(&mut self, out: &mut Vec<SessionEvent<E::Key, M>>) {
            self.sweep_into(Timestamp::MAX, out);
        }

        /// [`Self::finish_into`] returning a fresh `Vec`.
        pub fn finish(&mut self) -> Vec<SessionEvent<E::Key, M>> {
            self.sweep(Timestamp::MAX)
        }

        /// End one flow now ([`EndReason::ForceClosed`]): its last
        /// bytes reach the parser, which is flushed (`fin_*`) before
        /// the `Closed`. No-op for an unknown key.
        pub fn force_close_into(
            &mut self,
            key: &E::Key,
            now: Timestamp,
            out: &mut Vec<SessionEvent<E::Key, M>>,
        ) {
            self.engine.force_close(key, now, &mut self.core, out);
        }

        /// [`Self::force_close_into`] returning a fresh `Vec`.
        pub fn force_close(
            &mut self,
            key: &E::Key,
            now: Timestamp,
        ) -> Vec<SessionEvent<E::Key, M>> {
            let mut out = Vec::new();
            self.force_close_into(key, now, &mut out);
            out
        }
    };
}

/// One [`SessionParser`] type over a TCP capture: flow tracking,
/// reassembly (out-of-order hole fill, gaps, limits) and per-flow
/// parser dispatch, with an ordered [`SessionEvent`] output.
///
/// ```
/// use flowscope::extract::FiveTuple;
/// use flowscope::session::{SessionDriver, SessionEvent};
/// # use flowscope::{SessionParser, Timestamp};
/// # #[derive(Default, Clone)]
/// # struct Lines;
/// # impl SessionParser for Lines {
/// #     type Message = ();
/// #     fn feed_initiator(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
/// #     fn feed_responder(&mut self, _: &[u8], _: Timestamp, _: &mut Vec<()>) {}
/// # }
/// let mut driver = SessionDriver::new(FiveTuple::bidirectional(), Lines).with_emit_anomalies(true);
/// # let frames: Vec<flowscope::PacketView<'static>> = Vec::new();
/// for view in frames {
///     for ev in driver.track(view) {
///         match ev {
///             SessionEvent::Application { key, message, .. } => { let _ = (key, message); }
///             SessionEvent::ParserClosed { reason, detail, .. } => { let _ = (reason, detail); }
///             _ => {}
///         }
///     }
/// }
/// let _tail = driver.finish();
/// ```
///
/// For a parser that is `Clone` but not `Default`, pass it wrapped in
/// [`crate::session::TemplateFactory`].
pub struct SessionDriver<E, F>
where
    E: FlowExtractor,
    F: SessionParserFactory<E::Key>,
{
    engine: Engine<E>,
    core: SessionCore<E::Key, F>,
}

impl<E, F, M> SessionDriver<E, F>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone,
    F: SessionParserFactory<E::Key>,
    F::Parser: SessionParser<Message = M>,
{
    /// Default config.
    pub fn new(extractor: E, factory: F) -> Self {
        Self::with_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Explicit config (flow table and reassembly limits).
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self::from_tracker(FlowTracker::with_config(extractor, config), factory)
    }

    /// Take over an existing flow table — its config, idle-timeout
    /// predicate and live flows.
    pub fn from_tracker(tracker: FlowTracker<E, ()>, factory: F) -> Self {
        Self {
            engine: Engine::from_tracker(tracker),
            core: SessionCore::new(factory, Selector::All),
        }
    }

    shared_driver_api!();
}

/// One [`DatagramParser`] type over a UDP capture, with an ordered
/// [`SessionEvent`] output. The datagram sibling of
/// [`SessionDriver`]; no reassembly is involved.
pub struct DatagramDriver<E, F>
where
    E: FlowExtractor,
    F: DatagramParserFactory<E::Key>,
{
    engine: Engine<E>,
    core: DatagramCore<E::Key, F>,
}

impl<E, F, M> DatagramDriver<E, F>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone,
    F: DatagramParserFactory<E::Key>,
    F::Parser: DatagramParser<Message = M>,
{
    /// Default config.
    pub fn new(extractor: E, factory: F) -> Self {
        Self::with_config(extractor, factory, FlowTrackerConfig::default())
    }

    /// Explicit config.
    pub fn with_config(extractor: E, factory: F, config: FlowTrackerConfig) -> Self {
        Self::from_tracker(FlowTracker::with_config(extractor, config), factory)
    }

    /// Take over an existing flow table.
    pub fn from_tracker(tracker: FlowTracker<E, ()>, factory: F) -> Self {
        Self {
            engine: Engine::from_tracker(tracker),
            core: DatagramCore::new(factory, Selector::All),
        }
    }

    shared_driver_api!();
}
