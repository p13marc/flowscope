//! Slots of the typed [`super::Driver`].
//!
//! A slot is one parser core ([`crate::session::core`]) plus the
//! place its messages go (a [`super::SlotHandle`] queue or a
//! [`super::BroadcastSlotHandle`] fan-out). Slots own **no flow
//! table**: the driver's single engine feeds them, so every slot sees
//! the same flows, the same idle timeouts, the same dedup and the
//! same reassembled bytes as the lifecycle events report.

use std::hash::Hash;
use std::sync::Arc;

use crossbeam_queue::SegQueue;

use super::broadcast::BroadcastInner;
use super::slot::SlotMessage;
use super::typed::Event;
use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowSide, FlowStats};
use crate::extractor::Orientation;
use crate::parser_kind::ParserKind;
use crate::reassembler::StreamChunks;
use crate::session::core::{Ctx, DatagramCore, Output, Ports, SessionCore, Stream};
use crate::session::{DatagramParser, DatagramParserFactory, SessionParser, SessionParserFactory};

/// Where a slot's typed messages go.
pub(super) trait MessageSink<M, K>: Send + Sync + 'static {
    fn push(&self, msg: SlotMessage<M, K>);
}

impl<M: Send + 'static, K: Send + 'static> MessageSink<M, K> for Arc<SegQueue<SlotMessage<M, K>>> {
    fn push(&self, msg: SlotMessage<M, K>) {
        SegQueue::push(self, msg);
    }
}

impl<M, K> MessageSink<M, K> for Arc<BroadcastInner<M, K>>
where
    M: Send + Sync + Clone + 'static,
    K: Send + Sync + Clone + 'static,
{
    fn push(&self, msg: SlotMessage<M, K>) {
        BroadcastInner::push(self, msg);
    }
}

/// Per-call output of a slot: messages to its sink, parser closes
/// and anomalies to the driver's lifecycle buffer.
struct SlotOut<'a, K, Q> {
    sink: &'a Q,
    events: &'a mut Vec<Event<K>>,
}

impl<K, M, Q> Output<K, M> for SlotOut<'_, K, Q>
where
    K: Clone,
    M: std::fmt::Debug,
    Q: MessageSink<M, K>,
{
    fn message(
        &mut self,
        key: &K,
        side: FlowSide,
        orientation: Orientation,
        message: M,
        ts: Timestamp,
        _parser_kind: ParserKind,
    ) {
        crate::obs::trace_session_message(side, &message);
        self.sink.push(SlotMessage::new(
            key.clone(),
            side,
            orientation,
            message,
            ts,
        ));
    }

    fn parser_closed(
        &mut self,
        key: &K,
        parser_kind: ParserKind,
        reason: EndReason,
        detail: Option<String>,
        ts: Timestamp,
        _at_flow_end: bool,
    ) {
        self.events.push(Event::ParserClosed {
            key: key.clone(),
            parser_kind,
            reason,
            detail,
            ts,
        });
    }

    fn parser_side_stopped(
        &mut self,
        key: &K,
        parser_kind: ParserKind,
        side: FlowSide,
        reason: EndReason,
        detail: Option<String>,
        ts: Timestamp,
    ) {
        self.events.push(Event::ParserSideStopped {
            key: key.clone(),
            parser_kind,
            side,
            reason,
            detail,
            ts,
        });
    }

    fn anomaly(&mut self, key: &K, kind: AnomalyKind, ts: Timestamp) {
        crate::obs::record_anomaly(&kind);
        crate::obs::trace_anomaly(&kind);
        self.events.push(Event::FlowAnomaly {
            key: key.clone(),
            kind,
            ts,
        });
    }
}

/// Object-safe view of a slot, for the driver's slot list.
pub(super) trait ErasedSlot<K>: Send + Sync {
    fn needs_ports(&self) -> bool;
    fn wants_stream(&self, ports: Ports) -> bool;
    fn wants_datagram(&self, ports: Ports, l4: Option<crate::L4Proto>) -> bool;
    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &Stream<'_>,
        events: &mut Vec<Event<K>>,
    );
    /// Per side: `true` when this slot will never use that side's
    /// stream again.
    fn streams_done(&self, key: &K, ports: Ports) -> [bool; 2];
    fn on_datagram(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        payload: &[u8],
        events: &mut Vec<Event<K>>,
    );
    #[allow(clippy::too_many_arguments)]
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        anomalies: bool,
        events: &mut Vec<Event<K>>,
    );
    fn on_tick(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        events: &mut Vec<Event<K>>,
    );
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool);
}

/// A session-parser slot.
pub(super) struct SessionSlot<K, F, Q>
where
    F: SessionParserFactory<K>,
{
    pub(super) core: SessionCore<K, F>,
    pub(super) sink: Q,
}

impl<K, F, Q> ErasedSlot<K> for SessionSlot<K, F, Q>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    F: SessionParserFactory<K> + Sync,
    F::Parser: Sync,
    <F::Parser as SessionParser>::Message: Sync,
    Q: MessageSink<<F::Parser as SessionParser>::Message, K>,
{
    fn needs_ports(&self) -> bool {
        self.core.selector().needs_ports()
    }
    fn wants_stream(&self, ports: Ports) -> bool {
        self.core.wants(ports)
    }
    fn wants_datagram(&self, _ports: Ports, _l4: Option<crate::L4Proto>) -> bool {
        false
    }
    fn on_stream(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &Stream<'_>,
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core.on_stream(cx, ports, chunks, &mut out);
    }
    fn streams_done(&self, key: &K, ports: Ports) -> [bool; 2] {
        self.core.streams_done(key, ports)
    }
    fn on_datagram(
        &mut self,
        _cx: &Ctx<'_, K>,
        _ports: Ports,
        _payload: &[u8],
        _events: &mut Vec<Event<K>>,
    ) {
    }
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        anomalies: bool,
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core
            .on_flow_end(key, reason, stats, finals, anomalies, &mut out);
    }
    fn on_tick(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core
            .on_tick(now, stamp, orientation_of, anomalies, &mut out);
    }
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        self.core.retain(alive);
    }
}

/// A datagram-parser slot.
pub(super) struct DatagramSlot<K, F, Q>
where
    F: DatagramParserFactory<K>,
{
    pub(super) core: DatagramCore<K, F>,
    pub(super) sink: Q,
}

impl<K, F, Q> ErasedSlot<K> for DatagramSlot<K, F, Q>
where
    K: Hash + Eq + Clone + Send + Sync + 'static,
    F: DatagramParserFactory<K> + Sync,
    F::Parser: Sync,
    <F::Parser as DatagramParser>::Message: Sync,
    Q: MessageSink<<F::Parser as DatagramParser>::Message, K>,
{
    fn needs_ports(&self) -> bool {
        self.core.selector().needs_ports()
    }
    fn wants_stream(&self, _ports: Ports) -> bool {
        false
    }
    fn wants_datagram(&self, ports: Ports, l4: Option<crate::L4Proto>) -> bool {
        self.core.wants(ports, l4)
    }
    fn on_stream(
        &mut self,
        _cx: &Ctx<'_, K>,
        _ports: Ports,
        _chunks: &Stream<'_>,
        _events: &mut Vec<Event<K>>,
    ) {
    }
    fn streams_done(&self, _key: &K, _ports: Ports) -> [bool; 2] {
        [true, true]
    }
    fn on_datagram(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        payload: &[u8],
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core.on_datagram(cx, ports, payload, &mut out);
    }
    fn on_flow_end(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        _finals: [&StreamChunks; 2],
        _anomalies: bool,
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core.on_flow_end(key, reason, stats, &mut out);
    }
    fn on_tick(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        events: &mut Vec<Event<K>>,
    ) {
        let mut out = SlotOut {
            sink: &self.sink,
            events,
        };
        self.core
            .on_tick(now, stamp, orientation_of, anomalies, &mut out);
    }
    fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        self.core.retain(alive);
    }
}
