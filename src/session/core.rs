//! Per-parser dispatch shared by [`super::SessionDriver`],
//! [`super::DatagramDriver`] and every slot of the typed
//! [`crate::driver::Driver`].
//!
//! A *core* owns one parser type's per-flow state and turns
//! reassembled stream chunks (or datagrams) into messages and parser
//! closes. It owns no flow table: the engine
//! ([`super::engine::Engine`]) feeds it from one shared
//! [`crate::FlowDriver`], which is what keeps every consumer's notion
//! of "a flow" identical.
//!
//! Per-flow parser state is `Probing → Active → Closed`. `Closed` is
//! a tombstone kept until the flow's transport end, so a poisoned /
//! done / gap-stopped parser is never re-created mid-flow.

use std::collections::HashMap;
use std::hash::Hash;

use ahash::RandomState;
use smallvec::SmallVec;

use crate::Timestamp;
use crate::detect::signatures::{SignatureFn, SignatureMatch};
use crate::event::{AnomalyKind, EndReason, FlowSide, FlowStats};
use crate::extractor::Orientation;
use crate::parser_kind::ParserKind;
use crate::reassembler::{Chunk, StreamChunks};
use crate::session::{
    DatagramParser, DatagramParserFactory, GapResponse, SessionParser, SessionParserFactory,
    Transports,
};

/// Cap on the size of `poison_reason()` strings carried through
/// [`AnomalyKind::SessionParseError`] and parser-close details.
pub(crate) const REASON_MAX_BYTES: usize = 256;

/// Default probing budget (data-bearing packets) for signature slots.
pub const DEFAULT_PROBE_PACKETS: u8 = 4;

/// Bytes per side a signature is evaluated on. Every shipped
/// signature decides within this prefix.
pub const PROBE_BUFFER_CAP: usize = 64;

/// Cap on the stream bytes held for replay while a flow is probed.
/// A flow that needs more before its signature decides is rejected
/// rather than handed to the parser mid-stream.
pub(crate) const PROBE_REPLAY_BYTE_CAP: usize = 16 * 1024;

pub(crate) fn truncate_reason(s: &str) -> String {
    let mut owned = String::from(s);
    if owned.len() > REASON_MAX_BYTES {
        let cap = (0..=REASON_MAX_BYTES)
            .rev()
            .find(|i| owned.is_char_boundary(*i))
            .unwrap_or(0);
        owned.truncate(cap);
    }
    owned
}

/// Source and destination port of a packet, when it has them.
pub(crate) type Ports = Option<(u16, u16)>;

/// Which flows a core wants.
pub(crate) enum Selector {
    /// Every flow of the right transport.
    All,
    /// Flows with either port in the set.
    Ports(SmallVec<[u16; 4]>),
    /// Flows whose first bytes match a signature.
    Signature {
        signature: SignatureFn,
        max_probe_packets: u8,
    },
}

impl Selector {
    pub(crate) fn needs_ports(&self) -> bool {
        matches!(self, Selector::Ports(_))
    }

    /// Whether a packet with these ports can belong to a wanted flow.
    pub(crate) fn admits(&self, ports: Ports) -> bool {
        match self {
            Selector::Ports(set) => {
                ports.is_some_and(|(s, d)| set.contains(&s) || set.contains(&d))
            }
            Selector::All | Selector::Signature { .. } => true,
        }
    }
}

/// Where a core's output goes. The session drivers put everything in
/// one ordered buffer; typed-driver slots send messages to a drain
/// handle and closes / anomalies to the lifecycle buffer.
pub(crate) trait Output<K, M> {
    fn message(
        &mut self,
        key: &K,
        side: FlowSide,
        orientation: Orientation,
        message: M,
        ts: Timestamp,
        parser_kind: ParserKind,
    );

    /// A parser was closed. `at_flow_end` is `true` when the close is
    /// just the flow ending (the lifecycle already says so), `false`
    /// when the parser stopped early and the flow goes on.
    fn parser_closed(
        &mut self,
        key: &K,
        parser_kind: ParserKind,
        reason: EndReason,
        detail: Option<String>,
        ts: Timestamp,
        at_flow_end: bool,
    );

    /// Called only when the engine emits anomalies.
    fn anomaly(&mut self, key: &K, kind: AnomalyKind, ts: Timestamp);
}

/// Per-call context from the engine.
pub(crate) struct Ctx<'a, K> {
    pub key: &'a K,
    pub l4: Option<crate::L4Proto>,
    pub side: FlowSide,
    pub orientation: Orientation,
    pub ts: Timestamp,
    pub anomalies: bool,
}

/// Why a parser closed early, before the flow's end.
enum Close {
    Poison(Option<String>),
    Done,
    Gap(FlowSide, u64),
    Stopped(String),
}

impl Close {
    fn reason(&self) -> EndReason {
        match self {
            Close::Poison(_) => EndReason::ParseError,
            Close::Done => EndReason::ParserDone,
            Close::Gap(..) => EndReason::StreamGap,
            Close::Stopped(_) => EndReason::BufferOverflow,
        }
    }

    fn detail(self) -> Option<String> {
        match self {
            Close::Poison(r) => r,
            Close::Done => None,
            Close::Gap(side, n) => Some(format!("{n} bytes missing on the {side} side")),
            Close::Stopped(why) => Some(why),
        }
    }
}

enum SessionFlow<P> {
    /// Signature not decided yet. `replay` keeps the stream seen so
    /// far, in arrival order, for the parser once it pins.
    Probing {
        packets: u8,
        init: SmallVec<[u8; PROBE_BUFFER_CAP]>,
        resp: SmallVec<[u8; PROBE_BUFFER_CAP]>,
        replay: Vec<(FlowSide, Orientation, Timestamp, StreamChunks)>,
        replay_bytes: usize,
    },
    Active(P),
    /// Closed early or rejected by the signature; ignored until the
    /// flow ends.
    Closed,
}

/// A stream-parser core: one [`SessionParserFactory`], per-flow
/// parser state.
pub(crate) struct SessionCore<K, F>
where
    F: SessionParserFactory<K>,
{
    factory: F,
    selector: Selector,
    flows: HashMap<K, SessionFlow<F::Parser>, RandomState>,
    scratch: Vec<<F::Parser as SessionParser>::Message>,
}

impl<K, F> SessionCore<K, F>
where
    K: Hash + Eq + Clone,
    F: SessionParserFactory<K>,
{
    pub(crate) fn new(factory: F, selector: Selector) -> Self {
        Self {
            factory,
            selector,
            flows: HashMap::with_hasher(RandomState::new()),
            scratch: Vec::new(),
        }
    }

    pub(crate) fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Does this core want the byte stream of a flow whose packet
    /// has these ports? Consistent across a flow's packets.
    pub(crate) fn wants(&self, ports: Ports) -> bool {
        self.selector.admits(ports)
    }

    /// New reassembled output of one side of a flow. A flow this
    /// core has no state for yet is picked up only if `ports` pass
    /// the selector.
    pub(crate) fn on_stream<O>(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        chunks: &StreamChunks,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as SessionParser>::Message>,
    {
        if chunks.is_empty() {
            return;
        }
        if !self.flows.contains_key(cx.key) {
            if !self.selector.admits(ports) {
                return;
            }
            let state = match self.selector {
                Selector::Signature { .. } => SessionFlow::Probing {
                    packets: 0,
                    init: SmallVec::new(),
                    resp: SmallVec::new(),
                    replay: Vec::new(),
                    replay_bytes: 0,
                },
                Selector::All | Selector::Ports(_) => {
                    SessionFlow::Active(self.factory.new_parser(cx.key))
                }
            };
            self.flows.insert(cx.key.clone(), state);
        }
        let state = self.flows.get_mut(cx.key).expect("just inserted");
        match state {
            SessionFlow::Closed => {}
            SessionFlow::Active(parser) => {
                if let Some(close) = feed(parser, cx, chunks, &mut self.scratch, out) {
                    let kind = parser.parser_kind();
                    *state = SessionFlow::Closed;
                    emit_close(cx, kind, close, out);
                }
            }
            SessionFlow::Probing {
                packets,
                init,
                resp,
                replay,
                replay_bytes,
            } => {
                let Selector::Signature {
                    signature,
                    max_probe_packets,
                } = self.selector
                else {
                    unreachable!("only signature cores probe")
                };
                // The signature reads the contiguous prefix of each
                // side; a gap before the verdict ends that prefix.
                let probe = match cx.side {
                    FlowSide::Initiator => &mut *init,
                    FlowSide::Responder => &mut *resp,
                };
                for chunk in chunks.iter() {
                    match chunk {
                        Chunk::Data(d) if probe.len() < PROBE_BUFFER_CAP => {
                            let room = PROBE_BUFFER_CAP - probe.len();
                            probe.extend_from_slice(&d[..room.min(d.len())]);
                        }
                        Chunk::Data(_) => {}
                        Chunk::Gap(_) => break,
                    }
                }
                *packets = packets.saturating_add(1);
                *replay_bytes += chunks.len();
                replay.push((cx.side, cx.orientation, cx.ts, chunks.clone()));

                let verdicts = (signature(init), signature(resp));
                let matched = matches!(verdicts.0, SignatureMatch::Match)
                    || matches!(verdicts.1, SignatureMatch::Match);
                let rejected = (matches!(verdicts.0, SignatureMatch::NoMatch)
                    && matches!(verdicts.1, SignatureMatch::NoMatch))
                    || *packets >= max_probe_packets
                    || *replay_bytes > PROBE_REPLAY_BYTE_CAP;
                if matched {
                    let replay = std::mem::take(replay);
                    let mut parser = self.factory.new_parser(cx.key);
                    let mut closed = None;
                    for (side, orientation, ts, chunks) in &replay {
                        let rcx = Ctx {
                            key: cx.key,
                            l4: cx.l4,
                            side: *side,
                            orientation: *orientation,
                            ts: *ts,
                            anomalies: cx.anomalies,
                        };
                        if let Some(close) = feed(&mut parser, &rcx, chunks, &mut self.scratch, out)
                        {
                            closed = Some(close);
                            break;
                        }
                    }
                    match closed {
                        Some(close) => {
                            let kind = parser.parser_kind();
                            *state = SessionFlow::Closed;
                            emit_close(cx, kind, close, out);
                        }
                        None => *state = SessionFlow::Active(parser),
                    }
                } else if rejected {
                    *state = SessionFlow::Closed;
                }
            }
        }
    }

    /// `true` when this core will never use the flow's stream again:
    /// its parser closed or the signature rejected it, or the flow
    /// was never admitted.
    pub(crate) fn stream_done(&self, key: &K, ports: Ports) -> bool {
        match self.flows.get(key) {
            Some(SessionFlow::Closed) => true,
            Some(_) => false,
            None => !self.selector.admits(ports),
        }
    }

    /// The flow ended. `finals` are the last drained chunks of each
    /// side (initiator, responder) — usually empty, or out-of-order
    /// data released by the end-of-flow flush.
    pub(crate) fn on_flow_end<O>(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        anomalies: bool,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as SessionParser>::Message>,
    {
        let Some(SessionFlow::Active(mut parser)) = self.flows.remove(key) else {
            return;
        };
        let ts = stats.last_seen;
        let kind = parser.parser_kind();
        for (side, chunks) in [FlowSide::Initiator, FlowSide::Responder]
            .into_iter()
            .zip(finals)
        {
            let cx = Ctx {
                key,
                l4: Some(crate::L4Proto::Tcp),
                side,
                orientation: stats.orientation_for(side),
                ts,
                anomalies,
            };
            if let Some(close) = feed(&mut parser, &cx, chunks, &mut self.scratch, out) {
                emit_close(&cx, kind, close, out);
                return;
            }
        }
        if reason.is_graceful() {
            for side in [FlowSide::Initiator, FlowSide::Responder] {
                self.scratch.clear();
                match side {
                    FlowSide::Initiator => parser.fin_initiator(&mut self.scratch),
                    FlowSide::Responder => parser.fin_responder(&mut self.scratch),
                }
                let orientation = stats.orientation_for(side);
                for m in self.scratch.drain(..) {
                    out.message(key, side, orientation, m, ts, kind);
                }
            }
        } else {
            parser.rst_initiator();
            parser.rst_responder();
        }
        out.parser_closed(key, kind, reason, None, ts, true);
    }

    /// Periodic hook: `on_tick` on every live parser, closing those
    /// that poison or finish during it.
    pub(crate) fn on_tick<O>(
        &mut self,
        now: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as SessionParser>::Message>,
    {
        for (key, state) in self.flows.iter_mut() {
            let SessionFlow::Active(parser) = state else {
                continue;
            };
            let kind = parser.parser_kind();
            let orientation = orientation_of(key);
            self.scratch.clear();
            parser.on_tick(now, &mut self.scratch);
            for m in self.scratch.drain(..) {
                out.message(key, FlowSide::Initiator, orientation, m, now, kind);
            }
            if let Some(close) = check_close(parser) {
                *state = SessionFlow::Closed;
                let cx = Ctx {
                    key,
                    l4: None,
                    side: FlowSide::Initiator,
                    orientation,
                    ts: now,
                    anomalies,
                };
                emit_close(&cx, kind, close, out);
            }
        }
    }

    /// Drop state of flows the tracker no longer holds (their `Ended`
    /// was shed by an event mask, issue #185).
    pub(crate) fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        self.flows.retain(|k, _| alive(k));
    }
}

/// Feed one side's chunks into `parser`. Returns why the parser must
/// close, if it must.
fn feed<K, P, O>(
    parser: &mut P,
    cx: &Ctx<'_, K>,
    chunks: &StreamChunks,
    scratch: &mut Vec<P::Message>,
    out: &mut O,
) -> Option<Close>
where
    P: SessionParser,
    O: Output<K, P::Message>,
{
    let kind = parser.parser_kind();
    for chunk in chunks.iter() {
        scratch.clear();
        let gap = match chunk {
            Chunk::Data(bytes) => {
                match cx.side {
                    FlowSide::Initiator => parser.feed_initiator(bytes, cx.ts, scratch),
                    FlowSide::Responder => parser.feed_responder(bytes, cx.ts, scratch),
                }
                None
            }
            Chunk::Gap(missing) => Some((missing, parser.on_gap(cx.side, missing, cx.ts, scratch))),
        };
        for m in scratch.drain(..) {
            out.message(cx.key, cx.side, cx.orientation, m, cx.ts, kind);
        }
        if let Some(close) = check_close(parser) {
            return Some(close);
        }
        if let Some((missing, GapResponse::Stop)) = gap {
            return Some(Close::Gap(cx.side, missing));
        }
    }
    chunks.stop().map(|stop| {
        Close::Stopped(format!(
            "reassembly stopped on the {} side: {stop}",
            cx.side
        ))
    })
}

fn check_close<P: SessionParser>(parser: &P) -> Option<Close> {
    if parser.is_poisoned() {
        Some(Close::Poison(parser.poison_reason().map(truncate_reason)))
    } else if parser.is_done() {
        Some(Close::Done)
    } else {
        None
    }
}

fn emit_close<K, M, O: Output<K, M>>(cx: &Ctx<'_, K>, kind: ParserKind, close: Close, out: &mut O) {
    let reason = close.reason();
    if let Close::Poison(detail) = &close
        && cx.anomalies
    {
        out.anomaly(
            cx.key,
            AnomalyKind::SessionParseError {
                side: cx.side,
                reason: detail.clone(),
            },
            cx.ts,
        );
    }
    out.parser_closed(cx.key, kind, reason, close.detail(), cx.ts, false);
}

enum DatagramFlow<P> {
    Probing { packets: u8 },
    Active(P),
    Closed,
}

/// A datagram-parser core: one [`DatagramParserFactory`], per-flow
/// parser state.
pub(crate) struct DatagramCore<K, F>
where
    F: DatagramParserFactory<K>,
{
    factory: F,
    selector: Selector,
    transports: Transports,
    flows: HashMap<K, DatagramFlow<F::Parser>, RandomState>,
    scratch: Vec<<F::Parser as DatagramParser>::Message>,
}

impl<K, F> DatagramCore<K, F>
where
    K: Hash + Eq + Clone,
    F: DatagramParserFactory<K>,
{
    pub(crate) fn new(factory: F, selector: Selector) -> Self {
        let transports = factory.transports();
        Self {
            factory,
            selector,
            transports,
            flows: HashMap::with_hasher(RandomState::new()),
            scratch: Vec::new(),
        }
    }

    pub(crate) fn selector(&self) -> &Selector {
        &self.selector
    }

    /// Does this core want datagrams of this transport / ports?
    pub(crate) fn wants(&self, ports: Ports, l4: Option<crate::L4Proto>) -> bool {
        self.transports.admits(l4) && self.selector.admits(ports)
    }

    /// One datagram payload.
    pub(crate) fn on_datagram<O>(
        &mut self,
        cx: &Ctx<'_, K>,
        ports: Ports,
        payload: &[u8],
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as DatagramParser>::Message>,
    {
        if !self.transports.admits(cx.l4) {
            return;
        }
        if !self.flows.contains_key(cx.key) {
            if !self.selector.admits(ports) {
                return;
            }
            let state = match self.selector {
                Selector::Signature { .. } => DatagramFlow::Probing { packets: 0 },
                Selector::All | Selector::Ports(_) => {
                    DatagramFlow::Active(self.factory.new_parser(cx.key))
                }
            };
            self.flows.insert(cx.key.clone(), state);
        }
        let state = self.flows.get_mut(cx.key).expect("just inserted");
        if let DatagramFlow::Probing { packets } = state {
            let Selector::Signature {
                signature,
                max_probe_packets,
            } = self.selector
            else {
                unreachable!("only signature cores probe")
            };
            match signature(payload) {
                SignatureMatch::Match => {
                    *state = DatagramFlow::Active(self.factory.new_parser(cx.key))
                }
                verdict => {
                    *packets = packets.saturating_add(1);
                    if matches!(verdict, SignatureMatch::NoMatch) || *packets >= max_probe_packets {
                        *state = DatagramFlow::Closed;
                    }
                    return;
                }
            }
        }
        let DatagramFlow::Active(parser) = state else {
            return;
        };
        let kind = parser.parser_kind();
        self.scratch.clear();
        parser.parse(payload, cx.side, cx.ts, &mut self.scratch);
        for m in self.scratch.drain(..) {
            out.message(cx.key, cx.side, cx.orientation, m, cx.ts, kind);
        }
        if let Some(close) = check_datagram_close(parser) {
            *state = DatagramFlow::Closed;
            emit_close(cx, kind, close, out);
        }
    }

    pub(crate) fn on_flow_end<O>(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as DatagramParser>::Message>,
    {
        if let Some(DatagramFlow::Active(parser)) = self.flows.remove(key) {
            out.parser_closed(
                key,
                parser.parser_kind(),
                reason,
                None,
                stats.last_seen,
                true,
            );
        }
    }

    pub(crate) fn on_tick<O>(
        &mut self,
        now: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as DatagramParser>::Message>,
    {
        for (key, state) in self.flows.iter_mut() {
            let DatagramFlow::Active(parser) = state else {
                continue;
            };
            let kind = parser.parser_kind();
            let orientation = orientation_of(key);
            self.scratch.clear();
            parser.on_tick(now, &mut self.scratch);
            for m in self.scratch.drain(..) {
                out.message(key, FlowSide::Initiator, orientation, m, now, kind);
            }
            if let Some(close) = check_datagram_close(parser) {
                *state = DatagramFlow::Closed;
                let cx = Ctx {
                    key,
                    l4: None,
                    side: FlowSide::Initiator,
                    orientation,
                    ts: now,
                    anomalies,
                };
                emit_close(&cx, kind, close, out);
            }
        }
    }

    pub(crate) fn retain(&mut self, alive: &dyn Fn(&K) -> bool) {
        self.flows.retain(|k, _| alive(k));
    }
}

fn check_datagram_close<P: DatagramParser>(parser: &P) -> Option<Close> {
    if parser.is_poisoned() {
        Some(Close::Poison(parser.poison_reason().map(truncate_reason)))
    } else if parser.is_done() {
        Some(Close::Done)
    } else {
        None
    }
}
