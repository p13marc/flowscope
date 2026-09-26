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
use crate::reassembler::{Chunk, Chunks, ReassemblyStop, StreamChunks};
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
/// Past it, a side's further bytes are not kept; if the signature
/// then matches, the parser gets them as a leading gap (it starts
/// mid-stream on that side, and is told so).
pub(crate) const PROBE_REPLAY_BYTE_CAP: usize = 64 * 1024;

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

/// Reassembled output handed to a core: chunks drained from a
/// reassembler, or in-order bytes let through straight from the
/// packet (no copy).
#[derive(Clone, Copy)]
pub(crate) enum Stream<'a> {
    Chunks(&'a StreamChunks),
    Bytes(&'a [u8]),
}

impl<'a> Stream<'a> {
    pub(crate) fn is_empty(&self) -> bool {
        match self {
            Stream::Chunks(c) => c.is_empty(),
            Stream::Bytes(b) => b.is_empty(),
        }
    }

    /// Data bytes (gaps excluded).
    pub(crate) fn len(&self) -> usize {
        match self {
            Stream::Chunks(c) => c.len(),
            Stream::Bytes(b) => b.len(),
        }
    }

    pub(crate) fn stop(&self) -> Option<ReassemblyStop> {
        match self {
            Stream::Chunks(c) => c.stop(),
            Stream::Bytes(_) => None,
        }
    }

    pub(crate) fn iter(&self) -> StreamIter<'a> {
        match *self {
            Stream::Chunks(c) => StreamIter::Chunks(c.iter()),
            Stream::Bytes(b) => StreamIter::Bytes((!b.is_empty()).then_some(b)),
        }
    }

    /// Owned copy (for probing replay).
    pub(crate) fn to_chunks(self) -> StreamChunks {
        match self {
            Stream::Chunks(c) => c.clone(),
            Stream::Bytes(b) => {
                let mut c = StreamChunks::new();
                c.push_data(b);
                c
            }
        }
    }
}

pub(crate) enum StreamIter<'a> {
    Chunks(Chunks<'a>),
    Bytes(Option<&'a [u8]>),
}

impl<'a> Iterator for StreamIter<'a> {
    type Item = Chunk<'a>;
    fn next(&mut self) -> Option<Chunk<'a>> {
        match self {
            StreamIter::Chunks(c) => c.next(),
            StreamIter::Bytes(b) => b.take().map(Chunk::Data),
        }
    }
}

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

    /// A parser stopped reading one side; the other goes on.
    fn parser_side_stopped(
        &mut self,
        key: &K,
        parser_kind: ParserKind,
        side: FlowSide,
        reason: EndReason,
        detail: Option<String>,
        ts: Timestamp,
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
    /// Both sides stopped (the last stop's reason).
    BothSides(EndReason),
}

impl Close {
    fn reason(&self) -> EndReason {
        match self {
            Close::Poison(_) => EndReason::ParseError,
            Close::Done => EndReason::ParserDone,
            Close::Gap(..) => EndReason::StreamGap,
            Close::BothSides(reason) => *reason,
        }
    }

    fn detail(self) -> Option<String> {
        match self {
            Close::Poison(r) => r,
            Close::Done => None,
            Close::Gap(side, n) => Some(format!("{n} bytes missing on the {side} side")),
            Close::BothSides(_) => Some("both sides stopped".to_owned()),
        }
    }
}

/// What ended a [`feed`] early.
enum FeedEnd {
    /// Close the whole parser.
    Close(Close),
    /// Stop reading this side.
    StopSide(EndReason, String),
}

/// A parser with its per-side stop flags.
struct Active<P> {
    parser: P,
    stopped: [bool; 2],
}

fn side_idx(side: FlowSide) -> usize {
    match side {
        FlowSide::Initiator => 0,
        FlowSide::Responder => 1,
    }
}

impl<P: SessionParser> Active<P> {
    fn new(parser: P) -> Self {
        Self {
            parser,
            stopped: [false, false],
        }
    }

    /// Feed one side. Returns `true` when the parser is closed.
    fn feed<K, O>(
        &mut self,
        cx: &Ctx<'_, K>,
        stream: &Stream<'_>,
        scratch: &mut Vec<P::Message>,
        out: &mut O,
    ) -> bool
    where
        O: Output<K, P::Message>,
    {
        let si = side_idx(cx.side);
        if self.stopped[si] {
            return false;
        }
        let kind = self.parser.parser_kind();
        match feed(&mut self.parser, cx, stream, scratch, out) {
            None => false,
            Some(FeedEnd::Close(close)) => {
                emit_close(cx, kind, close, out);
                true
            }
            Some(FeedEnd::StopSide(reason, detail)) => {
                self.stopped[si] = true;
                crate::obs::record_parser_side_stopped(kind, cx.side, reason);
                out.parser_side_stopped(cx.key, kind, cx.side, reason, Some(detail), cx.ts);
                if self.stopped == [true, true] {
                    emit_close(cx, kind, Close::BothSides(reason), out);
                    return true;
                }
                false
            }
        }
    }
}

/// Probing state of one flow (boxed: most flows never probe, and it
/// is much larger than a parser handle).
#[derive(Default)]
struct Probe {
    packets: u8,
    /// Contiguous prefix of each side the signature reads.
    prefix: [SmallVec<[u8; PROBE_BUFFER_CAP]>; 2],
    /// A gap (or stop) ended that side's prefix: bytes after it are
    /// not contiguous with it.
    sealed: [bool; 2],
    /// The stream seen so far, in arrival order, for the parser once
    /// it pins.
    replay: Vec<(FlowSide, Orientation, Timestamp, StreamChunks)>,
    replay_bytes: usize,
    /// Whether each side has a chunk in `replay` (the first one is
    /// always kept).
    kept: [bool; 2],
    /// Bytes (data and gaps) of each side not kept in `replay` past
    /// the cap.
    lost: [u64; 2],
}

/// A signature verdict.
enum Verdict {
    Match,
    Reject,
    Undecided,
}

impl Probe {
    /// Record one side's output and evaluate the signature.
    fn step(
        &mut self,
        cx: &Ctx<'_, impl Sized>,
        stream: &Stream<'_>,
        signature: SignatureFn,
        max_probe_packets: u8,
    ) -> Verdict {
        let si = side_idx(cx.side);
        if !self.sealed[si] {
            let prefix = &mut self.prefix[si];
            for chunk in stream.iter() {
                match chunk {
                    Chunk::Data(d) => {
                        let room = PROBE_BUFFER_CAP.saturating_sub(prefix.len());
                        prefix.extend_from_slice(&d[..room.min(d.len())]);
                    }
                    Chunk::Gap(_) => {
                        self.sealed[si] = true;
                        break;
                    }
                }
            }
            if stream.stop().is_some() {
                self.sealed[si] = true;
            }
        }
        self.packets = self.packets.saturating_add(1);
        let len = stream.len();
        if !self.kept[si]
            || (self.lost[si] == 0 && self.replay_bytes + len <= PROBE_REPLAY_BYTE_CAP)
        {
            self.kept[si] = true;
            self.replay_bytes += len;
            self.replay
                .push((cx.side, cx.orientation, cx.ts, stream.to_chunks()));
        } else {
            let gaps: u64 = stream
                .iter()
                .map(|c| match c {
                    Chunk::Gap(n) => n,
                    Chunk::Data(_) => 0,
                })
                .sum();
            self.lost[si] += len as u64 + gaps;
        }
        let verdicts = (signature(&self.prefix[0]), signature(&self.prefix[1]));
        if matches!(verdicts.0, SignatureMatch::Match)
            || matches!(verdicts.1, SignatureMatch::Match)
        {
            Verdict::Match
        } else if (matches!(verdicts.0, SignatureMatch::NoMatch)
            && matches!(verdicts.1, SignatureMatch::NoMatch))
            || self.packets >= max_probe_packets
        {
            Verdict::Reject
        } else {
            Verdict::Undecided
        }
    }
}

enum SessionFlow<P> {
    /// Signature not decided yet. `replay` keeps the stream seen so
    /// far, in arrival order, for the parser once it pins.
    Probing(Box<Probe>),
    Active(Active<P>),
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
        chunks: &Stream<'_>,
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
                Selector::Signature { .. } => SessionFlow::Probing(Box::default()),
                Selector::All | Selector::Ports(_) => {
                    SessionFlow::Active(Active::new(self.factory.new_parser(cx.key)))
                }
            };
            self.flows.insert(cx.key.clone(), state);
        }
        let state = self.flows.get_mut(cx.key).expect("just inserted");
        match state {
            SessionFlow::Closed => {}
            SessionFlow::Active(active) => {
                if active.feed(cx, chunks, &mut self.scratch, out) {
                    *state = SessionFlow::Closed;
                }
            }
            SessionFlow::Probing(probe) => {
                let Selector::Signature {
                    signature,
                    max_probe_packets,
                } = self.selector
                else {
                    unreachable!("only signature cores probe")
                };
                match probe.step(cx, chunks, signature, max_probe_packets) {
                    Verdict::Undecided => {}
                    Verdict::Reject => *state = SessionFlow::Closed,
                    Verdict::Match => {
                        let probe = std::mem::take(&mut **probe);
                        let parser = self.factory.new_parser(cx.key);
                        *state = match pin(parser, probe, cx, &mut self.scratch, out) {
                            Some(active) => SessionFlow::Active(active),
                            None => SessionFlow::Closed,
                        };
                    }
                }
            }
        }
    }

    /// Per side (initiator, responder): `true` when this core will
    /// never use that side's stream again — its parser closed or
    /// stopped the side, the signature rejected the flow, or the flow
    /// was never admitted.
    pub(crate) fn streams_done(&self, key: &K, ports: Ports) -> [bool; 2] {
        match self.flows.get(key) {
            Some(SessionFlow::Closed) => [true, true],
            Some(SessionFlow::Active(a)) => a.stopped,
            Some(SessionFlow::Probing(_)) => [false, false],
            None => {
                let done = !self.selector.admits(ports);
                [done, done]
            }
        }
    }

    /// The flow ended. `finals` are the last drained chunks of each
    /// side (initiator, responder) — usually empty, or out-of-order
    /// data released by the end-of-flow flush. They go through the
    /// same path as live data: a flow still probing is probed on
    /// them, and a flow first seen in them is picked up (`ports` are
    /// the flow's, for port selectors).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn on_flow_end<O>(
        &mut self,
        key: &K,
        reason: EndReason,
        stats: &FlowStats,
        finals: [&StreamChunks; 2],
        ports: Ports,
        anomalies: bool,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as SessionParser>::Message>,
    {
        let ts = stats.last_seen;
        for (side, chunks) in [FlowSide::Initiator, FlowSide::Responder]
            .into_iter()
            .zip(finals)
        {
            if chunks.is_empty() {
                continue;
            }
            let cx = Ctx {
                key,
                l4: Some(crate::L4Proto::Tcp),
                side,
                orientation: stats.orientation_for(side),
                ts,
                anomalies,
            };
            self.on_stream(&cx, ports, &Stream::Chunks(chunks), out);
        }
        let Some(SessionFlow::Active(mut active)) = self.flows.remove(key) else {
            return;
        };
        let kind = active.parser.parser_kind();
        // Each side still read ends on its own terms: `fin_*` when the
        // flow ended gracefully or that side sent a FIN, `rst_*`
        // otherwise. A stopped side gets neither.
        for side in [FlowSide::Initiator, FlowSide::Responder] {
            if active.stopped[side_idx(side)] {
                continue;
            }
            let fin_seen = match side {
                FlowSide::Initiator => stats.fin_initiator,
                FlowSide::Responder => stats.fin_responder,
            };
            if reason.is_graceful() || fin_seen {
                self.scratch.clear();
                match side {
                    FlowSide::Initiator => active.parser.fin_initiator(&mut self.scratch),
                    FlowSide::Responder => active.parser.fin_responder(&mut self.scratch),
                }
                let orientation = stats.orientation_for(side);
                for m in self.scratch.drain(..) {
                    out.message(key, side, orientation, m, ts, kind);
                }
            } else {
                match side {
                    FlowSide::Initiator => active.parser.rst_initiator(),
                    FlowSide::Responder => active.parser.rst_responder(),
                }
            }
        }
        crate::obs::record_parser_closed(kind, reason);
        out.parser_closed(key, kind, reason, None, ts, true);
    }

    /// Periodic hook: `on_tick` on every live parser, closing those
    /// that poison or finish during it.
    pub(crate) fn on_tick<O>(
        &mut self,
        now: Timestamp,
        stamp: Timestamp,
        orientation_of: &dyn Fn(&K) -> Orientation,
        anomalies: bool,
        out: &mut O,
    ) where
        O: Output<K, <F::Parser as SessionParser>::Message>,
    {
        for (key, state) in self.flows.iter_mut() {
            let SessionFlow::Active(Active { parser, .. }) = state else {
                continue;
            };
            let kind = parser.parser_kind();
            let orientation = orientation_of(key);
            self.scratch.clear();
            parser.on_tick(now, &mut self.scratch);
            for m in self.scratch.drain(..) {
                out.message(key, FlowSide::Initiator, orientation, m, stamp, kind);
            }
            if let Some(close) = check_close(parser) {
                *state = SessionFlow::Closed;
                let cx = Ctx {
                    key,
                    l4: None,
                    side: FlowSide::Initiator,
                    orientation,
                    ts: stamp,
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

/// A probed flow matched: feed the parser what was seen so far —
/// the replay log in arrival order, then, for a side whose bytes did
/// not all fit, a gap for the missing part. `None` when the parser
/// closed during the replay.
fn pin<K, P, O>(
    parser: P,
    probe: Probe,
    cx: &Ctx<'_, K>,
    scratch: &mut Vec<P::Message>,
    out: &mut O,
) -> Option<Active<P>>
where
    P: SessionParser,
    O: Output<K, P::Message>,
{
    let mut active = Active::new(parser);
    for (side, orientation, ts, chunks) in &probe.replay {
        let rcx = Ctx {
            key: cx.key,
            l4: cx.l4,
            side: *side,
            orientation: *orientation,
            ts: *ts,
            anomalies: cx.anomalies,
        };
        if active.feed(&rcx, &Stream::Chunks(chunks), scratch, out) {
            return None;
        }
    }
    for (i, side) in [FlowSide::Initiator, FlowSide::Responder]
        .into_iter()
        .enumerate()
    {
        if probe.lost[i] == 0 {
            continue;
        }
        let mut gap = StreamChunks::new();
        gap.push_gap(probe.lost[i]);
        let rcx = Ctx {
            key: cx.key,
            l4: cx.l4,
            side,
            orientation: match side == cx.side {
                true => cx.orientation,
                false => cx.orientation.flipped(),
            },
            ts: cx.ts,
            anomalies: cx.anomalies,
        };
        if active.feed(&rcx, &Stream::Chunks(&gap), scratch, out) {
            return None;
        }
    }
    Some(active)
}

/// Feed one side's chunks into `parser`. Returns what ended the feed
/// early, if anything: the parser must close, or stop this side.
fn feed<K, P, O>(
    parser: &mut P,
    cx: &Ctx<'_, K>,
    chunks: &Stream<'_>,
    scratch: &mut Vec<P::Message>,
    out: &mut O,
) -> Option<FeedEnd>
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
            return Some(FeedEnd::Close(close));
        }
        match gap {
            Some((missing, GapResponse::Stop)) => {
                return Some(FeedEnd::Close(Close::Gap(cx.side, missing)));
            }
            Some((missing, GapResponse::StopSide)) => {
                return Some(FeedEnd::StopSide(
                    EndReason::StreamGap,
                    format!("{missing} bytes missing"),
                ));
            }
            _ => {}
        }
    }
    chunks.stop().map(|stop| {
        FeedEnd::StopSide(
            EndReason::BufferOverflow,
            format!("reassembly stopped: {stop}"),
        )
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
    crate::obs::record_parser_closed(kind, reason);
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
            crate::obs::record_parser_closed(parser.parser_kind(), reason);
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
        stamp: Timestamp,
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
                out.message(key, FlowSide::Initiator, orientation, m, stamp, kind);
            }
            if let Some(close) = check_datagram_close(parser) {
                *state = DatagramFlow::Closed;
                let cx = Ctx {
                    key,
                    l4: None,
                    side: FlowSide::Initiator,
                    orientation,
                    ts: stamp,
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
