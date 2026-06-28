//! Pluggable L7 message parsers.
//!
//! Two trait families:
//!
//! - [`SessionParser`] — for **stream-based** protocols (HTTP/1, TLS,
//!   DNS-over-TCP). One parser per session; receives bytes via
//!   `feed_initiator` / `feed_responder`; returns a `Vec` of typed
//!   messages every call. Pair with `netring::SessionStream` to get
//!   an async stream of L7 events.
//!
//! - [`DatagramParser`] — for **packet-based** protocols (DNS-over-UDP,
//!   syslog, NTP, SNMP). Receives one L4 payload at a time. Pair with
//!   `netring::DatagramStream`.
//!
//! Both trait shapes return owned `Vec<Message>` rather than borrowed
//! iterators or `SmallVec` to keep the public API stable across
//! versions of `smallvec` etc. The per-call allocation is amortized
//! across many bytes worth of work.
//!
//! # SessionParser vs `Reassembler`
//!
//! [`crate::Reassembler`] is the lower-level hook: one instance per
//! `(flow, side)`, receives raw TCP segments, callback-driven via
//! a user-supplied handler. `SessionParser` is the higher-level
//! abstraction: one instance per flow, two `feed_*` methods,
//! returns typed messages directly. Pick whichever fits your
//! integration:
//!
//! | Concern                       | `Reassembler`           | `SessionParser`             |
//! |-------------------------------|-------------------------|------------------------------|
//! | Granularity                   | per (flow, side)        | per flow                     |
//! | Output                        | callback (Handler)      | iterator/`Stream` of messages|
//! | Cross-direction state         | painful                 | natural                      |
//! | UDP support                   | no                      | use [`DatagramParser`]       |
//!
//! # Example
//!
//! ```
//! use flowscope::{FlowSide, SessionParser, Timestamp};
//!
//! #[derive(Default, Clone)]
//! struct LineParser {
//!     init_buf: Vec<u8>,
//!     resp_buf: Vec<u8>,
//! }
//!
//! impl SessionParser for LineParser {
//!     type Message = (FlowSide, String);
//!
//!     fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
//!         feed(&mut self.init_buf, bytes, FlowSide::Initiator, out);
//!     }
//!     fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
//!         feed(&mut self.resp_buf, bytes, FlowSide::Responder, out);
//!     }
//! }
//!
//! fn feed(buf: &mut Vec<u8>, bytes: &[u8], side: FlowSide, out: &mut Vec<(FlowSide, String)>) {
//!     buf.extend_from_slice(bytes);
//!     while let Some(nl) = buf.iter().position(|&b| b == b'\n') {
//!         let line = String::from_utf8_lossy(&buf[..nl]).into_owned();
//!         out.push((side, line));
//!         buf.drain(..=nl);
//!     }
//! }
//! ```

use crate::{
    event::{AnomalyKind, EndReason, FlowSide, FlowStats},
    timestamp::Timestamp,
};

/// Default per-side buffer cap for [`BufferedFrameDrain`] /
/// [`AccumulatingSessionParser`]. 64 KiB matches the TCP
/// receive-buffer scale.
pub const DEFAULT_FRAME_DRAIN_MAX_BUFFER: usize = 64 * 1024;

/// Reasons [`BufferedFrameDrain`] / [`AccumulatingSessionParser`]
/// poison themselves.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FrameDrainError {
    /// Buffer reached its `max_buffer` ceiling before the parser
    /// drained a complete message. Indicates protocol desync —
    /// the parser can't make progress.
    BufferFull,
    /// The `parse_one` closure returned `Some((msg, 0))` — a
    /// zero-byte advance. Reserved for closure-author bugs; the
    /// drain stops to avoid an infinite loop and the parser is
    /// poisoned.
    ZeroByteAdvance,
}

impl std::fmt::Display for FrameDrainError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameDrainError::BufferFull => f.write_str("parser buffer exceeded max_buffer cap"),
            FrameDrainError::ZeroByteAdvance => {
                f.write_str("parse_one returned Some((_, 0)) — zero-byte advance")
            }
        }
    }
}

impl std::error::Error for FrameDrainError {}

/// Buffered drain helper for custom parsers.
///
/// Encapsulates the "accumulate bytes, repeatedly call a parser
/// closure, drain consumed prefix, retain partial" pattern that
/// every custom [`SessionParser`] writes. Catches the off-by-one
/// bugs around drain offsets.
///
/// Typical use inside a [`SessionParser`] impl:
///
/// ```rust
/// # use flowscope::session::BufferedFrameDrain;
/// # use flowscope::{FlowSide, SessionParser, Timestamp};
/// # #[derive(Debug, Clone)] struct Msg;
/// # fn parse_one(b: &[u8]) -> Option<(Msg, usize)> { None }
/// #[derive(Default, Clone)]
/// struct MyParser {
///     init: BufferedFrameDrain<Msg>,
///     resp: BufferedFrameDrain<Msg>,
/// }
///
/// impl SessionParser for MyParser {
///     type Message = Msg;
///     fn feed_initiator(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Msg>) {
///         let _ = self.init.extend(b);
///         self.init.drain_with(parse_one);
///         out.append(&mut self.init.take_messages());
///     }
///     fn feed_responder(&mut self, b: &[u8], _: Timestamp, out: &mut Vec<Msg>) {
///         let _ = self.resp.extend(b);
///         self.resp.drain_with(parse_one);
///         out.append(&mut self.resp.take_messages());
///     }
/// }
/// ```
///
/// New in 0.10.0 (plan 106).
#[derive(Debug)]
pub struct BufferedFrameDrain<M> {
    buf: Vec<u8>,
    out: Vec<M>,
    max_buffer: usize,
    poisoned: Option<FrameDrainError>,
}

impl<M> Default for BufferedFrameDrain<M> {
    fn default() -> Self {
        Self::new()
    }
}

impl<M> Clone for BufferedFrameDrain<M> {
    /// Clones the configuration (`max_buffer`) but resets the
    /// buffer / messages / poison state — typical use is to
    /// rebuild the helper per session.
    fn clone(&self) -> Self {
        Self {
            buf: Vec::new(),
            out: Vec::new(),
            max_buffer: self.max_buffer,
            poisoned: None,
        }
    }
}

impl<M> BufferedFrameDrain<M> {
    /// Construct with the [default buffer
    /// cap](DEFAULT_FRAME_DRAIN_MAX_BUFFER).
    pub fn new() -> Self {
        Self::with_max_buffer(DEFAULT_FRAME_DRAIN_MAX_BUFFER)
    }

    /// Construct with a custom per-side buffer cap.
    pub fn with_max_buffer(max_buffer: usize) -> Self {
        Self {
            buf: Vec::new(),
            out: Vec::new(),
            max_buffer,
            poisoned: None,
        }
    }

    /// Append `bytes` to the buffer.
    ///
    /// Returns `Err(FrameDrainError::BufferFull)` if the new
    /// length would exceed `max_buffer`. The helper sets its
    /// internal poison flag (queryable via [`Self::is_poisoned`]).
    /// `bytes` are still appended up to the cap before poisoning,
    /// so consumers that surface poison to the driver get the
    /// last bit of data they can use.
    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), FrameDrainError> {
        if self.poisoned.is_some() {
            return Err(self.poisoned.clone().unwrap());
        }
        let new_len = self.buf.len().saturating_add(bytes.len());
        if new_len > self.max_buffer {
            let room = self.max_buffer.saturating_sub(self.buf.len());
            self.buf.extend_from_slice(&bytes[..room.min(bytes.len())]);
            self.poisoned = Some(FrameDrainError::BufferFull);
            return Err(FrameDrainError::BufferFull);
        }
        self.buf.extend_from_slice(bytes);
        Ok(())
    }

    /// Repeatedly call `parse_one` and drain the consumed prefix.
    /// Pushes each parsed message into the internal `out` queue
    /// (drain via [`Self::take_messages`]).
    ///
    /// `parse_one(buf) -> Option<(M, usize)>` semantics:
    /// - `Some((msg, n))` — a complete message; advance `n` bytes.
    /// - `None` — need more bytes.
    /// - `Some((_, 0))` is treated as poison (zero-byte advance
    ///   would loop forever).
    pub fn drain_with<F>(&mut self, mut parse_one: F)
    where
        F: FnMut(&[u8]) -> Option<(M, usize)>,
    {
        while self.poisoned.is_none() {
            match parse_one(&self.buf) {
                Some((msg, 0)) => {
                    self.out.push(msg);
                    self.poisoned = Some(FrameDrainError::ZeroByteAdvance);
                    return;
                }
                Some((msg, n)) => {
                    self.out.push(msg);
                    if n >= self.buf.len() {
                        self.buf.clear();
                    } else {
                        self.buf.drain(..n);
                    }
                }
                None => return,
            }
        }
    }

    /// Take the accumulated messages, clearing the queue.
    pub fn take_messages(&mut self) -> Vec<M> {
        std::mem::take(&mut self.out)
    }

    /// Bytes currently held in the buffer.
    pub fn buffered_len(&self) -> usize {
        self.buf.len()
    }

    /// `true` if the helper has poisoned itself (`BufferFull` or
    /// `ZeroByteAdvance`). Once set, [`Self::extend`] is a no-op.
    pub fn is_poisoned(&self) -> bool {
        self.poisoned.is_some()
    }

    /// Poison reason, if any.
    pub fn poison_reason(&self) -> Option<&FrameDrainError> {
        self.poisoned.as_ref()
    }
}

/// Convenience [`SessionParser`] impl over a `parse_one` closure
/// of shape `Fn(&[u8]) -> Option<(M, usize)>`.
///
/// Wraps two [`BufferedFrameDrain`]s (one per side) and exposes
/// the canonical "init + resp + drain-loop" pattern through one
/// constructor call. Reduces ~25 LoC of boilerplate per custom
/// parser to:
///
/// ```rust
/// # use flowscope::session::AccumulatingSessionParser;
/// # #[derive(Debug, Clone)] struct Msg;
/// # fn parse_one(b: &[u8]) -> Option<(Msg, usize)> { None }
/// let parser = AccumulatingSessionParser::new("my-protocol", parse_one);
/// ```
///
/// The closure must be `Clone + Send + 'static` so the parser
/// can be cloned per session (via the [`SessionParserFactory`]
/// blanket impl). Capturing closures usually satisfy `Clone` if
/// the captured values do.
///
/// New in 0.10.0 (plan 106).
pub struct AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    parser_kind: &'static str,
    parse_one: F,
    max_buffer: usize,
    init: BufferedFrameDrain<M>,
    resp: BufferedFrameDrain<M>,
}

impl<F, M> std::fmt::Debug for AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccumulatingSessionParser")
            .field("parser_kind", &self.parser_kind)
            .field("init_buffered", &self.init.buffered_len())
            .field("resp_buffered", &self.resp.buffered_len())
            .field(
                "poisoned",
                &(self.init.is_poisoned() || self.resp.is_poisoned()),
            )
            .finish()
    }
}

impl<F, M> Clone for AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    /// Clones the configuration + parse closure; resets per-session
    /// buffer state. Use for per-session reuse via the
    /// [`SessionParserFactory`] blanket impl.
    fn clone(&self) -> Self {
        Self {
            parser_kind: self.parser_kind,
            parse_one: self.parse_one.clone(),
            max_buffer: self.max_buffer,
            init: BufferedFrameDrain::with_max_buffer(self.max_buffer),
            resp: BufferedFrameDrain::with_max_buffer(self.max_buffer),
        }
    }
}

impl<F, M> AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    /// Construct with the [default per-side buffer
    /// cap](DEFAULT_FRAME_DRAIN_MAX_BUFFER).
    pub fn new(parser_kind: &'static str, parse_one: F) -> Self {
        Self::with_max_buffer(parser_kind, parse_one, DEFAULT_FRAME_DRAIN_MAX_BUFFER)
    }

    /// Construct with a custom per-side buffer cap.
    pub fn with_max_buffer(parser_kind: &'static str, parse_one: F, max_buffer: usize) -> Self {
        Self {
            parser_kind,
            parse_one,
            max_buffer,
            init: BufferedFrameDrain::with_max_buffer(max_buffer),
            resp: BufferedFrameDrain::with_max_buffer(max_buffer),
        }
    }
}

impl<F, M> SessionParser for AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    type Message = M;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<M>) {
        if self.init.extend(bytes).is_err() {
            out.append(&mut self.init.take_messages());
            return;
        }
        let parse_one = self.parse_one.clone();
        self.init.drain_with(parse_one);
        out.append(&mut self.init.take_messages());
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<M>) {
        if self.resp.extend(bytes).is_err() {
            out.append(&mut self.resp.take_messages());
            return;
        }
        let parse_one = self.parse_one.clone();
        self.resp.drain_with(parse_one);
        out.append(&mut self.resp.take_messages());
    }

    fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }

    fn is_poisoned(&self) -> bool {
        self.init.is_poisoned() || self.resp.is_poisoned()
    }

    fn poison_reason(&self) -> Option<&str> {
        // First poisoned side wins.
        let err = self.init.poison_reason().or(self.resp.poison_reason())?;
        Some(match err {
            FrameDrainError::BufferFull => "buffer cap exceeded",
            FrameDrainError::ZeroByteAdvance => "parse_one returned zero-byte advance",
        })
    }
}

/// Convenience [`DatagramParser`] impl over a `parse_one` closure
/// of shape `Fn(&[u8]) -> Option<M>`.
///
/// One UDP packet, one optional message. The closure receives the
/// raw payload; return `Some(message)` to emit one event,
/// `None` to drop the packet silently.
///
/// New in 0.10.0 (plan 106).
pub struct PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    parser_kind: &'static str,
    parse_one: F,
}

impl<F, M> std::fmt::Debug for PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PerDatagramParser")
            .field("parser_kind", &self.parser_kind)
            .finish()
    }
}

impl<F, M> Clone for PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    fn clone(&self) -> Self {
        Self {
            parser_kind: self.parser_kind,
            parse_one: self.parse_one.clone(),
        }
    }
}

impl<F, M> PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    pub fn new(parser_kind: &'static str, parse_one: F) -> Self {
        Self {
            parser_kind,
            parse_one,
        }
    }
}

impl<F, M> DatagramParser for PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + std::fmt::Debug + 'static,
{
    type Message = M;

    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp, out: &mut Vec<M>) {
        if let Some(msg) = (self.parse_one)(payload) {
            out.push(msg);
        }
    }

    fn parser_kind(&self) -> &'static str {
        self.parser_kind
    }
}

/// Parses a stream-oriented L7 protocol session. One instance per
/// flow; both directions feed through the same parser, allowing
/// state to interleave.
///
/// Implementors are owned by the per-flow slot; sync (no `await`).
/// Backpressure flows from the consuming `Stream` back to the
/// kernel ring once the per-flow message buffer fills up — see
/// the `netring::SessionStream` adapter.
///
/// # Per-flow rich state
///
/// For consumers that maintain per-flow user state updated by BOTH
/// the reassembler and the parser — TCP rich stats, application-
/// level counters, middleware state machines — keep that state on
/// [`crate::FlowEntry::user`] (typed via the `S` parameter on
/// the internal session engine) and update it from your event
/// loop after `track()`. The pattern is documented in
/// `docs/recipes.md` → "Per-flow user state via the consumer
/// loop". Avoid piping `&mut S` through `feed_*` — it would
/// ripple a generic parameter through every shipped parser.
pub trait SessionParser: Send + 'static {
    /// L7 message produced by this parser.
    ///
    /// - `Send + 'static` so messages can cross task boundaries.
    /// - `Debug` is required for the per-message `tracing::trace!`
    ///   event under the `tracing` feature (filter via
    ///   `EnvFilter::new("flowscope.message=warn")` to suppress).
    ///   Almost every Rust type derives `Debug` anyway, and the
    ///   bound is trivial to add for those that don't.
    type Message: Send + std::fmt::Debug + 'static;

    /// Feed the next chunk of bytes from the **initiator** side.
    /// `ts` is the observed time of the packet carrying these bytes.
    /// Push any complete messages parsed during this call into
    /// `out`.
    ///
    /// **0.11 break (plan 119):** signature changed from
    /// `-> Vec<Self::Message>` to taking `out: &mut Vec<…>`.
    /// Same idiom as `httparse::Request::parse` etc.
    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);

    /// Feed the next chunk of bytes from the **responder** side.
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);

    /// Initiator side has FIN'd. Default: no-op.
    fn fin_initiator(&mut self, _out: &mut Vec<Self::Message>) {}

    /// Responder side has FIN'd.
    fn fin_responder(&mut self, _out: &mut Vec<Self::Message>) {}

    /// Initiator side observed a RST. Default: no-op.
    fn rst_initiator(&mut self) {}

    /// Responder side observed a RST.
    fn rst_responder(&mut self) {}

    /// Periodic time hook. The driver calls this on every `sweep` /
    /// `finish` with the sweep's `now`, for every still-live parser.
    /// Lets stateful parsers emit time-driven messages (timeouts,
    /// unanswered requests). Emitted messages are attributed to
    /// [`FlowSide::Initiator`]. Default: no-op.
    fn on_tick(&mut self, _now: Timestamp, _out: &mut Vec<Self::Message>) {}

    /// True after the parser has hit an unrecoverable error and
    /// can no longer make progress. The driver checks this after
    /// every `feed_*` / `fin_*` call and tears the flow down on
    /// `true`. Default: `false` (parser never poisons).
    ///
    /// Parsers that want to drop a malformed message and keep
    /// going should NOT use this — just don't push the message
    /// into the returned `Vec`. Reserve poison for cases where
    /// internal state is corrupted past recovery (desynced framing,
    /// invalid magic bytes that won't appear later, etc.).
    ///
    /// Mirrors [`crate::Reassembler::is_poisoned`] — same wiring
    /// shape, same operator mental model.
    fn is_poisoned(&self) -> bool {
        false
    }

    /// Optional human-readable description of why the parser
    /// poisoned. Consulted only when [`is_poisoned`](Self::is_poisoned)
    /// returns `true`. Default: `None`.
    ///
    /// The driver truncates to ~256 bytes when forwarding via
    /// [`crate::SessionEvent::FlowAnomaly`].
    fn poison_reason(&self) -> Option<&str> {
        None
    }

    /// Symmetric "I'm done — close this flow cleanly" signal.
    /// Default: `false` (parser never self-terminates).
    ///
    /// Returning `true` tells the driver this parser has no more
    /// useful work to extract — the flow can close ahead of FIN
    /// / idle-timeout. The driver responds by synthesising
    /// [`crate::SessionEvent::Closed`] with
    /// [`crate::EndReason::ParserDone`] on the next check, after
    /// flushing any pending messages from the same `feed_*` /
    /// `on_tick` call.
    ///
    /// Reserve for protocols with intrinsic completion semantics:
    /// HTTP/1.0 `Connection: close` after body fully received;
    /// DNS-over-TCP after a query/response pair; framed protocols
    /// with a session-end sentinel. Do **not** use this to give
    /// up on bad input — that's [`is_poisoned`](Self::is_poisoned),
    /// which routes through [`crate::EndReason::ParseError`].
    ///
    /// Should be idempotent: once `is_done()` returns `true`, it
    /// should keep returning `true` for the lifetime of the parser.
    /// [`is_poisoned`](Self::is_poisoned) takes precedence — a
    /// parser that's both `is_done` and `is_poisoned` surfaces as
    /// `ParseError`, not `ParserDone`.
    fn is_done(&self) -> bool {
        false
    }

    /// Identifier for this parser, threaded into
    /// [`crate::SessionEvent::Application::parser_kind`]. New in
    /// 0.5.0.
    ///
    /// Use a stable, label-safe identifier — operators route
    /// metrics on this string. Convention:
    ///
    /// - Lowercase, ASCII, snake-case or slash-separated
    ///   (`http/1`, `dns-udp`, `rtp`, `length-prefixed`).
    /// - Stable for the lifetime of the parser instance.
    /// - Default: `""` (no kind set).
    ///
    /// `&'static str` rather than `Cow` so the value can flow into
    /// `metrics::counter!` labels without allocation. Parsers
    /// needing a dynamic kind should bake it into
    /// [`Self::Message`].
    fn parser_kind(&self) -> &'static str {
        ""
    }
}

/// Builds a fresh [`SessionParser`] per session. Modeled on
/// [`crate::ReassemblerFactory`].
///
/// Most parsers can skip implementing this manually: any parser
/// that's `SessionParser + Default + Clone` automatically becomes
/// a factory via the blanket impl below.
pub trait SessionParserFactory<K>: Send + 'static {
    type Parser: SessionParser;
    fn new_parser(&mut self, key: &K) -> Self::Parser;
}

impl<K, P> SessionParserFactory<K> for P
where
    P: SessionParser + Default + Clone,
{
    type Parser = P;
    fn new_parser(&mut self, _key: &K) -> P {
        self.clone()
    }
}

/// Parses a packet-oriented L7 protocol. One instance per flow;
/// receives one L4 payload at a time along with which side sent it.
pub trait DatagramParser: Send + 'static {
    /// L7 message produced by this parser. Same `Debug` bound as
    /// [`SessionParser::Message`].
    type Message: Send + std::fmt::Debug + 'static;

    /// Parse one L4 payload. `side` is the direction relative to
    /// the flow's initiator; `ts` is the observed time of the
    /// datagram. Push any complete messages decoded into `out`.
    ///
    /// **0.11 break (plan 119):** signature changed from
    /// `-> Vec<Self::Message>` to taking `out: &mut Vec<…>`.
    fn parse(
        &mut self,
        payload: &[u8],
        side: FlowSide,
        ts: Timestamp,
        out: &mut Vec<Self::Message>,
    );

    /// Periodic time hook — see [`SessionParser::on_tick`]. The
    /// driver calls this on every `sweep` / `finish`. Default: no-op.
    fn on_tick(&mut self, _now: Timestamp, _out: &mut Vec<Self::Message>) {}

    /// True after the parser has hit an unrecoverable error. See
    /// [`SessionParser::is_poisoned`] for the contract.
    fn is_poisoned(&self) -> bool {
        false
    }

    /// Optional reason for poison. See
    /// [`SessionParser::poison_reason`].
    fn poison_reason(&self) -> Option<&str> {
        None
    }

    /// Symmetric "I'm done — close this flow cleanly" signal,
    /// mirroring [`SessionParser::is_done`]. Default: `false`.
    fn is_done(&self) -> bool {
        false
    }

    /// See [`SessionParser::parser_kind`]. Default `""`.
    fn parser_kind(&self) -> &'static str {
        ""
    }
}

/// Builds a fresh [`DatagramParser`] per session.
pub trait DatagramParserFactory<K>: Send + 'static {
    type Parser: DatagramParser;
    fn new_parser(&mut self, key: &K) -> Self::Parser;
}

impl<K, P> DatagramParserFactory<K> for P
where
    P: DatagramParser + Default + Clone,
{
    type Parser = P;
    fn new_parser(&mut self, _key: &K) -> P {
        self.clone()
    }
}

/// Output of a [`SessionParser`] or [`DatagramParser`]-backed stream.
///
/// `K` is the flow key, `M` is the parser's message type.
///
/// `#[non_exhaustive]` to keep future variants additive without
/// breaking exhaustive external `match` blocks. Match with a
/// trailing `_ => {}` arm for forward-compatibility.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "type", rename_all = "snake_case"))]
#[cfg_attr(
    feature = "serde",
    serde(bound(
        serialize = "K: serde::Serialize, M: serde::Serialize",
        deserialize = "K: serde::de::DeserializeOwned, M: serde::de::DeserializeOwned"
    ))
)]
#[non_exhaustive]
pub enum SessionEvent<K, M> {
    /// First packet of a new session.
    Started { key: K, ts: Timestamp },
    /// Parser emitted a complete L7 message.
    Application {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        /// Identifier of the parser that produced this message —
        /// the value returned by [`SessionParser::parser_kind`] (or
        /// [`DatagramParser::parser_kind`] for UDP). New in 0.5.0.
        /// `""` when the parser doesn't override the default.
        parser_kind: &'static str,
    },
    /// Session ended (FIN/RST/idle/eviction). Any messages the
    /// parser flushed on close arrive as `Application` events
    /// before the corresponding `Closed`.
    Closed {
        key: K,
        reason: EndReason,
        stats: FlowStats,
        /// L4 protocol of the flow this session was tracked over.
        /// New in 0.7.0; mirrors [`crate::FlowEvent::Ended::l4`].
        l4: Option<crate::extractor::L4Proto>,
    },
    /// Live, in-flight per-flow anomaly forwarded from
    /// [`crate::FlowEvent::FlowAnomaly`]. Emitted only when the
    /// owning driver has `with_emit_anomalies(true)` set.
    FlowAnomaly {
        key: K,
        kind: AnomalyKind,
        ts: Timestamp,
    },

    /// Live, in-flight tracker-global anomaly forwarded from
    /// [`crate::FlowEvent::TrackerAnomaly`] (e.g.
    /// [`AnomalyKind::FlowTableEvictionPressure`]). Opt-in like
    /// [`Self::FlowAnomaly`].
    TrackerAnomaly { kind: AnomalyKind, ts: Timestamp },

    /// Periodic [`FlowStats`] snapshot forwarded from
    /// [`crate::FlowEvent::Tick`]. Emitted when the underlying
    /// [`crate::FlowTrackerConfig::flow_tick_interval`] is `Some`.
    /// New in 0.5.0.
    FlowTick {
        key: K,
        stats: FlowStats,
        ts: Timestamp,
    },
}

impl<K, M> SessionEvent<K, M> {
    /// Borrow the anomaly kind if this event is an anomaly (either
    /// per-flow or tracker-global). Returns `None` for the
    /// non-anomaly variants.
    pub fn anomaly_kind(&self) -> Option<&AnomalyKind> {
        match self {
            SessionEvent::FlowAnomaly { kind, .. } | SessionEvent::TrackerAnomaly { kind, .. } => {
                Some(kind)
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default, Clone)]
    struct CountParser {
        init_bytes: usize,
        resp_bytes: usize,
    }

    impl SessionParser for CountParser {
        type Message = (FlowSide, usize);
        fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
            self.init_bytes += b.len();
            out.push((FlowSide::Initiator, self.init_bytes));
        }
        fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<Self::Message>) {
            self.resp_bytes += b.len();
            out.push((FlowSide::Responder, self.resp_bytes));
        }
    }

    #[test]
    fn auto_impl_session_parser_factory() {
        // CountParser is Default + Clone + SessionParser → automatic factory.
        let mut f: CountParser = CountParser::default();
        let mut p: CountParser = SessionParserFactory::<u32>::new_parser(&mut f, &7);
        let mut m = Vec::new();
        p.feed_initiator(b"abc", Timestamp::default(), &mut m);
        assert_eq!(m, vec![(FlowSide::Initiator, 3)]);
    }

    #[derive(Default, Clone)]
    struct EchoDgram;
    impl DatagramParser for EchoDgram {
        type Message = (FlowSide, Vec<u8>);
        fn parse(
            &mut self,
            payload: &[u8],
            side: FlowSide,
            _ts: Timestamp,
            out: &mut Vec<Self::Message>,
        ) {
            out.push((side, payload.to_vec()));
        }
    }

    #[test]
    fn auto_impl_datagram_parser_factory() {
        let mut f = EchoDgram;
        let mut p: EchoDgram = DatagramParserFactory::<()>::new_parser(&mut f, &());
        let mut m = Vec::new();
        p.parse(b"hello", FlowSide::Responder, Timestamp::default(), &mut m);
        assert_eq!(m, vec![(FlowSide::Responder, b"hello".to_vec())]);
    }
}
