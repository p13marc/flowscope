//! The shared HTTP/1.x streaming engine.
//!
//! One state machine, two front-ends. The engine always runs in
//! streaming discipline internally — it emits a head as soon as the
//! header block parses, then reports body bytes as spans it does not
//! retain, then trailers, then an end-of-message marker. Nothing here
//! ever buffers a whole body.
//!
//! * [`HttpParser`](super::HttpParser) (passive telemetry) aggregates
//!   the spans back into one [`HttpRequest`](super::HttpRequest) /
//!   [`HttpResponse`](super::HttpResponse) per message.
//! * The inline-proxy front-end (issue #161) forwards the spans as
//!   events without aggregating.
//!
//! Because both front-ends share this machine, framing correctness
//! (chunked decoding, method-aware response framing, and — from
//! issue #163 — the RFC 9112 §6.3 smuggling rules) is implemented
//! exactly once.
//!
//! # Buffer discipline
//!
//! Each direction owns a [`BytesMut`]. Consumed regions are handed
//! out with `split_to(..).freeze()`, so every head, body span, and
//! trailer block is a refcounted view into the fed bytes — no memcpy
//! and no `unsafe` pointer arithmetic (offsets into the head region
//! are computed with plain integer arithmetic before the split).

use std::collections::VecDeque;

use bytes::{Bytes, BytesMut};

use super::poison::HttpPoison;
use super::types::{BodyFraming, HttpVersion, Normalization, SmugglingPolicy, SwitchKind};
use crate::error::{Error, Module};

/// Number of header slots parsed without touching the heap. Requests
/// above this fall back to a `Vec`; the default `max_headers` (64)
/// fits, so the common path allocates nothing per parse.
const HEADER_STACK_SLOTS: usize = 64;

/// Which side of the connection a direction represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Dir {
    /// Client → server: requests.
    Request,
    /// Server → client: responses.
    Response,
}

/// Caps enforced by the engine. Both front-ends map their public
/// config onto this; every field is a hard bound whose breach
/// desyncs the direction rather than growing memory.
#[derive(Debug, Clone)]
pub(crate) struct EngineLimits {
    /// Cap on the start line + header block, before it parses.
    pub max_head_bytes: usize,
    /// Cap on the header count within one message.
    pub max_headers: usize,
    /// Cap on one `<hex-size>[;ext]\r\n` chunk-size line.
    pub max_chunk_line_bytes: usize,
    /// Cap on the whole trailer block (including the zero-size chunk
    /// line and the terminating blank line).
    pub max_trailer_bytes: usize,
    /// Cap on outstanding request contexts awaiting a response.
    pub max_pipelined: usize,
    /// What to do about an ambiguously framed message.
    pub policy: SmugglingPolicy,
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_headers: 64,
            max_chunk_line_bytes: 1024,
            max_trailer_bytes: 8 * 1024,
            max_pipelined: 64,
            policy: SmugglingPolicy::Strict,
        }
    }
}

/// Parsed start line + headers, direction-agnostic.
///
/// The front-ends convert this into their own public shape — the
/// telemetry `HttpRequest` / `HttpResponse`, or (issue #161) the
/// streaming `RequestHead` / `ResponseHead`. The aggregating
/// telemetry front-end has no use for `framing` or `raw`; the
/// streaming one forwards both.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) struct Head {
    // Field order mirrors the wire: start line, then headers.
    pub dir: Dir,
    /// Request method; empty on a response.
    pub method: Bytes,
    /// Request target; empty on a response.
    pub path: Bytes,
    /// Response status; `0` on a request.
    pub status: u16,
    /// Response reason phrase; empty on a request.
    pub reason: Bytes,
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,
    /// How this message's body is delimited, decided here at head
    /// time — for responses using the matching request's method.
    pub framing: BodyFraming,
    /// `true` for a `1xx` interim response: it precedes the final
    /// response, never carries a body, and does not complete the
    /// exchange.
    pub interim: bool,
    /// Normalizations applied to resolve a framing ambiguity. Empty
    /// unless the policy is [`SmugglingPolicy::Normalize`] and the
    /// message needed fixing.
    pub applied: Vec<Normalization>,
    /// The exact on-wire head, start line through the blank line.
    pub raw: Bytes,
}

/// One step of progress on a direction.
///
/// The `raw` fields partition the wire bytes exactly: concatenating
/// `Head::raw` and every subsequent `raw` up to and including
/// [`End`](EngineEvent::End) reproduces the message byte for byte.
/// That is what lets a forwarding proxy relay bytes untouched while
/// the engine tracks boundaries.
///
/// The aggregating telemetry front-end ignores `raw` (it only needs
/// decoded payload); the streaming front-end added in issue #161 is
/// what forwards it.
#[derive(Debug, Clone)]
#[cfg_attr(not(test), allow(dead_code))]
pub(crate) enum EngineEvent {
    Head(Head),
    /// Body progress. `decoded` is payload (empty when the step
    /// consumed only framing bytes such as a chunk-size line);
    /// `raw` is every byte consumed by this step.
    Body {
        decoded: Bytes,
        raw: Bytes,
    },
    /// Trailer section of a chunked body. Always emitted for chunked
    /// framing, possibly with no fields.
    Trailers {
        fields: Vec<(Bytes, Bytes)>,
        raw: Bytes,
    },
    /// The message is fully framed; the next one may follow.
    End,
    /// The connection left HTTP/1.x behind. Both directions stop
    /// parsing; the caller tunnels the remaining bytes verbatim.
    Switch(SwitchKind),
}

/// Body-reading sub-state.
#[derive(Debug, Clone)]
enum BodyState {
    /// `Content-Length`-delimited; `remaining` bytes to go.
    Length { remaining: u64 },
    /// `Transfer-Encoding: chunked`.
    Chunked(ChunkState),
    /// Delimited by connection close.
    UntilClose,
}

/// Position within a chunked body.
#[derive(Debug, Clone)]
enum ChunkState {
    /// Awaiting a `<hex-size>[;ext]\r\n` line.
    Size,
    /// Consuming `remaining` payload bytes.
    Data { remaining: u64 },
    /// Consuming the CRLF that terminates a chunk's data.
    DataCrlf,
    /// Awaiting the trailer section, terminated by a blank line.
    /// The zero-size chunk line has been located but not consumed,
    /// so the whole block can be handed over as one slice.
    Trailer,
}

/// Per-direction state.
#[derive(Debug, Clone)]
enum DirState {
    /// Awaiting a start line + header block.
    Head,
    Body(BodyState),
    /// A protocol switch handed the connection over; nothing further
    /// is parsed here.
    Tunnel,
    /// Clean end of stream. Distinct from [`Desynced`](Self::Desynced):
    /// a FIN on an idle keep-alive connection is not an error.
    Closed,
    /// Framing was lost; the direction yields nothing further.
    Desynced,
}

/// What the engine remembers about a request while its response is
/// outstanding. RFC 9112 §6.3 rules 1–2 make response framing depend
/// on the request method, so this is enqueued when the request head
/// is emitted — not when its body completes, which would be too late
/// for a server that responds while the request body is still in
/// flight.
#[derive(Debug, Clone, Copy)]
struct ReqCtx {
    /// `HEAD` responses carry no body whatever the headers say.
    is_head: bool,
    /// A `2xx` to `CONNECT` turns the connection into a tunnel.
    is_connect: bool,
}

/// One direction's buffer + state.
#[derive(Debug, Clone)]
struct DirMachine {
    buf: BytesMut,
    state: DirState,
    /// Why this direction desynced, if it did.
    poison: Option<HttpPoison>,
    /// The in-flight message asked for the connection to close once
    /// it completes (`Connection: close`, or HTTP/1.0 without
    /// `keep-alive`).
    close_after_message: bool,
    /// How far [`scan_blank_line`] / [`scan_crlf`] has already looked,
    /// so a slowly-fed line is scanned once overall instead of once
    /// per feed.
    scanned: usize,
}

impl DirMachine {
    fn new() -> Self {
        Self {
            buf: BytesMut::new(),
            state: DirState::Head,
            poison: None,
            close_after_message: false,
            scanned: 0,
        }
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.state = DirState::Head;
        self.poison = None;
        self.close_after_message = false;
        self.scanned = 0;
    }

    /// Consume `n` bytes, returning them as a refcounted view.
    fn take(&mut self, n: usize) -> Bytes {
        self.scanned = self.scanned.saturating_sub(n);
        self.buf.split_to(n).freeze()
    }
}

/// The shared HTTP/1.x streaming state machine.
#[derive(Debug, Clone)]
pub(crate) struct Engine {
    limits: EngineLimits,
    request: DirMachine,
    response: DirMachine,
    /// Requests awaiting a response, in wire order.
    pending: VecDeque<ReqCtx>,
    /// A protocol switch to report once the response head that
    /// announced it has been fully framed.
    pending_switch: Option<SwitchKind>,
}

impl Engine {
    pub(crate) fn new(limits: EngineLimits) -> Self {
        Self {
            limits,
            request: DirMachine::new(),
            response: DirMachine::new(),
            pending: VecDeque::new(),
            pending_switch: None,
        }
    }

    fn dir_mut(&mut self, dir: Dir) -> &mut DirMachine {
        match dir {
            Dir::Request => &mut self.request,
            Dir::Response => &mut self.response,
        }
    }

    fn dir(&self, dir: Dir) -> &DirMachine {
        match dir {
            Dir::Request => &self.request,
            Dir::Response => &self.response,
        }
    }

    /// Append bytes to a direction's buffer.
    ///
    /// Bytes are dropped rather than stored once a direction can no
    /// longer parse them — after a desync, a protocol switch, or end
    /// of stream. Holding them would be a slow leak for the rest of
    /// the connection's life: nothing will ever consume them, and on
    /// a poisoned flow the peer may keep sending indefinitely.
    pub(crate) fn push(&mut self, dir: Dir, bytes: &[u8]) {
        if bytes.is_empty() || !self.can_consume(dir) {
            return;
        }
        self.dir_mut(dir).buf.extend_from_slice(bytes);
    }

    /// Whether a direction will still parse what it is given.
    fn can_consume(&self, dir: Dir) -> bool {
        matches!(self.dir(dir).state, DirState::Head | DirState::Body(_))
    }

    pub(crate) fn is_desynced(&self, dir: Dir) -> bool {
        matches!(self.dir(dir).state, DirState::Desynced)
    }

    /// Reset a direction to its initial state (TCP RST).
    pub(crate) fn reset(&mut self, dir: Dir) {
        self.dir_mut(dir).reset();
        if dir == Dir::Request {
            self.pending.clear();
        }
    }

    /// Advance one step.
    ///
    /// `Ok(Some(event))` — progress was made, call again.
    /// `Ok(None)` — more bytes are needed (or the direction is
    /// finished).
    /// `Err(_)` — framing was lost; the direction is now desynced.
    pub(crate) fn poll(&mut self, dir: Dir) -> crate::Result<Option<EngineEvent>> {
        loop {
            let state = self.dir(dir).state.clone();
            match state {
                DirState::Desynced | DirState::Closed | DirState::Tunnel => return Ok(None),
                DirState::Head => match self.poll_head(dir)? {
                    Some(ev) => return Ok(Some(ev)),
                    // Head not complete yet.
                    None => return Ok(None),
                },
                DirState::Body(body) => match self.poll_body(dir, body)? {
                    Progress::Event(ev) => return Ok(Some(ev)),
                    Progress::NeedMore => return Ok(None),
                    // A framing step completed with nothing to report
                    // (e.g. a zero-length body): keep going.
                    Progress::Again => continue,
                },
            }
        }
    }

    /// Signal end of stream on a direction.
    ///
    /// A close-delimited body ends here — that is the only way it can
    /// end. Every other state ends *cleanly*: a FIN on an idle
    /// keep-alive connection is normal, and must not be reported as a
    /// framing failure (a mid-message FIN is truncation, which the
    /// front-end can see from the absence of a preceding `End`).
    pub(crate) fn fin(&mut self, dir: Dir) -> Option<EngineEvent> {
        let m = self.dir_mut(dir);
        match std::mem::replace(&mut m.state, DirState::Closed) {
            DirState::Body(BodyState::UntilClose) => {
                let n = m.buf.len();
                let raw = m.take(n);
                Some(EngineEvent::Body {
                    decoded: raw.clone(),
                    raw,
                })
            }
            // Preserve a desync across FIN; everything else closes.
            DirState::Desynced => {
                m.state = DirState::Desynced;
                None
            }
            // A tunnel outlives a half-close: the switched-to protocol
            // owns the connection, and forgetting the tunnel here would
            // let push() start accepting-and-dropping bytes again — the
            // exact bug the tunnelled-push contract exists to prevent.
            DirState::Tunnel => {
                m.state = DirState::Tunnel;
                None
            }
            _ => None,
        }
    }

    /// `true` once a direction has seen end of stream.
    pub(crate) fn is_closed(&self, dir: Dir) -> bool {
        matches!(self.dir(dir).state, DirState::Closed)
    }

    /// `true` once a protocol switch handed the connection over.
    pub(crate) fn is_tunnelled(&self) -> bool {
        matches!(self.request.state, DirState::Tunnel)
    }

    // ── head ──────────────────────────────────────────────────────

    fn poll_head(&mut self, dir: Dir) -> crate::Result<Option<EngineEvent>> {
        let limits = self.limits.clone();

        // A prior-knowledge HTTP/2 client opens with the connection
        // preface where a request line would be (RFC 9113 §3.4).
        // Recognising it here keeps the parser from reporting a
        // malformed request for perfectly valid h2 traffic.
        if dir == Dir::Request {
            match preface_match(&self.request.buf) {
                PrefaceMatch::Yes => {
                    self.switch_to_tunnel();
                    return Ok(Some(EngineEvent::Switch(SwitchKind::Http2PriorKnowledge)));
                }
                PrefaceMatch::Partial => return Ok(None),
                PrefaceMatch::No => {}
            }
        }

        let m = self.dir_mut(dir);

        let Some(hlen) = scan_blank_line(&m.buf, &mut m.scanned) else {
            if m.buf.len() > limits.max_head_bytes {
                return Err(Self::desync(m, HttpPoison::HeadOverflow));
            }
            return Ok(None);
        };
        if hlen > limits.max_head_bytes {
            return Err(Self::desync(m, HttpPoison::HeadOverflow));
        }

        // Bytes an implementation could read two ways are refused
        // before parsing, so the reason names the actual problem
        // rather than a generic parse failure.
        if limits.policy != SmugglingPolicy::Observe
            && let Err(reason) = check_head_bytes(&m.buf[..hlen])
        {
            return Err(Self::desync(m, reason));
        }

        // Parse offsets while the borrow is live, then take the head
        // region as one refcounted slice and rebuild every field as a
        // zero-copy view into it.
        let parts = match parse_head_offsets(&m.buf[..hlen], dir, limits.max_headers) {
            Ok(p) => p,
            Err(_) => return Err(Self::desync(m, HttpPoison::MalformedHead)),
        };
        let raw = m.take(hlen);
        let head = parts.into_head(dir, &raw, raw.clone());
        let wants_close = signals_close(&head);

        match dir {
            Dir::Request => {
                if self.limits.policy != SmugglingPolicy::Observe
                    && let Err(reason) = check_single_host(&head.headers)
                {
                    let m = self.dir_mut(dir);
                    return Err(Self::desync(m, reason));
                }
                let (framing, applied) = match request_framing(&head.headers, self.limits.policy) {
                    Ok(v) => v,
                    Err(reason) => {
                        let m = self.dir_mut(dir);
                        return Err(Self::desync(m, reason));
                    }
                };
                if self.pending.len() >= self.limits.max_pipelined {
                    let m = self.dir_mut(dir);
                    return Err(Self::desync(m, HttpPoison::PipelineOverflow));
                }
                self.pending.push_back(ReqCtx {
                    is_head: head.method.as_ref().eq_ignore_ascii_case(b"HEAD"),
                    is_connect: head.method.as_ref().eq_ignore_ascii_case(b"CONNECT"),
                });
                let head = Head {
                    framing,
                    applied,
                    ..head
                };
                let m = self.dir_mut(dir);
                m.close_after_message = wants_close;
                m.state = body_state(framing);
                Ok(Some(EngineEvent::Head(head)))
            }
            Dir::Response => self.finish_response_head(head, wants_close),
        }
    }

    /// Frame a response head, applying the interim and tunnel rules.
    ///
    /// `1xx` responses (RFC 9110 §15.2) precede the final response and
    /// never carry a body, so they neither consume the pending request
    /// nor open a body state — a proxy forwards them and keeps
    /// reading. `101` and a `2xx` to `CONNECT` end HTTP framing
    /// altogether.
    fn finish_response_head(
        &mut self,
        head: Head,
        wants_close: bool,
    ) -> crate::Result<Option<EngineEvent>> {
        let status = head.status;

        // 101 Switching Protocols: forward the head, then hand the
        // connection over (RFC 9110 §15.2.2).
        if status == 101 {
            let protocol = header_value(&head.headers, b"upgrade").unwrap_or_default();
            let head = Head {
                framing: BodyFraming::None,
                interim: false,
                ..head
            };
            self.pending.pop_front();
            self.pending_switch = Some(SwitchKind::Upgrade { protocol });
            self.response.state = DirState::Body(BodyState::Length { remaining: 0 });
            return Ok(Some(EngineEvent::Head(head)));
        }

        // Other 1xx: interim. Do not consume the request — the final
        // response for it is still to come.
        if (100..=199).contains(&status) {
            let head = Head {
                framing: BodyFraming::None,
                interim: true,
                ..head
            };
            // Straight back to Head: an interim has no body and does
            // not complete the exchange.
            self.response.state = DirState::Head;
            return Ok(Some(EngineEvent::Head(head)));
        }

        let ctx = self.pending.pop_front();
        if ctx.is_none() && self.limits.policy != SmugglingPolicy::Observe {
            let m = self.dir_mut(Dir::Response);
            return Err(Self::desync(m, HttpPoison::UnexpectedResponse));
        }
        let is_head_request = ctx.is_some_and(|c| c.is_head);

        // A successful CONNECT turns the rest into a tunnel
        // (RFC 9110 §9.3.6).
        if ctx.is_some_and(|c| c.is_connect) && (200..=299).contains(&status) {
            let head = Head {
                framing: BodyFraming::None,
                interim: false,
                ..head
            };
            self.pending_switch = Some(SwitchKind::ConnectTunnel);
            self.response.state = DirState::Body(BodyState::Length { remaining: 0 });
            return Ok(Some(EngineEvent::Head(head)));
        }

        let (framing, applied) =
            match response_framing(status, is_head_request, &head.headers, self.limits.policy) {
                Ok(v) => v,
                Err(reason) => {
                    let m = self.dir_mut(Dir::Response);
                    return Err(Self::desync(m, reason));
                }
            };
        let head = Head {
            framing,
            interim: false,
            applied,
            ..head
        };
        self.response.close_after_message = wants_close;
        self.response.state = body_state(framing);
        Ok(Some(EngineEvent::Head(head)))
    }

    /// Put both directions into tunnel state.
    ///
    /// Bytes already buffered past the switch point are NOT discarded:
    /// they are the first bytes of the switched-to protocol (a server
    /// that flushes `101` + the first WebSocket frames in one segment,
    /// an h2 client's preface+SETTINGS+HEADERS in one write) and the
    /// caller must splice them. They stay in the direction buffers,
    /// retrievable once via [`Engine::take_residue`]; `push` refuses
    /// further bytes, so the residue is bounded by what arrived with
    /// the switch.
    fn switch_to_tunnel(&mut self) {
        self.request.state = DirState::Tunnel;
        self.response.state = DirState::Tunnel;
        self.pending.clear();
    }

    /// Take (and clear) the bytes a direction had buffered when the
    /// connection switched protocols. Empty if not tunnelled, or if
    /// already taken.
    pub(crate) fn take_residue(&mut self, dir: Dir) -> Bytes {
        if !self.is_tunnelled() {
            return Bytes::new();
        }
        let m = self.dir_mut(dir);
        let n = m.buf.len();
        m.take(n)
    }

    // ── body ──────────────────────────────────────────────────────

    fn poll_body(&mut self, dir: Dir, body: BodyState) -> crate::Result<Progress> {
        match body {
            BodyState::Length { remaining: 0 } => {
                // A switch announced by this message takes effect now
                // that it is fully framed.
                if let Some(kind) = self.pending_switch.take() {
                    self.switch_to_tunnel();
                    return Ok(Progress::Event(EngineEvent::Switch(kind)));
                }
                let m = self.dir_mut(dir);
                m.state = if m.close_after_message {
                    // The peer said it will close once this message
                    // ends, so nothing more can arrive on this
                    // direction.
                    DirState::Closed
                } else {
                    DirState::Head
                };
                Ok(Progress::Event(EngineEvent::End))
            }
            BodyState::Length { remaining } => {
                let m = self.dir_mut(dir);
                let take = remaining.min(m.buf.len() as u64) as usize;
                if take == 0 {
                    return Ok(Progress::NeedMore);
                }
                let raw = m.take(take);
                m.state = DirState::Body(BodyState::Length {
                    remaining: remaining - take as u64,
                });
                Ok(Progress::Event(EngineEvent::Body {
                    decoded: raw.clone(),
                    raw,
                }))
            }
            BodyState::UntilClose => {
                let m = self.dir_mut(dir);
                let n = m.buf.len();
                if n == 0 {
                    return Ok(Progress::NeedMore);
                }
                let raw = m.take(n);
                Ok(Progress::Event(EngineEvent::Body {
                    decoded: raw.clone(),
                    raw,
                }))
            }
            BodyState::Chunked(cs) => self.poll_chunked(dir, cs),
        }
    }

    fn poll_chunked(&mut self, dir: Dir, cs: ChunkState) -> crate::Result<Progress> {
        let limits = self.limits.clone();
        let m = self.dir_mut(dir);
        match cs {
            ChunkState::Size => {
                let Some(eol) = scan_crlf(&m.buf, &mut m.scanned) else {
                    if m.buf.len() > limits.max_chunk_line_bytes {
                        return Err(Self::desync(m, HttpPoison::ChunkLineOverflow));
                    }
                    return Ok(Progress::NeedMore);
                };
                if eol > limits.max_chunk_line_bytes {
                    return Err(Self::desync(m, HttpPoison::ChunkLineOverflow));
                }
                let line = &m.buf[..eol];
                let hex_end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
                let Some(size) = parse_hex(line[..hex_end].trim_ascii()) else {
                    return Err(Self::desync(m, HttpPoison::InvalidChunkSize));
                };
                if size == 0 {
                    // Leave the zero-size line in the buffer so the
                    // trailer block can be handed over as one slice.
                    m.state = DirState::Body(BodyState::Chunked(ChunkState::Trailer));
                    return Ok(Progress::Again);
                }
                let raw = m.take(eol + 2);
                m.state = DirState::Body(BodyState::Chunked(ChunkState::Data { remaining: size }));
                Ok(Progress::Event(EngineEvent::Body {
                    decoded: Bytes::new(),
                    raw,
                }))
            }
            ChunkState::Data { remaining } => {
                let take = remaining.min(m.buf.len() as u64) as usize;
                if take == 0 {
                    return Ok(Progress::NeedMore);
                }
                let raw = m.take(take);
                let left = remaining - take as u64;
                m.state = DirState::Body(BodyState::Chunked(if left == 0 {
                    ChunkState::DataCrlf
                } else {
                    ChunkState::Data { remaining: left }
                }));
                Ok(Progress::Event(EngineEvent::Body {
                    decoded: raw.clone(),
                    raw,
                }))
            }
            ChunkState::DataCrlf => {
                if m.buf.len() < 2 {
                    return Ok(Progress::NeedMore);
                }
                if &m.buf[..2] != b"\r\n" {
                    return Err(Self::desync(m, HttpPoison::MalformedChunkTerminator));
                }
                let raw = m.take(2);
                m.state = DirState::Body(BodyState::Chunked(ChunkState::Size));
                Ok(Progress::Event(EngineEvent::Body {
                    decoded: Bytes::new(),
                    raw,
                }))
            }
            ChunkState::Trailer => {
                // The buffer starts at the zero-size chunk line; the
                // section ends at the first blank line after it.
                let Some(end) = scan_trailer_end(&m.buf, &mut m.scanned) else {
                    if m.buf.len() > limits.max_trailer_bytes {
                        return Err(Self::desync(m, HttpPoison::TrailerOverflow));
                    }
                    return Ok(Progress::NeedMore);
                };
                if end > limits.max_trailer_bytes {
                    return Err(Self::desync(m, HttpPoison::TrailerOverflow));
                }
                let raw = m.take(end);
                let fields = parse_trailer_fields(&raw);
                // The body is complete; the zero-length state emits
                // `End` on the next poll and returns to `Head`.
                m.state = DirState::Body(BodyState::Length { remaining: 0 });
                Ok(Progress::Event(EngineEvent::Trailers { fields, raw }))
            }
        }
    }

    /// Mark a direction desynced, recording why, and build the error
    /// the front-end sees.
    fn desync(m: &mut DirMachine, reason: HttpPoison) -> Error {
        m.state = DirState::Desynced;
        m.poison = Some(reason);
        m.buf.clear();
        m.scanned = 0;
        match reason {
            HttpPoison::HeadOverflow
            | HttpPoison::ChunkLineOverflow
            | HttpPoison::TrailerOverflow => Error::buffer_overflow(Module::Http, 0),
            other => Error::parse(Module::Http, other.as_str()),
        }
    }

    /// Why a direction gave up, if it did.
    pub(crate) fn poison(&self, dir: Dir) -> Option<HttpPoison> {
        self.dir(dir).poison
    }

    /// Bytes buffered but not yet consumed on a direction. The
    /// streaming front-end uses this to bound how much it accepts.
    pub(crate) fn buffered(&self, dir: Dir) -> usize {
        self.dir(dir).buf.len()
    }
}

/// Outcome of one body step.
enum Progress {
    Event(EngineEvent),
    NeedMore,
    /// State advanced with nothing to report; poll again immediately.
    Again,
}

// ── framing rules (RFC 9112 §6.3) ─────────────────────────────────

/// Body framing for a request.
///
/// Per RFC 9112 §6.3 rule 6, a request with neither `Transfer-Encoding`
/// nor `Content-Length` has **no body** — regardless of method. (The
/// pre-0.23 parser ran bodied methods to EOF here, which mis-framed a
/// `POST` with no length on a keep-alive connection.)
fn request_framing(
    headers: &[(Bytes, Bytes)],
    policy: SmugglingPolicy,
) -> Result<(BodyFraming, Vec<Normalization>), HttpPoison> {
    let (te, cl, applied) = framing_headers(headers, policy)?;
    if te {
        return Ok((BodyFraming::Chunked, applied));
    }
    // §6.3 rule 6: a request with neither is bodyless.
    Ok(match cl {
        Some(0) | None => (BodyFraming::None, applied),
        Some(n) => (BodyFraming::ContentLength(n), applied),
    })
}

/// Resolve `Transfer-Encoding` and `Content-Length` into a single
/// unambiguous framing decision — the RFC 9112 §6.3 rules that every
/// smuggling technique attacks.
///
/// Returns `(chunked, content_length, normalizations)`.
///
/// | Situation | `Strict` | `Normalize` | `Observe` |
/// |---|---|---|---|
/// | `CL` + `TE` | poison | drop `CL`, use chunked | chunked wins |
/// | repeated `CL`, all equal | collapse | collapse | collapse |
/// | repeated `CL`, differing | poison | poison | first wins |
/// | `CL` not a plain number | poison | poison | ignored |
/// | `TE` not ending in `chunked` | poison | poison | ignored |
/// | unknown transfer coding | poison | poison | ignored |
/// | repeated `TE` (TE.TE) | poison | poison | chunked if any |
fn framing_headers(
    headers: &[(Bytes, Bytes)],
    policy: SmugglingPolicy,
) -> Result<(bool, Option<u64>, Vec<Normalization>), HttpPoison> {
    let observe = policy == SmugglingPolicy::Observe;
    let mut applied = Vec::new();

    // ── Transfer-Encoding ──
    let te_values: Vec<&Bytes> = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(b"transfer-encoding"))
        .map(|(_, v)| v)
        .collect();

    let mut chunked = false;
    if !te_values.is_empty() {
        if te_values.len() > 1 && !observe {
            return Err(HttpPoison::DuplicateTransferEncoding);
        }
        let codings: Vec<&[u8]> = te_values
            .iter()
            .flat_map(|v| v.split(|&b| b == b','))
            .map(|t| t.trim_ascii())
            .filter(|t| !t.is_empty())
            .collect();
        chunked = codings
            .last()
            .is_some_and(|t| t.eq_ignore_ascii_case(b"chunked"));
        if !observe {
            // Only `chunked` and `identity` are understood, and
            // `chunked` must come last or the length is undefined.
            for (i, coding) in codings.iter().enumerate() {
                let is_chunked = coding.eq_ignore_ascii_case(b"chunked");
                if !is_chunked && !coding.eq_ignore_ascii_case(b"identity") {
                    return Err(HttpPoison::UnknownTransferCoding);
                }
                if is_chunked && i != codings.len() - 1 {
                    return Err(HttpPoison::NonFinalChunked);
                }
            }
            if !chunked {
                return Err(HttpPoison::NonFinalChunked);
            }
        } else {
            chunked = codings.iter().any(|t| t.eq_ignore_ascii_case(b"chunked"));
        }
    }

    // ── Content-Length ──
    // One header may itself carry a comma-separated list; every value
    // across every header has to agree.
    let mut lengths: Vec<u64> = Vec::new();
    let mut saw_cl = false;
    for (_, v) in headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(b"content-length"))
    {
        saw_cl = true;
        for part in v.split(|&b| b == b',') {
            let t = part.trim_ascii();
            if t.is_empty() {
                continue;
            }
            match parse_decimal(t) {
                Some(n) => lengths.push(n),
                None if observe => {}
                None => return Err(HttpPoison::InvalidContentLength),
            }
        }
    }
    let content_length = if lengths.is_empty() {
        if saw_cl && !observe && !chunked {
            // A `Content-Length` header that yielded no usable value.
            return Err(HttpPoison::InvalidContentLength);
        }
        None
    } else {
        let first = lengths[0];
        if lengths.iter().any(|n| *n != first) {
            if !observe {
                return Err(HttpPoison::ConflictingContentLength);
            }
        } else if lengths.len() > 1 {
            applied.push(Normalization::CollapsedContentLength);
        }
        Some(first)
    };

    // ── the two together ──
    if chunked && content_length.is_some() {
        match policy {
            SmugglingPolicy::Strict => {
                return Err(HttpPoison::ContentLengthWithTransferEncoding);
            }
            // §6.3.3: the length is dropped and chunked framing wins.
            SmugglingPolicy::Normalize => applied.push(Normalization::StrippedContentLength),
            SmugglingPolicy::Observe => {}
        }
        return Ok((true, None, applied));
    }

    Ok((chunked, content_length, applied))
}

/// Parse a `Content-Length` value: ASCII digits only.
///
/// Deliberately stricter than `str::parse`, which accepts a leading
/// `+`. A recipient that ignores the sign and one that rejects it
/// disagree about the body length.
fn parse_decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(bytes).ok()?.parse().ok()
}

/// Reject head bytes that two recipients could read differently.
///
/// Obs-fold (RFC 9112 §5.2, deprecated) and a bare CR (§2.2) are both
/// parsed inconsistently across implementations, so under any policy
/// but [`Observe`](SmugglingPolicy::Observe) they are refused rather
/// than guessed at. Rejecting is what §5.2 permits a proxy to do, and
/// the alternative — rewriting the field — would mean the `raw` bytes
/// no longer match what the parser saw.
fn check_head_bytes(head: &[u8]) -> Result<(), HttpPoison> {
    let mut i = 0;
    while i < head.len() {
        match head[i] {
            b'\r' => {
                if head.get(i + 1) != Some(&b'\n') {
                    return Err(HttpPoison::BareCr);
                }
                // A line beginning with SP or HTAB continues the one
                // before it: an obs-fold.
                if i > 0
                    && matches!(head.get(i + 2), Some(b' ') | Some(b'\t'))
                    && head.get(i + 3).is_some()
                {
                    return Err(HttpPoison::ObsFold);
                }
                i += 2;
            }
            _ => i += 1,
        }
    }
    Ok(())
}

/// Reject a duplicated `Host`, which two hops could route on
/// differently.
fn check_single_host(headers: &[(Bytes, Bytes)]) -> Result<(), HttpPoison> {
    let n = headers
        .iter()
        .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(b"host"))
        .count();
    if n > 1 {
        return Err(HttpPoison::DuplicateHost);
    }
    Ok(())
}

/// Body framing for a response, given the matching request's method.
///
/// RFC 9112 §6.3 rules 1–2: responses to `HEAD`, and all `1xx` / `204`
/// / `304` responses, have no body even when they carry a
/// `Content-Length` or `Transfer-Encoding`.
fn response_framing(
    status: u16,
    request_was_head: bool,
    headers: &[(Bytes, Bytes)],
    policy: SmugglingPolicy,
) -> Result<(BodyFraming, Vec<Normalization>), HttpPoison> {
    if request_was_head || matches!(status, 100..=199 | 204 | 304) {
        return Ok((BodyFraming::None, Vec::new()));
    }
    let (te, cl, applied) = framing_headers(headers, policy)?;
    if te {
        return Ok((BodyFraming::Chunked, applied));
    }
    Ok(match cl {
        Some(0) => (BodyFraming::None, applied),
        Some(n) => (BodyFraming::ContentLength(n), applied),
        // No length and no chunked framing: the body runs to close.
        None => (BodyFraming::UntilClose, applied),
    })
}

/// The body state a freshly framed message starts in.
fn body_state(framing: BodyFraming) -> DirState {
    match framing {
        BodyFraming::None => DirState::Body(BodyState::Length { remaining: 0 }),
        BodyFraming::ContentLength(n) => DirState::Body(BodyState::Length { remaining: n }),
        BodyFraming::Chunked => DirState::Body(BodyState::Chunked(ChunkState::Size)),
        BodyFraming::UntilClose => DirState::Body(BodyState::UntilClose),
    }
}

/// The 24-octet HTTP/2 client connection preface (RFC 9113 §3.4).
const H2_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

/// Whether a buffer starts the HTTP/2 preface.
enum PrefaceMatch {
    Yes,
    /// A prefix so far — `PRI ` also starts a plausible HTTP/1
    /// request line, so nothing can be decided yet.
    Partial,
    No,
}

fn preface_match(buf: &[u8]) -> PrefaceMatch {
    let n = buf.len().min(H2_PREFACE.len());
    if buf[..n] != H2_PREFACE[..n] {
        return PrefaceMatch::No;
    }
    if buf.len() >= H2_PREFACE.len() {
        PrefaceMatch::Yes
    } else {
        PrefaceMatch::Partial
    }
}

/// First value of a header, case-insensitively.
fn header_value(headers: &[(Bytes, Bytes)], name: &[u8]) -> Option<Bytes> {
    headers
        .iter()
        .find(|(k, _)| k.as_ref().eq_ignore_ascii_case(name))
        .map(|(_, v)| v.clone())
}

/// Whether a message says the connection closes once it completes.
///
/// HTTP/1.1 defaults to persistent connections and opts out with
/// `Connection: close`; HTTP/1.0 defaults the other way and opts in
/// with `Connection: keep-alive` (RFC 9112 §9.3).
fn signals_close(head: &Head) -> bool {
    let tokens = |name: &[u8], want: &[u8]| {
        head.headers
            .iter()
            .filter(|(k, _)| k.as_ref().eq_ignore_ascii_case(name))
            .any(|(_, v)| {
                v.split(|&b| b == b',')
                    .any(|t| t.trim_ascii().eq_ignore_ascii_case(want))
            })
    };
    if tokens(b"connection", b"close") {
        return true;
    }
    head.version == HttpVersion::Http1_0 && !tokens(b"connection", b"keep-alive")
}

// ── head parsing ──────────────────────────────────────────────────

/// Byte range within the head region.
type Span = (usize, usize);

/// Offsets of every field within the head region, captured while the
/// `httparse` borrow is alive so the region can then be taken as one
/// refcounted slice.
struct HeadOffsets {
    method: Span,
    path: Span,
    status: u16,
    reason: Span,
    version: HttpVersion,
    headers: Vec<(Span, Span)>,
}

impl HeadOffsets {
    fn into_head(self, dir: Dir, region: &Bytes, raw: Bytes) -> Head {
        let cut = |(off, len): Span| -> Bytes {
            if len == 0 {
                Bytes::new()
            } else {
                region.slice(off..off + len)
            }
        };
        Head {
            dir,
            method: cut(self.method),
            path: cut(self.path),
            status: self.status,
            reason: cut(self.reason),
            version: self.version,
            headers: self
                .headers
                .into_iter()
                .map(|(n, v)| (cut(n), cut(v)))
                .collect(),
            // All replaced by the caller once framing is known.
            framing: BodyFraming::None,
            interim: false,
            applied: Vec::new(),
            raw,
        }
    }
}

/// Offset of `sub` within `base`.
///
/// Both slices come from the same allocation (`sub` is always a
/// sub-slice `httparse` carved out of `base`). Casting the pointers to
/// integers is safe — no `unsafe`, no provenance games — and the
/// debug assertion catches any future misuse.
#[inline]
fn span_of(base: &[u8], sub: &[u8]) -> Span {
    let off = (sub.as_ptr() as usize).saturating_sub(base.as_ptr() as usize);
    debug_assert!(
        off + sub.len() <= base.len(),
        "sub-slice must lie within the head region"
    );
    (off.min(base.len()), sub.len())
}

fn parse_head_offsets(head: &[u8], dir: Dir, max_headers: usize) -> crate::Result<HeadOffsets> {
    let mut stack = [httparse::EMPTY_HEADER; HEADER_STACK_SLOTS];
    let mut heap;
    let storage: &mut [httparse::Header<'_>] = if max_headers <= HEADER_STACK_SLOTS {
        &mut stack[..max_headers.max(1)]
    } else {
        heap = vec![httparse::EMPTY_HEADER; max_headers];
        &mut heap[..]
    };

    match dir {
        Dir::Request => {
            let mut req = httparse::Request::new(storage);
            match req.parse(head) {
                Ok(httparse::Status::Complete(_)) => {}
                Ok(httparse::Status::Partial) => {
                    return Err(Error::parse(Module::Http, "incomplete request head"));
                }
                Err(e) => return Err(Error::parse_with(Module::Http, "httparse failed", e)),
            }
            let method = req
                .method
                .ok_or_else(|| Error::parse(Module::Http, "missing method"))?;
            let path = req
                .path
                .ok_or_else(|| Error::parse(Module::Http, "missing path"))?;
            Ok(HeadOffsets {
                method: span_of(head, method.as_bytes()),
                path: span_of(head, path.as_bytes()),
                status: 0,
                reason: (0, 0),
                version: version_of(req.version)?,
                headers: header_spans(head, req.headers),
            })
        }
        Dir::Response => {
            let mut resp = httparse::Response::new(storage);
            match resp.parse(head) {
                Ok(httparse::Status::Complete(_)) => {}
                Ok(httparse::Status::Partial) => {
                    return Err(Error::parse(Module::Http, "incomplete response head"));
                }
                Err(e) => return Err(Error::parse_with(Module::Http, "httparse failed", e)),
            }
            let status = resp
                .code
                .ok_or_else(|| Error::parse(Module::Http, "missing status code"))?;
            let reason = resp.reason.unwrap_or("");
            Ok(HeadOffsets {
                method: (0, 0),
                path: (0, 0),
                status,
                reason: if reason.is_empty() {
                    (0, 0)
                } else {
                    span_of(head, reason.as_bytes())
                },
                version: version_of(resp.version)?,
                headers: header_spans(head, resp.headers),
            })
        }
    }
}

fn version_of(v: Option<u8>) -> crate::Result<HttpVersion> {
    match v.ok_or_else(|| Error::parse(Module::Http, "missing version"))? {
        0 => Ok(HttpVersion::Http1_0),
        1 => Ok(HttpVersion::Http1_1),
        other => Err(Error::parse(
            Module::Http,
            format!("unknown version: {other}"),
        )),
    }
}

fn header_spans(head: &[u8], hs: &[httparse::Header<'_>]) -> Vec<(Span, Span)> {
    let n = hs.iter().take_while(|h| !h.name.is_empty()).count();
    let mut out = Vec::with_capacity(n);
    for h in hs.iter().take(n) {
        out.push((span_of(head, h.name.as_bytes()), span_of(head, h.value)));
    }
    out
}

/// Split a trailer section into fields. The block starts with the
/// zero-size chunk line and ends with a blank line; anything that is
/// not a well-formed `name: value` line is skipped rather than
/// rejected (issue #163 tightens this).
fn parse_trailer_fields(block: &Bytes) -> Vec<(Bytes, Bytes)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    // Skip the zero-size chunk line.
    if let Some(eol) = find_crlf_from(block, 0) {
        pos = eol + 2;
    }
    while pos < block.len() {
        let Some(eol) = find_crlf_from(block, pos) else {
            break;
        };
        if eol == pos {
            break; // blank line: end of section
        }
        let line = &block[pos..eol];
        if let Some(colon) = line.iter().position(|&b| b == b':') {
            let name = (pos, colon);
            let value_start = pos + colon + 1;
            let trimmed = block[value_start..eol].len()
                - block[value_start..eol]
                    .iter()
                    .rev()
                    .take_while(|b| b.is_ascii_whitespace())
                    .count();
            let lead = block[value_start..eol]
                .iter()
                .take_while(|b| **b == b' ' || **b == b'\t')
                .count();
            out.push((
                block.slice(name.0..name.0 + name.1),
                block.slice(value_start + lead..value_start + trimmed.max(lead)),
            ));
        }
        pos = eol + 2;
    }
    out
}

// ── scanning ──────────────────────────────────────────────────────

/// Index of the first CRLF at or after `from`.
fn find_crlf_from(buf: &[u8], from: usize) -> Option<usize> {
    if from >= buf.len() {
        return None;
    }
    buf[from..]
        .windows(2)
        .position(|w| w == b"\r\n")
        .map(|p| p + from)
}

/// Length of the head region including its terminating blank line, or
/// `None` if it has not arrived yet.
///
/// `scanned` is a resume point: a header block fed one byte at a time
/// is scanned once in total rather than once per feed. Bare-LF line
/// endings are accepted here because `httparse` accepts them; issue
/// #163 makes that a policy decision.
fn scan_blank_line(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    let start = (*scanned).saturating_sub(3);
    let mut i = start;
    while i < buf.len() {
        if buf[i] == b'\n' {
            // "\n\n"
            if i >= 1 && buf[i - 1] == b'\n' {
                *scanned = i + 1;
                return Some(i + 1);
            }
            // "\r\n\r\n"
            if i >= 3 && buf[i - 1] == b'\r' && buf[i - 2] == b'\n' && buf[i - 3] == b'\r' {
                *scanned = i + 1;
                return Some(i + 1);
            }
        }
        i += 1;
    }
    *scanned = buf.len();
    None
}

/// Index of the first CRLF, resuming from `scanned`.
fn scan_crlf(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    let start = (*scanned).saturating_sub(1);
    if let Some(pos) = find_crlf_from(buf, start) {
        *scanned = pos;
        return Some(pos);
    }
    *scanned = buf.len();
    None
}

/// Length of a trailer section that begins at the zero-size chunk
/// line, including the terminating blank line.
fn scan_trailer_end(buf: &[u8], scanned: &mut usize) -> Option<usize> {
    // The section is `0\r\n` [ trailer-field CRLF ]* CRLF.
    let Some(first) = find_crlf_from(buf, 0) else {
        *scanned = buf.len();
        return None;
    };
    let mut pos = first + 2;
    loop {
        match find_crlf_from(buf, pos) {
            Some(eol) if eol == pos => {
                *scanned = 0;
                return Some(eol + 2);
            }
            Some(eol) => pos = eol + 2,
            None => {
                *scanned = buf.len();
                return None;
            }
        }
    }
}

/// Parse an ASCII-hex chunk size.
fn parse_hex(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    u64::from_str_radix(s, 16).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn engine() -> Engine {
        Engine::new(EngineLimits::default())
    }

    fn drain(e: &mut Engine, dir: Dir) -> Vec<EngineEvent> {
        let mut out = Vec::new();
        while let Ok(Some(ev)) = e.poll(dir) {
            out.push(ev);
        }
        out
    }

    /// Pull the framing decided for the next head on `dir`.
    fn framing_of(e: &mut Engine, dir: Dir) -> BodyFraming {
        loop {
            match e.poll(dir) {
                Ok(Some(EngineEvent::Head(h))) => return h.framing,
                Ok(Some(_)) => continue,
                other => panic!("expected a head, got {other:?}"),
            }
        }
    }

    #[test]
    fn framing_follows_rfc_9112_section_6_3() {
        // Rule 6: a request with neither TE nor CL has no body.
        let mut e = engine();
        e.push(Dir::Request, b"POST /a HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(framing_of(&mut e, Dir::Request), BodyFraming::None);

        // Chunked frames the body when it is the only signal.
        let mut e = engine();
        e.push(
            Dir::Request,
            b"POST /a HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n",
        );
        assert_eq!(framing_of(&mut e, Dir::Request), BodyFraming::Chunked);

        // A length frames exactly that many bytes.
        let mut e = engine();
        e.push(
            Dir::Request,
            b"POST /a HTTP/1.1\r\nContent-Length: 7\r\n\r\n",
        );
        assert_eq!(
            framing_of(&mut e, Dir::Request),
            BodyFraming::ContentLength(7)
        );

        // Rule 1: a response to HEAD has no body despite a length.
        let mut e = engine();
        e.push(Dir::Request, b"HEAD /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut e, Dir::Request);
        e.push(
            Dir::Response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 9\r\n\r\n",
        );
        assert_eq!(framing_of(&mut e, Dir::Response), BodyFraming::None);

        // A response with no length runs to connection close.
        let mut e = engine();
        e.push(Dir::Request, b"GET /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut e, Dir::Request);
        e.push(Dir::Response, b"HTTP/1.1 200 OK\r\n\r\n");
        assert_eq!(framing_of(&mut e, Dir::Response), BodyFraming::UntilClose);
    }

    #[test]
    fn request_head_then_end_for_bodyless() {
        let mut e = engine();
        e.push(Dir::Request, b"GET /a HTTP/1.1\r\nHost: x\r\n\r\n");
        let evs = drain(&mut e, Dir::Request);
        assert!(matches!(evs[0], EngineEvent::Head(_)));
        assert!(matches!(evs[1], EngineEvent::End));
        assert_eq!(evs.len(), 2);
    }

    #[test]
    fn chunked_body_is_decoded_and_reassembles_wire_bytes() {
        let mut e = engine();
        let wire: &[u8] = b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                            5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n";
        e.push(Dir::Request, wire);
        let evs = drain(&mut e, Dir::Request);

        let mut decoded = Vec::new();
        let mut raw = Vec::new();
        for ev in &evs {
            match ev {
                EngineEvent::Head(h) => raw.extend_from_slice(&h.raw),
                EngineEvent::Body { decoded: d, raw: r } => {
                    decoded.extend_from_slice(d);
                    raw.extend_from_slice(r);
                }
                EngineEvent::Trailers { raw: r, .. } => raw.extend_from_slice(r),
                EngineEvent::End | EngineEvent::Switch(_) => {}
            }
        }
        assert_eq!(decoded, b"hello world");
        assert_eq!(raw, wire, "raw spans must reproduce the wire bytes");
        assert!(matches!(evs.last(), Some(EngineEvent::End)));
    }

    #[test]
    fn head_response_has_no_body_despite_content_length() {
        let mut e = engine();
        e.push(
            Dir::Request,
            b"HEAD /x HTTP/1.1\r\n\r\nGET /y HTTP/1.1\r\n\r\n",
        );
        let _ = drain(&mut e, Dir::Request);
        e.push(
            Dir::Response,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        );
        let evs = drain(&mut e, Dir::Response);
        // Two complete responses, no body consumed for either.
        let heads: Vec<u16> = evs
            .iter()
            .filter_map(|ev| match ev {
                EngineEvent::Head(h) => Some(h.status),
                _ => None,
            })
            .collect();
        assert_eq!(heads, vec![200, 204]);
    }

    #[test]
    fn clean_fin_does_not_desync() {
        let mut e = engine();
        e.push(Dir::Request, b"GET / HTTP/1.1\r\n\r\n");
        let _ = drain(&mut e, Dir::Request);
        assert!(e.fin(Dir::Request).is_none());
        assert!(!e.is_desynced(Dir::Request), "clean FIN must not desync");
        assert!(e.is_closed(Dir::Request));
    }

    #[test]
    fn until_close_body_flushes_at_fin() {
        let mut e = engine();
        e.push(Dir::Request, b"GET / HTTP/1.1\r\n\r\n");
        let _ = drain(&mut e, Dir::Request);
        e.push(Dir::Response, b"HTTP/1.1 200 OK\r\n\r\nhel");
        let evs = drain(&mut e, Dir::Response);
        assert!(matches!(evs[0], EngineEvent::Head(_)));
        e.push(Dir::Response, b"lo");
        let _ = drain(&mut e, Dir::Response);
        let flushed = e.fin(Dir::Response);
        assert!(matches!(flushed, Some(EngineEvent::Body { .. })));
    }

    #[test]
    fn byte_at_a_time_matches_one_shot() {
        let wire: &[u8] = b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                            3\r\nabc\r\n0\r\n\r\n";
        let mut whole = engine();
        whole.push(Dir::Request, wire);
        let a = drain(&mut whole, Dir::Request);

        let mut split = engine();
        let mut b = Vec::new();
        for byte in wire {
            split.push(Dir::Request, std::slice::from_ref(byte));
            b.extend(drain(&mut split, Dir::Request));
        }
        let decoded = |evs: &[EngineEvent]| -> Vec<u8> {
            let mut v = Vec::new();
            for ev in evs {
                if let EngineEvent::Body { decoded, .. } = ev {
                    v.extend_from_slice(decoded);
                }
            }
            v
        };
        assert_eq!(decoded(&a), decoded(&b));
        assert_eq!(decoded(&b), b"abc");
    }

    #[test]
    fn oversized_head_desyncs_instead_of_growing() {
        let limits = EngineLimits {
            max_head_bytes: 64,
            ..EngineLimits::default()
        };
        let mut e = Engine::new(limits);
        e.push(Dir::Request, &[b'A'; 200]);
        assert!(e.poll(Dir::Request).is_err());
        assert!(e.is_desynced(Dir::Request));
    }
}
