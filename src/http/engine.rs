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
use super::types::{BodyFraming, HttpVersion};
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
}

impl Default for EngineLimits {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_headers: 64,
            max_chunk_line_bytes: 1024,
            max_trailer_bytes: 8 * 1024,
            max_pipelined: 64,
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
}

/// One direction's buffer + state.
#[derive(Debug, Clone)]
struct DirMachine {
    buf: BytesMut,
    state: DirState,
    /// Why this direction desynced, if it did.
    poison: Option<HttpPoison>,
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
            scanned: 0,
        }
    }

    fn reset(&mut self) {
        self.buf.clear();
        self.state = DirState::Head;
        self.poison = None;
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
}

impl Engine {
    pub(crate) fn new(limits: EngineLimits) -> Self {
        Self {
            limits,
            request: DirMachine::new(),
            response: DirMachine::new(),
            pending: VecDeque::new(),
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
    pub(crate) fn push(&mut self, dir: Dir, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.dir_mut(dir).buf.extend_from_slice(bytes);
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
                DirState::Desynced | DirState::Closed => return Ok(None),
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
            _ => None,
        }
    }

    /// `true` once a direction has seen end of stream.
    pub(crate) fn is_closed(&self, dir: Dir) -> bool {
        matches!(self.dir(dir).state, DirState::Closed)
    }

    // ── head ──────────────────────────────────────────────────────

    fn poll_head(&mut self, dir: Dir) -> crate::Result<Option<EngineEvent>> {
        let limits = self.limits.clone();
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

        // Parse offsets while the borrow is live, then take the head
        // region as one refcounted slice and rebuild every field as a
        // zero-copy view into it.
        let parts = match parse_head_offsets(&m.buf[..hlen], dir, limits.max_headers) {
            Ok(p) => p,
            Err(_) => return Err(Self::desync(m, HttpPoison::MalformedHead)),
        };
        let raw = m.take(hlen);
        let head = parts.into_head(dir, &raw, raw.clone());

        // Response framing needs the request method (§6.3 rules 1-2).
        let framing = match dir {
            Dir::Request => request_framing(&head.headers),
            Dir::Response => {
                let ctx = self.pending.pop_front();
                response_framing(head.status, ctx.is_some_and(|c| c.is_head), &head.headers)
            }
        };
        if dir == Dir::Request {
            if self.pending.len() >= self.limits.max_pipelined {
                let m = self.dir_mut(dir);
                return Err(Self::desync(m, HttpPoison::PipelineOverflow));
            }
            self.pending.push_back(ReqCtx {
                is_head: head.method.as_ref().eq_ignore_ascii_case(b"HEAD"),
            });
        }

        let head = Head { framing, ..head };
        let next = match framing {
            BodyFraming::None => DirState::Body(BodyState::Length { remaining: 0 }),
            BodyFraming::ContentLength(n) => DirState::Body(BodyState::Length { remaining: n }),
            BodyFraming::Chunked => DirState::Body(BodyState::Chunked(ChunkState::Size)),
            BodyFraming::UntilClose => DirState::Body(BodyState::UntilClose),
        };
        self.dir_mut(dir).state = next;
        Ok(Some(EngineEvent::Head(head)))
    }

    // ── body ──────────────────────────────────────────────────────

    fn poll_body(&mut self, dir: Dir, body: BodyState) -> crate::Result<Progress> {
        match body {
            BodyState::Length { remaining: 0 } => {
                self.dir_mut(dir).state = DirState::Head;
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
fn request_framing(headers: &[(Bytes, Bytes)]) -> BodyFraming {
    if has_chunked_encoding(headers) {
        return BodyFraming::Chunked;
    }
    match content_length(headers) {
        Some(0) | None => BodyFraming::None,
        Some(n) => BodyFraming::ContentLength(n),
    }
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
) -> BodyFraming {
    if request_was_head || matches!(status, 100..=199 | 204 | 304) {
        return BodyFraming::None;
    }
    if has_chunked_encoding(headers) {
        return BodyFraming::Chunked;
    }
    match content_length(headers) {
        Some(0) => BodyFraming::None,
        Some(n) => BodyFraming::ContentLength(n),
        // No length and no chunked framing: the body runs to close.
        None => BodyFraming::UntilClose,
    }
}

/// `true` if any `Transfer-Encoding` header lists `chunked`.
fn has_chunked_encoding(headers: &[(Bytes, Bytes)]) -> bool {
    headers.iter().any(|(name, value)| {
        name.as_ref().eq_ignore_ascii_case(b"transfer-encoding")
            && value
                .split(|&b| b == b',')
                .any(|tok| tok.trim_ascii().eq_ignore_ascii_case(b"chunked"))
    })
}

/// First `Content-Length` value, if numeric.
fn content_length(headers: &[(Bytes, Bytes)]) -> Option<u64> {
    for (name, value) in headers {
        if name.as_ref().eq_ignore_ascii_case(b"content-length") {
            let s = std::str::from_utf8(value).ok()?;
            return s.trim().parse::<u64>().ok();
        }
    }
    None
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
            // Replaced by the caller once framing is known.
            framing: BodyFraming::None,
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

        // Chunked wins over a length.
        let mut e = engine();
        e.push(
            Dir::Request,
            b"POST /a HTTP/1.1\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n",
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
                EngineEvent::End => {}
            }
        }
        assert_eq!(decoded, b"hello world");
        assert_eq!(raw, wire, "raw spans must reproduce the wire bytes");
        assert!(matches!(evs.last(), Some(EngineEvent::End)));
    }

    #[test]
    fn head_response_has_no_body_despite_content_length() {
        let mut e = engine();
        e.push(Dir::Request, b"HEAD /x HTTP/1.1\r\n\r\n");
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
