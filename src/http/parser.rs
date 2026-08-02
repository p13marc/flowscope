use bytes::Bytes;

use super::types::{BodyFraming, HttpConfig, HttpRequest, HttpResponse, HttpVersion, RequestHead};
use crate::error::{Error, Module};

/// Per-direction parser state.
#[derive(Debug, Clone)]
pub(crate) enum DirState {
    /// Awaiting a request line + headers (initiator side) or
    /// status line + headers (responder side).
    Headers,
    /// Reading a Content-Length-bounded body. `remaining` is bytes
    /// left to read into the body buffer.
    Body {
        remaining: usize,
        started: BodyStart,
    },
    /// Connection: close — body extends to FIN. Accumulate in
    /// the body buffer until the per-direction buffer hits
    /// `max_buffer`.
    UntilEof { started: BodyStart },
    /// Inline-streaming mode: the `RequestHead` was already emitted;
    /// now drain (and discard) exactly `remaining` Content-Length
    /// body bytes so the next request boundary is found without ever
    /// buffering the body.
    SkipBody { remaining: usize },
    /// Inline-streaming mode: drain (and discard) a chunk-framed
    /// body, tracking only enough state to find the terminating
    /// zero-size chunk. The proxy owns the raw bytes.
    SkipChunked(ChunkSkip),
    /// Inline-streaming mode: the request declared no length and no
    /// chunked framing — the body runs to FIN. Discard until `eof()`.
    SkipUntilEof,
    /// Desync — a previous parse error or buffer overflow forced
    /// us to give up on this direction. Bytes accumulate in vain
    /// until the next clean point (currently never automatically;
    /// users would need to drop the reassembler).
    Desynced,
}

/// Boundary-tracking state for discarding a chunk-framed body in
/// inline-streaming mode. We do **not** decode the payload — only
/// enough to locate the end of the body so the next request parses
/// cleanly.
#[derive(Debug, Clone)]
pub(crate) enum ChunkSkip {
    /// Reading a `<hex-size>[;ext]\r\n` chunk-size line.
    Size,
    /// Discarding `remaining` bytes of chunk data.
    Data { remaining: usize },
    /// Consuming the `\r\n` that terminates a chunk's data.
    DataCrlf,
    /// After the zero-size chunk: consuming trailer lines up to the
    /// terminating blank line.
    Trailer,
}

/// Snapshot taken when we transition from Headers → body, so we
/// can rebuild the [`HttpRequest`] / [`HttpResponse`] when the
/// body completes.
#[derive(Debug, Clone)]
pub(crate) struct BodyStart {
    pub is_request: bool,
    pub method: Bytes,
    pub path: Bytes,
    pub status: u16,
    pub reason: Bytes,
    pub version: HttpVersion,
    pub headers: Vec<(Bytes, Bytes)>,
}

impl BodyStart {
    fn into_request(self, body: Bytes) -> HttpRequest {
        HttpRequest {
            method: self.method,
            path: self.path,
            version: self.version,
            headers: self.headers,
            body,
        }
    }

    fn into_response(self, body: Bytes) -> HttpResponse {
        HttpResponse {
            status: self.status,
            reason: self.reason,
            version: self.version,
            headers: self.headers,
            body,
        }
    }

    /// Build the inline-streaming [`RequestHead`] from this snapshot.
    /// Consumes the header vec — no body is ever attached.
    fn into_request_head(self, framing: BodyFraming) -> RequestHead {
        RequestHead {
            method: self.method,
            path: self.path,
            version: self.version,
            headers: self.headers,
            framing,
        }
    }
}

/// Output of a parse step.
#[derive(Debug)]
pub(crate) enum ParseOutput {
    Request(HttpRequest),
    Response(HttpResponse),
    /// Inline-streaming mode: request headers, emitted before the body.
    RequestHead(RequestHead),
}

/// Try to advance the parser, possibly emitting one parsed message.
/// Returns:
/// - `Ok(Some(message))` — emitted; the caller should re-call to
///   look for pipelined messages.
/// - `Ok(None)` — need more bytes.
/// - `Err(_)` — desync.
pub(crate) fn step(
    state: &mut DirState,
    buffer: &mut Vec<u8>,
    is_request: bool,
    config: &HttpConfig,
) -> crate::Result<Option<ParseOutput>> {
    if buffer.len() > config.max_buffer {
        *state = DirState::Desynced;
        buffer.clear();
        return Err(Error::buffer_overflow(Module::Http, config.max_buffer));
    }

    loop {
        match state {
            DirState::Desynced => return Ok(None),

            DirState::Headers => {
                let mut headers_storage = vec![httparse::EMPTY_HEADER; config.max_headers];
                let buf_start = buffer.as_ptr();
                if is_request {
                    let mut req = httparse::Request::new(&mut headers_storage);
                    match req.parse(buffer) {
                        Ok(httparse::Status::Complete(hlen)) => {
                            // Single Arc for the header region. method /
                            // path / header names / values are all
                            // zero-copy Bytes::slice over this.
                            let header_bytes = Bytes::copy_from_slice(&buffer[..hlen]);
                            let snapshot = snapshot_request(&req, buf_start, &header_bytes)?;
                            advance_to_body(buffer, hlen);
                            if config.inline_streaming {
                                // Inline proxy: emit the routing head now,
                                // then drain-and-discard the body so the
                                // next request boundary is found without
                                // ever buffering the body.
                                let framing =
                                    body_framing(&snapshot.headers, true, &snapshot.method);
                                transition_to_skip(state, framing);
                                return Ok(Some(ParseOutput::RequestHead(
                                    snapshot.into_request_head(framing),
                                )));
                            }
                            let body_len = body_len_from_headers(&snapshot.headers);
                            transition_to_body(state, snapshot, body_len, true);
                            // Loop: maybe the body is already in the buffer
                            continue;
                        }
                        Ok(httparse::Status::Partial) => return Ok(None),
                        Err(e) => {
                            *state = DirState::Desynced;
                            buffer.clear();
                            return Err(Error::parse_with(Module::Http, "httparse failed", e));
                        }
                    }
                } else {
                    let mut resp = httparse::Response::new(&mut headers_storage);
                    match resp.parse(buffer) {
                        Ok(httparse::Status::Complete(hlen)) => {
                            let header_bytes = Bytes::copy_from_slice(&buffer[..hlen]);
                            let snapshot = snapshot_response(&resp, buf_start, &header_bytes)?;
                            let body_len = body_len_from_headers(&snapshot.headers);
                            advance_to_body(buffer, hlen);
                            transition_to_body(state, snapshot, body_len, false);
                            continue;
                        }
                        Ok(httparse::Status::Partial) => return Ok(None),
                        Err(e) => {
                            *state = DirState::Desynced;
                            buffer.clear();
                            return Err(Error::parse_with(Module::Http, "httparse failed", e));
                        }
                    }
                }
            }

            DirState::Body {
                remaining,
                started: _,
            } if *remaining == 0 => {
                // Zero-length body: emit immediately.
                if let DirState::Body { started, .. } = std::mem::replace(state, DirState::Headers)
                {
                    return Ok(Some(emit(started, Bytes::new())));
                }
                unreachable!();
            }

            DirState::Body { remaining, .. } => {
                if buffer.len() < *remaining {
                    return Ok(None);
                }
                let body_len = *remaining;
                let body = Bytes::copy_from_slice(&buffer[..body_len]);
                advance_to_body(buffer, body_len);
                if let DirState::Body { started, .. } = std::mem::replace(state, DirState::Headers)
                {
                    return Ok(Some(emit(started, body)));
                }
                unreachable!();
            }

            DirState::UntilEof { .. } => {
                // Body extends to FIN — we don't know length yet.
                // Wait for `eof()`.
                return Ok(None);
            }

            // ── Inline-streaming body skip states ─────────────────
            // The RequestHead was already emitted; here we only
            // consume body bytes to locate the next request. Nothing
            // is buffered or emitted.
            DirState::SkipBody { remaining } if *remaining == 0 => {
                *state = DirState::Headers;
                continue;
            }

            DirState::SkipBody { remaining } => {
                let take = (*remaining).min(buffer.len());
                advance_to_body(buffer, take);
                *remaining -= take;
                if *remaining == 0 {
                    *state = DirState::Headers;
                    continue;
                }
                return Ok(None);
            }

            DirState::SkipChunked(cs) => match advance_chunk_skip(cs, buffer) {
                Ok(ChunkProgress::Done) => {
                    *state = DirState::Headers;
                    continue;
                }
                Ok(ChunkProgress::NeedMore) => return Ok(None),
                Err(e) => {
                    *state = DirState::Desynced;
                    buffer.clear();
                    return Err(e);
                }
            },

            DirState::SkipUntilEof => {
                // Body runs to FIN — discard whatever is buffered so
                // far and wait for `eof()`.
                buffer.clear();
                return Ok(None);
            }
        }
    }
}

/// Force end-of-stream on `state`. If we were in `UntilEof`,
/// produce the message with whatever's buffered.
pub(crate) fn eof(state: &mut DirState, buffer: &mut Vec<u8>) -> Option<ParseOutput> {
    match std::mem::replace(state, DirState::Desynced) {
        DirState::UntilEof { started } => {
            let body = Bytes::copy_from_slice(buffer);
            buffer.clear();
            Some(emit(started, body))
        }
        // Inline mode: an until-EOF body ends cleanly at FIN. No
        // message (the head was already emitted); reset so a
        // subsequent connection reuse (rare) starts clean.
        DirState::SkipUntilEof => {
            buffer.clear();
            *state = DirState::Headers;
            None
        }
        _ => None,
    }
}

/// Progress signal from [`advance_chunk_skip`].
enum ChunkProgress {
    /// The zero-size chunk + trailers were consumed — body complete.
    Done,
    /// More bytes are needed to finish the current chunk-framing step.
    NeedMore,
}

/// Consume (discard) a chunk-framed body from `buffer`, advancing
/// `cs` across chunk-size lines, data, and trailers. Used only in
/// inline-streaming mode — the payload is not decoded, only skipped,
/// so the next request boundary is found. Returns `Done` once the
/// terminating zero-size chunk and its trailer block are consumed.
fn advance_chunk_skip(cs: &mut ChunkSkip, buffer: &mut Vec<u8>) -> crate::Result<ChunkProgress> {
    loop {
        match cs {
            ChunkSkip::Size => {
                let Some(pos) = find_crlf(buffer) else {
                    return Ok(ChunkProgress::NeedMore);
                };
                let line = &buffer[..pos];
                let hex_end = line.iter().position(|&b| b == b';').unwrap_or(line.len());
                let size = parse_hex(line[..hex_end].trim_ascii())
                    .ok_or_else(|| Error::parse(Module::Http, "invalid chunk size"))?;
                advance_to_body(buffer, pos + 2);
                *cs = if size == 0 {
                    ChunkSkip::Trailer
                } else {
                    ChunkSkip::Data { remaining: size }
                };
            }
            ChunkSkip::Data { remaining } => {
                let take = (*remaining).min(buffer.len());
                advance_to_body(buffer, take);
                *remaining -= take;
                if *remaining > 0 {
                    return Ok(ChunkProgress::NeedMore);
                }
                *cs = ChunkSkip::DataCrlf;
            }
            ChunkSkip::DataCrlf => {
                if buffer.len() < 2 {
                    return Ok(ChunkProgress::NeedMore);
                }
                if &buffer[..2] != b"\r\n" {
                    return Err(Error::parse(Module::Http, "malformed chunk terminator"));
                }
                advance_to_body(buffer, 2);
                *cs = ChunkSkip::Size;
            }
            ChunkSkip::Trailer => {
                let Some(pos) = find_crlf(buffer) else {
                    return Ok(ChunkProgress::NeedMore);
                };
                advance_to_body(buffer, pos + 2);
                // A blank line (`\r\n` with nothing before it) ends
                // the trailer block and thus the whole chunked body.
                if pos == 0 {
                    return Ok(ChunkProgress::Done);
                }
                // Otherwise it was a trailer header line; keep going.
            }
        }
    }
}

/// Index of the first `\r\n` in `buf`, or `None`.
fn find_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(2).position(|w| w == b"\r\n")
}

/// Parse an ASCII-hex byte string (chunk size). `None` if empty or
/// not valid hex.
fn parse_hex(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    usize::from_str_radix(s, 16).ok()
}

/// Set `state` to the inline body-skip state matching `framing`.
fn transition_to_skip(state: &mut DirState, framing: BodyFraming) {
    *state = match framing {
        BodyFraming::None | BodyFraming::ContentLength(0) => DirState::Headers,
        BodyFraming::ContentLength(n) => DirState::SkipBody {
            remaining: n as usize,
        },
        BodyFraming::Chunked => DirState::SkipChunked(ChunkSkip::Size),
        BodyFraming::UntilEof => DirState::SkipUntilEof,
    };
}

/// Determine body framing from headers at header-completion time.
/// `Transfer-Encoding: chunked` wins over Content-Length (and, per
/// RFC 7230 §3.3.3, a message with both is a smuggling risk the
/// caller can reject). Absent both, requests with a bodyless method
/// have no body; anything else runs to EOF.
fn body_framing(headers: &[(Bytes, Bytes)], is_request: bool, method: &[u8]) -> BodyFraming {
    if has_chunked_encoding(headers) {
        return BodyFraming::Chunked;
    }
    if let Some(n) = body_len_from_headers(headers) {
        return if n == 0 {
            BodyFraming::None
        } else {
            BodyFraming::ContentLength(n as u64)
        };
    }
    if is_request && matches!(method, b"GET" | b"HEAD" | b"DELETE" | b"OPTIONS") {
        BodyFraming::None
    } else {
        BodyFraming::UntilEof
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

fn emit(started: BodyStart, body: Bytes) -> ParseOutput {
    if started.is_request {
        ParseOutput::Request(started.into_request(body))
    } else {
        ParseOutput::Response(started.into_response(body))
    }
}

fn snapshot_request(
    req: &httparse::Request<'_, '_>,
    buf_start: *const u8,
    header_bytes: &Bytes,
) -> crate::Result<BodyStart> {
    let method_str = req
        .method
        .ok_or_else(|| Error::parse(Module::Http, "missing method"))?;
    let path_str = req
        .path
        .ok_or_else(|| Error::parse(Module::Http, "missing path"))?;
    let version = req
        .version
        .ok_or_else(|| Error::parse(Module::Http, "missing version"))?;
    let version = match version {
        0 => HttpVersion::Http1_0,
        1 => HttpVersion::Http1_1,
        _ => {
            return Err(Error::parse(
                Module::Http,
                format!("unknown version: {version}"),
            ));
        }
    };
    Ok(BodyStart {
        is_request: true,
        method: slice_in(header_bytes, buf_start, method_str.as_bytes()),
        path: slice_in(header_bytes, buf_start, path_str.as_bytes()),
        status: 0,
        reason: Bytes::new(),
        version,
        headers: collect_headers(req.headers, buf_start, header_bytes),
    })
}

fn snapshot_response(
    resp: &httparse::Response<'_, '_>,
    buf_start: *const u8,
    header_bytes: &Bytes,
) -> crate::Result<BodyStart> {
    let status = resp
        .code
        .ok_or_else(|| Error::parse(Module::Http, "missing status code"))?;
    let reason = resp.reason.unwrap_or("");
    let version = resp
        .version
        .ok_or_else(|| Error::parse(Module::Http, "missing version"))?;
    let version = match version {
        0 => HttpVersion::Http1_0,
        1 => HttpVersion::Http1_1,
        _ => {
            return Err(Error::parse(
                Module::Http,
                format!("unknown version: {version}"),
            ));
        }
    };
    let reason_bytes = if reason.is_empty() {
        Bytes::new()
    } else {
        slice_in(header_bytes, buf_start, reason.as_bytes())
    };
    Ok(BodyStart {
        is_request: false,
        method: Bytes::new(),
        path: Bytes::new(),
        status,
        reason: reason_bytes,
        version,
        headers: collect_headers(resp.headers, buf_start, header_bytes),
    })
}

fn collect_headers(
    hs: &[httparse::Header<'_>],
    buf_start: *const u8,
    header_bytes: &Bytes,
) -> Vec<(Bytes, Bytes)> {
    // Count non-empty headers up front so the Vec allocates once
    // (otherwise `.collect()` regrows a handful of times for typical
    // 10-header requests).
    let n = hs.iter().take_while(|h| !h.name.is_empty()).count();
    let mut out = Vec::with_capacity(n);
    for h in hs.iter().take(n) {
        out.push((
            slice_in(header_bytes, buf_start, h.name.as_bytes()),
            slice_in(header_bytes, buf_start, h.value),
        ));
    }
    out
}

/// Compute a zero-copy `Bytes::slice` of `header_bytes` covering the
/// range pointed at by `slice`. `slice` MUST be a sub-slice of the
/// `Vec<u8>` that `buf_start` pointed at when `header_bytes` was
/// taken (`Bytes::copy_from_slice(&buf[..hlen])`).
#[inline]
fn slice_in(header_bytes: &Bytes, buf_start: *const u8, slice: &[u8]) -> Bytes {
    // SAFETY: caller guarantees `slice` lies within `[buf_start,
    // buf_start + hlen)`. Pointer subtraction over a single
    // allocation is well-defined.
    let off = unsafe { slice.as_ptr().offset_from(buf_start) as usize };
    header_bytes.slice(off..off + slice.len())
}

/// Parse `Content-Length` from headers. Returns:
/// - `Some(n)` for a numeric Content-Length.
/// - `None` if no Content-Length found (caller decides EOF semantics).
fn body_len_from_headers(headers: &[(Bytes, Bytes)]) -> Option<usize> {
    for (name, value) in headers {
        if name.as_ref().eq_ignore_ascii_case(b"content-length") {
            let s = std::str::from_utf8(value).ok()?;
            return s.trim().parse::<usize>().ok();
        }
    }
    None
}

fn transition_to_body(
    state: &mut DirState,
    snapshot: BodyStart,
    body_len: Option<usize>,
    _is_request: bool,
) {
    match body_len {
        Some(0) => {
            *state = DirState::Body {
                remaining: 0,
                started: snapshot,
            };
        }
        Some(n) => {
            *state = DirState::Body {
                remaining: n,
                started: snapshot,
            };
        }
        None => {
            // Heuristic: GET / HEAD / DELETE on a request usually
            // have no body; for responses, no Content-Length means
            // body extends to FIN.
            if snapshot.is_request
                && matches!(
                    snapshot.method.as_ref(),
                    b"GET" | b"HEAD" | b"DELETE" | b"OPTIONS"
                )
            {
                *state = DirState::Body {
                    remaining: 0,
                    started: snapshot,
                };
            } else {
                *state = DirState::UntilEof { started: snapshot };
            }
        }
    }
}

fn advance_to_body(buffer: &mut Vec<u8>, n: usize) {
    // `drain(..n)` preserves the Vec's capacity (vs. `split_off(n)`
    // + reassign, which throws away the pre-allocated 8 KiB buffer
    // and forces a fresh allocation on the next `extend_from_slice`).
    buffer.drain(..n);
}
