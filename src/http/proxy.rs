//! [`HttpProxyParser`] — the sans-IO streaming front-end, for inline
//! proxies. See the type's own documentation for the event model and
//! the forwarding contract.

use bytes::Bytes;

use super::{
    engine::{Dir, Engine, EngineEvent, EngineLimits},
    poison::HttpPoison,
    types::{RequestHead, ResponseHead, SwitchKind},
};
use crate::FlowSide;

/// One step of progress on a connection.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum HttpEvent {
    /// Request start line + headers, before the body.
    RequestHead(RequestHead),
    /// Response status line + headers, before the body. Emitted for
    /// every `1xx` interim as well as the final response.
    ResponseHead(ResponseHead),
    /// Body progress. `data` is decoded payload — empty when the step
    /// consumed only framing bytes, such as a chunk-size line. `raw`
    /// is every byte the step consumed, framing included.
    Body {
        dir: FlowSide,
        data: Bytes,
        raw: Bytes,
    },
    /// Trailer section after a chunked body. Emitted for every chunked
    /// message, possibly with no fields.
    Trailers {
        dir: FlowSide,
        trailers: Vec<(Bytes, Bytes)>,
        raw: Bytes,
    },
    /// One message is fully framed. On a keep-alive connection the
    /// next one may follow immediately.
    End { dir: FlowSide },
    /// The connection left HTTP behind; tunnel the rest verbatim.
    SwitchProtocols { kind: SwitchKind },
}

/// Caps for [`HttpProxyParser`].
///
/// Every field bounds something an adversary controls. The struct is
/// `#[non_exhaustive]` so it can gain knobs without breaking you,
/// which means starting from [`Default`] and assigning the fields you
/// care about:
///
/// ```
/// use flowscope::http::HttpProxyConfig;
///
/// let mut cfg = HttpProxyConfig::default();
/// cfg.max_head_bytes = 16 * 1024;
/// ```
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpProxyConfig {
    /// Start line + header block. Default 64 KiB.
    pub max_head_bytes: usize,
    /// Header fields per message. Default 128.
    pub max_headers: usize,
    /// One `<hex-size>[;ext]\r\n` line. Default 256 B.
    pub max_chunk_line_bytes: usize,
    /// The whole trailer section. Default 8 KiB.
    pub max_trailer_bytes: usize,
    /// Requests that may be outstanding at once. Default 64.
    pub max_pipelined: usize,
    /// How much unparsed data one direction may hold before
    /// [`push`](HttpProxyParser::push) starts refusing bytes. This is
    /// the backpressure valve, not a failure: it must be at least
    /// `max_head_bytes` for the parser to make progress. Default
    /// 256 KiB.
    pub max_buffered_bytes: usize,
}

impl Default for HttpProxyConfig {
    fn default() -> Self {
        Self {
            max_head_bytes: 64 * 1024,
            max_headers: 128,
            max_chunk_line_bytes: 256,
            max_trailer_bytes: 8 * 1024,
            max_pipelined: 64,
            max_buffered_bytes: 256 * 1024,
        }
    }
}

/// Sans-IO HTTP/1.1 parser for inline proxies.
///
/// Feed bytes per direction, drain events. No sockets, no async, no
/// clock: the caller owns I/O, and therefore owns backpressure — the
/// same discipline `rustls`, `quinn-proto`, and `h2` use. One parser
/// owns both directions of a connection, because response framing
/// depends on the matching request's method (RFC 9112 §6.3 rules
/// 1–2).
///
/// ```
/// use bytes::Bytes;
/// use flowscope::FlowSide;
/// use flowscope::http::{HttpEvent, HttpProxyParser};
///
/// let mut p = HttpProxyParser::new();
/// let wire = Bytes::from_static(
///     b"POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 5\r\n\r\nhello",
/// );
/// let accepted = p.push(FlowSide::Initiator, &wire);
/// assert_eq!(accepted, wire.len());
///
/// // The head arrives before any body byte is looked at, so a proxy
/// // can pick a backend immediately.
/// let Some(HttpEvent::RequestHead(head)) = p.next_event() else {
///     panic!("expected a request head")
/// };
/// assert_eq!(head.host(), Some("api.example.com"));
///
/// // Body bytes are reported as spans the parser does not retain.
/// let mut body = Vec::new();
/// while let Some(ev) = p.next_event() {
///     match ev {
///         HttpEvent::Body { data, .. } => body.extend_from_slice(&data),
///         HttpEvent::End { .. } => break,
///         _ => {}
///     }
/// }
/// assert_eq!(body, b"hello");
/// ```
///
/// # Forwarding verbatim
///
/// Every event carries the exact wire bytes it consumed. Concatenating
/// [`RequestHead::raw`], each [`HttpEvent::Body`]'s `raw`, and
/// [`HttpEvent::Trailers`]' `raw` reproduces the message byte for
/// byte — so a proxy that forwards traffic unchanged relays `raw`
/// while flowscope tracks boundaries, and a proxy that rewrites
/// bodies uses the decoded `data` and re-frames.
///
/// # Bounded memory
///
/// The parser never buffers a whole body. Everything it does hold —
/// the head block, a chunk-size line, the trailer section — is capped
/// by [`HttpProxyConfig`], and breaching a cap poisons the connection
/// instead of growing. When a direction is holding
/// [`max_buffered_bytes`](HttpProxyConfig::max_buffered_bytes),
/// [`push`](Self::push) accepts fewer bytes than offered: that short
/// count is the backpressure signal, and the caller should stop
/// reading its socket until it has drained more events.
#[derive(Debug, Clone)]
pub struct HttpProxyParser {
    engine: Engine,
    config: HttpProxyConfig,
}

impl Default for HttpProxyParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpProxyParser {
    /// Construct with default caps.
    pub fn new() -> Self {
        Self::with_config(HttpProxyConfig::default())
    }

    /// Construct with explicit caps.
    pub fn with_config(config: HttpProxyConfig) -> Self {
        let limits = EngineLimits {
            max_head_bytes: config.max_head_bytes,
            max_headers: config.max_headers,
            max_chunk_line_bytes: config.max_chunk_line_bytes,
            max_trailer_bytes: config.max_trailer_bytes,
            max_pipelined: config.max_pipelined,
        };
        Self {
            engine: Engine::new(limits),
            config,
        }
    }

    /// Feed bytes for one direction; returns how many were accepted.
    ///
    /// A short count is the backpressure signal: the direction is
    /// holding as much unparsed data as
    /// [`max_buffered_bytes`](HttpProxyConfig::max_buffered_bytes)
    /// allows. Drain events, then re-offer the remainder with
    /// `data.slice(accepted..)` — slicing a [`Bytes`] is a refcount
    /// bump, not a copy. A poisoned connection accepts nothing.
    pub fn push(&mut self, dir: FlowSide, data: &Bytes) -> usize {
        if self.is_poisoned() {
            return 0;
        }
        let dir = to_dir(dir);
        let room = self
            .config
            .max_buffered_bytes
            .saturating_sub(self.engine.buffered(dir));
        let take = room.min(data.len());
        if take > 0 {
            self.engine.push(dir, &data[..take]);
        }
        take
    }

    /// Signal end of stream on a direction.
    ///
    /// A close-delimited body ends here; anything else simply closes.
    /// A FIN between messages is normal and is not a failure.
    pub fn fin(&mut self, dir: FlowSide) {
        self.engine.fin(to_dir(dir));
    }

    /// Take the next event, if one is ready.
    ///
    /// `None` means more bytes are needed (or the connection is
    /// finished). Events are produced lazily — this drives the parser,
    /// so keep calling it until it returns `None`.
    pub fn next_event(&mut self) -> Option<HttpEvent> {
        // Requests first: a response cannot be framed until its
        // request's method is known.
        for dir in [Dir::Request, Dir::Response] {
            match self.engine.poll(dir) {
                Ok(Some(ev)) => return Some(convert(dir, ev)),
                Ok(None) => continue,
                // The direction is now poisoned; is_poisoned() and
                // poison() report why.
                Err(_) => continue,
            }
        }
        None
    }

    /// `true` once framing was lost and parsing has stopped.
    ///
    /// An inline proxy should tear the connection down rather than
    /// keep forwarding: past a framing desync, the two endpoints no
    /// longer agree on where messages end, which is exactly the
    /// condition request smuggling exploits.
    pub fn is_poisoned(&self) -> bool {
        self.engine.is_desynced(Dir::Request) || self.engine.is_desynced(Dir::Response)
    }

    /// Why parsing stopped, if it did.
    pub fn poison(&self) -> Option<HttpPoison> {
        self.engine
            .poison(Dir::Request)
            .or_else(|| self.engine.poison(Dir::Response))
    }

    /// Stable slug for [`poison`](Self::poison).
    pub fn poison_reason(&self) -> Option<&'static str> {
        self.poison().map(HttpPoison::as_str)
    }

    /// `true` once no further HTTP message can arrive, so the caller
    /// can close or recycle the connection without guessing.
    ///
    /// That is the case after a protocol switch (the bytes belong to
    /// the tunnel now), and once both directions are finished —
    /// either by end of stream or because a message said the
    /// connection closes when it completes (`Connection: close`, or
    /// HTTP/1.0 without `keep-alive`).
    pub fn is_done(&self) -> bool {
        if self.engine.is_tunnelled() {
            return true;
        }
        self.engine.is_closed(Dir::Request) && self.engine.is_closed(Dir::Response)
    }

    /// Bytes held but not yet parsed on a direction. Bounded by
    /// [`max_buffered_bytes`](HttpProxyConfig::max_buffered_bytes) —
    /// a body never accumulates here.
    pub fn buffered(&self, dir: FlowSide) -> usize {
        self.engine.buffered(to_dir(dir))
    }
}

fn to_dir(side: FlowSide) -> Dir {
    match side {
        FlowSide::Initiator => Dir::Request,
        FlowSide::Responder => Dir::Response,
    }
}

fn to_side(dir: Dir) -> FlowSide {
    match dir {
        Dir::Request => FlowSide::Initiator,
        Dir::Response => FlowSide::Responder,
    }
}

fn convert(dir: Dir, ev: EngineEvent) -> HttpEvent {
    let side = to_side(dir);
    match ev {
        EngineEvent::Head(h) => match dir {
            Dir::Request => HttpEvent::RequestHead(RequestHead {
                method: h.method,
                path: h.path,
                version: h.version,
                headers: h.headers,
                framing: h.framing,
                raw: h.raw,
            }),
            Dir::Response => HttpEvent::ResponseHead(ResponseHead {
                status: h.status,
                reason: h.reason,
                version: h.version,
                headers: h.headers,
                framing: h.framing,
                interim: h.interim,
                raw: h.raw,
            }),
        },
        EngineEvent::Body { decoded, raw } => HttpEvent::Body {
            dir: side,
            data: decoded,
            raw,
        },
        EngineEvent::Trailers { fields, raw } => HttpEvent::Trailers {
            dir: side,
            trailers: fields,
            raw,
        },
        EngineEvent::End => HttpEvent::End { dir: side },
        EngineEvent::Switch(kind) => HttpEvent::SwitchProtocols { kind },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::BodyFraming;

    fn push_all(p: &mut HttpProxyParser, dir: FlowSide, bytes: &[u8]) {
        let data = Bytes::copy_from_slice(bytes);
        let n = p.push(dir, &data);
        assert_eq!(n, data.len(), "test inputs fit the default caps");
    }

    fn drain(p: &mut HttpProxyParser) -> Vec<HttpEvent> {
        let mut out = Vec::new();
        while let Some(ev) = p.next_event() {
            out.push(ev);
        }
        out
    }

    /// Concatenated `raw` of every event, which must reproduce the
    /// wire bytes exactly.
    fn raw_of(evs: &[HttpEvent]) -> Vec<u8> {
        let mut v = Vec::new();
        for ev in evs {
            match ev {
                HttpEvent::RequestHead(h) => v.extend_from_slice(&h.raw),
                HttpEvent::ResponseHead(h) => v.extend_from_slice(&h.raw),
                HttpEvent::Body { raw, .. } => v.extend_from_slice(raw),
                HttpEvent::Trailers { raw, .. } => v.extend_from_slice(raw),
                _ => {}
            }
        }
        v
    }

    fn decoded_of(evs: &[HttpEvent]) -> Vec<u8> {
        let mut v = Vec::new();
        for ev in evs {
            if let HttpEvent::Body { data, .. } = ev {
                v.extend_from_slice(data);
            }
        }
        v
    }

    #[test]
    fn head_arrives_before_any_body_byte() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /submit HTTP/1.1\r\nHost: api.example.com\r\nContent-Length: 1000\r\n\r\n",
        );
        let ev = p.next_event().expect("head must be ready");
        match ev {
            HttpEvent::RequestHead(h) => {
                assert_eq!(h.method.as_ref(), b"POST");
                assert_eq!(h.host(), Some("api.example.com"));
                assert_eq!(h.framing, BodyFraming::ContentLength(1000));
            }
            other => panic!("expected RequestHead, got {other:?}"),
        }
        assert!(p.next_event().is_none(), "no body has been fed yet");
    }

    #[test]
    fn body_is_never_accumulated() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /u HTTP/1.1\r\nContent-Length: 100000\r\n\r\n",
        );
        let _ = drain(&mut p);
        // Push the whole body through in slices, draining as we go.
        let chunk = Bytes::from_static(&[b'x'; 4096]);
        let mut sent = 0usize;
        while sent < 100_000 {
            let slice = chunk.slice(..chunk.len().min(100_000 - sent));
            let n = p.push(FlowSide::Initiator, &slice);
            sent += n;
            let _ = drain(&mut p);
            assert!(
                p.buffered(FlowSide::Initiator) <= HttpProxyConfig::default().max_buffered_bytes,
                "the parser must never accumulate a body"
            );
        }
        assert_eq!(p.buffered(FlowSide::Initiator), 0);
    }

    #[test]
    fn raw_spans_reproduce_the_wire() {
        let wire: &[u8] = b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
                            5\r\nhello\r\n6\r\n world\r\n0\r\nX-Sum: 9\r\n\r\n";
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, wire);
        let evs = drain(&mut p);
        assert_eq!(raw_of(&evs), wire);
        assert_eq!(decoded_of(&evs), b"hello world");

        let trailers: Vec<_> = evs
            .iter()
            .filter_map(|e| match e {
                HttpEvent::Trailers { trailers, .. } => Some(trailers.clone()),
                _ => None,
            })
            .collect();
        assert_eq!(trailers.len(), 1);
        assert_eq!(trailers[0][0].0.as_ref(), b"X-Sum");
        assert_eq!(trailers[0][0].1.as_ref(), b"9");
        assert!(matches!(evs.last(), Some(HttpEvent::End { .. })));
    }

    #[test]
    fn split_feeds_produce_the_same_events() {
        let wire: &[u8] = b"POST /u HTTP/1.1\r\nContent-Length: 11\r\n\r\nhello world\
                            GET /next HTTP/1.1\r\nHost: h\r\n\r\n";
        let mut whole = HttpProxyParser::new();
        push_all(&mut whole, FlowSide::Initiator, wire);
        let a = drain(&mut whole);

        let mut drip = HttpProxyParser::new();
        let mut b = Vec::new();
        for byte in wire {
            push_all(&mut drip, FlowSide::Initiator, std::slice::from_ref(byte));
            b.extend(drain(&mut drip));
        }
        assert_eq!(raw_of(&a), raw_of(&b));
        assert_eq!(decoded_of(&a), decoded_of(&b));
        assert_eq!(raw_of(&b), wire);
    }

    #[test]
    fn pipelined_requests_each_end_cleanly() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /a HTTP/1.1\r\nContent-Length: 3\r\n\r\nAAA\
              POST /b HTTP/1.1\r\nContent-Length: 2\r\n\r\nBB\
              GET /c HTTP/1.1\r\n\r\n",
        );
        let evs = drain(&mut p);
        let paths: Vec<String> = evs
            .iter()
            .filter_map(|e| match e {
                HttpEvent::RequestHead(h) => Some(h.path_str().unwrap().to_string()),
                _ => None,
            })
            .collect();
        assert_eq!(paths, vec!["/a", "/b", "/c"]);
        let ends = evs
            .iter()
            .filter(|e| matches!(e, HttpEvent::End { .. }))
            .count();
        assert_eq!(ends, 3, "one End per message");
    }

    #[test]
    fn response_framing_uses_the_request_method() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"HEAD /x HTTP/1.1\r\n\r\n");
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n",
        );
        let evs = drain(&mut p);
        match &evs[0] {
            HttpEvent::ResponseHead(h) => assert_eq!(h.framing, BodyFraming::None),
            other => panic!("expected ResponseHead, got {other:?}"),
        }
        assert!(matches!(evs[1], HttpEvent::End { .. }));
    }

    #[test]
    fn backpressure_short_count_when_caller_does_not_drain() {
        let cfg = HttpProxyConfig {
            max_buffered_bytes: 4096,
            ..HttpProxyConfig::default()
        };
        let mut p = HttpProxyParser::with_config(cfg);
        let big = Bytes::from(vec![b'x'; 8192]);
        // Nothing has been parsed, so only the cap is accepted.
        let n = p.push(FlowSide::Initiator, &big);
        assert_eq!(n, 4096);
        // Re-offering the remainder is a refcount slice, not a copy.
        assert_eq!(p.push(FlowSide::Initiator, &big.slice(n..)), 0);
    }

    #[test]
    fn framing_desync_poisons_with_a_typed_reason() {
        let cfg = HttpProxyConfig {
            max_head_bytes: 128,
            ..HttpProxyConfig::default()
        };
        let mut p = HttpProxyParser::with_config(cfg);
        push_all(&mut p, FlowSide::Initiator, &[b'A'; 200]);
        let _ = drain(&mut p);
        assert!(p.is_poisoned());
        assert_eq!(p.poison(), Some(HttpPoison::HeadOverflow));
        assert_eq!(p.poison_reason(), Some("head-overflow"));
        // A poisoned connection accepts nothing further.
        assert_eq!(
            p.push(
                FlowSide::Initiator,
                &Bytes::from_static(b"GET / HTTP/1.1\r\n\r\n")
            ),
            0
        );
    }

    #[test]
    fn bad_chunk_size_is_reported_as_such() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        );
        let _ = drain(&mut p);
        assert_eq!(p.poison(), Some(HttpPoison::InvalidChunkSize));
    }

    // ── interim responses, tunnels, completion (#162) ─────────────

    fn statuses(evs: &[HttpEvent]) -> Vec<(u16, bool)> {
        evs.iter()
            .filter_map(|e| match e {
                HttpEvent::ResponseHead(h) => Some((h.status, h.interim)),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn interim_responses_precede_the_final_one() {
        // 100-continue then the real response. The interim must be
        // reported (a proxy forwards it) but must not complete the
        // exchange or consume the request.
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /u HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\n",
        );
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok",
        );
        let evs = drain(&mut p);
        assert_eq!(statuses(&evs), vec![(100, true), (200, false)]);
        assert_eq!(decoded_of(&evs), b"ok");
        // Exactly one End: the interim did not complete anything.
        assert_eq!(
            evs.iter()
                .filter(|e| matches!(e, HttpEvent::End { .. }))
                .count(),
            1
        );
    }

    #[test]
    fn multiple_interims_then_final() {
        // 103 Early Hints (RFC 8297) can repeat before the final.
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"GET /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 103 Early Hints\r\nLink: </s.css>\r\n\r\n\
              HTTP/1.1 103 Early Hints\r\nLink: </t.css>\r\n\r\n\
              HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nx",
        );
        let evs = drain(&mut p);
        assert_eq!(statuses(&evs), vec![(103, true), (103, true), (200, false)]);
    }

    #[test]
    fn response_reader_runs_before_the_request_body_is_sent() {
        // The 100-continue deadlock: the server answers while the
        // request body is still outstanding. Framing the response
        // must not wait on the request completing.
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"POST /u HTTP/1.1\r\nExpect: 100-continue\r\nContent-Length: 1000000\r\n\r\n",
        );
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 100 Continue\r\n\r\n",
        );
        let evs = drain(&mut p);
        assert_eq!(statuses(&evs), vec![(100, true)]);
    }

    #[test]
    fn connect_tunnel_switches_and_stops_parsing() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n",
        );
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        );
        let evs = drain(&mut p);
        assert!(matches!(
            evs.last(),
            Some(HttpEvent::SwitchProtocols {
                kind: SwitchKind::ConnectTunnel
            })
        ));
        // Tunnelled bytes are the caller's to splice; nothing further
        // is parsed as HTTP.
        push_all(&mut p, FlowSide::Initiator, b"\x16\x03\x01\x02\x00\x01");
        assert!(p.next_event().is_none());
        assert!(!p.is_poisoned());
    }

    #[test]
    fn failed_connect_is_a_normal_response() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"CONNECT example.com:443 HTTP/1.1\r\n\r\n",
        );
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 2\r\n\r\nno",
        );
        let evs = drain(&mut p);
        assert!(
            !evs.iter()
                .any(|e| matches!(e, HttpEvent::SwitchProtocols { .. })),
            "a rejected CONNECT does not open a tunnel"
        );
        assert_eq!(decoded_of(&evs), b"no");
    }

    #[test]
    fn websocket_upgrade_switches_with_the_protocol_token() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"GET /chat HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n",
        );
        let evs = drain(&mut p);
        match evs.last() {
            Some(HttpEvent::SwitchProtocols {
                kind: SwitchKind::Upgrade { protocol },
            }) => assert_eq!(protocol.as_ref(), b"websocket"),
            other => panic!("expected an Upgrade switch, got {other:?}"),
        }
        // The 101 head itself is still reported, so a proxy forwards it.
        assert_eq!(statuses(&evs), vec![(101, false)]);
    }

    #[test]
    fn http2_preface_is_recognised_not_mistaken_for_a_request() {
        let mut p = HttpProxyParser::new();
        push_all(
            &mut p,
            FlowSide::Initiator,
            b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n\x00\x00\x00\x04\x00\x00\x00\x00\x00",
        );
        let evs = drain(&mut p);
        assert!(matches!(
            evs.first(),
            Some(HttpEvent::SwitchProtocols {
                kind: SwitchKind::Http2PriorKnowledge
            })
        ));
        assert!(!p.is_poisoned(), "h2 traffic is not a framing failure");
    }

    #[test]
    fn partial_preface_waits_instead_of_guessing() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"PRI * HTTP/2.0\r\n");
        assert!(
            p.next_event().is_none(),
            "a prefix of the preface must not decide either way"
        );
        push_all(&mut p, FlowSide::Initiator, b"\r\nSM\r\n\r\n");
        assert!(matches!(
            p.next_event(),
            Some(HttpEvent::SwitchProtocols {
                kind: SwitchKind::Http2PriorKnowledge
            })
        ));
    }

    #[test]
    fn connection_close_completes_the_direction() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"GET /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Length: 2\r\n\r\nhi",
        );
        let evs = drain(&mut p);
        assert_eq!(decoded_of(&evs), b"hi");
        p.fin(FlowSide::Initiator);
        assert!(
            p.is_done(),
            "after a Connection: close response the connection is finished"
        );
    }

    #[test]
    fn http_1_0_response_without_keep_alive_completes() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"GET /a HTTP/1.0\r\n\r\n");
        let _ = drain(&mut p);
        push_all(
            &mut p,
            FlowSide::Responder,
            b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nhi",
        );
        let _ = drain(&mut p);
        p.fin(FlowSide::Initiator);
        assert!(p.is_done(), "HTTP/1.0 defaults to closing");
    }

    #[test]
    fn clean_fin_is_not_a_poison() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"GET /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut p);
        p.fin(FlowSide::Initiator);
        p.fin(FlowSide::Responder);
        assert!(!p.is_poisoned());
        assert!(p.is_done());
    }

    #[test]
    fn close_delimited_response_flushes_at_fin() {
        let mut p = HttpProxyParser::new();
        push_all(&mut p, FlowSide::Initiator, b"GET /a HTTP/1.1\r\n\r\n");
        let _ = drain(&mut p);
        push_all(&mut p, FlowSide::Responder, b"HTTP/1.1 200 OK\r\n\r\nhello");
        let evs = drain(&mut p);
        assert_eq!(decoded_of(&evs), b"hello");
        p.fin(FlowSide::Responder);
        // Nothing was withheld: the body was reported as it arrived.
        assert!(!p.is_poisoned());
    }
}
