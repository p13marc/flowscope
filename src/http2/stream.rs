//! Per-stream state and the public [`Http2Parser`].

use std::collections::HashMap;

use bytes::{Bytes, BytesMut};

use super::{
    error::Http2Error,
    frame::{self, FRAME_HEADER_LEN, FrameKind, PREFACE, flags},
    hpack::HpackDecoder,
};
use crate::FlowSide;

/// Header fields of one stream, with the pseudo-headers pulled out.
///
/// Field order is preserved: RFC 9113 §8.3 requires pseudo-headers to
/// precede regular ones, and a proxy forwarding the block needs it
/// unchanged.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct StreamHead {
    pub stream_id: u32,
    /// Which side sent it: a request from the client, a response from
    /// the server.
    pub dir: FlowSide,
    /// Every field, pseudo-headers first, in wire order.
    pub fields: Vec<(Bytes, Bytes)>,
    /// `true` if the frame carrying this block also ended the stream
    /// — a request with no body, or a Trailers-Only response.
    pub end_stream: bool,
}

impl StreamHead {
    /// A pseudo-header or header value, by exact (lowercase) name.
    pub fn field(&self, name: &str) -> Option<&[u8]> {
        self.fields
            .iter()
            .find(|(n, _)| n.as_ref() == name.as_bytes())
            .map(|(_, v)| v.as_ref())
    }

    fn field_str(&self, name: &str) -> Option<&str> {
        self.field(name).and_then(|v| std::str::from_utf8(v).ok())
    }

    /// `:method` (RFC 9113 §8.3.1).
    pub fn method(&self) -> Option<&str> {
        self.field_str(":method")
    }

    /// `:path` — for gRPC this is `/package.Service/Method`.
    pub fn path(&self) -> Option<&str> {
        self.field_str(":path")
    }

    /// `:authority` — the h2 equivalent of `Host`, and the routing
    /// key for a terminating proxy.
    pub fn authority(&self) -> Option<&str> {
        self.field_str(":authority")
    }

    /// `:scheme`.
    pub fn scheme(&self) -> Option<&str> {
        self.field_str(":scheme")
    }

    /// `:status`, parsed, on a response.
    pub fn status(&self) -> Option<u16> {
        self.field_str(":status").and_then(|s| s.parse().ok())
    }

    /// `content-type`.
    pub fn content_type(&self) -> Option<&str> {
        self.field_str("content-type")
    }
}

/// One step of progress on an HTTP/2 connection.
///
/// The same vocabulary as the HTTP/1 streaming parser, keyed by
/// stream, so a consumer can handle both with one shape.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Http2Event {
    /// A complete field block: request or response headers.
    Head(StreamHead),
    /// `DATA` payload for a stream. Not retained by the parser.
    Body {
        stream_id: u32,
        dir: FlowSide,
        data: Bytes,
    },
    /// A field block that arrived after `DATA` — trailers. For gRPC
    /// this is where `grpc-status` lives.
    Trailers {
        stream_id: u32,
        dir: FlowSide,
        fields: Vec<(Bytes, Bytes)>,
    },
    /// The stream is complete in this direction.
    End { stream_id: u32, dir: FlowSide },
    /// The stream was cancelled (`RST_STREAM`).
    StreamReset { stream_id: u32, error_code: u32 },
    /// The peer is winding the connection down (`GOAWAY`).
    GoAway {
        last_stream_id: u32,
        error_code: u32,
    },
}

/// Caps for [`Http2Parser`].
///
/// Every field bounds something the peer chooses. `SETTINGS` can
/// lower the effective limits but never raise them past these.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http2Config {
    /// Largest frame accepted, before `SETTINGS_MAX_FRAME_SIZE`
    /// narrows it. Default 1 MiB (the protocol maximum is 16 MiB − 1;
    /// this is deliberately tighter).
    pub max_frame_size: u32,
    /// Cap on one reassembled field block across
    /// `HEADERS` + `CONTINUATION`. Default 64 KiB.
    pub max_header_block_bytes: usize,
    /// Hard ceiling on the HPACK dynamic table, whatever the peer's
    /// `SETTINGS_HEADER_TABLE_SIZE` says. Default 64 KiB.
    pub max_hpack_table_bytes: usize,
    /// Concurrent streams tracked per connection. Default 256.
    pub max_concurrent_streams: usize,
    /// Unparsed bytes held per direction before `push` applies
    /// backpressure. Default 1 MiB.
    pub max_buffered_bytes: usize,
}

impl Http2Config {
    /// Cap the largest accepted frame.
    #[must_use]
    pub fn with_max_frame_size(mut self, n: u32) -> Self {
        self.max_frame_size = n;
        self
    }

    /// Cap one reassembled field block.
    #[must_use]
    pub fn with_max_header_block_bytes(mut self, n: usize) -> Self {
        self.max_header_block_bytes = n;
        self
    }

    /// Cap the HPACK dynamic table.
    #[must_use]
    pub fn with_max_hpack_table_bytes(mut self, n: usize) -> Self {
        self.max_hpack_table_bytes = n;
        self
    }

    /// Cap tracked concurrent streams.
    #[must_use]
    pub fn with_max_concurrent_streams(mut self, n: usize) -> Self {
        self.max_concurrent_streams = n;
        self
    }

    /// Cap unparsed bytes per direction.
    ///
    /// Below `max_frame_size + 9` this becomes the effective frame
    /// ceiling: a frame that could never be held whole is refused
    /// with [`Http2Error::FrameTooLarge`] at its header.
    #[must_use]
    pub fn with_max_buffered_bytes(mut self, n: usize) -> Self {
        self.max_buffered_bytes = n;
        self
    }

    /// The largest frame that can actually be assembled.
    ///
    /// A frame bigger than a direction's buffer could never be held
    /// whole, so the buffer cap is the real ceiling however high
    /// `max_frame_size` is set. Left uncomposed the two caps
    /// contradict each other and the parser wedges: it buffers to the
    /// cap waiting for a frame that will never fit, then refuses
    /// every subsequent byte for the life of the connection — with
    /// the defaults, any frame larger than 1 MiB − 9. Refusing such a
    /// frame at its header is the same verdict, reached before the
    /// buffer fills and with a reason attached.
    fn effective_max_frame_size(&self) -> u32 {
        let by_buffer = self.max_buffered_bytes.saturating_sub(FRAME_HEADER_LEN);
        u32::try_from(by_buffer)
            .unwrap_or(u32::MAX)
            .min(self.max_frame_size)
    }
}

impl Default for Http2Config {
    fn default() -> Self {
        Self {
            max_frame_size: 1024 * 1024,
            max_header_block_bytes: 64 * 1024,
            max_hpack_table_bytes: 64 * 1024,
            max_concurrent_streams: 256,
            max_buffered_bytes: 1024 * 1024,
        }
    }
}

/// A field block spanning `HEADERS`/`PUSH_PROMISE` + `CONTINUATION`.
#[derive(Debug, Clone)]
struct PartialBlock {
    /// The stream `CONTINUATION` frames must arrive on.
    continuation_stream: u32,
    /// The stream the assembled block *describes*. Differs from
    /// `continuation_stream` for `PUSH_PROMISE`, whose block
    /// describes the promised stream while its continuations arrive
    /// on the sending one (RFC 9113 §6.6).
    describes_stream: u32,
    bytes: BytesMut,
    end_stream: bool,
}

/// What a stream has seen so far, so trailers can be told from a head.
///
/// Tracked **per direction**: a stream carries a request head from
/// the client and a response head from the server, and the server's
/// first field block is its head — not trailers on the request.
#[derive(Debug, Clone, Default)]
struct StreamState {
    head_seen_request: bool,
    head_seen_response: bool,
}

impl StreamState {
    /// Mark a field block seen for `dir`, returning whether one had
    /// already been seen — i.e. whether this block is trailers.
    fn mark_head(&mut self, dir: FlowSide) -> bool {
        let seen = match dir {
            FlowSide::Initiator => &mut self.head_seen_request,
            FlowSide::Responder => &mut self.head_seen_response,
        };
        std::mem::replace(seen, true)
    }
}

/// One direction's byte buffer plus the field block being assembled.
#[derive(Debug, Clone)]
struct DirState {
    buf: BytesMut,
    hpack: HpackDecoder,
    /// The field block currently being assembled, if any. `Some`
    /// means no other frame may interleave on `continuation_stream`.
    partial: Option<PartialBlock>,
    /// Effective `SETTINGS_MAX_FRAME_SIZE` for what this side sends.
    max_frame_size: u32,
    /// Set once the preface has been consumed (request side only).
    preface_seen: bool,
    done: bool,
}

impl DirState {
    fn new(cfg: &Http2Config) -> Self {
        Self {
            buf: BytesMut::new(),
            hpack: HpackDecoder::new(4096, cfg.max_hpack_table_bytes),
            partial: None,
            max_frame_size: cfg.effective_max_frame_size(),
            preface_seen: false,
            done: false,
        }
    }
}

/// Sans-IO HTTP/2 parser for one connection.
///
/// Feed bytes per direction, drain events — the same shape as
/// `flowscope::http::HttpProxyParser`. See the
/// [`http2`](crate::http2) module docs for what it does and does not
/// cover.
#[derive(Debug, Clone)]
pub struct Http2Parser {
    config: Http2Config,
    request: DirState,
    response: DirState,
    streams: HashMap<u32, StreamState>,
    events: std::collections::VecDeque<Http2Event>,
    error: Option<Http2Error>,
}

impl Default for Http2Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Parser {
    pub fn new() -> Self {
        Self::with_config(Http2Config::default())
    }

    pub fn with_config(config: Http2Config) -> Self {
        Self {
            request: DirState::new(&config),
            response: DirState::new(&config),
            config,
            streams: HashMap::new(),
            events: std::collections::VecDeque::new(),
            error: None,
        }
    }

    fn dir_mut(&mut self, dir: FlowSide) -> &mut DirState {
        match dir {
            FlowSide::Initiator => &mut self.request,
            FlowSide::Responder => &mut self.response,
        }
    }

    fn dir(&self, dir: FlowSide) -> &DirState {
        match dir {
            FlowSide::Initiator => &self.request,
            FlowSide::Responder => &self.response,
        }
    }

    /// Feed bytes for one direction; returns how many were accepted.
    ///
    /// A short count means the direction is holding
    /// [`max_buffered_bytes`](Http2Config::max_buffered_bytes) of
    /// unparsed data — drain events and re-offer the rest with
    /// `data.slice(n..)`, which is a refcount bump.
    ///
    /// **A zero return always implies a state the parser reports**:
    /// [`is_failed`](Self::is_failed) or
    /// [`is_finished`](Self::is_finished). The parser never sits on a
    /// full buffer in silence, so a caller that cannot see the count
    /// — [`Http2Session`](super::Http2Session), whose trait has no
    /// way to express a short read — can treat a refusal as "ask why"
    /// rather than "try again later".
    pub fn push(&mut self, dir: FlowSide, data: &Bytes) -> usize {
        if self.error.is_some() || self.dir(dir).done {
            return 0;
        }
        let room = self
            .config
            .max_buffered_bytes
            .saturating_sub(self.dir(dir).buf.len());
        if room == 0 {
            // The buffer is full and the last parse could not consume
            // it, so whatever sits at its head needs more room than
            // the cap allows and no future byte completes it.
            // Composing the caps keeps frames out of this state; what
            // is left is a cap set below the 24-byte preface. Either
            // way the connection is stuck, and a stuck parser that
            // returns 0 forever is indistinguishable from silence.
            self.fail(Http2Error::BufferOverflow);
            return 0;
        }
        let take = room.min(data.len());
        if take > 0 {
            self.dir_mut(dir).buf.extend_from_slice(&data[..take]);
            self.drive(dir);
        }
        take
    }

    /// Take the next event, if one is ready.
    pub fn next_event(&mut self) -> Option<Http2Event> {
        self.events.pop_front()
    }

    /// `true` once the connection failed and parsing stopped.
    pub fn is_failed(&self) -> bool {
        self.error.is_some()
    }

    /// Why parsing stopped, if it did.
    pub fn error(&self) -> Option<Http2Error> {
        self.error
    }

    /// Bytes held but not yet parsed on a direction.
    pub fn buffered(&self, dir: FlowSide) -> usize {
        self.dir(dir).buf.len()
    }

    /// Streams currently tracked.
    pub fn tracked_streams(&self) -> usize {
        self.streams.len()
    }

    /// Parse as much of a direction's buffer as possible.
    fn drive(&mut self, dir: FlowSide) {
        if let Err(e) = self.drive_inner(dir) {
            self.fail(e);
        }
    }

    fn fail(&mut self, e: Http2Error) {
        if self.error.is_none() {
            self.error = Some(e);
        }
        // Nothing further can be trusted: HPACK state is shared, so a
        // decode failure makes every later block meaningless.
        self.request.done = true;
        self.response.done = true;
        self.request.buf.clear();
        self.response.buf.clear();
        self.streams.clear();
    }

    fn drive_inner(&mut self, dir: FlowSide) -> Result<(), Http2Error> {
        // The client opens with the preface (RFC 9113 §3.4).
        if dir == FlowSide::Initiator && !self.request.preface_seen {
            let buf = &self.request.buf;
            let n = buf.len().min(PREFACE.len());
            if buf[..n] != PREFACE[..n] {
                return Err(Http2Error::BadPreface);
            }
            if buf.len() < PREFACE.len() {
                return Ok(());
            }
            let _ = self.request.buf.split_to(PREFACE.len());
            self.request.preface_seen = true;
        }

        loop {
            let max = self.dir(dir).max_frame_size;
            let buf = self.dir(dir).buf.clone().freeze();
            let Some((f, used)) = frame::parse_frame(&buf, max)? else {
                return Ok(());
            };
            let _ = self.dir_mut(dir).buf.split_to(used);
            self.handle_frame(dir, f)?;
        }
    }

    fn handle_frame(&mut self, dir: FlowSide, f: frame::Frame) -> Result<(), Http2Error> {
        // While a field block is open, only CONTINUATION on the same
        // stream may follow (§6.10). Anything else means the two
        // endpoints no longer agree on where the block ends.
        if let Some(open_id) = self
            .dir(dir)
            .partial
            .as_ref()
            .map(|p| p.continuation_stream)
            && (f.kind != FrameKind::Continuation || f.stream_id != open_id)
        {
            return Err(Http2Error::InterleavedContinuation);
        }

        match f.kind {
            FrameKind::Headers | FrameKind::PushPromise => {
                self.begin_block(dir, f)?;
            }
            FrameKind::Continuation => {
                if self.dir(dir).partial.is_none() {
                    return Err(Http2Error::UnexpectedContinuation);
                }
                self.continue_block(dir, f)?;
            }
            FrameKind::Data => {
                let end = f.has(flags::END_STREAM);
                if !f.payload.is_empty() {
                    self.events.push_back(Http2Event::Body {
                        stream_id: f.stream_id,
                        dir,
                        data: f.payload.clone(),
                    });
                }
                if end {
                    self.finish_stream(f.stream_id, dir);
                }
            }
            FrameKind::Settings => {
                // An ACK carries no payload and changes nothing.
                if !f.has(flags::ACK) {
                    let s = frame::parse_settings(&f.payload)?;
                    // A peer's SETTINGS govern what *it* sends, so
                    // they apply to the opposite direction's reader.
                    let target = match dir {
                        FlowSide::Initiator => FlowSide::Responder,
                        FlowSide::Responder => FlowSide::Initiator,
                    };
                    if let Some(n) = s.header_table_size {
                        let hard = self.config.max_hpack_table_bytes;
                        self.dir_mut(target)
                            .hpack
                            .set_max_size((n as usize).min(hard));
                    }
                    if let Some(n) = s.max_frame_size {
                        // Never above our own ceiling, and never
                        // above what the buffer can hold whole.
                        let ceiling = self.config.effective_max_frame_size();
                        self.dir_mut(target).max_frame_size = n.min(ceiling);
                    }
                }
            }
            FrameKind::RstStream => {
                if f.payload.len() < 4 {
                    return Err(Http2Error::MalformedFrame);
                }
                let code =
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]]);
                self.streams.remove(&f.stream_id);
                self.events.push_back(Http2Event::StreamReset {
                    stream_id: f.stream_id,
                    error_code: code,
                });
            }
            FrameKind::GoAway => {
                if f.payload.len() < 8 {
                    return Err(Http2Error::MalformedFrame);
                }
                let last =
                    u32::from_be_bytes([f.payload[0], f.payload[1], f.payload[2], f.payload[3]])
                        & 0x7fff_ffff;
                let code =
                    u32::from_be_bytes([f.payload[4], f.payload[5], f.payload[6], f.payload[7]]);
                self.events.push_back(Http2Event::GoAway {
                    last_stream_id: last,
                    error_code: code,
                });
            }
            // Flow control, priority, liveness, and extensions do not
            // affect how bytes are framed for an observer. A
            // forwarding proxy relays them untouched.
            FrameKind::WindowUpdate
            | FrameKind::Priority
            | FrameKind::Ping
            | FrameKind::Unknown(_) => {}
        }
        Ok(())
    }

    /// Start (and possibly complete) a field block.
    fn begin_block(&mut self, dir: FlowSide, f: frame::Frame) -> Result<(), Http2Error> {
        if f.payload.len() > self.config.max_header_block_bytes {
            return Err(Http2Error::HeaderListTooLong);
        }
        // A PUSH_PROMISE's block describes the stream it reserves,
        // not the one it arrived on.
        let describes_stream = f.promised_stream_id.unwrap_or(f.stream_id);
        // A promise does not end the stream it arrives on.
        let end_stream = f.promised_stream_id.is_none() && f.has(flags::END_STREAM);
        if f.has(flags::END_HEADERS) {
            self.complete_block(dir, describes_stream, &f.payload.clone(), end_stream)
        } else {
            let mut bytes = BytesMut::with_capacity(f.payload.len());
            bytes.extend_from_slice(&f.payload);
            self.dir_mut(dir).partial = Some(PartialBlock {
                continuation_stream: f.stream_id,
                describes_stream,
                bytes,
                end_stream,
            });
            Ok(())
        }
    }

    fn continue_block(&mut self, dir: FlowSide, f: frame::Frame) -> Result<(), Http2Error> {
        let cap = self.config.max_header_block_bytes;
        let (stream_id, end_stream, block) = {
            let d = self.dir_mut(dir);
            let Some(partial) = d.partial.as_mut() else {
                return Err(Http2Error::UnexpectedContinuation);
            };
            if partial.bytes.len() + f.payload.len() > cap {
                return Err(Http2Error::HeaderListTooLong);
            }
            partial.bytes.extend_from_slice(&f.payload);
            if !f.has(flags::END_HEADERS) {
                return Ok(());
            }
            let done = d.partial.take().expect("just checked");
            (done.describes_stream, done.end_stream, done.bytes)
        };
        self.complete_block(dir, stream_id, &block.freeze(), end_stream)
    }

    /// Decode a complete field block and report it.
    fn complete_block(
        &mut self,
        dir: FlowSide,
        stream_id: u32,
        block: &Bytes,
        end_stream: bool,
    ) -> Result<(), Http2Error> {
        // Decode first: HPACK state must advance for every block,
        // even one on a stream we would otherwise not track.
        let fields = self.dir_mut(dir).hpack.decode(block)?;

        let known = self.streams.contains_key(&stream_id);
        if !known && self.streams.len() >= self.config.max_concurrent_streams {
            return Err(Http2Error::TooManyStreams);
        }
        let state = self.streams.entry(stream_id).or_default();
        let is_trailers = state.mark_head(dir);

        if is_trailers {
            self.events.push_back(Http2Event::Trailers {
                stream_id,
                dir,
                fields,
            });
        } else {
            self.events.push_back(Http2Event::Head(StreamHead {
                stream_id,
                dir,
                fields,
                end_stream,
            }));
        }
        if end_stream {
            self.finish_stream(stream_id, dir);
        }
        Ok(())
    }

    fn finish_stream(&mut self, stream_id: u32, dir: FlowSide) {
        self.events.push_back(Http2Event::End { stream_id, dir });
        // A stream ended by the server is done for good; one ended by
        // the client may still receive a response, so its state stays
        // until RST_STREAM or the response's own END_STREAM.
        if dir == FlowSide::Responder {
            self.streams.remove(&stream_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a frame with the given type, flags, stream, payload.
    fn frame(kind: u8, flags: u8, stream: u32, payload: &[u8]) -> Vec<u8> {
        let mut v = Vec::new();
        let len = payload.len() as u32;
        v.extend_from_slice(&[(len >> 16) as u8, (len >> 8) as u8, len as u8]);
        v.push(kind);
        v.push(flags);
        v.extend_from_slice(&stream.to_be_bytes());
        v.extend_from_slice(payload);
        v
    }

    fn started() -> Http2Parser {
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        p
    }

    fn feed(p: &mut Http2Parser, dir: FlowSide, bytes: Vec<u8>) -> Vec<Http2Event> {
        p.push(dir, &Bytes::from(bytes));
        let mut out = Vec::new();
        while let Some(ev) = p.next_event() {
            out.push(ev);
        }
        out
    }

    /// A literal-with-indexing field: name and value, uncompressed.
    fn literal(name: &str, value: &str) -> Vec<u8> {
        let mut v = vec![0x40, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.push(value.len() as u8);
        v.extend_from_slice(value.as_bytes());
        v
    }

    #[test]
    fn a_request_head_carries_its_pseudo_headers() {
        let mut p = started();
        let mut block = vec![0x82, 0x87]; // :method GET, :scheme https
        block.extend(literal(":authority", "api.example.com"));
        block.extend(literal(":path", "/v1/orders"));
        let evs = feed(
            &mut p,
            FlowSide::Initiator,
            frame(0x1, flags::END_HEADERS, 1, &block),
        );
        match &evs[0] {
            Http2Event::Head(h) => {
                assert_eq!(h.stream_id, 1);
                assert_eq!(h.method(), Some("GET"));
                assert_eq!(h.scheme(), Some("https"));
                assert_eq!(h.authority(), Some("api.example.com"));
                assert_eq!(h.path(), Some("/v1/orders"));
                assert!(!h.end_stream);
            }
            other => panic!("expected a head, got {other:?}"),
        }
    }

    #[test]
    fn a_field_block_reassembles_across_continuation() {
        let mut p = started();
        let mut block = vec![0x82];
        block.extend(literal(":authority", "split.example"));
        let (a, b) = block.split_at(2);

        // HEADERS without END_HEADERS, then CONTINUATION with it.
        let mut wire = frame(0x1, 0, 1, a);
        wire.extend(frame(0x9, flags::END_HEADERS, 1, b));
        let evs = feed(&mut p, FlowSide::Initiator, wire);
        match &evs[0] {
            Http2Event::Head(h) => assert_eq!(h.authority(), Some("split.example")),
            other => panic!("expected a head, got {other:?}"),
        }
    }

    #[test]
    fn a_frame_interleaved_into_a_field_block_is_refused() {
        // §6.10: nothing may come between HEADERS and its
        // CONTINUATION on that stream. Allowing it would let a sender
        // desynchronise two implementations' idea of the block.
        let mut p = started();
        let mut wire = frame(0x1, 0, 1, &[0x82]);
        wire.extend(frame(0x0, 0, 1, b"data"));
        feed(&mut p, FlowSide::Initiator, wire);
        assert_eq!(p.error(), Some(Http2Error::InterleavedContinuation));
    }

    #[test]
    fn a_continuation_with_no_block_open_is_refused() {
        let mut p = started();
        feed(
            &mut p,
            FlowSide::Initiator,
            frame(0x9, flags::END_HEADERS, 1, &[0x82]),
        );
        assert_eq!(p.error(), Some(Http2Error::UnexpectedContinuation));
    }

    #[test]
    fn data_is_reported_and_end_stream_completes() {
        let mut p = started();
        let mut wire = frame(0x1, flags::END_HEADERS, 1, &[0x82]);
        wire.extend(frame(0x0, 0, 1, b"hello"));
        wire.extend(frame(0x0, flags::END_STREAM, 1, b" world"));
        let evs = feed(&mut p, FlowSide::Initiator, wire);

        let body: Vec<u8> = evs
            .iter()
            .filter_map(|e| match e {
                Http2Event::Body { data, .. } => Some(data.to_vec()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .concat();
        assert_eq!(body, b"hello world");
        assert!(matches!(
            evs.last(),
            Some(Http2Event::End { stream_id: 1, .. })
        ));
    }

    #[test]
    fn a_second_field_block_on_a_stream_is_trailers() {
        // Headers, data, then another block — that is where
        // grpc-status lives.
        let mut p = started();
        let mut wire = frame(0x1, flags::END_HEADERS, 1, &[0x88]); // :status 200
        wire.extend(frame(0x0, 0, 1, b"body"));
        let mut trailer = Vec::new();
        trailer.extend(literal("grpc-status", "0"));
        wire.extend(frame(
            0x1,
            flags::END_HEADERS | flags::END_STREAM,
            1,
            &trailer,
        ));
        let evs = feed(&mut p, FlowSide::Responder, wire);

        let trailers = evs.iter().find_map(|e| match e {
            Http2Event::Trailers { fields, .. } => Some(fields.clone()),
            _ => None,
        });
        let t = trailers.expect("trailers must be reported separately from the head");
        assert_eq!(t[0].0.as_ref(), b"grpc-status");
        assert_eq!(t[0].1.as_ref(), b"0");
    }

    #[test]
    fn a_trailers_only_response_is_a_head_not_trailers() {
        // gRPC's Trailers-Only: one HEADERS with END_STREAM and no
        // preceding block, so it is the head of the stream.
        let mut p = started();
        let mut block = vec![0x88];
        block.extend(literal("grpc-status", "5"));
        let evs = feed(
            &mut p,
            FlowSide::Responder,
            frame(0x1, flags::END_HEADERS | flags::END_STREAM, 3, &block),
        );
        match &evs[0] {
            Http2Event::Head(h) => {
                assert!(h.end_stream);
                assert_eq!(h.field("grpc-status"), Some(&b"5"[..]));
            }
            other => panic!("expected a head, got {other:?}"),
        }
    }

    #[test]
    fn interleaved_streams_keep_their_own_state() {
        let mut p = started();
        let mut wire = frame(0x1, flags::END_HEADERS, 1, &[0x82]);
        wire.extend(frame(0x1, flags::END_HEADERS, 3, &[0x83])); // :method POST
        wire.extend(frame(0x0, 0, 1, b"one"));
        wire.extend(frame(0x0, 0, 3, b"three"));
        let evs = feed(&mut p, FlowSide::Initiator, wire);

        let for_stream = |id: u32| -> Vec<u8> {
            evs.iter()
                .filter_map(|e| match e {
                    Http2Event::Body {
                        stream_id, data, ..
                    } if *stream_id == id => Some(data.to_vec()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .concat()
        };
        assert_eq!(for_stream(1), b"one");
        assert_eq!(for_stream(3), b"three");
    }

    #[test]
    fn a_push_promise_decodes_and_is_keyed_to_the_promised_stream() {
        // Regression: the four promised-id octets precede the field
        // block. Feeding them to HPACK killed the connection and
        // would have corrupted the dynamic table for every later
        // block — so a server that pushes broke everything after it.
        let mut p = started();
        let _ = feed(
            &mut p,
            FlowSide::Initiator,
            frame(0x1, flags::END_HEADERS, 1, &[0x82]),
        );

        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.push(0x84); // :path /
        payload.extend(literal(":authority", "push.example"));
        let evs = feed(
            &mut p,
            FlowSide::Responder,
            frame(0x5, flags::END_HEADERS, 1, &payload),
        );

        assert!(
            !p.is_failed(),
            "a valid PUSH_PROMISE must not fail the connection"
        );
        match &evs[0] {
            Http2Event::Head(h) => {
                assert_eq!(h.stream_id, 2, "the block describes the promised stream");
                assert_eq!(h.path(), Some("/"));
                assert_eq!(h.authority(), Some("push.example"));
            }
            other => panic!("expected a head, got {other:?}"),
        }
    }

    #[test]
    fn a_push_promise_does_not_corrupt_later_blocks() {
        // The real damage from the bug above: HPACK state is shared,
        // so a mis-decoded promise poisons every block after it.
        let mut p = started();
        let mut payload = 2u32.to_be_bytes().to_vec();
        payload.extend(literal(":authority", "shared.example"));
        let _ = feed(
            &mut p,
            FlowSide::Responder,
            frame(0x5, flags::END_HEADERS, 1, &payload),
        );
        // Index 62 is the entry the promise just inserted.
        let evs = feed(
            &mut p,
            FlowSide::Responder,
            frame(0x1, flags::END_HEADERS, 3, &[0x88, 0xbe]),
        );
        assert!(!p.is_failed());
        match &evs[0] {
            Http2Event::Head(h) => assert_eq!(h.authority(), Some("shared.example")),
            other => panic!("expected a head, got {other:?}"),
        }
    }

    #[test]
    fn sequential_streams_beyond_the_concurrency_cap_keep_working() {
        // A completed stream must free its slot. Otherwise a long
        // keep-alive connection doing ordinary sequential requests
        // would hit TooManyStreams and be killed — a false positive
        // on entirely normal traffic.
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_concurrent_streams(4));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        for i in 0..40u32 {
            let id = i * 2 + 1;
            let _ = feed(
                &mut p,
                FlowSide::Initiator,
                frame(0x1, flags::END_HEADERS | flags::END_STREAM, id, &[0x82]),
            );
            let _ = feed(
                &mut p,
                FlowSide::Responder,
                frame(0x1, flags::END_HEADERS | flags::END_STREAM, id, &[0x88]),
            );
            assert!(
                !p.is_failed(),
                "sequential streams must not exhaust the cap"
            );
            assert!(p.tracked_streams() <= 4, "tracked {}", p.tracked_streams());
        }
    }

    #[test]
    fn a_reset_stream_frees_its_slot() {
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_concurrent_streams(4));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        for i in 0..40u32 {
            let id = i * 2 + 1;
            let _ = feed(
                &mut p,
                FlowSide::Initiator,
                frame(0x1, flags::END_HEADERS, id, &[0x82]),
            );
            let _ = feed(
                &mut p,
                FlowSide::Initiator,
                frame(0x3, 0, id, &8u32.to_be_bytes()),
            );
            assert!(!p.is_failed(), "cancelled streams must free their slots");
        }
    }

    #[test]
    fn rst_stream_and_goaway_are_reported() {
        let mut p = started();
        let mut wire = frame(0x1, flags::END_HEADERS, 1, &[0x82]);
        wire.extend(frame(0x3, 0, 1, &8u32.to_be_bytes())); // CANCEL
        wire.extend(frame(0x7, 0, 0, &[0, 0, 0, 1, 0, 0, 0, 0]));
        let evs = feed(&mut p, FlowSide::Initiator, wire);
        assert!(evs.iter().any(|e| matches!(
            e,
            Http2Event::StreamReset {
                stream_id: 1,
                error_code: 8
            }
        )));
        assert!(evs.iter().any(|e| matches!(
            e,
            Http2Event::GoAway {
                last_stream_id: 1,
                ..
            }
        )));
    }

    #[test]
    fn settings_narrow_the_peers_limits_but_cannot_widen_ours() {
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_frame_size(16_384));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        // The client announces a 1 MiB max frame size for what the
        // server sends. Our own ceiling must still hold.
        let payload = [0x00, 0x05, 0x00, 0x10, 0x00, 0x00];
        feed(&mut p, FlowSide::Initiator, frame(0x4, 0, 0, &payload));
        assert_eq!(p.response.max_frame_size, 16_384);
    }

    #[test]
    fn a_bad_preface_fails_immediately() {
        let mut p = Http2Parser::new();
        p.push(
            FlowSide::Initiator,
            &Bytes::from_static(b"GET / HTTP/1.1\r\n"),
        );
        assert_eq!(p.error(), Some(Http2Error::BadPreface));
    }

    #[test]
    fn a_partial_preface_waits() {
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(&PREFACE[..10]));
        assert!(!p.is_failed());
        assert!(p.next_event().is_none());
    }

    #[test]
    fn split_feeds_produce_the_same_events() {
        let mut block = vec![0x82, 0x87];
        block.extend(literal(":authority", "drip.example"));
        block.extend(literal(":path", "/x"));
        let mut wire = PREFACE.to_vec();
        wire.extend(frame(0x1, flags::END_HEADERS, 1, &block));
        wire.extend(frame(0x0, flags::END_STREAM, 1, b"payload"));

        let describe = |evs: &[Http2Event]| -> Vec<String> {
            evs.iter()
                .map(|e| match e {
                    Http2Event::Head(h) => format!("head {:?} {:?}", h.authority(), h.path()),
                    Http2Event::Body { data, .. } => {
                        format!("body {}", String::from_utf8_lossy(data))
                    }
                    Http2Event::Trailers { .. } => "trailers".into(),
                    Http2Event::End { stream_id, .. } => format!("end {stream_id}"),
                    other => format!("{other:?}"),
                })
                .collect()
        };

        let mut whole = Http2Parser::new();
        let a = feed(&mut whole, FlowSide::Initiator, wire.clone());

        let mut drip = Http2Parser::new();
        let mut b = Vec::new();
        for byte in &wire {
            b.extend(feed(&mut drip, FlowSide::Initiator, vec![*byte]));
        }
        assert_eq!(describe(&a), describe(&b));
        assert!(!describe(&a).is_empty());
    }

    #[test]
    fn too_many_streams_is_refused() {
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_concurrent_streams(4));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        for i in 0..32u32 {
            let id = i * 2 + 1;
            feed(
                &mut p,
                FlowSide::Initiator,
                frame(0x1, flags::END_HEADERS, id, &[0x82]),
            );
            if p.is_failed() {
                assert_eq!(p.error(), Some(Http2Error::TooManyStreams));
                return;
            }
        }
        panic!("unbounded stream tracking must be refused");
    }

    #[test]
    fn an_oversized_field_block_is_refused() {
        let mut p =
            Http2Parser::with_config(Http2Config::default().with_max_header_block_bytes(256));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        // A block built up across CONTINUATIONs past the cap.
        let chunk = vec![0x82u8; 200];
        let mut wire = frame(0x1, 0, 1, &chunk);
        wire.extend(frame(0x9, 0, 1, &chunk));
        feed(&mut p, FlowSide::Initiator, wire);
        assert_eq!(p.error(), Some(Http2Error::HeaderListTooLong));
    }

    #[test]
    fn a_failed_connection_accepts_nothing_further() {
        let mut p = Http2Parser::new();
        p.push(FlowSide::Initiator, &Bytes::from_static(b"not h2"));
        assert!(p.is_failed());
        assert_eq!(p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE)), 0);
    }

    #[test]
    fn a_frame_that_could_never_fit_the_buffer_is_refused_at_its_header() {
        // The wedge: `max_frame_size` above `max_buffered_bytes`
        // means a frame the parser accepts but can never assemble. It
        // used to buffer to the cap and then refuse every byte for
        // the life of the connection, reporting nothing — and a
        // caller that cannot see the accepted count, like the
        // `SessionParser` adapter, would read that as silence.
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_buffered_bytes(4096));
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        // A 64 KiB DATA frame: legal under the 1 MiB default
        // `max_frame_size`, impossible under a 4 KiB buffer.
        let mut wire = vec![0x00, 0xff, 0xff, 0x0, 0x0, 0, 0, 0, 1];
        wire.extend(std::iter::repeat_n(0u8, 8192));
        p.push(FlowSide::Initiator, &Bytes::from(wire));
        assert_eq!(p.error(), Some(Http2Error::FrameTooLarge));
    }

    #[test]
    fn backpressure_applies_when_a_frame_spans_offers() {
        // A short count is still the signal for a frame that *can*
        // fit but has not all arrived. Backpressure is not a failure.
        let mut p = Http2Parser::with_config(
            Http2Config::default()
                .with_max_buffered_bytes(8192)
                .with_max_frame_size(4096),
        );
        p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
        // A 3500-byte DATA frame, delivered in two offers with far
        // more trailing data than the buffer can take at once.
        let mut wire = vec![0x00, 0x0d, 0xac, 0x0, 0x0, 0, 0, 0, 1];
        wire.extend(std::iter::repeat_n(0u8, 3500));
        wire.extend(std::iter::repeat_n(0u8, 16_384));
        let accepted = p.push(FlowSide::Initiator, &Bytes::from(wire.clone()));
        assert!(accepted < wire.len(), "a full buffer must short-count");
        assert!(!p.is_failed(), "backpressure is not a failure");
    }

    #[test]
    fn a_buffer_cap_below_the_preface_fails_rather_than_stalls() {
        // The one path cap composition cannot rescue: a cap so small
        // that even the 24-byte preface cannot be held. This is the
        // `BufferOverflow` guard, and the only way that variant is
        // ever constructed.
        let mut p = Http2Parser::with_config(Http2Config::default().with_max_buffered_bytes(8));
        p.push(FlowSide::Initiator, &Bytes::copy_from_slice(&PREFACE[..8]));
        p.push(FlowSide::Initiator, &Bytes::copy_from_slice(&PREFACE[8..]));
        assert_eq!(p.error(), Some(Http2Error::BufferOverflow));
    }

    #[test]
    fn never_panics_on_arbitrary_bytes() {
        for seed in 0..64u8 {
            let mut p = Http2Parser::new();
            p.push(FlowSide::Initiator, &Bytes::from_static(PREFACE));
            let bytes: Vec<u8> = (0..256u16)
                .map(|i| (i as u8).wrapping_mul(seed).wrapping_add(7))
                .collect();
            p.push(FlowSide::Initiator, &Bytes::from(bytes.clone()));
            p.push(FlowSide::Responder, &Bytes::from(bytes));
            while p.next_event().is_some() {}
        }
    }
}
