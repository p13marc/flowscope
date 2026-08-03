//! [`Http2Parser`] as a [`SessionParser`](crate::SessionParser).
//!
//! The HTTP/1 counterpart is
//! [`HttpProxySession`](crate::http::HttpProxySession) (#164); this is
//! the same boundary for h2 (#196).

use bytes::Bytes;

use super::{Http2Config, Http2Error, Http2Event, Http2Parser};
use crate::{FlowSide, ParserKind, Timestamp};

/// [`Http2Parser`] as a [`SessionParser`](crate::SessionParser), so
/// per-stream h2 events ride flowscope's own plumbing — the typed
/// `Driver`, the pcap replay helpers, the `emit` writers.
///
/// Use this when flowscope drives the bytes. Use [`Http2Parser`]
/// directly when *you* own the sockets: the trait cannot express a
/// short read, so [`push`](Http2Parser::push)'s accepted count — the
/// backpressure signal — is not available through this adapter, and
/// bytes are copied once at the boundary because the trait hands out
/// `&[u8]`.
///
/// # Direction is not stream
///
/// The driver labels every message with the [`FlowSide`] the bytes
/// arrived on. For h2 that is the *transport* direction, not a
/// message identity: one connection carries many concurrent streams
/// in both directions, so the key to route on is the `stream_id` on
/// the event itself, and the envelope's side only ever says which
/// peer sent these bytes.
///
/// # Joining late
///
/// [`Http2Parser::new`] demands the client preface, because a caller
/// that owns the socket knows the connection started at byte zero. A
/// driver does not: capture starts mid-flow, heuristic slots pin
/// after probing, an h2c upgrade may have had its preface consumed
/// elsewhere. So [`Http2Session::new`] sets
/// [`Http2Config::require_preface`] to `false`, which *tolerates* a
/// missing preface rather than skipping one — a preface that is there
/// is still consumed, and bytes that are not frame-aligned still
/// fail. Pass [`with_config`](Self::with_config) a default
/// `Http2Config` to demand it.
///
/// A terminal [`Http2Error`] surfaces as a poisoned parser. The
/// driver drops it and emits
/// [`Event::ParserClosed`](crate::driver::Event::ParserClosed) with
/// [`EndReason::ParseError`](crate::EndReason::ParseError) rather than
/// keep feeding a parser whose HPACK state is already meaningless.
/// The TCP flow itself keeps going — flowscope does not own the
/// socket, so closing the connection is the caller's decision.
///
/// ```
/// use flowscope::http2::{Http2Event, Http2Session};
/// use flowscope::{SessionParser, Timestamp};
///
/// // A HEADERS frame on stream 1, ":method: GET" as static index 2.
/// // No preface: this flow was picked up mid-connection.
/// let mut wire = vec![0, 0, 1, 0x1, 0x05, 0, 0, 0, 1];
/// wire.push(0x82);
///
/// let mut session = Http2Session::new();
/// let mut out = Vec::new();
/// session.feed_initiator(&wire, Timestamp::default(), &mut out);
///
/// let Some(Http2Event::Head(head)) = out.first() else {
///     panic!("expected a head")
/// };
/// assert_eq!(head.stream_id, 1);
/// assert_eq!(head.method(), Some("GET"));
/// ```
#[derive(Debug, Clone)]
pub struct Http2Session {
    inner: Http2Parser,
}

impl Default for Http2Session {
    fn default() -> Self {
        Self::new()
    }
}

impl Http2Session {
    /// A session for a connection flowscope may have joined late:
    /// default caps, preface tolerated rather than required.
    pub fn new() -> Self {
        Self::with_config(Http2Config::default().with_require_preface(false))
    }

    /// A session with explicit caps and preface policy.
    ///
    /// `Http2Config::default()` demands the preface, exactly as
    /// [`Http2Parser::new`] does — the tolerance is a property of
    /// [`Http2Session::new`], not of the adapter.
    pub fn with_config(config: Http2Config) -> Self {
        Self {
            inner: Http2Parser::with_config(config),
        }
    }

    /// The underlying parser, for state the trait does not expose:
    /// the typed [`Http2Error`], `buffered`, `tracked_streams`.
    pub fn parser(&self) -> &Http2Parser {
        &self.inner
    }

    fn feed(&mut self, dir: FlowSide, bytes: &[u8], out: &mut Vec<Http2Event>) {
        if bytes.is_empty() {
            return;
        }
        // The trait gives us a borrowed slice, so one copy here is
        // unavoidable; every event downstream is a refcounted view of
        // it. Feed in a loop because the parser bounds how much it
        // will hold at once and the trait has no way to say "not all
        // of it yet".
        let mut data = Bytes::copy_from_slice(bytes);
        loop {
            let accepted = self.inner.push(dir, &data);
            while let Some(ev) = self.inner.next_event() {
                out.push(ev);
            }
            if accepted == data.len() {
                break;
            }
            if accepted == 0 {
                // `push` only refuses everything from a state it
                // reports: the connection failed, or this direction
                // finished. It never sits on a full buffer in
                // silence. So the tail dropped here is a tail no
                // parser could have used, and the caller learns why
                // from `is_poisoned` / `is_done`.
                debug_assert!(
                    self.inner.is_failed() || self.inner.is_finished(dir),
                    "push refused bytes without reporting a reason",
                );
                break;
            }
            data = data.slice(accepted..);
        }
    }

    fn rebuild(&mut self) {
        // A RST ends this connection; the four-tuple may be reused by
        // the next one. Rebuilding from the config carries the caps
        // *and* the preface policy over.
        self.inner = Http2Parser::with_config(self.inner.config().clone());
    }
}

impl crate::SessionParser for Http2Session {
    type Message = Http2Event;

    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Http2Event>) {
        self.feed(FlowSide::Initiator, bytes, out);
    }

    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp, out: &mut Vec<Http2Event>) {
        self.feed(FlowSide::Responder, bytes, out);
    }

    fn fin_initiator(&mut self, out: &mut Vec<Http2Event>) {
        self.inner.fin(FlowSide::Initiator);
        while let Some(ev) = self.inner.next_event() {
            out.push(ev);
        }
    }

    fn fin_responder(&mut self, out: &mut Vec<Http2Event>) {
        self.inner.fin(FlowSide::Responder);
        while let Some(ev) = self.inner.next_event() {
            out.push(ev);
        }
    }

    fn rst_initiator(&mut self) {
        self.rebuild();
    }

    fn rst_responder(&mut self) {
        self.rebuild();
    }

    fn parser_kind(&self) -> ParserKind {
        ParserKind::Http2
    }

    fn is_poisoned(&self) -> bool {
        self.inner.is_failed()
    }

    fn poison_reason(&self) -> Option<&str> {
        self.inner.error().map(Http2Error::as_str)
    }

    fn is_done(&self) -> bool {
        self.inner.is_done()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::SessionParser as _;
    use crate::http2::PREFACE;

    const HEADERS: u8 = 0x1;
    const DATA: u8 = 0x0;
    const END_HEADERS: u8 = 0x4;

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

    fn literal(name: &str, value: &str) -> Vec<u8> {
        let mut v = vec![0x40, name.len() as u8];
        v.extend_from_slice(name.as_bytes());
        v.push(value.len() as u8);
        v.extend_from_slice(value.as_bytes());
        v
    }

    fn feed(s: &mut Http2Session, dir: FlowSide, bytes: &[u8]) -> Vec<Http2Event> {
        let mut out = Vec::new();
        match dir {
            FlowSide::Initiator => s.feed_initiator(bytes, Timestamp::default(), &mut out),
            FlowSide::Responder => s.feed_responder(bytes, Timestamp::default(), &mut out),
        }
        out
    }

    #[test]
    fn adapter_emits_stream_events_through_the_trait() {
        let mut s = Http2Session::new();
        let mut block = vec![0x82, 0x87]; // :method GET, :scheme https
        block.extend(literal(":authority", "api.example"));
        block.extend(literal(":path", "/v1/things"));
        let mut wire = PREFACE.to_vec();
        wire.extend(frame(HEADERS, END_HEADERS, 1, &block));

        let out = feed(&mut s, FlowSide::Initiator, &wire);
        let head = out
            .iter()
            .find_map(|e| match e {
                Http2Event::Head(h) => Some(h),
                _ => None,
            })
            .expect("a head");
        assert_eq!(head.authority(), Some("api.example"));
        assert_eq!(head.path(), Some("/v1/things"));
        assert_eq!(s.parser_kind(), ParserKind::Http2);
    }

    #[test]
    fn adapter_joins_a_connection_with_no_preface() {
        // The default session tolerates it...
        let mut tolerant = Http2Session::new();
        let bare = frame(HEADERS, END_HEADERS, 3, &[0x82]);
        let out = feed(&mut tolerant, FlowSide::Initiator, &bare);
        assert!(!tolerant.is_poisoned(), "{:?}", tolerant.poison_reason());
        assert!(matches!(out.first(), Some(Http2Event::Head(h)) if h.stream_id == 3));

        // ...and a session built from a default config does not.
        let mut strict = Http2Session::with_config(Http2Config::default());
        feed(&mut strict, FlowSide::Initiator, &bare);
        assert_eq!(strict.poison_reason(), Some("bad-preface"));
    }

    #[test]
    fn adapter_reports_a_framing_failure_as_poison() {
        let mut s = Http2Session::new();
        // A field block left open, then another frame on the same
        // stream — RFC 9113 §6.10 forbids the interleave.
        let mut wire = frame(HEADERS, 0, 1, &[0x82]);
        wire.extend(frame(DATA, 0, 1, b"x"));
        feed(&mut s, FlowSide::Initiator, &wire);
        assert!(s.is_poisoned());
        assert_eq!(s.poison_reason(), Some("interleaved-continuation"));
    }

    /// The trait hands over a whole slice at once with no way to say
    /// "not yet", so the adapter has to loop rather than silently
    /// drop the tail.
    #[test]
    fn adapter_survives_a_feed_larger_than_the_buffer_cap() {
        let mut s = Http2Session::with_config(
            Http2Config::default()
                .with_require_preface(false)
                .with_max_buffered_bytes(8 * 1024)
                .with_max_frame_size(4 * 1024),
        );
        let mut wire = frame(HEADERS, END_HEADERS, 1, &[0x82]);
        let chunk = vec![b'x'; 1024];
        for _ in 0..64 {
            wire.extend(frame(DATA, 0, 1, &chunk)); // 64 KiB of DATA
        }
        let out = feed(&mut s, FlowSide::Initiator, &wire);
        let body: usize = out
            .iter()
            .filter_map(|e| match e {
                Http2Event::Body { data, .. } => Some(data.len()),
                _ => None,
            })
            .sum();
        assert_eq!(body, 64 * 1024, "no body bytes may be lost");
        assert!(!s.is_poisoned());
    }

    /// Fails without the cap composition in `Http2Config`: `push`
    /// takes 4096, cannot parse a 16 KiB frame, refuses the rest, and
    /// the adapter drops 12 KiB with `is_poisoned()` false and zero
    /// events — the driver sees a healthy, permanently silent flow.
    #[test]
    fn a_frame_too_large_for_the_buffer_is_reported_not_swallowed() {
        let mut s = Http2Session::with_config(
            Http2Config::default()
                .with_require_preface(false)
                .with_max_buffered_bytes(4096),
        );
        let out = feed(
            &mut s,
            FlowSide::Initiator,
            &frame(DATA, 0, 1, &vec![0u8; 16 * 1024]),
        );
        assert!(
            s.is_poisoned(),
            "a parser that can never progress must say so"
        );
        assert_eq!(s.poison_reason(), Some("frame-too-large"));
        assert!(out.is_empty());
    }

    #[test]
    fn adapter_reset_starts_a_clean_connection_and_keeps_its_policy() {
        let mut s = Http2Session::new();
        let mut bad = frame(HEADERS, 0, 1, &[0x82]);
        bad.extend(frame(DATA, 0, 1, b"x"));
        feed(&mut s, FlowSide::Initiator, &bad);
        assert!(s.is_poisoned());

        s.rst_initiator();
        assert!(!s.is_poisoned(), "a reset starts a fresh connection");
        // And the preface tolerance survived the rebuild.
        let out = feed(
            &mut s,
            FlowSide::Initiator,
            &frame(HEADERS, END_HEADERS, 5, &[0x82]),
        );
        assert!(matches!(out.first(), Some(Http2Event::Head(h)) if h.stream_id == 5));
    }

    #[test]
    fn fin_finishes_the_session_without_poisoning() {
        let mut s = Http2Session::new();
        feed(
            &mut s,
            FlowSide::Initiator,
            &frame(HEADERS, END_HEADERS, 1, &[0x82]),
        );
        let mut out = Vec::new();
        s.fin_initiator(&mut out);
        assert!(!s.is_done(), "the responder side is still live");
        s.fin_responder(&mut out);
        assert!(s.is_done());
        assert!(!s.is_poisoned(), "a clean close is not a parse error");
    }
}
