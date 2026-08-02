//! [`HttpExchangeParser`] — request + response aggregator.
//!
//! Wraps [`super::HttpParser`] and stitches each request to the
//! response that arrives on the same flow. Emits one
//! [`HttpExchange`] per logical exchange — the shape every HTTP
//! observer example reached for.

use std::collections::VecDeque;
use std::time::Duration;

use crate::Timestamp;
use crate::session::SessionParser;

use super::HttpParser;
use super::session::HttpMessage;
use super::types::{HttpConfig, HttpRequest, HttpResponse};

/// Outcome of an observed HTTP exchange.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HttpOutcome {
    /// Request + matching response received.
    Completed,
    /// Request observed but flow ended before response arrived.
    NoResponse,
    /// Flow RST'd mid-exchange (one or both sides).
    Reset,
}

/// One HTTP request + response pair.
///
/// The response is `None` for [`HttpOutcome::NoResponse`] /
/// [`HttpOutcome::Reset`] when the responder never sent one. Body
/// bytes are kept on `request.body` / `response.body` per the
/// underlying [`HttpRequest`] / [`HttpResponse`] shape.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub elapsed: Option<Duration>,
    pub request_ts: Timestamp,
    pub response_ts: Option<Timestamp>,
    pub outcome: HttpOutcome,
}

impl HttpExchange {
    /// Convenience: status / 100 of the response, or `None` if no
    /// response was observed or the status falls outside
    /// `[100, 599]`.
    pub fn status_class(&self) -> Option<u8> {
        self.response.as_ref().and_then(|r| r.status_class())
    }

    /// `true` iff the exchange completed with a `2xx` response.
    pub fn is_success(&self) -> bool {
        self.status_class() == Some(2)
    }

    /// `true` iff the exchange completed with a `4xx` or `5xx`
    /// response.
    pub fn is_error(&self) -> bool {
        matches!(self.status_class(), Some(4) | Some(5))
    }
}

/// `SessionParser` impl that emits one [`HttpExchange`] per
/// request/response pair.
///
/// Assumes HTTP/1.1 in-order delivery: pipelined requests on
/// one connection are matched FIFO to responses. Flows that end
/// with pending requests drain into [`HttpOutcome::NoResponse`]
/// exchanges; RST yields [`HttpOutcome::Reset`].
#[derive(Debug, Clone)]
pub struct HttpExchangeParser {
    inner: HttpParser,
    pending: VecDeque<(HttpRequest, Timestamp)>,
    /// Requests that were in flight when the flow was reset. Held
    /// until the driver's `fin_*` so they can be reported with
    /// [`HttpOutcome::Reset`] — `rst_*` itself has no output channel.
    reset: VecDeque<(HttpRequest, Timestamp)>,
}

impl Default for HttpExchangeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl HttpExchangeParser {
    pub fn new() -> Self {
        Self {
            inner: HttpParser::default(),
            pending: VecDeque::new(),
            reset: VecDeque::new(),
        }
    }

    pub fn with_config(config: HttpConfig) -> Self {
        Self {
            inner: HttpParser::with_config(config),
            pending: VecDeque::new(),
            reset: VecDeque::new(),
        }
    }
}

impl SessionParser for HttpExchangeParser {
    type Message = HttpExchange;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, _out: &mut Vec<Self::Message>) {
        let mut inner = Vec::new();
        self.inner.feed_initiator(bytes, ts, &mut inner);
        for msg in inner {
            if let HttpMessage::Request(req) = msg {
                self.pending.push_back((req, ts));
            }
        }
        // Initiator never emits exchanges; only responses do.
    }

    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>) {
        let mut inner = Vec::new();
        self.inner.feed_responder(bytes, ts, &mut inner);
        for msg in inner {
            if let HttpMessage::Response(resp) = msg
                && let Some((req, req_ts)) = self.pending.pop_front()
            {
                let elapsed = ts.saturating_sub(req_ts);
                out.push(HttpExchange {
                    request: req,
                    response: Some(resp),
                    elapsed: Some(elapsed),
                    request_ts: req_ts,
                    response_ts: Some(ts),
                    outcome: HttpOutcome::Completed,
                });
            }
        }
    }

    fn fin_initiator(&mut self, _out: &mut Vec<Self::Message>) {
        let mut _drop = Vec::new();
        self.inner.fin_initiator(&mut _drop);
    }

    fn fin_responder(&mut self, out: &mut Vec<Self::Message>) {
        let mut inner = Vec::new();
        self.inner.fin_responder(&mut inner);
        for msg in inner {
            if let HttpMessage::Response(resp) = msg
                && let Some((req, req_ts)) = self.pending.pop_front()
            {
                out.push(HttpExchange {
                    request: req,
                    response: Some(resp),
                    elapsed: None,
                    request_ts: req_ts,
                    response_ts: None,
                    outcome: HttpOutcome::Completed,
                });
            }
        }
        // Requests cut short by a reset are reported as such; the
        // rest simply never saw a response.
        for (req, ts) in self.reset.drain(..) {
            out.push(HttpExchange {
                request: req,
                response: None,
                elapsed: None,
                request_ts: ts,
                response_ts: None,
                outcome: HttpOutcome::Reset,
            });
        }
        for (req, ts) in self.pending.drain(..) {
            out.push(HttpExchange {
                request: req,
                response: None,
                elapsed: None,
                request_ts: ts,
                response_ts: None,
                outcome: HttpOutcome::NoResponse,
            });
        }
    }

    fn rst_initiator(&mut self) {
        self.reset_pending();
    }

    fn rst_responder(&mut self) {
        self.reset_pending();
    }

    fn parser_kind(&self) -> crate::ParserKind {
        crate::ParserKind::Other("http-exchange")
    }

    fn is_poisoned(&self) -> bool {
        self.inner.is_poisoned()
    }

    fn poison_reason(&self) -> Option<&str> {
        self.inner.poison_reason()
    }
}

impl HttpExchangeParser {
    /// Move in-flight requests to the reset queue. `rst_*` has no
    /// output channel, and the driver always calls `fin_*` after it,
    /// so the exchanges surface there with [`HttpOutcome::Reset`].
    fn reset_pending(&mut self) {
        self.reset.extend(self.pending.drain(..));
    }
}
