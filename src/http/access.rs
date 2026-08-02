//! Access logging for the streaming path.
//!
//! An inline proxy still owes its operator the same records a passive
//! monitor produces: who asked for what, what came back, how big it
//! was, and whether the connection was refused. [`HttpAccessLog`]
//! derives those from the [`HttpEvent`] stream **without retaining a
//! single body byte** — it watches heads and counts, nothing more.

use bytes::Bytes;

use super::{poison::HttpPoison, proxy::HttpEvent, types::HttpVersion};
use crate::FlowSide;

/// How an exchange finished.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum HttpAccessOutcome {
    /// A request and its response were both fully framed.
    Completed,
    /// The connection ended with the request unanswered.
    NoResponse,
    /// Framing was refused; nothing further was forwarded.
    Refused { reason: HttpPoison },
    /// The exchange handed the connection to another protocol.
    Switched,
}

/// One line of an access log, derived from the streaming events.
///
/// Byte counts are **wire** bytes of the message body as framed
/// (chunk framing included), counted as they passed — the parser
/// never held them.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct HttpAccessRecord {
    pub method: Bytes,
    /// Request-target exactly as it appeared on the wire.
    pub path: Bytes,
    /// Routing authority — absolute-form target if present, else the
    /// `Host` header. `None` if neither was usable.
    pub authority: Option<String>,
    pub version: HttpVersion,
    /// Final response status. `None` when no response was framed.
    /// Interim `1xx` responses never land here.
    pub status: Option<u16>,
    /// Body bytes sent by the client, as framed on the wire.
    pub request_body_bytes: u64,
    /// Body bytes sent by the server, as framed on the wire.
    pub response_body_bytes: u64,
    pub outcome: HttpAccessOutcome,
}

impl HttpAccessRecord {
    /// Method as UTF-8.
    pub fn method_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.method).ok()
    }

    /// Request-target as UTF-8.
    pub fn path_str(&self) -> Option<&str> {
        std::str::from_utf8(&self.path).ok()
    }

    /// Status class — `status / 100`.
    pub fn status_class(&self) -> Option<u8> {
        let cls = self.status? / 100;
        (1..=5).contains(&cls).then_some(cls as u8)
    }
}

/// Turns a stream of [`HttpEvent`]s into access records.
///
/// Feed every event; take a record whenever one completes. Requests
/// are matched to responses in wire order, the way HTTP/1.1
/// pipelining requires.
///
/// ```
/// use bytes::Bytes;
/// use flowscope::FlowSide;
/// use flowscope::http::{HttpAccessLog, HttpProxyParser};
///
/// let mut proxy = HttpProxyParser::new();
/// let mut log = HttpAccessLog::new();
/// let mut records = Vec::new();
///
/// proxy.push(
///     FlowSide::Initiator,
///     &Bytes::from_static(b"GET /health HTTP/1.1\r\nHost: api.example\r\n\r\n"),
/// );
/// proxy.push(
///     FlowSide::Responder,
///     &Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok"),
/// );
/// while let Some(ev) = proxy.next_event() {
///     log.observe(&ev, &mut records);
/// }
///
/// assert_eq!(records.len(), 1);
/// assert_eq!(records[0].status, Some(200));
/// assert_eq!(records[0].response_body_bytes, 2);
/// assert_eq!(records[0].authority.as_deref(), Some("api.example"));
/// ```
#[derive(Debug, Clone, Default)]
pub struct HttpAccessLog {
    /// Requests awaiting a response, in wire order.
    pending: std::collections::VecDeque<Pending>,
    /// Response-side byte count for the exchange being answered.
    response_bytes: u64,
    /// Status of the final (non-interim) response in flight.
    status: Option<u16>,
    /// Set once a switch is seen, so the open exchange is reported
    /// as switched rather than unanswered.
    switched: bool,
}

#[derive(Debug, Clone)]
struct Pending {
    method: Bytes,
    path: Bytes,
    authority: Option<String>,
    version: HttpVersion,
    body_bytes: u64,
    /// `true` once the request side is fully framed, so later body
    /// bytes belong to the next request rather than this one.
    complete: bool,
}

impl HttpAccessLog {
    pub fn new() -> Self {
        Self::default()
    }

    /// Feed one event, pushing any completed records into `out`.
    pub fn observe(&mut self, event: &HttpEvent, out: &mut Vec<HttpAccessRecord>) {
        match event {
            HttpEvent::RequestHead(head) => {
                self.pending.push_back(Pending {
                    method: head.method.clone(),
                    path: head.path.clone(),
                    authority: head.authority().ok().map(|a| a.host),
                    version: head.version,
                    body_bytes: 0,
                    complete: false,
                });
            }
            HttpEvent::ResponseHead(head) => {
                // Interim responses precede the real one and carry no
                // body; they are not the outcome of the exchange.
                if !head.interim {
                    self.response_bytes = 0;
                    if let Some(p) = self.pending.front_mut() {
                        p.complete = true;
                    }
                    self.status = Some(head.status);
                }
            }
            HttpEvent::Body { dir, raw, .. } => match dir {
                FlowSide::Initiator => {
                    if let Some(p) = self.pending.iter_mut().find(|p| !p.complete) {
                        p.body_bytes += raw.len() as u64;
                    }
                }
                FlowSide::Responder => self.response_bytes += raw.len() as u64,
            },
            HttpEvent::Trailers { dir, raw, .. } => match dir {
                FlowSide::Initiator => {
                    if let Some(p) = self.pending.iter_mut().find(|p| !p.complete) {
                        p.body_bytes += raw.len() as u64;
                    }
                }
                FlowSide::Responder => self.response_bytes += raw.len() as u64,
            },
            HttpEvent::End { dir } => {
                match dir {
                    FlowSide::Initiator => {
                        if let Some(p) = self.pending.iter_mut().find(|p| !p.complete) {
                            p.complete = true;
                        }
                    }
                    FlowSide::Responder => {
                        // A response completed: pair it with the
                        // oldest outstanding request.
                        if let Some(p) = self.pending.pop_front() {
                            out.push(self.record(p, HttpAccessOutcome::Completed));
                        }
                        self.response_bytes = 0;
                        self.status = None;
                    }
                }
            }
            HttpEvent::SwitchProtocols { .. } => {
                self.switched = true;
            }
        }
    }

    /// Close the log out, reporting every exchange that never got a
    /// response.
    ///
    /// Call when the connection ends, or when the parser refuses it —
    /// pass the [`poison`](super::HttpProxyParser::poison) so the
    /// records say *why* nothing came back.
    pub fn finish(&mut self, poison: Option<HttpPoison>, out: &mut Vec<HttpAccessRecord>) {
        let outcome = match (poison, self.switched) {
            (Some(reason), _) => HttpAccessOutcome::Refused { reason },
            (None, true) => HttpAccessOutcome::Switched,
            (None, false) => HttpAccessOutcome::NoResponse,
        };
        while let Some(p) = self.pending.pop_front() {
            out.push(self.record(p, outcome.clone()));
        }
        self.response_bytes = 0;
        self.status = None;
        self.switched = false;
    }

    fn record(&self, p: Pending, outcome: HttpAccessOutcome) -> HttpAccessRecord {
        let completed = matches!(outcome, HttpAccessOutcome::Completed);
        HttpAccessRecord {
            method: p.method,
            path: p.path,
            authority: p.authority,
            version: p.version,
            status: if completed { self.status } else { None },
            request_body_bytes: p.body_bytes,
            response_body_bytes: if completed { self.response_bytes } else { 0 },
            outcome,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::HttpProxyParser;

    fn run(client: &[u8], server: &[u8]) -> (Vec<HttpAccessRecord>, HttpProxyParser) {
        let mut proxy = HttpProxyParser::new();
        let mut log = HttpAccessLog::new();
        let mut out = Vec::new();
        proxy.push(FlowSide::Initiator, &Bytes::copy_from_slice(client));
        proxy.push(FlowSide::Responder, &Bytes::copy_from_slice(server));
        while let Some(ev) = proxy.next_event() {
            log.observe(&ev, &mut out);
        }
        log.finish(proxy.poison(), &mut out);
        (out, proxy)
    }

    #[test]
    fn records_a_completed_exchange() {
        let (recs, _) = run(
            b"POST /orders HTTP/1.1\r\nHost: api.example\r\nContent-Length: 5\r\n\r\nhello",
            b"HTTP/1.1 201 Created\r\nContent-Length: 2\r\n\r\nok",
        );
        assert_eq!(recs.len(), 1);
        let r = &recs[0];
        assert_eq!(r.method_str(), Some("POST"));
        assert_eq!(r.path_str(), Some("/orders"));
        assert_eq!(r.authority.as_deref(), Some("api.example"));
        assert_eq!(r.status, Some(201));
        assert_eq!(r.request_body_bytes, 5);
        assert_eq!(r.response_body_bytes, 2);
        assert_eq!(r.outcome, HttpAccessOutcome::Completed);
        assert_eq!(r.status_class(), Some(2));
    }

    #[test]
    fn counts_chunked_wire_bytes_without_holding_them() {
        let (recs, proxy) = run(
            b"POST /u HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
        );
        assert_eq!(recs.len(), 1);
        // "5\r\n" + "hello" + "\r\n" + "0\r\n\r\n" = 15 wire bytes.
        assert_eq!(recs[0].request_body_bytes, 15);
        assert_eq!(proxy.buffered(FlowSide::Initiator), 0);
    }

    #[test]
    fn pipelined_exchanges_pair_in_order() {
        let (recs, _) = run(
            b"GET /a HTTP/1.1\r\nHost: h\r\n\r\nGET /b HTTP/1.1\r\nHost: h\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\n\r\nA\
              HTTP/1.1 404 Not Found\r\nContent-Length: 1\r\n\r\nB",
        );
        let seen: Vec<(&str, Option<u16>)> = recs
            .iter()
            .map(|r| (r.path_str().unwrap(), r.status))
            .collect();
        assert_eq!(seen, vec![("/a", Some(200)), ("/b", Some(404))]);
    }

    #[test]
    fn interim_responses_do_not_end_the_exchange() {
        let (recs, _) = run(
            b"POST /u HTTP/1.1\r\nHost: h\r\nExpect: 100-continue\r\nContent-Length: 2\r\n\r\nhi",
            b"HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 204 No Content\r\n\r\n",
        );
        assert_eq!(recs.len(), 1, "the interim is not its own record");
        assert_eq!(recs[0].status, Some(204));
    }

    #[test]
    fn an_unanswered_request_is_reported() {
        let (recs, _) = run(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n", b"");
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].outcome, HttpAccessOutcome::NoResponse);
        assert_eq!(recs[0].status, None);
    }

    #[test]
    fn a_refused_connection_says_why() {
        let (recs, _) = run(
            b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\
              Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            b"",
        );
        // The request never framed, so there is nothing to pair —
        // but the refusal itself must not be silent.
        assert!(
            recs.iter()
                .all(|r| matches!(r.outcome, HttpAccessOutcome::Refused { .. }))
        );
    }

    #[test]
    fn a_tunnelled_exchange_is_marked_switched() {
        let (recs, _) = run(
            b"CONNECT h:443 HTTP/1.1\r\nHost: h:443\r\n\r\n",
            b"HTTP/1.1 200 Connection Established\r\n\r\n",
        );
        assert_eq!(recs.len(), 1);
        assert_eq!(recs[0].outcome, HttpAccessOutcome::Switched);
        assert_eq!(recs[0].method_str(), Some("CONNECT"));
    }
}
