//! [`DnsExchangeParser`] — DNS query + response aggregator.
//!
//! Wraps [`super::DnsUdpParser`] with correlation enabled and
//! emits one [`DnsExchange`] per logical exchange (query +
//! response, or query + timeout, or response with error rcode).

use std::time::Duration;

use crate::Timestamp;
use crate::event::FlowSide;
use crate::session::DatagramParser;

use super::DnsUdpParser;
use super::datagram::DnsMessage;
use super::types::{DnsConfig, DnsQuestion, DnsRcode, DnsRecord};

/// Outcome of an observed DNS exchange.
#[derive(Debug, Clone, PartialEq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DnsOutcome {
    /// Query + matching response with `rcode == NoError`.
    Completed,
    /// Query observed but no response within `DnsConfig::query_timeout`.
    NoResponse,
    /// Response arrived but the rcode signals failure (NXDOMAIN /
    /// SERVFAIL / FORMERR / …).
    Failed { rcode: DnsRcode },
}

/// One DNS query + response pair.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnsExchange {
    pub transaction_id: u16,
    pub question: DnsQuestion,
    pub answers: Vec<DnsRecord>,
    pub elapsed: Option<Duration>,
    pub query_ts: Timestamp,
    pub response_ts: Option<Timestamp>,
    pub outcome: DnsOutcome,
}

/// `DatagramParser` impl that emits one [`DnsExchange`] per
/// logical exchange.
///
/// Internally uses the correlation feature of
/// [`super::DnsUdpParser`]. The parser is UDP-only — DNS-over-TCP
/// uses different framing and is deferred to a follow-up plan.
#[derive(Debug, Clone)]
pub struct DnsExchangeParser {
    inner: DnsUdpParser,
}

impl Default for DnsExchangeParser {
    fn default() -> Self {
        Self::new()
    }
}

impl DnsExchangeParser {
    pub fn new() -> Self {
        Self {
            inner: DnsUdpParser::with_correlation(),
        }
    }

    pub fn with_config(config: DnsConfig) -> Self {
        Self {
            inner: DnsUdpParser::with_config(config),
        }
    }
}

impl DatagramParser for DnsExchangeParser {
    type Message = DnsExchange;

    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp, out: &mut Vec<DnsExchange>) {
        let mut inner_out = Vec::new();
        self.inner.parse(payload, side, ts, &mut inner_out);
        for msg in inner_out {
            match msg {
                DnsMessage::Query(_) => {
                    // Queries don't fire exchanges on their own —
                    // the matching response (or on_tick timeout)
                    // does. The inner Correlator records the query.
                }
                DnsMessage::Response(r) => {
                    let question = r.questions.first().cloned().unwrap_or(DnsQuestion {
                        name: String::new(),
                        qtype: 0,
                        qclass: 0,
                    });
                    let query_ts = r
                        .elapsed
                        .and_then(|e| {
                            r.timestamp
                                .to_duration()
                                .checked_sub(e)
                                .map(|d| Timestamp::new(d.as_secs() as u32, d.subsec_nanos()))
                        })
                        .unwrap_or(r.timestamp);
                    let outcome = match r.rcode {
                        DnsRcode::NoError => DnsOutcome::Completed,
                        other => DnsOutcome::Failed { rcode: other },
                    };
                    out.push(DnsExchange {
                        transaction_id: r.transaction_id,
                        question,
                        answers: r.answers,
                        elapsed: r.elapsed,
                        query_ts,
                        response_ts: Some(r.timestamp),
                        outcome,
                    });
                }
                DnsMessage::Unanswered(q) => {
                    let question = q.questions.first().cloned().unwrap_or(DnsQuestion {
                        name: String::new(),
                        qtype: 0,
                        qclass: 0,
                    });
                    out.push(DnsExchange {
                        transaction_id: q.transaction_id,
                        question,
                        answers: Vec::new(),
                        elapsed: None,
                        query_ts: q.timestamp,
                        response_ts: None,
                        outcome: DnsOutcome::NoResponse,
                    });
                }
            }
        }
    }

    fn on_tick(&mut self, now: Timestamp, out: &mut Vec<DnsExchange>) {
        let mut inner_out = Vec::new();
        self.inner.on_tick(now, &mut inner_out);
        for msg in inner_out {
            if let DnsMessage::Unanswered(q) = msg {
                let question = q.questions.first().cloned().unwrap_or(DnsQuestion {
                    name: String::new(),
                    qtype: 0,
                    qclass: 0,
                });
                out.push(DnsExchange {
                    transaction_id: q.transaction_id,
                    question,
                    answers: Vec::new(),
                    elapsed: None,
                    query_ts: q.timestamp,
                    response_ts: None,
                    outcome: DnsOutcome::NoResponse,
                });
            }
        }
    }

    fn parser_kind(&self) -> &'static str {
        "dns-exchange"
    }
}
