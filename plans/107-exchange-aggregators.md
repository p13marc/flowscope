# Plan 107 — `HttpExchangeParser` + `DnsExchangeParser`

## Summary

Ship aggregator parsers for HTTP and DNS that mirror the
shape `TlsHandshakeParser` proved out in 0.9: one rich event
per logical exchange (request + response), with derived
fields and an outcome discriminant.

- **`HttpExchangeParser`** — one `HttpExchange` per
  request/response pair. Carries the request, the response
  (or `None` on truncation), elapsed time, and an
  `HttpOutcome` discriminant (`Completed` /
  `NoResponse` / `Reset`).
- **`DnsExchangeParser`** — one `DnsExchange` per
  query/response pair on the same flow (TCP only, since UDP
  has the existing `Correlator` mechanism). Carries
  question, answers, RTT, and an `DnsOutcome`.

These collapse the "stitch a request to its response"
pattern that consumers currently hand-roll in HTTP observers
and DNS query/response correlators.

Theme 5 follow-up from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md);
explicitly called out as the pattern other L7 protocols
should adopt after `TlsHandshakeParser` (plan 97 in 0.9.0)
showed how clean the shape is.

## Status

**Ready to implement.** Targets 0.10.0.

## Prerequisites

- Plan 97 — `TlsHandshakeParser` aggregator shipped in
  0.9.0. The implementation template.

## Out of scope

- **Aggregating across multiple exchanges on one flow** (e.g.
  one event per HTTP keep-alive session, not per request).
  Each exchange is its own event; consumers aggregate
  further in their own state.
- **Body inspection** (mime parsing, parameter extraction).
  The exchange carries the raw body via `HttpRequest::body`
  / `HttpResponse::body`; users who want parsed bodies
  layer on top.
- **Streaming responses** (HTTP/1.1 chunked encoding
  partials). Today the underlying `HttpParser` waits for the
  full body before emitting; the exchange aggregator
  inherits that property.
- **HTTP/2 / HTTP/3.** The plan-93 deferred-items list keeps
  these out.

---

## Surface 1 — `HttpExchangeParser`

### API

```rust
// src/http/exchange.rs
pub struct HttpExchangeParser {
    config: HttpConfig,
}

impl HttpExchangeParser {
    pub fn new() -> Self;
    pub fn with_config(config: HttpConfig) -> Self;
}

impl SessionParser for HttpExchangeParser {
    type Message = HttpExchange;
    fn parser_kind(&self) -> &'static str { "http-exchange" }
    /* … */
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct HttpExchange {
    pub request: HttpRequest,
    pub response: Option<HttpResponse>,
    pub elapsed: Option<Duration>,
    pub request_ts: Timestamp,
    pub response_ts: Option<Timestamp>,
    pub outcome: HttpOutcome,
}

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum HttpOutcome {
    /// Request + matching response received.
    Completed,
    /// Request observed but flow ended before response arrived.
    NoResponse,
    /// Flow RST'd mid-exchange.
    Reset,
}
```

### Internal state machine

Per (flow, side) — initiator emits requests, responder
emits responses. State per direction:

```rust
enum DirState {
    Idle,
    AwaitingResponseForRequest { req: HttpRequest, ts: Timestamp },
}
```

Pipelined requests on HTTP/1.1: the parser buffers requests
in a FIFO until responses arrive (HTTP/1.1 mandates
in-order). The flow ends → drain the FIFO; each pending
request gets `outcome: NoResponse`.

### Convenience accessors

```rust
impl HttpExchange {
    /// Convenience: status / 100. Same as `response.as_ref()
    /// .and_then(|r| r.status_class())`.
    pub fn status_class(&self) -> Option<u8>;

    /// True iff completed with a 2xx response.
    pub fn is_success(&self) -> bool;

    /// True iff completed with a 4xx or 5xx response.
    pub fn is_error(&self) -> bool;
}
```

---

## Surface 2 — `DnsExchangeParser`

### API

```rust
// src/dns/exchange.rs
pub struct DnsExchangeParser {
    config: DnsConfig,
    /// TTL for unanswered queries before they fire NoResponse.
    /// Default: 5s (matching the existing DNS correlator).
    pub timeout: Duration,
}

impl DnsExchangeParser {
    pub fn new() -> Self;
    pub fn with_config(config: DnsConfig) -> Self;
    pub fn with_timeout(self, ttl: Duration) -> Self;
}

impl DatagramParser for DnsExchangeParser {
    type Message = DnsExchange;
    fn parser_kind(&self) -> &'static str { "dns-exchange" }
    /* … */
}

#[derive(Debug, Clone)]
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

#[derive(Debug, Clone, PartialEq)]
#[non_exhaustive]
pub enum DnsOutcome {
    /// Query + matching response received.
    Completed,
    /// Query observed but no response within timeout.
    NoResponse,
    /// Response with NXDOMAIN / SERVFAIL / FORMERR rcode.
    Failed { rcode: u8 },
}
```

`DnsExchangeParser` internally uses the existing
`flowscope::dns::Correlator` for the matching logic.

---

## Files

```
src/http/exchange.rs        # HttpExchangeParser + HttpExchange + HttpOutcome (NEW)
src/http/mod.rs             # re-export
src/dns/exchange.rs         # DnsExchangeParser + DnsExchange + DnsOutcome (NEW)
src/dns/mod.rs              # re-export
tests/http_exchange.rs      # fixture coverage
tests/dns_exchange.rs       # fixture coverage
examples/http_log.rs        # MIGRATED to HttpExchangeParser
docs/recipes.md             # add "Aggregating L7 exchanges" section
CHANGELOG.md                # 0.10 entry
```

## Implementation steps

1. **HTTP exchange:**
   - Internal `HttpExchangeParser` wraps an existing
     `HttpParser` and accumulates state per direction.
   - On `HttpMessage::Request`, push into the per-side FIFO.
   - On `HttpMessage::Response`, pop the oldest pending
     request and emit a `Completed` exchange.
   - On `fin_*`, drain FIFOs and emit `NoResponse`
     exchanges.

2. **DNS exchange:**
   - Internal `DnsExchangeParser` wraps a `DnsUdpParser` with
     correlation enabled.
   - On `DnsMessage::Response` matched to a query, emit
     `Completed` (or `Failed` if rcode ≠ 0).
   - On `DnsMessage::Unanswered`, emit `NoResponse`.

3. **Tests:**
   - HTTP: pipelined 3 requests + 3 responses → 3 exchanges
     in order.
   - HTTP: 2 requests, flow ends before responses → 2
     NoResponse.
   - HTTP: 1 request, RST → 1 Reset exchange.
   - DNS: query + response → 1 Completed with rcode 0.
   - DNS: query without response, on_tick past timeout → 1
     NoResponse.
   - DNS: response with NXDOMAIN → 1 Failed.

4. **Migrate `examples/http_log.rs`** — replace `HttpParser`
   with `HttpExchangeParser`; print request + response on one
   line.

5. **Add `docs/recipes.md`** "Aggregating L7 exchanges"
   section.

6. **CHANGELOG entry** under 0.10.0 "Added".

## Acceptance criteria

- Both parsers ship; both implement `SessionParser` /
  `DatagramParser`.
- HTTP example migrated.
- 6+ integration tests pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry.

## Risks

- **HTTP pipelining edge cases.** Pipelined requests can
  receive responses out-of-order under HTTP/2, but
  HTTP/1.1 mandates order. The exchange parser assumes
  HTTP/1.1 ordering; if a request can't be matched, log a
  warning and emit `NoResponse`. Mitigation: document the
  HTTP/1.1 assumption.

- **DNS UDP vs TCP correlation.** DNS-over-TCP (RFC 1035
  §4.2.2) has different framing; the exchange parser is
  UDP-only for now. Document and defer TCP variant.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `HttpExchangeParser` + types | ~280 | 5 |
| `DnsExchangeParser` + types | ~200 | 4 |
| Tests (6+ scenarios) | ~340 | 5 |
| Example migration | ~−40 net | 1 |
| Docs + CHANGELOG | ~80 | 1 |
| **Total** | **~860 LoC** | **~16 hours** |

## Provenance

Postmortem theme 5 follow-up:

> [TlsHandshakeParser] is the pattern other L7 protocols
> should adopt: `HttpExchangeParser` (request/response
> pair aggregator), `DnsExchangeParser` (query/response
> pair aggregator).
