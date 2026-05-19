# Plan 37 — Unify the DNS API; delete `DnsUdpObserver`

## 1. Summary

DNS-over-UDP ships **two** unrelated APIs: `DnsUdpParser` (a plain
`DatagramParser`) and `DnsUdpObserver` (a `FlowExtractor`-wrapping
callback tap). Query/response correlation — RTT matching and
unanswered-query detection — lives **only** in the observer, so any
user who wants correlation is forced onto the odd-one-out API and
has to hand-roll a `sweep_unanswered` timer (`examples/dns_log.rs`
does exactly this). This plan folds correlation into `DnsUdpParser`
using the `on_tick` hook from plan 36, adds a `DnsMessage::Unanswered`
variant, and **deletes `DnsUdpObserver`** and its now-orphaned
`DnsHandler` callback trait. DNS-over-UDP collapses to one API shape
— `DatagramParser` — consistent with every other protocol.

## 2. Status

Not started.

## 3. Prerequisites

- **Plan 36** — `DnsUdpParser` needs the timestamped `parse`
  (for query/response RTT) and the `on_tick` hook (for the
  unanswered sweep). Hard prerequisite.
- Plan 35 (`PcapFlowSource::datagrams`) is *nice to have* so
  `examples/dns_log.rs` can use the one-liner, but not required —
  the example can drive `FlowDatagramDriver` directly.

## 4. Out of scope

- **DNS-over-TCP correlation.** `DnsTcpParser` (a `SessionParser`)
  could also correlate now that plan 36 timestamps `feed_*` and adds
  `on_tick`. Deferred to a follow-up — TCP/53 correlation is rarer
  and `DnsTcpParser` would need its own correlator wiring. Noted in
  `INDEX.md` as an unblocked follow-up, not planned here.
- DNS resolution / validation / DNSSEC — flowscope is passive; no
  change.

## 5. Files

| File | Change |
|------|--------|
| `src/dns/datagram.rs` | `DnsUdpParser` becomes a struct holding an optional `Correlator`; new constructors; `parse` uses `parse_message_at` + records/matches; `on_tick` sweeps. `DnsMessage` gains `Unanswered` + `#[non_exhaustive]`. |
| `src/dns/correlator.rs` | `#[derive(Debug, Clone)]` on `Correlator` (needed so `DnsUdpParser: Clone`). |
| `src/dns/observer.rs` | **Delete.** |
| `src/dns/types.rs` | Remove the `DnsHandler` trait (orphaned once the observer is gone). Keep `DnsConfig`, `DnsQuery`, `DnsResponse`, `DnsRdata`. |
| `src/dns/mod.rs` | Drop `mod observer;`, the `DnsUdpObserver` re-export, and the `DnsHandler` re-export; update module rustdoc. |
| `examples/dns_log.rs` | Rewrite onto `FlowDatagramDriver` + `DnsUdpParser::with_correlation()`. |
| `CLAUDE.md` | Module-map lines for `dns/observer.rs` and `dns/types.rs` (`DnsHandler`). |
| `docs/SESSION_GUIDE.md` | Remove `DnsUdpObserver` from the decision flow / examples; point DNS at `DnsUdpParser`. |
| `README.md` | DNS feature-table cell mentions `DnsUdpParser` only. |
| `CHANGELOG.md` | Breaking-removal entry + migration recipe. |

## 6. API

```rust
// src/dns/datagram.rs
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum DnsMessage {
    Query(DnsQuery),
    Response(DnsResponse),          // .elapsed carries RTT when correlated
    /// A query that received no response within `query_timeout`.
    /// Emitted by `on_tick` when correlation is enabled.
    Unanswered(DnsQuery),
}

/// Per-flow DNS-over-UDP parser. Without correlation, each datagram
/// is parsed independently. With correlation, `Response` messages
/// carry RTT in `elapsed` and `on_tick` emits `Unanswered`.
#[derive(Debug, Default, Clone)]
#[non_exhaustive]
pub struct DnsUdpParser { /* correlator: Option<Correlator<()>>, config: DnsConfig */ }

impl DnsUdpParser {
    /// No correlation — stateless per-datagram parsing (the
    /// pre-0.4 behaviour; this is also `Default`).
    pub fn new() -> Self;
    /// Enable query/response correlation with default `DnsConfig`.
    pub fn with_correlation() -> Self;
    /// Enable correlation with explicit config (`query_timeout`,
    /// `max_pending`).
    pub fn with_config(config: DnsConfig) -> Self;
}

impl DatagramParser for DnsUdpParser {
    type Message = DnsMessage;
    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp) -> Vec<DnsMessage>;
    fn on_tick(&mut self, now: Timestamp) -> Vec<DnsMessage>;
}
```

`Correlator<()>` is the scope-free correlator — a `DnsUdpParser` is
already per-flow, so transaction IDs never collide across flows and
no explicit scope key is needed.

Migration (CHANGELOG): replace `DnsUdpObserver::new(extractor,
handler)` plugged into a `FlowTracker` with
`FlowDatagramDriver::new(extractor, DnsUdpParser::with_correlation())`
(or `PcapFlowSource::datagrams(...)`). The three `DnsHandler`
callbacks map to `DnsMessage` match arms:
`on_query` → `DnsMessage::Query`, `on_response` → `DnsMessage::
Response`, `on_unanswered` → `DnsMessage::Unanswered`. The manual
`sweep_unanswered` timer is gone — periodic `driver.sweep(now)` (or
`finish()`) drives `on_tick`.

## 7. Implementation steps

1. **`src/dns/correlator.rs`** — add `#[derive(Debug, Clone)]` to
   `Correlator`. Confirm `DnsConfig` and `DnsQuery` are already
   `Clone + Debug` (they are — the observer clones both today).
2. **`src/dns/datagram.rs`** — change `DnsUdpParser` from a unit
   struct to `{ correlator: Option<Correlator<()>>, config:
   DnsConfig }` with private fields, `#[derive(Debug, Default,
   Clone)]`, `#[non_exhaustive]`. `Default` = `correlator: None` =
   no correlation.
3. Add `new()` / `with_correlation()` / `with_config(DnsConfig)`.
4. Rewrite `parse` to take `ts` (plan 36 already changed the
   signature) and use `parse_message_at(payload, ts)` instead of
   `parse_message`. On `Query`: if correlating,
   `correlator.record_query((), q.clone())`. On `Response`: if
   correlating, `match_response(&(), tx_id, ts)` and set
   `r.elapsed`.
5. Implement `on_tick(now)`: when correlating, `correlator.sweep(now)`
   and map each expired `DnsQuery` to `DnsMessage::Unanswered`;
   otherwise empty.
6. **`DnsMessage`** — add `#[non_exhaustive]` and the `Unanswered`
   variant.
7. **Delete `src/dns/observer.rs`** (the file, the `DnsUdpObserver`
   type, and the `peek_udp` helper).
8. **`src/dns/types.rs`** — delete the `DnsHandler` trait. Grep for
   any other `DnsHandler` reference first; the observer is its only
   user.
9. **`src/dns/mod.rs`** — drop `mod observer;`, `pub use
   observer::DnsUdpObserver;`, and the `DnsHandler` item from the
   `pub use types::*;` surface (or from an explicit re-export list).
   Update the module rustdoc — the "two integration shapes" section
   becomes one.
10. **`examples/dns_log.rs`** — rewrite: build
    `FlowDatagramDriver::new(FiveTuple::bidirectional(),
    DnsUdpParser::with_correlation())`; loop over
    `PcapFlowSource::open(path)?.views()` calling `driver.track(...)`;
    `match` the `SessionEvent::Application { message, .. }` on the
    three `DnsMessage` arms; end with `driver.finish()`. (If plan 35
    landed, collapse the loop to `PcapFlowSource::datagrams(...)`.)
11. **`CLAUDE.md`** — update the `src/dns/` module map: drop the
    `observer.rs` line, drop `DnsHandler` from the `types.rs` line,
    note `DnsUdpParser` now correlates.
12. **Docs** — `SESSION_GUIDE.md` and `README.md` per §5.
13. **`CHANGELOG.md`** — breaking-removal entry with the §6
    migration recipe.

## 8. Tests

- **`src/dns/datagram.rs`** unit tests:
  - `with_correlation`: feed a query then its response, assert the
    `Response` message's `elapsed` is `Some(_)`.
  - `on_tick` after `query_timeout` elapses emits
    `DnsMessage::Unanswered` for an unmatched query; a matched query
    produces none.
  - `new()` / `default()`: no correlation — `Response.elapsed` is
    `None`, `on_tick` empty (regression guard for the old
    behaviour).
- **Integration** — extend `tests/dns_parser.rs` (or a new
  `tests/dns_correlation.rs`): drive a DNS fixture pcap through
  `FlowDatagramDriver` + `DnsUdpParser::with_correlation()`, assert
  query / response / unanswered counts.
- **Doctest** — the `dns/mod.rs` quick-start sample compiles.
- Confirm `cargo build --features dns` (without other features)
  still compiles after the observer removal.

## 9. Acceptance criteria

- `DnsUdpObserver`, `DnsHandler`, and `peek_udp` no longer exist;
  `grep -r DnsUdpObserver src/ examples/ docs/` is empty.
- DNS-over-UDP has exactly one API shape: `DnsUdpParser`.
- `examples/dns_log.rs` uses `DnsUdpParser::with_correlation()` and
  has no hand-rolled `sweep_unanswered` timer.
- `cargo test --all-features` clean; correlation tests green.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` zero warnings.
- `cargo machete` reports no newly-unused dependency (the observer's
  `peek_udp` had no extra deps, but confirm).

## 10. Risks

- **`Correlator` is public API.** It stays exported (advanced users
  may want a custom-scoped correlator). Adding `#[derive(Clone,
  Debug)]` is additive. No break there.
- **`DnsMessage` gaining `#[non_exhaustive]`** is technically
  breaking for external exhaustive `match` blocks — but it *should*
  have carried it from the start (CLAUDE.md: `#[non_exhaustive]` on
  every public enum). Call it out in the CHANGELOG; the fix for
  consumers is a trailing `_ => {}` arm.
- **netring.** If netring re-exports `DnsUdpObserver` under
  `netring::flow::*`, that re-export must go. Audit netring; netring
  also gains the correlating `DnsUdpParser` for free through its
  `datagram_stream`.
- **`DnsConfig` field assumptions.** `Correlator` reads
  `config.max_pending` and `config.query_timeout`. Confirm both
  still exist and are public after any `types.rs` edits — only the
  `DnsHandler` trait is removed, not `DnsConfig`.

## 11. Effort

M — the correlation logic already exists in `Correlator` and is
merely *relocated* from the observer into the parser; the bulk is
deletion (`observer.rs`, `DnsHandler`) and the `dns_log.rs` rewrite.
Estimate half a day.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F5** (🟠) — "DNS is a
third API shape; correlation lives only in the observer." Plan 36
shipped the trait capability; this plan consumes it and removes the
redundant shape.
