# Plan 80 — `SessionParser::is_done()` / `DatagramParser::is_done()`

## Summary

`SessionParser::is_poisoned()` ships the "I'm broken" signal —
the driver synthesises `EndReason::ParseError` and tears the flow
down. The symmetric "I'm done, please close cleanly" signal does
not exist. Three motivating cases the netring author flagged in
round-2 feedback:

1. **HTTP/1.0** observes `Connection: close` + body fully
   received. The parser knows the response is complete but FIN
   may be seconds away (or never, if the peer aborts).
2. **DNS-over-TCP** query/response pair completed — the
   single-pair message lifecycle is done; waiting for FIN is
   wasteful.
3. **Custom framed binary protocols** that ship a "session-end"
   sentinel frame. Same pattern.

The round-1 decline (`HTTP/1.0 Connection: close already triggers
FIN`) was correct for HTTP/1.0 but doesn't generalise. The round-2
ask is to ship the symmetric API anyway, as a low-cost ergonomic
fix.

This plan adds `is_done()` to both `SessionParser` and
`DatagramParser`, plus a new `EndReason::ParserDone` variant.
The driver checks `is_done()` after each `feed_*` / `parse` call
and synthesises a terminal event if it returns `true`.

## Status

Not started.

## Prerequisites

- Plan 36 (`SessionParser::on_tick`) — shipped in 0.4.0. The
  trait shape is stable; `is_done()` is a small additive method.
- Plan 31 (`SessionParser` trait launched) — shipped in 0.2.0.
- Plan 37 (`DatagramParser::on_tick`) — shipped in 0.4.0. Mirror
  on the datagram side.

## Out of scope

- Plumbing `is_done()` through the parser's `Message` type. The
  parser's last batch of messages flushes via the normal path
  before the driver checks `is_done()`. No "final message" hook.
- Re-arming. Once a parser is done, the driver tears down the
  flow; subsequent packets on the same 5-tuple start a fresh
  flow with a fresh parser.
- Cooperative shutdown: the parser can't *request* the driver to
  hold the flow open. `is_done()` returning `true` is a unilateral
  signal; the driver responds immediately on the next check.
- Mid-tick (between `feed_*` and `fin_*`) checks. The driver
  checks `is_done()` at the same cadence it checks `is_poisoned()`
  — see Implementation steps step 3.

## Files

- `src/session.rs` — add `fn is_done(&self) -> bool { false }`
  to `SessionParser`; mirror on `DatagramParser`.
- `src/event.rs` — add `EndReason::ParserDone` variant
  (`#[non_exhaustive]` already, so this is additive).
- `src/obs.rs` — add `"parser_done"` arm to `reason_label`.
- `src/session_driver.rs` — driver checks `is_done()` after
  every `feed_initiator` / `feed_responder` / `on_tick` call,
  synthesises `SessionEvent::Closed { reason: ParserDone, .. }`.
- `src/datagram_driver.rs` — mirror.
- `src/driver.rs` — `EndReason::ParserDone` handled the same way
  as `ParseError` (synthesises an `Ended` event; removes the
  reassembler state). Reuses the existing parser-poison
  machinery.
- `docs/SESSION_GUIDE.md` — new subsection "Parser-driven graceful
  close" with the lifecycle pattern.
- `CHANGELOG.md` — `### Added` entry.
- Test parsers: `src/test_helpers.rs` — add a `OneShotParser`
  that returns `is_done() = true` after the first message, for
  driver-level integration tests.

## API

```rust
// src/session.rs

pub trait SessionParser: Send + 'static {
    // ... existing methods ...

    /// Symmetric "I'm done — close this flow cleanly" signal.
    /// Default: `false` (parser never self-terminates).
    ///
    /// Returning `true` tells the driver this parser has no
    /// more useful work to extract — the flow can close ahead
    /// of FIN/idle-timeout. The driver responds by synthesising
    /// [`crate::SessionEvent::Closed`] with [`crate::EndReason::ParserDone`]
    /// on the next check, after flushing any pending messages.
    ///
    /// Reserve for protocols with intrinsic completion semantics
    /// (HTTP/1.0 `Connection: close` after body, DNS-over-TCP
    /// query/response pair, framed protocols with session-end
    /// sentinel). Do not use to signal "I want to give up
    /// gracefully on bad input" — that's [`is_poisoned`](Self::is_poisoned).
    ///
    /// Implementations should be idempotent: once `is_done()`
    /// returns `true`, it should keep returning `true` for the
    /// lifetime of the parser.
    fn is_done(&self) -> bool {
        false
    }
}

pub trait DatagramParser: Send + 'static {
    // ... existing methods ...

    /// Symmetric to [`SessionParser::is_done`]. Default `false`.
    fn is_done(&self) -> bool {
        false
    }
}
```

```rust
// src/event.rs

#[non_exhaustive]
pub enum EndReason {
    Fin,
    Rst,
    IdleTimeout,
    Evicted,
    BufferOverflow,
    ParseError,
    /// New in 0.7.0. A [`crate::SessionParser`] or
    /// [`crate::DatagramParser`] returned `true` from
    /// [`crate::SessionParser::is_done`] /
    /// [`crate::DatagramParser::is_done`]. Synthesised by the
    /// session- / datagram-driver; the tracker itself never
    /// emits this reason.
    ParserDone,
}
```

## Implementation steps

1. **Add `is_done()` defaulted on both traits** in `src/session.rs`.
   Document the contract: idempotent, post-message flush, not for
   poison-style giveup.
2. **Add `EndReason::ParserDone`** in `src/event.rs`. The
   `#[non_exhaustive]` attribute makes this additive.
3. **Driver check sequencing** — the canonical loop in
   `FlowSessionDriver::poll_session_events`:
   ```text
   for each event from tracker.track(view):
       if event is FlowEvent::Started { key, .. }:
           parsers.insert(key, factory(key))
           emit SessionEvent::Started
       elif event is FlowEvent::Packet { key, side, .. }:
           if let Some(payload) = reassembler.take() {
               messages = parser.feed_<side>(payload, ts)
               for msg in messages: emit SessionEvent::Application
               if parser.is_poisoned():
                   synthesise SessionEvent::Closed { ParseError }
                   remove flow
               elif parser.is_done():     // NEW
                   synthesise SessionEvent::Closed { ParserDone }
                   remove flow
           }
       elif event is FlowEvent::Ended { … }:
           emit SessionEvent::Closed (with the tracker's reason)
   ```
   Order matters: `is_poisoned()` is checked before `is_done()`
   so a parser that's *both* poisoned and done surfaces as
   `ParseError` (worse condition wins).
4. **Driver check on `on_tick`**: when `sweep_with_parsers` calls
   `parser.on_tick(now)`, after consuming the returned messages
   the driver also checks `is_done()`. A tick-driven completion
   (e.g., DNS-over-TCP correlator's query-timeout-completes-pair)
   then synthesises a `Closed { ParserDone }` immediately.
5. **Mirror on datagram driver.** Same logic; no reassembler
   take-and-feed step (datagrams are one-shot).
6. **Idempotence of removal.** Once the driver removes the flow
   from `parsers`, subsequent packets on the same 5-tuple within
   the tracker's idle window go through the *new* flow's parser
   (the tracker's flow lifecycle is unchanged — the driver only
   removes its own parser-map entry; the tracker still sees the
   flow until its own idle/FIN). When the tracker eventually
   emits its own `Ended`, the driver checks for an existing
   parser-map entry and skips a duplicate `Closed` emission.
7. **`OneShotParser` test helper** in `src/test_helpers.rs`:
   ```rust
   #[derive(Default)]
   pub struct OneShotParser { done: bool }
   impl SessionParser for OneShotParser {
       type Message = ();
       fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
           self.done = true;
           vec![()]
       }
       fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
           Vec::new()
       }
       fn is_done(&self) -> bool { self.done }
       fn parser_kind(&self) -> &'static str { "one-shot" }
   }
   ```
   Mirror `OneShotDatagramParser`.
8. **CHANGELOG entry under `### Added`**:
   ```
   - **`SessionParser::is_done()` / `DatagramParser::is_done()`**
     + **`EndReason::ParserDone`** (plan 80). Reverses the 0.6
     decline of round-1 #10. Lets a parser signal completion
     ahead of FIN/idle (HTTP/1.0 after body, DNS-over-TCP after
     query/response pair, custom framed protocols).
     Default `false`; driver checks after every `feed_*` /
     `parse` / `on_tick`.
   ```

## Tests

- `src/session_driver.rs::tests`:
  - `is_done_triggers_parser_done_close` — `OneShotParser`,
    feed one chunk, assert a `Closed { reason: ParserDone, … }`
    fires next.
  - `is_done_after_on_tick_triggers_close` — parser becomes done
    in its `on_tick` return; assert next sweep emits
    `Closed { ParserDone }`.
  - `is_poisoned_wins_over_is_done` — parser is both; assert
    `Closed { ParseError }` not `ParserDone`.
  - `parser_done_flow_does_not_double_close_on_natural_fin` —
    flow closes via `ParserDone`; later FIN doesn't emit a
    second `Closed`.
- `src/datagram_driver.rs::tests` — mirror with
  `OneShotDatagramParser`.
- `tests/parser_proptest.rs` — extend an existing proptest to
  fuzz a parser whose `is_done()` flips randomly; assert exactly
  one `Closed` event per flow.

## Acceptance criteria

- `SessionParser::is_done()` defaulted to `false`; existing
  parsers compile unchanged.
- Driver synthesises `EndReason::ParserDone` after the parser
  flips, ahead of any natural FIN/idle.
- `is_poisoned()` precedence is preserved (poison wins).
- No double-`Closed` for a flow that goes `ParserDone` then
  naturally FINs.
- `cargo test --all-features` clean (target: ~310+ tests).
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- Feature-matrix CI green.
- `docs/SESSION_GUIDE.md` documents the lifecycle (when to use
  `is_done` vs `is_poisoned` vs natural FIN).
- `OBSERVABILITY.md` notes the new `reason="parser_done"` metric
  label.

## Risks

- **Premature flow tear-down.** A parser that returns `true`
  before the protocol is actually complete drops a live flow.
  Documented as a contract violation; not flowscope's job to
  detect.
- **Subtle double-emission on FIN race.** A parser returns
  `is_done() = true` on a `feed_initiator`; the same tick later
  observes a FIN. Driver must emit exactly one `Closed`. Test
  `parser_done_flow_does_not_double_close_on_natural_fin`
  catches this.
- **`on_tick`-driven completion semantics.** The on_tick path
  synthesises `Closed` from inside a sweep, which mutates the
  parser map mid-iteration. Implementation must defer the
  removal until after the sweep's iterator yields. Same shape
  as the existing `sweep_with_parsers` post-sweep parser drain.

## Effort

~70 LoC source (trait methods + EndReason variant + driver
check + helper parsers) + ~120 LoC tests + ~20 lines
SESSION_GUIDE. ~4 hours.

## Provenance

Round-2 feedback item F5 (= round-1 #10) in
[`docs/feedback-2026-05-29-netring-round2.md`](../docs/feedback-2026-05-29-netring-round2.md).
Reverses the 0.6 decline; round-2's expanded use case (DNS-over-TCP,
framed protocols) supplies the missing motivation.

The variant name (`ParserDone` over the author's `ParserClosed`)
and the precedence rule (poison wins) are documented in
`docs/0.7-PLAN-OF-RECORD.md` §5.
