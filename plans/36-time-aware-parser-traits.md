# Plan 36 — Time-aware `SessionParser` / `DatagramParser`

## 1. Summary

`SessionParser` and `DatagramParser` are **time-blind**:
`feed_initiator` / `feed_responder` / `parse` never learn the
observed time, and there is no periodic hook. A parser therefore
cannot timestamp its messages, emit timeout-driven output, or do
query/response RTT correlation — which is why DNS correlation had to
be bolted on as a separate `DnsUdpObserver` extractor-tap (review
finding F5). This plan makes both traits time-aware:

- `feed_initiator` / `feed_responder` / `parse` gain a
  `ts: Timestamp` parameter (breaking signature change).
- Both traits gain a defaulted `on_tick(&mut self, now: Timestamp)
  -> Vec<Message>` — the driver calls it on every `sweep` / `finish`.

The change is **behaviourally inert** for every existing parser:
they ignore the new parameter and inherit the default `on_tick`. It
*unblocks* the DNS unification in plan 37 and any future
time-dependent parser (timing analysis, idle detection).

## 2. Status

Not started.

## 3. Prerequisites

Recommended (not strictly required) after:
- **Plan 32** — so the `on_tick` driver wiring is written once
  against the `S`-free driver signatures.
- **Plan 33** — `finish()` calls `sweep(Timestamp::MAX)`, which
  drives a final `on_tick`; without 33, `on_tick` still fires on
  every explicit `sweep(now)`.

## 4. Out of scope

- `fin_initiator` / `fin_responder` / `rst_initiator` /
  `rst_responder` stay un-timestamped. The driver already stamps the
  resulting `Closed` / `Application` events with `stats.last_seen`;
  a parser flushing on close does not need its own clock.
- Actually *using* the new capability for DNS — that is plan 37.
- `is_poisoned` / `poison_reason` — unchanged.

## 5. Files

| File | Change |
|------|--------|
| `src/session.rs` | `SessionParser` / `DatagramParser` trait method signatures; new `on_tick`; module doctest. |
| `src/session_driver.rs` | `drain_into_parser` passes `ts` to `feed_*`; `sweep` calls `on_tick` on live parsers. |
| `src/datagram_driver.rs` | `translate_events` passes `ts` to `parse`; `sweep` calls `on_tick`. |
| `src/http/parser.rs`, `src/http/session.rs` | `HttpParser::feed_*` take `_ts`. |
| `src/tls/parser.rs`, `src/tls/session.rs` | `TlsParser::feed_*` take `_ts`. |
| `src/dns/datagram.rs` | `DnsUdpParser::parse` takes `ts` (used in plan 37; here just `_ts`). |
| `src/dns/session.rs` | `DnsTcpParser::feed_*` take `_ts`. |
| `examples/length_prefixed_pcap.rs` | `feed_*` take `_ts`. |
| `tests/parser_proptest.rs`, `tests/{http,tls,dns}_parser.rs` | Add `ts` argument to every `feed_*` / `parse` call. |
| `docs/SESSION_GUIDE.md` | Trait-shape reference block, every `SessionParser` / `DatagramParser` code sample, migration snippets. |
| `src/lib.rs` | Top-level doc — verify no inline trait sample. |
| `CHANGELOG.md` | Breaking-change entry + migration recipe. |

## 6. API

```rust
// src/session.rs — SessionParser
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    // before: fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;

    /// Periodic time hook. The driver calls this on every `sweep` /
    /// `finish` with the sweep's `now`, for every still-live parser.
    /// Lets stateful parsers emit time-driven messages (timeouts,
    /// unanswered requests). Default: no-op.
    ///
    /// Emitted messages are attributed to `FlowSide::Initiator` in
    /// the resulting `SessionEvent::Application` (the message has no
    /// inherent call direction).
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> {
        Vec::new()
    }

    // fin_*, rst_*, is_poisoned, poison_reason — unchanged.
}

// src/session.rs — DatagramParser
pub trait DatagramParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    // before: fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message>;
    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp) -> Vec<Self::Message>;

    /// See [`SessionParser::on_tick`].
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> {
        Vec::new()
    }

    // is_poisoned, poison_reason — unchanged.
}
```

Migration recipe (CHANGELOG): add `_ts: Timestamp` (or `ts` if you
use it) to every `feed_initiator` / `feed_responder` / `parse`
implementation. `on_tick` is optional — omit it unless your parser
is stateful and time-driven.

## 7. Implementation steps

1. **`src/session.rs`** — edit the four trait method signatures
   (`SessionParser::feed_initiator` / `feed_responder`,
   `DatagramParser::parse`, all gain `ts: Timestamp`). Add `on_tick`
   with its default to both traits. `Timestamp` is already imported
   (`use crate::timestamp::Timestamp;`).
2. Update the `src/session.rs` module-level doctest (`LineParser`)
   and the `#[cfg(test)]` `CountParser` / `EchoDgram` to the new
   signatures.
3. **`src/session_driver.rs`** — `drain_into_parser` already
   receives a `ts`; pass it into `parser.feed_initiator(bytes, ts)`
   / `feed_responder(bytes, ts)`.
4. **`src/session_driver.rs`** — in `sweep`, after `translate_events`
   + `finalize` (so ended-flow parsers are already removed),
   iterate the surviving `self.parsers`; call `on_tick(now)` on each
   and push `SessionEvent::Application { key, side: Initiator,
   message, ts: now }` for every returned message. Append after the
   translated events.
5. **`src/datagram_driver.rs`** — thread the view timestamp into
   `translate_events` and on into `parser.parse(payload, side, ts)`.
   Add the same `on_tick`-on-`sweep` block as step 4.
6. **Parser impls** — `HttpParser`, `TlsParser`, `DnsTcpParser`,
   `DnsUdpParser`: add `_ts: Timestamp` to their `feed_*` / `parse`
   signatures. No body changes (plan 37 will *use* `ts` in
   `DnsUdpParser`).
7. **Examples** — `length_prefixed_pcap.rs` `feed_*` gain `_ts`.
8. **Tests** — `parser_proptest.rs` and the per-parser fixture
   tests call `feed_*` / `parse` directly; add a timestamp argument
   (a fixed `Timestamp::new(0, 0)` is fine — these tests are not
   time-sensitive).
9. **Docs** — `SESSION_GUIDE.md`: the "Concrete trait shape" block,
   every worked `impl SessionParser` / `impl DatagramParser`, and
   the migration snippets. Document the `on_tick` cadence ("fires on
   `sweep` / `finish`, not per-packet") and the Initiator-side
   convention.
10. **`CHANGELOG.md`** — breaking entry with the §6 recipe.

## 8. Tests

- **Behavioural-inertness guard.** The existing 11 parser proptests
  in `tests/parser_proptest.rs` plus the fixture tests must pass
  unchanged (modulo the mechanical `ts` argument) — they prove that
  adding the parameter and the defaulted `on_tick` changes nothing
  for parsers that ignore them.
- **`on_tick` wiring test** (`session_driver.rs`): a test parser
  whose `on_tick` returns a sentinel message; drive one flow, call
  `sweep(now)`, assert a `SessionEvent::Application { side:
  Initiator, message: sentinel, .. }` appears; assert `on_tick` is
  **not** called for an already-ended flow.
- Same `on_tick` test for `FlowDatagramDriver`.
- **`finish()` drives `on_tick`** (if plan 33 landed): assert the
  final `finish()` call produces the `on_tick` sentinel.

## 9. Acceptance criteria

- Both traits carry `ts` on the data methods and a defaulted
  `on_tick`.
- `cargo test --all-features` clean — every existing parser test
  passes with only the mechanical `ts` argument added.
- `cargo build --all-features --all-targets` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` zero warnings (every doc
  sample updated).
- A wiring test confirms `on_tick` fires on `sweep` for live flows
  and not for ended ones.

## 10. Risks

- **netring.** netring's `session_stream` / `datagram_stream`
  adapters call `feed_*` / `parse` and must pass the packet
  timestamp; they also gain access to `on_tick` (should call it on
  their sweep path for parity with the sync drivers). Update netring
  in lockstep — this is the largest cross-repo touch of the whole
  series. Audit `netring` before merging.
- **`on_tick` side attribution.** Returning `Vec<Message>` and
  attributing to `FlowSide::Initiator` is the simple choice.
  Considered alternative: `on_tick -> Vec<(FlowSide, Message)>` so
  the parser picks the side. Rejected for now — inconsistent with
  `feed_*`'s `Vec<Message>`, and every concrete use (DNS
  `Unanswered` = a query the initiator sent) wants `Initiator`
  anyway. Revisit only if a real parser needs responder-side tick
  output.
- **Wide mechanical sweep.** ~6 parser impls + ~4 example/doc files
  + the proptest harness. Low individual risk, but easy to miss a
  doctest — `cargo doc` and `cargo test --doc` are the backstop.

## 11. Effort

L — touches many files, but every change is mechanical (add a
parameter, thread a value). The only genuinely new code is the
`on_tick`-on-`sweep` block in two drivers (~15 lines each) and the
tests. Estimate one day including the netring audit.

## 12. Provenance

`plans/API-ERGONOMICS-REVIEW.md` finding **F5** (🟠) — root cause
"the typed parser traits are time-blind." This plan ships the trait
capability; plan 37 consumes it to unify DNS.
