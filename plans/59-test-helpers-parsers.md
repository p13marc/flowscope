# Plan 59 — `flowscope::test_helpers` parser stubs

## 1. Summary

Across the netring repo, **five files** carry hand-rolled noop /
echo parsers under different names (`StubParser`,
`StubSessionParser`, `EchoParser`, …). Every flowscope minor that
touches the parser-trait shape forces a sweep across all of them —
the 0.4 `ts: Timestamp` arg meant 12 line edits across 5 files in
netring alone.

flowscope already has a `test-helpers` feature gate (it exposes
`extract::parse::test_frames`). Add a small parser-stub module under
the same feature: `NoopSessionParser`, `NoopDatagramParser`,
`EchoSessionParser`. Downstream test code reduces to
`use flowscope::test_helpers::NoopSessionParser` and future trait
evolution is absorbed in flowscope once instead of every consumer.

## 2. Status

Not started.

## 3. Prerequisites

None. Trivially additive.

## 4. Out of scope

- A kitchen sink of parsers. Three carefully-chosen primitives
  cover the actual use patterns (no-op = "I don't care about
  messages, just exercise the wiring"; echo = "I want each chunk
  surfaced for inspection"). Test code that needs richer behaviour
  (counting bytes, asserting on specific protocol shapes) should
  keep its own focused parser.
- Releasing the stubs without the `test-helpers` feature gate.
  Keep them out of the default build to avoid pollution.
- An `EchoDatagramParser`. Datagram parsers are one-shot; the
  noop variant is enough surface to absorb trait evolution.

## 5. Files

| File | Change |
|------|--------|
| `src/test_helpers/mod.rs` (new module) | Define `NoopSessionParser`, `NoopDatagramParser`, `EchoSessionParser`. |
| `src/lib.rs` | `#[cfg(any(test, feature = "test-helpers"))] pub mod test_helpers;` alongside the existing `test-helpers` gating of `extract::parse::test_frames`. |
| `Cargo.toml` | No new feature — the existing `test-helpers` feature gains additional content. |
| Internally: existing in-tree test parsers (`session_driver.rs::LineParser`, `datagram_driver.rs::EchoUdp`, `tests/round_trip.rs::PassthroughParser`, `benches/session_driver.rs::NoopParser`) **stay put** — they have purpose-built shapes. The new helpers serve external consumers and any future "I just need a noop" use in our own tests. |
| `docs/SESSION_GUIDE.md` | One-line mention under "Testing pattern". |
| `CHANGELOG.md` | Additive entry. |

## 6. API

```rust
// src/test_helpers/mod.rs
//! Parser stubs intended for downstream test crates that need a
//! `SessionParser` / `DatagramParser` impl but don't care about
//! the produced messages.
//!
//! Gated behind the `test-helpers` Cargo feature (alongside
//! `extract::parse::test_frames`). Not for production use.

use crate::{DatagramParser, FlowSide, SessionParser, Timestamp};

/// A `SessionParser` that produces no messages. Use when test
/// code needs to exercise the driver / stream wiring without
/// caring about parsed output.
#[derive(Debug, Default, Clone)]
pub struct NoopSessionParser;

impl SessionParser for NoopSessionParser {
    type Message = ();
    fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
    fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
}

/// A `DatagramParser` that produces no messages. Mirror of
/// `NoopSessionParser`.
#[derive(Debug, Default, Clone)]
pub struct NoopDatagramParser;

impl DatagramParser for NoopDatagramParser {
    type Message = ();
    fn parse(&mut self, _payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
}

/// A `SessionParser` that echoes each fed chunk as a
/// side-tagged `Vec<u8>` message. Use when test code wants to
/// inspect the reassembled byte stream.
#[derive(Debug, Default, Clone)]
pub struct EchoSessionParser;

impl SessionParser for EchoSessionParser {
    type Message = (FlowSide, Vec<u8>);
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        vec![(FlowSide::Initiator, bytes.to_vec())]
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        vec![(FlowSide::Responder, bytes.to_vec())]
    }
}
```

Future trait-shape evolution (a new defaulted method, a renamed
argument) absorbs into these stubs once; downstream test crates
re-export and move on.

## 7. Implementation steps

1. **Create `src/test_helpers/mod.rs`** with the three structs +
   trait impls above.
2. **`src/lib.rs`**: add `#[cfg(any(test, feature =
   "test-helpers"))] pub mod test_helpers;`. Place near the existing
   `test-helpers` cfg blocks.
3. **No `Cargo.toml` change** — the `test-helpers` feature already
   exists; new content slips in.
4. **Sanity test**: a small in-tree test using
   `NoopSessionParser` via `FlowSessionDriver::new` to confirm the
   feature wiring + the `Default + Clone` shape (so the auto
   `SessionParserFactory` blanket impl works through it).
5. **`docs/SESSION_GUIDE.md`** — one bullet in the testing
   subsection: "for downstream tests that don't care about parser
   output, see `flowscope::test_helpers::Noop*` (under the
   `test-helpers` feature)."
6. **CHANGELOG** — additive entry.

## 8. Tests

- **Driver smoke test** (`#[cfg(all(test, feature = "test-helpers"))]`):
  build `FlowSessionDriver::new(FiveTuple::bidirectional(),
  NoopSessionParser::default())`, drive a 3WHS through, assert
  `Started` + `Closed` events emit, zero `Application` events.
- **Echo smoke test**: same with `EchoSessionParser`, feed a
  payload via TCP, assert `Application { message: (Initiator,
  payload), .. }` lands.
- **Default + Clone** are derived; no separate trait test needed.

## 9. Acceptance criteria

- `flowscope::test_helpers::{NoopSessionParser, NoopDatagramParser,
  EchoSessionParser}` exported when the `test-helpers` feature is
  on.
- `--no-default-features --features test-helpers` builds.
- `--no-default-features` (i.e. test-helpers off) does **not**
  expose the module.
- `cargo build/test/clippy/fmt/doc --all-features` clean.

## 10. Risks

- **Trait additions still touch flowscope.** If `SessionParser`
  grows a new (possibly defaulted) method, these stubs may need an
  override. That's the same maintenance flowscope's own test
  parsers carry — but now the cost lives once, not in every
  consumer.
- **API stability of helpers.** Pre-1.0 the stubs are themselves
  subject to change. Document as "stable shape per `0.x` minor;
  rare changes only when the underlying trait shape changes."

## 11. Effort

S — ~80 lines including tests. One sitting.

## 12. Provenance

[`docs/feedback-2026-05-22-netring.md`](../docs/feedback-2026-05-22-netring.md)
item **#8**. Author's data point: 12 line edits across 5 files in
netring during the 0.4 `ts` arg bump, *just for noop stubs*.
