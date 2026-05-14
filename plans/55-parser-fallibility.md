# Plan 55 — Fallible `SessionParser` / `DatagramParser`

## Summary

Today's `SessionParser::feed_initiator` returns `Vec<Self::Message>`
unconditionally. There's no way for a parser to signal "I hit an
unrecoverable error; tear this flow down." The current workaround
is the parser silently consuming bytes without producing messages
— functionally a leak (no observability, no teardown).

This plan adds a poison-style fallibility hook to `SessionParser`
and `DatagramParser`, mirroring the `Reassembler::is_poisoned`
mechanism (Plan 42 §1) that already exists. A parser sets internal
poison state when it hits an unrecoverable error; the driver
checks after each `feed_*` / `parse` call and synthesises an
`Ended { reason: ParseError }` plus an optional live
`Anomaly { kind: SessionParseError, .. }` for the flow.

The trait change is minimal — one new default-`false` method per
trait — and pre-1.0 BC-acceptable. This is exactly the kind of
"design it right once" decision that the BC-allowed policy is
for.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 42 §1 — `Reassembler::is_poisoned()` precedent. Shipped in
  0.2.0.
- Plan 51 — `FlowSessionDriver` wraps `FlowDriver` internally,
  consolidating the synthesis-of-Ended-events path. Land 51
  first; this plan extends that synthesis to cover parser
  poison.

## Out of scope

- A `type Error` associated type on the parser traits. We
  deliberately don't go full `Result<Vec<M>, E>` — see "Why
  poison flag, not Result" below.
- Structured error payload on `EndReason::ParseError`. The poison
  state is binary; if real demand surfaces for richer info,
  consumers can put it in their `Message` type.
- Per-message recovery semantics. Parsers that want to skip a
  bad message and keep going just don't push it into their
  `Vec`. Only flow-level teardown goes through the new path.

---

## Why poison flag, not `Result`?

Two alternatives considered:

| Shape | Pros | Cons |
|-------|------|------|
| `is_poisoned(&self) -> bool` + optional `poison_reason(&self) -> Option<&str>` | Mirrors `Reassembler::is_poisoned` precedent. Default-false impl means zero churn for existing parsers that don't error. Recovery (per-message skip) stays internal to the parser. | Less Rust-y than `Result`. Error info is unstructured. |
| `feed_initiator(...) -> Result<Vec<M>, E>` with `type Error` assoc | Idiomatic Rust. Carries structured error. | Forces every impl to declare an `Error` type even when infallible. Conflates per-message and flow-level errors. Bigger BC break. |

**Picked the poison flag.** Reasons:
- Symmetry with `Reassembler::is_poisoned` — same wiring on the
  driver side, same mental model for users.
- Default-false impl is purely additive at the trait level (the
  shipped HTTP/TLS/DNS parsers don't break).
- Per-message recovery already works (don't push the bad message
  into the Vec); only flow-level teardown needed the new hook.
- The driver already has the BufferOverflow synthesis path from
  Plan 42 — extending it to handle parser poison is a few extra
  lines, not new infrastructure.

If a future consumer really needs structured error info, the
follow-up is `Result<Vec<M>, E>` as an additive third method
`feed_initiator_result` or similar. Not 0.3.0's problem.

---

## Files

### MODIFIED

- `src/session.rs` — add `SessionParser::is_poisoned(&self) -> bool`
  + `poison_reason(&self) -> Option<&str>` (default false / None).
  Same on `DatagramParser`.
- `src/event.rs` — add `EndReason::ParseError` and
  `AnomalyKind::SessionParseError { side, reason: Option<String> }`.
- `src/session_driver.rs` — check `is_poisoned()` after every
  `feed_*` call; synthesise `Ended { reason: ParseError }` and
  forward an `Anomaly` when `emit_anomalies` is on.
- `src/driver.rs` — when consumed via `FlowSessionDriver`,
  delegates through. No direct `SessionParser` knowledge on
  `FlowDriver` itself.
- `src/obs.rs` — `record_flow_ended` already handles all
  `EndReason` arms via match; the new variant adds a `reason ==
  "parse_error"` metric label arm.
- `CHANGELOG.md` — 0.3.0 entry; migration note for `EndReason`
  exhaustive matches.
- `docs/SESSION_GUIDE.md` — extend Plan 53's "Writing a
  SessionParser" section with a "Signalling unrecoverable
  errors" subsection.

### NEW

None.

---

## API

### `src/session.rs`

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + 'static;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message>;
    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}

    /// True after the parser has hit an unrecoverable error and
    /// can no longer make progress. The driver checks this after
    /// every `feed_*` / `fin_*` call and tears the flow down on
    /// `true`. Default: `false` (parser never poisons).
    ///
    /// Parsers that want to drop a malformed message and keep
    /// going should NOT use this — just don't push the message
    /// into the returned `Vec`. Reserve poison for cases where
    /// internal state is corrupted past recovery (desynced framing,
    /// invalid magic bytes that won't appear later, etc.).
    fn is_poisoned(&self) -> bool { false }

    /// Optional human-readable description of why the parser
    /// poisoned. Consulted only when `is_poisoned()` returns
    /// `true`. Default: `None`.
    fn poison_reason(&self) -> Option<&str> { None }
}
```

Same shape on `DatagramParser`:

```rust
pub trait DatagramParser: Send + 'static {
    type Message: Send + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message>;
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }
}
```

### `src/event.rs`

```rust
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndReason {
    Fin,
    Rst,
    IdleTimeout,
    Evicted,
    BufferOverflow,
    /// New in 0.3.0. A [`crate::SessionParser`] or
    /// [`crate::DatagramParser`] returned `true` from
    /// `is_poisoned()`. The driver tore the flow down to prevent
    /// silent state corruption.
    ParseError,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum AnomalyKind {
    BufferOverflow { /* ... */ },
    OutOfOrderSegment { /* ... */ },
    FlowTableEvictionPressure { /* ... */ },
    /// New in 0.3.0. Live signal that a parser poisoned mid-flow.
    /// The corresponding `Ended { reason: ParseError }` follows
    /// in the same tick.
    SessionParseError {
        side: FlowSide,
        /// Optional human-readable reason from
        /// [`crate::SessionParser::poison_reason`]. Capped at the
        /// first 256 bytes to bound the anomaly event size.
        reason: Option<String>,
    },
}
```

### `src/session_driver.rs` — synthesis

After each per-(flow, side) `feed_*` call in `translate_events`:

```rust
let messages = parser.feed_initiator(&drained);
for m in messages { /* emit Application ... */ }
if parser.is_poisoned() {
    let reason = parser.poison_reason().map(|s| {
        let mut owned = String::from(s);
        owned.truncate(256);
        owned
    });
    self.synthesise_parser_poison(key.clone(), FlowSide::Initiator, reason, ts, &mut out);
}
```

`synthesise_parser_poison` is the parser-side analog of the
existing BufferOverflow synthesis path:

```rust
fn synthesise_parser_poison(
    &mut self,
    key: E::Key,
    side: FlowSide,
    reason: Option<String>,
    ts: Timestamp,
    out: &mut Vec<SessionEvent<E::Key, P::Message>>,
) {
    if self.emit_anomalies {
        out.push(SessionEvent::Anomaly {
            key: Some(key.clone()),
            kind: AnomalyKind::SessionParseError {
                side,
                reason: reason.clone(),
            },
            ts,
        });
    }
    if let Some(stats) = self.driver.tracker().snapshot_stats(&key) {
        // EndReason::ParseError gets synthesised on the next
        // FlowDriver track() tick. Mark the parser slot dead so
        // we don't double-emit.
        out.push(SessionEvent::Closed {
            key: key.clone(),
            reason: EndReason::ParseError,
            stats,
        });
    }
    self.parsers.remove(&key);
    self.driver.tracker_mut().forget(&key);
}
```

### `src/driver.rs`

`FlowDriver` doesn't have a `SessionParser` slot, so the
poison-driven synthesis lives in `FlowSessionDriver`. The
`FlowDriver::finalize_ended_flows` loop already handles
`EndReason::ParseError` correctly via its existing match (treats
all non-FIN/non-IdleTimeout as `rst()` for reassembler cleanup).

### `src/obs.rs`

`record_flow_ended` already routes through the `EndReason` enum
to a label string. Add the new arm:

```rust
fn reason_label(reason: EndReason) -> &'static str {
    match reason {
        EndReason::Fin => "fin",
        EndReason::Rst => "rst",
        EndReason::IdleTimeout => "idle",
        EndReason::Evicted => "evicted",
        EndReason::BufferOverflow => "buffer_overflow",
        EndReason::ParseError => "parse_error",  // new
    }
}
```

And the anomaly label:

```rust
fn anomaly_label(kind: &AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::BufferOverflow { .. } => "buffer_overflow",
        AnomalyKind::OutOfOrderSegment { .. } => "ooo_segment",
        AnomalyKind::FlowTableEvictionPressure { .. } => "flow_table_eviction",
        AnomalyKind::SessionParseError { .. } => "parse_error",  // new
    }
}
```

---

## Implementation steps

1. **Add `is_poisoned` / `poison_reason`** trait methods to
   `SessionParser` and `DatagramParser`. Default-false / None.
2. **Add `EndReason::ParseError`** variant.
3. **Add `AnomalyKind::SessionParseError`** variant.
4. **Update `src/obs.rs`** label functions.
5. **Wire `FlowSessionDriver` synthesis**: after each `feed_*` /
   `fin_*` call, check `is_poisoned()`; if true, emit anomaly
   (when on), emit `Closed { reason: ParseError }`, drop parser
   slot, call `tracker.forget(&key)`.
6. **Same wiring for `FlowDatagramDriver`** (Plan 57) — coordinate
   with that plan. If Plan 57 lands first, this plan adds the
   parser-poison handling there. If 55 lands first, 57 inherits
   the pattern.
7. **Update HTTP / TLS / DNS shipped parsers** to optionally set
   poison state on malformed input. **Default behaviour stays
   the same** — they currently drop bad bytes silently; this plan
   gives them the *option* to signal poison via `is_poisoned()`.
   Whether each parser starts using the option is a per-parser
   judgment call. For 0.3.0, ship the trait machinery; update
   parsers in a follow-up if real bugs surface.
8. **Add SESSION_GUIDE.md subsection** "Signalling unrecoverable
   errors" under the Plan 53 parser-author walkthrough.
9. **CHANGELOG entry** under 0.3.0 with migration note: anyone
   doing an exhaustive `match EndReason { ... }` outside flowscope
   needs the new `ParseError` arm.

---

## Tests

### `src/session_driver.rs`

```rust
#[test]
fn poison_in_feed_initiator_synthesises_parse_error_ended() {
    let mut d = FlowSessionDriver::<_, PoisonAfterNBytes>::new(
        FiveTuple::bidirectional(),
    );
    // 3WHS + 200B initiator data — parser poisons after 100 B.
    let mut events = Vec::new();
    for f in build_3whs() {
        events.extend(d.track(view(&f, 0)));
    }
    let data = ipv4_tcp(/* 200 B */);
    events.extend(d.track(view(&data, 0)));
    // Expect: an Application event for the messages parsed before
    // poison, then Closed { reason: ParseError }.
    let closed = events
        .into_iter()
        .find_map(|e| match e {
            SessionEvent::Closed { reason, .. } => Some(reason),
            _ => None,
        })
        .expect("Closed event");
    assert_eq!(closed, EndReason::ParseError);
}

#[test]
fn poison_with_emit_anomalies_fires_parse_error_anomaly() {
    let mut d = FlowSessionDriver::<_, PoisonAfterNBytes>::new(
        FiveTuple::bidirectional(),
    )
    .with_emit_anomalies(true);
    // Same scenario.
    let events: Vec<_> = /* ... */;
    let anomaly = events.iter().find(|e| matches!(
        e,
        SessionEvent::Anomaly {
            kind: AnomalyKind::SessionParseError { .. }, ..
        }
    ));
    assert!(anomaly.is_some());
}

#[test]
fn non_poisoning_parser_unaffected() {
    // The four shipped parsers (HTTP / TLS / DNS-UDP / DNS-TCP)
    // never set is_poisoned(); their existing tests must pass
    // without modification.
    // Run a representative HTTP fixture through and assert no
    // Closed { reason: ParseError } events.
}

// Test parser:
#[derive(Default, Clone)]
struct PoisonAfterNBytes {
    init_bytes: usize,
    poisoned: bool,
}

impl SessionParser for PoisonAfterNBytes {
    type Message = ();
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<()> {
        self.init_bytes += bytes.len();
        if self.init_bytes > 100 {
            self.poisoned = true;
        }
        Vec::new()
    }
    fn feed_responder(&mut self, _: &[u8]) -> Vec<()> { Vec::new() }
    fn is_poisoned(&self) -> bool { self.poisoned }
    fn poison_reason(&self) -> Option<&str> {
        if self.poisoned { Some("test poison after 100 bytes") } else { None }
    }
}
```

### `src/event.rs` (unit)

```rust
#[test]
fn end_reason_parse_error_variant_exists() {
    let r = EndReason::ParseError;
    assert_ne!(r, EndReason::Fin);
}

#[test]
fn anomaly_kind_session_parse_error_carries_reason() {
    let k = AnomalyKind::SessionParseError {
        side: FlowSide::Initiator,
        reason: Some("bad magic".to_string()),
    };
    assert!(matches!(k, AnomalyKind::SessionParseError { .. }));
}
```

### `tests/metrics_integration.rs`

Add a test that drives a `PoisonAfterNBytes` parser through and
verifies:
- `flowscope_flows_ended_total{reason="parse_error"}` increments.
- `flowscope_anomalies_total{kind="parse_error"}` increments
  (with `with_emit_anomalies(true)`).

---

## Acceptance criteria

- [ ] `SessionParser::is_poisoned()` and
      `DatagramParser::is_poisoned()` exist with default-false
      impl.
- [ ] `*::poison_reason()` exists with default-None impl.
- [ ] `EndReason::ParseError` variant exists.
- [ ] `AnomalyKind::SessionParseError { side, reason }` variant
      exists; `reason` is `Option<String>` truncated to 256 bytes.
- [ ] `FlowSessionDriver` synthesises `Closed { reason:
      ParseError }` on poison, forgets the flow, drops the parser
      slot.
- [ ] `FlowDatagramDriver` (Plan 57) does the same for
      `DatagramParser` poison.
- [ ] When `emit_anomalies` is on, a
      `SessionEvent::Anomaly { kind: SessionParseError }` fires
      before the `Closed` event.
- [ ] obs metric labels include `reason="parse_error"` and
      `kind="parse_error"`.
- [ ] All four shipped parsers (HTTP / TLS / DNS-UDP / DNS-TCP)
      compile unchanged (default false / None).
- [ ] Round-trip CI test (Plan 52) updated to use the new
      `EndReason` arm in any exhaustive match.
- [ ] SESSION_GUIDE.md "Signalling unrecoverable errors"
      subsection added.
- [ ] CHANGELOG entry under 0.3.0; migration note for
      `EndReason` matches.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Existing exhaustive matches.** Adding `EndReason::ParseError`
   breaks every external exhaustive match. CHANGELOG migration
   recipe: add an explicit `EndReason::ParseError => /* same as
   Rst */` arm. The internal `obs.rs` and `driver.rs` matches
   are updated in this plan.
2. **`AnomalyKind::SessionParseError { reason: Option<String> }`
   allocates per anomaly.** The truncation cap (256 B) bounds
   the size, but allocation cost is real. Document; for hot
   paths consumers can disable `emit_anomalies` and rely on the
   `Closed { reason: ParseError }` path which carries no
   `reason` string.
3. **Per-side poison semantics.** If a parser poisons after
   `feed_initiator` but not `feed_responder`, we synthesise the
   anomaly with `side: Initiator` and tear down the whole flow
   (both sides). That's correct — poison is flow-level by design.
   Document.
4. **Coordination with Plan 51.** Plan 51 refactors
   `FlowSessionDriver` to wrap `FlowDriver`. This plan extends
   that refactored structure. Land 51 first; this plan slots in
   cleanly.
5. **Coordination with Plan 57.** Plan 57 (`FlowDatagramDriver`)
   needs the same poison wiring for `DatagramParser`. Whichever
   plan lands first adds the trait methods + reason label; the
   other inherits.
6. **HTTP / TLS / DNS parsers don't use the option in 0.3.0.**
   They continue to silently drop bad bytes (their current
   behaviour). Whether to retrofit `is_poisoned` into them is a
   per-parser judgment call for a follow-up release. Documented.

---

## Effort

- LOC: ~200 (trait methods + variants + driver wiring + tests +
  doc).
- Time: 1.5 days.

---

## Provenance

Identified during the 0.3.0 planning review (not in the des-rs
feedback report). The current trait shape silently consumes
bytes from a corrupted parser — a real correctness gap that the
des-rs team would hit eventually with their PSMSG parser when
malformed publishers connect to a mediator. Closing it now is a
pre-1.0 design-quality decision.

Mirrors the `Reassembler::is_poisoned` precedent that shipped in
0.2.0 (Plan 42 §1). Same wiring pattern, same operator mental
model.
