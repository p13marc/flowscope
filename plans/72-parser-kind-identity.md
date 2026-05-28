# Plan 72 — Parser identity on `SessionEvent::Application`

## Summary

Downstream consumers route metrics / events by parser identity
(`metrics/rtp/...`, `metrics/sip/...`,
`metrics/http/...`). Today the parser identity has to be baked
into the `Message` type itself, which conflates "what's this
message" with "what parser produced it." The conflation forces
every consumer to redo the same factoring.

Lift parser identity to the trait + event level:

- New `SessionParser::parser_kind(&self) -> &'static str`
  trait method, default `""`.
- New `DatagramParser::parser_kind(&self) -> &'static str`,
  same default.
- New `parser_kind: &'static str` field on
  `SessionEvent::Application` (the existing variant).
- Drivers thread the kind through from the per-flow parser
  instance.

Pre-1.0 BC policy permits the variant-field addition;
migration is one new field or a `..` pattern.

## Status

Not started. Targets 0.5.0.

## Prerequisites

- Plan 51 (`SessionEvent::Anomaly` + `#[non_exhaustive]` on
  `SessionEvent`) — shipped in 0.3.0. The enum-level
  non_exhaustive makes future variant additions painless;
  field-level additions on existing variants still break
  destructuring (Rust doesn't propagate `#[non_exhaustive]` to
  variants automatically).

## Out of scope

- Identifying datagram parsers in `SessionEvent::Application`.
  The current `FlowDatagramDriver` already emits
  `SessionEvent::Application` for UDP — the field works for
  both directions. We add the corresponding
  `DatagramParser::parser_kind` so the UDP path can populate
  it.
- A free-form `Cow<'static, str>` or dynamic string. We use
  `&'static str` to bound the metric-cardinality story (label
  values must be static so the metric system can pre-allocate).
  Parsers needing dynamic kinds bake them into `Message`.
- Per-instance kind variation. The trait method takes `&self`
  but is expected to return the same value for the lifetime of
  the parser. Don't return e.g. seq-counter-based names.
- Backporting `parser_kind` to all four shipped parsers' label
  conventions in the same release. We DO set sensible
  defaults: `http/1`, `tls`, `dns-udp`, `dns-tcp`. The
  consumer-facing names match what the metric vocabulary
  already uses where applicable.

---

## Files

### MODIFIED

- `src/session.rs` — add `parser_kind()` default-`""` method
  on both parser traits. Add `parser_kind: &'static str` field
  on `SessionEvent::Application`.
- `src/session_driver.rs` — thread kind from
  `self.parsers.get(&key).map(|p| p.parser_kind())` into
  Application emission.
- `src/datagram_driver.rs` — same.
- `src/http/session.rs` — `HttpParser::parser_kind() ->
  "http/1"`.
- `src/tls/session.rs` — `TlsParser::parser_kind() -> "tls"`.
- `src/dns/datagram.rs` — `DnsUdpParser::parser_kind() ->
  "dns-udp"`.
- `src/dns/session.rs` — `DnsTcpParser::parser_kind() ->
  "dns-tcp"`.
- `examples/length_prefixed_pcap.rs` — set `"length-prefixed"`
  on the example parser; demonstrates the convention.
- `tests/length_prefixed_example.rs` — same.
- `tests/round_trip.rs` — `PassthroughParser::parser_kind()
  -> "passthrough"`; verifies the kind survives the
  pcap → driver → SessionEvent path.
- `docs/SESSION_GUIDE.md` — extend "Writing your own
  SessionParser" with a paragraph on the convention.
- `CHANGELOG.md` — 0.5.0 entry; migration recipe for the
  `Application` field addition.

### NEW

None.

---

## API

### `src/session.rs`

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn fin_initiator(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn fin_responder(&mut self) -> Vec<Self::Message> { Vec::new() }
    fn rst_initiator(&mut self) {}
    fn rst_responder(&mut self) {}
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }

    /// Identifier for this parser, threaded into
    /// [`crate::SessionEvent::Application::parser_kind`].
    ///
    /// Use a stable, label-safe identifier — operators route
    /// metrics on this string. Convention:
    ///
    /// - Lowercase, ASCII, snake-case or slash-separated
    ///   (`http/1`, `dns-udp`, `rtp`, `length-prefixed`).
    /// - Stable for the lifetime of the parser instance.
    /// - Default: `""` (caller-facing as "no kind set").
    ///
    /// `&'static str` rather than `Cow` so the value can flow
    /// into `metrics::counter!` labels without allocation. If
    /// you need a dynamic kind, bake it into [`Self::Message`].
    fn parser_kind(&self) -> &'static str { "" }
}

pub trait DatagramParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;

    fn parse(&mut self, payload: &[u8], side: FlowSide, ts: Timestamp) -> Vec<Self::Message>;
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
    fn is_poisoned(&self) -> bool { false }
    fn poison_reason(&self) -> Option<&str> { None }

    /// See [`SessionParser::parser_kind`].
    fn parser_kind(&self) -> &'static str { "" }
}
```

### `src/session.rs` — `SessionEvent::Application`

```rust
#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum SessionEvent<K, M> {
    Started { /* ... */ },
    /// Parser emitted a complete L7 message.
    Application {
        key: K,
        side: FlowSide,
        message: M,
        ts: Timestamp,
        /// Identifier of the parser that produced this
        /// message (new in 0.5.0). See
        /// [`SessionParser::parser_kind`].
        parser_kind: &'static str,
    },
    Closed { /* ... */ },
    Anomaly { /* ... */ },
    FlowTick { /* ... */ },  // if Plan 71 lands first
}
```

### Driver wiring

`FlowSessionDriver::drain_into_parser` and
`FlowDatagramDriver::translate_events` both already have the
per-flow parser instance in hand when they emit Application
events. The change is two lines per call site:

```rust
let kind = parser.parser_kind();
let messages = match side {
    FlowSide::Initiator => parser.feed_initiator(&drained, ts),
    FlowSide::Responder => parser.feed_responder(&drained, ts),
};
for m in messages {
    out.push(SessionEvent::Application {
        key: key.clone(),
        side,
        message: m,
        ts,
        parser_kind: kind,
    });
}
```

### Shipped parsers — set the kind

```rust
// src/http/session.rs
impl SessionParser for HttpParser {
    // ...
    fn parser_kind(&self) -> &'static str { "http/1" }
}

// src/tls/session.rs
impl SessionParser for TlsParser {
    fn parser_kind(&self) -> &'static str { "tls" }
}

// src/dns/datagram.rs
impl DatagramParser for DnsUdpParser {
    fn parser_kind(&self) -> &'static str { "dns-udp" }
}

// src/dns/session.rs
impl SessionParser for DnsTcpParser {
    fn parser_kind(&self) -> &'static str { "dns-tcp" }
}
```

---

## Implementation steps

1. **Add `parser_kind()` trait method** with default `""` on
   both `SessionParser` and `DatagramParser`. No call site
   churn yet — default is safe.
2. **Add `parser_kind: &'static str` field** to
   `SessionEvent::Application`. This breaks destructuring
   patterns; fix internal patterns in driver + tests + obs.
3. **Wire the field** in `FlowSessionDriver` and
   `FlowDatagramDriver` Application emission paths.
4. **Set `parser_kind` on shipped parsers**: HTTP `http/1`,
   TLS `tls`, DNS-UDP `dns-udp`, DNS-TCP `dns-tcp`.
5. **Update the worked example** (`length_prefixed_pcap.rs`)
   to demonstrate the convention.
6. **Update SESSION_GUIDE.md** "Writing your own
   SessionParser" with a paragraph on the convention.
7. **CHANGELOG entry** under 0.5.0 with migration recipe.

The destructuring break is the only friction. Migration
recipe:

```diff
- SessionEvent::Application { key, side, message, ts } => ...
+ SessionEvent::Application { key, side, message, ts, parser_kind } => ...
+ // OR:
+ SessionEvent::Application { key, side, message, ts, .. } => ...
```

---

## Tests

```rust
#[test]
fn shipped_http_parser_reports_correct_kind() {
    let p = HttpParser::default();
    assert_eq!(p.parser_kind(), "http/1");
}

#[test]
fn shipped_tls_parser_reports_correct_kind() {
    let p = TlsParser::default();
    assert_eq!(p.parser_kind(), "tls");
}

#[test]
fn dns_parsers_report_correct_kinds() {
    assert_eq!(DnsUdpParser::default().parser_kind(), "dns-udp");
    assert_eq!(DnsTcpParser::default().parser_kind(), "dns-tcp");
}

#[test]
fn parser_kind_threaded_into_application_events() {
    // Drive an HTTP fixture through FlowSessionDriver.
    // Verify every Application event has parser_kind == "http/1".
    let mut d = FlowSessionDriver::<_, HttpParser>::new(
        FiveTuple::bidirectional(),
    );
    // ... drive http_session.pcap ...
    for ev in events {
        if let SessionEvent::Application { parser_kind, .. } = ev {
            assert_eq!(parser_kind, "http/1");
        }
    }
}

#[test]
fn default_parser_kind_is_empty() {
    #[derive(Default, Clone)]
    struct Noop;
    impl SessionParser for Noop {
        type Message = ();
        fn feed_initiator(&mut self, _: &[u8], _: Timestamp) -> Vec<()> {
            vec![()]
        }
        fn feed_responder(&mut self, _: &[u8], _: Timestamp) -> Vec<()> {
            Vec::new()
        }
    }
    assert_eq!(Noop.parser_kind(), "");
}
```

---

## Acceptance criteria

- [ ] `SessionParser::parser_kind(&self) -> &'static str`
      method exists; default `""`.
- [ ] `DatagramParser::parser_kind(&self) -> &'static str`
      mirrors.
- [ ] `SessionEvent::Application` has the new field;
      `FlowSessionDriver` and `FlowDatagramDriver` populate
      it from the per-flow parser.
- [ ] Shipped parsers report stable identifiers
      (`http/1`, `tls`, `dns-udp`, `dns-tcp`).
- [ ] The worked example sets `length-prefixed`; the
      round-trip CI test sets `passthrough`.
- [ ] SESSION_GUIDE.md "Writing your own SessionParser"
      mentions the convention.
- [ ] CHANGELOG entry under 0.5.0 with migration recipe for
      the destructuring break.
- [ ] `cargo test --all-features` clean (after migration of
      the in-tree match patterns).
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Destructuring break on `SessionEvent::Application`.**
   Pre-1.0 BC policy allows; migration is one new field or a
   `..` pattern. CHANGELOG includes the migration recipe.
   All in-tree patterns updated as part of this plan.
2. **Static-string constraint.** Parsers can't return dynamic
   names. For dynamic-namespace parsers (e.g. SIP routing by
   user-agent), bake into `Message`. Documented.
3. **Naming convention drift.** If two consumer organisations
   pick different conventions for HTTP variants (`http`,
   `http/1`, `http/1.1`), our shipped `http/1` becomes a
   de-facto convention. Documented; we own the four built-in
   names.
4. **Field ordering in destructuring patterns.** Rust's
   `SessionEvent::Application { key, side, message, ts,
   parser_kind }` reorders compared to existing source —
   field-order in patterns is irrelevant to the compiler but
   may cause readability churn in PRs. Style guide
   recommendation: keep `parser_kind` last.
5. **Future: variant additions vs field additions.** The
   `#[non_exhaustive]` on the enum protects variant addition;
   field addition on a variant still breaks. If we predict
   more variant-field churn, we could pivot to
   `Application(ApplicationEvent<K, M>)` with the struct
   non_exhaustive. Premature; skip until a second field is
   actually needed.

---

## Effort

- LOC: ~60 source (4 trait method overrides on shipped
  parsers + driver-side wiring + Application field) + ~30 tests.
- Time: ½ day.

---

## Provenance

Wishlist item F1.7 from
`docs/feedback-2026-08-11-simple-nms.md`. The team
specifically wants the metric namespace partly derived from
the parser kind (`metrics/rtp/...`), and the trait-level
approach centralises this without forcing kind to be baked
into every consumer's `Message` type.

The `&'static str` constraint matches our metrics-cardinality
discipline (per OBSERVABILITY.md) — never put high-cardinality
values in metric labels, including parser kinds, which by
construction are a small enumerable set.
