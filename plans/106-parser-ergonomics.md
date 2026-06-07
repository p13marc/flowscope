# Plan 106 — custom-parser ergonomics overhaul

## Summary

Three additions to make writing custom `SessionParser` /
`DatagramParser` impls less tedious:

1. **`AccumulatingSessionParser<F>`** — pre-baked builder for
   the universal "init_buf + resp_buf + parse-one-loop"
   pattern. Most custom parsers (RESP, length-prefixed,
   line-based, framed binary) follow this shape.
2. **Fallible `feed_*` variant on `SessionParser` /
   `DatagramParser`** — optional `Result`-returning method
   so parsers can surface "the byte stream is garbage"
   without going through a manual `is_poisoned()` flag.
3. **`BufferedFrameDrain` helper** — a small struct
   encapsulating the "fill a buffer, drain N bytes when a
   message parses, retain partial" pattern. Catches the
   off-by-one bugs every custom parser has on first write.

Theme 7 from
[`plans/100-examples-postmortem.md`](./100-examples-postmortem.md).
The `redis_protocol.rs` example exposed all three pain points.

## Status

**Ready to implement.** Targets 0.10.0. Independent of other
0.10 plans except for the small overlap with plan 108 — both
touch the `session.rs` module.

## Prerequisites

- The `SessionParser` / `DatagramParser` traits (locked since
  0.1.0). This plan extends them additively.

## Out of scope

- **`#[derive(SessionParser)]` macro.** Listed in the
  postmortem as "strategic — 0.11+." Out of scope here; the
  `AccumulatingSessionParser` adapter is the bridge.
- **A new top-level parser trait.** `SessionParser` and
  `DatagramParser` stay. The additions are method-default
  extensions + an adapter type.
- **Reworking reassembler interaction.** Plan 74's
  `SegmentBufferReassembler` is the storage layer; the
  parser sees byte streams from there. Out of scope to
  change that interface.

---

## Surface 1 — `AccumulatingSessionParser<F>`

The universal pattern for custom binary / text protocols:

```rust
// Today: every consumer rolls their own.
#[derive(Default, Clone)]
struct MyParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for MyParser {
    type Message = MyMessage;
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<MyMessage> {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf)
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<MyMessage> {
        self.resp_buf.extend_from_slice(bytes);
        drain(&mut self.resp_buf)
    }
}

fn drain(buf: &mut Vec<u8>) -> Vec<MyMessage> {
    let mut out = Vec::new();
    while let Some((msg, consumed)) = parse_one(buf) {
        out.push(msg);
        buf.drain(..consumed);
    }
    out
}

fn parse_one(buf: &[u8]) -> Option<(MyMessage, usize)> { /* protocol logic */ }
```

Proposal:

```rust
// 0.10: register the parse_one closure once.
let parser = AccumulatingSessionParser::new("my-protocol", parse_one);
//                                          ^               ^
//                                       parser_kind     Fn(&[u8]) -> Option<(M, usize)>
```

Reduces ~25 LoC of boilerplate per custom parser to one
constructor call.

### API

```rust
// src/session.rs (new module member)
pub struct AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + 'static,
{
    parser_kind: &'static str,
    parse_one: F,
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
    /// Max bytes per side before declaring the parser
    /// desynced. Defaults to 64 KiB.
    max_buffer: usize,
    poisoned: bool,
}

impl<F, M> AccumulatingSessionParser<F, M>
where
    F: Fn(&[u8]) -> Option<(M, usize)> + Clone + Send + 'static,
    M: Send + 'static,
{
    pub fn new(parser_kind: &'static str, parse_one: F) -> Self;

    pub fn with_max_buffer(mut self, n: usize) -> Self;
}

impl<F, M> SessionParser for AccumulatingSessionParser<F, M> { … }
impl<F, M> Clone for AccumulatingSessionParser<F, M> { /* clones parse_one closure */ }
```

The `parse_one: Fn(&[u8]) -> Option<(M, usize)>` contract is
the universal one:

- Return `Some((message, bytes_consumed))` when a complete
  message is available.
- Return `None` when more bytes are needed.
- Returning `Some((_, 0))` is forbidden (caught with a
  debug-mode assert; in release, treated as desync to avoid
  infinite loops).

### Datagram variant

```rust
pub struct PerDatagramParser<F, M>
where
    F: Fn(&[u8]) -> Option<M> + Clone + Send + 'static,
    M: Send + 'static,
{
    parser_kind: &'static str,
    parse_one: F,
}

impl<F, M> DatagramParser for PerDatagramParser<F, M> {
    type Message = M;
    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<M> {
        (self.parse_one)(payload).into_iter().collect()
    }
}
```

UDP is even simpler — one packet, one optional message.

---

## Surface 2 — fallible `feed_*`

The existing trait:

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;
    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    // …
}
```

Garbage input has no error path — parsers return `Vec::new()`
silently or set a manual `is_poisoned()` flag.

The extension:

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;
    /// `Default::default()` if the parser never fails.
    /// Concrete error type if it does.
    type Error: std::error::Error + Send + 'static = Infallible;

    fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;
    fn feed_responder(&mut self, bytes: &[u8], ts: Timestamp) -> Vec<Self::Message>;

    /// Fallible variant. Default impl wraps the infallible
    /// method.
    fn feed_initiator_fallible(
        &mut self,
        bytes: &[u8],
        ts: Timestamp,
    ) -> Result<Vec<Self::Message>, Self::Error> {
        Ok(self.feed_initiator(bytes, ts))
    }
    fn feed_responder_fallible(
        &mut self,
        bytes: &[u8],
        ts: Timestamp,
    ) -> Result<Vec<Self::Message>, Self::Error> {
        Ok(self.feed_responder(bytes, ts))
    }

    // … existing methods …
}
```

**The driver layer routes `Err` automatically.** When a
`SessionParser` returns `Err`, `FlowSessionDriver` synthesises
a `SessionEvent::Closed { reason: ParseError, … }` for the
flow on the next tick. No manual poison flag needed.

The associated-type default `Error = Infallible` keeps the
addition backward-compatible — existing impls don't need to
declare `Error` if they never fail.

### Wait — associated-type defaults aren't stable.

As of Rust 1.88, `associated_type_defaults` is still unstable.
**Workaround**: ship the fallible variant as a `pub trait
FallibleSessionParser: SessionParser` extension trait.
Consumers who want fallibility implement both:

```rust
impl SessionParser for MyParser { … existing … }
impl FallibleSessionParser for MyParser {
    type Error = MyParseError;
    fn feed_initiator_fallible(&mut self, …) -> Result<…, Self::Error> { … }
    fn feed_responder_fallible(&mut self, …) -> Result<…, Self::Error> { … }
}
```

The driver checks `dyn FallibleSessionParser` at runtime
(small enum discriminator) and routes Err to a synthesised
Closed event.

Less elegant than the assoc-type-default shape but ships
today. When `associated_type_defaults` stabilises, the
extension trait collapses into the main trait (additive
deprecation).

---

## Surface 3 — `BufferedFrameDrain<M>`

A small helper for parsers that need to manage their own
buffer + drain pattern (when `AccumulatingSessionParser`
doesn't fit):

```rust
// src/session.rs
pub struct BufferedFrameDrain<M> {
    buf: Vec<u8>,
    out: Vec<M>,
    max_buffer: usize,
}

impl<M> BufferedFrameDrain<M> {
    pub fn new() -> Self;
    pub fn with_max_buffer(n: usize) -> Self;

    pub fn extend(&mut self, bytes: &[u8]) -> Result<(), FrameDrainError>;

    /// Repeatedly call `parse_one` and drain consumed bytes;
    /// accumulate messages into `out`. Stop when `parse_one`
    /// returns `None`.
    pub fn drain_with<F>(&mut self, parse_one: F)
    where
        F: FnMut(&[u8]) -> Option<(M, usize)>;

    pub fn take_messages(&mut self) -> Vec<M>;
    pub fn buffered_len(&self) -> usize;
    pub fn is_poisoned(&self) -> bool;
}
```

Used inside a custom `SessionParser` impl:

```rust
#[derive(Default, Clone)]
struct ComplexParser {
    init: BufferedFrameDrain<MyMessage>,
    resp: BufferedFrameDrain<MyMessage>,
}

impl SessionParser for ComplexParser {
    type Message = MyMessage;
    fn feed_initiator(&mut self, b: &[u8], _: Timestamp) -> Vec<MyMessage> {
        let _ = self.init.extend(b);
        self.init.drain_with(parse_one);
        self.init.take_messages()
    }
    fn feed_responder(&mut self, b: &[u8], _: Timestamp) -> Vec<MyMessage> {
        let _ = self.resp.extend(b);
        self.resp.drain_with(parse_one);
        self.resp.take_messages()
    }
}
```

Catches the off-by-one bugs. Useful when parsers need
per-side state beyond a single buffer (e.g. recursive
protocols where state is more than just bytes).

---

## Files

```
src/session.rs                    # add AccumulatingSessionParser + BufferedFrameDrain
                                  # add FallibleSessionParser extension trait
src/datagram_session.rs           # add PerDatagramParser
src/driver.rs                     # route fallible Err to ParseError synthesis
src/session_driver.rs             # same
docs/recipes.md                   # rewrite custom-parser section
examples/redis_protocol.rs        # MIGRATED to AccumulatingSessionParser
examples/length_prefixed_pcap.rs  # MIGRATED to AccumulatingSessionParser
tests/parser_helpers.rs           # NEW — accumulator + drain + fallible coverage
CHANGELOG.md                      # 0.10 entry
```

## Implementation steps

1. **Add `BufferedFrameDrain<M>`** — small struct, straightforward
   API.
2. **Add `AccumulatingSessionParser<F, M>`** — built on top of
   `BufferedFrameDrain` plus the parser-kind constant.
3. **Add `PerDatagramParser<F, M>`** for UDP parity.
4. **Add `FallibleSessionParser` extension trait + matching
   `FallibleDatagramParser`.**
5. **Update `FlowSessionDriver`** to detect `dyn
   FallibleSessionParser` at construction (via a small
   builder method `.with_fallible_parser()`) and route Err →
   `ParseError` close synthesis. Same for
   `FlowDatagramDriver`.
6. **Migrate `examples/redis_protocol.rs`** to use the new
   shape — drops from ~180 LoC to ~80.
7. **Migrate `examples/length_prefixed_pcap.rs`** to use
   `AccumulatingSessionParser` — drops from ~130 LoC to
   ~70.
8. **Rewrite `docs/recipes.md` custom-parser section** to
   lead with `AccumulatingSessionParser`; keep the manual
   `SessionParser` impl as the "drop down if you need it"
   reference.
9. **CHANGELOG entry** under 0.10.0 "Added".

## Tests

`tests/parser_helpers.rs` (new):

```rust
// AccumulatingSessionParser
- Single complete message: feed → 1 message.
- Split across two feeds: feed half → 0, feed rest → 1.
- Two messages in one feed: feed both → 2 messages.
- max_buffer enforcement: feed > max → parser poisons.

// PerDatagramParser
- Single payload → Some(msg) → returned.
- Garbage payload → None → empty Vec.

// FallibleSessionParser
- Parser returning Ok works normally.
- Parser returning Err triggers ParseError close synthesis
  in the driver.
- Parser returning Err on first feed → flow sees Closed
  immediately on the next tick.

// BufferedFrameDrain
- extend + drain_with cycle.
- max_buffer enforcement.
- take_messages returns and clears.
```

Plus property test: arbitrary chunking of the same byte
stream produces the same message sequence.

## Acceptance criteria

- `AccumulatingSessionParser` / `PerDatagramParser` /
  `BufferedFrameDrain` ship.
- `FallibleSessionParser` + `FallibleDatagramParser`
  extension traits ship.
- Drivers correctly synthesise `ParseError` close events
  when a fallible parser returns `Err`.
- Two example migrations — ~40-100 LoC reduction each.
- 12+ test scenarios pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- CHANGELOG entry under 0.10.0 "Added"; no breakage.

## Risks

- **`AccumulatingSessionParser`'s closure storage `F: Clone`
  requirement.** Most closures implement `Clone`
  automatically; capturing-by-move closures don't. Mitigation:
  document the requirement; for closures that don't, suggest
  wrapping in `Arc<dyn Fn(_)>`.

- **Driver detection of fallibility.** Routing `Err` to
  `ParseError` requires knowing at construction time whether
  the parser is fallible. `dyn FallibleSessionParser` downcast
  is fragile. Mitigation: explicit builder method —
  `FlowSessionDriver::with_fallible_parser(p)` selects the
  fallible path; `with_parser(p)` keeps the infallible default.

- **`Infallible` ergonomics on Stable Rust.** Until associated-type
  defaults stabilise, the extension-trait shape is the only
  option. Document the migration path (extension trait → main
  trait method) in rustdoc so future readers don't get
  confused.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `BufferedFrameDrain` | ~100 | 2 |
| `AccumulatingSessionParser` | ~150 | 3 |
| `PerDatagramParser` | ~50 | 1 |
| `FallibleSessionParser` + `FallibleDatagramParser` | ~80 | 2 |
| Driver detection + ParseError routing | ~120 | 4 |
| Tests (12+ scenarios) | ~320 | 5 |
| Example migrations (2 files, ~140 LoC saved net) | ~−40 net | 2 |
| Docs + CHANGELOG | ~80 | 1 |
| **Total** | **~860 LoC** | **~20 hours** |

## Provenance

Postmortem theme 7:

> `SessionParser::feed_*` returns `Vec<Self::Message>` — no
> `Result`. When I hit garbage I could either return
> `Vec::new()` silently or implement `is_poisoned()` myself.
> Both feel wrong: silent-drop hides bugs, manual poison
> flag is duplication.
>
> Recursive parsers (RESP arrays) need to consume bytes
> partially. The drain pattern `let n = parse_one(&buf);
> buf.drain(..n);` was awkward — easy to get wrong if `n`
> exceeds the buffer.
>
> The `init_buf` / `resp_buf` accumulator pattern is so
> universal it should be a struct. Every custom-protocol
> example reimplements it.

The example file in question — `redis_protocol.rs` —
implements the RESP protocol in ~180 LoC of which ~120 is
the accumulator + drain + parse-one boilerplate. Plan 106
collapses that to ~80 LoC total.
