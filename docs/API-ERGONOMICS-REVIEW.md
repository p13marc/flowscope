# API Ergonomics Review — flowscope 0.3.0

**Date:** 2026-05-18
**Scope:** Public API surface — is the crate user-friendly? Is the
API high-level enough?
**Status:** Shipped. All six findings landed as the `plan 32-34` …
`plan 37` commits (see §5 and `CHANGELOG.md`). This document is kept
as the rationale record for that work.
**Backward compatibility:** breaking changes were *in scope*. Pre-1.0
policy allows it; `netring` updates in lockstep, `CHANGELOG.md`
carries the migration recipes.

---

## 1. Verdict

The crate is well-architected and the reference docs are excellent.
But the API is **high-level for the demo, mid-level for real work**.
The README quick-start is a genuine one-expression hello-world; the
moment a user wants anything past "list flow lifecycle from a pcap"
they hand-assemble 3–4 types and hit avoidable friction.

Every issue below is fixable in the constructor / convenience layer.
**None of it touches the `SessionParser` / `DatagramParser` trait
shape** locked since 0.1 — the one finding that *would* touch a trait
(F5) is additive (a defaulted method).

Headline number: of the 5 shipped examples, **4 carry a generic-
parameter type annotation** that a well-shaped API would not require,
and **1 contains a magic-number workaround** (`86_400`) for a missing
method.

---

## 2. Methodology

Reviewed: `src/lib.rs` re-exports, the public constructors of
`FlowDriver` / `FlowSessionDriver` / `FlowDatagramDriver` /
`FlowTracker` / `PcapFlowSource`, all 5 runnable examples, the README
quick-start, and `docs/SESSION_GUIDE.md`.

Compared against the public APIs of `etherparse`, `pcap`,
`pcap-parser`, `tls-parser`, `netflow_parser`, `httparse`, `pnet`,
`simple-dns`, and the `pcap-analyzer` (PAL) plugin framework — the
closest architectural analogs in the Rust packet/flow/DPI space.

What the best-regarded crates in this space converge on:

1. One obvious constructor; `&[u8]` → structured value in one call.
2. Builders for *construction*, bare functions for *parsing*.
3. A real `std::Iterator` for streamed input (never manual
   `consume`/`refill`).
4. Statefulness hidden behind `&mut self` — the caller never manages
   protocol state, template caches, or reassembly buffers.
5. Graceful partial failure — return what parsed plus a diagnostic.

flowscope already satisfies 2, 3, 4, and 5. It is weakest on **1**.

---

## 3. What the API already gets right

Worth stating, so the review is balanced — these are real strengths
and should not regress:

- **Typed `SessionParser` / `DatagramParser`** with an associated
  `Message` type — strictly better than the `Box<dyn Any>` result
  channel that PAL's `Plugin` trait uses.
- **`feed_initiator` / `feed_responder` → `Vec<Message>` owns the
  resync/buffering loop** — precisely the painful part that raw
  `tls-parser` pushes onto users via `Err::Incomplete`.
- **`PcapFlowSource::with_extractor()` returns a real `Iterator`** —
  not the fake `consume`/`refill` "iterator" that `pcap-parser` is
  universally cited for.
- **`#[non_exhaustive]` project-wide**, `with_*` builders on the
  setup path, bare `track()` on the hot path, `Default + Clone`
  blanket factory impl.
- **`SESSION_GUIDE.md` is genuinely good** — the decision tree is
  the right mitigation for a necessarily wide L7 surface.

---

## 4. Findings

Ranked by how many users hit them.

### F1 — Generic-parameter ceremony (every user hits this) 🔴

The per-flow user-state parameter `S` defaults to `()`, but Rust type-
parameter defaults **do not participate in inference**. Every driver
constructor is generic over `S`, so `S` must be inferred or annotated
— and it usually can't be inferred. The annotation leaks into every
construction site.

Evidence — from the shipped examples:

```rust
// examples/http_log.rs:55
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);

// examples/tls_observer.rs:46
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);

// examples/dns_log.rs:68
let mut tracker: FlowTracker<_, ()> = FlowTracker::new(observer);

// examples/length_prefixed_pcap.rs:110
let mut driver =
    FlowSessionDriver::<_, LengthPrefixedParser>::new(FiveTuple::bidirectional());
```

The 95% of users who never attach per-flow user state still pay for
`S` in every type signature and turbofish.

A second, related wart: `FlowDriver::new` takes a factory **by
value** (`new(extractor, factory)`), but `FlowSessionDriver::new`
takes the parser **as a generic with no argument** (`::<_, P>::new(
extractor)`, constructed internally via `Default`). Two constructors,
two shapes, for the same conceptual thing.

**Proposed fix (breaking).** This review recommends the bolder of two
options:

- **Option A (minimal):** keep `S` on the drivers, but split the
  constructors across impl blocks so the common one pins `S = ()`:
  `new` / `with_config` move to `impl<E, F> FlowDriver<E, F, ()>`;
  the stateful constructors get distinct names on the generic block.
  Removes the annotation; keeps three type params.
- **Option B (recommended):** **remove `S` from the drivers
  entirely.** Drivers always run their tracker with `S = ()`. Per-
  flow user state stays available on `FlowTracker<E, S>` for users
  who build the tracker directly (`with_state` / `track_with_payload`
  already live there). A driver that *also* carries a per-flow parser
  *and* per-flow user state is a rare combination not worth taxing
  every signature for.

Under Option B:

```rust
pub struct FlowDriver<E, F> { ... }          // was <E, F, S = ()>
pub struct FlowSessionDriver<E, P> { ... }   // was <E, P, S = ()>
pub struct FlowDatagramDriver<E, P> { ... }  // was <E, P, S = ()>

// take the parser/factory by value, like FlowDriver already does:
impl<E, P> FlowSessionDriver<E, P> {
    pub fn new(extractor: E, parser: P) -> Self;
}
```

Before / after at the call site:

```rust
// before
let mut driver: FlowDriver<FiveTuple, _, ()> =
    FlowDriver::new(FiveTuple::bidirectional(), factory);
let mut driver =
    FlowSessionDriver::<_, LengthPrefixedParser>::new(FiveTuple::bidirectional());

// after
let mut driver = FlowDriver::new(FiveTuple::bidirectional(), factory);
let mut driver = FlowSessionDriver::new(FiveTuple::bidirectional(),
                                        LengthPrefixedParser::default());
```

**Breakage:** type signatures naming `FlowDriver<_, _, ()>` etc. drop
a parameter; `FlowSessionDriver` / `FlowDatagramDriver` constructors
gain a value argument. `netring`'s adapters and `tracker_mut()`
callers update. Mechanical.

### F2 — No high-level pcap → L7 adapter 🔴

`PcapFlowSource::with_extractor()` (pcap/source.rs:85) yields a clean
`Iterator<Item = Result<FlowEvent>>`. There is **no equivalent for
sessions or datagrams.** Offline HTTP/TLS/DNS means hand-wiring
`FlowDriver` + factory + the `views()` loop, as every L7 example
does:

```rust
// examples/http_log.rs:62-73 — the boilerplate the high-level path skips
let src = PcapFlowSource::open(&path)?;
for view in src.views() {
    let view = view?;
    for ev in driver.track(view.as_view()) { ... }
}
```

The README quick-start makes flowscope look one-liner-easy, then the
ergonomics fall off a cliff at L7.

**Proposed fix (additive).** Mirror `with_extractor` for the typed
parser paths, with the final sweep folded into the iterator:

```rust
impl<R: Read> PcapFlowSource<R> {
    pub fn with_extractor<E>(self, extractor: E) -> EventIter<R, E>;        // exists
    pub fn sessions<E, P>(self, extractor: E, parser: P)                    // new
        -> SessionIter<R, E, P>;     // Item = Result<SessionEvent<E::Key, P::Message>>
    pub fn datagrams<E, P>(self, extractor: E, parser: P)                   // new
        -> DatagramIter<R, E, P>;
}
```

Target call site:

```rust
for evt in PcapFlowSource::open("trace.pcap")?
    .sessions(FiveTuple::bidirectional(), HttpParser::default())
{
    if let SessionEvent::Application { message, .. } = evt? { ... }
}
```

**Breakage:** none — purely additive.

### F3 — Manual final sweep; the `86_400` magic number 🟠

In a manual driver loop the caller must remember to flush still-open
flows at end-of-input. `http_log.rs` does this with a magic-number
hack:

```rust
// examples/http_log.rs:74-81
if let Some(ts) = last_ts {
    let far = flowscope::Timestamp::new(ts.sec.saturating_add(86_400), 0);
    for ev in driver.sweep(far) { ... }
}
```

A `86_400` magic number **in an official example** is a tell: the API
forced the user to invent a workaround. A user who forgets this
silently loses their last flows — a correctness footgun, not just an
ergonomic one.

**Proposed fix (additive).** A `finish()` on every driver that sweeps
at the maximum timestamp:

```rust
impl<E, F> FlowDriver<E, F> {
    /// Sweep all remaining flows — call once at end of input.
    pub fn finish(&mut self) -> Vec<FlowEvent<E::Key>> {
        self.sweep(Timestamp::MAX)
    }
}
```

Then `http_log.rs:74-81` collapses to `for ev in driver.finish() { … }`.
(Once F2 lands, the `PcapFlowSource` iterators call `finish()`
internally and the example stops needing even that.)

**Breakage:** none — additive. Optionally add `Timestamp::MAX` as a
named const if not already public.

### F4 — `.as_view()` noise in every hot loop 🟠

Every example threads `OwnedPacketView` → `PacketView<'_>` by hand:

```rust
driver.track(view.as_view())     // http_log.rs:66, tls_observer.rs:52
driver.track(view?.as_view())    // length_prefixed_pcap.rs:113
```

`track` should accept the owned view directly.

**Proposed fix (mildly breaking).**

```rust
impl<'a> From<&'a OwnedPacketView> for PacketView<'a> { ... }

pub fn track(&mut self, view: impl Into<PacketView<'_>>) -> FlowEvents<E::Key>;
```

Call site becomes `driver.track(&view)` / `driver.track(view?)`.

**Breakage:** signature of `track` changes from `PacketView<'_>` to
`impl Into<PacketView<'_>>`. Existing `PacketView` arguments still
compile (`Into` is reflexive). Low impact.

### F5 — DNS is a third API shape; the typed traits are time-blind 🟠

DNS-over-UDP exposes **two** unrelated APIs: `DnsUdpParser` (a plain
`DatagramParser`) and `DnsUdpObserver` (an extractor-tap with
callbacks). Query/response **correlation + RTT + unanswered
detection** lives only in the observer. So "DNS with RTT in a sync
loop" forces the odd-one-out API *and* manual timer management:

```rust
// examples/dns_log.rs:67-80
let observer = DnsUdpObserver::new(FiveTuple::bidirectional(), Logger);
let mut tracker: FlowTracker<_, ()> = FlowTracker::new(observer);
for view in PcapFlowSource::open(&path)?.views() {
    ...
    if now_sec > last_sweep_sec {
        tracker.extractor().sweep_unanswered(now);   // hand-rolled timer
        last_sweep_sec = now_sec;
    }
}
```

Root cause: `SessionParser` / `DatagramParser` have **no time
input**. `parse(&mut self, payload, side)` never learns "what time is
it now," so a correlating parser physically cannot emit timeout /
unanswered events. That is why correlation had to be bolted on as a
separate observer shape.

**Proposed fix (additive — defaulted trait method).** Give the parser
traits a tick hook:

```rust
pub trait DatagramParser: Send + 'static {
    type Message: Send + 'static;
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message>;
    /// Called by the driver on each sweep with the current time.
    /// Default: no-op. Lets stateful parsers emit time-driven messages.
    fn on_tick(&mut self, _now: Timestamp) -> Vec<Self::Message> { Vec::new() }
}
```

Same defaulted method on `SessionParser`. The drivers call `on_tick`
during `sweep` / `finish`. A correlating `DnsUdpParser` then emits
`Unanswered` as a normal `Message` — and `DnsUdpObserver` can be
**deleted**, collapsing DNS to one shape consistent with HTTP/TLS.

**Breakage:** none for the trait (defaulted method, per `INDEX.md`'s
"trait-method overrides for diagnostics" convention). Removing
`DnsUdpObserver` is breaking — but it deletes an inconsistency.

### F6 — Driver naming and return-type inconsistency 🟡

Lower priority, but noted for completeness:

- `FlowDriver` (callback/reassembler), `FlowSessionDriver` (typed
  TCP), `FlowDatagramDriver` (typed UDP). The names don't telegraph
  "callback vs typed-stream." `FlowDriver` reads like the base case
  when it is actually the callback-factory case.
- `FlowDriver::track` returns `FlowEvents<K>`; `FlowSessionDriver::
  track` returns plain `Vec<SessionEvent<…>>`. Same conceptual
  return, two types.

**Proposed fix:** out of scope for a first pass — fold into the F1
plan only if a rename is cheap. If renamed, `FlowDriver` →
`FlowCallbackDriver` would make the trio self-describing
(`Callback` / `Session` / `Datagram`). Flag for discussion; don't
block F1–F5 on it.

---

## 5. Plan-of-record (shipped)

The six findings shipped as the plans below — F5 split into two, the
trait capability (36) and its DNS consumer (37). The plan files have
been deleted per the repo convention (shipped plans → removed; `git
log` and `CHANGELOG.md` are the durable record).

| Plan | Finding | Change | Breaking? | Commit |
|------|---------|--------|-----------|--------|
| 32 | F1 | Remove `S` from drivers; parser-by-value constructors | yes | `plan 32-34` |
| 33 | F3 | `finish()` on all drivers; public `Timestamp::MAX` | no | `plan 32-34` |
| 34 | F4 | `track` takes `impl Into<PacketView>` | minor | `plan 32-34` |
| 35 | F2 | `PcapFlowSource::sessions` / `datagrams` iterators | no | `plan 35` |
| 36 | F5 | `ts` param + `on_tick` on the parser traits | yes | `plan 36` |
| 37 | F5 | Fold correlation into `DnsUdpParser`; drop `DnsUdpObserver` | yes | `plan 37` |

**Acceptance bar** (met): all 5 examples lost every generic-parameter
annotation and the `86_400` hack, and an offline L7 program is a
single iterator expression — matching the README quick-start's bar
for the `FlowEvent` path.

---

## 6. Breakage summary & migration

Per `INDEX.md` the pre-1.0 policy permits this; consumers update in
lockstep and the CHANGELOG carries recipes.

| Break | Who is affected | Migration |
|-------|-----------------|-----------|
| Drivers lose `S` param | code naming `FlowDriver<_,_,()>` etc.; `netring` adapters | drop the `()`; for per-flow state use `FlowTracker` directly |
| `FlowSessionDriver`/`Datagram` ctor gains a value arg | direct constructors | pass `Parser::default()` instead of turbofish |
| `track` arg type → `impl Into<PacketView>` | none expected | reflexive `Into`; existing calls still compile |
| `DnsUdpObserver` removed | DNS-correlation users | switch to the correlating `DnsUdpParser` + `on_tick` |

`netring` re-export checklist (per CLAUDE.md "Relationship to
netring"): verify `netring::flow::*` re-exports after F1 (driver type
arity) and F5 (DNS surface). The `SessionParser`/`DatagramParser`
trait gaining `on_tick` needs no netring change — defaulted.

---

## 7. Appendix — peer-crate comparison

| Crate | Hello-world | flowscope vs. it |
|-------|-------------|------------------|
| `etherparse` | `SlicedPacket::from_ethernet(&buf)?` — one call | flowscope matches this for `FlowEvent`+pcap; loses it at L7 (F2) |
| `netflow_parser` | `parser.parse_bytes(&buf)` — stateful, hidden | flowscope hides state well; but `S` leaks into *types* (F1) |
| `tls-parser` | returns `IResult` / `Err::Incomplete` — user owns resync | flowscope is **better**: parsers own the resync loop |
| `pcap-parser` | manual `consume`/`refill` "iterator" | flowscope is **better**: real `Iterator` |
| `pcap-analyzer` (PAL) | `Plugin` trait, `get_results()->Box<dyn Any>` | flowscope is **better**: typed `Message` assoc-type |
| `pcap` | typestate `Capture<Inactive>`→`Active` | comparable; flowscope's builder-on-setup is fine |

Conclusion: flowscope's *trait* design is at or above the best in the
domain. The gap is entirely in the *constructor and convenience
layer* — which is exactly what F1–F5 address.
