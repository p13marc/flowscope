# Plan 73 — Rich-state pattern in SESSION_GUIDE

## Summary

`simple-nms` wishlist F1.4 asks for `&mut S` (per-flow user
state) to be plumbed into `SessionParser::feed_*`. The trait
change would ripple through every shipped parser and every
consumer of `SessionParserFactory`. The wishlist itself notes
the alternative: drive per-flow state updates from the
consumer's event loop after `track()` using the existing
`FlowTracker::get_mut(&key)` accessor.

**This plan declines the API change** and ships the alternative
as a documented pattern in `SESSION_GUIDE.md`. Doc-only — no
code changes.

## Status

Not started. Targets 0.5.0.

## Prerequisites

- `FlowTracker::get_mut(&E::Key) -> Option<&mut FlowEntry<S>>`
  already exists. `FlowEntry::user` is `pub`. The pattern
  works on current code; the gap is purely documentation.
- Plan 36 (time-aware parsers) — shipped in 0.4.0. The `ts:
  Timestamp` parameter on `feed_*` is part of the canonical
  pattern.

## Out of scope

- Adding `S` as a generic parameter to `SessionParser` /
  `DatagramParser`. This is the explicit non-decision; if a
  future second consumer asks AND has a use case the
  consumer-loop pattern can't address, we revisit.
- A "state-aware parser" trait alongside the existing one.
  Adds API surface for a single consumer; deferred until at
  least two consumers ask.
- Built-in helper types for common patterns. Users wire their
  own state structs; the pattern is straightforward enough
  not to need framework support.

---

## Files

### MODIFIED

- `docs/SESSION_GUIDE.md` — new "Updating per-flow state from
  parser messages" subsection between "Writing your own
  SessionParser" and "Sync vs async session driving".
- `CHANGELOG.md` — 0.5.0 entry under "Docs" mentioning the
  new walkthrough.

### NEW

None.

---

## Content outline

The new SESSION_GUIDE subsection covers:

### When to reach for this pattern

If your application maintains rich per-flow state (TCP rich
stats, connection-level counters, middleware state machines)
that gets updated by BOTH the reassembler (TCP-layer signals)
and the L7 parser (application-layer signals), you have a
state-consolidation problem: where does the state live, and
who writes it?

flowscope's answer: the state lives on `FlowEntry::user`, and
the **consumer's event loop** writes it. The parser produces
messages; the consumer's loop turns messages into state
updates.

### The canonical pattern

```rust
use flowscope::{FlowSessionDriver, FlowSide, SessionEvent};
use flowscope::extract::FiveTuple;

// 1. Define your per-flow state.
#[derive(Default)]
struct RichFlowState {
    init_messages: u64,
    resp_messages: u64,
    last_message_at: Option<flowscope::Timestamp>,
}

// 2. Wire the driver with `S = RichFlowState`.
let mut driver = FlowSessionDriver::<_, MyParser, RichFlowState>::new(
    FiveTuple::bidirectional(),
);

// 3. After each `track()`, walk the events and update state.
for view in source.views() {
    for ev in driver.track(view?) {
        match ev {
            SessionEvent::Application { key, side, message, ts, .. } => {
                if let Some(entry) = driver.tracker_mut().get_mut(&key) {
                    let s = &mut entry.user;
                    match side {
                        FlowSide::Initiator => s.init_messages += 1,
                        FlowSide::Responder => s.resp_messages += 1,
                    }
                    s.last_message_at = Some(ts);
                    consume_message(message);
                }
            }
            SessionEvent::Closed { key, stats, .. } => {
                if let Some(entry) = driver.tracker().get(&key) {
                    publish_rich_summary(&key, stats, &entry.user);
                }
            }
            _ => {}
        }
    }
}
```

### Why this works

- **No second `HashMap` in the consumer.** State lives on
  `FlowEntry` next to the standard `FlowStats`; tracker LRU
  eviction cleans both up together.
- **No trait change.** `SessionParser` stays minimal —
  message production is decoupled from state mutation.
- **Reassembler-side updates use the same pattern.** A custom
  `Reassembler` can hold a `Weak`-style handle to the tracker,
  or the consumer's event loop reads
  `reassembler.dropped_segments()` after `track()` and writes
  the delta into `entry.user`.

### Trade-offs vs the "parser holds state" pattern

| Concern | Consumer-loop pattern (this) | Parser-holds-state pattern |
|---------|-----------------------------|-----------------------------|
| Where state lives | `FlowEntry::user` (one source) | Per-parser HashMap (a second source) |
| Eviction | LRU drops together | Manual cleanup on parser `rst_*` |
| Thread safety | Single mut accessor through tracker | Parser manages |
| Looks like | Imperative event-handler | Encapsulated parser |

For the common case (one consumer, one parser-per-protocol,
state updated by both reassembler and parser),
consumer-loop wins on simplicity.

### When the parser DOES need state on every byte

For state that genuinely tracks at the parsing-step level —
e.g. HPACK decoder state in an HTTP/2 parser — that state
belongs inside the parser, owned by the parser. The
"per-flow rich state" pattern is for state that's *about* the
flow, not state that's *internal* to parsing.

### Pointer to the worked reference

A complete example is at
[`examples/length_prefixed_pcap.rs`](../examples/length_prefixed_pcap.rs)
— see how the example uses `S = ()` because the parser produces
self-contained messages. For a rich-state version, replace `S
= ()` with your state type and add the consumer-loop block
above.

---

## Implementation steps

1. Read the existing "Writing your own SessionParser"
   subsection in SESSION_GUIDE.md (Plan 53). Don't duplicate;
   the new subsection slots after it.
2. Draft the subsection in this plan's "Content outline"
   structure.
3. Cross-link from `src/session.rs`'s `SessionParser` rustdoc
   to the new SESSION_GUIDE anchor.
4. Cross-link from
   `docs/feedback-2026-08-11-simple-nms.md` (the upstream
   wishlist document) to this subsection so future readers
   asking about F1.4 land on the answer.
5. CHANGELOG entry under 0.5.0 "Docs" section.

No code changes.

---

## Tests

None — doc-only. The pattern uses APIs already exercised by
existing tests (`FlowTracker::get_mut`, `FlowEntry::user`,
`SessionEvent::Application` consumption). If we ever want a
proof-of-life test for the doc pattern itself, add a
`tests/rich_state_pattern.rs` that compiles the example code
verbatim. Skip for now — the in-line code block carries
enough signal.

Verify the doc itself with `cargo doc --all-features
--no-deps` (should stay zero warnings).

---

## Acceptance criteria

- [ ] New SESSION_GUIDE.md "Updating per-flow state from
      parser messages" subsection exists, structured as
      outlined.
- [ ] Cross-links from `src/session.rs` `SessionParser`
      rustdoc and from `docs/feedback-2026-08-11-simple-nms.md`
      to the new section.
- [ ] CHANGELOG entry under 0.5.0 "Docs" mentions the
      walkthrough.
- [ ] `cargo doc --all-features --no-deps` zero warnings.

---

## Risks

1. **Documentation drift.** The pattern relies on
   `FlowEntry::user` being `pub`. If a future refactor seals
   the field, the doc breaks. Mitigation: the
   `SESSION_GUIDE.md` section explicitly cites the API surface
   (`tracker.get_mut(&key).map(|e| &mut e.user)`); any
   refactor that changes the surface is a clear signal to
   update the doc.
2. **Pattern doesn't address EVERY use case the wishlist
   identified.** F1.4 specifically mentioned middleware
   parsers that wanted `&mut S` inside `feed_initiator` so the
   parser could route on state. The consumer-loop pattern
   doesn't help there — the parser still doesn't see state
   during parsing. If `simple-nms` comes back saying their
   middleware parser fundamentally needs state inside
   `feed_*`, we'll consider a `StateAwareSessionParser` trait
   as a follow-up. Today's pattern covers the majority case.
3. **"Just document it" feels weak.** It IS — documentation
   is doing the work that an API change would do. The
   trade-off is that one consumer (us) takes on the
   maintenance of the explanation rather than every consumer
   taking on the trait change. Pre-1.0 we should err on the
   side of fewer API axes.

---

## Effort

- LOC: ~150 lines of new prose in SESSION_GUIDE.md (about the
  same as Plan 53's "Writing your own SessionParser"
  subsection).
- Time: ½ day.

---

## Provenance

Counter-proposal to wishlist item F1.4 from
`docs/feedback-2026-08-11-simple-nms.md`. The wishlist
explicitly identifies the consumer-loop pattern as the
fallback ("Keep the second map. Acceptable cost, but the
duplicate-lookup pattern shows up in every middleware
parser.") — this plan promotes the fallback to the canonical
pattern by documenting it clearly.

Pre-1.0 we prefer documenting patterns over adding API axes
that solve one consumer's problem. If a SECOND consumer asks
for `&mut S` in `feed_*`, we revisit and consider a
`StateAwareSessionParser` trait. Today: doc-only.
