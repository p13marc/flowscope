# Plan 53 — SessionParser author guide

## Summary

Add a "Writing your own `SessionParser`" walkthrough section to
`docs/SESSION_GUIDE.md` documenting the trait contract explicitly:
chunk-size invariants, `fin_*` / `rst_*` semantics, resync after
`bytes_dropped_oversize > 0`, and the canonical pattern for
length-prefixed binary protocols.

Doc-only. Anchors the existing `examples/length_prefixed_pcap.rs`
example into a discoverable home in the guide.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 25 §2 — `examples/length_prefixed_pcap.rs` shipped in 0.2.0.
- Plan 42 §2 — `OverflowPolicy` and `bytes_dropped_oversize`
  documentation already in SESSION_GUIDE.

## Out of scope

- New code. This plan is doc-only.
- Adding `SessionParser` trait methods. The contract is
  documented better, not changed.
- Rewriting any of the four shipped parsers. They're already in
  the codebase as worked examples; the guide just links to them
  better.

---

## Files

### MODIFIED

- `docs/SESSION_GUIDE.md` — add a new "Writing your own
  `SessionParser`" subsection between "Custom protocol via
  `SessionParser`" and "Sync vs async session driving".

### NEW

None.

---

## Content outline

The new subsection covers:

### Trait contract

For each method, what the driver guarantees and what the parser
must do:

| Method | Driver guarantees | Parser responsibilities |
|--------|-------------------|--------------------------|
| `feed_initiator(&mut self, bytes: &[u8])` | Called per-packet with the bytes that arrived on this side since the last call. `bytes` may be 1..N bytes — no minimum size. Calls are serialised; never concurrent. | Buffer partial frames internally. Return only fully-decoded messages. Do not assume `bytes` is aligned to a frame boundary. |
| `feed_responder(&mut self, bytes: &[u8])` | Mirror of initiator. | Same. |
| `fin_initiator(&mut self) -> Vec<Self::Message>` | Called once when the initiator-side stream closes cleanly (FIN observed). | Flush any in-flight buffered state that can still be decoded; return decoded messages. Drop partial frames. Default is no-op. |
| `fin_responder(&mut self) -> Vec<Self::Message>` | Mirror. | Same. |
| `rst_initiator(&mut self)` | Called once when the flow is reset abruptly (RST, eviction, or `OverflowPolicy::DropFlow` synthesis). No further calls for this side. | Drop in-flight buffer state; do not flush. Default is no-op. |
| `rst_responder(&mut self)` | Mirror. | Same. |

### Partial-frame buffering

Show the canonical pattern:

```rust
#[derive(Default, Clone)]
struct MyParser { init_buf: Vec<u8>, resp_buf: Vec<u8> }

impl SessionParser for MyParser {
    type Message = MyMessage;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.init_buf.extend_from_slice(bytes);
        drain(&mut self.init_buf, FlowSide::Initiator)
    }
    // mirror for feed_responder
}

fn drain(buf: &mut Vec<u8>, side: FlowSide) -> Vec<MyMessage> {
    let mut out = Vec::new();
    while let Some(consumed) = try_decode_one(buf, side) {
        out.push(consumed);
    }
    out
}
```

Key rules:
- **Don't drain the buffer until a complete message is in.**
  Decode-and-consume is atomic per message; the next call sees the
  rest.
- **Per-side buffers are independent.** A partial frame on
  initiator does not block responder progress.

### Resync after `bytes_dropped_oversize > 0`

Reference [SESSION_GUIDE §Recovery after buffer cap](./SESSION_GUIDE.md#recovery-after-buffer-cap):
when a parser detects (via `FlowStats` on `Ended`, or live via
`FlowEvent::Anomaly`) that bytes were dropped, it must resync.
Three strategies, ordered by parser-side cost:

1. **Use `OverflowPolicy::DropFlow`** (recommended for framed
   binary protocols). The driver synthesises `Ended { reason:
   BufferOverflow }` and tears the flow down. The parser never
   sees the corrupted continuation — fresh start on the next flow.
2. **Marker re-scan** for protocols with a fixed-length marker
   prefix (HTTP `\r\n\r\n`, your PSMSG-style marker). On detected
   gap, walk the buffer looking for the next marker, discard
   everything before it.
3. **Tear down at the parser layer**: keep state until the next
   `fin_*` / `rst_*`, but emit no messages. Caller observes a gap
   in the message stream.

### `fin_*` vs `rst_*` semantics

```text
  ┌────────────────────────────────┬─────────────────┐
  │ End reason                     │ Method invoked  │
  ├────────────────────────────────┼─────────────────┤
  │ EndReason::Fin                 │ fin_*           │
  │ EndReason::IdleTimeout         │ fin_*           │
  │ EndReason::Rst                 │ rst_*           │
  │ EndReason::Evicted             │ rst_*           │
  │ EndReason::BufferOverflow      │ rst_*           │
  └────────────────────────────────┴─────────────────┘
```

`fin_*` is the right place to flush a half-parsed message if your
protocol allows partial decode at EOF (HTTP/1.1 with `Connection:
close` for example). For most binary protocols, an incomplete
frame at FIN is just a truncated stream — drop the buffer.

### Length-prefixed binary protocols

Point at `examples/length_prefixed_pcap.rs` as the worked
reference. Summarise its three teachable points:

1. **Variable-length headers** (PFX2 vs PFX4 → 7- vs 9-byte
   prefix).
2. **Partial-header / partial-body buffering** (`peek_header`
   returns `None` until both header and body are fully present).
3. **Recovery policy**: the example stalls on unknown marker.
   Real parsers should pair with `OverflowPolicy::DropFlow` and
   document the resync strategy.

### Testing pattern

Show the byte-by-byte sliced test:

```rust
#[test]
fn handles_partial_chunks() {
    let wire_bytes: &[u8] = /* ... */;
    let mut parser = MyParser::default();
    let mut out = Vec::new();
    for byte in wire_bytes {
        out.extend(parser.feed_initiator(std::slice::from_ref(byte)));
    }
    assert_eq!(out, expected);
}
```

This catches the vast majority of partial-frame bugs without a
proptest harness. Recommended for every custom parser.

---

## Implementation steps

1. Read the current SESSION_GUIDE.md "Custom protocol via
   `SessionParser`" section. Don't rewrite it; the new subsection
   slots in after it.
2. Draft the subsection in this plan's "Content outline" structure.
3. Add internal anchors that the rest of the guide can link from
   (e.g., `#writing-your-own-sessionparser`).
4. Add a forward link from `examples/length_prefixed_pcap.rs`'s
   doc comment ("See SESSION_GUIDE for the trait-contract
   walkthrough").
5. No code changes.

---

## Tests

None — doc-only. The two existing pieces of test surface
(`tests/length_prefixed_example.rs` and `src/session_driver.rs`
unit tests) already exercise the patterns the guide documents.

Verify the doc itself with `cargo doc --all-features --no-deps`
(should remain zero warnings).

---

## Acceptance criteria

- [ ] New SESSION_GUIDE.md subsection exists, structured as
      described.
- [ ] Trait-method table is complete with driver guarantees +
      parser responsibilities for all six methods.
- [ ] `examples/length_prefixed_pcap.rs` doc comment links to the
      new section.
- [ ] `cargo doc --all-features --no-deps` zero warnings.
- [ ] CHANGELOG entry under 0.3.0 mentions the docs additions.

---

## Risks

1. **Guide drift over time.** Any change to the `SessionParser`
   trait contract (adding methods, changing semantics) must update
   this section. Mitigation: cross-reference from `src/session.rs`
   trait doc to the SESSION_GUIDE section so the connection is
   visible.
2. **Length-prefixed example doesn't cover all protocols.**
   Stream-shaped protocols (HTTP body streams) and frame-with-
   length-trailer protocols (NDR-encoded RPC) have different
   resync strategies. Document the example as one canonical
   pattern, not the only one. Pointer to the four shipped parsers
   for comparison.

---

## Effort

- LOC: ~150 lines of new prose in SESSION_GUIDE.md.
- Time: half a day.

---

## Provenance

Reported as item #9 in `flowscope-feedback-2026-05-14.md` (des-rs
team). The `examples/length_prefixed_pcap.rs` example they asked
for shipped in 0.2.0 ([Plan 25 §2](./25-binary-protocol-example.md))
— this plan closes the discoverability gap and documents the
trait contract that the example demonstrates.
