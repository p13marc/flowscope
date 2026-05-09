# Plan 25 — Length-prefixed binary protocol example + sync session driver

## Summary

Two coupled deliverables:

1. **`FlowSessionDriver<E, P, S>`** — a small sync helper that
   bundles `FlowTracker` + `BufferedReassembler` + per-flow
   `SessionParser`. It is the offline / no-tokio mirror of netring's
   async `session_stream`. ~80 LOC of new public API in `src/driver.rs`.
2. **`examples/length_prefixed_pcap.rs`** — a documentation-grade
   example of a custom `SessionParser` for a length-prefixed binary
   protocol (PSMSG-shaped), driven by `FlowSessionDriver` against a
   pcap fixture. The example is ~50 LOC end-to-end.

The example shows the three things you can't currently learn from
the four shipped parsers (HTTP/TLS/DNS-UDP/DNS-TCP) — they all use
external crates (`httparse`, `tls-parser`, `simple-dns`) and don't
illustrate the "I have my own wire format" path:

1. How to handle a marker that varies in length (PSMSG vs PSMSG4 →
   different header sizes).
2. How to recover from a partially-arrived header (don't consume from
   the buffer until the full header *and* body are present).
3. How to wire the same `SessionParser` into both the **sync**
   offline path (`PcapFlowSource` + `FlowSessionDriver`) and the
   **async** live path (`netring::AsyncCapture::flow_stream().session_stream()`).

This is the W5 wishlist item from
`/home/mpardo/git/des-rs/des-discovery/reports/des-capture-rewrite-analysis-2026-05-09.md`.

### Why not just an example?

The original draft of this plan shipped only the example, with the
pcap-driver wiring inlined. It was ~50 LOC of nested-match
boilerplate that demonstrated honestly how verbose flowscope's sync
side is — but exactly that ugliness is what the netring async
adapters were designed to hide.

Every offline pcap user needs the same wiring; writing it once in
the library beats every consumer reinventing it. The
`FlowSessionDriver` is small (~80 LOC), parallels the existing
`FlowDriver`, and makes the example trivial. **We commit to that
shape.**

## Status

Not started.

## Prerequisites

- Plan 31 (SessionParser) — shipped.
- `pcap` feature module — shipped.

## Out of scope

- Pulling DES specifics into flowscope's public surface. The example
  uses a *PSMSG-shaped* protocol, intentionally generic — it does not
  import or know about `des_parser` / `des_writer` / etc.
- A generic `BinaryProtocolParser<F>` helper. The point is to teach
  the pattern, not to add API surface. Defer.
- A live-capture example using netring. The flowscope example must
  compile without a tokio runtime. We add a *pointer* comment at the
  top of the example showing the equivalent netring-based wiring in
  five lines.
- Extending `FlowSessionDriver` to manage `DatagramParser` instances
  (those don't need reassembly; users can pair `FlowDriver` with
  per-flow datagram parsers directly). If demand surfaces, add a
  `FlowDatagramDriver` later.

---

## Files

### NEW

- `src/session_driver.rs` — `FlowSessionDriver<E, P, S>`.
- `examples/length_prefixed_pcap.rs` — sync, offline, reads a pcap
  fixture and prints decoded records.
- `tests/fixtures/length_prefixed/sample.pcap` — small pcap with a
  synthetic length-prefixed exchange. ~10 records, ~5 KB.
- `tests/fixtures/length_prefixed/README.md` — describes how the
  fixture was generated, the wire format used, and the regen command.
- `tests/fixtures/length_prefixed/generate.rs` — one-shot generator
  script (compiled as `examples/generate_length_prefixed_pcap.rs` so
  it picks up workspace deps; not a runtime tool).
- `tests/length_prefixed_example.rs` — integration test running the
  example's parser against the fixture.

### MODIFIED

- `src/lib.rs` — re-export `FlowSessionDriver`.
- `Cargo.toml` — `[[example]] name = "length_prefixed_pcap"
  required-features = ["pcap"]` and the matching generator entry.
- `README.md` — one-line pointer under "Custom protocols".
- `docs/SESSION_GUIDE.md` — link from the "Custom protocol via
  `SessionParser`" section to the new example as the worked
  reference. Add a "Sync vs async session driving" subsection
  comparing `FlowSessionDriver` and `session_stream`.
- `CHANGELOG.md` — additive entry in the next minor release.

---

## API — `FlowSessionDriver`

```rust
//! Sync companion to netring's async `session_stream`. Owns a
//! `FlowTracker`, one `BufferedReassembler` per (flow, side), and one
//! `SessionParser` per flow. Drives them in lockstep, yielding
//! `SessionEvent<P::Message, K>` per packet.

use crate::{
    BufferedReassembler, BufferedReassemblerFactory, FlowEvent, FlowExtractor,
    FlowSide, FlowTracker, FlowTrackerConfig, PacketView, SessionEvent,
    SessionParser, Timestamp,
};
use std::collections::HashMap;
use std::hash::Hash;

pub struct FlowSessionDriver<E, P, S = ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Default + Send + 'static,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    reassemblers: HashMap<(E::Key, FlowSide), BufferedReassembler>,
    parsers: HashMap<E::Key, P>,
    factory: BufferedReassemblerFactory,
}

impl<E, P, S> FlowSessionDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: SessionParser + Default + Send + 'static,
    S: Default + Send + 'static,
{
    pub fn new(extractor: E) -> Self {
        Self::with_config(extractor, FlowTrackerConfig::default())
    }

    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self {
        let factory = match config.max_reassembler_buffer {
            Some(cap) => BufferedReassemblerFactory::default()
                .with_max_buffer(cap)
                .with_overflow_policy(config.overflow_policy),
            None => BufferedReassemblerFactory::default(),
        };
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            reassemblers: HashMap::new(),
            parsers: HashMap::new(),
            factory,
        }
    }

    /// Drive one packet, yielding zero or more `SessionEvent`s.
    pub fn track(&mut self, view: PacketView<'_>)
        -> Vec<SessionEvent<P::Message, E::Key>>
    {
        let mut out = Vec::new();
        let events = self.tracker.track_with_payload(view, |key, side, _seq, payload| {
            self.reassemblers
                .entry((key.clone(), side))
                .or_insert_with(|| self.factory.new_reassembler(key, side))
                .segment(/* seq from outer */ 0, payload);
        });
        // Drain bytes from each side's reassembler into the per-flow parser.
        for ev in &events {
            let key = match ev.key() { Some(k) => k.clone(), None => continue };
            // (wiring described in the implementation steps below)
            // ...
        }
        out.extend(events.into_iter().map(SessionEvent::from));
        out
    }

    /// Run a sweep at `now` (idle-timeout enforcement), yielding any
    /// resulting `Closed` events.
    pub fn sweep(&mut self, now: Timestamp)
        -> Vec<SessionEvent<P::Message, E::Key>>
    {
        // Same patch loop as track(): drain remaining bytes, finalize
        // parsers, emit Closed events.
        unimplemented!()
    }

    pub fn tracker(&self) -> &FlowTracker<E, S> { &self.tracker }
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> { &mut self.tracker }
}
```

> The above sketch elides the per-event drain loop; the implementation
> mirrors the existing `FlowDriver::track` pattern (re-use that code).
> The factory honours `FlowTrackerConfig::max_reassembler_buffer` /
> `overflow_policy` introduced by Plan 42.

### Anomaly emission

When Plan 42 lands, `FlowSessionDriver` accepts the same
`with_emit_anomalies(bool)` toggle and surfaces `SessionEvent::Anomaly`
parallel to `FlowEvent::Anomaly`. Cross-reference Plan 42 §3 for the
vocabulary.

---

## API — example

```rust
//! Length-prefixed binary protocol — minimal SessionParser example.
//!
//! Wire format (synthetic, modelled after DES PSMSG):
//!
//!   ┌────────┬──────────┬─────────────────────┐
//!   │ marker │ length   │ body                │
//!   │ "PFXn," │ u16/u32  │ body_len bytes      │
//!   └────────┴──────────┴─────────────────────┘
//!
//! Two markers:
//!   - `PFX2,` → 2-byte u16 length follows. 7-byte header total.
//!   - `PFX4,` → 4-byte u32 length follows. 9-byte header total.
//!
//! For the live, async, netring-backed equivalent of the wiring at
//! the bottom of this file:
//!
//!     use netring::AsyncCapture;
//!     let mut events = AsyncCapture::open("eth0")?
//!         .flow_stream(FiveTuple::bidirectional())
//!         .session_stream(LengthPrefixedParser::default());
//!     while let Some(ev) = events.next().await { /* ... */ }

use bytes::Bytes;
use flowscope::extract::FiveTuple;
use flowscope::pcap::PcapFlowSource;
use flowscope::{
    FlowSessionDriver, FlowSide, SessionEvent, SessionParser,
};
use std::env;

const MARKER_2: &[u8] = b"PFX2,";
const MARKER_4: &[u8] = b"PFX4,";
const HDR_LEN_2: usize = MARKER_2.len() + 2;  // 7
const HDR_LEN_4: usize = MARKER_4.len() + 4;  // 9

#[derive(Debug, Clone)]
pub struct Record {
    pub side: FlowSide,
    pub body: Bytes,
}

#[derive(Default, Clone)]
pub struct LengthPrefixedParser {
    init_buf: Vec<u8>,
    resp_buf: Vec<u8>,
}

impl SessionParser for LengthPrefixedParser {
    type Message = Record;

    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Record> {
        Self::drain(&mut self.init_buf, bytes, FlowSide::Initiator)
    }
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Record> {
        Self::drain(&mut self.resp_buf, bytes, FlowSide::Responder)
    }
}

impl LengthPrefixedParser {
    fn drain(buf: &mut Vec<u8>, incoming: &[u8], side: FlowSide) -> Vec<Record> {
        buf.extend_from_slice(incoming);
        let mut out = Vec::new();
        while let Some((hdr, body_len)) = peek_header(buf) {
            let total = hdr + body_len;
            if buf.len() < total { break; }
            let body = Bytes::copy_from_slice(&buf[hdr..total]);
            buf.drain(..total);
            out.push(Record { side, body });
        }
        out
    }
}

fn peek_header(buf: &[u8]) -> Option<(usize, usize)> {
    if buf.len() < HDR_LEN_2 { return None; }
    if buf.starts_with(MARKER_4) {
        if buf.len() < HDR_LEN_4 { return None; }
        let len = u32::from_be_bytes(buf[MARKER_4.len()..HDR_LEN_4].try_into().unwrap()) as usize;
        return Some((HDR_LEN_4, len));
    }
    if buf.starts_with(MARKER_2) {
        let len = u16::from_be_bytes(buf[MARKER_2.len()..HDR_LEN_2].try_into().unwrap()) as usize;
        return Some((HDR_LEN_2, len));
    }
    None
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = env::args().nth(1).ok_or("usage: length_prefixed_pcap <trace.pcap>")?;
    let mut driver = FlowSessionDriver::<_, LengthPrefixedParser>::new(
        FiveTuple::bidirectional(),
    );
    for view in PcapFlowSource::open(&path)?.views() {
        for ev in driver.track(view?.as_view()) {
            match ev {
                SessionEvent::Message { side, message, .. } => {
                    let arrow = if side == FlowSide::Initiator { "→" } else { "←" };
                    println!("{arrow} {:?} ({} bytes)", message, message.body.len());
                }
                SessionEvent::Closed { .. } => {}
                _ => {}
            }
        }
    }
    Ok(())
}
```

---

## Implementation steps

1. **Land `FlowSessionDriver`** in `src/session_driver.rs` (or
   alongside `FlowDriver` in `src/driver.rs` if shape allows reuse).
   Mirror `FlowDriver`'s structure — most of the per-event drain
   loop is shared.
2. **Re-export** from `src/lib.rs`.
3. **Generate the pcap fixture** at
   `tests/fixtures/length_prefixed/sample.pcap` via a
   `pcap-file`-based generator (compiled as
   `examples/generate_length_prefixed_pcap.rs`):
   - Synthesize an IPv4 + TCP exchange between 10.0.0.1:1234 ↔
     10.0.0.2:5678 with several `PFX2,` frames each direction and
     one `PFX4,` frame on the responder side.
   - Total ~10 messages, ~5 KB pcap.
4. **Document** the fixture in `tests/fixtures/length_prefixed/README.md`.
5. **Write `examples/length_prefixed_pcap.rs`** as above. Keep it
   under ~80 LOC.
6. **Integration test** at `tests/length_prefixed_example.rs`:
   - Run the parser against the fixture.
   - Assert exact record count, sides, and body lengths.
   - Run the same parser against a *byte-by-byte sliced* version of
     the same wire bytes (split each frame across two `feed_*` calls)
     and assert identical results — proves partial-header / partial-body
     buffering.
7. **`Cargo.toml`** entries with `required-features = ["pcap"]`.
8. **Cross-link** from `docs/SESSION_GUIDE.md` ("Custom protocol via
   `SessionParser`") to the new example. Add the "Sync vs async
   session driving" subsection.
9. **README**: short pointer in the "Examples" section.
10. **CHANGELOG**: doc + new public API additions.

---

## Tests

### `tests/length_prefixed_example.rs`

```rust
#[test]
fn parses_pcap_fixture() {
    let mut driver = FlowSessionDriver::<_, LengthPrefixedParser>::new(
        FiveTuple::bidirectional(),
    );
    let records: Vec<_> = collect_messages(&mut driver, FIXTURE_PATH);
    assert_eq!(records.len(), 10);
    let init = records.iter().filter(|r| r.side == FlowSide::Initiator).count();
    let resp = records.iter().filter(|r| r.side == FlowSide::Responder).count();
    assert_eq!((init, resp), (5, 5));
}

#[test]
fn handles_split_headers_and_bodies() {
    // Feed the same wire bytes from the fixture but in 1-byte chunks.
    // Confirm same N records emerge — direct test of LengthPrefixedParser,
    // bypassing the pcap layer.
}

#[test]
fn ignores_unknown_marker() {
    // Feed garbage prefix + valid frame.
    // Document the expected behaviour: parser stalls (peek_header returns None).
    // If we add resync logic later this test gets updated.
}
```

### Doctest in the example

The example is itself the doctest — `cargo test --example
length_prefixed_pcap` runs it.

### Existing test surface

- `cargo test --features pcap` continues to pass.
- `cargo build --example length_prefixed_pcap --features pcap` succeeds.

---

## Acceptance criteria

- [ ] `FlowSessionDriver<E, P, S>` lives in `src/session_driver.rs`,
      re-exported from the crate root.
- [ ] `examples/length_prefixed_pcap.rs` exists and compiles under
      `--features pcap`. Under ~80 LOC.
- [ ] Fixture pcap + generator script committed.
- [ ] Integration test passes; covers partial-header / partial-body
      handling on byte-sliced input.
- [ ] SESSION_GUIDE.md cross-links to the new example and the new
      "Sync vs async session driving" subsection.
- [ ] README.md mentions the example.
- [ ] CHANGELOG entry covering the new helper + example.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **`FlowSessionDriver` vs `FlowDriver` overlap.** `FlowSessionDriver`
   composes `FlowDriver` internally rather than duplicating its
   logic — same factory, same per-event drain pattern, with the
   additional per-flow `SessionParser` instance. Code duplication
   should be minimal.
2. **Per-flow parser lifetime.** Parsers are dropped on
   `EndReason::*`. If users want post-end statistics they should
   capture them in their `SessionParser::Message` type or pull from
   `FlowStats`.
3. **Marker collision.** `PFX2,` / `PFX4,` chosen because they're
   non-printable-prefix-free and distinct from common wire protocols.
   Documented; fixture deliberately uses ports outside the well-known
   range.
4. **Fixture regeneration drift.** If `pcap-file` changes on-disk
   format, the fixture might need re-generating. Mitigation: ship
   the generator; document the regen command in the fixture README.
5. **Plan 42 coupling.** `FlowSessionDriver` should pick up Plan 42's
   buffer-cap / overflow-policy fields automatically when the user
   configures them on `FlowTrackerConfig`. If Plan 42 ships first,
   wire it in directly; if Plan 25 ships first, leave the factory
   unconfigured and add the wiring in 42.

---

## Effort

- LOC: ~80 (`FlowSessionDriver`) + ~80 (example) + ~150 (tests +
  fixture generator) + ~5 KB pcap + ~30 lines docs.
- Time: 1.5 days (½ day driver + ½ day fixture & generator + ½ day
  example/tests/docs).
