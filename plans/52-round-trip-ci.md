# Plan 52 — Cross-source round-trip CI fixture

## Summary

Add a CI test that exercises the full `synthesize bytes → pcap →
PcapFlowSource → FlowSessionDriver → assert bytes match`
pipeline. Catches regressions in the seam between flowscope's
pcap source, tracker, reassembler, and session driver — exactly
the integration class that downstream consumers like `des-rs`
have hit before (their `offline_pcap_regression.rs` is the
analogue in their repo).

~150 LOC, no new deps. Lives in flowscope's `tests/` so any PR
that touches the data path runs it.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 25 §1 (`FlowSessionDriver`) — shipped in 0.2.0.
- `pcap` feature module — shipped.
- `test-helpers` feature (`extract::parse::test_frames`) —
  available since the test-helpers feature was introduced.

## Out of scope

- A netring-side round-trip test. netring's `CaptureWriter` /
  pcap-writing path is netring's responsibility; the round-trip
  on the flowscope side uses `pcap-file` directly to synthesise
  the input. This means the test doesn't transitively pull in
  netring (correct — flowscope is netring's *upstream*).
- Round-trip across all four shipped parsers. One passthrough
  `SessionParser` is enough to validate the byte-equality
  invariant; testing HTTP/TLS/DNS message-level round-trip is
  covered by their respective parser tests.
- Performance benchmarks. The round-trip test is correctness-only.

---

## Files

### NEW

- `tests/round_trip.rs` — the integration test.

### MODIFIED

- `Cargo.toml` — `[[test]]` entry with required features
  `pcap, session, extractors, test-helpers`.
- `CHANGELOG.md` — 0.3.0 entry under "Testing".

---

## API

The test ships a tiny passthrough `SessionParser` that yields the
bytes it received unchanged:

```rust
#[derive(Default, Clone)]
struct PassthroughParser {
    init: Vec<u8>,
    resp: Vec<u8>,
}

impl SessionParser for PassthroughParser {
    type Message = (FlowSide, Vec<u8>);
    fn feed_initiator(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.init.extend_from_slice(bytes);
        vec![(FlowSide::Initiator, bytes.to_vec())]
    }
    fn feed_responder(&mut self, bytes: &[u8]) -> Vec<Self::Message> {
        self.resp.extend_from_slice(bytes);
        vec![(FlowSide::Responder, bytes.to_vec())]
    }
}
```

---

## Implementation steps

1. **Create `tests/round_trip.rs`** with the test scaffold:
   - `#![cfg(all(feature = "pcap", feature = "session", feature = "test-helpers"))]`
   - Use `tempfile::NamedTempFile` (already a workspace dev-dep
     candidate) OR an in-memory `Vec<u8>` wrapped in a `Cursor` to
     avoid touching disk. **Recommend in-memory** to keep the test
     fully deterministic + fast.
2. **Synthesise the wire bytes**. A canonical TCP session:
   - 3WHS (SYN, SYN-ACK, ACK)
   - Initiator payload: `b"GET /test HTTP/1.0\r\n\r\n"` plus a
     larger 1024-byte synthetic payload to exercise multi-segment
     reassembly.
   - Responder payload: `b"HTTP/1.0 200 OK\r\n\r\nbody"`.
   - FIN/FIN/ACK termination.
   - Use `flowscope::extract::parse::test_frames::ipv4_tcp` (the
     existing test-helper).
3. **Write to in-memory pcap**:
   ```rust
   let mut buf = Vec::new();
   {
       let mut w = pcap_file::pcap::PcapWriter::new(&mut buf).unwrap();
       for (ts, bytes) in &wire_bytes {
           w.write_packet(&PcapPacket {
               timestamp: *ts,
               orig_len: bytes.len() as u32,
               data: bytes.as_slice().into(),
           }).unwrap();
       }
   }
   ```
4. **Read back via `PcapFlowSource`**:
   ```rust
   let mut driver = FlowSessionDriver::<_, PassthroughParser>::new(
       FiveTuple::bidirectional(),
   );
   let mut init_bytes = Vec::new();
   let mut resp_bytes = Vec::new();
   let cursor = std::io::Cursor::new(buf);
   for view in PcapFlowSource::from_reader(cursor)?.views() {
       for ev in driver.track(view?.as_view()) {
           if let SessionEvent::Application { message: (side, b), .. } = ev {
               match side {
                   FlowSide::Initiator => init_bytes.extend_from_slice(&b),
                   FlowSide::Responder => resp_bytes.extend_from_slice(&b),
               }
           }
       }
   }
   ```
5. **Assert byte equality**. The bytes the parser saw must match
   the bytes synthesised on each side. This catches:
   - Pcap encoder/decoder skew.
   - Reassembler dropping or reordering bytes.
   - FlowSessionDriver missing a drain on Packet events.
   - FiveTuple canonicalization swapping init/resp inadvertently.
6. **Add a second test variant: chunked payloads**. Same wire
   bytes split across more, smaller TCP segments (5x100B instead
   of 1x500B). Verifies the reassembler concatenates in order.
7. **Add a third test variant: bidirectional interleaving**. Send
   init and resp data segments interleaved in time. Verifies the
   driver routes packets to the correct side regardless of arrival
   order.

---

## API additions needed (if any)

`PcapFlowSource::open` takes a path. For in-memory pcaps we need
either:

- **Add `PcapFlowSource::from_reader<R: Read>(r: R)`** — small
  API addition, well-justified for testing + any consumer who
  wants in-memory pcaps. Plumbs into the existing constructor.
  Recommended.
- Or use `tempfile` to write to disk first. Avoids API addition
  but ties the test to filesystem I/O. Marginally less clean.

**Recommendation: add `from_reader`** as part of this plan.
~5 LOC change in `src/pcap/source.rs`.

```rust
impl<R: std::io::Read + std::io::Seek> PcapFlowSource<R> {
    pub fn from_reader(reader: R) -> Result<Self, PcapError> {
        let pcap_reader = pcap_file::pcap::PcapReader::new(reader)?;
        Ok(Self { reader: pcap_reader })
    }
}
```

Verify the current `PcapFlowSource` struct signature supports this
generic — it appears to already be `PcapFlowSource<R>` where `R:
BufRead`, so this may be a one-line tweak.

---

## Tests

The test file itself IS the test deliverable. Structure:

```rust
// tests/round_trip.rs

#[test]
fn passthrough_single_segment_round_trip() {
    let init = b"GET /test HTTP/1.0\r\n\r\n";
    let resp = b"HTTP/1.0 200 OK\r\n\r\nbody";
    let (init_seen, resp_seen) = run_round_trip(&[(init.as_slice(), resp.as_slice())]);
    assert_eq!(init_seen, init);
    assert_eq!(resp_seen, resp);
}

#[test]
fn passthrough_chunked_round_trip() {
    let init = b"chunk1...chunk2...chunk3";
    let resp = b"response payload";
    // Split init into 5 segments of varying size, all in-order.
    let (init_seen, resp_seen) = run_round_trip_chunks(&[
        (b"chunk1...", b""),
        (b"chunk2...", b""),
        (b"chunk3", b"response "),
        (b"", b"payload"),
    ]);
    assert_eq!(init_seen, init);
    assert_eq!(resp_seen, resp);
}

#[test]
fn passthrough_interleaved_round_trip() {
    // Initiator and responder talk over the same window.
    let segments = &[
        (b"i1", b""),
        (b"", b"r1"),
        (b"i2", b""),
        (b"", b"r2"),
    ];
    let (init, resp) = run_round_trip_chunks(segments);
    assert_eq!(init, b"i1i2");
    assert_eq!(resp, b"r1r2");
}
```

### Proptest variant

Beyond the three hand-written variants above, add a proptest that
generates random bidirectional TCP sessions and round-trips them.
This catches edge cases the hand-written tests miss (single-byte
segments, payload sizes near MTU boundaries, wrap-around-near
sequence-number corner cases).

```rust
use proptest::prelude::*;

proptest! {
    #[test]
    fn passthrough_random_bidirectional_session(
        init_chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..1500), 0..16),
        resp_chunks in proptest::collection::vec(proptest::collection::vec(any::<u8>(), 0..1500), 0..16),
    ) {
        let mut interleaved: Vec<(&[u8], &[u8])> = Vec::new();
        for i in 0..init_chunks.len().max(resp_chunks.len()) {
            let init = init_chunks.get(i).map(Vec::as_slice).unwrap_or(b"");
            let resp = resp_chunks.get(i).map(Vec::as_slice).unwrap_or(b"");
            interleaved.push((init, resp));
        }
        let (init_seen, resp_seen) = run_round_trip_chunks(&interleaved);
        let init_expected: Vec<u8> = init_chunks.iter().flatten().copied().collect();
        let resp_expected: Vec<u8> = resp_chunks.iter().flatten().copied().collect();
        prop_assert_eq!(init_seen, init_expected);
        prop_assert_eq!(resp_seen, resp_expected);
    }
}
```

Add `proptest = "1"` to the `dev-dependencies` if not already
present (it is — used elsewhere in the test suite). Cap iterations
at the proptest default (256) so CI time stays bounded; bump to
`PROPTEST_CASES=10000` for stress runs.

---

## Acceptance criteria

- [ ] `tests/round_trip.rs` exists with at least three hand-written
      variants (single-segment, chunked, interleaved) plus one
      proptest variant for random bidirectional sessions.
- [ ] All variants pass on a clean checkout.
- [ ] `PcapFlowSource::from_reader<R: Read + Seek>` added if not
      already present.
- [ ] Test runs in <100 ms (in-memory; no disk I/O).
- [ ] CHANGELOG entry under 0.3.0 "Testing".
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **`pcap-file` API for in-memory writing.** Need to verify
   `PcapWriter::new(&mut Vec<u8>)` works (it requires `Write`,
   which `&mut Vec<u8>` satisfies). If the BufWriter wrapping in
   the current constructor is mandatory, wrap accordingly.
2. **Timestamp alignment**. Timestamps in the synthesised pcap
   must avoid the `last_seen.saturating_sub(now)` edge case in
   the tracker's idle-sweep. Use monotonically increasing
   timestamps starting at `Duration::from_secs(1)` (avoid 0 so
   `saturating_sub` doesn't underflow comparisons elsewhere).
3. **FiveTuple canonicalization drift**. The test pins the
   canonicalisation behaviour (key.a ≤ key.b) by asserting that
   bytes sent from the "first-seen orientation" land in `init_seen`
   regardless of which IP/port pair started the flow. Document
   this expectation in a code comment.

---

## Effort

- LOC: ~200 (test scaffold + 3 hand-written variants + proptest +
  shared helper).
- Time: half a day.

---

## Provenance

Reported as item #10 in `flowscope-feedback-2026-05-14.md`
(des-rs team). They run an analogous regression test in their
own repo (`offline_pcap_regression.rs`) and asked for one in
flowscope's CI so seam-breakage is caught upstream.

The test would have caught the src/dst-canonicalisation drift
they hit in their commit `77ad744`. Worth the half-day to
prevent the equivalent regression here.
