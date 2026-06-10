# Plan 142 — HTTP/2 passive observation + Akamai fingerprint

## Summary

Ship a passive HTTP/2 (RFC 9113) parser as `flowscope::http2`,
behind the new `http2` feature. Surfaces:

- Frame-level events for `SETTINGS`, `WINDOW_UPDATE`, `HEADERS`
  (+ `CONTINUATION`), `PRIORITY`, `RST_STREAM`, `GOAWAY`,
  `PUSH_PROMISE`.
- `Http2Request` / `Http2Response` typed messages after HPACK
  decode, including pseudo-headers (`:method` / `:scheme` /
  `:authority` / `:path` / `:status`) in observed order.
- **Akamai HTTP/2 fingerprint** — the de-facto bot-detection
  signal for the HTTP/2 layer (2017 paper, in use by Akamai
  Bot Manager, Cloudflare, GreyNoise).

HTTP/1.1 is becoming the minority of web traffic in 2026 (most
browsers + most CDN-fronted services speak HTTP/2 or QUIC).
Without HTTP/2, flowscope can't observe the bulk of modern web
traffic.

## Status

Not started.

## Prerequisites

- **Plan 130** (KeyFields trait) — Http2Request carries no
  new key dependency, but the EVE emit path lands cleaner with
  the trait split.
- **Plan 140** (JA4+ family) — JA4H is HTTP/1.1 only; the
  Akamai fingerprint complements it on the HTTP/2 side.

## Out of scope

- **HTTP/3 / QUIC.** Plan 145 covers QUIC Initial-packet
  observation; HTTP/3 over QUIC's encrypted-payload requires
  key extraction (impossible passively without session keys).
- **Active sending / endpoint role.** Pure passive parser.
- **Body decoding (gzip / br / zstd).** Surface raw frame
  bytes; decompression is consumer-side.
- **`SETTINGS` ACK enforcement.** We observe `SETTINGS_ACK`
  but don't track ACK / un-ACK'd states; that's an endpoint
  concern.
- **Server push validation.** `PUSH_PROMISE` frames are
  surfaced verbatim; we don't validate promised stream
  semantics.

## Pre-1.0 breaks

None for existing users. Additive — new feature, new module.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/http2/mod.rs` | Public API surface — `Http2Parser` (`SessionParser`), `Http2Message`, `Http2Frame`, `AkamaiHttp2Fingerprint` |
| New | `src/http2/parser.rs` | Frame parser state machine — preface + frame loop |
| New | `src/http2/hpack.rs` | HPACK encoder/decoder via `httlib-hpack` — per-direction dynamic tables |
| New | `src/http2/frames.rs` | Frame types: `SettingsFrame`, `WindowUpdateFrame`, `HeadersFrame`, `PriorityFrame`, `ContinuationFrame`, `GoAwayFrame`, `PushPromiseFrame`, `RstStreamFrame` |
| New | `src/http2/types.rs` | `Http2Request`, `Http2Response`, `Http2Settings`, pseudo-header tracking |
| New | `src/http2/akamai.rs` | Akamai HTTP/2 fingerprint computation |
| New | `src/http2/session.rs` | `Http2Parser` (`SessionParser`) — feeds frames + emits typed messages |
| Modify | `src/lib.rs` | `#[cfg(feature = "http2")] pub mod http2;` + re-exports |
| Modify | `src/detect/signatures.rs` | Add `http2_preface` signature (the 24-byte preface) for heuristic routing |
| Modify | `src/parser_kinds` | Add `HTTP2 = "http2"` constant |
| Modify | `Cargo.toml` | `http2 = ["reassembler", "session", "dep:httlib-hpack", "dep:bytes"]`; CI matrix entry |
| New | `tests/http2_parser.rs` | Frame-by-frame parse correctness |
| New | `tests/http2_akamai.rs` | Akamai fingerprint against known browser captures |
| New | `tests/fixtures/http2/` | Pcap fixtures: curl, chrome, firefox, go h2 client |
| New | `examples/01-l7-logging/http2_log.rs` | Pcap → per-message log |
| New | `examples/02-forensics/http2_fingerprint.rs` | Pcap → Akamai fingerprint per flow |
| New | `docs/http2-format.md` | Frame catalog + Akamai fingerprint format spec |
| Modify | `CHANGELOG.md` | 0.12 entry |

## API

### `Http2Parser` (SessionParser)

```rust
// src/http2/session.rs

use crate::{FlowSide, SessionParser, Timestamp};

/// Passive HTTP/2 parser (RFC 9113). One per flow; the driver
/// instantiates via `.clone()` per the SessionParser factory
/// blanket impl.
///
/// Routing: bind to port 443 + heuristic with the
/// `detect::signatures::http2_preface` signature (matches the
/// 24-byte connection preface `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).
///
/// State: per-direction HPACK dynamic table, per-stream HEADERS
/// accumulation (`HEADERS` + zero-or-more `CONTINUATION`),
/// connection-level + per-stream flow-control window state
/// (informational only), Akamai-fingerprint-input collector.
#[derive(Debug, Clone)]
pub struct Http2Parser {
    config: Http2Config,
    initiator: DirectionState,
    responder: DirectionState,
    akamai_inputs: AkamaiInputCollector,
    poisoned: bool,
}

impl SessionParser for Http2Parser {
    type Message = Http2Message;

    fn feed_initiator(&mut self, b: &[u8], ts: Timestamp,
        out: &mut Vec<Self::Message>) { … }
    fn feed_responder(&mut self, b: &[u8], ts: Timestamp,
        out: &mut Vec<Self::Message>) { … }
    fn parser_kind(&self) -> &'static str { "http2" }
    fn is_poisoned(&self) -> bool { self.poisoned }
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub enum Http2Message {
    Request(Http2Request),
    Response(Http2Response),
    Settings { side: FlowSide, frame: SettingsFrame },
    /// Emitted once per flow when the Akamai fingerprint
    /// inputs are complete (after the first HEADERS).
    AkamaiFingerprint(AkamaiHttp2Fingerprint),
    GoAway { side: FlowSide, error_code: u32, last_stream_id: u32 },
}
```

### `Http2Request` / `Http2Response`

```rust
// src/http2/types.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http2Request {
    pub stream_id: u32,
    pub method: Bytes,
    pub scheme: Bytes,
    pub authority: Bytes,
    pub path: Bytes,
    /// Pseudo-header order observed in the HEADERS frame.
    /// E.g. ['m', 'a', 's', 'p'] for `:method`, `:authority`,
    /// `:scheme`, `:path` — input to the Akamai fingerprint.
    pub pseudo_header_order: SmallVec<[char; 4]>,
    pub headers: Vec<(Bytes, Bytes)>,
    pub end_stream: bool,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http2Response {
    pub stream_id: u32,
    pub status: u16,
    pub headers: Vec<(Bytes, Bytes)>,
    pub end_stream: bool,
}
```

### Akamai HTTP/2 fingerprint

```rust
// src/http2/akamai.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct AkamaiHttp2Fingerprint {
    /// `SETTINGS` values from the first SETTINGS frame, in
    /// observed order. CSV of `id:value` pairs.
    pub settings_csv: String,
    /// Connection-level (stream 0) `WINDOW_UPDATE` increment
    /// before the first HEADERS, or 0 if none.
    pub window_update: u32,
    /// `PRIORITY` frame descriptors before the first HEADERS,
    /// CSV of `streamid:exclusive:depstream:weight`.
    pub priority_csv: String,
    /// Pseudo-header order in the first HEADERS frame, comma-
    /// joined first letters (e.g. `m,a,s,p`).
    pub pseudo_header_order: String,
}

impl AkamaiHttp2Fingerprint {
    /// Full canonical fingerprint string, pipe-separated.
    /// Example:
    /// `1:65536,3:1000,4:6291456,6:262144|10485760|0|m,a,s,p`
    pub fn to_string(&self) -> String { … }

    /// SHA-256 of the canonical string, hex.
    /// Useful for compact correlation keys.
    pub fn sha256_hex(&self) -> String { … }
}
```

### `Http2Config`

```rust
// src/http2/mod.rs

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct Http2Config {
    /// HPACK dynamic table size override. Default 4096 per
    /// RFC 7541 §4.2.
    pub max_dynamic_table_bytes: usize,
    /// Maximum HEADERS+CONTINUATION accumulated bytes per
    /// stream before the parser poisons. Default 64 KiB.
    pub max_headers_bytes: usize,
    /// Maximum concurrent streams tracked per direction.
    /// Default 1024.
    pub max_concurrent_streams_tracked: usize,
    /// Emit per-frame `Settings` messages (default false —
    /// only the Akamai input collection cares).
    pub emit_settings_frames: bool,
}
```

## Implementation steps

### Phase 1: dep + frame parser skeleton

1. `Cargo.toml`: add `httlib-hpack = "0.1"` (or pinned latest).
   Optional, gated under `http2`. Add `http2` feature.
2. `src/http2/frames.rs`: byte layout structs for each frame
   type. RFC 9113 §4. Parser surface: `Frame::parse(&[u8])
   -> Result<(Frame, usize), Error>` (consume-and-go).
3. `src/http2/parser.rs`: state machine
   `Preface → Settings → FrameLoop`. Per-direction. Handles
   incomplete frames (return `NeedMoreData`).

### Phase 2: HPACK integration

4. `src/http2/hpack.rs`: wrap `httlib-hpack` with per-
   direction dynamic table. Track table size updates from
   `SETTINGS_HEADER_TABLE_SIZE`. Per-stream HEADERS +
   CONTINUATION accumulation (CONTINUATION can only follow
   HEADERS / PUSH_PROMISE per RFC 9113 §6.10).

### Phase 3: Typed message construction

5. `src/http2/types.rs`: `Http2Request` / `Http2Response`
   types.
6. `src/http2/session.rs`: `Http2Parser` SessionParser impl.
   Decode HEADERS, classify pseudo-headers, construct
   `Http2Request` (client→server) or `Http2Response`
   (server→client) based on `:status` presence.

### Phase 4: Akamai fingerprint

7. `src/http2/akamai.rs`: `AkamaiInputCollector` accumulates
   the four inputs from the first ~5 client frames after the
   preface. Emits `Http2Message::AkamaiFingerprint` once.
8. Format: `SETTINGS_CSV|WU|PRIORITY_CSV|PSEUDO_HEADER_ORDER`.
   Reference: Akamai 2017 paper.

### Phase 5: Heuristic routing signature

9. `src/detect/signatures.rs`: add `http2_preface` — matches
   the 24-byte connection preface. Used with
   `Driver::builder.session_heuristic(Http2Parser::default(),
   http2_preface)` for non-standard-port detection.

### Phase 6: Tests + fixtures + example

10. Capture pcap fixtures from real browsers (curl --http2,
    chrome devtools, firefox, golang h2 client). Embed
    minimal pcaps under `tests/fixtures/http2/`.
11. Frame-by-frame parse tests against the fixtures.
12. Akamai fingerprint tests asserting known browser
    fingerprints.
13. `examples/01-l7-logging/http2_log.rs` — pcap → per-frame /
    per-message log.
14. `examples/02-forensics/http2_fingerprint.rs` — pcap →
    Akamai fingerprint per flow.
15. `docs/http2-format.md` — frame catalog + Akamai
    fingerprint format spec.

## Tests

### Unit

- `frames::tests::settings_frame_parses_id_value_pairs`
- `frames::tests::headers_frame_accumulates_with_continuation`
- `frames::tests::window_update_frame_parses_increment`
- `frames::tests::priority_frame_parses_descriptor`
- `hpack::tests::static_table_lookups_match_rfc7541_appendix_a`
- `hpack::tests::dynamic_table_size_update_evicts_oldest`
- `hpack::tests::huffman_decode_matches_rfc7541_appendix_b_fixtures`
- `akamai::tests::canonical_string_matches_chrome_known_value`
- `parser::tests::preface_required_before_frame_loop`
- `parser::tests::garbage_after_preface_poisons`

### Integration

- `tests/http2_parser.rs::curl_http2_simple_get_emits_request`
- `tests/http2_parser.rs::server_push_promise_surfaces_as_message`
- `tests/http2_parser.rs::goaway_emits_terminal_message`
- `tests/http2_parser.rs::headers_continuation_split_reassembles`
- `tests/http2_akamai.rs::chrome_fingerprint_matches_known`
- `tests/http2_akamai.rs::firefox_fingerprint_matches_known`
- `tests/http2_akamai.rs::go_h2_client_fingerprint_matches_known`
- `tests/http2_akamai.rs::sha256_round_trips`
- `tests/parser_proptest.rs` — add HTTP/2 splitting-invariance
  proptest

## Acceptance criteria

- `cargo build --features http2,pcap` clean.
- `cargo test --features http2,pcap` clean.
- `cargo clippy --features http2,pcap --all-targets -- -D warnings`
  clean.
- New `http2` CI matrix entry.
- All Akamai fingerprint golden tests match published browser
  fingerprints (e.g. Chrome 119:
  `1:65536,3:1000,4:6291456,6:262144|15663105|0|m,a,s,p`).
- `examples/02-forensics/http2_fingerprint.rs` runs end-to-end
  on the shipped pcap fixtures.
- `docs/http2-format.md` documents every frame type observed +
  the Akamai fingerprint format.
- Bench: HTTP/2 parse throughput documented in
  `docs/performance.md` (just one new bench row;
  `cargo bench --bench session_driver --features http2`).

## Risks

- **R1: HPACK dynamic-table sync on packet loss.** Passive
  observation requires lossless reassembly; one missed frame
  desyncs both directions' HPACK state. Mitigation: TCP
  reassembler in front (`reassembler` feature already
  required); on `is_poisoned()`, the driver tears the flow
  down and we emit `ParseError`. Documented.
- **R2: `httlib-hpack` activity / maintenance.** Single-author
  crate; last release 2024. Mitigation: fallback to a
  hand-rolled HPACK decoder (~400 LoC) if `httlib-hpack` goes
  unmaintained; the static-table + Huffman tables are RFC-
  fixed. Track upstream activity; revisit at 0.13 if needed.
- **R3: Akamai fingerprint spec drift.** Akamai hasn't
  re-published the formal spec since 2017 but implementations
  in the wild stay consistent. Mitigation: golden fixtures
  pinned to published Chrome / Firefox values; a spec drift
  surfaces as a test failure with a clear delta.
- **R4: Memory cost of HPACK dynamic tables.** Per direction
  per flow, max ~4 KiB + per-stream HEADERS accumulation up
  to `max_headers_bytes`. At max_flows=100k that's 800 MB
  worst-case. Configurable via `Http2Config`; document the
  default + the math.
- **R5: PUSH_PROMISE deprecation.** RFC 9113 marked it
  "MAY be sent by the server" with Chrome 106+ defaulting off.
  We surface it for completeness but consumers should not
  expect to see it on modern traffic.

## Effort

| Step | LoC | Hours |
|---|---|---|
| `httlib-hpack` integration + per-direction dynamic tables | 250 | 5 |
| Frame parser state machine | 350 | 6 |
| HEADERS + CONTINUATION accumulation per stream | 180 | 4 |
| Typed message construction (Request / Response) | 180 | 4 |
| Akamai fingerprint inputs + canonical format | 150 | 3 |
| Heuristic signature (http2_preface) | 30 | 0.5 |
| Tests (10 unit + 9 integration + proptest) | 500 | 8 |
| 4 pcap fixtures (curl / chrome / firefox / go) | — | 2 |
| Example + docs/http2-format.md | 200 | 4 |
| CHANGELOG | 40 | 1 |
| **Total** | **~1880** | **~38 hours (~5 days)** |

## Provenance

netring 0.21 wishlist (Phase F §"HTTP/2 passive observation").
The 0.12 audit ranked this Tier-1 (third-highest ROI after
JA4+ and IPFIX). Without HTTP/2, flowscope can't observe the
majority of modern web traffic; with it, the
flowscope + JA4+ + Akamai-HTTP/2 combo becomes a real bot-
detection / NDR building-block. Suricata 7.0 ships HTTP/2;
Zeek's `http2` pkg is mature; no published Rust passive-HTTP/2
crate exists in Jan 2026 — greenfield opportunity inside the
established `httlib-hpack` ecosystem.

References:
- RFC 9113 (HTTP/2)
- RFC 7541 (HPACK)
- Akamai 2017 white paper "Passive Fingerprinting of HTTP/2
  Clients" (Mike Cailler)
- `github.com/httlib/httlib-hpack`
- `github.com/lwthiker/curl-impersonate` (browser HTTP/2
  fingerprint reference)
