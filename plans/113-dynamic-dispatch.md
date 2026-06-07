# Plan 113 — dynamic dispatch: signatures + heuristic routing

## Summary

The "dynamic protocol detection" feature pair surfaced by
plan 112's audit, shipped as two sub-PRs:

- **Sub-plan A — `flowscope::detect::signatures`.** Pure-
  function magic-byte recognizers for ~12 protocols with
  3-state output (`Match` / `NoMatch` / `NeedMoreData`).
  Standalone use AND building block for sub-plan B.
- **Sub-plan B — `Routing::Heuristic` on plan-116's unified
  `Driver`.** Signature-based dispatch with the cheap-first
  cascade + pin-on-first-match + bounded packet budget
  pattern.

This pair brings flowscope's dynamic-detection capability
in line with Suricata 8 / nDPI / Wireshark conventions
without ML / unbounded state / mid-stream reclassification.

| Sub-PR | Scope | LoC | Hours |
|--------|-------|-----|-------|
| A | 12 signatures + registry table | ~720 | ~9 |
| B | `Routing::Heuristic` + per-flow detection state | ~870 | ~16.5 |
| **Total** | | **~1,590** | **~25.5** |

## Status

**Ready to implement.** Targets 0.10.0. Sub-A ships
independently (consumers can call signatures standalone);
sub-B depends on both sub-A AND plan 116 (unified
`Driver`).

## Prerequisites

- **Plan 102 sub-C** — `flowscope::detect` module (shannon
  entropy + light primitives). Sub-A adds `signatures` as a
  submodule of `detect`.
- **Plan 116** — unified `Driver<E, M>`. Sub-B extends the
  `DriverBuilder<E, M>` with three new methods. Hard
  prerequisite for sub-B.

## Out of scope (whole plan)

- **Speculative parallel parsing.** Zeek runs multiple
  candidate analyzers and prunes losers; that requires
  per-flow per-parser state proportional to the candidate
  set. flowscope dispatches ONLY the matching parser.
- **Mid-stream protocol change detection.** Once pinned, a
  flow stays pinned.
- **Cross-flow signature aggregation** (e.g. "flow N is
  HTTP, flow N+1 to the same dst is probably HTTP too").
- **Probabilistic / scored signatures.** Sub-A is 3-state
  (`Match` / `NoMatch` / `NeedMoreData`); sub-B dispatches
  on `Match` only.
- **Aho-Corasick multi-pattern matching.** Each signature
  is a standalone function; sub-B walks the registered
  list.
- **Bayesian / ML-based detection.** Deterministic
  functions only.
- **Large protocol catalog.** Ship 8-12 signatures
  matching the common-protocol set + the ones flowscope
  already parses. Adding more is a per-consumer ask.
- **Server-side / response-side signatures.** Initial cut
  focuses on initiator-direction first-packet detection.
- **TLS server-side / ALPN sniffing.** TLS's ClientHello
  is signature-detectable; the TLS-over-X demultiplexing
  is downstream.
- **Custom budget per signature** (sub-B). All
  heuristic-routed parsers share the same
  `max_probe_packets`; per-parser override is a future
  plan.

---

## Sub-plan A — `flowscope::detect::signatures`

### Signature shape

```rust
// src/detect/signatures.rs

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureMatch {
    /// Bytes definitively match this protocol.
    Match,
    /// Bytes definitively do not match.
    NoMatch,
    /// Not enough bytes to decide — re-check with more.
    NeedMoreData,
}

pub type SignatureFn = fn(&[u8]) -> SignatureMatch;
```

### Shipped signatures

Each signature is a few dozen lines:

```rust
pub fn http_request(bytes: &[u8]) -> SignatureMatch;
pub fn http_response(bytes: &[u8]) -> SignatureMatch;
pub fn tls_client_hello(bytes: &[u8]) -> SignatureMatch;
pub fn tls_server_hello(bytes: &[u8]) -> SignatureMatch;
pub fn ssh_banner(bytes: &[u8]) -> SignatureMatch;
pub fn dns_message(bytes: &[u8]) -> SignatureMatch;
pub fn smtp_banner(bytes: &[u8]) -> SignatureMatch;
pub fn ftp_banner(bytes: &[u8]) -> SignatureMatch;
pub fn irc_message(bytes: &[u8]) -> SignatureMatch;
pub fn redis_resp(bytes: &[u8]) -> SignatureMatch;
pub fn mqtt_connect(bytes: &[u8]) -> SignatureMatch;
pub fn postgres_startup(bytes: &[u8]) -> SignatureMatch;
```

Sample implementations:

```rust
/// HTTP/1.x: method + space + path + space + `HTTP/1.`.
pub fn http_request(bytes: &[u8]) -> SignatureMatch {
    const METHODS: &[&[u8]] = &[
        b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ",
        b"OPTIONS ", b"PATCH ", b"TRACE ", b"CONNECT ",
    ];
    if bytes.len() < 16 {
        if !METHODS.iter().any(|m|
            bytes.len() < m.len() ||
            bytes.starts_with(m) ||
            m.starts_with(bytes))
        {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    if !METHODS.iter().any(|m| bytes.starts_with(m)) {
        return SignatureMatch::NoMatch;
    }
    let scan_limit = bytes.len().min(256);
    if bytes[..scan_limit].windows(7).any(|w| w == b"HTTP/1.") {
        SignatureMatch::Match
    } else {
        SignatureMatch::NeedMoreData
    }
}

/// TLS ClientHello: 0x16 content type + valid version + handshake type 0x01.
pub fn tls_client_hello(bytes: &[u8]) -> SignatureMatch {
    if bytes.len() < 6 {
        if !bytes.is_empty() && bytes[0] != 0x16 {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    if bytes[0] != 0x16 { return SignatureMatch::NoMatch }
    let version = u16::from_be_bytes([bytes[1], bytes[2]]);
    if !matches!(version, 0x0301 | 0x0302 | 0x0303) {
        return SignatureMatch::NoMatch;
    }
    if bytes[5] != 0x01 { return SignatureMatch::NoMatch }
    SignatureMatch::Match
}

/// SSH banner: `SSH-N.M-…\r\n`.
pub fn ssh_banner(bytes: &[u8]) -> SignatureMatch {
    if bytes.len() < 4 {
        if !b"SSH-".starts_with(bytes) {
            return SignatureMatch::NoMatch;
        }
        return SignatureMatch::NeedMoreData;
    }
    if !bytes.starts_with(b"SSH-") { return SignatureMatch::NoMatch }
    if bytes.len() < 8 { return SignatureMatch::NeedMoreData }
    if !(bytes[4].is_ascii_digit() && bytes[5] == b'.') {
        return SignatureMatch::NoMatch;
    }
    SignatureMatch::Match
}
```

### Registry table

```rust
pub fn registry() -> impl Iterator<Item = (&'static str, SignatureFn)> {
    [
        ("http",          http_request as SignatureFn),
        ("tls",           tls_client_hello as SignatureFn),
        ("dns",           dns_message as SignatureFn),
        ("ssh",           ssh_banner as SignatureFn),
        ("smtp",          smtp_banner as SignatureFn),
        ("ftp",           ftp_banner as SignatureFn),
        ("irc",           irc_message as SignatureFn),
        ("redis-resp",    redis_resp as SignatureFn),
        ("mqtt",          mqtt_connect as SignatureFn),
        ("postgres",      postgres_startup as SignatureFn),
    ]
    .into_iter()
}
```

`parser_kind` strings align with
`flowscope::parser_kinds::*` constants.

### Files (sub-A)

```
src/detect/signatures.rs    # NEW — 12 signatures + registry
src/detect/mod.rs           # re-export
tests/detect_signatures.rs  # 12+ scenarios per signature + proptest
docs/recipes.md             # "Heuristic protocol detection" section
CHANGELOG.md                # 0.10 entry
```

### Implementation steps (sub-A)

1. Create `src/detect/signatures.rs` with the 12 signature
   functions.
2. Add `registry()` returning the curated `(kind, fn)`
   table.
3. Re-export from `src/detect/mod.rs`.
4. `tests/detect_signatures.rs`:
   - Known-good byte sequence → `Match`.
   - Known-bad sequence → `NoMatch`.
   - Truncated prefix → `NeedMoreData`.
   - Random bytes → `NoMatch`.
   - Splitting-invariance proptest: any prefix of a `Match`
     input never returns `NoMatch` (only `Match` or
     `NeedMoreData`).
5. `docs/recipes.md` "Heuristic protocol detection" section.
6. CHANGELOG entry.

### Sample tests (sub-A)

```rust
#[test]
fn http_request_signature() {
    assert_match_table(http_request, &[
        (b"GET / HTTP/1.1\r\n", SignatureMatch::Match),
        (b"POST /a HTTP/1.0\r\n", SignatureMatch::Match),
        (b"GET ", SignatureMatch::NeedMoreData),
        (b"GE", SignatureMatch::NeedMoreData),
        (b"XYZ", SignatureMatch::NoMatch),
        (b"\x16\x03\x01", SignatureMatch::NoMatch),
        (b"GET /index.html ", SignatureMatch::NeedMoreData),
    ]);
}

#[test]
fn tls_client_hello_signature() {
    assert_match_table(tls_client_hello, &[
        (&[0x16, 0x03, 0x01, 0x00, 0x42, 0x01], SignatureMatch::Match),
        (&[0x16, 0x03, 0x03, 0x00, 0x42, 0x01], SignatureMatch::Match),
        (&[0x16, 0x03, 0x04, 0x00, 0x42, 0x01], SignatureMatch::NoMatch),
        (&[0x17, 0x03, 0x01, 0x00, 0x42, 0x01], SignatureMatch::NoMatch),
        (&[0x16, 0x03], SignatureMatch::NeedMoreData),
        (b"GET / HTTP/1.1", SignatureMatch::NoMatch),
    ]);
}

#[test]
fn splitting_invariance_proptest() {
    use proptest::prelude::*;
    proptest!(|(prefix_len in 1usize..=64)| {
        let bytes = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let prefix_len = prefix_len.min(bytes.len());
        let prefix = &bytes[..prefix_len];
        let result = http_request(prefix);
        prop_assert_ne!(result, SignatureMatch::NoMatch);
    });
}
```

12+ scenarios per signature × 12 signatures + 1 proptest =
~150 test cases.

---

## Sub-plan B — `Routing::Heuristic` on the unified `Driver`

### New routing variant

```rust
// src/driver/routing.rs (file landed by plan 116)
pub enum Routing {
    Ports(SmallVec<[u16; 4]>),
    Broadcast,

    /// NEW (plan 113 sub-B): payload-based routing.
    /// Examine the first `max_probe_packets` packets of each
    /// new flow; fire when `signature(buf)` returns Match.
    /// After a match, the parser is pinned to the flow.
    Heuristic {
        signature: SignatureFn,
        max_probe_packets: u8,
    },
}
```

### Builder API additions

```rust
impl<E, M> DriverBuilder<E, M> {
    pub fn session_heuristic<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        lift: F,
    ) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    pub fn session_heuristic_with_budget<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        max_probe_packets: u8,
        lift: F,
    ) -> Self where /* same bounds */;

    pub fn datagram_heuristic<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        lift: F,
    ) -> Self where /* same bounds */;
}
```

`PipelineBuilder<E, M>` (plan 116) proxies all three.

### Per-flow detection state

```rust
enum FlowDetection {
    Probing {
        seen: u8,
        init_buf: ArrayVec<u8, 64>,
        resp_buf: ArrayVec<u8, 64>,
    },
    Pinned(SlotIdx),
    GaveUp,
}
```

Stored in a `HashMap<E::Key, FlowDetection>` parallel to
the flow tracker — owned by the unified `Driver`'s internal
state (plan 116's `src/driver/dispatch.rs`).

Memory cost per active flow: `Probing` ~140 bytes;
`Pinned` 4 bytes; `GaveUp` 0 bytes. For a 100k-flow
tracker, steady-state is ~4 B/flow (most flows pin on
1-2 packets).

### Per-packet dispatch

```text
On packet receipt for flow K:
  1. tracker.track(view) → emit Flow events.
  2. Run port-based routing.
  3. Look up FlowDetection[K]:
     a. Probing: append payload to per-side buffer (capped),
        evaluate every heuristic signature.
        - If any returns Match → transition to Pinned(slot).
          Dispatch the accumulated buffer to that parser.
        - Else if `seen + 1 >= max_probe_packets` → GaveUp.
        - Else: seen += 1, continue.
     b. Pinned(slot): dispatch directly.
     c. GaveUp: no heuristic dispatch.
  4. Run broadcast routing.
  5. Return merged Vec<Event<K, M>>.
```

### Per-flow cleanup

On `Event::FlowEnded` from the tracker, drop the
`FlowDetection` entry for that key.

### Concrete usage

```rust
use flowscope::detect::signatures::{
    http_request, tls_client_hello, dns_message,
};

let mut driver = Driver::<_, MyL7>::builder(ext)
    // Port-routed: covers the common case.
    .session_on_ports(HttpParser::default(),         [80, 8080], MyL7::Http)
    .session_on_ports(TlsHandshakeParser::default(), [443],       MyL7::Tls)
    .datagram_on_ports(DnsUdpParser::default(),      [53],        MyL7::Dns)

    // Heuristic: catches HTTP on 9000, TLS on 8443, etc.
    .session_heuristic(HttpParser::default(),         http_request,     MyL7::Http)
    .session_heuristic(TlsHandshakeParser::default(), tls_client_hello, MyL7::Tls)
    .datagram_heuristic(DnsUdpParser::default(),      dns_message,      MyL7::Dns)

    .build();
```

### Files (sub-B)

```
src/driver/routing.rs       # add Heuristic variant (file landed by 116)
src/driver/dispatch.rs      # add FlowDetection + dispatch (landed by 116)
src/driver/mod.rs           # 3 new builder methods + PipelineBuilder proxies
tests/heuristic_routing.rs  # 6+ scenarios
examples/extract_iocs.rs    # extend with both port + heuristic modes
docs/recipes.md             # update "Multi-protocol monitoring"
CHANGELOG.md                # 0.10 entry
```

### Implementation steps (sub-B)

1. Add `Routing::Heuristic` variant.
2. Add `FlowDetection` enum + storage to `Driver`'s
   dispatch state.
3. Add the four builder methods (3 on `DriverBuilder`, plus
   PipelineBuilder proxies).
4. Update per-packet dispatch with the probe → pin → give-up
   state machine.
5. Drop detection state on `Event::FlowEnded`.
6. Tests + example + docs + CHANGELOG.

### Tests (sub-B)

```rust
#[test]
fn heuristic_matches_http_on_unusual_port() {
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_heuristic(HttpParser::default(), http_request, |m| m)
        .build();

    let frames = build_http_pcap_on_port(9999, "GET /index.html HTTP/1.1\r\n\r\n");
    let messages: Vec<HttpMessage> = drive(&mut driver, &frames);
    assert!(matches!(messages.first(), Some(HttpMessage::Request(_))));
}

#[test]
fn heuristic_gives_up_after_budget() {
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_heuristic_with_budget(HttpParser::default(), http_request, 2, |m| m)
        .build();
    let frames = build_garbage_pcap(9999);
    let messages = drive(&mut driver, &frames);
    assert!(messages.is_empty());
}

#[test]
fn port_route_wins_when_both_apply() {
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_on_ports(HttpParser::default(), [80], |m| m)
        .session_heuristic(HttpParser::default(), http_request, |m| m)
        .build();
    let frames = build_http_pcap_on_port(80, "GET / HTTP/1.1\r\n\r\n");
    let messages: Vec<HttpMessage> = drive(&mut driver, &frames);
    assert_eq!(messages.len(), 1);
}

#[test]
fn pinning_persists_across_packets() { /* … */ }

#[test]
fn heuristic_then_tracker_ended_drops_detection_state() { /* … */ }
```

Plus proptest: arbitrary chunking produces identical
output regardless of per-side buffer fill order.

---

## Acceptance criteria (whole plan)

- 12 signature functions + `registry()` ship (sub-A).
- Per-signature unit tests pass; proptest passes (sub-A).
- `Routing::Heuristic` variant ships (sub-B).
- Four builder methods land — 3 on `DriverBuilder`, all 3
  proxied through `PipelineBuilder` (sub-B).
- Per-flow detection state machine works (sub-B).
- 6+ heuristic-routing integration tests pass (sub-B).
- `cargo test --all-features` clean across both PRs.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `docs/recipes.md` "Heuristic protocol detection" +
  updated "Multi-protocol monitoring" sections ship.
- `examples/extract_iocs.rs` shows both port + heuristic
  modes (sub-B).
- CHANGELOG entries per sub-PR under 0.10.0 "Added".

## Risks

- **Signature drift over time** (sub-A) — signatures are
  intentionally lenient; update in patch releases.
- **False positives on uncommon traffic** (sub-A) —
  multiple discriminators per signature.
- **Detection state memory at high flow counts** (sub-B) —
  64-byte × 2-side × 100k flows = ~12.8 MiB if every flow
  is probing. Steady-state drops to 4 B/flow.
- **Signature evaluation overhead in the probe window**
  (sub-B) — ~2 µs per flow during probing. Negligible.
- **Order-dependence of registration** (sub-B) — two
  heuristics that could both match same payload —
  first-registration wins. Documented.
- **Pinning permanence** (sub-B) — once pinned, flow
  doesn't unpin. Mid-stream mismatches result in
  `ParseError`-Closed. This is correct behaviour.
- **Buffer cap (64 B) too small for some signatures**
  (sub-B) — handles every shipped signature; make it a
  named const so future plans can tune.

## Effort

| Sub-PR / section | LoC | Hours |
|------------------|-----|-------|
| A — 12 signatures | ~300 | 4 |
| A — registry + types | ~40 | 0.5 |
| A — per-signature tests | ~280 | 3 |
| A — splitting-invariance proptest | ~40 | 0.5 |
| A — docs + CHANGELOG | ~60 | 1 |
| B — Routing::Heuristic variant | ~30 | 0.5 |
| B — FlowDetection state + storage | ~80 | 2 |
| B — Builder methods + Pipeline proxies | ~120 | 2.5 |
| B — Per-packet dispatch update | ~140 | 4 |
| B — Cleanup on FlowEnded | ~30 | 1 |
| B — Tests (6+ scenarios + proptest) | ~360 | 5 |
| B — Example extension | ~30 | 0.5 |
| B — Docs + CHANGELOG | ~80 | 1 |
| **Total** | **~1,590** | **~25.5** |

## Provenance

Plan 112 (the dynamic-lazy analysis document):

> Plan 113 — `flowscope::detect::signatures` — small
> module with magic-byte recognizers for the eight or so
> protocols flowscope ships parsers for.
>
> Plan 114 — `Routing::Heuristic { signatures }` on the
> unified `Driver`. Adds a new routing mode that runs a
> list of signatures over the first N bytes of payload per
> flow; pins on first match.

Industry refs:
- nDPI uses Aho-Corasick magic patterns as the cheap stage.
- Wireshark's heuristic dissector contract is `bool` on a
  prefix.
- Zeek's DPD signature set is BPF-like; ours is just
  function pointers.
- Suricata 8 pattern-then-probe sequencing.
- Wireshark conversation pinning.

Consolidated from prior individual plans 113 (signatures)
and 114 (heuristic routing). They are tightly coupled —
sub-A is the building block; sub-B is the consumer. Both
plans share their out-of-scope list and their industry
research; ship as one cohesive plan with two PR
boundaries.
