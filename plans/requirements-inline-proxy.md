# flowscope requirements — becoming the L7 core for an inline proxy

**Author context:** written from the perspective of **zenoh-bridge-tcp**, a
bidirectional TCP↔Zenoh bridge that also routes HTTP/HTTPS/gRPC by Host/SNI.
It wants to delete ~2,000 lines of hand-rolled `tls_parser.rs` /
`http_parser.rs` / `http_response_parser.rs` / multiroute framing and use
flowscope as its shared, fuzz-tested L7 core.

**Audience:** an implementer (LLM or human) working **inside the flowscope
repo**. This is a requirements + design spec, not a patch. **Backward-compat
breaks are allowed** — target a clean `0.23`/`1.0` API; keep the passive-
telemetry path working but feel free to restructure the public surface.

**A caveat on citations:** the freshest standards facts (ECH → RFC 9849/9848,
the ML-KEM hybrid drafts' final RFC numbers, a couple of HPACK/`RFC 9110 §10`
sub-anchors) were gathered by live web research that post-dates the model's
training cutoff. **Re-verify every RFC *number* against datatracker/IANA
before hardcoding it in normative docs or comments.** The *mechanics* below
are stable; the *numbering* of very recent RFCs is what to double-check.

---

## 0. TL;DR — the one paradigm shift

flowscope today is **passive-telemetry-first**: it buffers each full message
body and emits one `HttpMessage::Request`/`Response` record. An **inline
proxy** needs the opposite discipline — **sans-IO streaming**:

> emit **Head** (routing key) as soon as headers are parsed → stream **Body**
> as zero-copy chunks it never retains → emit **Trailers** → **End**; and on a
> protocol switch emit **SwitchProtocols** and get out of the way. The caller
> owns the sockets, the buffering, and therefore the backpressure.

This is exactly the model `rustls`, `quinn-proto`, `h2`, and Cloudflare
Pingora converged on. flowscope already has the parsing machinery; what's
missing is this **event shape** and the proxy-grade framing correctness that
rides on it. Everything below serves that shift.

The single spike already done (`spike/inline-streaming` branch) proves the
request-head half is additive and cheap — see `spike-inline-streaming.md`.
This document is the full picture it teed up.

---

## 1. Hard constraints (non-negotiable)

1. **Pure compute.** The parser paths must stay free of `async`/`tokio`/
   `libc`/`std::net`/sockets/threads. (Verified true of `src/http/*` and
   `src/tls/*` today — keep it that way.) The bridge must run as an
   **unprivileged, cross-platform** process; flowscope must never pull in a
   capability (CAP_NET_*), root, raw sockets, or OS-specific code on any path
   the bridge compiles. This is why the bridge can adopt flowscope and can
   **never** adopt netring.
2. **Caller owns I/O and time.** No internal I/O, no wall-clock reads; time is
   injected (`Timestamp` already is). `push(&[u8]) -> consumed` + drain
   events; returning "need more bytes" mid-message is how the caller does flow
   control.
3. **Bounded memory, no silent unbounded buffering.** Every reassembly buffer
   (TCP-segment, TLS-record, HPACK header block, chunk) has an explicit cap;
   exceeding it **poisons** the parser with a reason, never OOMs.
4. **License firewall.** Keep the core MIT/Apache: SNI/ALPN parse, first-byte
   classification, HTTP framing, JA3, **JA4 (client) are BSD/permissive** and
   belong in the core. **JA4S/JA4H/JA4X/… are FoxIO License 1.1 (non-
   commercial)** and must stay isolated behind `ja4plus`, off by default and
   out of `l7`/`full` — as they already are. The bridge is a redistributed
   product; a FoxIO leak into the default build would taint it.
5. **Additive where you can, break cleanly where you should.** `#[non_exhaustive]`
   on the public enums already makes new variants non-breaking; use that. But
   if a clean inline API means a new parser *type* or a reshaped `Event` enum,
   take the major bump — the telemetry `SessionParser` can stay beside it.

---

## 2. What already exists — leverage, do not rebuild

The implementer should **not** re-invent these; they're shipped and relevant:

| Capability | Where | Use for |
|---|---|---|
| **TLS `TlsParser`** — SNI + ALPN, TCP-segment **and** PQ-large-ClientHello reassembly across records | `src/tls/` (`TlsClientHello::sni()`, `.alpn`) | closes the bridge's **G6** split-ClientHello bug; the SNI/ALPN routing key |
| **QUIC Initial** — long-header decode + Initial-secret + AEAD decrypt → **SNI/ALPN** | `quic` feature (`QuicInitial`) | future **HTTP/3 / DoH routing** — SNI on encrypted-by-default transports |
| **`app_proto::classify`** — AppProtocol from ALPN+SNI+port; `from_tls_handshake`, `from_quic_initial` | `src/app_proto.rs` | firm up the bridge's protocol decision *after* TLS/QUIC parse |
| **`emit/*`** (EVE / Zeek / IPFIX / NDJSON) + **`obs.rs`** (`flowscope_*` metrics) | `src/emit`, `src/obs.rs` | the bridge's **G7** observability gap — access logs + metrics for free |
| **JA3 + JA4 (client)** — BSD | `tls-fingerprints` | observability + a stable routing/grouping signal (survives GREASE + Chrome ext-shuffle) |
| **HTTP inline-streaming request side** | `spike/inline-streaming` branch | request-head-early + body-skip + chunked-skip + `is_poisoned` — polish & land |
| **`SegmentBufferReassembler`, `session` engine, fuzz corpus, `cargo-semver-checks` CI** | crate-wide | the reassembly + test infrastructure to build on |

**Gaps flowscope does *not* have today** (the meat of this doc): a proxy-grade
**streaming HTTP/1.1 exchange** parser (response side, method-aware, 1xx,
trailers, smuggling reject/normalize, upgrade/CONNECT tunnel), a **raw
first-byte protocol classifier**, and an **HTTP/2 + HPACK + gRPC** per-stream
router.

---

## 3. Requirements, prioritized

Each item: **Problem → What the bridge needs → Proposed flowscope API →
Closes**. Bridge issue IDs (E1–E6, F3, G1/G6/G7, D2/D4, #46, #50) are
cross-references.

### P0 — the inline-streaming HTTP/1.1 exchange (the core deliverable)

This is what unlocks the bridge deleting `http_parser.rs` +
`http_response_parser.rs` + multiroute's `read_full_request`, and it fixes the
whole E-series at once.

#### R1. A sans-IO streaming exchange API (Head → Body → Trailers → End)

**Problem.** The telemetry `HttpParser` withholds the message until the whole
body is buffered and never surfaces body chunks or trailers. An inline proxy
must route on the head immediately and stream the body it forwards but does
not keep.

**What the bridge needs.** Per direction: the head as soon as headers parse;
then the body as **zero-copy `&[u8]`/`Bytes` slices of the fed buffer** with
its framing; then trailers; then an explicit end. Caller-driven flow control
(stop pushing = backpressure). This mirrors Pingora's
`request_body_filter`/`response_body_filter` per-chunk model and `h2`'s
`RecvStream::poll_data()`/`trailers()`.

**Proposed API** (new type, alongside the telemetry `SessionParser` — a clean
break is fine):

```rust
/// Sans-IO HTTP/1.1 exchange parser for inline proxies. No I/O, no async,
/// no time reads. Feed bytes per direction, drain events.
pub struct HttpProxyParser { /* per-direction state, config, HPACK n/a for h1 */ }

pub enum Dir { ClientToServer, ServerToClient }

impl HttpProxyParser {
    pub fn with_config(cfg: HttpProxyConfig) -> Self;

    /// Feed bytes for one direction; returns how many were consumed.
    /// Un-consumed bytes must be re-fed (or are held internally, impl choice
    /// — but never buffer a whole body). Returning consumed < len is the
    /// backpressure signal: the caller controls the socket read pace.
    pub fn push(&mut self, dir: Dir, buf: &[u8]) -> Result<usize>;

    /// Signal FIN on a direction (close-delimited bodies flush here).
    pub fn fin(&mut self, dir: Dir);

    /// Drain the next event, if any.
    pub fn next_event(&mut self) -> Option<HttpEvent<'_>>;

    pub fn is_poisoned(&self) -> bool;
    pub fn poison_reason(&self) -> Option<&str>;
    /// HTTP-semantic completion (e.g. Connection: close after final body):
    /// lets the caller close/reuse the connection deterministically.
    pub fn is_done(&self) -> bool;
}

pub enum HttpEvent<'a> {
    /// Request start line + headers, emitted before the body. Carries the
    /// framing so the proxy knows how to stream and where the next message
    /// starts. (This is the spike's `RequestHead`, generalized.)
    RequestHead(RequestHead<'a>),
    /// Response status line + headers. Framing is computed using the
    /// method of the matching request (see R2).
    ResponseHead(ResponseHead<'a>),
    /// A body chunk — zero-copy slice of the fed buffer. Repeatable.
    /// For chunked bodies this is the DECODED payload (framing removed);
    /// `raw` gives the on-wire bytes when the proxy forwards verbatim.
    Body { dir: Dir, data: &'a [u8] },
    /// Trailer fields after a chunked body (gRPC-status lives here).
    Trailers(Vec<(Bytes, Bytes)>),
    /// One message fully framed; connection may carry the next.
    End { dir: Dir },
    /// Protocol switch — stop parsing, tunnel raw bytes (see R2).
    SwitchProtocols(SwitchKind),
    /// More bytes needed to make progress (optional; push() consumption
    /// already conveys this — include if it simplifies callers).
    NeedMore,
}

pub enum BodyFraming { None, ContentLength(u64), Chunked, UntilClose }
pub enum SwitchKind { WebSocket, Connect, Upgrade(Bytes), Http2Preface }
```

Design notes for the implementer:
- **Zero-copy.** Body chunks and header name/value pairs must be `Bytes`
  slices over the fed buffer (the telemetry parser already does the single-Arc
  header trick in `parser.rs`; extend it to body). This also serves the
  bridge's **G1** (kills its per-chunk `to_vec`).
- **Forwarding vs decoding chunked.** The bridge forwards bytes over Zenoh; it
  primarily needs *boundaries + trailers + smuggling rejection*, not decoded
  bodies. Offer both: a decoded `Body` and access to the raw on-wire slice, so
  a forwarding proxy can pass bytes through unchanged while flowscope tracks
  framing. (The spike already does raw chunk *skipping*; this generalizes it
  to surfacing.)
- **Caller-owned buffering.** Never accumulate a full body internally; cap the
  header block and the chunk-size line, poison on overflow.

**Closes:** E1 (full-body forwarding), D4 (no whole-response RAM buffering),
G1 (zero-copy), and is the substrate for R2–R4.

#### R2. Method-aware response framing, 1xx interims, and tunnel detection

**Problem.** RFC 9112 §6.3 rules 1–2: responses to **HEAD** and all
**1xx/204/304** have no body regardless of CL/TE; a **2xx to CONNECT** becomes
a tunnel. The response parser therefore **must know the request method**. And
**1xx interims** (100-continue, 103 Early Hints) precede the final response,
unbounded; a naive one-status-line-is-the-response reader deadlocks
(`Expect: 100-continue`) or mis-frames the next pipelined response.

**What the bridge needs.** The exchange parser correlates request↔response
(FIFO, like the existing `HttpExchangeParser`, which already retains the
method in `pending`) and uses the method to frame the response. It must:
- emit **`ResponseHead` for each 1xx** and keep reading until the non-1xx
  final — never body-frame a 1xx;
- frame HEAD responses as no-body even with `Content-Length` present;
- on `2xx`-to-CONNECT and on `101 Switching Protocols` (WebSocket / other
  Upgrade), emit **`SwitchProtocols`** so the caller tunnels the rest
  verbatim;
- keep **send-side and receive-side state independently advanceable** so the
  response reader is live the instant request *headers* are forwarded,
  regardless of body progress (this is the real 100-continue deadlock fix).

**Proposed API.** Fold this into `HttpProxyParser` (it sees both directions),
or provide `HttpProxyExchange` layering over it. The method threading is the
one genuine cross-direction coupling — `HttpExchangeParser` already has the
scaffolding (`pending: VecDeque<(HttpRequest, Timestamp)>`), so extend that to
carry method into the response direction's framing decision.

**Closes:** E3 (HEAD), E4 (100-continue / 1xx), E5 (WebSocket/CONNECT tunnel —
detection half; the raw tunnel itself is the caller's job).

#### R3. Proxy-grade smuggling defense: reject vs normalize, and poison

**Problem.** The bridge hand-rolls the RFC 7230/9112 §6.3 checks
(`http_response_parser.rs`), but multiroute swallows parse errors
(`if let Ok(Some(..))`), so the defenses go inert and a bad message *stalls*
to a 30s timeout instead of failing (**E6**). Also F3-class request-target
bugs (absolute-URI vs Host precedence, duplicate Host, Unicode lowercasing).

**What the bridge needs.** flowscope must implement the §6.3 algorithm as the
single source of truth and **fail loudly**:
- **Reject + poison** (caller sends 400/502 + close): request with non-final
  chunked TE; conflicting/duplicate-non-identical Content-Length; unrecognized
  transfer coding; **CL + TE both present** on a forwarded message.
- **Normalize** when forwarding: strip Content-Length when TE present
  (mandatory, §6.3.3); obs-fold → SP or reject; bare CR → SP or reject;
  collapse an all-identical CL list; ignore unknown chunk-extensions.
- **TE.TE obfuscation**: strict header parsing — no `xchunked`, no duplicate
  TE, no leading-whitespace/`Transfer-Encoding\n:` tricks.
- Surface every rejection via `is_poisoned()` + `poison_reason()` so the proxy
  never forwards-and-stalls. (The spike already poisons on desync in inline
  mode; extend to these specific §6.3 rejections with distinct reasons.)
- **Request target (F3):** honor absolute-form authority over `Host` for
  absolute-URIs; **reject duplicate `Host`**; use `to_ascii_lowercase` and
  **reject non-ASCII** in the authority (no Unicode `to_lowercase()` — U+212A
  KELVIN → `k` is a routing-desync primitive). Note: the bridge still applies
  its *own* key-safety policy on top (`validate_dns_for_key`), so flowscope
  should surface the raw + a normalized authority, not impose Zenoh-key rules.

**Closes:** E6, F3. Consolidates the bridge's smuggling CVE-surface into
flowscope's fuzz corpus (extend the `http` fuzz target with CL.TE/TE.CL/TE.TE
vectors).

#### R4. Pipelining correctness

**Problem.** The bridge's multiroute mis-handles HTTP/1.1 pipelining both ways
(**E2**): two requests in one segment become one blob; post-response bytes
desync the stream.

**What the bridge needs.** The streaming parser already loops per message
(the spike's pipelined tests pass); R1's `End` event + correct per-message
boundary tracking gives the bridge clean pipelining. Ensure `End` fires
exactly at each message boundary and the next `push` resumes cleanly, in both
directions, with the response-queue kept in request order.

**Closes:** E2.

---

### P1 — protocol classification and TLS routing surface

#### R5. Raw first-byte protocol classifier

**Problem.** flowscope classifies by ALPN/SNI/**port** (`app_proto`), and its
`detect` module is entropy/ngram primitives — there is **no raw-first-byte
prober**. The bridge hand-rolls `protocol_detect.rs` (TLS vs uppercase-HTTP-
method vs Raw; 16-byte peek; misses lowercase methods, h2 preface, SSH/SMTP;
single-shot, no need-more signal).

**What the bridge needs.** An incremental classifier that never mis-classifies
on a short read:

```rust
pub enum WireProtocol { Tls, Http1, Http2Preface, Ssh, Raw }
pub enum Classify { Decided(WireProtocol), NeedMore }

/// Feed the first bytes of a connection; decide the wire protocol.
pub fn classify_first_bytes(peek: &[u8]) -> Classify;
```

Rules the implementer must bake in (from the research):
- **TLS**: `16 03 0X` + (once ≥6 bytes) `…01` ClientHello. ~6-byte minimum.
- **HTTP/2 preface FIRST** (before HTTP/1, because `PRI ` is also an h1-method-
  shaped prefix): the 24-octet `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`.
- **HTTP/1**: uppercase method token + SP; need up to 8 bytes (`CONNECT `/
  `OPTIONS `). Decide a policy on lowercase (RFC says methods are case-
  sensitive/uppercase; treat lowercase as Raw or reject — the bridge treats it
  as Raw today).
- **SSH**: `SSH-2.0-` / `SSH-1.99-`.
- Short read → **`NeedMore`**, never a wrong `Decided`. Server-speaks-first
  protocols (SSH/SMTP banners) mean the caller needs an inspect *timeout* →
  default to `Raw`; that timeout is the caller's, but the classifier must
  return `NeedMore` (not `Raw`) while the peek is still short.
- **ALPACA mitigation**: document that callers should *bind* the chosen
  backend protocol to negotiated **ALPN + SNI/Host** and refuse mismatches,
  rather than trusting first-byte heuristics alone.

**Closes:** the bridge's `protocol_detect.rs` gap; firms up `--auto-import`
(h2c-preface and SSH become first-class instead of opaque-Raw).

#### R6. Surface ALPN prominently + ECH-aware SNI degradation

**Problem.** `TlsParser` already parses ALPN, but the bridge only reads SNI
today; and TLS routing must survive ECH and PQ.

**What the bridge needs.**
- **ALPN as a first-class routing signal** next to SNI on the ClientHello
  result (the bridge needs it for #46 and for choosing h1 vs h2 on the
  terminated path). Confirm `alpn: &[&str]`/`Vec<String>` is ergonomically
  exposed.
- **Split/PQ reassembly guarantee.** X25519MLKEM768 (group `0x11EC`, Chrome
  default since v131, ~half of HTTPS in 2025) makes ClientHellos ~1.6–2 kB,
  routinely spanning multiple TCP segments — the "SNI is in packet 1"
  assumption is dead. Ensure the reassembler accumulates across TCP segments
  **and** TLS records until the handshake `uint24` length is satisfied before
  parsing extensions. (This is the deep reason G6 matters; it's not an edge
  case anymore.)
- **ECH advisory + graceful degradation.** With Encrypted Client Hello (ECH;
  draft-ietf-tls-esni — *verify: reportedly RFC 9849, 2026*; extension
  `0xfe0d`), an observer without the ECH key sees only the **outer**
  `public_name`, not the real inner SNI. Also **GREASE ECH** (RFC 8701) is
  byte-indistinguishable from real ECH, so *presence of `0xfe0d` implies
  nothing*. Requirements: expose `ech_present: bool` (advisory only — never
  route/fail differently on it) and always surface the **outer SNI**; the
  routing **degradation ladder** is: inner SNI/ALPN (only if the proxy is an
  ECH decryption point with the key) → outer/plaintext SNI + ALPN → JA4 /
  first-byte class → Raw passthrough. `TlsClientHello` already carries ECH
  fields; make sure the "degrade, don't error on 0xfe0d" contract is explicit.

**Closes:** #46 groundwork (bridge sets rustls ALPN from what flowscope
reports), robustness of SNI routing under PQ/ECH.

#### R7. Observability wiring for the inline path (G7)

**Problem.** The bridge has zero metrics/health. flowscope's `emit/*` + `obs`
exist but are wired for the telemetry path.

**What the bridge needs.**
- The inline/streaming path should still be able to **emit the same flow
  records + `flowscope_*` metrics** (access logs in EVE/Zeek/NDJSON, per-flow
  bytes/duration/status) as telemetry mode — i.e. the streaming parser feeds
  `obs`/`emit` too, not just the buffering one. A toggle or a shared emit hook.
- **JA4 (client)** as a cheap, stable observability/routing dimension (one
  SHA-256 over sorted GREASE-stripped lists; survives Chrome ext-shuffle that
  broke JA3). Keep it in the BSD core; keep JA4S/JA4H behind `ja4plus`.
- **Health/readiness is NOT flowscope's job** — `/healthz`/`/readyz` live in
  the bridge (modeled on netring's `MonitorHealth` shape, copy-not-depend).
  Flag this boundary so the implementer doesn't add HTTP endpoints to a pure
  parser lib.

**Closes:** G7 (the parser-provided half).

#### R8. Bounded buffers = backpressure primitive (D2 support)

**Problem.** The bridge's worst scaling bug (D2) is head-of-line blocking from
unbounded/blocking buffering. The sans-IO `push()` model is the fix *at the
parse layer*: the caller stops reading the socket when downstream is slow.

**What the bridge needs.** Guarantee flowscope **never** buffers a whole body
and that `push()` semantics let the caller pace reads (consume-what-you-can,
re-feed the rest, or an explicit `NeedMore`). Every internal buffer bounded +
poison-on-exceed. (The Zenoh-session HOL fix is bridge-side; flowscope's job
is to not be the unbounded buffer.)

**Supports:** D2.

---

### P2 — HTTP/2, gRPC, and HTTP/3 routing (large, optional)

#### R9. HTTP/2 + HPACK + gRPC per-stream router

**Problem.** flowscope has *classify-only* h2 ("HTTP/2 out of scope"); no
frame/HPACK parser, no `ParserKind::Http2`. Terminated-gRPC routing needs it.
(Note: gRPC-**over-TLS** already works for the bridge via SNI passthrough —
this is only for the **terminated/decrypted** h2 case, `--https-terminate`.)

**What the bridge needs (minimum to extract a per-stream routing key).** A
sans-IO h2 parser that:
- consumes the 24-octet **preface**, then the 9-octet frame header loop
  (RFC 9113 §4.1): Length(24) Type(8) Flags(8) R(1) StreamID(31);
- maintains **one HPACK decoder per connection** (RFC 7541), fed **every**
  HEADERS/CONTINUATION block **in receive order** (incremental-indexing
  entries are referenced later — you cannot skip blocks you don't care about);
  static table 1–61, dynamic FIFO bounded by `SETTINGS_HEADER_TABLE_SIZE`;
- reassembles a field block across HEADERS + CONTINUATION until `END_HEADERS`
  (no interleaving), **per Stream ID**;
- emits, per stream, a `RequestHead`-equivalent with the pseudo-headers
  `:method` `:scheme` `:authority` `:path` (they precede regular fields) plus
  `content-type`;
- for **gRPC**: `:path = /package.Service/Method`, `content-type:
  application/grpc*`, DATA = Length-Prefixed-Message (1-byte flag + 4-byte BE
  length + message), status in **trailers** (`grpc-status`, incl.
  Trailers-Only = one HEADERS frame). Surface `:path`/`:authority` for
  routing; DATA is not needed to route.
- respects `SETTINGS_MAX_FRAME_SIZE`/`MAX_HEADER_LIST_SIZE` as memory bounds;
  handles RST_STREAM/GOAWAY for stream/connection teardown; a pure router can
  ignore WINDOW_UPDATE (a forwarder relays it).

This is a **large, self-contained new parser** (`src/http2/`, `http2` feature,
`ParserKind::Http2`). Model the event shape on R1 (Head/Body/Trailers/End, but
keyed by Stream ID). It's genuinely Phase C — the bridge does not block on it.

**Closes:** #50, terminated-gRPC routing by `:authority`.

#### R10. HTTP/3 / DoH routing via the existing QUIC Initial

**Problem/opportunity.** flowscope already extracts SNI/ALPN from the QUIC
Initial (AEAD-decrypt). For future h3 routing the bridge would reuse that.

**What the bridge needs.** Nothing new short-term — just keep the QUIC Initial
SNI/ALPN path ergonomic and feed it through `app_proto::from_quic_initial`.
Full h3 (QPACK + streams) is far-future and out of scope here. Noted so the
implementer sees the through-line: the R1 event model should be reusable for
an eventual h3 parser.

---

## 4. Suggested phasing (maps to the bridge roadmap)

| Phase | flowscope work | Bridge payoff | Size |
|---|---|---|---|
| **A** (mostly done) | Land the `spike/inline-streaming` request side; ensure `TlsParser` SNI+ALPN + PQ/segment reassembly is ergonomic | Adopt TLS parser → **G6** closed; request-head routing | S |
| **B** (core) | **R1–R4**: streaming exchange (Head/Body/Trailers/End), method-aware + 1xx + tunnel detection, §6.3 reject/normalize + poison, pipelining; **R5** first-byte classifier | Delete `http_parser.rs` + `http_response_parser.rs` + `read_full_request`; fixes **E1–E6, F3, D4, G1**; firms `--auto-import` | **L (the main lift)** |
| **B+** | **R6** ALPN/ECH surface, **R7** obs/emit for inline + JA4, **R8** bounded-buffer guarantees | **#46**, **G7**, **D2** support | M |
| **C** (optional) | **R9** h2+HPACK+gRPC per-stream router; **R10** h3 groundwork | Terminated-gRPC routing (**#50**) | **XL** |

**Ordering rationale:** B is the high-leverage core — one streaming exchange
parser closes the entire multiroute correctness backlog and lets the bridge
delete its most bug-prone code. A is nearly free (spike). C is large and only
needed for the *terminated* h2/gRPC niche (SNI passthrough already covers
gRPC-over-TLS), so it should not gate B.

---

## 5. API-design principles (cross-cutting, from production proxies)

- **Sans-IO, caller-drives-I/O** (rustls `read_tls`/`process_new_packets`,
  quinn-proto events, httparse `Partial/Complete`). `push(bytes) -> consumed`
  + drain events; no sockets/async/time inside.
- **Head → Body(chunks) → Trailers → End**, never whole-message buffering
  (h2 `RecvStream`, Pingora body filters). Body chunks are zero-copy `Bytes`.
- **Independently advanceable request/response state** — the response reader
  must run the moment request headers are forwarded (the 100-continue
  deadlock fix).
- **Carry the request method into response framing** — mandatory for
  HEAD/CONNECT (§6.3 rules 1–2).
- **Framing + smuggling defense live *inside* the state machine**, not in the
  caller — httparse stops at headers; that boundary is exactly the CVE
  surface, so flowscope must own it and poison on violation.
- **Header transparency**: preserve original header case + raw (non-UTF-8)
  bytes for forwarding (Pingora wraps `http` types with a case side-table).
  The bridge forwards headers it doesn't read; don't lossy-normalize them.
- **Explicit `SwitchProtocols` terminal state** for WebSocket(101)/CONNECT(2xx)
  /h2-preface → caller tunnels raw.
- **Everything `#[non_exhaustive]`**; new variants stay non-breaking; take the
  major bump only for the new parser type.

---

## 6. Test & fuzz expectations (flowscope-side)

- Property tests: split-invariance for the streaming parser (byte-at-a-time ==
  one-shot) for Head/Body/Trailers/End, both directions — extend
  `tests/parser_proptest.rs` (the spike added the inline request cases).
- Smuggling regression suite: CL.TE, TE.CL, TE.TE (obfuscated TE), duplicate
  CL (identical→ok, differing→poison), CL+TE→poison, obs-fold, bare CR — each
  asserting `is_poisoned()` + reason, not silent acceptance.
- Method-aware framing: HEAD with `Content-Length` → no body; 1xx loop
  (100/103 then final); 204/304 no body; CONNECT 2xx → `SwitchProtocols`.
- Extend the CI-smoked `fuzz/fuzz_targets/http.rs` (spike added the inline
  pass) with the h2 target when R9 lands (preface + HPACK dynamic-table
  coherence invariants).
- Keep `cargo-semver-checks` green for additive changes; document the major
  bump if a new parser *type* reshapes the public surface.

---

## 7. Reference index (verify recent RFC numbers before quoting)

- HTTP/1.1 framing & smuggling: **RFC 9112** (§2.2 bare CR, §5.2 obs-fold,
  §6.1–6.3 body length + TE/CL, §7 chunked); **RFC 9110** (§9.3 methods,
  §10.1.1 Expect/100-continue, §15.2 1xx, §7.8/§15.2.2 Upgrade/101, §9.3.6
  CONNECT). Smuggling taxonomy: PortSwigger "HTTP Desync Attacks" (CL.TE/
  TE.CL/TE.TE). **RFC 8297** 103 Early Hints.
- HTTP/2 & HPACK: **RFC 9113** (§3.3 prior-knowledge, §3.4 preface, §4.1
  frames, §6.x frame types, §6.10 CONTINUATION, §8.3 pseudo-headers; §3.1
  deprecates h2c-upgrade); **RFC 7541** (static table App. A, dynamic table,
  Huffman App. B). gRPC-over-HTTP2 PROTOCOL doc.
- WebSocket: **RFC 6455** (§4 handshake, §4.2.2 accept, §5 framing);
  **RFC 8441** (WS over h2, `SETTINGS_ENABLE_CONNECT_PROTOCOL=0x08`, Extended
  CONNECT `:protocol=websocket`, success=2xx); **RFC 9220** (WS over h3).
- TLS: **RFC 8446** (§4.1.2 ClientHello, §4.2 extensions, §5.1 records);
  **RFC 6066** §3 SNI; **RFC 7301** ALPN; IANA TLS ExtensionType + Supported
  Groups (X25519MLKEM768 = **0x11EC**, block 0x11EB–0x11ED). PQ hybrid:
  draft-ietf-tls-ecdhe-mlkem, draft-ietf-tls-hybrid-design (**verify final
  RFC numbers**); ML-KEM = **NIST FIPS 203**. ECH: draft-ietf-tls-esni →
  **reportedly RFC 9849** + SVCB carriage **RFC 9848**, ext `0xfe0d`, SVCB
  `ech` key = 8 (**verify all three numbers on datatracker/IANA**). GREASE:
  **RFC 8701**.
- Fingerprints: JA3 (Salesforce, BSD), JA4 (FoxIO — **JA4 client = BSD**;
  JA4S/JA4H/etc = **FoxIO License 1.1, non-commercial**).
- sans-IO exemplars: rustls, quinn-proto, httparse; Cloudflare Pingora
  (`pingora-proxy` body filters), the `h2` crate (`RecvStream`). ALPACA
  cross-protocol attack (bind protocol to ALPN+SNI).
