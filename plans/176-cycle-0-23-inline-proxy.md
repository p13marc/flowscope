# Plan 176 — 0.23 inline-proxy cycle (sans-IO streaming L7 core)

**Milestone:** [Inline-grade: sans-IO L7 core for inline proxies](https://github.com/p13marc/flowscope/milestone/3)
**Epics:** #172 (streaming HTTP/1.1 exchange) · #173 (classification & TLS routing) · #174 (h2/HPACK/gRPC)
**Inputs:** `plans/requirements-inline-proxy.md` (R1–R10 spec) · `plans/spike-inline-streaming.md` (feasibility, GO)
**Convention:** delete this file in the PR series that ships the cycle; `CHANGELOG.md` + `docs/migration-0.22-to-0.23.md` are the durable record.

## Verified standards facts (live research, 2026-08-02 — supersedes the requirements doc's citations)

| Claim | Verdict |
|---|---|
| ECH = RFC 9849 | **Confirmed** (published March 2026) |
| ECH SVCB carriage = RFC 9848 | **Confirmed** |
| SVCB `ech` SvcParamKey = 8 | **Wrong — it is 5** (IANA, per RFC 9848) |
| X25519MLKEM768 final RFC | **Not yet an RFC** — draft-ietf-tls-ecdhe-mlkem-05, IESG-approved, RFC Editor queue (July 2026). Cite the draft. |
| X25519MLKEM768 = 0x11EC; ML-KEM = FIPS 203 | Confirmed |

## Defects found during the cycle audit (fixed in #160 / #163)

1. `parser::eof()` (`parser.rs:272`) mem::replaces state with `Desynced` → clean FIN on idle keep-alive poisons an inline parser. Outside fuzz coverage (no `fin_*` pass).
2. Telemetry mode never frames/decodes chunked (`has_chunked_encoding` unreachable without the spike flag) → raw chunk framing in `HttpRequest::body` or desync.
3. `HttpExchangeParser` enqueues the method at body completion (too late for response framing), drops `RequestHead` silently, `HttpOutcome::Reset` unreachable.
4. Duplicate/conflicting `Content-Length` accepted (first wins); TE+CL co-presence accepted.
5. `find_crlf` O(n²) on slow-fed chunk lines; no caps on chunk-size line / trailer block.
6. Hot-path allocs: `vec![EMPTY_HEADER; 64]` per `step()`; `Vec::new()` per exchange `feed_*`.
7. `slice_in` single-Arc header trick relies on unchecked pointer-provenance `unsafe`.

Also (driver, #166): heuristic probe never replays probed bytes into the pinned parser; `NoMatch` treated as `NeedMoreData` (no fast-fail); `Pinned`/`GaveUp` map entries never expire.

## Design decisions of record

- **D1 — Both shapes.** Standalone `HttpProxyParser` in `src/http/proxy.rs` (owns both directions; `push(dir: FlowSide, &Bytes) -> crate::Result<usize>` consumed-count backpressure; `fin(dir)`; `next_event() -> Option<HttpEvent>`; `is_poisoned`/`poison() -> Option<HttpPoison>`/`is_done`) + a thin `HttpProxySession: SessionParser` adapter for Driver/pcap/obs. Reuse `FlowSide`; no new `Dir` enum. Rationale: `SessionParser`'s `&mut Vec<Message>` sink cannot express backpressure or borrowed output.
- **D2 — Owned events, refcounted `Bytes`, no lifetimes.** `HttpEvent { RequestHead, ResponseHead, Body{dir, data, raw}, Trailers{dir, trailers, raw}, End{dir}, SwitchProtocols{kind} }`; `data` = decoded payload, `raw` = exact wire bytes. Forwarding invariant (proptested): `head.raw ++ Σ Body.raw ++ Trailers.raw` == wire bytes. `SwitchKind { ConnectTunnel, Upgrade{protocol}, Http2PriorKnowledge }`. No `NeedMore` variant (push's consumed count conveys it). Rationale: a lending `HttpEvent<'a>` forbids holding the head while draining, and kills any `'static` adapter; `Bytes::slice_ref` gives the same zero-copy safely (h2/Pingora shape).
- **D3 — One shared engine, two front-ends.** `parser.rs` → `engine.rs` (pub(crate), zero semver cost): always streams internally. Telemetry `HttpParser` aggregates (chunked fix once, for both); proxy forwards events. `RequestHead` extended with `raw: Bytes` + `applied: Vec<Normalization>`; new `ResponseHead { status, reason, version, headers, framing, interim, raw, applied }`. Rename `BodyFraming::UntilEof` → `UntilClose`.
- **D4 — Method threading inside the parser.** `pending: VecDeque<ReqCtx{is_head, is_connect}>` enqueued at `RequestHead` emission (the 100-continue deadlock fix — responder frameable the instant request headers parse). 1xx loop (`interim: true`, don't pop); HEAD/204/304 → `framing: None`; CONNECT-2xx / 101 → `SwitchProtocols` + Tunnel (push consumes 0, `is_done`). Bounded by `max_pipelined`. Empty-queue response: poison in proxy mode (`UnexpectedResponse`), tolerated in `Observe`.
- **D5 — Typed smuggling defense.** `SmugglingPolicy { Strict (proxy default), Normalize, Observe (telemetry-only) }`; `Normalization { StrippedContentLength, CollapsedContentLength, ObsFoldToSpace, BareCrToSpace }`; `HttpPoison` enum (~19 variants, `as_str()` feeds `poison_reason()`). §6.3 table lives in the engine, shared by both front-ends:

  | Violation | Strict | Normalize | Observe |
  |---|---|---|---|
  | CL + TE both present | poison | strip CL, frame Chunked | TE wins |
  | Duplicate CL, identical | collapse | collapse | collapse |
  | Duplicate/differing CL | poison | poison | desync (today) |
  | TE non-final chunked / unknown coding | poison | poison | desync |
  | TE.TE obfuscation | poison | poison | best-effort |
  | obs-fold | poison | → SP | accept |
  | bare CR | poison | → SP | accept |
  | Duplicate `Host` | poison | poison | first wins |

  F3: `RequestHead::authority() -> Result<Authority, HttpPoison>` — absolute-form wins over `Host`, duplicate-Host reject, `to_ascii_lowercase` only (U+212A hazard). `Authority { raw, host, port }`; consumer key policy stays consumer-side.
- **D6 — Separate `HttpProxyConfig`** (field-mutation style): `max_head_bytes` 64 KiB, `max_headers` 128, `max_chunk_line_bytes` 256, `max_trailer_bytes` 8 KiB, `max_pipelined` 64, `max_event_queue` 1024 (throttles, doesn't poison), `smuggling: Strict`.
- **D7 — Spike API superseded.** `HttpConfig::inline_streaming` and `HttpMessage::RequestHead` never ship (0.22.0 predates them); skip-state machinery recycled into the engine; spike tests/fuzz invariants ported to `HttpProxyParser`.
- **D8 — No new Cargo feature.** Everything under `http` (pure compute, no new deps). Layout: `engine.rs` (pub(crate)), `proxy.rs`, reshaped `session.rs`/`exchange.rs`/`types.rs`. h2 gets its own `http2` feature (#170).
- **D9 — PR sequence (breaking-first):** PR1 = #160 engine unification (M–L) → PR2 = #161 HttpProxyParser (L) → PR3 = #162 method-aware framing (M) → PR4 = #163 smuggling (M) → PR5 = #164 adapter + docs (S). Epic #173's issues are independent of each other; #170/#171 sequence after.
- **D10 — Forward-compat.** First-byte classifier (#165) shares the h2-preface constant with `SwitchKind::Http2PriorKnowledge`; R6 is TLS-surface only; the h2 front-end (#170) reuses Head/Body/Trailers/End keyed by stream id — nothing in the 0.23 types is h1-specific except `framing`.

## Issue map

| Issue | Title | PR |
|---|---|---|
| #160 | HTTP engine unification (keystone, breaking) | PR1 |
| #161 | HttpProxyParser sans-IO core (R1/R4/R8) | PR2 |
| #162 | Method-aware response framing (R2) | PR3 |
| #163 | Smuggling defense + authority (R3/F3) | PR4 |
| #164 | HttpProxySession adapter + docs | PR5 |
| #165 | First-byte classifier (R5) | — |
| #166 | Heuristic-probe driver fixes | — |
| #167 | ECH/ALPN routing contract (R6) | — |
| #168 | Inline-path observability (R7) | — |
| #169 | Bounded-memory contract audit (R8) | — |
| #170 | h2 frames + HPACK + per-stream events (R9) | — |
| #171 | gRPC routing surface | — |

## Deferral dispositions

- "Lazy iterator return type on parser `feed_*`/`parse`" (declined twice in INDEX.md): **superseded** — the sans-IO `push`/`next_event` shape is what the third consumer actually needed; do not revive the iterator ask.
- "HTTP/2 passive parser — defer until a consumer asks": **activated** by #170 (terminated-gRPC routing is the consumer).
- "Parser `&mut S` API change": unaffected; the consumer-loop pattern stands.
