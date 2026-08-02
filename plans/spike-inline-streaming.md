# Spike: HTTP inline-streaming mode for inline proxies

**Branch:** `spike/inline-streaming` · **Baseline:** flowscope 0.22.0 (`master`)
**Question:** can flowscope's `HttpParser` be extended to serve an inline
proxy (route on headers before the body, stream the body without
buffering it), and how invasive is it? · **Verdict: GO.**

---

## 1. Why this spike exists

flowscope's `HttpParser` is built for **passive telemetry**: it buffers a
message's whole body in RAM and emits one `HttpMessage::Request` /
`Response` (`parser.rs` `DirState::Body` arm). An **inline proxy**
(zenoh-bridge-tcp's `--http-import` / multiroute router) needs the
opposite: the `Host`/method the instant the headers arrive, then it
streams the raw body onward and must *not* retain it. On the 0.22 API
there is no way to get a header-complete request without buffering the
body, and chunked bodies aren't framed at all. That mismatch is the only
thing blocking the bridge from replacing its ~2,000 lines of hand-rolled
`http_parser.rs` / `http_response_parser.rs` / multiroute framing with
flowscope as a shared, fuzz-tested L7 core.

This spike adds an **opt-in inline-streaming mode** and measures the cost.

## 2. What was built (all additive, default OFF)

New public API (`src/http`):

- `HttpConfig::inline_streaming: bool` (default `false`).
- `BodyFraming { None, ContentLength(u64), Chunked, UntilEof }` — how the
  body is delimited, computed at header time.
- `RequestHead { method, path, version, headers, framing }` + accessors
  (`host()`, `method_str()`, `path_str()`, `content_length()`, `header()`,
  `headers_all()`).
- `HttpMessage::RequestHead(RequestHead)` variant.

Behaviour when `inline_streaming = true` (request side only):

1. At header completion the parser emits `RequestHead` **before any body
   byte is read**, carrying the routing metadata + `BodyFraming`.
2. It then **drains and discards** the body per that framing —
   Content-Length, **chunked** (a real chunk-size/data/trailer skip state
   machine), or until-EOF — so the next request boundary is found on
   keep-alive/pipelined connections **without ever buffering the body**
   (`step()` `SkipBody` / `SkipChunked` / `SkipUntilEof` arms, bounded by
   the existing `max_buffer` guard which now never trips on large bodies
   because each step empties the buffer).
3. A framing desync **poisons** the parser (`is_poisoned()` /
   `poison_reason()`), so the driver tears the flow down instead of
   forwarding smuggled bytes. Poison is gated on `inline_streaming`, so
   telemetry behaviour is byte-for-byte unchanged.

Not done (deliberately, out of spike scope — see §6): chunked **decode**
for the telemetry path, HEAD/1xx/204/304-aware **response** framing, and
`is_done()` completion signalling. These are Phase B and are documented,
not prototyped.

## 3. Blast radius

```
 src/http/types.rs        | +104   (BodyFraming, RequestHead, config flag)
 src/http/parser.rs       | +231/-2 (skip states + chunk skip + framing calc)
 src/http/session.rs      | +165/-1 (variant wiring, is_poisoned, 7 tests)
 src/http/mod.rs          | +21/-2  (re-exports + docs)
 tests/parser_proptest.rs | +66     (3 inline property tests)
 fuzz/fuzz_targets/http.rs| +21     (inline pass + no-full-Request invariant)
 6 files, +608 / -7
```

The heavy lifting is concentrated in `parser.rs`; every other change is
small and additive. **No existing function signature changed** (the
`pub(crate)` `step`/`DirState`/`ParseOutput` internals grew arms/variants;
public types only gained `#[non_exhaustive]` variants/fields).

## 4. Verification (all green on this branch)

| Gate | Result |
|---|---|
| `cargo test --all-features` | **pass**, 0 failures (incl. 7 new inline unit tests + 3 inline proptests) |
| `cargo clippy --all-targets --all-features` | **clean** |
| `cargo fmt --check` | **clean** |
| `cargo semver-checks check-release --all-features` (vs `master`) | **196 checks pass, "no semver update required"** — fully non-breaking |
| `cargo +nightly fuzz run http` | 200,000 runs, **no panic** (both telemetry + inline passes) |
| Existing telemetry tests (flag off) | **unchanged** — same messages, no poison on desync |

The load-bearing test: a `POST … Content-Length: 1000` fed **headers-only**
emits exactly one `RequestHead{framing: ContentLength(1000)}` immediately,
and the subsequent 1000 body bytes produce **no message and are never
buffered** (`inline_post_emits_head_before_body_is_fed`). Chunked bodies
are skipped and the next pipelined request is located cleanly
(`inline_chunked_head_then_boundary_found`).

## 5. Bridge API-fit (decision-grade)

zenoh-bridge-tcp `src/import/multiroute.rs` today runs, per request:
`parse_http_request` → `parsed.dns` (Host, normalized + key-validated) →
`check_backend_available` → publish → `read_full_request` (which itself
hand-rolls `http_response_parser::find_chunked_body_end` for chunked and
manual Content-Length accounting). It also has the E6 smuggling stall and
E4 100-continue bugs living in that bespoke framing.

Mapping onto the new API — the parser becomes a **framing oracle beside
the data path** (the bridge still owns the socket reads and forwards the
raw bytes; it feeds a copy to an inline `HttpParser` to learn boundaries):

| Bridge need today | Replaced by |
|---|---|
| `parse_http_request` → headers, `method`, `header_len` | `HttpMessage::RequestHead` (emitted before body) |
| `parsed.is_chunked` / `parsed.content_length` | `RequestHead.framing: BodyFraming` |
| `read_full_request` + `find_chunked_body_end` + CL loop | drive the parser until it consumes the body (`SkipChunked`/`SkipBody`) → boundary known; delete the bespoke body reader |
| E6 "swallowed parse error → stall" | `is_poisoned()` → tear down the flow |
| routing key `parsed.dns` | `RequestHead.host()` |

What stays bridge-side (correctly): `normalize_dns` + `validate_dns_for_key`
(F1 key-safety is bridge policy, not parsing) applied to
`RequestHead.host()`. What flowscope removes: all of the bridge's HTTP
*parsing and framing*, i.e. `http_parser.rs` + `http_response_parser.rs` +
the `read_full_request` loop.

**Conclusion:** the API genuinely *removes* the bridge's bespoke framing
rather than relocating it, and folds E6/E4-class bugs into a fuzz-tested
parser. The one behavioural note: flowscope inline mode discards the body,
so the bridge feeds a byte copy purely for boundary/desync tracking — the
raw bytes still flow over Zenoh unchanged.

## 6. Remaining work to productionize (post-spike)

1. **Response framing (Phase B)** — HEAD/1xx/204/304-aware, chunked
   *decode*, `is_done()`. This needs the request method threaded into the
   response direction; `HttpExchangeParser` already retains the method in
   `pending`, so it belongs there. This is what lets the bridge also
   replace `http_response_parser.rs`. Estimated moderate (a second pass
   comparable to this one).
2. **Bridge migration** — swap multiroute + `connection.rs` onto
   `RequestHead`/`BodyFraming`, delete the bespoke modules, diff against
   the bridge's regression net (already built). Small–moderate once (1)
   lands.
3. Optional: expose a helper that returns "bytes consumed for the body so
   far" if a consumer wants exact per-body accounting without re-deriving
   it.

None of the above threatens flowscope's no-CAP / no-root / cross-platform
posture — the whole `src/http` module is pure compute (verified: zero
async/tokio/libc/socket), and these additions keep it that way.

## 7. Recommendation — GO

The inline mode is additive, non-breaking, fuzz-clean, and demonstrably
fits the bridge's routing loop while deleting its most bug-prone code. The
request side is done in this spike; the response side (Phase B) is a
well-scoped follow-up on the same pattern. Recommend committing the bridge
to flowscope as its shared L7 core, sequenced as: land this request-side
mode → Phase B response framing → migrate the bridge (behind its
regression net) → delete the bespoke parsers.
