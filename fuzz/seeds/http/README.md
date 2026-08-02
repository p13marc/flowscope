# HTTP fuzz seeds

Named starting points for `fuzz_targets/http.rs`, kept in the repo
because each one is a specific framing hazard worth re-exercising
whenever the parser changes. The generated corpus lives in
`fuzz/corpus/` and is not committed.

Run with the seeds mixed in:

```bash
cargo +nightly fuzz run http fuzz/corpus/http fuzz/seeds/http
```

| Seed | Hazard |
|---|---|
| `smuggle-cl-te` | `Content-Length` and `Transfer-Encoding` together (CL.TE) |
| `smuggle-te-cl` | the same, other order, with a real chunked body (TE.CL) |
| `smuggle-te-te` | duplicated `Transfer-Encoding` (TE.TE obfuscation) |
| `smuggle-dup-cl` | two contradictory `Content-Length` values |
| `smuggle-obs-fold` | deprecated obs-fold header continuation |
| `smuggle-dup-host` | two `Host` headers — ambiguous routing key |
| `chunked-trailers` | chunked body with a trailer section |
| `connect` | `CONNECT`, which turns into a tunnel on a 2xx |
| `h2-preface` | HTTP/2 prior-knowledge preface where a request goes |

The deterministic assertions for these live in
`tests/http_smuggling.rs`; the seeds exist so the fuzzer starts from
interesting shapes rather than rediscovering them.
