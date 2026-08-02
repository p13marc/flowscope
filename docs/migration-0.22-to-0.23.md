# Migrating from 0.22 to 0.23

The 0.23 cycle turns flowscope into a usable L7 core for **inline
proxies**, not only for passive observation — the milestone
[*Inline-grade: sans-IO L7 core for inline proxies*](https://github.com/p13marc/flowscope/milestone/3).
The HTTP/1.x parser was rebuilt around a single streaming engine
shared by the passive front-end and the new inline one.

Most of this cycle is additive. The compile-time break is small, but
**HTTP framing behaviour changed in several places** — every change
is a bug fix, and each one is listed below because it can alter what
your pipeline observes.

## 1. `BodyFraming::UntilEof` → `UntilClose` (#160)

RFC 9112 calls this "delimited by connection close", so the variant
now matches the specification's language.

```rust
// Before:
matches!(framing, BodyFraming::UntilEof)

// After:
matches!(framing, BodyFraming::UntilClose)
```

`BodyFraming` was added after 0.22.0 was published, so no released
version of flowscope ever exposed the old name — this affects only
code built against `master`.

## 2. HTTP behaviour changes (all fixes) (#160)

No API changed here; the parser simply frames messages correctly
where it previously did not. If you assert on parsed output, review
these.

### Chunked bodies are decoded

`Transfer-Encoding: chunked` was never framed on the telemetry path.
Depending on the method, the raw chunk framing landed inside
`HttpRequest::body`, or the direction desynced and dropped every
following message on that connection.

```rust
// Wire: "POST /u HTTP/1.1\r\nTransfer-Encoding: chunked\r\n\r\n\
//        5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"

// Before: body == b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"  (or nothing at all)
// After:  body == b"hello world"
```

Trailer fields (`0\r\nX-Checksum: ...\r\n\r\n`) are appended to the
message's `headers` list, after the head's own fields.

### A clean FIN is no longer a parse error

End of stream on an idle keep-alive connection used to force the
direction into a desynced state, which a driver surfaced as
`EndReason::ParseError` plus a `SessionParseError` anomaly. A FIN
that arrives between messages is now simply the end of the stream.
Expect fewer spurious parse-error flow endings.

### `HEAD`, `1xx`, `204`, `304` responses are bodyless

Per RFC 9112 §6.3 rules 1–2, these responses never carry a body even
when they advertise `Content-Length` or `Transfer-Encoding`. The
parser now tracks the request method to apply this.

```text
Before: HEAD response with "Content-Length: 100" consumed the next
        100 bytes — i.e. the following response — as its body.
After:  the HEAD response is complete at its blank line, and the
        following response parses normally.
```

### Requests without a length have no body

Per §6.3 rule 6, a request carrying neither `Content-Length` nor
`Transfer-Encoding` has no body regardless of method. Previously a
bodyless `POST` ran to end of stream and swallowed any pipelined
requests behind it.

### `HttpOutcome::Reset` is now produced

`HttpExchangeParser` used to discard in-flight requests on reset, so
the `Reset` variant was unreachable. Requests that were awaiting a
response when the flow reset are now reported with that outcome (at
`fin_*`, since `rst_*` has no output channel). If you match
exhaustively on `HttpOutcome`, this arm can now fire.

## 3. Removed: the `inline_streaming` config flag

If you built against `master` between the `spike/inline-streaming`
work and this cycle, `HttpConfig::inline_streaming` and
`HttpMessage::RequestHead` no longer exist. They were spike surface
that never shipped to crates.io. The capability they prototyped —
routing on the head before the body, without buffering it — is the
inline front-end delivered by issue #161, with a proper streaming
API (`Head` → `Body` → `Trailers` → `End`) rather than a mode flag
on the telemetry parser.

## 4. Smuggling defense is on by default for the streaming parser

`HttpProxyParser` defaults to `SmugglingPolicy::Strict`, so a message
whose framing is ambiguous poisons the connection instead of being
forwarded. If you were relying on best-effort framing, choose the
policy explicitly:

```rust
let mut cfg = HttpProxyConfig::default();
cfg.smuggling = SmugglingPolicy::Normalize;   // fix what §6.3.3 allows
// or SmugglingPolicy::Observe                // never poison
```

The passive `HttpParser` is hard-wired to `Observe` and cannot poison
a monitored flow — telemetry behaviour is unchanged.

Under `Normalize`, check `head.applied`: a non-empty list means the
head's `raw` bytes are **not** safe to forward verbatim, because they
still carry the ambiguity. Re-serialize from the parsed headers.

## 5. Reassembly is bounded by default (#188)

`FlowTrackerConfig::max_reassembler_buffer` changed from `None` to
`Some(1 MiB)` per side. The default configuration now has a per-flow
reassembly bound; previously a single flow whose parser never consumed
could grow one buffer per direction without limit.

The existing `OverflowPolicy::SlidingWindow` default applies, so a
flow that exceeds the cap **survives**: the oldest bytes are dropped
and counted in `FlowStats::reassembly_bytes_dropped_oversize_initiator`
/ `_responder`. Truncation is visible, not silent — check those
counters if a parser starts seeing gaps it did not see in 0.22.

If you legitimately need more (large file transfers reassembled whole,
say), raise it rather than removing it:

```rust
let mut cfg = FlowTrackerConfig::default();
cfg.max_reassembler_buffer = Some(16 * 1024 * 1024);
```

`None` still means unbounded and is still supported — it is only safe
when you control the traffic.

## 6. Cleanup no longer depends on `Ended` being emitted (#185)

If you shed events with `EventMask::ENDED`, per-flow reassemblers and
parsers used to stay resident for the life of the driver, because
teardown keyed off the `Ended` event while the tracker reaped the flow
regardless. Every sweep now reconciles against the tracker and
releases what belongs to flows that are gone, refunding their memcap
bytes.

No API change and nothing to migrate — but if you avoided
`EventMask::ENDED` because of this, you no longer need to. A parser
reclaimed this way gets no `fin_initiator` / `fin_responder` call:
there is no `Ended` event to attach the resulting messages to, and a
consumer suppressing `Ended` has said it does not want them. Flows
that end normally are unaffected and still get their final tick, fin,
and `Closed`.

## Additive — no migration needed

- The internal streaming engine (`src/http/engine.rs`) is
  `pub(crate)`; nothing about it appears in the public API.
- Performance work (stack-resident header scratch, refcounted body
  spans instead of copies, resumable line scanning) is transparent.
- `src/http` no longer contains any `unsafe`.
