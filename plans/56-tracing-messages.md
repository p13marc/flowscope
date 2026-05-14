# Plan 56 — `tracing-messages` sub-feature

## Summary

When the `tracing` Cargo feature is enabled today, flowscope emits
`tracing::info!` events on flow lifecycle transitions (created,
ended) and `tracing::warn!` on anomalies. **Per-message** events
(`SessionEvent::Application`) are deliberately not emitted because
high-rate chatty protocols (DNS, HTTP/1.1 keep-alive) can push
50k+ messages/sec — the per-event tracing overhead matters.

But for low/medium-rate protocols (DES PSMSG, MQTT, custom
binary), per-message tracing is exactly the live-debugging signal
operators want. This plan adds a `tracing-messages` sub-feature
that opts in: when both `tracing` and `tracing-messages` are on,
flowscope emits `tracing::trace!` per `SessionEvent::Application`.

Tiny plan — ~50 LOC. The deferred half of item #8 from the
des-rs feedback report.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 40 (observability) — `tracing` feature shipped in 0.2.0.
- Plan 51 (anomaly forwarding) — `FlowSessionDriver` wraps
  `FlowDriver`, so the tracing hook lives in one place.

## Out of scope

- Per-packet tracing (`FlowEvent::Packet` × `trace!`). Way too
  hot — would saturate any subscriber at modest packet rates.
  Operators wanting per-packet visibility should use `RUST_LOG`
  + a custom subscriber, not a flowscope feature.
- Custom span hierarchies (flow → message). The plan emits flat
  events, not nested spans, to keep overhead bounded.
- Configurable trace level. `trace!` is the right level — users
  who want messages in their logs will set
  `RUST_LOG=flowscope.message=trace`.

---

## Files

### MODIFIED

- `Cargo.toml` — add `tracing-messages` feature; depends on
  `tracing`.
- `src/obs.rs` — add `trace_session_message` function, feature-
  gated.
- `src/session_driver.rs` — call the hook on every
  `SessionEvent::Application` emission.
- `src/datagram_driver.rs` (from Plan 57) — same.
- `CHANGELOG.md` — 0.3.0 entry.
- `docs/OBSERVABILITY.md` — extend the "Tracing" section.

### NEW

None.

---

## API

### `Cargo.toml`

```toml
[features]
# (existing features)
tracing-messages = ["tracing"]
```

### `src/obs.rs`

```rust
#[cfg(all(feature = "tracing-messages", feature = "reassembler"))]
pub(crate) fn trace_session_message<M: std::fmt::Debug>(
    side: FlowSide,
    msg: &M,
) {
    tracing::trace!(
        target: "flowscope.message",
        ?side,
        message = ?msg,
        "session message"
    );
}

#[cfg(any(not(feature = "tracing-messages"), not(feature = "reassembler")))]
#[inline(always)]
pub(crate) fn trace_session_message<M>(_side: FlowSide, _msg: &M) {}
```

The hook deliberately uses `?msg` (Debug formatting) rather than
serde or similar — `tracing` doesn't depend on serde, and the
shipped parsers' message types all derive `Debug`. Consumers
writing custom parsers should derive `Debug` on their `Message`
type (already a convention).

The `Message: Debug` requirement is opt-in: only paid when
`tracing-messages` is enabled. We don't add a trait bound on
`SessionParser::Message`; the call site casts `&M` to `&dyn Debug`
via the `?msg` macro.

Wait — `?msg` requires `M: Debug` at the call site. Since the
call site lives in `session_driver.rs`, the bound has to be on
that function. Let me revise: the `trace_session_message` is only
called when the feature is on; the bound only matters then.

The cleanest path: keep `M: Debug` as a runtime requirement only.
Use `tracing::trace!` directly at the call site with a `cfg!`
guard:

```rust
// In session_driver.rs translate_events:
#[cfg(feature = "tracing-messages")]
{
    tracing::trace!(target: "flowscope.message", side = ?side, message = ?m, "session message");
}
```

That requires `m: Debug` only when the feature is on. The
`SessionEvent::Application` consumer of `m` happens regardless;
just one extra reference.

But this means every custom parser's `Message` type must impl
`Debug` if the user enables `tracing-messages`. That's a soft
requirement.

Actually let me simplify: require `Message: Debug` on the
`SessionParser` / `DatagramParser` trait, period. It's a tiny
bound, almost every Rust type ends up with `Debug` derived, and
it makes a bunch of debugging affordances (including this plan)
cheaper.

```rust
pub trait SessionParser: Send + 'static {
    type Message: Send + std::fmt::Debug + 'static;
    // ...
}
```

That's a BC break (existing impls need `Debug` on their Message
types). All four shipped parsers' message types already derive
`Debug`. The example parser does too. Likely free for external
consumers but document the requirement.

### `src/session_driver.rs`

In the `Application` emission path:

```rust
for m in messages {
    crate::obs::trace_session_message(side, &m);
    out.push(SessionEvent::Application {
        key: key.clone(),
        side,
        message: m,
        ts,
    });
}
```

The trace call is a no-op when the feature is off (compile-time
stripped).

---

## Implementation steps

1. **Add `tracing-messages` feature** to Cargo.toml. Depends on
   `tracing`.
2. **Add `Message: Debug` bound** to `SessionParser` and
   `DatagramParser`. Document in CHANGELOG as a BC break. The
   four shipped parsers + example parser already satisfy it.
3. **Add `obs::trace_session_message`** with feature-gated body /
   no-op fallback.
4. **Call from `FlowSessionDriver::translate_events`** on every
   `Application` emission.
5. **Call from `FlowDatagramDriver`** (Plan 57) on every
   `Application` emission.
6. **Update `docs/OBSERVABILITY.md`** "Tracing" section with the
   new sub-feature.
7. **CHANGELOG entry** mentioning the new feature + the
   `Message: Debug` bound addition.

---

## Tests

A simple smoke test verifies the feature compiles and the trace
event fires. Uses `tracing-subscriber`'s test utilities (already
a dev-dep).

```rust
#[cfg(all(feature = "tracing-messages", feature = "session", feature = "extractors"))]
#[test]
fn trace_session_message_fires_on_application_event() {
    use tracing_subscriber::layer::SubscriberExt;
    use tracing_subscriber::util::SubscriberInitExt;

    let captured = std::sync::Arc::new(std::sync::Mutex::new(Vec::<String>::new()));
    let captured_clone = captured.clone();

    let subscriber = tracing_subscriber::registry()
        .with(tracing_subscriber::fmt::layer()
            .with_writer(move || {
                struct W(std::sync::Arc<std::sync::Mutex<Vec<String>>>);
                impl std::io::Write for W {
                    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
                        self.0.lock().unwrap().push(String::from_utf8_lossy(buf).into_owned());
                        Ok(buf.len())
                    }
                    fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
                }
                W(captured_clone.clone())
            }));

    let _guard = subscriber.set_default();

    let mut d = FlowSessionDriver::<_, LineParser>::new(FiveTuple::bidirectional());
    // ... drive a flow that produces messages ...

    let log = captured.lock().unwrap();
    assert!(log.iter().any(|l| l.contains("flowscope.message")));
}
```

This is more invasive than the metrics_integration test; if
`tracing-subscriber` registry composition gets fiddly, fall back
to verifying the call is reachable (no panic, no compile error).
Compile-only test is fine for shipping.

---

## Acceptance criteria

- [ ] `tracing-messages` Cargo feature exists, depending on
      `tracing`.
- [ ] `SessionParser::Message` and `DatagramParser::Message`
      have `Debug + Send + 'static` bound.
- [ ] When `tracing-messages` is on, `tracing::trace!` fires per
      `SessionEvent::Application` (verified by smoke test or
      manual run).
- [ ] When `tracing-messages` is off, the trace call is a no-op
      (compile-time stripped).
- [ ] `docs/OBSERVABILITY.md` documents the new sub-feature.
- [ ] CHANGELOG entry under 0.3.0; migration note for the
      `Message: Debug` bound (likely a no-op for most consumers).
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **`Message: Debug` bound break.** All four shipped parsers'
   Message types derive Debug; the example parser does too.
   Likely free for external consumers but document in CHANGELOG.
2. **Trace event volume.** At 50k messages/sec, even
   `trace!`-level events are expensive when a subscriber is
   attached. The feature is opt-in for exactly this reason;
   document in OBSERVABILITY.md that consumers should set
   `RUST_LOG` to gate the level appropriately.
3. **Privacy concerns.** Per-message `?msg` formatting may emit
   sensitive payload bytes (HTTP headers, etc.). Document; users
   who care about leaks should not enable the feature in
   production environments without scrubbing their Debug impls.

---

## Effort

- LOC: ~40 (feature gate + obs hook + call site + Debug bound +
  doc).
- Tests: ~50 LOC smoke test.
- Time: ¼ day.

---

## Provenance

Item #8 from the des-rs feedback report
(`plans/flowscope-feedback-2026-05-14.md`) — "Tracing spans by
default on Application events". Initially deferred in Plan 45's
rejected-proposals section as "low value, easy to do — defer to
follow-up release." On second look, it really is cheap; the
soft `Message: Debug` bound is the only friction point and is
easy enough to swallow pre-1.0.

The `target: "flowscope.message"` namespace makes it easy for
operators to filter:
- `RUST_LOG=flowscope=info` — flow lifecycle only.
- `RUST_LOG=flowscope=info,flowscope.message=trace` — add
  per-message visibility.
- `RUST_LOG=flowscope.anomaly=warn` — anomalies only.
