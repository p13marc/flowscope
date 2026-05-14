# Plan 57 — `FlowDatagramDriver` (UDP sync mirror)

## Summary

`FlowSessionDriver` (Plan 25 §1, shipped in 0.2.0) is the sync
mirror of netring's async `session_stream` for TCP-based
`SessionParser`s. The UDP side has no equivalent: `DatagramParser`
is a public trait but the only sync way to consume one today is
to drive `FlowTracker` directly, extract the UDP payload by hand,
and route to a per-flow `DatagramParser` instance. Every
consumer does the same boilerplate.

This plan ships `FlowDatagramDriver<E, P, S>` — the sync mirror
of netring's async `datagram_stream`. Same shape as
`FlowSessionDriver`, no reassembler (UDP doesn't need one), just
tracker + per-flow `DatagramParser` + UDP-payload extraction.

## Status

Not started. Targets 0.3.0 ([Plan 45](./45-release-0.3.0.md)).

## Prerequisites

- Plan 25 §1 (`FlowSessionDriver`) — shipped in 0.2.0. The sync
  session driver shape that this plan mirrors.
- `DatagramParser` trait — shipped in 0.2.0 (Plan 31).
- Coordinates with Plan 55 (parser fallibility) — the
  `is_poisoned()` synthesis lives here too.
- Coordinates with Plan 56 (`tracing-messages`) — the per-message
  trace hook fires from this driver.

## Out of scope

- A `Conversation`-style aggregator for UDP. UDP doesn't have a
  flow direction the way TCP does (no SYN-defined initiator),
  but `FiveTuple::bidirectional()` still canonicalises the
  endpoint pair — sufficient for a sync `DatagramParser`.
- Encryption-aware UDP (DTLS / QUIC). Standard `DatagramParser`
  for UDP just routes plaintext payloads; DTLS/QUIC handling is
  the parser's responsibility.
- UDP reassembly (IP fragments). That's Plan 50.5 territory and
  remains deferred.

---

## Files

### NEW

- `src/datagram_driver.rs` — `FlowDatagramDriver<E, P, S>`.

### MODIFIED

- `src/lib.rs` — register and re-export `FlowDatagramDriver`
  behind `feature = "session"` (same as `FlowSessionDriver`).
- `CHANGELOG.md` — 0.3.0 entry.
- `docs/SESSION_GUIDE.md` — extend "Sync vs async session
  driving" subsection to mention the datagram analog.

### Possibly MODIFIED

- `src/tracker.rs` — *maybe* extend
  `FlowTracker::track_with_payload` to also fire the callback
  for UDP packets. See "UDP payload extraction" below.

---

## API

### `src/datagram_driver.rs`

```rust
//! Sync companion to netring's async `datagram_stream`. Owns a
//! `FlowTracker` and one `DatagramParser` per flow. Yields
//! `SessionEvent`s per UDP packet — `Started` on first sight,
//! `Application` per parsed message, `Closed` on flow end.
//!
//! Use this when you want typed L7 messages from a synchronous
//! loop driving UDP traffic (DNS-over-UDP, syslog, SNMP, NTP,
//! custom binary datagram protocols).

use std::collections::HashMap;
use std::hash::Hash;

use ahash::RandomState;

use crate::event::{EndReason, FlowEvent, FlowSide};
use crate::extractor::FlowExtractor;
use crate::session::{DatagramParser, SessionEvent};
use crate::tracker::{FlowTracker, FlowTrackerConfig};
use crate::view::PacketView;
use crate::Timestamp;

pub struct FlowDatagramDriver<E, P, S = ()>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Default + Clone + Send + 'static,
    S: Send + 'static,
{
    tracker: FlowTracker<E, S>,
    parser_factory: P,
    parsers: HashMap<E::Key, P, RandomState>,
    emit_anomalies: bool,
    monotonic_ts: Option<Timestamp>,
    dedup: Option<crate::dedup::Dedup>,
}

impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Default + Clone + Send + 'static,
    S: Default + Send + 'static,
{
    pub fn new(extractor: E) -> Self {
        Self::with_config(extractor, FlowTrackerConfig::default())
    }

    pub fn with_config(extractor: E, config: FlowTrackerConfig) -> Self {
        Self {
            tracker: FlowTracker::with_config(extractor, config),
            parser_factory: P::default(),
            parsers: HashMap::with_hasher(RandomState::new()),
            emit_anomalies: false,
            monotonic_ts: None,
            dedup: None,
        }
    }
}

impl<E, P, S> FlowDatagramDriver<E, P, S>
where
    E: FlowExtractor,
    E::Key: Hash + Eq + Clone + Send + 'static,
    P: DatagramParser + Default + Clone + Send + 'static,
    S: Send + 'static,
{
    /// Mirror of [`crate::FlowDriver::with_emit_anomalies`].
    pub fn with_emit_anomalies(mut self, enable: bool) -> Self {
        self.emit_anomalies = enable;
        self
    }

    /// Mirror of [`crate::FlowDriver::with_monotonic_timestamps`].
    pub fn with_monotonic_timestamps(mut self, enable: bool) -> Self {
        self.monotonic_ts = if enable { Some(Timestamp::default()) } else { None };
        self
    }

    /// Mirror of [`crate::FlowDriver::with_dedup`].
    pub fn with_dedup(mut self, dedup: crate::dedup::Dedup) -> Self {
        self.dedup = Some(dedup);
        self
    }

    /// Mirror of [`crate::FlowSessionDriver::with_idle_timeout_fn`].
    pub fn with_idle_timeout_fn<F>(mut self, f: F) -> Self
    where
        F: Fn(&E::Key, Option<crate::L4Proto>) -> Option<std::time::Duration>
            + Send + 'static,
    {
        self.tracker.set_idle_timeout_fn(f);
        self
    }

    /// Drive one packet. Returns zero or more `SessionEvent`s.
    pub fn track(
        &mut self,
        view: PacketView<'_>,
    ) -> Vec<SessionEvent<E::Key, P::Message>> {
        // Dedup (Plan 49).
        if let Some(d) = self.dedup.as_mut() {
            if !d.keep(view) {
                return Vec::new();
            }
        }
        // Monotonic ts clamp (Plan 48).
        let view = self.clamp_view(view);

        let mut out: Vec<SessionEvent<E::Key, P::Message>> = Vec::new();
        let factory = &mut self.parser_factory;
        let parsers = &mut self.parsers;

        let flow_events = self.tracker.track_with_payload(view, |_, _, _, _| {
            // TCP callback fires here; UDP doesn't. UDP payload
            // is extracted from `view` separately below.
        });

        // Extract the UDP payload from `view` (if any) and route
        // to the per-flow DatagramParser. The current
        // `track_with_payload` callback is TCP-only — see
        // `extract_udp_payload` below.
        let udp_payload = extract_udp_payload(view);

        for ev in flow_events {
            match ev {
                FlowEvent::Started { key, ts, .. } => {
                    parsers.entry(key.clone()).or_insert_with(|| factory.clone());
                    out.push(SessionEvent::Started { key, ts });
                }
                FlowEvent::Packet { key, side, ts, .. } => {
                    if let Some(payload) = udp_payload.as_deref() {
                        if let Some(parser) = parsers.get_mut(&key) {
                            for m in parser.parse(payload, side) {
                                crate::obs::trace_session_message(side, &m);
                                out.push(SessionEvent::Application {
                                    key: key.clone(),
                                    side,
                                    message: m,
                                    ts,
                                });
                            }
                            // Parser poison check (Plan 55).
                            if parser.is_poisoned() {
                                self.synthesise_parser_poison(
                                    key.clone(),
                                    side,
                                    parser.poison_reason().map(truncate_reason),
                                    ts,
                                    &mut out,
                                );
                            }
                        }
                    }
                }
                FlowEvent::Ended { key, reason, stats, .. } => {
                    parsers.remove(&key);
                    out.push(SessionEvent::Closed { key, reason, stats });
                }
                FlowEvent::Anomaly { key, kind, ts } => {
                    if self.emit_anomalies {
                        out.push(SessionEvent::Anomaly { key, kind, ts });
                    }
                }
                FlowEvent::Established { .. } | FlowEvent::StateChange { .. } => {
                    // UDP doesn't produce these; ignore.
                }
            }
        }
        out
    }

    pub fn sweep(&mut self, now: Timestamp) -> Vec<SessionEvent<E::Key, P::Message>> {
        // ... mirror of FlowSessionDriver::sweep ...
    }

    pub fn tracker(&self) -> &FlowTracker<E, S> { &self.tracker }
    pub fn tracker_mut(&mut self) -> &mut FlowTracker<E, S> { &mut self.tracker }

    // ... synthesise_parser_poison, clamp_view helpers ...
}

fn truncate_reason(s: &str) -> String {
    let mut owned = String::from(s);
    owned.truncate(256);
    owned
}
```

### UDP payload extraction

`FlowTracker::track_with_payload`'s callback is TCP-only by
design — TCP has sequence numbers; UDP doesn't. Two options for
getting at UDP payload bytes:

**Option A — extend the tracker's callback** to fire for UDP too,
with a placeholder seq (e.g. always 0):

```rust
pub fn track_with_payload<F>(
    &mut self,
    view: PacketView<'_>,
    payload_cb: F,
) -> FlowEvents<E::Key>
where
    F: FnMut(&E::Key, FlowSide, u32, &[u8]),
{ /* fires for TCP AND UDP */ }
```

Pros: one extraction pass; consistent shape.
Cons: changes the contract of an existing API; existing TCP-only
callers may not want UDP payloads.

**Option B — extract UDP payload separately** in
`FlowDatagramDriver`:

```rust
fn extract_udp_payload(view: PacketView<'_>) -> Option<&[u8]> {
    use etherparse::{SlicedPacket, TransportSlice};
    let pkt = SlicedPacket::from_ethernet(view.frame).ok()?;
    match pkt.transport? {
        TransportSlice::Udp(udp) => Some(udp.payload()),
        _ => None,
    }
}
```

Pros: localised to the datagram driver; doesn't touch tracker
contract.
Cons: re-parses the frame (double work, since the extractor
already parsed it).

**Picked Option B.** The double-parse cost is fine for UDP
(typically lower packet rate than TCP), and option A would
churn `FlowTracker`'s public contract for a single consumer.

If profiling reveals the double-parse as a bottleneck, revisit
with a new tracker method (`track_with_l4_payload`) that
generalises across L4 protocols.

### `src/lib.rs`

```rust
#[cfg(feature = "session")]
pub mod datagram_driver;

// ...

#[cfg(feature = "session")]
pub use datagram_driver::FlowDatagramDriver;
```

---

## Implementation steps

1. **Create `src/datagram_driver.rs`** with the struct and
   `track` method as sketched.
2. **Implement `extract_udp_payload`** using `etherparse`
   (already a dep via `extractors` feature).
3. **Wire all six builder methods** (`with_emit_anomalies`,
   `with_monotonic_timestamps`, `with_dedup`,
   `with_idle_timeout_fn`, `with_config`, plus the default
   `new`). Match `FlowSessionDriver`'s surface exactly so users
   can swap one for the other when they're handling mixed
   TCP/UDP traffic.
4. **Implement `sweep(now)`** with the same monotonic-ts and
   anomaly handling as `track`.
5. **Implement `synthesise_parser_poison`** (Plan 55 wiring).
6. **Re-export from `src/lib.rs`**.
7. **Add tests** (see Tests).
8. **Update SESSION_GUIDE.md** "Sync vs async session driving"
   to mention `FlowDatagramDriver` alongside `FlowSessionDriver`.
9. **CHANGELOG entry**.

---

## Tests

### `src/datagram_driver.rs` (unit)

```rust
#[derive(Default, Clone)]
struct EchoUdpParser;
impl DatagramParser for EchoUdpParser {
    type Message = (FlowSide, Vec<u8>);
    fn parse(&mut self, payload: &[u8], side: FlowSide) -> Vec<Self::Message> {
        vec![(side, payload.to_vec())]
    }
}

#[test]
fn started_and_application_for_udp_packet() {
    let mut d = FlowDatagramDriver::<_, EchoUdpParser>::new(FiveTuple::bidirectional());
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"query");
    let events = d.track(view(&f, 0));
    let started = events.iter().any(|e| matches!(e, SessionEvent::Started { .. }));
    let app = events
        .iter()
        .find_map(|e| match e {
            SessionEvent::Application { message: (s, b), .. } => Some((*s, b.clone())),
            _ => None,
        });
    assert!(started);
    assert_eq!(app, Some((FlowSide::Initiator, b"query".to_vec())));
}

#[test]
fn closed_event_on_idle_timeout() {
    let mut cfg = FlowTrackerConfig::default();
    cfg.idle_timeout_udp = std::time::Duration::from_secs(1);
    let mut d = FlowDatagramDriver::<_, EchoUdpParser>::with_config(
        FiveTuple::bidirectional(),
        cfg,
    );
    let f = ipv4_udp([10, 0, 0, 1], [10, 0, 0, 2], 1, 53, b"q");
    d.track(view(&f, 0));
    let ended = d.sweep(Timestamp::new(10, 0));
    let closed = ended.iter().find(|e| matches!(e, SessionEvent::Closed { .. }));
    assert!(closed.is_some());
}

#[test]
fn tcp_packets_do_not_fire_application_events() {
    let mut d = FlowDatagramDriver::<_, EchoUdpParser>::new(FiveTuple::bidirectional());
    // TCP SYN — extract_udp_payload returns None; no Application event.
    let syn = ipv4_tcp([0; 6], [0; 6], [10, 0, 0, 1], [10, 0, 0, 2],
                       1234, 80, 0, 0, 0x02, b"");
    let events = d.track(view(&syn, 0));
    assert!(events.iter().any(|e| matches!(e, SessionEvent::Started { .. })));
    assert!(!events.iter().any(|e| matches!(e, SessionEvent::Application { .. })));
}

#[test]
fn parser_poison_synthesises_parse_error_closed() {
    // Plan 55 coordination test. Verify is_poisoned() check
    // triggers Closed { reason: ParseError } + the parser slot
    // is dropped.
}
```

### Integration

The shipped `DnsUdpParser` is a `DatagramParser`. Add a small
integration test driving the existing DNS pcap fixture through
`FlowDatagramDriver` and verifying the events match what the
existing pcap-driven DNS tests produce. Cross-validates the new
driver against an established parser.

---

## Acceptance criteria

- [ ] `FlowDatagramDriver<E, P, S>` exists in
      `src/datagram_driver.rs`, re-exported from the crate root.
- [ ] All six builder methods present (`new`, `with_config`,
      `with_emit_anomalies`, `with_monotonic_timestamps`,
      `with_dedup`, `with_idle_timeout_fn`).
- [ ] `track(view)` returns
      `Vec<SessionEvent<E::Key, P::Message>>` with `Started` on
      first sight, `Application` per parsed message, `Closed` on
      flow end.
- [ ] `sweep(now)` mirrors `FlowSessionDriver::sweep`.
- [ ] Parser poison (Plan 55) tears the flow down via
      `Closed { reason: ParseError }`.
- [ ] `extract_udp_payload` returns `None` for non-UDP frames
      (no Application events for TCP).
- [ ] Existing `DnsUdpParser` works end-to-end via the new
      driver against the existing DNS pcap fixture.
- [ ] SESSION_GUIDE.md mentions the datagram driver alongside
      the session driver.
- [ ] CHANGELOG entry under 0.3.0.
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **Double-parse cost.** `extract_udp_payload` re-parses the
   frame to find the UDP header. The extractor already parsed it.
   For UDP, packet rate is typically lower than TCP, so the cost
   is acceptable. Documented; benchmark in Plan 54 can quantify.
2. **Mixed TCP/UDP capture handling.** If users want both TCP
   and UDP from the same capture, they need both
   `FlowSessionDriver` AND `FlowDatagramDriver`, each fed the same
   `PacketView` stream. Each driver ignores the wrong protocol
   (UDP frames produce no Application events on FlowSessionDriver;
   TCP frames produce no Application events on
   FlowDatagramDriver). Document.
3. **Shared FlowTracker across both drivers.** Currently each
   driver owns its own tracker. Two trackers fed the same packets
   double-count flows. For most real consumers this is fine
   (they're decoding only one protocol type). Document; if real
   demand surfaces for shared-tracker mode, follow-up plan.
4. **Parser poison handling is identical to Plan 55**. Land Plan
   55 first; this plan inherits the wiring.

---

## Effort

- LOC: ~250 (driver + extraction helper + tests).
- Time: ½ day.

---

## Provenance

Identified during the 0.3.0 planning review (not in the des-rs
feedback report). des-rs uses TCP (DES PSMSG is TCP-based) so
they don't need a UDP driver. But the asymmetry —
`FlowSessionDriver` exists, `FlowDatagramDriver` doesn't —
forces every UDP consumer (DNS / syslog / NTP / SNMP /
arbitrary binary datagram protocols) to reinvent the same
boilerplate. The shipped `DnsUdpParser` consumer is the
canonical use case.

Sync mirrors are a project convention (CLAUDE.md "sync/async
parity"). `FlowDatagramDriver` completes the matrix:

|              | sync (flowscope)        | async (netring)       |
|--------------|-------------------------|------------------------|
| `FlowEvent`  | `FlowDriver`            | `flow_stream`          |
| TCP `SessionParser` | `FlowSessionDriver` | `session_stream`     |
| UDP `DatagramParser` | **`FlowDatagramDriver`** (this plan) | `datagram_stream` |
