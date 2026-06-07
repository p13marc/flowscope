# Plan 114 — `Routing::Heuristic` for the unified `Driver`

## Summary

Add a payload-signature routing mode to plan 116's unified
`Driver<E, M>` — `Routing::Heuristic { signature,
max_probe_packets }` — that uses payload signatures (plan
113) to choose a parser when port-based routing doesn't
match.

Implements the **cheap-first cascade + pin-on-first-match +
bounded packet budget** pattern that every production DPI
system (Suricata, Zeek, nDPI, Wireshark) converges on.
After a signature pins a flow, dispatch is O(1) — same cost
as port-routed today.

## Status

**Ready to implement.** Targets 0.10.0. Depends on plans
116 (unified Driver) and 113 (signatures); 114 lands after
both.

## Prerequisites

- **Plan 116** — `Driver<E, M>` + `DriverBuilder<E, M>`. The
  unified driver this plan extends. Hard prerequisite.
- **Plan 113** — `flowscope::detect::signatures`. Optional —
  consumers can register custom signatures; the shipped
  table is the convenience.

## Out of scope

- **Speculative parallel parsing.** Zeek runs multiple
  candidate analyzers and prunes losers; that requires
  per-flow per-parser state proportional to the candidate
  set. flowscope's approach: dispatch ONLY the matching
  parser; if a signature pins HTTP and the flow turns out
  to be something else, the parser will fail and the flow
  gets `ParseError`-Closed. Same predictability we have
  today.
- **Mid-stream protocol change detection.** Once pinned, a
  flow stays pinned. Protocols don't change mid-stream in
  practice (TLS-after-HTTP-upgrade is technically a thing
  but covered by the existing TLS parser registering
  separately).
- **Cross-flow signature aggregation** (e.g. "flow N's
  signature says HTTP, flow N+1 to the same dst is
  probably HTTP too"). Out of scope.
- **Probabilistic / scored signatures.** Plan 113's
  signatures are 3-state (`Match` / `NoMatch` /
  `NeedMoreData`); 114 dispatches on `Match` only. Scoring
  is a follow-up if a consumer asks.
- **Custom budget per signature.** All heuristic-routed
  parsers share the same `max_probe_packets`; per-parser
  override is a future plan.

---

## API

### New routing variant

```rust
// src/driver/routing.rs (file landed by plan 116)
pub enum Routing {
    // … existing variants from plan 116 …
    /// Port-set routing — fires when `dst_port ∈ ports || src_port ∈ ports`.
    Ports(SmallVec<[u16; 4]>),
    /// Fire on every packet matching this L4.
    Broadcast,

    /// NEW (plan 114): payload-based routing.
    /// Examine the first `max_probe_packets` packets of each
    /// new flow; fire when `signature(buf)` returns Match.
    /// After a match, the parser is pinned to the flow and
    /// receives every subsequent packet directly (no per-
    /// packet signature evaluation).
    Heuristic {
        signature: SignatureFn,
        /// Maximum packets to probe before giving up.
        /// Typical: 4-8. Wider hurts memory, more accurate.
        max_probe_packets: u8,
    },
}
```

### Builder API additions

```rust
impl<E, M> DriverBuilder<E, M> {
    // … existing methods from plan 116 …

    /// Register a session parser that fires when `signature`
    /// matches on the flow's first segments. Defaults to
    /// probing the first 4 packets.
    pub fn session_heuristic<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        lift: F,
    ) -> Self
    where
        P: SessionParser + Clone + Send + 'static,
        F: Fn(P::Message) -> M + Send + 'static;

    /// Same with a custom probe budget.
    pub fn session_heuristic_with_budget<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        max_probe_packets: u8,
        lift: F,
    ) -> Self where /* same bounds */;

    /// Datagram-side variant.
    pub fn datagram_heuristic<P, F>(
        self,
        parser: P,
        signature: detect::signatures::SignatureFn,
        lift: F,
    ) -> Self where /* same bounds */;
}
```

`PipelineBuilder<E, M>` (plan 116) proxies all three
methods through to its inner `DriverBuilder` — heuristic
routing works equally from the `Pipeline` entry point.

### Convenience: dispatch by registry

```rust
impl<E, M> DriverBuilder<E, M> {
    /// Register every parser in `registry()` with its
    /// canonical heuristic signature. Convenience for
    /// "give me detection for everything flowscope ships."
    /// Consumer provides a single lift closure that handles
    /// every parser_kind via `Message`.
    pub fn with_shipped_heuristics<F>(self, _lift: F) -> Self
    where
        // … signature TBD per how the message type is unified …
}
```

(Strict typing of `with_shipped_heuristics` is awkward
because each parser has a different `Message`. Likely we
ship this only with the `AnyL7Message` preset deferred from
plan 92 — call it a future enhancement.)

---

## Internal state machine

### Per-flow detection state

```rust
enum FlowDetection {
    /// New flow — no packets received yet; or some packets
    /// but no signature has matched.
    Probing {
        /// How many packets we've already probed.
        seen: u8,
        /// Per-side accumulation buffer (small — we only
        /// want the first ~64 bytes of payload to match
        /// against).
        init_buf: ArrayVec<u8, 64>,
        resp_buf: ArrayVec<u8, 64>,
    },
    /// A heuristic-routed parser claimed the flow. Its slot
    /// index in `session_slots` (or `datagram_slots`) is
    /// stored; subsequent packets dispatch directly.
    Pinned(SlotIdx),
    /// Probe budget exhausted without a match. Packets
    /// continue to flow through port-routed and broadcast
    /// parsers but no heuristic parser sees them.
    GaveUp,
}
```

Stored in a `HashMap<E::Key, FlowDetection>` parallel to
the existing flow tracker — owned by the unified `Driver`'s
internal state (plan 116's `src/driver/dispatch.rs`).

Memory cost per active flow:
- `Probing`: ~140 bytes (two 64-byte ArrayVecs + counter).
- `Pinned`: 4 bytes.
- `GaveUp`: 0 bytes.

For a 100k-flow tracker with all flows still probing, total
overhead is ~14 MiB. The state transitions to `Pinned` or
`GaveUp` typically within 1-2 packets for well-known
protocols (TLS pins on the ClientHello byte; HTTP pins on
`GET ` + `HTTP/1.`). At steady state, the memory is
dominated by `Pinned` (4 bytes/flow) — negligible.

### Per-packet dispatch

```text
On packet receipt for flow K:
  1. tracker.track(view) → emit Flow events as before.
  2. Run port-based routing (existing plan-116 path).
     Each matching port-routed parser fires.
  3. Look up FlowDetection[K]:
     a. Probing: append payload to per-side buffer (capped),
        evaluate every heuristic signature against the
        buffer.
        - If any returns Match → transition to Pinned(slot).
          Dispatch the packet (and the accumulated buffer)
          to that parser.
        - Else if `seen + 1 >= max_probe_packets` → transition
          to GaveUp.
        - Else: seen += 1, continue.
     b. Pinned(slot): dispatch directly to the slot's parser.
     c. GaveUp: no heuristic dispatch.
  4. Run broadcast routing (existing plan-116 path).
  5. Return merged Vec<Event<K, M>>.
```

### Per-flow cleanup

On `Event::FlowEnded` from the tracker, drop the
`FlowDetection` entry for that key. Memory bounded by the
flow tracker's `max_flows`.

---

## Concrete example — `extract_iocs.rs` with heuristic routing

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

A TLS flow on port 8443:
- Port-based routing: no match (TLS isn't on 443 here).
- Heuristic: ClientHello bytes arrive → `tls_client_hello`
  returns `Match` → flow pinned to the TLS parser slot.
- Subsequent packets: O(1) dispatch to the parser.

Total signature evaluation cost: one match on the first
packet of the flow. Identical to port-routed cost after.

---

## Files

```
src/driver/routing.rs        # add Heuristic variant (file landed by 116)
src/driver/dispatch.rs       # add detection state + dispatch (file landed by 116)
src/driver/mod.rs            # add new builder methods
tests/heuristic_routing.rs   # 6+ end-to-end scenarios
examples/extract_iocs.rs     # extend example with both modes
docs/recipes.md              # update "Multi-protocol monitoring"
CHANGELOG.md                 # 0.10 entry
```

## Implementation steps

1. Add `Routing::Heuristic { signature, max_probe_packets }`
   variant to the routing enum (file added by plan 116).
2. Add `FlowDetection` enum + `HashMap<K, FlowDetection>`
   storage to `Driver`'s dispatch state.
3. Add the four builder methods
   (`session_heuristic`, `session_heuristic_with_budget`,
   same for datagram).
4. Update per-packet dispatch:
   - Before port-routed dispatch, check the flow's
     detection state.
   - If `Probing`, accumulate the payload into the per-
     side buffer (capped at 64 bytes).
   - Walk the heuristic-registered slots; on `Match`,
     transition to `Pinned(slot)` and dispatch the
     accumulated buffer to that parser.
   - On exhaustion, transition to `GaveUp`.
   - If `Pinned`, dispatch directly.
5. On `Event::FlowEnded`, drop the detection state.
6. Proxy the three new builder methods through
   `PipelineBuilder<E, M>` (plan 116) for parity.
7. `tests/heuristic_routing.rs`:
   - HTTP on port 9000 → pinned + parsed correctly.
   - TLS on port 8443 → pinned + ClientHello parsed.
   - Encrypted random bytes on port 80 → port-routed HTTP
     parser tries, fails, no heuristic catches it →
     ParseError-Closed.
   - Probe budget exhaustion → flow transitions to GaveUp;
     subsequent packets are not heuristic-dispatched.
   - Mixed port-route + heuristic registrations: port wins
     when applicable, heuristic catches the rest.
   - Two heuristic parsers registered for the same protocol
     (e.g. two HTTP parsers with different lifts) → first
     in registration order wins on Match.
8. Extend `examples/extract_iocs.rs` to register both
   port-based and heuristic-routed copies of each parser.
9. Update `docs/recipes.md` "Multi-protocol monitoring"
   section.
10. CHANGELOG entry under 0.10.0 "Added."

## Tests

`tests/heuristic_routing.rs`:

```rust
#[test]
fn heuristic_matches_http_on_unusual_port() {
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_heuristic(HttpParser::default(), http_request, |m| m)
        .build();

    // Synthetic HTTP traffic on port 9999.
    let frames = build_http_pcap_on_port(9999, "GET /index.html HTTP/1.1\r\n\r\n");
    let messages: Vec<HttpMessage> = drive(&mut driver, &frames);
    assert!(matches!(messages.first(), Some(HttpMessage::Request(_))));
}

#[test]
fn heuristic_gives_up_after_budget() {
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_heuristic_with_budget(HttpParser::default(), http_request, 2, |m| m)
        .build();

    // Garbage on port 9999.
    let frames = build_garbage_pcap(9999);
    let messages = drive(&mut driver, &frames);
    assert!(messages.is_empty());

    // Verify the flow is in GaveUp state (no more heuristic
    // evaluations would happen on subsequent packets — we'd
    // need an introspection accessor for this; defer).
}

#[test]
fn port_route_wins_when_both_apply() {
    // Register HTTP both port-routed on 80 and heuristic.
    // For a port-80 flow, port-routed dispatches first; the
    // heuristic dispatcher should NOT also fire (else we'd
    // get duplicate events).
    let mut driver = Driver::<_, HttpMessage>::builder(ext)
        .session_on_ports(HttpParser::default(), [80], |m| m)
        .session_heuristic(HttpParser::default(), http_request, |m| m)
        .build();

    let frames = build_http_pcap_on_port(80, "GET / HTTP/1.1\r\n\r\n");
    let messages: Vec<HttpMessage> = drive(&mut driver, &frames);
    // Expect exactly 1 message, not 2.
    assert_eq!(messages.len(), 1);
}

#[test]
fn pinning_persists_across_packets() {
    // Single HTTP flow with multiple requests over its
    // lifetime. After the first match, no further signature
    // evaluation should happen. Verify by stuffing a TLS-like
    // payload mid-flow — the HTTP parser should receive it
    // (and presumably fail to parse), not the TLS parser
    // claim it.
    let mut driver = Driver::<_, AnyL7Message>::builder(ext)
        .session_heuristic(HttpParser::default(), http_request, AnyL7Message::Http)
        .session_heuristic(TlsHandshakeParser::default(), tls_client_hello, AnyL7Message::Tls)
        .build();

    let frames = build_pcap_http_then_tls_bytes(/* same flow */);
    let messages = drive(&mut driver, &frames);
    // Only HTTP messages — TLS bytes mid-flow look like
    // garbage to the HTTP parser, which may emit a poison
    // event, but no TLS parsing should happen.
    assert!(messages.iter().all(|m| matches!(m, AnyL7Message::Http(_))));
}

#[test]
fn heuristic_then_tracker_ended_drops_detection_state() {
    // Verify memory cleanup: a flow that ends should drop
    // its FlowDetection entry. Verify via an introspection
    // accessor (added as part of this plan).
}
```

Plus a proptest: arbitrary chunking of the same packet
stream produces identical message output regardless of how
the per-side buffer fills.

## Acceptance criteria

- `Routing::Heuristic` variant ships.
- Four builder methods land (three on `DriverBuilder`, all
  three proxied through `PipelineBuilder`).
- Per-flow detection state machine works correctly across
  the test scenarios.
- 6+ integration tests pass.
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- `examples/extract_iocs.rs` updated to show both modes.
- `docs/recipes.md` updated.
- CHANGELOG entry.

## Risks

- **Detection state memory at high flow counts.** 64-byte
  buffer × 2 sides × 100k flows = 12.8 MiB if every flow
  is still probing. Mitigation: budget defaults to 4
  packets, typical pin happens within 1-2 packets, steady-
  state memory drops to 4 B/flow.
- **Signature evaluation overhead in the probe window.** N
  registered heuristics × M probe packets × 1 evaluation
  each = N*M signature calls per flow. Typical N=5,
  M=4 → 20 evaluations per flow. Each signature is ~20-100
  ns. Total: ~2 µs per flow during probing. Negligible.
- **Order-dependence of registration.** Two heuristics that
  could both match the same payload — first-registration
  wins. Document explicitly; if a consumer needs different
  semantics they can use predicate routing (deferred per
  plan 92 Q2; can revisit if asked).
- **Pinning permanence.** A flow that pins to (say) HTTP
  but is actually a custom protocol that happens to start
  with `GET ` will get `ParseError`-Closed shortly after.
  This is the right behaviour — we don't want a flow to
  unpin mid-stream and re-probe. Document the trade-off.
- **Buffer cap (64 B) too small for some signatures.**
  Most signatures decide within ~20 B; SSH banner needs
  ~10 B; TLS ClientHello needs 6 B for the discriminator.
  64 B handles every shipped signature. Make the cap a
  named const so future plans can tune.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `Routing::Heuristic` variant | ~30 | 0.5 |
| `FlowDetection` state + storage | ~80 | 2 |
| Four builder methods + PipelineBuilder proxies | ~120 | 2.5 |
| Per-packet dispatch update | ~140 | 4 |
| Per-flow cleanup on Event::FlowEnded | ~30 | 1 |
| Tests (6+ scenarios + 1 proptest) | ~360 | 5 |
| Example extension | ~30 | 0.5 |
| Docs + CHANGELOG | ~80 | 1 |
| **Total** | **~870 LoC** | **~16.5 hours** |

(Slightly higher than the original 109-tied estimate
because builder proxies now span both `DriverBuilder` and
`PipelineBuilder` after plan 116's unification.)

## Provenance

Plan 112 (the analysis document) — recommendation
adopted, adapted for plan 116's unified driver:

> Plan 114 — `Routing::Heuristic { signatures }` on
> the unified `Driver`. Adds a new routing mode
> that runs a list of signatures over the first N bytes of
> payload per flow; pins on first match. After the pin, the
> parser receives subsequent packets directly (zero
> per-packet detection overhead). The "cheap-first
> cascade" + "pin-on-first-match" + "bounded packet
> budget" patterns directly.

Industry pattern adopted: Wireshark conversation pinning
(Wikipedia/Wireshark docs) plus nDPI's FPC budget plus
Suricata's pattern-then-probe sequencing.

Plan 115 (strategic review) — re-targeted from
`FlowMultiDriver` (plan 109, deleted) to the unified
`Driver<E, M>` (plan 116).
