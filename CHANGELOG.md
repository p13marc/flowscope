# Changelog

## 0.21.0 (unreleased) — detection architecture: typed DetectorKind, Detector trait + registry, NDR detectors

The 2026 roadmap's (#140) keystone detection-architecture group,
plus the pDNS name map and the final tap-merge phase. Migration
recipes in `docs/migration-0.20-to-0.21.md`.

### Breaking — `OwnedAnomaly::kind` is typed `DetectorKind` (#133)

Detector identity graduates from a string slug
(`Cow<'static, str>`) to the typed `flowscope::DetectorKind` enum
(`ParserKind` precedent, 0.20 #109): `BeaconCv`, `BeaconRita`,
`PortScanTrw`, `Dga`, the four #132 detector kinds,
`Other(&'static str)` for downstream detectors, and an `Unknown`
deserialization fallback.

- **The wire is byte-identical** — each variant serializes to the
  exact slug 0.20 emitted (`"PortScanTRW"`, `"DgaScorer"`, …), as
  a plain JSON string. EVE `anomaly.event` and NDJSON `kind`
  consumers need no changes.
- `OwnedAnomaly::new` takes `DetectorKind`;
  `DetectorScore::name()` is now `kind() -> DetectorKind` (old
  string = `kind().as_str()`).
- `DetectorKind::attack_technique()` maps built-in kinds to
  stable MITRE ATT&CK technique IDs (`PortScanTrw` → `"T1046"`,
  beacons → `"T1071"`, `Dga` → `"T1568.002"`, …) — deletes the
  slug→technique tables downstream consumers maintained.
- `EveJsonWriter::write_owned_anomaly` emits an additive
  `anomaly.attack_technique` field when the mapping exists.
- `OwnedAnomaly::from_flow_anomaly` bridges via
  `DetectorKind::Other(short_kind())` — emitted strings
  unchanged; the typed tracker axis stays in `flowscope_kind`.
- `DetectorKind` is exported at the crate root and in the prelude.

## 0.20.0 (2026-06-29) — NSM primitives + driver/event convergence + 1.0-prep API sweep

Pure, no-async — fits the runtime-free lib rule. The largest pre-1.0
breaking batch yet, so the version bumps 0.19 → 0.20.

Three themes:

- **Driver/event convergence (#84, closed).** One typed
  `driver::Driver<E>` is the public driver shape; the per-parser
  `Flow{Session,Datagram}Driver` engines and the `SessionEvent` carrier
  go crate-private (#98 / #99 / #100), and the public surface settles on
  `Event<K>` + `SlotHandle`/`SlotDrain` (#97 / #101).
- **1.0-prep strong-typing sweep.** `parser_kind()` returns a typed
  `ParserKind` enum (#109); `Event<K>` variants drop the redundant
  `Flow` prefix to match `FlowEvent<K>` (#110); the offline pcap surface
  keeps the strongly-typed `*_from_pcap` helpers (un-deprecated, #86 /
  #108) and gains a unified lifecycle-plus-message `Pulse` stream (#111).
- **Carried pre-1.0 breaks:** `parse()`→`Result` (#85), EVE `flow_hash`
  → `community_id` (#88), `#[non_exhaustive]` everywhere (#78), and the
  canonical-direction fix — `Started`/`Packet` events now carry both
  `side` and a deterministic `orientation` (#118).

### Breaking — canonical `Orientation` on flow events (#118 / #119, epic #123)

`FlowEvent::{Started, Packet}` and `Event::{Started, Packet}` gain an
`orientation: Orientation` field alongside the existing `side`. This
closes #71: `FlowSide` is **arrival-order-relative** — `Initiator`
binds to whichever endpoint's packet reached the tracker first — so a
tap-merge (two NICs / two queues feeding one tracker, with a scheduling
race) can flip it, binding `Initiator` to the server on some flows and
the client on others. `Orientation` (`Forward` / `Reverse`) is computed
purely from the address-sorted canonical key, so the **same wire
direction always carries the same `Orientation` regardless of arrival
order** — the property `FlowSide` lacks and the one you want for
Community ID ordering, biflow keying, and dedup across capture points.

flowscope already kept the two as distinct internal concepts (so it
avoids the CICFlowMeter "sorted == initiator" conflation bug); this
change simply stops discarding `Orientation` at the event boundary.

Also added (all additive):

- `FlowStats::initiator_orientation` — the canonical `Orientation` the
  flow's initiator (first-seen packet) had; the deterministic bridge
  for translating `side` ↔ `orientation` on a finished flow.
- `FlowStats::side_for(orientation)` / `orientation_for(side)` —
  translate between the two axes for a given flow.
- `FlowEntry::initiator_orientation()` accessor (live snapshots).
- `Orientation` now derives `Default` (`Forward`) + `Hash`, and gains
  `flipped()` and `as_str()` (`"forward"` / `"reverse"`).

**Migration.** Add `orientation` to any exhaustive `Started`/`Packet`
pattern (or a trailing `..`), and to any direct struct construction
(synthetic events: prefer `flowscope::test_helpers::events`). On the
serde wire the new field appears as `"orientation": "forward"` /
`"reverse"` — purely additive to the JSON. Consumers that only need
"who started it" keep using `side` unchanged. See
`docs/migration-0.19-to-0.20.md` §"#118" and `docs/concepts.md` →
"Direction, orientation, and capture leg".

**netring.** No code change required — netring forwards events
verbatim; the new field rides along. netring can optionally surface
`orientation` in its own adapters.

### Additive — per-direction capture-leg binding on `FlowStats` (#120, epic #123 phase 2)

A **merged** bidirectional flow can now report which physical capture
leg (NIC / `RxMetadata::source_idx`) each canonical direction arrived
on, without splitting into two flows — the IPFIX biflow-merge model
(RFC 5103: a forward `ingressInterface` IE 10 + a reverse one), the
missing middle ground between "drop the leg" (plain merge) and "fold
the leg into the key" (`Tagged`, which splits).

- `FlowStats::source_idx_forward` / `source_idx_reverse` +
  `source_idx_for(orientation)` — the leg bound to each canonical
  `Orientation`. The first **non-zero** `source_idx` seen for a
  direction binds it; `0` is the documented "unused" sentinel, so
  pcap / synthetic sources leave both `None`.
- `FlowStats::capture_leg_inconsistent` — flips when a second, *different*
  non-zero leg appears for an already-bound direction (the tap-miswire /
  asymmetric-routing IOC; the original binding is kept).

Keyed by `Orientation` (not `FlowSide`) so the binding is
arrival-order-stable, like the rest of the #71 fix. The tracker now
reads `view.rx_metadata.source_idx` on the per-packet path (a single
`u32` compare + conditional store — negligible, always-on). Available
on `Ended` / `Tick` / `snapshot_stats`. Purely additive (`FlowStats` is
`#[non_exhaustive]`); existing consumers unaffected. Per-*packet* leg
fidelity (audit tier) is tracked separately (#121).

### Additive — SYN-based initiator inference (#122, epic #123 phase 3)

A new opt-in `FlowTrackerConfig::infer_tcp_initiator` (default `false`)
makes the **logical role** axis (`FlowSide`) race-robust for TCP. When
enabled, a flow whose first observed packet is a `SYN+ACK` — the
response delivered before the request, a tap-merge / two-queue race —
has its inferred initiator **flipped** at flow creation so the SYN
sender is correctly labelled `Initiator`, and the new
`FlowStats::direction_flipped` flag is set (the analogue of Zeek's
`conn.log` `^`). A bare `SYN` first packet (the common case), a
non-handshake packet (mid-stream capture), or a non-TCP flow falls back
to arrival order unchanged.

Default-off preserves the historical first-seen semantics for
single-tap consumers (where the SYN is always seen first, so the flag
changes nothing). This corrects the role axis specifically; the
canonical `Orientation` axis (#118) is already race-immune for every
protocol regardless of this flag. Additive — only the new config field
and `FlowStats` flag are added.

### Additive — unified offline `Pulse` stream (#111)

`pcap::session_pulses::<P>(path)` / `datagram_pulses::<P>(path)` replay a
pcap through a single parser and yield one ordered `pcap::Pulse<K, M>`
stream that interleaves flow lifecycle **and** typed messages
(`Started` / `Message(SlotMessage)` / `Ended` / `Tick`). Fills the gap
between `session_messages::<P>` (messages only) and `Driver::run_pcap`
(lifecycle only) — and closes the trailing-drain footgun: close-flush
messages arrive as `Message` pulses *before* the flow's `Ended`, so
nothing is left buffered when the iterator ends. `Pulse` and both
iterators are exported from the prelude. Example:
`examples/01-l7-logging/pcap_pulses.rs`.

### Additive — `SlotDrain` shared trait (#101, driver-convergence 5/5)

`driver::SlotDrain<M, K>` — a shared drain surface
(`drain` / `drain_n` / `pending` / `parser_kind`) implemented by both
`SlotHandle` (competitive-consumer) and `BroadcastSlotHandle`
(fan-out), so a downstream drain loop can be generic over the
delivery mode (`fn pump(s: &mut impl SlotDrain<M, K>)`). The
type-specific extras (`SlotHandle::drain_replacing` / `clear`,
`BroadcastSlotHandle::subscribers`) stay inherent. Purely additive —
the existing inherent methods are unchanged. Re-exported from
`flowscope::driver` and the prelude. Closes the #84 convergence.

### Breaking — `parser_kind()` returns the typed `ParserKind` enum (#109)

The stringly-typed parser-identity seam is closed. `SessionParser` /
`DatagramParser::parser_kind` now return [`ParserKind`] (default
`ParserKind::Unspecified`, was `""`) instead of `&'static str`, and the
enum — which shipped in 0.18 (#21) but was never wired in — gains a
variant for **every** shipped parser (26 built-ins:
`Http1` / `Tls` / `TlsHandshake` / `DnsUdp` / `DnsTcp` / `Icmp` / `Ssh` /
`Ntp` / `Ssdp` / `Tftp` / `Mdns` / `NetbiosNs` / `Ftp` / `Smtp` /
`WireGuard` / `Modbus` / `Stun` / `Rdp` / `Snmp` / `Radius` / `Dhcp` /
`Quic` / `Smb` / `Ldap` / `Kerberos` / `Dnp3`), plus `Other(&'static str)`
for downstream parsers.

The lift threads through `driver::Event::ParserClosed::parser_kind`,
`SlotHandle::parser_kind`, `SlotDrain::parser_kind`, `BroadcastSlotHandle`,
the crate-internal session/datagram engines, and the
`AccumulatingSessionParser::new` / `PerDatagramParser::new` /
`test_helpers::events::parser_closed` constructors.

- **Output is unchanged.** `ParserKind` has a custom serde impl that
  serializes as its `as_str()` slug (a plain JSON string, not a tagged
  object), so the `parser_kind` field in emitted events is byte-for-byte
  identical to the old `&'static str`. Metric labels are unchanged.
- New `ParserKind::from_slug(&str)` is the inverse for built-in slugs
  (also backs `Deserialize`); the `parser_kinds::*` `&str` constants stay
  for raw slug comparison.
- Affects only **direct callers** and **downstream parser impls**; the
  typed driver, slots, and `*_from_pcap` helpers need no change. Migration
  recipe in `docs/migration-0.19-to-0.20.md`. `ParserKind` is now exported
  from the prelude.

[`ParserKind`]: https://docs.rs/flowscope/latest/flowscope/enum.ParserKind.html

### Breaking — `Event<K>` variant names aligned with `FlowEvent<K>` (#110)

The high-level `driver::Event<K>` carried a redundant `Flow` prefix on
six variants while the lower-level `event::FlowEvent<K>` did not — so the
two event enums read with opposite conventions and `Event::FlowStarted`
stuttered. The prefix is dropped to match `FlowEvent`:

| before | after |
|---|---|
| `Event::FlowStarted` | `Event::Started` |
| `Event::FlowEstablished` | `Event::Established` |
| `Event::FlowStateChange` | `Event::StateChange` |
| `Event::FlowPacket` | `Event::Packet` |
| `Event::FlowEnded` | `Event::Ended` |
| `Event::FlowTick` | `Event::Tick` |

`FlowAnomaly` / `TrackerAnomaly` / `ParserClosed` are unchanged (already
aligned / no `FlowEvent` analogue). A consequence: `Event` and `FlowEvent`
now serialize to the **same** `type` tags (`"started"`, `"ended"`, …) — the
`Event` serde `type` tag for these variants changes from `"flow_started"`
&c. to `"started"` &c. No shipped emitter serializes `Event` (CSV / EVE /
NDJSON all serialize `FlowEvent`), so structured-output formats are
unaffected; only code that pattern-matches `Event::Flow*` or directly
serializes `Event` needs the rename. Pre-1.0 breaking — recipe in
`docs/migration-0.19-to-0.20.md`.

### Additive — `#[must_use]` on driver builder / handles / iterator

Idiomatic lint coverage (Rust API guideline C-MUST-USE) on the types
where dropping the value is a silent bug: `DriverBuilder` (does nothing
until `.build()`), `RunPcap` (a lazy pcap-replay iterator — drops do no
work), and `SlotHandle` / `BroadcastSlotHandle` (drop the handle and the
parser's typed messages are never read). Purely additive — a `let _ =`
silences it where dropping is intentional.

### Fixed — `<parser>,pcap` feature combos compile

The high-level `*_from_pcap` typed helpers are built on the offline
session/datagram engine, which needs the `reassembler` feature (its
trait backs even the datagram path's no-op reassembler). Five parser
features that ship a helper but didn't pull `reassembler` —
`quic` / `dns` / `kerberos` / `smb` / `ldap` — failed to compile under
`--features "<parser>,pcap"` (a latent gap: CI only built each parser
solo). Each now pulls `reassembler` (additive — TCP parsers genuinely
reassemble; datagram parsers need the trait for the no-op stub). New CI
`feature-matrix` rows (`quic,pcap` / `dns,pcap` / `kerberos,pcap` /
`smb,pcap` / `ldap,pcap` / `tls,pcap`) pin it.

### Additive — `Event<K>` emit-readiness (#97, driver-convergence 1/5)

First (additive) step of the #84 driver/event convergence — makes the
typed driver's `Event<K>` a first-class consumer/emit event so the
later breaking steps can retire `SessionEvent`.

- **`impl From<FlowEvent<K>> for Event<K>`** — total, lossless
  conversion from the tracker primitive. New variant
  **`Event::FlowStateChange`** gives `FlowEvent::StateChange` a
  counterpart so nothing is dropped (`FlowPacket.tcp` defaults to
  `None`; `FlowEnded.ts` comes from `stats.last_seen`).
- **`Event::into_flow_event` / `Event::to_flow_event`** — the reverse
  projection (`ParserClosed -> None`, having no tracker counterpart).
- **`Event<K>: Serialize`** under `serde` — same `tag = "type"` /
  `snake_case` shape as `FlowEvent`. `Serialize`-only: `ParserClosed`'s
  `parser_kind: &'static str` precludes a general `Deserialize`
  (deserialize the round-trippable `FlowEvent` and `From` it instead).
- **`emit::LifecycleEvent` trait** + **`write_lifecycle`** on every
  writer (CSV / Zeek / NDJSON / EVE) — emit either a `FlowEvent<K>` or a
  typed `Event<K>` through the same writers (the `FlowEvent` path stays
  zero-copy via `Cow`). The typed `Driver<E>`'s emitted stream is
  unchanged (it still omits raw `StateChange`).

### Breaking — retire `SessionEvent` from the public API (#100, driver-convergence 4/5)

Completes the two-enum end state: the public event vocabulary is now
just `FlowEvent<K>` (tracker primitive + emit/serde input) and
`Event<K>` (typed-driver consumer event). `SessionEvent<K, M>` — the
redundant third enum, whose only unique arm was `Application{message}`
— is demoted to a crate-private engine carrier (the typed slots and
the offline pcap helpers still use it internally).

- **Removed `SessionEvent` from the crate root and prelude.** Typed L7
  messages now arrive as `SlotMessage { key, side, message }` from a
  parser's `SlotHandle`; flow lifecycle arrives as `Event<K>`.
- **`PcapFlowSource::sessions()` / `datagrams()` are no longer public.**
  They backed the per-parser `*_from_pcap` helpers and remain as the
  private engine for them. The public offline surfaces are unchanged:
  `pcap::session_messages::<P>` / `pcap::datagram_messages::<P>`
  (yield `(key, message)`), the per-parser `*_from_pcap` helpers, and
  `Driver::run_pcap` (lifecycle `Event<K>` + slot messages).
- **Migration:** replace
  `for ev in source.sessions(ext, P) { if let SessionEvent::Application { message, .. } = ev? { … } }`
  with `for (key, message) in pcap::session_messages::<P>(path)? { … }`
  (path-based) or, for a non-path reader / combined lifecycle, a
  `Driver::builder` + `session_on_ports` + `track_into`/`drain` loop.
- netring is the only known external consumer; it owns its async
  session-event type and migrates in the coordinated 0.20 release
  (netring#107). flowscope CI does not build netring.

### Breaking — delete `FlowSessionDriver` / `FlowDatagramDriver` (#99, driver-convergence 3/5)

Removes the two single-parser convenience drivers (and their 20
constructors — the `new` / `with_config` / `with_factory*` /
`with_state*` explosion) from the public API. Their single-parser job
is subsumed by the typed [`driver::Driver<E>`] plus one slot, and the
reassembly-vs-noop distinction is already a registration choice
(`session_on_ports` vs `datagram_on_ports`). **`FlowDriver` stays** as
the documented low-level run-to-completion primitive.

- **Removed `FlowSessionDriver` and `FlowDatagramDriver`** from the
  crate root and the prelude. The parser-dispatch engine survives as a
  crate-private detail (the typed `Driver` slots and the offline `pcap`
  source still need it), but it is no longer nameable or constructible
  by downstream code.
- **Migration:** replace
  `FlowSessionDriver::new(ext, parser)` + `driver.track(view)` with
  ```rust,ignore
  let mut builder = Driver::builder(ext);
  let mut slot = builder.session_on_ports(parser, [port, ..]);  // datagram_on_ports for UDP
  let mut driver = builder.build();
  // per packet: driver.track_into(view, &mut events); slot.drain(&mut msgs);
  ```
  The raw `SessionEvent` stream becomes `Event<K>` (flow lifecycle) +
  typed `SlotHandle` messages. The offline one-liners
  (`pcap::session_messages` / `flow_summaries`, the `*_from_pcap`
  helpers) are unaffected.
- netring's `pcap_flow.rs` is the only known external consumer; it
  migrates when it adopts flowscope 0.20 (netring#107) and is
  unaffected until then.

### Breaking — one driver builder (#98, driver-convergence 2/5)

Collapses the two `Driver<E>` builders into one. The
`DeferredDriverBuilder` / `Driver::deferred()` / `build_with(ext)` split
(plan 124, 0.12.0) existed to register parsers before the extractor
instance was known; in practice nothing used it, and the eager
`DriverBuilder` already carries every knob — including
`session_on_ports_broadcast_each`, which the deferred mirror never had.

- **Removed `Driver::deferred()`, `DeferredDriverBuilder`, and
  `build_with(ext)`.** Use `Driver::builder(extractor)` → register
  slots → `build()`. The extractor is supplied up front; registration
  order is unchanged.
- No change to `DriverBuilder`, `Driver<E>`, `Event<K>`, slot handles,
  or the emitted stream. netring forwards no deferred-builder surface,
  so no downstream change is required.

### Additive — generic pcap message iterators + prelude (#86)

- **`pcap::session_messages::<P>(path)` / `pcap::datagram_messages::<P>(path)`**
  — two generic one-call iterators that yield `(FiveTupleKey, P::Message)`
  for *any* `SessionParser` / `DatagramParser` with a `Default`. The
  registration-free **building block** under the per-parser `*_from_pcap`
  helpers; the one-stop call for parsers without a bespoke helper or with
  non-`Default` config. (Two functions, not one `messages::<P>()`:
  `SessionParser` and `DatagramParser` are distinct traits, and overlapping
  blanket impls over `P` are rejected by coherence — splitting by transport
  keeps the API registration-free.) Now exported from the prelude.
- **Per-parser `*_from_pcap` helpers kept as the high-level typed surface.**
  `tls::client_hellos_from_pcap`, `http::requests_from_pcap`,
  `quic::initials_from_pcap`, &c. return the *specific, pre-filtered*
  message type (`Box<TlsClientHello>`, `HttpRequest`, `QuicInitial`) — a
  strict ergonomics/typing win over the generic enum stream for the
  marquee protocols, so they are **not** deprecated. The two layers stand
  side by side: reach for the typed helper when one exists, drop to
  `session_messages::<P>` otherwise.
- **`pcap::flow_summaries(path)`** — renamed from `flow_summaries_from_pcap`
  for naming consistency; the old name is a `#[deprecated]` alias.

### Additive — tracker load-shedding (#79)

- **`EventMask`** — a `bitflags` set selecting which `FlowEvent`
  variants the tracker should *not* emit, for source-level
  back-pressure under overload. Each bit maps to one variant
  (`PACKET` is the highest-volume); the empty default suppresses
  nothing.
- **`FlowTrackerConfig::with_event_filter(EventMask)`** — static,
  per-variant suppression. Suppressed events are never *constructed*
  — the `FlowStats` / `HistoryString` clones behind `Ended` / `Tick`
  are skipped entirely.
- **`FlowTracker::pause_events()` / `resume_events()` / `events_paused()`**
  — runtime, total shed for the duration of an overload episode
  ("shunt mode"). When driving through a `FlowDriver`, reach it via
  `driver.tracker_mut().pause_events()`.
- Accounting (TCP state machine, byte/packet counters, idle
  bookkeeping) always keeps running while shedding, so flows still
  finalize correctly when emission resumes. The driver-emitted `Tick`
  honours the same `EventMask::TICK` bit and pause state. Pure,
  additive, inert at the default. Resolves netring#54's flowscope
  side.

### Additive — JA4-QUIC client fingerprint (#82)

- **`tls::ja4_quic` / `tls::ja4_quic_parts`** — JA4 *client* fingerprint
  with the QUIC transport marker (`q…` instead of `t…`). License-clean
  (JA4 client is BSD-3-equivalent), gated on `tls-fingerprints` — **not**
  `ja4plus`. Byte-identical to `ja4` except the leading transport char.
- **`QuicInitial::client_hello: Option<TlsClientHello>`** — the QUIC
  parser now surfaces the full ClientHello recovered from the Initial's
  CRYPTO stream (cipher / extension / version lists), reusing the shared
  `tls` conversion. Present only when the `tls` feature is also enabled
  (additive field on a `#[non_exhaustive]` struct).
- **`quic::ja4(&QuicInitial) -> Option<String>`** — one-call convenience
  (gated on `tls-fingerprints`). Verified against the RFC 9001 §A.1
  Client Initial golden vector.
- `TlsClientHello` gained `PartialEq` + `Eq` derives (additive).

### 1.0-prep issue batch (#69, #78, #85, #87, #88)

- **BREAKING — `#[non_exhaustive]` coverage sweep** (#78). Brought 43
  growable public structs/enums into compliance with the project rule
  ("`#[non_exhaustive]` on every public struct/enum that may grow",
  CLAUDE.md). The gap was older types predating the 0.2.0 rule: the
  DNS / HTTP / TLS / ICMP wire-record structs + message enums
  (`DnsQuery` / `DnsResponse` / `DnsRecord` / `DnsRdata` / `HttpRequest` /
  `HttpResponse` / `HttpMessage` / `HttpVersion` / `TlsAlert` /
  `TlsMessage` / `IcmpMessage` / `IcmpInner` / `DnsParseResult`), the
  `*Config` structs, the flow keys (`FiveTupleKey` / `IpPairKey` /
  `FlowLabelKey` / `TaggedKey`), the encap combinators, the JA4 `*Parts`,
  `event::{OverflowPolicy, FlowState}`, `Extracted`, `BurstHit`,
  `FlowFingerprint`, `RiskSeverity`, `tracker::{FlowEntry, FlowTrackerStats}`,
  `Transition`, and the IPFIX `InformationElement` / `FieldSpec` /
  `TemplateDefinition`. Construction now goes through new `new()`
  constructors (or `Default` + field mutation for configs) — downstream
  struct-literal construction and exhaustive matches need the
  mechanical update in `docs/migration-0.19-to-0.20.md`. Every type
  the #66 primitive→enum lift named was already covered.
  - **Sealed-trait decision (documented, no code change):** the public
    extension traits `SessionParser` / `DatagramParser` / `FlowExtractor` /
    `KeyFields` / `DetectorScore` stay **open** for 1.0 — custom parsers,
    extractors, and keys are documented use cases (`KeyFields` in
    particular is required for downstream custom keys to use the emit
    writers). Rationale in `docs/design.md` → "Trait extensibility".
  - **`cargo-semver-checks` CI gate** confirmed green against the
    0.19.0 baseline + isolated `emit` / `aggregate` feature-matrix
    rows added so every feature is built somewhere.

- **BREAKING — parser fallibility unified: 16 `Option` parsers → `Result`**
  (#85). Every remaining hand-rolled wire parser's free `parse*()` function
  now returns `Result<T, ParseError>` with a per-module, `#[non_exhaustive]`
  `ParseError` (the shape #65 introduced for dnp3/smb/ldap/kerberos/quic),
  so callers can finally tell "not my protocol" from "malformed / truncated".
  Swept modules: `arp`, `ndp`, `lldp`, `cdp`, `dhcp`, `ssdp`, `netbios_ns`,
  `stun`, `ssh` (`parse_kexinit_payload`), `ntp`, `tftp`, `wireguard`,
  `modbus` (`parse_one`), `rdp` (`parse_frame`), `snmp`, `radius`. Each
  `ParseError` is re-exported from its module (e.g. `flowscope::arp::ParseError`).
  - **Error-model unification.** Every per-module `ParseError` (the 16 new
    *and* the 5 from #65) now implements `From<ParseError> for flowscope::Error`
    and has a matching `flowscope::Module` variant, so a parse failure can
    bubble through `?` into the unified `crate::Error` while keeping its rich
    typed form. Previously those enums could never become a `crate::Error`.
  - **Unaffected:** the `SessionParser` / `DatagramParser` trait sink methods
    (`feed_*` / `parse(&mut Vec<…>)`) and the `*_from_pcap` helpers — only the
    free `parse*()` functions changed. See `docs/migration-0.19-to-0.20.md`.


- **BREAKING — `flow_hash` dropped from EVE output, `community_id` is
  canonical** (#88). The proprietary 64-bit FNV-1a `flow_hash` field is
  no longer emitted by `EveJsonWriter` (event-driven *or* FlowRecord
  path). The standard Corelight **Community ID** (`community_id`) is now
  the sole, portable flow identifier — emitted when built with the
  `community-id` feature. `FlowRecord` gains a `community_id:
  Option<String>` field (populated by `from_parts` / `from_key_fields`),
  so NDJSON / CSV / EVE FlowRecord output all carry it. The FNV hash
  stays available in-process as `KeyFields::stable_hash()` for sharding
  / keying but is non-portable. *Migration:* dashboards keying on
  `flow_hash` must pivot to `community_id` (enable the `community-id`
  feature). See `docs/migration-0.19-to-0.20.md`.
- **BUGFIX — `l7` / `full` feature umbrellas corrected** (#87 part 1).
  `full` previously carried *fewer* parsers than `l7` and was not a
  superset. `l7` now enables every license-clean protocol parser; `full`
  is `l7` + every license-clean capability (ml / ipfix / asset /
  fingerprint / observability / emit), excluding only the FoxIO-licensed
  `ja4plus`. Compile-time `compile_error!` guards
  (`src/feature_umbrellas.rs`) + new `l7` / `full` CI matrix entries
  prevent silent drift.
- **Feature tier restructure + odd-gating fixes** (#87 part 2). Coarse,
  correct umbrellas between "one parser" and `l7`/`full`, so consumers
  stop hand-assembling parser lists; granular leaf flags are unchanged.
  New tiers: `parsers-core` (http/tls/dns/icmp), `parsers-l2l3`
  (arp/ndp/lldp/cdp/dhcp), `parsers-tier2` (the 19 Tier-2 parsers),
  `ml` (ml-features + nprint), `export` (ipfix(+export) + emit writers),
  `nsm` (fingerprint + tls-fingerprints + analysis). `l7` and `full` are
  now *recomposed* from these tiers (single source of truth); each tier
  has its own `compile_error!` drift guard, and CI builds every tier
  solo. Odd-gating fixes:
  - **`asset` is now self-sufficient** — it pulls its discovery parsers
    (`arp`/`ndp`/`dhcp`/`lldp`/`cdp`/`ssdp`/`mdns`/`netbios-ns`), so
    `--features asset` no longer compiles an empty inventory. Additive;
    `mdns` transitively enables `dns`.
  - **`ml-features` → `ipfix` coupling documented** as intentional
    (the feature vector is computed from the dep-free
    `ipfix::FlowRecord`), not decoupled.
  - **`lib.rs` feature table** rewritten — was stale (http/tls/dns/pcap
    only); now documents every umbrella, tier, parser, and capability
    (Rust API guideline C-FEATURE).
- **`PacketView::with_source_idx(u32)` / `OwnedPacketView::with_source_idx`
  + `RxMetadata::from_source_idx(u32)`** (#69) — one-call per-packet
  source-index builders (cross-crate-friendly given `RxMetadata` is
  `#[non_exhaustive]`). Fixes the stale `Tagged` module doc to a live
  doctest.
- **docs/design.md reconciled with the shipped surface** (#88 part A) —
  IPFIX + `ml_features` are in-crate (non-goals updated), parsers use the
  `&mut Vec` sink, and `Driver<E>` is `Send + Sync`.

- **`detect::IocSet`** (#72) — typed threat-intel membership over
  `{ipv4, ipv6, domain, url, sha256, md5, ja3, ja4}` with optional
  per-entry reputation (Suricata `datarep`) and a feed-file loader.
  Domains match subdomain-aware (Zeek `Intel::DOMAIN`); `with_capacity`
  bounds memory.
- **`detect::FlowRisk`** + `RiskSeverity` (#73) — an nDPI-style risk
  bitset (self-signed/expired/weak/obsolete TLS, SNI↔DNS mismatch, DGA,
  cleartext creds, suspicious JA4, …) with an aggregate `score()`,
  `max_severity()`, and stable slugs. Native model re-implementation,
  not an FFI binding.
- **Risk/IOC adapters** (#83) — the pure "verbs"
  that turn parser output into the standalone primitives above:
  `FlowRisk::from_tls` (obsolete version + weak cipher via the new
  public `detect::is_weak_cipher`), `FlowRisk::from_dns` (DGA label +
  Punycode/IDN, via `DgaScorer`), `FlowRisk::from_port_proto`
  (port↔protocol mismatch / known-proto-nonstd-port, alias-token aware
  so `tls` on 443's `"tls/https"` label is consistent), and
  `IocSet::check_tls` (screens SNI + JA3 + JA4 of a `TlsHandshake` in
  one call). All pure, independently testable; gated by the relevant
  parser feature (`tls` / `extractors`).
- **`flowscope::analysis` composition layer** (#83) — behind the new
  `analysis` feature, the opt-in wiring that turns parser output into
  enriched, SIEM-ready flow records:
  - `FlowAnalyzer<K>` — bounded (TTL + capacity, LRU) per-flow
    accumulator. Feed it `observe_tls` / `observe_http` /
    `observe_dns_query` / `observe_dns_response` (each gated by its
    parser feature); `finalize(key, stats)` on the flow's `Ended`
    event computes `FlowRisk`, screens the optional `IocSet`, evicts
    the per-flow state, and returns the record. `snapshot` for a
    mid-flow view; `evict_expired` / `forget` for housekeeping.
  - `AnalyzedFlow<K>` — the enriched record: key + `FlowStats` +
    `L7Summary` + computed `FlowRisk` + `Vec<IocMatch>`, with
    `is_clean` / `severity` / `score` / `has_ioc` accessors.
  - `L7Summary` — the curated, security-relevant L7 facts (SNI/Host,
    JA3/JA4, TLS version+cipher, HTTP UA/method/URI, DNS qnames
    bounded to `MAX_DNS_QUERIES`).

  A pure composition layer (the `asset::Inventory` shape), runtime-free,
  features-not-verdicts. Example: `examples/03-detection/flow_analysis.rs`.
  `IocMatch` gains a `serde` derive (additive) so hits serialize.
  - **`EveJsonWriter::write_analyzed_flow`** (with `analysis` +
    `emit-eve`) — the SIEM-ready single-pass emit: an EVE `flow`
    event carrying the 5-tuple (+ `community_id`),
    counters, observed L7 (`tls` / `http` / `dns` objects), and a
    `flowscope` extension object with the risk slug array + aggregate
    `score` + `severity` and the threat-intel `ioc` hits.
    `flow.alerted` reflects `AnalyzedFlow::is_clean`.
- **Community ID v1 flow hashing** (#76, folds #70) — behind the new
  `community-id` feature (SHA-1 + base64). `FiveTupleKey::community_id()`
  / `KeyFields::community_id()`, emitted as `community_id` in the EVE
  writer, for cross-tool SIEM pivots (Zeek/Suricata/Security Onion).
  Golden-tested against the published spec vectors.
- **Stable shard hash** (#76, folds #70) — always-on (no crypto)
  `FiveTupleKey::stable_hash()` / `shard_index(n)` and the generic
  `KeyFields` equivalents: seed-fixed, process-stable, direction-
  invariant — both legs of a flow map to the same shard. This is a
  fast, non-portable in-process identifier (the portable cross-tool id
  is `community_id`); it is **not** emitted by the writers. `docs/sharded.md`
  and the `sharded_capture` example updated to use it.
- **`correlate::CountMinSketch` + `BloomFilter`** (#75) — mergeable
  streaming sketches alongside `HyperLogLog` (heavy-hitter frequency;
  seen-before membership). Both `Mergeable` for sharded union.
- **`correlate::BitStore`** (#74, partial) — Suricata `xbits`/`hostbits`
  semantics: per-key named flags + values with per-entry TTL.
- **DNP3 header CRC validation** (#80) — `DnpMessage::header_crc_valid`;
  the data-link header CRC is now checked (DNP3 CRC-16, verified against
  the IEEE 1815 spec vector). Per-block user-data CRCs stay unverified
  by design.
- **JA4 suite completion** (#77) — FoxIO-licensed, behind `ja4plus`:
  - **JA4T / JA4TS** (`tcp_fingerprint::{ja4t, ja4t_from_tcp, ja4t_from_parts}`,
    needs `tcp_fingerprint`) — passive TCP-stack fingerprint from a SYN /
    SYN-ACK.
  - **JA4L / JA4LS** (`ja4l::{ja4l, ja4l_client, ja4l_server}`) — handshake
    latency / "light distance" fingerprint.
  - **JA4SSH** (`ssh::Ja4sshAccumulator`, needs `ssh`) — rolling SSH-session
    fingerprint over packet sizes + ACK patterns (200-packet window).

  All three are **golden-tested against FoxIO's own Zeek test baselines** and
  bit-faithful to the reference (`zeek/ja4{t,l,ssh}/main.zeek`). The
  license-clean `tcp_fingerprint` (p0f-style) remains the non-FoxIO option.
- **CI**: `cargo-semver-checks` pre-1.0 stability gate + `community-id` /
  `ja4plus` feature-matrix entries (#78).

## 0.19.0 — RITA-style robust beacon detector

Additive over 0.18.

- **`detect::patterns::RitaBeaconDetector`** + `RitaBeaconScore` — a
  robust periodicity detector using the quartile/median statistics from
  [RITA](https://github.com/activecm/rita) v5 (`analysis/beacons.go`):
  **Bowley skewness** + **median absolute deviation (MADM)** on the
  inter-arrival intervals and payload sizes, plus a duration-coverage
  bonus. Unlike the coefficient-of-variation `BeaconDetector`, the
  median-based scoring survives outliers — a single missed beacon or a
  retransmit storm barely moves the score, where a mean/stddev CV craters
  — so it scores jittered C2 (e.g. Cobalt Strike's default jitter) far
  better. Same `observe(key, ts, bytes) -> Option<Score>` /
  `forget` / `tracked` shape as `BeaconDetector`, and a `DetectorScore`
  impl emitting a `BeaconRita` anomaly. The two statistical scores are
  bit-faithful to RITA's `calculateStatisticalScore` (verified against the
  upstream source); RITA's additional histogram/modal-fit score is not
  reproduced. Pure stats, no new dependency.

## 0.18.0 — Tier-2 protocol cycle + ML features + IPFIX export + AD recon + lateral movement + QUIC

The biggest cycle since 0.10. Drove every named row in the
`#14` Tier-2 protocol epic to completion, closed the
asset-inventory composition layer (`#27`), shipped CICFlowMeter
parity in `flowscope::ml_features` (totals + per-packet IAT +
Active/Idle + nPrint per-packet bit matrix), finished `#17`'s
cross-flow memcap enforcement story, added the binary IPFIX
wire encoder so flowscope is self-sufficient for IPFIX export
(no netring dependency in that direction), shipped the AD-recon
pair (Kerberos + LDAP), the lateral-movement SMB2/3 parser
(M1 + M2 + M3 — dialect + tree-connect + file ops + NTLM +
DCE-RPC bind), and the QUIC Initial parser (RFC 9001 §5.2
passive decryption → ClientHello SNI/ALPN).

Issues closed this cycle: `#3` QUIC Initial, `#6` NDP,
`#7` SSH+HASSH, `#8` ECH, `#9` p0f, `#10` JA4H, `#11` DHCP,
`#12` SMB2/3 (M1+M2+M3), `#13` Kerberos+LDAP, `#14` Tier-2
epic, `#15` ml-features (incl. `#30` nPrint), `#16` IPFIX-
IE-keyed FlowRecord (incl. routing), `#17` reassembler
hardening, `#20` fuzz harnesses, `#23` LLDP, `#24` JA4X,
`#25` CDP, `#26` memcap enforcement, `#27` asset inventory,
`#28` IPFIX wire encoder, `#29` DNP3, `#30` nPrint matrix.

### Added — new feature gates

| Feature | Module | Highlights |
|---|---|---|
| `arp` | `flowscope::arp` | ARP parser + `is_gratuitous` / `is_likely_spoof` predicates. Issue `#1`. |
| `ndp` | `flowscope::ndp` | IPv6 Neighbor Discovery — ARP sibling. Issue `#6`. |
| `dhcp` | `flowscope::dhcp` | RFC 2132 options + Fingerbank-style fingerprint. Issue `#11`. |
| `lldp` | `flowscope::lldp` | L2 asset discovery + rogue-switch detection. Issue `#23`. |
| `cdp` | `flowscope::cdp` | Cisco Discovery Protocol — LLDP sibling. Issue `#25`. |
| `ssh` | `flowscope::ssh` | Banner + KEXINIT + HASSH client fingerprint. Issue `#7`. |
| `tcp_fingerprint` | `flowscope::tcp_fingerprint` | p0f-style passive TCP/IP OS fingerprint. Issue `#9`. |
| `ntp` | `flowscope::ntp` | UDP/123 monlist / amplification detection. |
| `ssdp` | `flowscope::ssdp` | UPnP / IoT asset discovery. |
| `tftp` | `flowscope::tftp` | Device-config-theft visibility. |
| `mdns` | `flowscope::mdns` | RFC 6762 multicast DNS + RFC 6763 DNS-SD service walker. Pairs with `asset`. |
| `netbios-ns` | `flowscope::netbios_ns` | NBNS RFC 1002 §4.2 with name encoding/suffix decode. Pairs with `asset`. |
| `ftp` | `flowscope::ftp` | TCP/21 control channel — USER/PASS aggregation, AUTH-TLS upgrade, RETR/STOR transfer events. |
| `smtp` | `flowscope::smtp` | TCP/25+587 — MAIL FROM / RCPT TO envelope addresses, AUTH PLAIN/LOGIN base64 decode, STARTTLS upgrade, DATA body byte counting. |
| `wireguard` | `flowscope::wireguard` | Passive WG handshake detection (Donenfeld 2017). |
| `modbus` | `flowscope::modbus` | TCP/502 OT visibility — function codes + exception codes + read/write decode. |
| `stun` | `flowscope::stun` | RFC 5389 — WebRTC peer detection + NAT-type discovery via XOR-MAPPED-ADDRESS. |
| `rdp` | `flowscope::rdp` | X.224 negotiation metadata-only (T1021.001) — `Cookie: mstshash=USER` capture + RDP protocol flags. |
| `snmp` | `flowscope::snmp` | v1/v2c via rusticata snmp-parser — community string + PDU + varbind OIDs. |
| `radius` | `flowscope::radius` | RFC 2865/2866 via rusticata radius-parser — identity attributes for NAC/wireless-auth correlation. |
| `asset` | `flowscope::asset` | Unified `Asset` + LRU-bounded `Inventory` composition layer over `arp`/`ndp`/`dhcp`/`lldp`/`cdp`/`ssdp`/`mdns`/`netbios-ns`. Issue `#27`. |
| `ipfix` | `flowscope::ipfix` | IANA IE registry constants + `FlowRecord` IE-keyed canonical record + `flowEndReason` + `tcpControlBits` helpers. Scoped piece of `#16`. |
| `ipfix-export` | `flowscope::ipfix::wire` | RFC 7011/7012 binary IPFIX Message encoder — `MessageBuilder` + `TemplateRegistry` + default IPv4/IPv6 templates. Issue `#28`. |
| `ml-features` | `flowscope::ml_features` | CICFlowMeter parity — totals/throughput + per-packet IAT + Active/Idle period accounting. Issue `#15`. |
| `ml-features-nprint` | `flowscope::nprint` | nPrint (CCS 2021) per-packet ternary header-bit matrix for model-agnostic ML. Eth/IPv4/TCP/UDP base headers, bounded at 100 packets/flow default. Issue `#30`. |
| `dnp3` | `flowscope::dnp3` | DNP3 (IEEE 1815-2012) OT/SCADA metadata — link header + first-block application header + IIN bits. Link-layer reassembly deliberately out (Suricata CVE-2026-22259). Issue `#29`. |
| `kerberos` | `flowscope::kerberos` | Kerberos passive metadata (TCP/UDP 88) — AS/TGS/KRB-ERROR. Surfaces principals, realm, etype list, and `kerberoast_suspect` boolean (TGS-REQ + RC4-HMAC = MITRE T1558.003). Issue `#13`. |
| `ldap` | `flowscope::ldap` | LDAP RFC 4511 (TCP/389) — Bind/Search/Result, `creds_present` (Simple bind), `search_attributes_spn_query` (BloodHound / GetUserSPNs signal, MITRE T1087). Issue `#13`. |
| `smb` | `flowscope::smb` | SMB2/3 (TCP/445) — dialect detect + command + tree-connect target + CREATE filename + READ/WRITE size + NTLM identity (domain/user/workstation) + DCE-RPC BIND UUIDs. Lateral-movement / pass-the-hash / credential-dump / PrintNightmare visibility (MITRE T1021.002, T1550.002, T1003). Issue `#12`. |
| `quic` | `flowscope::quic` | QUIC Initial (UDP/443) — RFC 9001 §5.2 Initial-secret derivation + AEAD decrypt + CRYPTO reassembly + ClientHello → SNI/ALPN. The only L7 visibility for HTTP/3 and DNS-over-QUIC. Issue `#3`. |
| `fingerprint` | `flowscope::detect::fingerprint` | First-N packet-length + IAT baseline. Issue `#4`. |

### Added — new infrastructure

- **`flowscope::correlate::WelfordStats`** — Welford's online running statistics primitive (count, mean, sample/population variance, min, max, parallel merge). Used by FlowStats IAT + Active/Idle but generally useful.
- **`flowscope::correlate::NeighborTable`** + `ArpTable` alias — IP → link-layer binding tracker for spoof detection. Issue `#1`.
- **TCP overlap-policy reassembler hardening** — `TcpOverlapPolicy` enum (First/Last/LowerSeq/HigherSeq) + tracker-wide config. Cross-flow `reassembly_memcap` + `MemcapPolicy` enforced in `FlowDriver`. Issue `#17` + `#26`.
- **`Reassembler::rexmit_inconsistencies()`** — Ptacek-Newsham TCP overlap-evasion IOC. Scoped piece of `#17`.
- **`Driver<E>`: `Send + Sync`** — structural fix (commit 5b53a6b earlier); composes with `Arc` sharing.

### Added — FlowStats fields (additive — struct is `#[non_exhaustive]`)

- `last_seen_initiator` / `last_seen_responder: Timestamp`
- `iat_flow` / `iat_initiator` / `iat_responder: WelfordStats`
- `active_periods` / `idle_periods: WelfordStats`
- `active_period_start: Option<Timestamp>`

### Added — FlowRecord fields (`#[non_exhaustive]`)

- `retransmits_initiator` / `retransmits_responder: u64` — flowscope-specific extension fields so the CSV emitter can fully reproduce its existing schema through the `write_flow_record` path.
- `original_end_reason: Option<EndReason>` — flowscope private-enterprise extension that preserves the 8-variant `EndReason` fidelity that IPFIX IE 136 (`flowEndReason`) collapses to 5 standard values. Internal flowscope consumers (CSV / Zeek / NDJSON / EVE writers) prefer this shadow when present; pure-IPFIX consumers read `flow_end_reason`. Issue `#16` close.

### Added — KeyFields trait

- `KeyFields::protocol_identifier() -> Option<u8>` — IANA L4 protocol number (TCP=6 / UDP=17 / ICMP=1 / ICMPv6=58 / SCTP=132). Overrides on `FiveTupleKey` + `L4Proto`. Default `None`. Enables the generic `FlowRecord::from_key_fields<K: KeyFields>` builder. Issue `#16`.

### Added — FlowRecord generic constructor

- `FlowRecord::from_key_fields<K: KeyFields>(stats, key, end_reason)` — generic builder used by every emit writer's `write_event(FlowEnded)` path so the IPFIX-IE-keyed FlowRecord is the single canonical record shape; emit writers are pure views over it. `FlowRecord::from_parts` is a thin wrapper around it for the `FiveTupleKey`-specialised call site.

### Changed — emit writers

- **CSV** and **EVE** `write_event(FlowEnded)` paths now route through `write_flow_record` when `ipfix` is enabled — single source of truth for the FlowEnded row shape. **Zeek** and **NDJSON** keep their parallel paths (Zeek's `history` column has no FlowRecord equivalent; NDJSON's `write_event` and `write_flow_record` serialize different schemas by design). Issue `#16` close.

### Added — FlowTrackerConfig fields

- `tcp_overlap_policy: TcpOverlapPolicy` (default `First`)
- `reassembly_memcap: Option<u64>`
- `reassembly_memcap_policy: MemcapPolicy` (default `Ignore`)
- `active_idle_threshold: Option<Duration>` (default `Some(1s)` per CICFlowMeter)

### Added — emit module

- **`write_flow_record(&FlowRecord)`** on CSV / Zeek / NDJSON / EVE — gated on `ipfix`. Each emitter now accepts a `FlowRecord` directly; the user-visible "every emitter is a view over FlowRecord" surface from issue `#16` lands.
- New `EveOptions::custom_anomaly_type` field, `EveJsonWriter::write_owned_anomaly`.

### Added — strong types on marquee security signals

- **`flowscope::kerberos::KerberosEtype`** — typed enum over the IANA `etype` registry (DES / 3DES / AES-128/256 / RC4-HMAC / etc.) with `is_aes()` / `is_rc4()` / `is_weak()` / `is_des()` predicates, `Display`, `From<i32>` / `Into<i32>`. `KerberosMessage::etypes` is now `Vec<KerberosEtype>` instead of `Vec<i32>` — the security-relevant question "is this Kerberoasting-prone?" reduces to `etype.is_rc4()` at the call site.
- **`flowscope::quic::QuicVersion`** — typed enum over RFC 9000 v1, RFC 9369 v2, IETF drafts (`0xff000000..0xff00007f`), and `Other(u32)`. `is_v1()` / `is_v2()` / `is_draft()` predicates, `Display` (renders `v1` / `v2` / `draft-NN` / `0x...`), `From<u32>` / `Into<u32>`. `QuicInitial::version` is now `QuicVersion` instead of `u32`.
- **`flowscope::smb::DceRpcInterfaceUuid`** — `#[repr(transparent)]` 16-byte newtype with canonical hyphenated-hex `Display`, `Hash`, `Eq`, and a `well_known_name()` reverse lookup over 11 curated lateral-movement / cred-dump / DCSync interfaces (`svcctl` / `winreg` / `lsarpc` / `samr` / `netlogon` / `spoolss` / `atsvc` / `eventlog` / `wkssvc` / `srvsvc` / `drsuapi`). `SmbMessage::dcerpc_bind_uuids` is now `Vec<DceRpcInterfaceUuid>` instead of `Vec<String>` — eliminates duplicate `format!` allocations and enables typed-equality comparison.

### Added — high-level one-call helpers

- **`flowscope::tls::client_hellos_from_pcap`** + **`handshakes_from_pcap`** — yield `(FiveTupleKey, TlsClientHello)` / `(FiveTupleKey, TlsHandshake)` over the full pcap → tracker → reassembler → TlsParser pipeline in one call. For TLS visibility examples this collapses the manual `Driver::builder + SlotHandle + clear+drain` quartet to 3 lines.
- **`flowscope::quic::initials_from_pcap`** — same shape for QUIC Initial decode → ClientHello SNI/ALPN.
- **`flowscope::smb::messages_from_pcap`** — same shape for SMB lateral-movement signals.
- **`SlotHandle::drain_replacing(&mut Vec<_>)`** — eliminates the `out.clear(); slot.drain(&mut out);` two-step in every per-packet drain loop. Pure additive; reads at the call site as the single thing it is.

### Added — prelude

- `FiveTupleKey` — used as `Event<FiveTupleKey>` / `SlotMessage<_, FiveTupleKey>` annotations in every consumer; previously required `use flowscope::extract::FiveTupleKey;`.
- `KerberosEtype`, `QuicVersion`, `DceRpcInterfaceUuid` — the new strong-typed enums above.

### Removed — stale `Pipeline` references

- The 0.10-era `flowscope::Pipeline` type was deleted in plan 121 (0.11 typed-driver collapse) but CLAUDE.md still described it as the "highest-level entry point". Swept the references; replaced with the actual current shape (`*_from_pcap` per-parser iterators + `PcapFlowSource::sessions` for unsurveyed parsers).

### Added — TLS handshake fields

- `TlsHandshake::certificate_chain: Vec<Bytes>` — leaf-first TLS 1.2 cert chain. Issue `#24` prereq.
- `TlsHandshake::ja4x: Option<String>` (behind `ja4plus`) — JA4X server-cert fingerprint computed automatically from the leaf cert.

### Added — IPFIX module

- `FlowRecord` IE-keyed canonical flow record with `from_parts(&FlowStats, &FiveTupleKey, Option<EndReason>)` constructor.
- `FlowEndReason` + `From<EndReason>` mapping (5-state IPFIX-canonical vocabulary).
- `encode_tcp_control_bits` helper (RFC 7125).
- `flowscope::ipfix::wire` binary encoder (`MessageBuilder`, `TemplateRegistry`, `TemplateDefinition`, `FieldSpec`, `EncodeError`, default `FLOWSCOPE_TEMPLATE_FLOW_IPV4` / `_IPV6`).

### Added — examples

- `examples/05-export/ipfix_wire_export.rs` — end-to-end pcap → FlowRecord → IPFIX Message bytes.

### Changed (pre-1.0 breaking)

- `AssetSourceSet` bitflag added `MDNS` (bit 6) and `NBNS` (bit 7); `OTHER` reserved-for-future-parsers comment updated.
- `FieldSpec::wire_length()` const — 4 bytes for IANA IEs, 8 with enterprise number set.
- **Strong-type lifts across LDAP / Kerberos / DNP3 / nPrint** ([#66](https://github.com/p13marc/flowscope/issues/66)). Four primitive-typed fields graduated to dedicated enums modelled on the existing 0.18 `QuicVersion` / `KerberosEtype` / `DceRpcInterfaceUuid` shape:
  - `flowscope::ldap::LdapMessage::result_code: Option<u32>` → `Option<LdapResultCode>` (RFC 4511 §4.1.9 codes; 14 spelled-out variants + `Other(u32)`).
  - `flowscope::ldap::LdapMessage::search_scope: Option<u32>` → `Option<LdapSearchScope>` (`BaseObject` / `SingleLevel` / `WholeSubtree` + `Other`).
  - `flowscope::kerberos::KerberosMessage::error_code: Option<i32>` → `Option<KerberosErrorCode>` (RFC 4120 §7.5.9 codes; 8 spelled-out variants including the brute-force / password-spray signals + `Other(i32)` + an `is_brute_force_signal()` predicate).
  - `flowscope::nprint::NPrintRow::bits: Vec<i8>` → `Vec<NPrintBit>` (`Absent` / `Zero` / `One`; per-row memory footprint unchanged — still one byte per bit).
  - `flowscope::dnp3::DnpMessage::link_dir: bool` → `DnpLinkDirection` (`ToOutstation` / `ToMaster`).
  - `flowscope::dnp3::DnpMessage::link_prm: bool` → `DnpLinkRole` (`Primary` / `Secondary`).
  Each enum: `from_raw(value)` + `as_raw()` / `as_bit()` round-trip + `as_str()` (stable lowercase slug for metric labels) + `Display` (alias for `as_str()`). All enums are `#[non_exhaustive]`. Migration: replace `if result_code == Some(0)` with `result_code == Some(LdapResultCode::Success)`; replace `if bit == 0` with `if matches!(bit, NPrintBit::Zero)`; replace `link_dir` boolean checks with `matches!(link_dir, DnpLinkDirection::ToOutstation)`.
- **`parse()` Option → Result sweep across new modules** ([#65](https://github.com/p13marc/flowscope/issues/65)). The 0.18 parsers each now return `Result<T, ParseError>` instead of `Option<T>`, with a per-module `ParseError` enum exposing the operationally-distinct failure mode:
  - `flowscope::dnp3::{parse, ParseError}` — `Truncated { need, have }` / `BadStartBytes` / `InvalidLength(u8)`.
  - `flowscope::kerberos::{parse, ParseError}` — `Empty` / `UnknownTag(u8)` / `AsnDecode`.
  - `flowscope::ldap::{parse, parse_with_len, ParseError}` — `AsnDecode` (single variant — rusticata ldap-parser doesn't surface granular causes).
  - `flowscope::smb::{parse, ParseError}` — `Truncated { need, have }` / `UnknownProtocol`.
  - `flowscope::quic::{parse, ParseError}` — `NotInitial` / `AeadDecryptFailed` / `CryptoFrameDecode` (with a reserved future `_NoClientHello` variant — currently `parse` returns the metadata-only `QuicInitial` when CRYPTO is empty).
  Migration: replace `if let Some(msg) = parse(...)` with `if let Ok(msg) = parse(...)`. The SessionParser / DatagramParser wrappers handle this internally — no behavioral regression for users of the typed-driver path.

### Fixed

- pre-existing test-feature-gate bugs in `error.rs` / `test_helpers.rs` that broke partial-feature `cargo test` builds (mDNS commit f9c1df9 caught + fixed in passing).
- ipfix `timestamp_to_unix_ms` cfg-gating so `ipfix`-only builds without `tracker` stop dead-code warning (commit 40ca1fe).

### Stats

- **1619 tests passing** (up from 809 at 0.13.0 start; +810 over the cycle).
- Zero clippy warnings under `--all-features --all-targets -D warnings`.
- Zero rustdoc warnings under `RUSTDOCFLAGS=-D warnings`.
- `cargo machete` clean (no unused deps).
- **26 CI feature-matrix entries** (`ipfix`, `ntp`, `ssdp`, `tftp`, `asset`, `mdns`, `netbios-ns`, `ftp`, `smtp`, `wireguard`, `modbus`, `stun`, `rdp`, `ml-features`, `ml-features-nprint`, `ipfix-export`, `snmp`, `radius`, `dnp3`, `kerberos`, `ldap`, `smb`, `quic`, the `asset,*` combos).

### Fixed (build hygiene)

- `extractors` feature missing `dep:smallvec` despite using `SmallVec` in `layers/` since 0.9. Latent CI gap surfaced by `ml-features-nprint` (the first matrix entry whose minimum feature set is just `extractors`). One-line manifest fix.

## 0.17.0 — multi-source / RX-metadata / ARP / fingerprint cycle (in progress)

Driven by the four netring-flagged issues
([#1](https://github.com/p13marc/flowscope/issues/1) /
[#2](https://github.com/p13marc/flowscope/issues/2) /
[#4](https://github.com/p13marc/flowscope/issues/4) /
[#5](https://github.com/p13marc/flowscope/issues/5)) — the fifth
([#3 QUIC Initial parser](https://github.com/p13marc/flowscope/issues/3))
is genuinely a multi-day cycle on its own (crypto + 3 fuzz
harnesses) and is deferred to its own release.

### Breaking (pre-1.0)

- **`PacketView` and `OwnedPacketView` are `#[non_exhaustive]`**
  (issue #2). Struct-literal construction from outside the crate
  no longer compiles. Migration: use `PacketView::new(frame,
  ts)` (shipped since 0.2) and the new
  `.with_rx_metadata(rx)` builder. This break unlocks every
  future `PacketView` field addition being purely additive.
- **`MacPairKey::a` / `.b` are now `MacAddr` instead of `[u8; 6]`**
  (issue #1). `MacAddr` is a `#[repr(transparent)]` newtype with
  `Display` (`aa:bb:cc:dd:ee:ff`), predicates (`is_broadcast` /
  `is_multicast` / `is_unicast` / `is_locally_administered` /
  `is_zero`), `ZERO` + `BROADCAST` constants, and
  `From<[u8; 6]>` / `Into<[u8; 6]>` for wire-format interop.

### Added

#### Issue #5 — `Tagged<E, T>` extractor combinator (tap-merge)

`flowscope::extract::Tagged<E, T>` prefixes any extractor's key
with a per-packet tag. Per-source attribution becomes
`Tagged::new(extractor, tag_fn)`; source-merged stays the bare
extractor. The `FlowTracker` requires no API change — the
merge knob is purely at extractor registration time. Pairs
naturally with `RxMetadata::source_idx` (see #2).

#### Issue #2 — `RxMetadata` on `PacketView`

`flowscope::rx_metadata::RxMetadata { hw_timestamp, rx_hash,
vlan, checksum, source_idx }` — per-packet hardware-provided
metadata threaded through from the NIC's receive path. Every
field is independently optional / defaulted, so pcap /
synthetic sources need no changes. Mirrors Linux's
`XDP_RX_METADATA_*` enumeration for direct netring translation.
Re-exported at crate root: `ChecksumStatus`, `RssHashType`,
`RxHash`, `RxMetadata`, `VlanProto`, `VlanTag`. `VlanTag`
ships `.vid() / .pcp() / .dei()` accessors.

#### Issue #1 — `MacAddr` + `arp` feature + `NeighborTable`

- Crate-root `MacAddr` newtype (see Breaking above).
- New opt-in `arp` feature:
  - `flowscope::arp::ArpMessage { oper, sender, sender_ip,
    target, target_ip }` — always IPv4-over-Ethernet,
    non-conforming wire shapes rejected at parse.
  - `ArpOp::{ Request, Reply, RarpRequest, RarpReply, Other(u16) }`
    with `as_str()` slugs + `From<u16>`.
  - `ArpMessage::is_gratuitous()` + `is_likely_spoof()`
    convenience predicates (spoof = gratuitous reply with
    `target_mac != sender_mac`).
  - `arp::parse(payload)` / `arp::parse_frame(frame)` —
    stateless free-function parser (ARP has no 5-tuple flow
    concept; consumers integrate by checking EtherType
    `0x0806`). `parse_frame` strips one 802.1Q VLAN tag
    transparently.
- New always-on `flowscope::correlate::NeighborTable<L3, L4>` —
  generic IP→link-layer binding tracker with TTL + LRU
  bounds. Generic from day one so the future IPv6 NDP module
  reuses the same storage without rename. Returns
  `NeighborEvent::{ NewBinding, Refresh, Changed }` from
  `.observe(ip, addr, now)`.
- `correlate::ArpTable` type alias under `arp` feature.
- `l7` umbrella now includes `arp`.

#### Issue #4 — `flowscope::detect::fingerprint`

New opt-in `fingerprint` feature — encrypted-flow behavioural
fingerprinting via packet-length + inter-arrival sequences.

- `FingerprintBuilder` — alloc-free per-flow accumulator.
  `.observe(payload_len, is_initiator, ts_micros)` is the
  per-packet hook. Backed by `ArrayVec<_, 32>`; further packets
  past the 32-sample cap silently no-op the sequence push but
  keep updating aggregate counters.
- `FlowFingerprint` — finalised form. Hashable + serde. Two
  consumer surfaces: `fnv1a() -> u64` for IOC equality;
  `as_features() -> [f64; 8]` for ML-pipeline export.
- Prior-art citations: Cisco Joy / Mercury (SPLT); FoxIO
  JA4L / JA4LS; Anderson & McGrew (ACM AISec 2016).
- Privacy footnote in module rustdoc.

Test count: **994 passing** (+59 over 0.16.0). Zero clippy
warnings under `--all-features --all-targets -D warnings`,
zero rustdoc warnings.

## 0.16.0 — JA4S behind opt-in `ja4plus` (FoxIO License)

**Licensing correction (breaking for JA4S users).** JA4S is part of the JA4+
suite and is licensed under the **FoxIO License 1.1** (source-available,
non-commercial; patent pending) — *not* MIT/Apache like the rest of flowscope.
In 0.15 it shipped under `tls-fingerprints` alongside the BSD JA3 + JA4-client
fingerprints, which inadvertently put FoxIO-licensed code in the royalty-free
surface.

### Changed (breaking)

- **JA4S moved to a new opt-in `ja4plus` feature** (off by default, and
  deliberately excluded from `l7` / `full`). The default build and
  `tls-fingerprints` now contain **only** the royalty-free JA3 + JA4 *client*
  fingerprints. To get JA4S, enable `ja4plus` explicitly.
  - Gated behind `ja4plus`: `tls::ja4s` module (`ja4s` / `ja4s_parts` /
    `Ja4sParts`), `TlsMessage::Ja4s`, `TlsHandshake.ja4s`.
  - `TlsServerHello.extension_types` stays ungated — it's generic observed
    data, not the FoxIO algorithm.
- **`LICENSE-FoxIO-1.1` + `NOTICE`** added at the crate root and shipped in the
  published package. Per the FoxIO License, the license text + notices travel
  with every copy of the source (a cargo feature gates *compilation*, not what's
  in the `.crate` tarball). `src/tls/ja4s.rs` carries an
  `SPDX-License-Identifier: LicenseRef-FoxIO-1.1` header.

### Migration

- Using JA4S? Add `features = ["ja4plus"]` (it implies `tls-fingerprints`).
- **Commercial use of JA4S requires a FoxIO OEM license** — see NOTICE.
- Code reading `TlsHandshake.ja4s` or matching `TlsMessage::Ja4s` must be
  `#[cfg(feature = "ja4plus")]`.

## 0.15.0 — JA4S server fingerprinting

Additive (0 new deps). Adds the ServerHello half of JA4 fingerprinting,
so the TLS observer can fingerprint both ends of a handshake.

### Added

- **JA4S** (`tls::ja4s`, feature `tls-fingerprints`) — `ja4s(&TlsServerHello)`
  / `ja4s_parts` / `Ja4sParts`, the FoxIO ServerHello fingerprint
  (`[t|q][version][ext_count][alpn]_[cipher]_[ext_hash]`). The extension
  list is hashed in observed order (servers don't shuffle), GREASE
  removed.
- `TlsServerHello::extension_types: Vec<u16>` — the ServerHello extension
  order, populated by the parser (feeds JA4S).
- `TlsMessage::Ja4s { fingerprint }` — emitted by `TlsParser` after each
  ServerHello when `TlsConfig::ja4` is set.
- `TlsHandshake::ja4s: Option<String>` — the aggregator surfaces JA4S
  alongside the existing `ja4` (client) field.

### Changed

- **JA4/JA4S ALPN encoding fixed to the FoxIO spec** (first + last char of
  the ALPN, e.g. `http/1.1` → `h1`). The client JA4 previously used the
  first two chars; single/two-char ALPNs like `h2` are unaffected, but
  multi-char ALPNs now match reference JA4 databases.

## 0.14.1

Bug fix found during netring 0.22 adoption.

### Fixed

- **ICMP datagram routing.** `datagram_broadcast(IcmpParser::new())`
  silently delivered nothing: the datagram driver's payload extractor
  matched only `TransportSlice::Udp`, so ICMPv4/ICMPv6 frames were
  skipped and the ICMP parser never ran. `extract_udp_payload` now also
  returns the full ICMP message bytes for `TransportSlice::Icmpv4` /
  `Icmpv6`. This unblocks ICMP-error correlation
  (`datagram_broadcast(IcmpParser)` → `IcmpMessage` → `error_inner` →
  `FlowTracker::stats_for_inner`). Regression test:
  `tests/icmp_datagram_routing.rs`. The path was previously untested at
  the driver level (only `parse_v4`/`parse_v6` were unit-tested).

## 0.14.0

The **operations-layer ergonomics** cycle. Driven by netring
0.22 adoption (wishlist file retired after cycle release —
durable record in this changelog + `git log`).

Mostly additive — one **breaking removal** in the post-audit
polish round: `LabelTable::override_count` renamed to
`LabelTable::len`. Safe because `override_count` only ever
shipped on master, never on crates.io. Find/replace migration
in `docs/migration-0.13-to-0.14.md` §10.

Test count after the cycle: **920 passing** (up from 809 at
0.13.0 release, +111 new). Zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings. All 13 CI feature-matrix combinations clean.

Migration: [`docs/migration-0.13-to-0.14.md`](docs/migration-0.13-to-0.14.md).

### Removed (breaking, pre-1.0)

- **`LabelTable::override_count`** (plan 172) — replaced by
  the idiomatic `LabelTable::len()` (same semantics). Pre-1.0,
  only on master, never on crates.io.

### Added — pre-release polish round (plans 170-174)

- **`flowscope::icmp::MtuSignalKind`** + **`IcmpType::mtu_signal()`**
  + **`IcmpMessage::mtu_signal()`** + **`MtuSignalKind::next_hop_mtu()`**
  + **`MtuSignalKind::as_str()`** (plan 170). Unified v4
  `FragmentationNeeded` + v6 `PacketTooBig` PMTU-mismatch
  signal. Sibling to `DestUnreachableKind` for non-DU
  classification. Re-exported at crate root + in prelude.
- **`RollingRate::sum(k, now)`** + **`top_k(n, now)`** +
  **`clear()`** + **`len(now)`** (plan 171). `sum` is the
  raw window sum (sibling to `rate`); `top_k` is the built-in
  sorted top-N (no manual `snapshot().collect().sort()`
  dance); `clear` drops all buckets; `len` counts unique
  in-window keys.
- **`LabelTable::remove`** + **`contains`** + **`is_empty`**
  + **`len`** (plan 172). Inverse + introspection ops for
  hot-reload config without restart. `len` replaces the
  removed `override_count`.
- **`FlowStats::throughput_bps`** + **`throughput_pps`** +
  **`throughput_bps_for(side)`** + **`throughput_pps_for(side)`**
  (plan 173). Lifetime-average throughput with safe-divide
  built in — zero-duration flows return `0.0`, not NaN /
  Infinity.
- **Three runnable examples** for the 0.14 surface (plan 174):
  - `examples/04-observability/bandwidth_by_app.rs` — `RollingRate`
    + `top_k` + `LabelTable` + `app_label_with`.
  - `examples/04-observability/icmp_explained_drops.rs` —
    `FlowTracker::lookup_inner` + `stats_for_inner` +
    `DestUnreachableKind` + `MtuSignalKind`.
  - `examples/04-observability/direction_skew_anomaly.rs` —
    `FlowStats::direction_skew` + `bytes_for` +
    `throughput_bps_for`.
- **Rustdoc cross-links** (plan 174) — `RollingRate` ↔
  `TimeBucketedCounter` / `TopK` / `Ewma` / `BurstDetector`;
  `DestUnreachableKind` ↔ `MtuSignalKind`; `app_label` ↔
  `app_label_with`; `evict_expired` ↔ `drain_expired`; per-
  side throughput accessors ↔ their non-`_for` siblings.

### Added — base round (plans 160-168)

- **`flowscope::correlate::RollingRate<K, V>`** + 
  **`flowscope::correlate::RateValue`** (plan 164). Per-key
  per-second rate over a sliding window. Sibling to
  `TimeBucketedCounter` but generic over the value type
  (bytes/sec, request count, latency sums). Bucket-reuse
  zero-alloc when consecutive records fall in the same
  bucket. `RateValue` is a small sealed-style trait
  implemented for `u64` / `u32` / `i64` / `i32` / `f64` /
  `f32`. Methods: `new_unbounded` / `record` / `rate` /
  `snapshot` / `for_each_bucket` / `evict_expired` /
  `bucket_count` / `is_empty`.
- **`flowscope::well_known::LabelTable`** + 
  **`FiveTupleKey::protocol_label_with`** + 
  **`FiveTupleKey::app_label_with`** (plan 165). Site-custom
  port label extensibility. `LabelTable::new` inherits the
  built-in table; `LabelTable::standalone` is whitelist-only.
  `Send + Sync + Clone`. Labels are `&'static str` (use
  `Box::leak` for runtime-loaded strings).
- **Discoverability sweep** (plan 167):
  - **Prelude expanded** with `TimeBucketedCounter`,
    `TimeBucketedSet`, `KeyIndexed`, `BurstDetector`, `Ewma`,
    `TopK`, `RollingRate`, `FlowStateMap`, `IcmpType`,
    `IcmpMessage`, `IcmpInner`, `LabelTable`. The full
    prelude manifest is in `docs/discoverability.md`.
  - **New `docs/discoverability.md`** — one-page tour
    grouped by use case ("count things per key over time" /
    "react to ICMP errors" / "emit structured anomalies" /
    …). Lists every shipped primitive with one-line pitches
    + rustdoc links.
- **`FiveTupleKey::from_inner_canonical(&IcmpInner) -> Option<FiveTupleKey>`**
  + **`FiveTupleKey::from_inner_literal(&IcmpInner) -> Option<FiveTupleKey>`**
  (plan 161). Public canonicalisation helpers that build a
  `FiveTupleKey` from an ICMPv4 / ICMPv6 error message's
  embedded original 5-tuple. The canonical variant applies the
  same `src > dst` swap as `FiveTuple::bidirectional()`; the
  literal variant preserves the orientation for
  `FiveTuple::unidirectional()` consumers. Returns `None` when
  a port-carrying proto (TCP / UDP / SCTP) has missing ports.
  Gated on the `icmp` feature.
- **`FlowTracker<FiveTuple, S>::lookup_inner(&IcmpInner) -> Option<FiveTupleKey>`**
  + **`stats_for_inner(&IcmpInner) -> Option<(FiveTupleKey, FlowStats)>`**
  (plan 161). Specialised impl block (FiveTupleKey-shaped
  lookups are FiveTuple-extractor specific). Joins an ICMP
  error back to a live flow with one method call — replaces
  the hand-rolled `HashMap<FlowKey, FlowStats>` mirror cache
  every L4 monitor was rebuilding. Direction-agnostic via the
  canonicalisation helper. O(1) hash lookup. Gated on `icmp`.
  
  Verified-wrong wishlist claim: the plan 161 caveat asserted
  `FlowTracker` was "mutate-only". `FlowTracker<E, S>` actually
  exposes `get`, `snapshot_stats`, `flows`, `iter_active`
  already — no refactor needed.
- **`L4Proto::canonical_name() -> &'static str`** (plan 163).
  Lowercase, always-Some sibling to the existing `proto_str()`
  (which is uppercase + `Option`, for EVE / Suricata schema).
  Returns `"tcp"`, `"udp"`, `"icmp"`, `"icmp6"`, `"sctp"`,
  `"other"`. Use for metric labels and snake_case slugs.
- **`FiveTupleKey::app_label() -> &'static str`** (plan 163).
  Always-Some companion to `protocol_label()`. Falls back to
  `proto.canonical_name()` when no well-known L7 label matches.
  Removes the `is_tcp: bool` workaround from bandwidth-by-app
  reports.
- **`flowscope::icmp::DestUnreachableKind`** enum + 
  **`IcmpType::dest_unreachable_kind() -> Option<DestUnreachableKind>`**
  (plan 162). Unified v4/v6 vocabulary for the ~17 ICMPv4 and
  ~8 ICMPv6 Destination Unreachable codes. Replaces the
  ~30-line classifier consumers were writing per-pipeline.
  `as_str()` returns a stable metric-label slug. Re-exported
  at the crate root (`flowscope::DestUnreachableKind`) and in
  the prelude. **Match on the v4/v6 code enums directly when
  you need the exact code or the v4 `FragmentationNeeded` MTU.**
- **`flowscope::icmp::types` is now `pub mod`** (plan 162;
  absorbs the wishlist's plan 166). The canonical short path
  (`flowscope::icmp::DestUnreachableKind` via the existing
  `pub use types::*;` glob) is unchanged; the new
  `flowscope::icmp::types::Icmpv6DestUnreachCode` long path
  now also resolves. Pre-fix, rustdoc + autocomplete
  suggested the long path but it failed to compile (private
  module).
- **`KeyIndexed::drain_expired(now) -> Vec<(K, V)>`** + 
  **`drain_expired_into(now, &mut Vec<(K, V)>) -> usize`**
  (plan 160). Sibling to `evict_expired` (which discards) —
  returns the expired entries as owned `(K, V)` pairs so the
  caller can inspect them. Typical for "DNS resolved but no
  connection followed", "ICMP didn't explain a flow death"
  patterns. The `_into` variant amortises allocation across
  calls. Honest allocation contract: the underlying
  `lru::LruCache` has no `drain()`, so a `Vec` is unavoidable.
- **`FlowStats::bytes_for(side)`** / **`pkts_for(side)`** /
  **`mean_pkt_size_for(side)`** / **`direction_skew()`** (plan
  168). Pure sugar over the existing `bytes_initiator` /
  `bytes_responder` / `packets_*` fields. `direction_skew` is
  `(bytes_initiator - bytes_responder) / total_bytes`, clamped
  to `[-1, 1]`. Useful for one-sided-flow detection (DoS,
  scans, CDN downloads).

## 0.13.0

The **fully `Send + Sync` driver** + **canonical anomaly value type**
+ **detector-output uniformity** cycle. Driven by netring 0.21
adoption friction (wishlist file retired after cycle release).

### Added

- **`examples/00-getting-started/sharded_capture.rs`** +
  **`docs/sharded.md`** — sharded-driver recipe (plan 155).
  Shows the N-thread + per-shard `Driver<E>` pattern with
  cross-shard aggregation via `AtomicU64` counters. Built on
  plan 156's `Driver<E>: Send + Sync`. Recipe covers the
  when-to-shard decision, CPU pinning, netring composition,
  and the per-shard detector pitfall.
- **`flowscope::correlate::FlowStateMap<T, K>`** — per-flow
  typed state with automatic eviction on `FlowEvent::Ended`
  + TTL sweep (plan 154). Layered over `KeyIndexed<K, T>` —
  ~150 LoC. `get_or_default(&key, now)` lazily constructs
  `T::default()`; `feed(&FlowEvent)` drives eviction/refresh;
  `sweep(now)` removes idle entries. Defaults `K` to
  `FiveTupleKey` for the common case.
- **`flowscope::test_helpers::events`** — synthetic
  `FlowEvent` + `driver::Event` constructors (plan 153). Use
  `events::started(key, ts)` instead of the multi-line field-
  init dance. Sub-module `events::driver` mirrors the typed
  driver's `Event<K>` variants. Saves the `#[doc(hidden)]
  pub fn new` escape hatch downstream test crates have been
  using.
- **`flowscope::correlate::KeyIndexed::get_mut`** — mutable
  TTL-aware get (plan 154 prereq). Mirrors `get` returning
  `&mut V` so consumers mutate in place without
  `remove` + `insert`.
- Fix: `KeyIndexed::new_unbounded` now uses
  `lru::LruCache::unbounded()` under the hood instead of
  `LruCache::new(usize::MAX)`. The latter caused hashbrown
  capacity overflow on first insert. Plan 154 follow-up.
- **`PcapFlowSource::with_speed_factor(f64)`** — time-realistic
  pcap replay pacing (plan 152). `1.0` = original timing, `2.0`
  = double speed, `f64::INFINITY` = as-fast-as-possible
  (default). Sleeps `std::thread::sleep(dt / factor)` between
  consecutive packets. Tokio caveat documented: blocking sleep
  monopolises the worker; use `spawn_blocking` or a dedicated
  thread.
- **`BroadcastSlotHandle<M, K>`** + 
  **`DriverBuilder::session_on_ports_broadcast_each`** —
  fan-out drain handle for session parsers (plan 150). Where
  `SlotHandle::clone` produces a competitive consumer (MPMC —
  one message goes to one drainer), `BroadcastSlotHandle::clone`
  produces a fresh subscriber that sees **every** message.
  Backed by `Arc<BroadcastInner>` holding a
  `Mutex<Vec<Weak<SegQueue<...>>>>` subscriber list; the slot's
  push fans out to every live subscriber, pruning dead Weaks
  inline. Per-push cost is O(subscribers) clones + atomic
  pushes — typically negligible (logger + metrics + sink = 3
  subscribers). New `M: Clone` bound on the broadcast variant
  (every shipped parser message — `HttpMessage`, `DnsMessage`,
  `TlsMessage` — already derives `Clone`). Drop-prunes
  subscribers lazily.
  
  For 0.13: shipped for `session_on_ports` only. Datagram +
  heuristic broadcast variants defer to 0.14 if a consumer
  asks.
- **`SlotHandle::drain_n(out, max) -> usize`** — bounded drain
  for back-pressure (plan 149). `max = 0` is a no-op;
  `max = usize::MAX` is equivalent to [`drain`]. The micro-
  optimisation `swap()` + opaque `SlotBuf<M, K>` variant
  considered for round 1 was deferred — `SegQueue::pop` is
  ~10ns and downstream emit dwarfs it. If a future benchmark
  proves it matters, `swap` ships in 0.14 with the same shape.
- **`flowscope::OwnedAnomaly`** — canonical owned, serialisable
  detector-output value (plan 147). `kind` slug,
  `Severity`, `Timestamp`, flattened 5-tuple fields,
  `SmallVec<[..; 4]>` observations + metrics (zero-alloc for
  the typical 2-5 observation case), `Option<AnomalyKind>`
  bridge field. Construct via `OwnedAnomaly::new` + the
  `with_key` / `with_observation` / `with_metric` builders, or
  bridge a flowscope-internal typed event via
  `OwnedAnomaly::from_flow_anomaly`. Wire-stable under
  `#[non_exhaustive]`; serde-feature-gated `Serialize` +
  `Deserialize` for cross-process retention.
- **`flowscope::DetectorScore`** trait — output-side conversion
  to `OwnedAnomaly` (plan 147). `name() -> &'static str` +
  `into_anomaly(ts) -> OwnedAnomaly`. Lets consumers route any
  detector score through a uniform emit path without trying
  to unify the heterogeneous detector input surfaces.
  Implemented on `ScanScore<K>` (`"PortScanTRW"`),
  `BeaconScore<K>` (`"BeaconCv"`), `DgaScore` (`"DgaScorer"`).
- **Per-score `into_anomaly` inherent methods** —
  `ScanScore::into_anomaly(ts)` /
  `BeaconScore::into_anomaly(ts)` /
  `DgaScore::into_anomaly(ts, Option<&dyn KeyFields>)`. The
  DGA variant takes an optional flow key for 5-tuple context
  (DGA scoring is keyless on the detector side but consumers
  usually have the DNS-query flow context).
- **`EveJsonWriter::write_owned_anomaly`** —
  `event_type: "anomaly"` emission from an `OwnedAnomaly`
  (plan 147). Observations nest under `anomaly.labels`,
  metrics under `anomaly.metrics`. `anomaly.type` follows
  the bridged `AnomalyKind`'s classification when
  `flowscope_kind.is_some()`; otherwise
  `EveOptions::custom_anomaly_type` (default `"applayer"`).
- **`FlowEventNdjsonWriter::write_owned_anomaly`** — one
  NDJSON line per anomaly, using the `serde`-derived shape
  on `OwnedAnomaly`.
- **`EveOptions::custom_anomaly_type: &'static str`** field —
  default EVE `anomaly.type` value for non-bridged
  `OwnedAnomaly` emissions. Default `"applayer"`.

### Changed

- **`Driver<E>: Send + Sync`** unconditionally (plan 156). The
  0.12 CHANGELOG claimed the central `FlowTracker` held
  `Rc<RefCell>` internals making the driver `!Send`; that
  description was incorrect — the actual `!Send` source was
  the `Vec<Box<dyn ErasedSlot<E::Key>>>` slot list's missing
  `+ Send` bound. Adding `+ Send + Sync` to the trait object
  and the matching parser `Send + Sync` bound at registration
  sites is a structural one-line fix with no `unsafe`, no
  runtime overhead, and no opt-in knob. Drivers built with
  `Driver::builder` now move freely between worker threads
  in a tokio multi-thread runtime; `tokio::spawn(driver_task)`
  on the default runtime just works. Stale `Rc<RefCell>` doc
  comments at `src/driver/{slot,mod}.rs` rewritten. All shipped
  parsers (HTTP / DNS / TLS / ICMP) already satisfied the
  Send + Sync bound; the change is strictly additive on the
  type level.

  Bounds tightening that *might* break consumer code:
  - `SessionParser` / `DatagramParser` impls registered through
    `DriverBuilder::session_on_ports` etc. now require
    `Send + Sync` (was `Send` alone).
  - `P::Message` / `D::Message` now require `Send + Sync` (was
    `Send`).
  - Closures stored inside the driver (`StateInit`, `IdleTimeoutFn`,
    `ParserFactory`) now require `Send + Sync` (was `Send`).
  All shipped types satisfy these bounds; downstream impls
  almost certainly do too (anything holding `&'static`, `Arc`,
  `Bytes`, primitive state).

## 0.12.0

The **cross-thread + structured-output + API debt retirement
+ named-detector + TLS-modernisation + DFIR-sinks cycle**.

Base scope driven by the netring 0.21 wishlist (per-CPU
sharded capture with multi-thread tokio runtimes need
`Send + Sync` slot handles, EVE JSON output for SIEM ingest,
chrono interop for legacy systems). Expanded post-strategic-
review with public-trait-shape debt cleanup (KeyFields split,
chrono symmetry, error/feature pruning) plus three
high-leverage features: a named-detector library
(BeaconDetector / PortScanDetector / DgaScorer), ECH signal
extraction on TLS handshakes, and streaming file-hash sinks
for DFIR / IR pipelines.

### BREAKING (pre-1.0)

- **`AnomalyFields` split into `KeyFields` + `AnomalyFields`**
  (plan 130). The single trait conflated two distinct concerns:
  5-tuple key accessors (`src_ip` / `dest_port` / `proto_str`)
  and anomaly-classification accessors (`anomaly_type` /
  `anomaly_event`). Now split along the natural cleavage.
  - Custom keys: replace `impl AnomalyFields for MyKey` with
    `impl KeyFields for MyKey` when overriding key methods.
  - `AnomalyKind` keeps `impl AnomalyFields` unchanged.
  - Both traits live at the crate root; `prelude` re-exports
    both. `use flowscope::prelude::*;` continues to work.

- **Emit writers generic over `K: KeyFields`** (plan 130).
  `FlowEventCsvWriter::write_event<K>` /
  `FlowEventNdjsonWriter::write_event<K>` /
  `ZeekConnLogWriter::write_event<K>` now accept any key
  implementing `KeyFields`. Existing `FiveTupleKey` callers
  unchanged; custom keys gain emit-writer compatibility by
  implementing `KeyFields`.

- **`From<Timestamp> for chrono::DateTime<Utc>`** (plan 130 §4)
  replaces `TryFrom`. `Timestamp::sec` is u32 (≤ year 2106)
  which fits inside chrono's representable range — the error
  case was theatre. `ChronoOutOfRange` deleted; migration:
  `ts.try_into().unwrap()` → `ts.into()`.

- **`DriverBuilder<E>` registration methods gain `P::Message:
  Send + 'static` bound** (plan 130). Parity with
  `DeferredDriverBuilder<E>`. Every shipped parser already
  satisfies `Send`, so this is invisible in practice.

- **`Error::Module::Pipeline` removed** (plan 131). Pipeline was
  deleted in 0.11; the enum still listed it. Dead-code removal.
  Five new variants added: `Driver` / `Emit` / `Detect` /
  `Aggregate` / `Correlate` for subsystems that don't error
  today but will as soon as one does.

- **`ja3` + `ja4` Cargo features collapsed into `tls-fingerprints`**
  (plan 131). Two-flag split was a usability footgun: ja3 + ja4
  together is almost universal in 2026 NDR/SIEM consumers.
  Migration: rename `ja3, ja4` → `tls-fingerprints` in
  Cargo.toml `[features]` / `[[example]]` blocks. The
  `Ja3Parts` / `ja3()` / `Ja4Parts` / `ja4_fingerprint()` /
  `ja4_parts()` public exports stay at the same paths.

- **`tracing-messages` Cargo feature removed** (plan 131).
  Per-message `tracing::trace!` emission is now always-on under
  the `tracing` feature. The `SessionParser::Message: Debug`
  bound was already always-on, so the dedicated feature was
  redundant clutter. Migration: drop `tracing-messages` from
  Cargo.toml; suppress per-message output at runtime via
  `tracing-subscriber::EnvFilter`, e.g.
  `EnvFilter::new("info,flowscope.message=warn")`.

- **`SlotHandle<M, K>` is now `Send + Sync`.** Backing storage
  changed from `Rc<RefCell<Vec<SlotMessage>>>` to
  `Arc<crossbeam_queue::SegQueue<SlotMessage>>` (lock-free MPMC).
  Move the handle to a tokio task on another core, share via
  `Arc` with multiple drainers, drain inside an async loop while
  the driver runs on a dedicated capture thread. The driver
  itself (`Driver<E>`) remains `!Send` (the central `FlowTracker`
  holds `Rc<RefCell>` state internally).

  Generic bounds tighten: `M: Send + 'static, K: Send + 'static`.
  Every shipped `SessionParser::Message` and `DatagramParser::Message`
  already meets this — the trait bounds require it — so in
  practice nothing changes for existing consumers.

  `Clone` hands out a second **competitive consumer**: both
  handles drain from the same queue and race for messages
  (sum of `clone().drain()` calls equals total pushed). For
  broadcast semantics, drain into a channel and fan out.

  Migration: typically nothing. If your code asserted `!Send`
  on a `SlotHandle` (unusual), update the bound.

### Added

- **`flowscope::detect::patterns`** module (plan 143) — three
  packaged named-detector recipes with pinned algorithm
  references and tuned thresholds. Always-on; no Cargo feature
  gate.
  - **`PortScanDetector<K>`** — Threshold Random Walk
    (Jung et al., IEEE S&P 2004). Per-source sequential
    hypothesis test on connection outcomes. Defaults:
    θ0 = 0.8, θ1 = 0.2, α = β = 0.01. Verdict resets state on
    cross.
  - **`BeaconDetector<K>`** — RITA-style composite
    coefficient-of-variation score on (inter-arrival,
    bytes) tuples. Suppresses chatty short-lived flows
    (n ≥ 10 observations and mean interval ∈ [10 s, 24 h]).
  - **`DgaScorer`** — bigram log-likelihood scorer over a
    37-class alphabet; bigram table compiled at first use
    from an embedded English baseline corpus. Returns
    auxiliary features (length, vowel ratio, digit ratio,
    max consonant run, char entropy) for composite scoring.

- **ECH (Encrypted Client Hello) signal extraction** (plan 144,
  draft-ietf-tls-esni-22):
  - `TlsClientHello::ech_present: bool`,
    `ech_config_id: Option<u8>`, `sni_is_outer: bool` —
    surfaced when extension type `0xfe0d` is observed in the
    ClientHello.
  - `TlsServerHello::ech_retry_configs: bool` —
    best-effort plaintext-fallback signal (encrypted-EE
    retry_configs are not passively observable).
  - `TlsHandshake::ech_outcome: EchOutcome` (NotOffered /
    Accepted / Rejected / Unknown) + `ech_config_id`.
  - `TlsClientHello` and `TlsServerHello` gained
    `#[non_exhaustive]` + `#[derive(Default)]`; `TlsVersion`
    gained `#[derive(Default)]` with `Tls1_3` as the default
    variant.

- **`flowscope::detect::file`** — streaming-hash sinks behind
  the new `file-hash` Cargo feature (plan 146):
  - `Sha256Sink` (sha2 crate), `Md5Sink` (md-5 crate) —
    streaming hashes over reassembled payload windows with
    constant-overhead first-64-byte MIME probe.
  - `FileHashSink` trait — algorithm() / update() / finish() /
    bytes_hashed(). Consumer-implementable for non-shipped
    hashes.
  - `FileHashEvent` — algorithm + lowercase hex digest +
    byte count + best-effort `FileType` classification.
  - `FileType` enum — 16 magic-byte-detected types:
    `Pe` / `Elf` / `MachO` / `Pdf` / `Png` / `Jpeg` / `Gif` /
    `Webp` / `Zip` / `Gzip` / `Bzip2` / `Xz` / `Mp4` / `Mp3` /
    `Sqlite3` / `Unknown`. Bridges flowscope into DFIR / IR
    pipelines (VirusTotal hash matching, Suricata
    `file_md5` / `file_sha256` ergonomics) without storing
    file bytes.

- **`Event::tcp(&self) -> Option<&TcpInfo>`** (plan 130 §3) —
  cross-variant accessor on the typed `driver::Event<K>` that
  returns the `FlowPacket.tcp` field when present, `None` on
  every other variant. Useful for pipelines that want "TCP
  info if available" without a destructuring `match` on
  `FlowPacket`. The `tcp` field itself is unchanged but now
  carries a loud rustdoc note that it's `None` unless
  `DriverBuilder::emit_packet_details(true)` is set.

- **`TopK::new_unbounded()`** + **`BurstDetector::new_unbounded(...)`**
  (plan 130 §5) — convenience constructors completing the
  `correlate::*::new_unbounded` set (`TimeBucketedCounter`,
  `TimeBucketedSet`, `KeyIndexed` shipped earlier in 0.12
  base). `TopK::new_unbounded` retains every observed key
  (k = usize::MAX, no eviction). `BurstDetector::new_unbounded`
  is naming-parity with the family (the detector has no LRU
  cap; this is an alias for `new(...)`).

- **`flowscope::emit::EveJsonWriter`** (plan 123, behind
  `emit-eve` feature) — Suricata 7.x EVE JSON writer. One JSON
  object per line in three `event_type` shapes:
  - `"flow"` for `FlowEvent::Ended` (per-flow with
    pkts_toserver / pkts_toclient / bytes / start / end / age /
    reason).
  - `"anomaly"` for `FlowAnomaly` / `TrackerAnomaly` (with
    Suricata-style `anomaly.type` + `anomaly.event` +
    `severity` numeric).
  - `"stats"` for `FlowEvent::Tick` (opt-in via
    `EveOptions::include_stats`).

  Schema-compatible with Filebeat's Suricata module, Splunk
  Suricata TA, Tenzir's `read_suricata`, and ECS-converting
  downstream pipelines. Severity mapping is identity by
  default (Critical=1, Error=2, Warning=3, Info=4) — override
  via `EveOptions::severity_numeric`.

- **`correlate::*::new_unbounded` convenience constructors**
  (plan 128 Phase 7) — three trivial delegates to the existing
  `new` constructors with `usize::MAX` capacity, on
  `TimeBucketedCounter::new_unbounded(window, bucket)`,
  `TimeBucketedSet::new_unbounded(window, bucket)`,
  `KeyIndexed::new_unbounded(ttl)`. Prefer the bounded
  constructors when memory pressure matters; the unbounded
  variants suit lifecycle-scoped or test contexts.

- **`Driver::deferred()` constructor** (plan 124) — builds a
  `DeferredDriverBuilder<E>` that defers extractor *instance*
  selection until `.build_with(ext)`. Useful when slot
  registration ordering precedes extractor selection
  (consumer-built monitor chains like netring's
  `MonitorBuilder` that want every protocol registered before
  the user picks the capture source).

  Type-system distinction: `DeferredDriverBuilder` has no
  `build()` method, so the compile-time guarantee that an
  extractor is set is preserved by the type system, not by a
  runtime panic.

  `Driver::deferred().session_on_ports(p, ports).build_with(ext)`
  is behaviourally equivalent to
  `Driver::builder(ext).session_on_ports(p, ports).build()`.

- **`flowscope::AnomalyFields` trait** (plan 126) — structured
  field access for emit writers. Default-`None` methods:
  `src_ip` / `src_port` / `dest_ip` / `dest_port` / `proto_str` /
  `app_proto_str` / `anomaly_type` / `anomaly_event`. Shipped
  impls:
  - `L4Proto`: returns uppercase EVE labels (`"TCP"` / `"UDP"` /
    `"ICMP"` / `"ICMPv6"` / `"SCTP"`). `Other(_)` returns `None`.
  - `FiveTupleKey`: src/dest IP/port + proto; app proto via the
    well-known port table.
  - `AnomalyKind`: maps each variant to a Suricata EVE `type`
    (`"stream"` for buffer/OOO/retransmit/watermark/eviction;
    `"applayer"` for parse errors) and to the stable
    `short_kind` slug for `anomaly_event`.

  Custom keys (`Ipv4FlowKey`, etc.) opt in by implementing the
  relevant accessors; emit writers extract typed fields without
  going through `Debug` formatting.

- **`Timestamp::write_iso8601` / `to_iso8601`** (plan 127) —
  alloc-free `RFC 3339 / ISO 8601` rendering for log lines and
  JSON output. Pure Howard Hinnant `civil_from_days` — no
  chrono dep required. Format:
  `YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ` (UTC, nanosecond precision).
- **`chrono` interop feature** (plan 127, refined by plan 130
  §4 later in the same cycle) — when the `chrono` feature is
  enabled, infallible `From<chrono::DateTime<chrono::Utc>>` for
  `Timestamp` and infallible `From<Timestamp>` for
  `chrono::DateTime<chrono::Utc>`. (The plan 127 ship initially
  used a `TryFrom` shape with a `ChronoOutOfRange` error type
  for the theoretical out-of-range case; plan 130 §4 retired
  it before release — `Timestamp::sec: u32` fits inside
  chrono's range with room to spare. See the BREAKING section
  above.) Uses `chrono` `default-features = false, features =
  ["alloc"]` — alloc-free runtime path, alloc only for
  the test-side cross-check against `to_rfc3339_opts`.

## 0.11.1

Fills the one deferred-item gap from the 0.11.0 plan-121 audit
that's blocking netring 0.19's connection-termination path.

### Added

- **`Driver<E>::force_close(key, now) -> Vec<Event<E::Key>>`**
  and **`Driver<E>::force_close_into(key, now, &mut out)`** —
  port of `FlowSessionDriver::force_close` to the typed driver.
  Per registered slot: drains reassembler-buffered bytes
  through the parser, calls `fin_initiator` / `fin_responder`,
  emits typed messages into the slot handle, and emits a
  `ParserClosed` lifecycle event. The central tracker emits
  a final `FlowEnded { reason: ForceClosed }`. No-op if `key`
  is not currently tracked.

  Internal: `ErasedSlot` trait gains a `force_close_into`
  method; all four slot impls (concrete session/datagram +
  heuristic session/datagram) implement it. Heuristic slots
  also drop their per-flow detection state.

Two integration tests in `tests/driver.rs` cover the
happy-path emission shape and the no-op-on-unknown-flow case.

## 0.11.0

The **zero-allocation cycle**. Triggered by the netring 0.19
dependency audit; lands the architectural changes netring's
zero-allocation `monitor.protocol::<P>(handler)` pattern needs,
collapses the closed-`M` sum-type `Driver<E, M>` shape into a
typed-slot-drain shape, and deletes the 0.9-era legacy driver
types.

### BREAKING

- **`SessionParser` + `DatagramParser` trait shape changed.**
  `feed_initiator` / `feed_responder` / `fin_initiator` /
  `fin_responder` / `on_tick` (SessionParser) and `parse` /
  `on_tick` (DatagramParser) now take `&mut Vec<Self::Message>`
  instead of returning `Vec<Self::Message>`. Same idiom as
  `httparse::Request::parse`. Migration:
  ```diff
  -fn feed_initiator(&mut self, b: &[u8], ts: Timestamp)
  -    -> Vec<Self::Message> { vec![msg] }
  +fn feed_initiator(&mut self, b: &[u8], ts: Timestamp,
  +    out: &mut Vec<Self::Message>) { out.push(msg); }
  ```

- **`Driver<E, M>` replaced by typed `Driver<E>` + `SlotHandle<M, K>`.**
  The driver emits flow-lifecycle `Event<K>` only (no `M`
  parameter, no `Message` variant); per-parser typed messages
  flow through `SlotHandle<P::Message, E::Key>` returned by the
  builder at registration time. Migration:
  ```diff
  -let mut driver = Driver::<_, MyMsg>::builder(ext)
  -    .session_on_ports(HttpParser::default(), [80], MyMsg::Http)
  -    .build();
  -for event in driver.track(view) {
  -    match event {
  -        Event::Message { message: MyMsg::Http(http), .. } => ...,
  -        Event::FlowStarted { .. } => ...,
  -    }
  -}
  +let mut builder = Driver::builder(ext);
  +let mut http_slot = builder.session_on_ports(HttpParser::default(), [80]);
  +let mut driver = builder.build();
  +
  +let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
  +let mut http_msgs: Vec<SlotMessage<HttpMessage, FiveTupleKey>> = Vec::new();
  +driver.track_into(view, &mut events);
  +http_slot.drain(&mut http_msgs);
  +for ev in &events { /* lifecycle */ }
  +for m in &http_msgs { /* typed HttpMessage */ }
  ```

- **Module renames.** `flowscope::driver_unified::*` →
  `flowscope::driver::*`. The 0.9-era `flowscope::driver` (was
  `FlowDriver`) moves to `flowscope::flow_driver`; the top-level
  `flowscope::FlowDriver` re-export is unchanged.

- **Deleted types.** `FlowMultiSessionDriver`,
  `FlowSessionDriverBuilder`, `FlowDatagramDriverBuilder`,
  legacy top-level `Pipeline` + `PipelineBuilder` +
  `EventKind` + `NoSessionParser` + `NoDatagramParser`,
  `flowscope::driver_unified::Driver<E, M>` and its
  supporting types (`DriverSlot`, lift-closure-based
  `ConcreteSlot`, `HeuristicSessionSlot`, `Event<K, M>`,
  unified `Pipeline<E, M>`).

- **`Event::FlowPacket::frame` field removed.** Previously
  every packet under `emit_packet_details(true)` carried an
  `Option<Vec<u8>>` populated by `view.frame.to_vec()` — a
  64–1500-byte memcpy per packet at ~1.5 GB/sec at 1 Mpps.
  Consumers that need the frame bytes hold onto the source
  `PacketView` they handed to `track_into`. The
  `emit_packet_details(true)` knob still populates `tcp:
  Option<TcpInfo>`.

- **HTTP / DNS / TLS payload types converted to `bytes::Bytes`.**
  - `HttpRequest::method` / `path`: `String` → `Bytes`
  - `HttpRequest::headers`: `Vec<(String, Vec<u8>)>` → `Vec<(Bytes, Bytes)>`
  - `HttpResponse::reason`: `String` → `Bytes`
  - `HttpResponse::headers`: same as request
  - `DnsRdata::TXT(Vec<Vec<u8>>)` → `TXT(SmallVec<[Bytes; 4]>)`
  - `DnsRdata::Other.data: Vec<u8>` → `Bytes`
  - `TlsClientHello::compression: Vec<u8>` → `Bytes`

  New convenience accessors: `HttpRequest::method_str()`,
  `path_str()`; `HttpResponse::reason_str()` returning
  `Option<&str>`. Existing accessors (`req.host()`,
  `req.content_type()`, etc.) keep their `Option<&str>`
  signature.

### Added

- **`flowscope::driver::Driver<E>`** + `DriverBuilder<E>` —
  the typed driver shape.
- **`flowscope::driver::SlotHandle<M, K>`** + `SlotMessage<M, K>`
  — typed drain handles. `.drain(&mut Vec<SlotMessage<M, K>>) ->
  usize`, `.pending()`, `.parser_kind()`, `.clear()`.
- **`flowscope::driver::Event<K>`** — flow-lifecycle event type.
  Variants: `FlowStarted`, `FlowEstablished`, `FlowPacket`,
  `FlowEnded`, `FlowTick`, `ParserClosed`, `FlowAnomaly`,
  `TrackerAnomaly`.
- **`Driver::track_into(view, &mut Vec<Event<K>>)`** +
  `sweep_into` + `finish_into` — zero-allocation surface that
  reuses the caller's buffer.
- **`FlowSessionDriver::track_into` /
  `FlowDatagramDriver::track_into`** — zero-allocation variants
  on the kept sync primitives.
- **`flowscope::parser_kinds::TLS_HANDSHAKE`** — stable constant
  for the TLS-handshake aggregator parser kind.

### Performance

Measured per `cargo bench --bench zero_alloc` (counting
allocator wrapping the global allocator). 0.10.1 → 0.11.0:

| Measurement | 0.10.1 | 0.11.0 | delta |
|---|---|---|---|
| `Driver::track_into`, 0 slots, non-L7 traffic | 1.000 allocs/pkt | **0.000** | -100% |
| `Driver::track_into`, **5 HTTP slots**, non-L7 traffic | (new) | **0.000** | gate ✅ |
| HTTP `feed_initiator` steady-state | 13 allocs/call | **5** | -62% |
| HTTP/1.1 GET parse, fresh parser, 10 headers | 28 allocs, 21 995 B | **7 allocs, 5 906 B** | -75% / -73% |
| `emit_packet_details(true)` per-packet frame copy | 1 500 B | **field removed** | -100% |

The bench harness lives at `benches/zero_alloc.rs` +
`benches/support/counting_allocator.rs`.

### Notes

- The `bytes` crate is now a dependency of the `dns` feature
  (was previously only pulled in by `http`, `tls`, `icmp`).
- The typed `Driver<E>` is **single-threaded by design** — the
  slot buffers are `Rc<RefCell>`, not `Arc<Mutex>`. For
  cross-task delivery, drain inside the event loop and post
  through a channel.
- `FlowDriver`, `FlowSessionDriver`, `FlowDatagramDriver` stay
  public as raw sync primitives. Most users want the typed
  `Driver<E>`; the legacy types remain for advanced consumers
  who already have an event loop and want raw flow tracking
  without the typed-slot dispatch layer.

## 0.10.1

CI / build hygiene patch. Three of the `cargo clippy --no-default-
features --features X -- -D warnings` matrix entries (`dns`,
`http,tls`, `icmp`) were failing on 0.10.0 because of stale cfg
gates:

- `src/driver_builder.rs` imported `session_driver` /
  `datagram_driver` (both `reassembler`-gated) under `feature =
  "session"`. Bumped the gates to require `reassembler`.
- The same module imported `DatagramParser` unconditionally even
  though the datagram-driver block needs `extractors +
  reassembler + session`. Split the import.
- `Error::parse` was cfg-gated to be visible under `feature =
  "icmp"`, but the icmp parser only calls `Error::parse_with`.
  Dropped `icmp` from the gate.

No behavioural / API changes; the public surface is identical to
0.10.0.

## 0.10.0

Combined 0.9 + 0.10 cycle release. The 0.9 work shipped (high-
level `Pipeline`, public `flowscope::layers`, unified `Error`,
`flowscope::correlate`, multi-parser driver, OOO TCP reassembly,
JA4 + `TlsHandshakeParser`, auto-sweep, MSRV 1.88, callback-
factory removal) PLUS the full 0.10 DX cycle (emit / aggregate /
detect / well_known / correlate ext / exchange aggregators /
parser ergonomics / DX polish / signatures / heuristic routing)
PLUS the centerpiece plan 116 (unified `Driver<E, M>` +
`Event<K, M>` + `Pipeline` over the new `driver_unified`
namespace, with all 6 builder knobs shipped: `config` /
`monotonic_timestamps` / `emit_anomalies` / `emit_packet_details`
/ `dedup` / `idle_timeout_fn`).

The 0.10.0 release ships the legacy `FlowDriver` /
`FlowSessionDriver` / `FlowDatagramDriver` /
`FlowMultiSessionDriver` / `flowscope::Pipeline` (with
`Event<K, SM, DM>`) / `FlowEvent` / `SessionEvent` types
alongside the unified equivalents. Consumers can migrate at
their own pace; the legacy deletion sweep (plan 117) is queued
for the next major release with at least a 4-week migration
window.

Test count: ~430 passing, zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings.

### Added — plan 116 unified driver

- **Plan 116 — all builder knobs shipped.** `NoopReassembler` +
  `NoopReassemblerFactory` in `flowscope::reassembler`. The
  unified `Driver` now runs a central `FlowDriver` over the noop
  factory, giving it `emit_anomalies` / `dedup` /
  `idle_timeout_fn` / `monotonic_timestamps` /
  `emit_packet_details` builder methods, all proxied through
  `PipelineBuilder`.
- **Plan 116 — `emit_packet_details` + `Event::FlowPacket`
  enrichment (plan 108 absorbed).** `DriverBuilder` and
  `PipelineBuilder` gain `emit_packet_details(bool)`. When set,
  every emitted `Event::FlowPacket` carries
  `tcp: Option<TcpInfo>` and `frame: Option<Vec<u8>>`
  populated from a fresh per-packet extraction; default
  `false` (the per-packet `extract` + frame `memcpy` is opt-in
  because the overhead is real). Closes the last
  plan-116-spec gap besides the deferred `emit_anomalies` /
  `dedup` / direct `idle_timeout_fn` (workaround:
  `driver.tracker_mut().set_idle_timeout_fn(f)`).
- **Plan 116 PR 4 partial — unified-driver demo + migration
  recipe.** New `examples/unified_driver_demo.rs` showcases the
  unified `Driver` with port-routed HTTP + DNS dispatch plus a
  signature-based heuristic catch-all under one driver and one
  `Event<K, M>` stream. `docs/recipes.md` gains a "Migrating to
  the unified Driver (0.10+)" section with a full legacy →
  unified mapping table. The legacy driver / event types remain
  shipped in 0.10 for migration; the deletion sweep is deferred
  to the next major release.
- **Plan 116 PR 3 — `flowscope::driver_unified::Pipeline`
  wrapper.** Mirror of the 0.9 `flowscope::Pipeline` shape, but
  the event stream is the unified `Event<K, M>` and the
  builder proxies the full session / datagram / heuristic
  registration API of the underlying `DriverBuilder`. Supports
  `.config(…)`, `.session_on_ports / .session_broadcast /
  .datagram_on_ports / .datagram_broadcast`,
  `.run_pcap(path) / .run_iter(iter)`, and `.reset()` for
  re-running on multiple inputs. The legacy `flowscope::Pipeline`
  (with `Event<K, SM, DM>`) stays shipped in 0.10 for
  migration.
- **Plan 116 PR 2b + Plan 113 sub-B — heuristic routing.**
  Adds four builder methods on `DriverBuilder` —
  `session_heuristic`, `session_heuristic_with_budget`,
  `datagram_heuristic`, `datagram_heuristic_with_budget` —
  that wire a payload `SignatureFn` (from plan 113 sub-A)
  into per-flow detection state. Each heuristic slot keeps a
  Probing / Pinned / GaveUp state per flow:
  - Probing: buffer up to 64 B per side; evaluate the
    signature on each side every probe packet.
  - Pinned (first `Match`): dispatch every subsequent packet
    directly to the inner driver — O(1) cost.
  - GaveUp (`max_probe_packets` exhausted with no Match): no
    further dispatch for that flow.
  `DEFAULT_PROBE_PACKETS = 4` and `PROBE_BUFFER_CAP = 64`
  constants are public for consumers wanting to scale.
- **Plan 116 PR 2a — datagram dispatch on the unified Driver.**
  Adds `DriverBuilder::datagram_on_ports` and
  `DriverBuilder::datagram_broadcast` mirroring their session
  counterparts. UDP parsers (DnsUdpParser, IcmpParser,
  PerDatagramParser, etc.) compose with TCP parsers under one
  `Driver<E, M>`. Internal `ConcreteDatagramSlot` wraps a
  `FlowDatagramDriver`; same lift-and-filter behaviour as the
  session path.
- **Plan 116 migration mapping (legacy → unified).** The
  unified API in `flowscope::driver_unified` ships alongside
  the 0.9-era types for migration; the deletion sweep is
  queued for the next major release. Reference mapping
  (legacy 0.9 → unified 0.10):

  | 0.9 type / variant | Unified 0.10 equivalent |
  |--------------------|--------------------------|
  | `FlowSessionDriver::new(ext, p)` | `Driver::builder(ext).session_broadcast(p, identity).build()` |
  | `FlowDatagramDriver::new(ext, p)` | `Driver::builder(ext).datagram_broadcast(p, identity).build()` |
  | `FlowMultiSessionDriver` | `Driver` with multiple `.session_on_ports(…)` / `.session_broadcast(…)` |
  | `flowscope::Pipeline::builder(ext).session(p)` | `flowscope::driver_unified::Pipeline::builder(ext).session_broadcast(p, identity)` |
  | `pipeline::Event::Flow(FlowEvent::Started)` | `Event::FlowStarted` |
  | `pipeline::Event::Flow(FlowEvent::Established)` | `Event::FlowEstablished` |
  | `pipeline::Event::Flow(FlowEvent::Packet)` | `Event::FlowPacket` (now with optional `tcp` / `frame`) |
  | `pipeline::Event::Flow(FlowEvent::Ended)` | `Event::FlowEnded` |
  | `pipeline::Event::Flow(FlowEvent::Tick)` | `Event::FlowTick` |
  | `pipeline::Event::Flow(FlowEvent::FlowAnomaly)` | `Event::FlowAnomaly` (deferred — see module rustdoc) |
  | `pipeline::Event::Flow(FlowEvent::TrackerAnomaly)` | `Event::TrackerAnomaly` (deferred) |
  | `pipeline::Event::Flow(FlowEvent::StateChange)` | dropped — `FlowEstablished` is the only transition surfaced |
  | `pipeline::Event::Tcp(SessionEvent::Application)` | `Event::Message` |
  | `pipeline::Event::Tcp(SessionEvent::Closed)` | `Event::FlowEnded` (lifecycle) + `Event::ParserClosed` (per-parser) |
  | `pipeline::Event::Udp(SessionEvent::Application)` | `Event::Message` |
  | `pipeline::Event::Udp(SessionEvent::Closed)` | `Event::FlowEnded` + `Event::ParserClosed` |

  See `docs/recipes.md` → "Migrating to the unified Driver
  (0.10+)" for a worked example.
- **Plan 116 PR 1 — unified `Driver<E, M>` + `Event<K, M>`
  preview.** First step of the centerpiece API redesign that
  collapses the 0.9-era 6-driver / 4-event surface into one
  driver and one event type. Ships under
  `flowscope::driver_unified::{Driver, Event, DriverBuilder}`
  alongside the legacy `FlowSessionDriver` /
  `FlowMultiSessionDriver` / `Pipeline` types for migration.
  - `Driver::builder(extractor).session_on_ports(parser, ports,
    lift)` — port-routed session parsers.
  - `Driver::builder(extractor).session_broadcast(parser, lift)`
    — fire on every flow regardless of port.
  - `Driver::track(view) / sweep(now) / finish()` return
    `Vec<Event<K, M>>` merging the central tracker's flow
    lifecycle (`FlowStarted` / `FlowEstablished` /
    `FlowPacket` / `FlowEnded` / `FlowTick` / `FlowAnomaly` /
    `TrackerAnomaly`) with parser-sourced outputs (`Message` /
    `ParserClosed`).
  - `Event::key() / timestamp() / parser_kind() /
    anomaly_kind() / is_flow_event() / is_parser_event()`
    accessors.
  - Follow-up PRs (2-5, not yet started): UDP / datagram
    dispatch + heuristic routing; Pipeline rewrite; test +
    example migration; legacy-type deletion.
- **Plan 107 — HTTP + DNS exchange aggregators.** Mirror of the
  0.9 `TlsHandshakeParser` shape for two more L7 protocols. One
  rich event per logical exchange instead of per-message
  decomposition.
  - `HttpExchangeParser` — emits one `HttpExchange` per
    request/response pair. Handles HTTP/1.1 pipelining (FIFO
    matching). Outcomes: `Completed` / `NoResponse` / `Reset`.
    Convenience accessors: `status_class()` / `is_success()` /
    `is_error()`.
  - `DnsExchangeParser` — emits one `DnsExchange` per
    query/response pair (UDP only — TCP variant deferred).
    Built atop `DnsUdpParser` with correlation enabled.
    Outcomes: `Completed` / `NoResponse` /
    `Failed { rcode }`.
- **Plan 106 — parser ergonomics.** Three helpers for writing
  custom `SessionParser` / `DatagramParser` impls without
  reinventing the buffer + drain boilerplate that every
  custom-protocol example writes.
  - `BufferedFrameDrain<M>` — accumulate bytes, repeatedly call
    a `parse_one(&[u8]) -> Option<(M, usize)>` closure, drain
    consumed prefix, retain partial. Catches off-by-one bugs and
    poisons on overflow / zero-byte advance.
  - `AccumulatingSessionParser<F, M>` — one-line `SessionParser`
    impl wrapping two `BufferedFrameDrain`s + the closure +
    parser_kind label. Reduces ~25 LoC of boilerplate per custom
    parser to one constructor call.
  - `PerDatagramParser<F, M>` — one-line `DatagramParser` impl
    over `Fn(&[u8]) -> Option<M>` — UDP parity.
  - `FrameDrainError` for `BufferFull` / `ZeroByteAdvance`
    poison reasons; `DEFAULT_FRAME_DRAIN_MAX_BUFFER` constant
    (64 KiB) for the default per-side cap.

  Fallible `feed_*` trait extension was scoped out of this PR —
  driver-level Err routing is folded into plan 116 (unified
  Driver).
- **Plan 102 sub-A — `flowscope::correlate` extensions.** Four
  cross-flow correlation primitives that every detector example
  reinvented:
  - `TimeBucketedSet<K, V>` — TTL'd set keyed by `K` with value
    set `V`; cardinality + entries-above-threshold queries.
    For port-scan detection ("distinct destination ports per
    source within window") and DNS-tunnel detection ("distinct
    labels per source").
  - `BurstDetector<K, E>` + `BurstHit<K>` — N events of kind X
    within window, optionally followed by event of kind Y.
    Pure-burst (SYN floods) and burst-then-trigger (failed-auth
    burst → success) modes.
  - `TopK<K>` — bounded "top K by count" Misra-Gries tracker.
    Exact under capacity; bounded-error after. `.observe` /
    `.observe_n(weight)` / `.top()` / `.estimate(&K)`.
  - `Ewma<K>` — per-key exponentially weighted moving average
    with optional `.evict_stale(now, ttl)` for memory bounding.
- **Plan 113 sub-A — `flowscope::detect::signatures`.** Pure-
  function magic-byte recognizers for 10 protocols. Each
  signature returns `Match` / `NoMatch` / `NeedMoreData`; no
  state, no allocation, suitable for hot-path dispatch.
  - HTTP: `http_request` / `http_response`.
  - TLS: `tls_client_hello` / `tls_server_hello`.
  - DNS: `dns_message`.
  - Banner protocols: `ssh_banner` / `smtp_banner` /
    `ftp_banner` / `irc_message`.
  - Framed protocols: `redis_resp` / `mqtt_connect` /
    `postgres_startup`.
  - `registry()` iterates `(parser_kind, SignatureFn)` for the
    curated set — strings align with
    `flowscope::parser_kinds::*` so signature matches dispatch
    back to the existing parsers.
  - Each signature ships with a splitting-invariance test: any
    prefix of a `Match` input is `Match` or `NeedMoreData`,
    never `NoMatch`.
- **Plan 110 sub-A — rustdoc landing pages + 9 HTTP accessors.**
  Module-level rustdoc on `flowscope::http`, `flowscope::tls`,
  `flowscope::dns`, and `flowscope::icmp` now leads with a
  curated `# Convenience accessors` table listing every shipped
  accessor on the main types — same surface, much more
  discoverable. Plus 9 new accessor methods (per plan: 7; this
  release: 9 — two extras mirror existing HttpResponse helpers
  on HttpRequest):
  - `HttpRequest::referer()` / `accept()` /
    `content_type()` / `content_length()`
  - `HttpResponse::status_class()` / `is_success()` /
    `is_redirect()` / `is_client_error()` / `is_server_error()`
- **Plan 102 sub-B — `flowscope::aggregate`.** Distribution +
  quantile primitives behind a new `aggregate` Cargo feature.
  - `Histogram` — explicit-bucket counter with `record` /
    `quantile` (linear-interp) / `merge` / `buckets()` iterator,
    plus `log_spaced(low, high, count)` for geometric ranges.
    No extra deps.
  - `Percentile` — streaming quantile estimator wrapping the
    `tdigest` crate. Buffered-record API (`record` is `&mut`,
    batches into the digest in 512-sample chunks).
  - `HistogramError` for boundary-validation failures.
  - `examples/flow_duration_histogram.rs` migrated to
    `Histogram` (drops the manual bucket-loop + sort-based
    quantile).
- **Plan 102 sub-C — `flowscope::detect`.** Small toolkit of
  lightweight detection primitives every detector example
  reinvented:
  - `shannon_entropy(&[u8]) -> f64` — DNS tunnel detection,
    encoded-payload spotting.
  - `is_high_entropy(&[u8], threshold) -> bool` — entropy +
    threshold convenience.
  - `ngram_distribution(&[u8], n) -> NgramDist` — n-gram
    frequency table with built-in `mode()` / `entropy()` /
    `distinct()`.
  - `is_base64ish(&str) -> bool` — base64-shaped string
    detection (≥16 chars).
  - `is_hex_string(&str) -> bool` — hex-shaped string detection
    (≥16 chars).
  - `hamming_distance(a, b) -> Option<usize>` — fixed-length
    byte comparison.
  - `examples/dns_tunnel_detector.rs` migrated to the shipped
    `shannon_entropy` helper (drops a 19-line local copy).
- **Plan 101 — `flowscope::emit`.** Structured event sinks for
  the three log formats every flow-analysis pipeline ends up
  emitting. Each writer takes a `std::io::Write` sink and a
  `FlowEvent<FiveTupleKey>` per call; defaults to emitting only
  `FlowEvent::Ended`.
  - `FlowEventCsvWriter` — RFC-4180-quoted CSV (no extra deps).
    Behind the `emit` feature.
  - `FlowEventNdjsonWriter` — newline-delimited JSON using the
    locked snake_case wire vocabulary. Behind the `emit-ndjson`
    feature (pulls in `serde_json` + requires `serde`).
  - `ZeekConnLogWriter` — tab-separated Zeek `conn.log` rows
    with `#fields` / `#types` / `#close` headers, auto-generated
    UIDs, full `EndReason` → Zeek `conn_state` mapping. Behind
    the `emit` feature.
  - `EndReason::as_zeek_state()` — pure-function mapping
    documented stable for the 0.10 cycle.
  - The three existing examples (`flow_csv_export`,
    `flow_json_export`, `zeek_style_conn_log`) migrated to the
    new writers — each dropped from 60-100 LoC to ~15 LoC.
- **Plan 102 sub-D — `flowscope::well_known`.** Curated
  `(L4Proto, port)` → label table with ~70 entries (IANA-aligned
  plus widely-deployed cloud-native services like Kafka, Redis,
  Elasticsearch, MinIO, MongoDB, etc.). Lookup is binary-search
  based, zero-cost on miss. Lower-numbered port disambiguates
  the client/server side automatically.
  - `flowscope::well_known::protocol_label(proto, src_port, dst_port)`
    → `Option<&'static str>`.
  - `flowscope::well_known::entries()` iterates every shipped row.
  - `FiveTupleKey::well_known_port()` → lower-numbered endpoint
    port.
  - `FiveTupleKey::protocol_label()` → forwards to
    `well_known::protocol_label`.
- **Plan 110 sub-B — quick-win helper sweep.** Small additive
  helpers across `Timestamp`, `FlowStats`, `EndReason`,
  `LayerKind`, `Layer<'_>`, `LayerStack`, and `KeyIndexed`. No
  breaking changes; consumers can keep doing what they're doing
  or opt in to the new helpers as they encounter them.
  - `Timestamp::to_unix_f64()` / `from_unix_f64()` /
    `relative_to()` / `from_system_time()`. The existing
    `Display` impl is unchanged (Zeek-compatible
    `"{sec}.{nsec:09}"`).
  - `FlowStats::total_bytes()` / `total_packets()` /
    `total_retransmits()` / `retransmit_rate()` / `duration()` /
    `duration_secs()` — convenience over the per-side fields
    every consumer aggregated by hand.
  - `EndReason::as_str()` — snake-case short label (canonical
    source for the metric vocabulary and `Display` output).
    `Display` continues to render the same slug.
  - `LayerKind::is_l2()` / `is_l3()` / `is_l4()` / `is_tunnel()`
    `const` predicates — group dispatch on the layer enum
    without spelling out variants.
  - `Layer<'_>::Display` — one-line summary like
    `tcp src_port=12345 dst_port=80 seq=1000 ack=0 flags=[S]`.
    Stable, grep-friendly format for ad-hoc tracing /
    debug logs.
  - `LayerStack::depth()` / `iter_kinds()` — inspect the
    zero-alloc parser's populated slots.
  - `KeyIndexed::peek(&key, now)` — read-only `get` that does
    NOT bump LRU recency. Use when the outer scope holds
    `&self` rather than `&mut self`, or when the access is
    incidental (logging / metrics).

### Added — plan 94 / 96 / 97 / 74 / 75 / 81 / 92 / 99 (0.9 cycle absorbed)

The biggest release since 0.1: a high-level `Pipeline` entry
point, a public per-packet layered view (`flowscope::layers`),
unified errors, cross-flow correlation primitives, a composite
multi-parser driver, OOO TCP reassembly, JA4 + a TLS
handshake aggregator, packet-clock auto-sweep for live/offline
parity, MSRV 1.85 → 1.88, and removal of the legacy
callback-factory L7 APIs.

#### 0.9 audit (measured against 0.8.0, 2026-06-06)

Per the umbrella that drove the cycle:

- **38 driver constructors** across the three sync driver
  structs (`FlowDriver` 6+4, `FlowSessionDriver` 10+4,
  `FlowDatagramDriver` 10+4). New
  `Driver::builder(extractor)` shape consolidates the common
  case; existing constructors stay for 0.9 (deletion deferred
  to 0.10).
- **No "start here" entry point** — every prior example began
  `FlowSessionDriver::new(…)`. The 0.9 introduces
  `flowscope::Pipeline` + `flowscope::prelude` so a new
  program needs one `use flowscope::prelude::*;`.
- **No public per-packet layered view** — `etherparse::SlicedPacket`
  was parsed internally by the FiveTuple extractor and
  discarded. The 0.9 `flowscope::layers` module exposes a
  zero-copy view with tunnel walking, ARP / MPLS / ICMP
  slices, and a `LayerParser` + `LayerStack` zero-allocation
  fast path.
- **Two duplicated L7 API shapes** — every L7 module shipped
  both a callback-style `*Factory` / `*Handler` surface and
  the strategic `SessionParser` shape. The legacy column is
  deleted (see Breaking).
- **Five separate `Error` enums** (`http::Error`, `tls::Error`,
  `dns::Error`, `pcap::Error`, `icmp::Error`) with no shared
  trait. Collapsed into one `flowscope::Error` carrying
  `Module` + `ErrorCode` + source chain.

#### 0.9 cycle features

- **`flowscope::correlate` module** (plan 81). Three composable
  primitives for cross-flow correlation patterns:
  - `TimeBucketedCounter<K>` — windowed per-key event counter
    with bucket-based aggregation (DDoS rate-limits, SYN-flood
    thresholds, "did key K cross N in W seconds").
  - `KeyIndexed<K, V>` — TTL'd LRU cache with packet-clock
    eviction (DNS query/response correlation, ICMP error tying
    back to the original flow, generic request/response
    matching).
  - `SequencePattern` trait + `KeylessSequencePattern` blanket-
    adapter — generic FSM for event-stream pattern detectors
    (port scans, "auth-failure-then-success", retry storms).
- **`FlowTracker::with_auto_sweep(interval)`** (plan 75).
  Packet-clock-driven implicit sweeps so live and offline
  pipelines emit identical event streams for identical inputs.
  Off by default. Sets `FlowTrackerConfig::auto_sweep_interval`.
  After each `track()` call, if
  `view.timestamp - last_sweep_ts >= interval`, runs an implicit
  sweep and merges its events into the returned vector. Manual
  `sweep()` resets `last_sweep_ts` so mixing manual + auto
  is safe.
- **Driver builders** (plan 94 Tier 2 partial). New
  `Driver::builder(extractor)` entry point on
  `FlowSessionDriver` + `FlowDatagramDriver`. Discoverable
  chainable shape: `.parser(p) / .config(c) /
  .emit_anomalies(b) / .monotonic_timestamps(b) / .dedup(d) /
  .idle_timeout_fn(f) / .build()`. The plan-94 Tier 2 spec
  called for collapsing all 38 driver constructors into one
  builder; this cut ships the most-discoverable entry point
  alongside the existing constructors. Constructor deletion
  is deferred to a follow-up cycle so consumers can migrate
  at their own pace.
- **`flowscope::layers` fast path** (plan 94 Tier 3 fast-path
  follow-up). Mirror of gopacket's `DecodingLayerParser`
  pattern. `LayerParser` + `LayerStack`: zero per-frame
  allocation, caller-owned scratch reusable across the
  packet loop, optional `.only(&[LayerKind…])` mask that
  skips slots the consumer doesn't care about. The
  ergonomic `Layers::parse_ethernet` path stays — the fast
  path is opt-in for consumers who have profiled and need it.
- **`SegmentBufferReassembler`** (plan 74). TCP reassembler
  with out-of-order hole-fill. Holds OOO segments in a
  `BTreeMap<start_seq, segment>` until the preceding hole is
  filled, then drains the contiguous prefix into the ready
  buffer. Segments older than `ooo_deadline` (default 1s) are
  expired; the `holes_expired` counter ticks. Defaults: 256 KiB
  OOO cap, 1s deadline, strict overlap (RFC 5722). Implements
  the [`Reassembler`] trait; pair with `FlowSessionDriver` /
  `BufferedReassemblerFactory` builders. Drop-in for binary
  protocols (HTTP/2 HPACK, TLS record alignment) where
  `BufferedReassembler`'s OOO-drop strategy desyncs the parser.
- **`FlowMultiSessionDriver<E, M>`** (plan 92). Composite
  driver running N session parsers against the same packet
  stream in one pass. Each registered parser observes packets
  matching its routing rule:
  - `.with_parser_on_ports(parser, ports, lift)` — fires when
    `dst_port ∈ ports || src_port ∈ ports`.
  - `.with_parser_broadcast(parser, lift)` — fires on every
    packet matching the flow's L4.
  Each parser's emitted messages are lifted to a user-supplied
  sum type `M` via the registration-time closure; events are
  merged in registration order. The 0.9 implementation runs
  parallel `FlowSessionDriver` instances internally (one per
  parser), trading the shared-tracker storage optimisation
  from the plan for ergonomic simplicity; this is documented
  inline and the optimisation can land in a follow-up.
- **TLS modernization** (plan 97). Two TLS additions behind
  Cargo features:
  - **`ja4` Cargo feature** — JA4 client fingerprint (FoxIO
    v1, 2023): cipher / extension sorting + GREASE removal +
    human-readable header (`t13d1516h2_8daaf6152771_b186095e22b6`).
    Public `flowscope::tls::ja4::ja4()` / `ja4_parts()`.
    Pulls `sha2` only when the feature is on.
  - **`TlsHandshakeParser`** — `SessionParser` that aggregates
    ClientHello + ServerHello + Alert into one `TlsHandshake`
    event per handshake. Carries SNI, ALPN (client + server),
    JA3/JA4 (when features on), negotiated version, cipher,
    `resumption_attempted`, and a `HandshakeOutcome` discriminant
    (`Completed` / `AlertedByServer` / `AlertedByClient` /
    `Truncated`). Reuses the existing `TlsParser` internally.
    `parser_kind()` returns `"tls-handshake"`.
  - `TlsConfig.ja4: bool` defaults to `false`.
  - `TlsMessage::Ja4 { fingerprint }` joins the existing
    `TlsMessage::Ja3 { … }` shape on the per-message stream.
- **`flowscope::layers` extensions** (plan 94 Tier 3 follow-up).
  Tunnel walking for VXLAN (UDP/4789), GTP-U (UDP/2152), GRE,
  and IP-in-IP — `Layers::has_tunnel()` / `Layers::truncated()`
  signal the outcome. New slice types: `ArpSlice`, `MplsSlice`,
  `Icmpv4Slice`, `Icmpv6Slice`, `GreSlice`, `VxlanSlice`,
  `GtpUSlice`. New convenience accessors: `.arp()`, `.mpls()`,
  `.icmpv4()`, `.icmpv6()`, `.gre()`, `.vxlan()`, `.gtpu()`.
  Inline `SmallVec` capacity grew from 6 → 8 to cover the
  outer-Eth+IP+UDP+VXLAN + inner-Eth+IP+TCP+Payload tunnel
  case without spilling.
- **`Pipeline::reset()` + `Pipeline::run_iter(iter)`** (plan 94
  Tier 1 follow-up). `reset()` drops per-flow tracker state so
  the same Pipeline can be re-run against multiple sources.
  `run_iter` drives the pipeline over any `IntoIterator<Item =
  OwnedPacketView>` — useful for custom sources (eBPF
  userspace, embedded, synthetic / test fixtures, netring's
  batched recv re-rolled into owned views). `OwnedPacketView`
  promoted from `pcap::source` to `view.rs` so `run_iter` is
  usable without the `pcap` feature.
- **`flowscope::layers` module** (plan 94 Tier 3). Public per-
  packet introspection: `Layers<'a>` with direct accessors
  (`.tcp()`, `.ipv4()`, `.vlan()`, …) and a dynamic walk
  (`iter` / `find` / `find_all` over `LayerKind`). Built atop
  `etherparse::SlicedPacket` with flowscope-shaped slice types
  (`TcpSlice`, `UdpSlice`, `Ipv4Slice`, `Ipv6Slice`,
  `EthernetSlice`, `VlanSlice`). Constructed via
  `PacketView::layers()` or `Layers::parse_ethernet` /
  `parse_ip`. Coverage in this first cut: Ethernet + VLAN
  (single + Q-in-Q) + IPv4/IPv6 + TCP (with options iterator) +
  UDP. Tunnel walking (VXLAN/GTP-U/GRE), ARP, ICMP slices, and
  a zero-allocation `LayerParser` fast path are scoped for
  follow-ups.
- **`flowscope::Pipeline` high-level entry point** (plan 94
  Tier 1). One import, one builder chain, one iterator over a
  unified `Event<K, SM, DM>` enum. Bundles
  `FlowSessionDriver` + `FlowDatagramDriver` with sensible
  defaults (anomalies emitted, monotonic timestamps for offline
  replay). Constructed via
  `Pipeline::builder(extractor).session(p).build()` /
  `.datagram(p)`. Runs via `pipeline.run_pcap("trace.pcap")`.
  Power users continue to drop down to the underlying drivers.
- **`flowscope::prelude` module**. `use flowscope::prelude::*;`
  imports `Pipeline`, `FiveTuple`, `FlowEvent`, `SessionEvent`,
  `Timestamp`, `Error`, `Result`, `Layers`, the protocol
  parsers, and the rest of the common surface so a
  hello-world program needs one `use`.

### Breaking (0.9 cycle)

- **Callback-factory L7 APIs removed** (plan 94 acceptance).
  The legacy `HttpFactory` / `HttpReassembler` / `HttpHandler`
  and `TlsFactory` / `TlsReassembler` / `TlsHandler` types are
  deleted. They predated the strategic `SessionParser` trait
  (0.1.0) and have been redundant since. Every callback use
  case is strictly subsumed by a `SessionParser` + a consumer
  loop on `SessionEvent::Application`. Migration:

  ```diff
  - use flowscope::http::{HttpFactory, HttpHandler, HttpRequest, HttpResponse};
  - use flowscope::FlowDriver;
  -
  - struct Logger;
  - impl HttpHandler for Logger {
  -     fn on_request(&self, req: &HttpRequest) { /* … */ }
  -     fn on_response(&self, resp: &HttpResponse) { /* … */ }
  - }
  -
  - let factory = HttpFactory::with_handler(Logger);
  - let mut driver = FlowDriver::new(ext, factory);
  - for view in source.views() {
  -     for _ev in driver.track(&view?) { /* lifecycle only */ }
  - }
  + use flowscope::extract::FiveTuple;
  + use flowscope::http::{HttpMessage, HttpParser};
  + use flowscope::{FlowSessionDriver, SessionEvent};
  +
  + let mut driver = FlowSessionDriver::new(ext, HttpParser::default());
  + for view in source.views() {
  +     for ev in driver.track(&view?) {
  +         if let SessionEvent::Application { message, .. } = ev {
  +             match message {
  +                 HttpMessage::Request(r)  => { /* … */ }
  +                 HttpMessage::Response(r) => { /* … */ }
  +             }
  +         }
  +     }
  + }
  ```

  Same shape for TLS: `TlsFactory` / `TlsHandler` →
  `TlsParser` + `for ev in driver.track(…)` consumer loop with
  `TlsMessage::ClientHello` / `ServerHello` / `Alert` arms.
  For one-shot handshake aggregation, use the new
  `TlsHandshakeParser` (plan 97).
- **MSRV bumped 1.85 → 1.88** (plan 99). Rust 1.88 (June 2025)
  stabilised let-chains at expression position
  (`if let Some(a) = x && let Some(b) = y { … }`), which
  flowscope's source already uses in several spots. The bump
  formalises the requirement and clears the way for an idiom
  sweep across the rest of the codebase. AFIT (1.75), async
  closures (1.85), and trait upcasting (1.86) are also
  available within the new MSRV.
- **Error types unified into `flowscope::Error`** (plan 96). The
  five module-local enums (`http::Error`, `tls::Error`,
  `dns::Error`, `pcap::Error`, `icmp::Error`) are removed.
  Every fallible flowscope API now returns
  `flowscope::Result<T>` (alias for `Result<T, flowscope::Error>`).
  `Error` carries a `Module`, an `ErrorCode`, a human-readable
  message, and an optional `source` chain to the upstream
  parser library's error type.

  *Migration:*
  ```diff
  - match err {
  -     flowscope::http::Error::Parse(s)          => log::warn!("http parse: {s}"),
  -     flowscope::http::Error::BufferOverflow(n) => log::error!("http overflow at {n}"),
  - }
  + use flowscope::{Module, ErrorCode};
  + match (err.module(), err.code()) {
  +     (Module::Http, ErrorCode::Parse)          => log::warn!("http: {err}"),
  +     (Module::Http, ErrorCode::BufferOverflow) => log::error!("http: {err}"),
  +     _ => {}
  + }
  ```

  Walk the underlying parser error with
  `std::error::Error::source()`. Display format is
  `"{module}: {code}: {message}"` — not API-stable, do not
  parse.

## 0.8.0 — serde, force_close, iter_active, ICMP helpers, DnsResolutionCache (2026-06-06)

Driven by the `netring` consolidated wishlist (2026-06-06,
after three prior feedback rounds). Pre-1.0 breaking changes;
`netring` updates in lockstep.

### Breaking

- **`FlowEvent::Established` gains a `l4: Option<L4Proto>` field**
  (plan 87). Rounds out the trio with `Started` (0.4.0) and
  `Ended` (0.7.0); same shape, same mechanical migration.
  *Migration:*
  ```diff
  - FlowEvent::Established { key, ts } => …
  + FlowEvent::Established { key, ts, l4 } => …
    // or
  + FlowEvent::Established { key, ts, .. } => …
  ```

### Deprecated

- **`FlowTracker::all_flow_stats`** in favour of
  [`FlowTracker::iter_active`] (plan 90). One-line migration; the
  new method exposes per-flow user state, TCP state, and L4
  protocol in addition to stats. Removal targeted for 0.9 or 0.10.

### Added

- **`serde` Cargo feature** (plan 83) — opt-in `Serialize` +
  `Deserialize` derives on every public event, message,
  accessor, and configuration type. **Locked wire vocabulary
  from 0.8 forward**: snake_case field / variant names; enums
  with payloads use adjacent tagging (`{"kind": "tcp"}` /
  `{"kind": "other", "value": 99}`); enums with all struct
  variants use internal tagging (`{"kind": "out_of_order_segment",
  "side": "initiator", "count": 5}`); `Timestamp` serializes as
  `{"sec": u32, "nsec": u32}`. Once shipped, dashboards depend
  on these names — renames require a CHANGELOG-documented
  breaking change. Adds `serde_json` / `bytes,serde` /
  `arrayvec,serde` / `smallvec,serde` transitive feature
  enablement. New CI feature-matrix entries: `serde` standalone
  + `serde,l7,pcap` combined.
- **Multi-protocol monitor recipe + example** (plan 91).
  `examples/multi_protocol_monitor.rs` demonstrates running
  HTTP + TLS + DNS + ICMP parsers against a single pcap with
  correlated (timestamp-merged) output. SESSION_GUIDE gains a
  "Multi-protocol monitoring" section covering both the simple
  "every parser, every pass" pattern and the performant manual-
  dispatch pattern. A full composite driver (wishlist B2) is
  deferred to a 0.9 RFC; this recipe is the recommended pattern
  until then.
- **`flowscope::dns::DnsResolutionCache`** (plan 85). TTL'd
  per-client DNS resolution cache for cross-protocol correlation:
  `"did client X recently resolve target Y?"` / `"what hostname
  did X use for Y?"`. Records every A / AAAA answer; skips
  CNAME / NS / MX. LRU-bounded (default 16,384 entries); periodic
  `sweep(now)` drops expired entries. Hostnames canonicalised to
  lowercase ASCII (RFC 1035 §2.3.1). Two netring detectors already
  hand-rolled this primitive; this lifts it once.
- **`FlowTracker::force_close` + driver mirrors + `EndReason::ForceClosed`**
  (plan 89). External orchestration can now end a specific flow
  ahead of FIN / idle / eviction. Use cases: resource budgets,
  test harnesses, rate limiters. Driver-level mirrors
  (`FlowDriver::force_close`, `FlowSessionDriver::force_close`,
  `FlowDatagramDriver::force_close`) tear down the parser +
  reassembler slots before emitting the terminal event. New
  `flowscope_flows_ended_total{reason="force_closed"}` metric label.
- **`FlowTracker::iter_active() -> impl Iterator<Item = ActiveFlow<'_, K, S>>`**
  (plan 90). Snapshots every live flow with key + stats + user
  state + TCP state + L4 protocol. `ActiveFlow` is
  `#[non_exhaustive]` named-struct so future fields stay
  non-breaking. LRU order untouched (uses `peek`-equivalent
  iteration).
- **`IcmpType::is_error()`, `error_inner()`, `short_kind()` +
  mirrors on `IcmpMessage`** (plan 84). `is_error` returns true
  for the seven error-class variants (Destination Unreachable,
  Redirect, Time Exceeded, Parameter Problem on v4; the v6
  counterparts plus Packet Too Big). `error_inner` returns
  `(label, &IcmpInner)` in one call — saves the 40-LoC manual
  match every ICMP-correlation consumer was writing.
  `short_kind` returns the stable variant slug as `&'static str`
  for metric labels (v4 and v6 variants with the same semantics
  share the same slug; `family` field disambiguates).
- **`AnomalyKind::short_kind() -> &'static str`** (plan 88).
  Stable variant slug returned for explicit metric-label intent.
  Same string as `Display`; pick whichever expresses your call
  site's intent.
- **`PARSER_KIND` / `PARSER_KIND_UDP` / `PARSER_KIND_TCP`
  constants per parser module + `flowscope::parser_kinds`
  umbrella re-export** (plan 86). Use the constants at match
  sites in place of `"http/1"` / `"dns-udp"` / `"tls"` / etc.
  string literals so typos fail to resolve (compile error)
  rather than silently miss at runtime. Each parser's
  `parser_kind()` impl now returns its module constant —
  single source of truth.

## 0.7.0 — ICMP parser, HTTP accessors, anomaly severity (2026-05-23)

Driven by the `netring` round-2 retrospective (2026-05-29, after
writing four L7 examples against 0.6). Pre-1.0 breaking changes;
`netring` updates in lockstep.

### Breaking

- **`FlowEvent::Ended` and `SessionEvent::Closed` gain a
  `l4: Option<L4Proto>` field** (plan 79). Mirrors the `l4` field
  already present on `FlowEvent::Started`; saves the per-consumer
  `HashMap<K, L4Proto>` workaround for "what protocol was this
  flow?" Pre-1.0 variant-field addition.
  *Migration:* update destructure patterns to bind or ignore the
  new field:
  ```diff
  - FlowEvent::Ended { key, reason, stats, history } => …
  + FlowEvent::Ended { key, reason, stats, history, l4 } => …
    // or
  + FlowEvent::Ended { key, reason, stats, history, .. } => …
  ```
  Same change applies to `SessionEvent::Closed`. New tracker
  accessor `FlowTracker::snapshot_l4(key)` populates the field on
  driver-synthesised Ended events (`BufferOverflow` / `ParseError`
  / `ParserDone`).

### Added

- **`flowscope::icmp` module + `icmp` Cargo feature** (plan 76).
  `IcmpParser` is a `DatagramParser` over ICMPv4 + ICMPv6,
  emitting a unified `IcmpMessage { family, ty }`. Type coverage
  via etherparse: v4 Echo Request/Reply, Destination Unreachable,
  Redirect, Time Exceeded, Parameter Problem, Timestamp; v6
  Destination Unreachable, Packet Too Big, Time Exceeded,
  Parameter Problem, Echo Request/Reply, plus manually-parsed
  Neighbor Solicitation / Advertisement. Other types surface as
  `Other { raw_type, raw_code, raw_body }`. **`IcmpInner`** —
  the killer feature for cross-protocol correlation — extracts
  `(src, dst, proto, src_port, dst_port)` from the embedded IP
  header in ICMP error messages, letting consumers tie ICMP
  errors back to the specific TCP/UDP flow they reference. The
  `l7` umbrella feature now includes `icmp`. Feature-matrix CI
  gains an `icmp`-standalone entry.
- **`SessionParser::is_done()` / `DatagramParser::is_done()`** +
  **`EndReason::ParserDone`** (plan 80). Reverses the 0.6 decline
  of round-1 #10. Lets a parser signal completion ahead of
  FIN/idle (HTTP/1.0 after body, DNS-over-TCP after Q/R pair,
  framed protocols with session-end sentinels). Default `false`;
  the driver checks after every `feed_*` / `parse` / `on_tick`.
  Poison precedence: a parser that's both poisoned AND done
  surfaces as `ParseError`. `OneShotSessionParser` /
  `OneShotDatagramParser` ship in `test_helpers` for driver
  integration tests. New `reason="parser_done"` label on
  `flowscope_flows_ended_total`.
- **`AnomalyKind::severity() -> Severity`** (plan 82). Defaulted
  classification: routine TCP noise (`OutOfOrderSegment`,
  `RetransmittedSegment`) → `Info`; cap / eviction pressure →
  `Warning`; parser poison → `Error`. `critical` reserved for
  future use. `Severity` is `Ord` so threshold filters compile
  directly (`kind.severity() >= Severity::Warning`). The
  `flowscope.anomaly` tracing target gains a structured
  `severity` field for subscriber routing.
- **HTTP and TLS convenience accessors** (plan 78). On
  `HttpRequest`: `host()`, `user_agent()`, `cookie()`. On
  `HttpResponse`: `content_type()`, `content_length()` (parsed
  `u64`), `set_cookie()` (iterator over multiple values). Both
  gain `header(name)` and `headers_all(name)` for arbitrary
  case-insensitive (RFC 7230 §3.2) lookup. `TlsClientHello::sni()`
  mirrors the `sni` field for accessor symmetry. Saves the
  `find().and_then(str::from_utf8)` dance every L7 example was
  carrying.
- **`impl Display` for `L4Proto`, `EndReason`, `AnomalyKind`**
  (plan 77). Rendered strings match the existing metric-label
  vocabulary (`tcp`/`udp`/`other`, `fin`/`rst`/`idle`/…,
  `buffer_overflow`/`ooo_segment`/…), so logs and Prometheus
  scrapes use the same tokens. Saves the `match l4 { … }`
  boilerplate that every consumer was writing against 0.6.
- **Intra-doc-link recipe in `docs/SESSION_GUIDE.md`** (plan 62).
  Closes a partial-implementation gap from the 0.6 cycle: the
  recipe shipped to `CLAUDE.md` (in-repo only); downstream
  re-exporters (`netring`, sister crates) read docs.rs and the
  crates.io package. Now in published reference material with a
  crate-level rustdoc breadcrumb for discoverability. CLAUDE.md
  collapses to a pointer so the source of truth doesn't drift.

## 0.6.0 — Driver state restore, anomaly split, watermark threshold (2026-05-23)

Driven by the `netring` 0.14.0 integration feedback (2026-05-22).
Pre-1.0 breaking changes; `netring` updates in lockstep.

This cycle was developed in parallel with the 0.5.0 release
(TCP rich diagnostics / FlowTick / parser_kind) which shipped
from a separate feedback source; the breaking-change notes below
are relative to 0.5.0.

### Breaking

- **Drivers regain the `S` per-flow-user-state type parameter
  (partial reversal of plan 32).** `FlowDriver<E, F>` →
  `FlowDriver<E, F, S = ()>`; same on `FlowSessionDriver` and
  `FlowDatagramDriver`. Existing call sites are **unchanged**: the
  common `new` / `with_config` constructors live on a pinned
  `impl<E, F> FlowDriver<E, F, ()>` block, so inference picks
  `S = ()` without an annotation. Advanced consumers (notably
  `netring`) can now drop their custom driver clones — every
  per-flow-state use case goes through the drivers again. New
  constructors: `with_state`, `with_state_and_config` (for
  `S: Default`), and `with_state_init`, `with_state_init_and_config`
  (custom init via `FnMut(&E::Key) -> S`). `tracker()` /
  `tracker_mut()` return `&FlowTracker<E, S>` again.
  *Migration:* code that explicitly named `FlowDriver<E, F>` /
  `FlowSessionDriver<E, P>` / `FlowDatagramDriver<E, P>` should
  either stay the same (the `S = ()` default kicks in) or be
  written explicitly as `FlowDriver<E, F, ()>`. Code that wants
  per-flow state switches from a hand-rolled `FlowTracker` + parser
  dispatch to the appropriate `with_state*` constructor.
- **`Anomaly { key: Option<K> }` split into `FlowAnomaly` +
  `TrackerAnomaly` on both `FlowEvent` and `SessionEvent`** (plan
  43). Per-flow anomalies (`BufferOverflow`, `OutOfOrderSegment`,
  `SessionParseError`, `ReassemblerHighWatermark`) land in
  `FlowAnomaly { key, kind, ts }`; tracker-global anomalies
  (`FlowTableEvictionPressure`) land in `TrackerAnomaly { kind, ts }`.
  Removes the `if let Some(k) = key` plumbing from every consumer.
  `FlowEvent` gains `#[non_exhaustive]` (was missing); both events
  gain a defaulted `anomaly_kind()` accessor for kind-only routing.
  *Migration:* replace `SessionEvent::Anomaly { key: Some(k), kind,
  ts } => …` with `SessionEvent::FlowAnomaly { key, kind, ts } =>
  …`, and `Anomaly { key: None, .. }` with `TrackerAnomaly { kind,
  ts }`.

### Added

- **`FlowTracker::finish()`** — `sweep(Timestamp::MAX)` under a
  readable name. Plan 33 added `finish()` to the drivers; plan 39
  brings the tracker to parity.
- **`FlowTracker::sweep_with_parsers`** and
  **`sweep_with_datagram_parsers`** — bake the on_tick choreography
  from the drivers into reusable helpers. Direct-tracker consumers
  (multi-stream wrappers, future custom drivers) drop their
  hand-rolled "sweep → on_tick → translate ended" boilerplate.
  Callback-shaped (`FnMut(&K, FlowSide, P::Message, Timestamp)`);
  per-flow parser map stays caller-owned for full construction-
  policy flexibility.
- **`l7` umbrella feature** — `flowscope = { version = "0.5",
  features = ["l7"] }` enables `http` + `tls` + `dns` together.
  Strict subset of `full` (no `pcap`, no observability).
- **CI feature-matrix** (internal): the workflow now runs
  library-only build + clippy across six partial-feature
  combinations to catch latent cfg dead-code at PR time.
- **`AsPacketView` trait + blanket `From<&T>` impl for
  `PacketView`** (plan 50). Foreign owned-packet types (netring's
  `OwnedPacket`, pcap-rs `Packet`, anything else) opt in with three
  lines and feed `tracker.track(&owned)` directly. Generalises 0.4's
  explicit `From<&OwnedPacketView>` (which is now an
  `AsPacketView` impl, going through the blanket). Existing call
  sites continue to compile via the blanket.
- **`flowscope::test_helpers::{NoopSessionParser,
  NoopDatagramParser, EchoSessionParser}`** (plan 59), under the
  existing `test-helpers` feature. Absorbs trait-shape evolution
  for downstream test crates: every minor that touches the parser
  trait shape no longer needs a sweep of hand-rolled noop stubs in
  consumer code.

### Breaking (minor)

- The explicit `impl From<&OwnedPacketView> for PacketView` from
  0.4 is removed in favour of `impl AsPacketView for OwnedPacketView`
  + the new blanket `impl<T: AsPacketView> From<&T> for
  PacketView<'_>` (plan 50). Existing `tracker.track(&owned)`
  calls go through the blanket and are unaffected. Only callers
  that named the explicit `From` impl by path are affected
  (extremely unlikely outside flowscope's own internals).

### Added (continued)

- **`AnomalyKind::ReassemblerHighWatermark { side, bytes, cap,
  threshold_pct }`** plus `BufferedReassembler::with_high_watermark_threshold(percent)`
  and the matching `BufferedReassemblerFactory` /
  `FlowTrackerConfig::reassembler_high_watermark_pct` knobs (plan
  44). Fires a `FlowAnomaly` once per below→above transition of
  the configured cap percentage (debounced; re-arms after the
  buffer drains below). Lets operators see cap pressure building
  before `BufferOverflow` bites. `Reassembler` trait grows
  defaulted `bytes_in_flight`, `high_watermark_crossings`, and
  `high_watermark_threshold` accessors (third-party impls
  unaffected).
- **`FlowSessionDriver::with_factory` /
  `FlowSessionDriver::with_state_factory` (and the
  `*_and_config` variants); same on `FlowDatagramDriver`** (plan
  58). Accept an `FnMut(&E::Key) -> P` closure per flow instead of
  cloning a template. Drops the `P: Clone` bound when constructed
  via the factory path — useful for parsers with expensive setup
  (compiled regex sets, ML model weights, big cipher tables) where
  the heavy state is shared via `Arc` and the per-flow handle is
  cheap. Existing `new` / `with_state*` ctors are unchanged.

## 0.5.0 — TCP rich diagnostics, periodic ticks, parser kinds (2026-05-28)

Driven by the `simple-nms` upstream wishlist (2026-08-11); the
two-consumer signal on the periodic-tick ask (also from `des-rs`
2026-05-14) reversed the previous snapshot-only stance.

### Breaking

- **`Reassembler::segment` takes a `ts: Timestamp`.** The new
  parameter is the carrying packet's kernel/source timestamp;
  `BufferedReassembler` uses it only to forward classified
  retransmits to `on_duplicate`. Pre-1.0 trait break per the BC
  policy.
  *Migration:* one-line signature update on every
  `Reassembler::segment` impl. Existing in-tree impls
  (`HttpReassembler`, `TlsReassembler`, `NoopReassembler`) take
  `_ts: crate::Timestamp` and ignore it.
- **`TcpInfo` is `#[non_exhaustive]`.** Closes an oversight from
  the 0.2.0 project-wide pass. External consumers always read the
  struct, so the change is benign in practice; internal
  constructors use struct-literal syntax.
- **`SessionEvent::Application` gains a `parser_kind: &'static
  str` field.** Variant-field addition — destructuring patterns
  need a new field name or `..`.
  *Migration:*
  ```diff
  - SessionEvent::Application { key, side, message, ts } => ...
  + SessionEvent::Application { key, side, message, ts, parser_kind } => ...
  + // OR
  + SessionEvent::Application { key, side, message, ts, .. } => ...
  ```

### Added

- **TCP retransmit classification.** `BufferedReassembler`
  distinguishes retransmits (`seq + len <= expected_seq`,
  including partial overlap) from strict OOO segments
  (`seq > expected_seq`) using wrap-aware sequence-space
  comparison. New `Reassembler::retransmits()` accessor and
  `on_duplicate(seq, payload, ts)` default-no-op hook let custom
  reassemblers track and react.
- **`AnomalyKind::RetransmittedSegment { side, count }`** —
  coalesced per (flow, side) per tick.
- **`FlowStats::retransmits_{initiator,responder}`** —
  populated by `FlowDriver::finalize_ended_flows` and
  `snapshot_flow_stats`.
- **`TcpInfo::window: u16`** — raw TCP receive window from the
  header (unscaled; window-scale tracking is a future plan).
- **Periodic `FlowEvent::Tick { key, stats, ts }` /
  `SessionEvent::FlowTick`** (opt-in via
  `FlowTrackerConfig::flow_tick_interval: Option<Duration>`,
  default `None`). The driver emits one Tick per live flow per
  interval, driven by packet timestamps (no wall-clock
  dependency). `stats` carries reassembler-patched diagnostics —
  same shape as `Ended.stats`.
- **`SessionParser::parser_kind` / `DatagramParser::parser_kind`**
  trait methods (default `""`). Shipped parsers report
  `http/1`, `tls`, `dns-udp`, `dns-tcp`. The length-prefixed
  example reports `length-prefixed`. Threaded into every
  `SessionEvent::Application::parser_kind`.
- **Metrics**:
  - `flowscope_retransmits_total{side=...}` — cumulative
    classified retransmits at `Ended`.
  - `flowscope_flow_ticks_total` — Tick emission counter.
  - New `retransmit` label on `flowscope_anomalies_total{kind}`.

### Fixed

- **Reassembly-diagnostic metrics on natural flow end.** The
  tracker called `record_flow_ended` from inside
  `track_with_payload` / `sweep` *before* the driver patched in
  reassembler-derived `FlowStats` fields, so
  `flowscope_reassembly_dropped_ooo_total`,
  `flowscope_reassembly_bytes_dropped_oversize_total`, and
  `flowscope_reassembler_high_watermark_bytes` always saw zeroes
  on FIN/RST/idle ends. Split into a new
  `record_reassembly_diagnostics` call fired from
  `finalize_ended_flows` after patching.

### Docs

- **SESSION_GUIDE.md**:
  - New "Updating per-flow state from parser messages" subsection
    documenting the canonical consumer-loop pattern that obviates
    threading `&mut S` through `SessionParser::feed_*`. The
    `simple-nms` wishlist's F1.4 ask is addressed here.
  - "Periodic flow ticks" subsection.
  - "Reassembly health" extended with retransmit + watermark
    fields and the new `Reassembler::segment(ts)` signature.
  - Trait-shape reference block updated with `parser_kind`.
- **OBSERVABILITY.md** — three new metric rows and corresponding
  Prometheus sample queries.
- Annotated responses to the simple-nms wishlist items F1.1–F1.7
  threaded into the per-plan commit messages and SESSION_GUIDE
  sections.

## 0.4.0 — API ergonomics (2026-05-20)

Driven by the audit in
[`docs/API-ERGONOMICS-REVIEW.md`](docs/API-ERGONOMICS-REVIEW.md).
Pre-1.0 breaking changes; `netring` and other consumers update in
lockstep.

### Breaking

- **Drivers lose the `S` per-flow-user-state type parameter.**
  `FlowDriver<E, F, S>` → `FlowDriver<E, F>`,
  `FlowSessionDriver<E, P, S>` → `FlowSessionDriver<E, P>`,
  `FlowDatagramDriver<E, P, S>` → `FlowDatagramDriver<E, P>`. The
  drivers always run their tracker with `S = ()`; per-flow user
  state remains on `FlowTracker<E, S>` for code that builds the
  tracker directly. This removes the `<_, ()>` /
  `<FiveTuple, _, ()>` annotation that type-parameter-default
  inference forced on every construction site.
  *Migration:* delete the trailing `, ()` from any explicit driver
  type; for per-flow user state, use `FlowTracker` directly.
- **`FlowSessionDriver` / `FlowDatagramDriver` constructors take the
  parser by value.** `new(extractor)` → `new(extractor, parser)`;
  `with_config(extractor, config)` → `with_config(extractor,
  parser, config)`. The parser bound relaxes from `Default + Clone`
  to just `Clone`, so non-`Default` (config-built) parsers now
  work.
  *Migration:* `FlowSessionDriver::<_, P>::new(ext)` →
  `FlowSessionDriver::new(ext, P::default())`.
- **`SessionParser` / `DatagramParser` data methods take a
  timestamp.** `feed_initiator` / `feed_responder` / `parse` gain a
  `ts: Timestamp` parameter — the observed time of the carrying
  packet — so stateful parsers can timestamp their messages and do
  time-driven correlation.
  *Migration:* add `_ts: Timestamp` (or `ts` if you use it) to every
  `feed_*` / `parse` implementation.
- **DNS-over-UDP unified on `DnsUdpParser`; `DnsUdpObserver` and the
  `DnsHandler` trait are removed.** `DnsUdpParser` is now a struct —
  construct it via `DnsUdpParser::new()` / `::with_correlation()` /
  `::with_config()`, not the bare `DnsUdpParser` literal.
  `with_correlation()` folds in the query/response correlation the
  observer used to own: `DnsResponse::elapsed` carries RTT, and
  `on_tick` emits the new `DnsMessage::Unanswered` variant.
  `DnsMessage` is now `#[non_exhaustive]`.
  *Migration:* replace `DnsUdpObserver` + `FlowTracker` + the
  hand-rolled `sweep_unanswered` timer with
  `FlowDatagramDriver::new(extractor, DnsUdpParser::with_correlation())`
  — or `PcapFlowSource::datagrams(...)` for offline pcap. The
  `DnsHandler` callbacks (`on_query` / `on_response` /
  `on_unanswered`) become `DnsMessage::{Query, Response,
  Unanswered}` match arms; periodic `sweep()` / `finish()` drives
  `on_tick`.

### Added

- **`SessionParser::on_tick` / `DatagramParser::on_tick`** — a
  defaulted periodic hook the drivers call on every `sweep` /
  `finish`, for every live parser (including one a sweep is about to
  close). Lets a parser emit time-driven messages — timeouts,
  unanswered requests — attributed to the initiator side. Default:
  no-op, so existing parsers are unaffected.

- **`finish()` on all three drivers** — `FlowDriver::finish()`,
  `FlowSessionDriver::finish()`, `FlowDatagramDriver::finish()`.
  Sweeps every still-open flow to its end; call once when input is
  exhausted. Equivalent to `sweep(Timestamp::MAX)` — replaces the
  ad-hoc "sweep with a far-future timestamp" pattern.
- **`Timestamp::MAX`** — the maximum representable timestamp
  (`u32::MAX` seconds), for forcing an end-of-input flush.
- **`track()` accepts `impl Into<PacketView>`** on `FlowTracker`,
  `FlowDriver`, `FlowSessionDriver`, and `FlowDatagramDriver`, plus a
  new `impl From<&OwnedPacketView> for PacketView`. A pcap
  `&OwnedPacketView` can be passed straight to `track()` — no
  `.as_view()`. Existing `track(packet_view)` calls are unaffected
  (`Into` is reflexive); `OwnedPacketView::as_view()` is retained.
- **`PcapFlowSource::sessions()` / `datagrams()`** — one-step
  offline L7 pipelines. `sessions(extractor, parser)` returns an
  iterator of typed `SessionEvent`s straight from a pcap, with the
  end-of-input flush folded in; `datagrams()` is the UDP mirror.
  Brings offline HTTP/TLS/DNS to the one-expression bar that
  `with_extractor()` already set for `FlowEvent`s.

## 0.3.0 — Production hardening

Eleven sub-plans driven by external feedback from the `des-rs`
team (2026-05-14) plus four planning-review additions. The plans
themselves have been pruned from `plans/` (shipped → deleted
convention); the implementation is in `git log` under the
`plan NN:` commit prefixes.

### Highlights

- **Live `FlowStats` snapshots** (Plan 46)
  via `FlowDriver::snapshot_flow_stats()` and
  `FlowSessionDriver::snapshot_flow_stats()`. Lazy iterator
  returning `(K, FlowStats)` with reassembler diagnostics
  patched in. Use `.collect::<Vec<_>>()` for the snapshot-
  everything case; `.take(1)` / `.filter()` consumers pay
  nothing for the rest.
- **Reassembler high-watermark** on `FlowStats` (peak buffer
  occupancy per side). Useful for tuning
  `max_reassembler_buffer`. New
  `flowscope_reassembler_high_watermark_bytes` metric (histogram).
- **Per-key idle timeouts** (Plan 47)
  via `FlowTracker::set_idle_timeout_fn(F)` and the matching
  `with_idle_timeout_fn(F)` builders on both drivers. Plus
  `FiveTupleKey::either_port(u16) -> bool` helper for the
  canonical port-based override case.
- **Monotonic timestamps** (opt-in,
  Plan 48) via
  `with_monotonic_timestamps(true)`. Clamps NIC timestamps to a
  running max — useful when downstream consumers want a strictly
  non-decreasing timeline.
- **Sync-side dedup** (Plan 49)
  via the new `flowscope::Dedup` primitive and
  `with_dedup(Dedup::loopback())` builder on both drivers.
  Content-hash + length + time-window match; ~1.2 µs per
  1500-byte frame.
- **`FlowDatagramDriver`** (Plan 57)
  — sync mirror of netring's `datagram_stream` for UDP-based
  `DatagramParser`s.
- **`SessionEvent::Anomaly`** forwarding
  (Plan 51) +
  `FlowSessionDriver::with_emit_anomalies(true)`. Plus an
  internal refactor: `FlowSessionDriver` now wraps `FlowDriver`
  for single source of truth on anomaly / overflow synthesis.
- **Parser fallibility** (Plan 55)
  via `SessionParser::is_poisoned()` / `poison_reason()` (mirror
  on `DatagramParser`). On poison, the driver synthesises
  `Ended { reason: ParseError }` plus optional
  `Anomaly { kind: SessionParseError, .. }`.
- **`tracing-messages` sub-feature** (Plan 56)
  — emit `tracing::trace!` per `SessionEvent::Application`.
  Off by default; targets `flowscope.message`.
- **Criterion benchmark harness** (Plan 54)
  under `benches/` with five groups (extractor, tracker,
  reassembler, session_driver, dedup). Documented baselines in
  [`docs/PERFORMANCE.md`](docs/PERFORMANCE.md). Plan 41's
  hot-cache claim verified at ~1.4× monoflow vs 10k-flow
  round-robin.
- **Round-trip CI fixture** (Plan 52)
  — `tests/round_trip.rs` exercises
  synthesize→pcap→PcapFlowSource→FlowSessionDriver→assert
  byte-equality across hand-written + proptest cases.
- **SessionParser author guide**
  (Plan 53) — new
  walkthrough section in `docs/SESSION_GUIDE.md` covering the
  trait contract, partial-buffer pattern, resync strategies,
  and testing approach.

### Breaking changes

Pre-1.0 release; these are minor breaks that pay off in
long-term API quality:

- **`SessionEvent` is now `#[non_exhaustive]`** with a new
  `Anomaly` variant. External `match` blocks need a wildcard
  arm.
- **`EndReason` is now `#[non_exhaustive]`** with a new
  `ParseError` variant. External `match` blocks over
  `EndReason` need a new arm (treat it like `Rst` for
  cleanup semantics).
- **`SessionParser::Message` and `DatagramParser::Message`**
  gain a `Debug` trait bound (was just `Send + 'static`). All
  four shipped parsers + the example parser already derive
  `Debug`; external impls add one derive line.
- **`Reassembler` trait gains a `high_watermark()` method**
  with a default-zero impl. Existing impls compile unchanged;
  custom reassemblers can override to surface their own peak.
- **`SessionParser` / `DatagramParser` gain `is_poisoned()` +
  `poison_reason()`** methods with default impls (`false` /
  `None`). Existing impls compile unchanged.

Internal-only:
- **`FlowSessionDriver` is rewired** to wrap `FlowDriver`
  internally. Public signature unchanged; consumers using the
  type alias / generic shape need a recompile.
- **`FlowDriver::track` split into `track_pending` +
  `finalize`** for callers that need access to reassemblers
  between segment dispatch and Ended-event finalization. The
  high-level `track` and `sweep` methods keep the existing
  one-shot semantics.

### New API

- `flowscope::FlowDatagramDriver<E, P, S>` — sync UDP driver.
- `flowscope::Dedup` — content-hash dedup primitive.
- `flowscope::IdleTimeoutFn<K>` — predicate type alias for
  per-key idle-timeout overrides.
- `FlowTracker::all_flow_stats()` — borrow-iterator over live
  FlowStats.
- `FlowTracker::set_idle_timeout_fn` / `clear_idle_timeout_fn`.
- `FlowDriver::snapshot_flow_stats()` / `with_idle_timeout_fn`
  / `with_dedup` / `with_monotonic_timestamps` /
  `track_pending` / `sweep_pending` / `finalize` /
  `reassembler` / `drain_buffer` / `emits_anomalies` / `dedup`.
- `FlowSessionDriver::snapshot_flow_stats` /
  `with_idle_timeout_fn` / `with_dedup` /
  `with_monotonic_timestamps` / `dedup`.
- `FiveTupleKey::either_port(u16) -> bool`.
- `BufferedReassembler::high_watermark()` /
  `Reassembler::high_watermark()` trait method.
- `Timestamp::saturating_sub(other) -> Duration`.
- `EndReason::ParseError`.
- `AnomalyKind::SessionParseError { side, reason }`.
- `flowscope::obs::METRIC_REASSEMBLER_HIGH_WATERMARK`.

### Migration

Most consumers need only a recompile. The exhaustive-match
fixes:

```diff
- match reason {
-     EndReason::Fin => ...,
-     EndReason::Rst => ...,
-     EndReason::IdleTimeout => ...,
-     EndReason::Evicted => ...,
-     EndReason::BufferOverflow => ...,
- }
+ match reason {
+     EndReason::Fin => ...,
+     EndReason::Rst => ...,
+     EndReason::IdleTimeout => ...,
+     EndReason::Evicted => ...,
+     EndReason::BufferOverflow => ...,
+     EndReason::ParseError => ..., // treat like Rst
+     _ => ..., // future variants land in 0.4.0+
+ }

- match event {
-     SessionEvent::Started { .. } => ...,
-     SessionEvent::Application { .. } => ...,
-     SessionEvent::Closed { .. } => ...,
- }
+ match event {
+     SessionEvent::Started { .. } => ...,
+     SessionEvent::Application { .. } => ...,
+     SessionEvent::Closed { .. } => ...,
+     SessionEvent::Anomaly { .. } => ..., // new in 0.3.0
+     _ => ..., // forward-compatible
+ }
```

For external `SessionParser` / `DatagramParser` impls whose
`Message` type didn't derive `Debug`:

```diff
- #[derive(Clone)]
+ #[derive(Debug, Clone)]
  struct MyMessage { ... }
```

## 0.2.0 — Reassembly observability + metrics/tracing hooks

This minor release ships the bundle described in
Plan 42:
optional buffer caps on `BufferedReassembler`, end-of-flow reassembly
diagnostics on `FlowStats`, and a live `FlowEvent::Anomaly` stream.
It also adds opt-in `metrics` + `tracing` features (Plan 40)
that share the same `AnomalyKind` vocabulary, plus a hot-cache
fast-path on `FlowTracker` (Plan 41).
The motivating consumer is [`des-rs`](https://github.com/p13marc/des-rs)'s
`tools/des-capture`, which can now drop its hand-rolled
`TcpStreamTracker` in favour of flowscope.

### Highlights

- **`BufferedReassembler::with_max_buffer(n)`** — optional per-side
  byte cap, paired with **`with_overflow_policy(...)`** to choose:
  - `OverflowPolicy::SlidingWindow` (default) — drop oldest bytes
    from the buffer; flow stays alive; parser sees a gap and must
    resync. Best for stream-shaped / append-only protocols.
  - `OverflowPolicy::DropFlow` — poison the reassembler; the driver
    synthesises an `Ended { reason: EndReason::BufferOverflow }`
    event on the next tick. Best for framed binary protocols (DES
    PSMSG, TLS records, length-prefixed wire formats).
- **Reassembly diagnostics on `FlowStats`** — four new fields
  (`reassembly_dropped_ooo_initiator/responder`,
  `reassembly_bytes_dropped_oversize_initiator/responder`) populated
  by `FlowDriver` when each flow ends.
- **Live `FlowEvent::Anomaly`** — opt-in via
  `FlowDriver::with_emit_anomalies(true)`. Emits one `AnomalyKind`
  per (flow, side, kind) per tick:
  - `BufferOverflow { side, bytes, policy }`
  - `OutOfOrderSegment { side, count }`
  - `FlowTableEvictionPressure { evicted_in_tick, evicted_total }` —
    tracker-global signal that `max_flows` is the bottleneck.

### Breaking changes

- **`#[non_exhaustive]`** applied project-wide to every public
  struct/enum that's likely to grow over time. From now on, additive
  changes are unconditionally non-breaking.
  Affected types: `FlowStats`, `FlowTrackerConfig`, `AnomalyKind`,
  `OverflowPolicy`. Construct via `::default()` and mutate; do not
  rely on struct-literal construction from outside the crate.
- **`FlowEvent::key()`** now returns `Option<&K>` (was `&K`).
  `None` is reserved for tracker-global anomalies (e.g.
  `FlowTableEvictionPressure`); per-flow events still return
  `Some(key)`. Migrate via `event.key().expect("non-anomaly")` or
  pattern-match.
- **`EndReason`** gained a new `BufferOverflow` variant. Any
  exhaustive `match EndReason { ... }` needs a new arm. Treat it
  like `Rst` for cleanup semantics (the driver does).
- **`Reassembler` trait** gained three default-zero diagnostic
  methods (`dropped_segments`, `bytes_dropped_oversize`,
  `is_poisoned`). Existing impls compile unchanged; surface real
  counts by overriding.

### Observability hooks (Plan 40)

- New optional `metrics` Cargo feature: counters, gauges, and
  histograms wired through `FlowTracker` and `FlowDriver`. Metric
  vocabulary documented in [docs/OBSERVABILITY.md](docs/OBSERVABILITY.md).
- New optional `tracing` Cargo feature: structured events at flow
  lifecycle transitions and on every emitted anomaly.
- Both features are zero-cost when off (compile-time stubbed).
- Public metric-name constants exported from `flowscope::obs`
  (`METRIC_FLOWS_CREATED`, `METRIC_ANOMALIES`, …).

### Sync session driver + worked example (Plan 25)

- **`FlowSessionDriver<E, P, S>`** — the sync mirror of netring's
  async `session_stream`. Bundles `FlowTracker` + per-(flow, side)
  `BufferedReassembler` + per-flow `SessionParser` and yields
  `SessionEvent`s without a runtime dependency. Honours
  `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`
  automatically.
- **`examples/length_prefixed_pcap.rs`** — end-to-end example of
  writing a custom `SessionParser` for a length-prefixed binary
  protocol (PSMSG-shaped). Demonstrates partial-header / partial-body
  buffering and pairs with a deterministic pcap fixture under
  `tests/fixtures/length_prefixed/`.
- New integration test `tests/length_prefixed_example.rs` verifies
  the parser against the fixture and against byte-by-byte sliced
  input.

### Performance (Plan 41)

- `FlowTracker` gains a "last flow seen" hot-cache that skips the
  hash lookup when consecutive packets share a key. Estimated 2x
  throughput on monoflow workloads (single iperf3 / HTTP/2 stream),
  small win on heterogeneous traffic. No API impact.

### New API

- `flowscope::OverflowPolicy` (`SlidingWindow`, `DropFlow`).
- `flowscope::AnomalyKind` (non_exhaustive).
- `BufferedReassembler::with_max_buffer` /
  `with_overflow_policy` / `bytes_dropped_oversize` / `is_poisoned`.
- `BufferedReassemblerFactory::with_max_buffer` /
  `with_overflow_policy`.
- `FlowTrackerConfig::max_reassembler_buffer` / `overflow_policy`.
- `FlowTracker::snapshot_stats(&K)` /
  `snapshot_history(&K)` / `forget(&K)` — accessors used by the
  driver to synthesise `BufferOverflow` end events.
- `FlowDriver::with_emit_anomalies(bool)`.
- `FlowEvent::Anomaly { key, kind, ts }`.
- `FlowSessionDriver<E, P, S>` — sync session driver that bundles
  `FlowTracker` + per-(flow, side) reassembler + per-flow
  `SessionParser`. The sync mirror of netring's `session_stream`.
- `flowscope::obs` module — `metrics` / `tracing` hook surface plus
  the public metric-name constants.

### Migration

Most consumers need only:

```diff
- let cfg = FlowTrackerConfig { max_flows: 100, ..Default::default() };
+ let mut cfg = FlowTrackerConfig::default();
+ cfg.max_flows = 100;
```

(Within the same crate, struct-literal syntax with `..Default::default()`
keeps working — `non_exhaustive` only restricts external constructors.)

If you destructure or pattern-match `FlowEvent::Ended { stats: FlowStats { ... } }`,
add `..` to the inner pattern:

```diff
- FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, ... } } => ...
+ FlowEvent::Ended { stats: FlowStats { packets_initiator, packets_responder, .. } } => ...
```

If you call `event.key()` and treat the return as a borrow:

```diff
- let k: &K = event.key();
+ let k: Option<&K> = event.key();
```

---

## 0.1.0 — Initial release

`flowscope` is a passive flow & session tracking library extracted
from the previous `netring-flow{,-http,-tls,-dns,-pcap}` workspace
into a single, publishable crate with feature-gated modules. The
core layers (extractor → tracker → reassembler → session/datagram
parsers) are runtime-free and cross-platform; protocol parsers are
opt-in via Cargo features.

### Core

- `PacketView` / `Timestamp` — abstract input.
- `FlowExtractor` trait + built-in extractors: `FiveTuple`, `IpPair`,
  `MacPair`. Decap combinators: `StripVlan`, `StripMpls`, `InnerVxlan`,
  `InnerGtpU`, `InnerGre`. Combinator: `AutoDetectEncap` (tries
  plain → VLAN → MPLS → VXLAN → GTP-U → GRE in order). Key
  augmentation: `FlowLabel<E>` (IPv6 flow label).
- `FlowTracker<E, S>` — bidirectional flow accounting, TCP state
  machine (`SynSent → Established → FinWait → Closed` + `Reset`),
  per-protocol idle timeouts (Suricata defaults), LRU eviction.
  `manual_tick(now)` alias for `sweep`.
- `FlowEvent<K>` — `Started`, `Packet`, `Established`, `StateChange`,
  `Ended` (with `EndReason`, `FlowStats`, `HistoryString`).
- `Reassembler` / `ReassemblerFactory<K>` — sync per-(flow, side) TCP-
  segment hook; `BufferedReassembler` built-in.
- `FlowDriver<E, F, S>` — sync wrapper combining tracker + reassembler.
- `SessionParser` / `DatagramParser` (with `*Factory<K>` companions
  and blanket impls for `Default + Clone` parsers) — typed L7 message
  parsing per flow. Trait shape stable for the 1.0 lock; future
  additions will be additive.
- `SessionEvent<K, M>` — `Started { key, ts }`,
  `Application { key, side, message, ts }`,
  `Closed { key, reason, stats }`.

### Protocol parsers (each behind its own feature)

- **`http`** — HTTP/1.0 / HTTP/1.1 via `httparse`. Both
  `HttpFactory` (callback-style) and `HttpParser` (`SessionParser`)
  ship side by side. Pipelined messages, split segments, and
  Connection: close bodies handled.
- **`tls`** — passive TLS handshake observer. `TlsFactory`
  (callback) and `TlsParser` (`SessionParser`) emit ClientHello /
  ServerHello / Alert events. Records past ChangeCipherSpec are
  silently skipped (encrypted). Optional `ja3` sub-feature for JA3
  fingerprinting (GREASE stripped per RFC 8701).
- **`dns`** — DNS message parser. UDP path: `DnsUdpObserver`
  (callback-style tap on top of any `FlowExtractor`) and
  `DnsUdpParser` (`DatagramParser`). TCP path: `DnsTcpParser`
  (`SessionParser`, RFC 1035 §4.2.2 length-prefixed framing).
  Per-flow query/response correlator with 16-bit transaction ID
  scoping, oldest-first eviction on overflow, sweep for unanswered
  timeouts.
- **`pcap`** — `PcapFlowSource` for offline replay; produces views &
  flow events from any `.pcap` file.

### Tokio integration

For an async stream over flow / session / datagram events, see
[`netring`](https://crates.io/crates/netring)'s `AsyncCapture::flow_stream`,
`.session_stream`, `.datagram_stream`, and `.broadcast`. The traits
they consume live in this crate; the Stream impls live in `netring`.

### Tests

- 167 unit tests + 11 parser proptests (splitting invariance and
  no-panic across HTTP / TLS / DNS-UDP / DNS-TCP) + tracker
  proptests (FiveTuple canonicalization, TCP state-machine
  invariants).
- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo fmt --check` clean.
- `cargo doc --all-features --no-deps` clean.

### Documentation

- [`docs/SESSION_GUIDE.md`](docs/SESSION_GUIDE.md) — decision-flow
  for picking between `FlowEvent`, `Reassembler`, `*Factory<H>`,
  `SessionParser`, `DatagramParser`, and `Conversation<K>`. Includes
  migration recipes from callback-style factories to the typed-stream
  parser API.

### Notes

- This crate replaces `netring-flow`, `netring-flow-http`,
  `netring-flow-tls`, `netring-flow-dns`, and `netring-flow-pcap`
  (none of which were ever published to crates.io). Migration:
  rename your dep to `flowscope` and update import paths from
  `netring_flow_http::X` → `flowscope::http::X` (and similarly for
  `tls` / `dns` / `pcap`). Trait names and types are unchanged.
- Out of scope for v0.1.0:
  - HTTP/2, HTTP/3 (no plan yet).
  - DoH / DoT / DoQ (no plan yet).
  - NetFlow / IPFIX export (plan 32, deferred).
  - Observability (`metrics` / `tracing` integration; plan 40,
    deferred).
  - Zero-copy reassembly (plan 41, deferred — needs profiling-guided
    redesign).
  - IPv6 fragment reassembly (plan 50.5, deferred).
  - `protolens` companion (plan 21, on demand).
  - CLI tooling (`flow-summary`, `flow-replay`; plan 60, would need
    workspace conversion).
