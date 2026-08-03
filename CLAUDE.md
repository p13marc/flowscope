# CLAUDE.md

## Project Overview

`flowscope` is a passive flow & session tracking library for packet
capture pipelines. Single crate with feature-gated modules. Runtime-
free, cross-platform — no tokio, no futures, no Linux-specific code in
the core.

- Edition 2024, MSRV 1.97 (uniformized across toolchains, images,
  and CI after the 0.22 cycle; was 1.88)
- Single Cargo package; modules `http` / `http2` / `tls`
  (+ `tls-fingerprints`) / `dns` / `pcap` are opt-in via Cargo
  features. Observability hooks
  (`metrics`, `tracing`) are opt-in too.
- Pairs with [`netring`](https://crates.io/crates/netring) for live
  Linux capture; with `pcap` files for offline replay; with any other
  source of `&[u8]` frames (tun-tap, eBPF userspace, embedded, etc.)
- Pre-1.0 API; trait shape (`SessionParser` / `DatagramParser`) is
  stable since 0.1.0. Public structs are `#[non_exhaustive]` since
  0.2.0 — additive fields/variants are unconditionally non-breaking.

## Implementation Status

**0.23.0 cycle** (inline-proxy / sans-IO L7 core — milestone
"Inline-grade: sans-IO L7 core for inline proxies", **in progress,
not yet published**).

Fifteen PRs across three epics (#172 / #173 / #174) plus a
backlog-clearing round, one branch/PR per issue, breaking-first so
`docs/migration-0.22-to-0.23.md` accretes. Turns flowscope from a
passive-telemetry library into one that can also sit inline in the
data path.

- **One streaming HTTP engine, two front-ends (`#160`, breaking).**
  `src/http/parser.rs` became `src/http/engine.rs`: a single
  `pub(crate)` state machine that emits a head, then body spans it
  never retains, then trailers, then an end marker. `HttpParser` is
  now an aggregating front-end over it (public shape unchanged);
  `HttpProxyParser` forwards the events. Because framing lives in one
  place, the telemetry path inherited every fix: chunked bodies are
  decoded (they were never framed at all before), a clean FIN no
  longer looks like a parse error, HEAD/1xx/204/304 responses are
  framed correctly, and `HttpOutcome::Reset` became reachable.
  `BodyFraming::UntilEof` → `UntilClose`.
- **`HttpProxyParser` — sans-IO streaming (`#161`).**
  `push(dir, &Bytes) -> usize` + `next_event()`. Two contracts make
  it a forwarding core: every event carries the exact wire bytes it
  consumed (concatenating `raw` reproduces the message byte for
  byte), and the parser never accumulates a body — a short `push`
  return is the backpressure signal.
- **Method-aware framing, interims, tunnels (`#162`).** 1xx
  interims reported without completing the exchange (the
  100-continue deadlock is structurally impossible: directions
  advance independently and the request context is queued at
  *head* time); CONNECT-2xx and 101 emit `SwitchProtocols`; the h2
  preface at request position is recognised rather than reported as
  malformed.
- **RFC 9112 §6.3 smuggling defense (`#163`).** `SmugglingPolicy`
  (Strict / Normalize / Observe) with the full violation table in the
  engine, typed `HttpPoison` reasons, and `RequestHead::authority()`
  resolving the routing key ASCII-only (Unicode folding makes U+212A
  a desync primitive). 22-case regression suite + committed fuzz
  seeds.
- **`HttpProxySession` adapter (`#164`)** so the streaming events can
  ride the typed `Driver`, plus the runnable
  `examples/01-l7-logging/http_streaming_proxy.rs`.
- **`flowscope::classify` (`#165`).** `classify_first_bytes` — the
  cleartext counterpart to `app_proto`: `Tls` / `Http1` /
  `Http2Preface` / `Ssh` / `Raw`, with prefix safety as the
  load-bearing property (a short peek never decides wrongly). No
  deps, no feature gate.
- **Heuristic-probe fixes (`#166`).** Probe-consumed frames are now
  replayed into the pinned parser (they were silently dropped — the
  bytes that identified the protocol were the ones the parser never
  saw); a definitive `NoMatch` fast-fails; probe state is bounded.
- **TLS routing contract (`#167`).** `docs/tls-routing.md`: the
  degradation ladder, `ech_present` as advisory-only (GREASE ECH is
  byte-indistinguishable), post-quantum ClientHello sizing, ALPACA
  binding. `TlsHandshake::routing_alpn()` / `routing_sni()`.
  Citations corrected: ECH is **RFC 9849**, DNS carriage **RFC 9848**
  with SVCB `ech` key **5**, ML-KEM hybrids still a draft.
- **Inline-path observability (`#168`).** `HttpAccessLog` →
  `HttpAccessRecord` (head-only, never bodies) →
  `EveJsonWriter::write_http_access`; `flowscope_http_messages_total`
  and `flowscope_http_poisoned_total{reason}`.
- **Bounded-memory contract (`#169`).** `docs/bounded-memory.md` from
  a crate-wide audit. Found two leaks in this cycle's own code (a
  desynced HTTP direction that kept accumulating — a regression from
  #160; heuristic probe state #166 had only partly bounded) and five
  pre-existing gaps now tracked as #184–#188.
- **HTTP/2 on the typed `Driver` (`#196`).** `Http2Session` — the
  `SessionParser` adapter HTTP/1 got in #164. Plus
  `Http2Config::require_preface` (the session tolerates a missing
  preface so a mid-stream join parses rather than poisons) and a
  wedge fix: `max_frame_size` and `max_buffered_bytes` now compose,
  so `push` returning 0 always implies a reported state — the
  invariant the adapter's loop rests on, since the trait cannot
  express a short read.
- **HTTP/2 + HPACK + gRPC (`#170`, `#171`).** New `http2` feature:
  frame layer, a hand-rolled RFC 7541 HPACK decoder (validated
  against the Appendix C vectors), HEADERS+CONTINUATION reassembly,
  per-stream events reusing the HTTP/1 vocabulary, and the gRPC
  routing surface (`GrpcCall`, `GrpcStatus` incl. Trailers-Only).
  All buffers bounded by `Http2Config`. New fuzz target.

**Backlog-clearing round (#184–#188), closing the audit's own
findings before release.** The bounded-memory page states a memory
contract; shipping it beside five open holes in that contract would
have been inconsistent.

- **`MemcapPolicy` behaves as documented (`#186`).** `DropPacket`
  refuses the segment *before* handing it to the reassembler (the
  only point where rejection is possible — `Reassembler::segment`
  returns `()` and cannot be undone); `PassThrough` releases the
  side's buffer and keeps the flow, via the new additive
  `Reassembler::release` (default no-op); `Ignore`'s doc now says
  it only reports, matching Suricata. Also: bytes a parser drained
  return to the pool immediately instead of at flow end.
- **Cleanup decoupled from event emission (`#185`).** Teardown keyed
  off `FlowEvent::Ended`, which `EventMask::ENDED` can shed while
  the tracker reaps the flow anyway — so shedding under load leaked
  one reassembler pair and one parser per flow. Each sweep now
  reconciles against the tracker, *after* ordinary teardown so a
  flow ending in that same sweep still gets its final tick / `fin_*`
  / `Closed`.
- **`max_reassembler_buffer` defaults to `Some(1 MiB)` (`#188`),**
  was `None`. Plus `SegmentBufferReassembler::append_ready` now
  trims a segment larger than the whole cap instead of appending it
  in full.
- **QUIC reassembly bounded (`#184`).** New `QuicConfig` (conns /
  TTL / crypto bytes / crypto frames) + `pending_dropped()` /
  `tracked()`. The TTL advances only on *progress*, so replaying
  frames can no longer hold an entry past it. The frame cap is what
  bounds the quadratic re-sort; the byte cap alone would allow
  65 536 one-byte frames.
- **`PortScanDetector` capacity-bounded (`#187`).**
  `with_capacity` (default 10 000) + LRU eviction on `last_touch` +
  `evicted()`. `observe` deliberately keeps its `(key, success)`
  signature.

Test count after the cycle: **2161 passing** (up from 1919 at
0.22.0). Zero clippy warnings under `--all-features --all-targets
-D warnings`, zero rustdoc warnings. New modules: `src/classify.rs`,
`src/http/{engine,proxy,poison,access}.rs`, `src/http2/`. New docs:
`docs/tls-routing.md`, `docs/bounded-memory.md`,
`docs/migration-0.22-to-0.23.md`. Every issue in the milestone and
the whole open backlog is closed. **Not yet published to crates.io —
the user has asked for no release yet.**

**0.22.0 cycle** (fingerprinting & encrypted-traffic frontier —
the #140 roadmap's fingerprinting/L7-depth group,
**published to crates.io as 0.22.0 on 2026-07-03**).

Six PRs (#151–#155 + #141), one branch/PR per issue,
breaking-first so `docs/migration-0.21-to-0.22.md` accretes. Closes
the last six open #140 roadmap items. Themes:

- **Unified JA4+ surface + license audit (`#136`).**
  `flowscope::fingerprint` facade — one import site for the whole
  JA4+ family, grouped by license (royalty-free
  `tls-fingerprints` vs FoxIO-1.1 `ja4plus`). New public
  `tls::ja3_fingerprint` / `ja3_canonical`. Confirmed JA4S/X/H/
  SSH/T/L stay out of the `l7`/`full` umbrellas.
- **Post-quantum ClientHello reassembly (`#135`, small break).**
  X25519MLKEM768 (Chrome 131+/Firefox default) makes the CH
  ~1.4 KiB — too big for one segment/Initial. `QuicUdpParser` is
  now **stateful** (unit→struct; use `::new()`): accumulates
  CRYPTO frames per-DCID across QUIC Initials. `TlsClientHello`
  gains `key_share_groups`/`pq_key_share`; `TlsHandshake` mirrors
  `pq_key_share`; new `tls::is_pq_hybrid_group` /
  `pq_hybrid_group_name`.
- **Encrypted-DNS + HTTP/2·3 detection + IP-fragment reassembly
  (`#138`, additive).** `flowscope::app_proto` (`AppProtocol` +
  `classify` from ALPN/SNI/port; `is_known_doh_host` curated
  resolver list). Port 853 in `well_known`.
  `flowscope::ip_fragment::IpFragmentReassembler` (RFC 791 key,
  RFC 5722 overlap-drop IOC; `push`/`push_ipv4`).
- **Asset fingerprint correlation (`#137`, additive).**
  `Asset::from_tls_handshake` / `from_ssh_kexinit` /
  `from_tcp_fingerprint` finally wire JA3/JA4/JA4X/HASSH/p0f into
  the inventory (new `AssetSourceSet` TLS/SSH/P0F bits). x509
  subject/SAN extraction (`ja4plus`). Lifted IP cap 4→16 + plural
  `hostnames`; `first_seen` + `source_count()` + `role()` /
  `AssetRole`. (Typed-newtype fingerprints deliberately skipped —
  they're canonically hash strings.)
- **Single-table parser/module registries (`#139`, break).**
  `slug_enum!` generates `ParserKind` (enum + `as_str` +
  `from_slug` from one table — kills the as_str/from_slug drift
  bug class); `module_enum!` generates `Module` + `Display`.
  Removed the deprecated `flowscope::parser_kinds` umbrella. Slugs
  byte-identical.
- **Throughput-by-owner aggregation (`#141`, additive).**
  `correlate::BandwidthByKey<K>` — per-key tx/rx byte-rate over a
  sliding window on `RollingRate`, generic over the owner key
  (pid / cgroup / `Attribution` / FiveTuple / ParserKind).
  `correlate::ByteSemantics` (Wire/Goodput) tag +
  `correlate::Attribution(u64)` opaque owner newtype. flowscope
  stays process-unaware — the consumer supplies the owner key.

Test count after the cycle: **1919 passing** (up from 1890 at
0.21.0). Zero clippy warnings under `--all-features --all-targets
-D warnings`, zero rustdoc warnings. New modules:
`src/app_proto.rs`, `src/ip_fragment.rs`, `src/tls/pq.rs`,
`src/correlate/bandwidth.rs`. New examples
`examples/01-l7-logging/encrypted_app_classify.rs`,
`examples/04-observability/bandwidth_by_owner.rs`,
`examples/02-forensics/ip_fragment_reassembly.rs` +
`asset_fingerprint_correlation.rs`. The five new public modules
each ship a rustdoc doctest. Migration recipes in
`docs/migration-0.21-to-0.22.md`. Published to crates.io as
`0.22.0` on 2026-07-03 (carrying the 0.21.0 cycle with it).

**0.21.0 cycle** (detection architecture — the #140 roadmap
keystone group, **never published separately — shipped inside
0.22.0 on 2026-07-03**).

Eight PRs (#146–#149 + earlier branches), one branch/PR per
issue, sequenced breaking-first so the migration doc
(`docs/migration-0.20-to-0.21.md`) accretes. Themes:

- **Typed detector identity (`#133`, breaking).** `OwnedAnomaly.kind`
  graduates from a `Cow<'static, str>` slug to the typed
  `flowscope::DetectorKind` enum (ParserKind precedent, #109) —
  compile-time break, **byte-identical wire** (slugs preserved:
  `Dga`→`"DgaScorer"`, `PortScanTrw`→`"PortScanTRW"`). Adds
  `attack_technique() -> Option<&'static str>` MITRE ATT&CK
  mapping; `EveJsonWriter` emits `anomaly.attack_technique`
  additively. `DetectorScore::name()` → `kind()`.
- **Unified `Detector` trait + `DetectorRegistry` (`#131`,
  keystone).** Register a heterogeneous detector set once, drive
  it from one event stream (`observe` / `observe_event` /
  `observe_dns`) via defaulted no-op lifecycle hooks + caller-buffer
  output (`track_into` idiom). Derived aggregation keys `SrcHost` /
  `HostPair` replace the per-consumer `SrcIpKey` newtype. Shipped
  `Detector` impls for beacon / RITA-beacon (threshold+cooldown
  emission gate) / port-scan (success derived from `HistoryString`)
  + a `DgaDetector` wrapper.
- **Four upstreamed NDR detectors (`#132`).** `DnsTunnelDetector`
  (T1071.004), `NewlyObservedDomainDetector` (T1568),
  `ConnectionFloodDetector` (T1498), `DataExfilDetector` (T1048) —
  all native `Detector` impls on the new `correlate` primitives,
  threshold+cooldown gated.
- **New `correlate` streaming primitives (`#134`, additive).**
  `EwmaVar` (EWMA mean+variance → N-sigma), `FirstSeen` (TTL
  first-seen set), `CountingBloomFilter` (delete-capable),
  `Cusum` + `PageHinkley` (sequential change-point — NOT
  Mergeable, path-dependent), `DdSketch` + `WindowedQuantiles`
  (relative-error quantiles, Mergeable). Plus `Mergeable` for
  `WelfordStats`.
- **`dns::NameMap` (`#130`, additive).** Zeek/Corelight namecache:
  plural provenance-tagged names per IP, answer-TTL expiry, CNAME
  chain + PTR reverse, global + client-scoped lookup, `drain_new`
  delta feed. Alongside the unchanged `DnsResolutionCache`.
- **Opt-in per-packet `source_idx` (`#121`, small break).**
  `FlowEvent::Packet` / `Event::Packet` become variant-level
  `#[non_exhaustive]` and carry `source_idx: Option<u32>`, gated by
  `FlowTrackerConfig::emit_packet_source_idx` /
  `DriverBuilder::emit_packet_source_idx` (default off). Closes the
  last per-packet phase of tap-merge epic #123.

Test count after the cycle: **1890 passing** (up from 1763 at
0.20.0). Zero clippy warnings under `--all-features --all-targets
-D warnings`, zero rustdoc warnings. New modules:
`src/detector_kind.rs`, `src/detect/registry.rs`,
`src/detect/patterns/{dns_tunnel,nod,conn_flood,data_exfil}.rs`,
`src/correlate/{ewma_var,first_seen,counting_bloom,change_point,ddsketch}.rs`,
`src/dns/name_map.rs`. Migration recipes in
`docs/migration-0.20-to-0.21.md`. Never published as a standalone
crates.io release — its changes shipped inside `0.22.0` on
2026-07-03.

**0.20.0 cycle** (driver/event convergence + 1.0-prep
strong-typing sweep, shipped 2026-06-29).

The largest pre-1.0 breaking batch yet. Three themes:

- **Driver/event convergence (`#84`, closed).** The public
  driver shape settles on ONE typed `driver::Driver<E>`:
  register a session/datagram slot per parser
  (`session_on_ports` / `datagram_on_ports`), drain typed
  messages from a `SlotHandle`, consume flow lifecycle via
  `Event<K>` (`track_into` / `run_pcap`). The per-parser
  `FlowSessionDriver` / `FlowDatagramDriver` engines and the
  `SessionEvent` carrier went crate-private (`#98` / `#99` /
  `#100`); `DeferredDriverBuilder` / `Driver::deferred()` /
  `build_with()` and `PcapFlowSource::sessions()` /
  `datagrams()` were demoted/removed. `Event<K>` gained
  emit-readiness + a shared `SlotDrain` trait across
  `SlotHandle` / `BroadcastSlotHandle` (`#97` / `#101`). The
  low-level `FlowDriver` stays. `netring` migration tracked in
  netring`#107`.
- **1.0-prep strong-typing sweep.**
  - `SessionParser` / `DatagramParser::parser_kind()` now
    return the typed `ParserKind` enum (default
    `Unspecified`, was `""`); the enum grew to 26 built-in
    variants + `Other(&'static str)` and threads through
    `Event::ParserClosed` / `SlotHandle` / `SlotDrain` /
    `BroadcastSlotHandle` (`#109`). Custom string serde keeps
    emitted `parser_kind` JSON + metric labels byte-for-byte
    unchanged.
  - `Event<K>` variants drop the redundant `Flow` prefix to
    match `FlowEvent<K>` (`FlowStarted`→`Started`, …; `#110`).
  - Offline pcap surface: the strongly-typed per-parser
    `*_from_pcap` helpers are KEPT (un-deprecated; `#86` /
    `#108`) as the high-level front door over the generic
    `pcap::session_messages::<P>` / `datagram_messages::<P>`
    building blocks, plus a new unified lifecycle-and-message
    `pcap::Pulse<K, M>` stream via `session_pulses::<P>` /
    `datagram_pulses::<P>` (`#111`).
  - `#[must_use]` on `DriverBuilder` / `RunPcap` /
    `SlotHandle` / `BroadcastSlotHandle`.
  - Fixed a latent `<parser>,pcap` build gap — `quic` / `dns`
    / `kerberos` / `smb` / `ldap` now pull `reassembler` so
    their pcap helpers compile; six new `<parser>,pcap` CI
    rows pin it.
- **Carried pre-1.0 breaks (landed earlier in the cycle):**
  `parse()`→`Result<T, ParseError>` (`#85`), EVE `flow_hash`
  → canonical `community_id` (`#88`), `#[non_exhaustive]`
  project-wide (`#78`), and the `l7` / `full` feature-umbrella
  correction + coarse tiers (`#87`).
- **Canonical `Orientation` on flow events (`#118`, epic
  `#123` — the `#71` tap-merge fix).** `FlowEvent::{Started,
  Packet}` and `Event::{Started, Packet}` now carry a
  deterministic `orientation: Orientation` alongside `side`.
  `FlowSide` is arrival-order-relative (a tap-merge race can
  flip `Initiator` between the two NIC legs); `Orientation`
  (`Forward`/`Reverse`, address-sorted) is stable across that
  race — the axis you want for Community ID ordering / biflow
  keying / cross-sensor dedup. Additive companions:
  `FlowStats::initiator_orientation` +
  `side_for`/`orientation_for`, `FlowEntry::initiator_orientation()`,
  `Orientation::{flipped, as_str, Default=Forward, Hash}`. The
  three direction axes (logical role / canonical orientation /
  physical capture leg) are documented in `docs/concepts.md` →
  "Direction, orientation, and capture leg" (`#119`) with a
  tap-merge recipe in `docs/recipes.md`. Phase 2 (`#120`,
  merge-preserving physical leg) shipped: `FlowStats`
  `source_idx_forward`/`source_idx_reverse` +
  `source_idx_for(orientation)` fold the capture leg
  (`RxMetadata::source_idx`) to a per-`Orientation` binding on a
  merged flow (IPFIX biflow-merge model), with
  `capture_leg_inconsistent` as the tap-miswire IOC. Phase 3
  SYN-based initiator (`#122`) shipped: opt-in
  `FlowTrackerConfig::infer_tcp_initiator` flips a
  `SYN+ACK`-first flow at creation so the SYN sender stays
  `Initiator` (race-robust role axis), recording
  `FlowStats::direction_flipped` (Zeek `^`). Per-packet leg
  fidelity (`#121`) still open.

Test count after the convergence + strong-typing work:
**1763 passing** (up from 1541 mid-0.18). Zero clippy warnings
under `--all-features --all-targets -D warnings`, zero rustdoc
warnings. New `parser_kind.rs` wiring + `src/pcap/pulses.rs` +
`tests/orientation_axis.rs`. Migration recipes in
`docs/migration-0.19-to-0.20.md`. Published to crates.io as
`0.20.0` on 2026-06-29.

**0.18.0 cycle** (Tier-2 protocol completion + ML features +
IPFIX self-sufficiency, in progress).

Drove every named row in the `#14` Tier-2 protocol epic to
completion (except DNP3 — spun off to `#29` for its license +
CVE complexity), closed the asset-inventory composition
layer (`#27`), shipped CICFlowMeter parity in
`flowscope::ml_features` (`#15`), finished `#17`'s
cross-flow memcap enforcement story (`#26`), and added the
binary IPFIX wire encoder (`#28`) so flowscope is
self-sufficient for IPFIX export without depending on
netring.

### Cycle headlines

- **Tier-2 parsers shipped** (gated by their own Cargo
  features, all behind `l7`):
  `arp` / `ndp` / `dhcp` / `lldp` / `cdp` / `ssh` /
  `tcp_fingerprint` / `ntp` / `ssdp` / `tftp` / `mdns` /
  `netbios-ns` / `ftp` / `smtp` / `wireguard` / `modbus` /
  `stun` / `rdp` / `snmp` / `radius`. SNMP and RADIUS use
  the rusticata crates (snmp-parser / radius-parser);
  everything else is hand-rolled.
- **Asset inventory** (`asset` feature) — composition
  layer over the L2/L3/L4 asset-discovery parsers
  (arp/ndp/dhcp/lldp/cdp/ssdp/mdns/netbios-ns). MAC-keyed
  `Asset` records + LRU-bounded `Inventory` + per-parser
  `from_*` adapters. `AssetSourceSet` bitflag tracks
  contributing sources.
- **`flowscope::ml_features`** (`#15` closed) — full
  CICFlowMeter feature vector parity:
  - Totals + throughput + per-direction packet-length
    means + down/up ratio + TCP flag presence + Zeek
    `conn_state` derivation (commit `34c60cb`).
  - Per-packet IAT (Flow / Fwd / Bwd, mean+std+min+max)
    via new `correlate::WelfordStats` + per-direction
    tracker plumbing (commit `99f00ee`).
  - Active/Idle period accounting via
    `FlowTrackerConfig::active_idle_threshold` (default
    1s per CICFlowMeter convention; commit `78ce7a9`).
  - Builder chain:
    `CicFlowFeatures::from_flow_record(&rec).with_iat(&stats)`.
  - nPrint raw-mode is the only piece still open —
    separate scope from running-stats; tracked in `#30`.
- **`#17` close** — TCP overlap-policy enum (First / Last /
  LowerSeq / HigherSeq) + cross-flow `reassembly_memcap`
  + `MemcapPolicy` enum (Ignore / DropFlow / DropPacket /
  PassThrough). Full enforcement in `FlowDriver` per
  `#26`: inline per-segment delta accounting, per-tick
  coalesced `GlobalMemcapHit` anomaly, refund on
  `finalize_ended_flows` + `force_close`. New
  `Reassembler::rexmit_inconsistencies()` for the
  Ptacek-Newsham overlap-evasion IOC.
- **`#16` scoped close** — `flowscope::FlowRecord` IPFIX
  IE-keyed canonical record + emitter unification.
  `write_flow_record(&FlowRecord)` shipped on
  CSV / Zeek / NDJSON / EVE (gated on `ipfix`); the
  user-visible "every emitter is a view over FlowRecord"
  surface lands. Two flowscope-extension fields
  (`retransmits_initiator`/`responder`) added to FlowRecord
  so CSV can reproduce its existing schema through the
  unified path. Internal `IntoFlowRecord` routing (route
  `write_event(Ended)` through `write_flow_record`) is
  the only piece still open — pure mechanical cleanup
  with no user-visible change.
- **`#28` close** — `flowscope::ipfix::wire` binary
  IPFIX Message encoder (RFC 7011/7012). `MessageBuilder`
  + `TemplateRegistry` + `TemplateDefinition` + `FieldSpec`
  + default IPv4/IPv6 templates. Pure-bytes — UDP/SCTP
  I/O explicitly out of scope. Lives in flowscope, NOT
  netring (per the dependency-direction rule in this
  doc). Example: `examples/05-export/ipfix_wire_export.rs`.
- **`#24` close** — JA4X x509 server-certificate
  fingerprint via the rusticata `x509-parser`. Gated
  behind `ja4plus` (FoxIO License 1.1, same as JA4S —
  off by default).
- **Welford running stats** — new
  `flowscope::correlate::WelfordStats` primitive
  (count + mean + sample/population variance + min + max +
  parallel-merge). Used by FlowStats IAT + Active/Idle
  but generally useful.
- **NeighborTable** (`arp` feature) —
  `correlate::NeighborTable<L3, L4>` IP → link-layer
  binding tracker with `ArpTable = NeighborTable<Ipv4Addr,
  MacAddr>` type alias. Asset/spoof-detection helper.
- **Prelude expansion** — all new modules surfaced through
  `flowscope::prelude::*` so consumers don't have to know
  the module path.

Test count after the 0.18 cycle: **1541 passing** (up from
920 at 0.14.0 release). Zero clippy warnings under
`--all-features --all-targets -D warnings`. Zero rustdoc
warnings. The CI feature-matrix builds every leaf feature plus
the `l7` / `full` umbrellas and (since #87) the coarse
`parsers-core` / `parsers-l2l3` / `parsers-tier2` / `ml` /
`export` / `nsm` tiers, each solo.

New modules registered in `src/`:
`arp/`, `ndp/`, `dhcp/`, `lldp/`, `cdp/`, `ssh/`,
`tcp_fingerprint/`, `ntp/`, `ssdp/`, `tftp/`, `mdns/`,
`netbios_ns/`, `ftp/`, `smtp/`, `wireguard/`, `modbus/`,
`stun/`, `rdp/`, `snmp/`, `radius/`, `asset/`,
`ipfix/wire/`, `ml_features/`, `correlate/welford.rs`,
`correlate/neighbor_table.rs`.

### Pre-publish hardening (post Tier-2 ship)

- **Pre-1.0 breaking 1 — `parse()` Option→Result sweep** (#65). The
  five new wire parsers (`dnp3` / `kerberos` / `ldap` / `smb` /
  `quic`) now return `Result<T, ParseError>` with a per-module
  `ParseError` enum exposing the operationally-distinct failure
  mode. `SessionParser` / `DatagramParser` wrappers and the
  `*_from_pcap` helpers are unaffected — only direct callers of
  `parse()` need migration. See
  `docs/migration-0.17-to-0.18.md` for recipes.
- **Pre-1.0 breaking 2 — primitive→enum lifts** (#66). Six fields
  graduated from `bool` / `u32` / `i32` / `i8` to dedicated
  `#[non_exhaustive]` enums modelled on the existing 0.18
  `KerberosEtype` / `QuicVersion` / `DceRpcInterfaceUuid`
  strong-types: `LdapResultCode`, `LdapSearchScope`,
  `KerberosErrorCode`, `NPrintBit`, `DnpLinkDirection`,
  `DnpLinkRole`. Each provides `from_raw(value)` +
  `as_raw()` / `as_bit()` round-trip + `as_str()` stable
  lowercase slug + `Display`.
- **Additive — `Driver::run_pcap()`** (#64). One-call iterator
  over a pcap file on the typed driver. Yields the `Event<K>`
  stream; per-parser typed messages still flow through
  registered `SlotHandle`s. Gated on `pcap`.
- **Additive — per-parser `*_from_pcap` helpers** (#62, #63).
  `flowscope::http::{requests,responses,exchanges}_from_pcap`,
  `flowscope::dns::messages_from_pcap`,
  `flowscope::{kerberos,ldap,ssh}::messages_from_pcap`, and
  `flowscope::pcap::flow_summaries_from_pcap` (returns
  `(FiveTupleKey, FlowStats, EndReason)` tuples).
- **Examples** — 16 new examples across the 0.18 cycle covering
  every new feature surface; see `examples/README.md` for the
  full catalogue. Total examples now > 60.
- Test count after the pre-publish hardening: **1099 passing**
  (1089 lib + 10 integration), zero clippy warnings under
  `--all-features --all-targets -D warnings`, zero rustdoc
  warnings.

**0.14.0 cycle** (netring 0.22 adoption — operations-layer
ergonomics: ICMP error correlation + bandwidth-by-app
primitives + site-custom labels + discoverability,
shipped 2026-06-12).

Plans 160 / 161 / 162 / 163 / 164 / 165 / 167 / 168.
Triggered by the netring 0.22 adoption wishlist (wishlist
file retired after cycle completion; durable record in
`CHANGELOG.md` and `git log`).

Headlines:

- **Plan 161 — `FlowTracker<FiveTuple, S>::lookup_inner`**.
  Specialised impl block (not generic — `IcmpInner` is
  FiveTupleKey-shaped) that joins an ICMP error's embedded
  inner 5-tuple back to a live flow. Plus
  `FiveTupleKey::from_inner_canonical` + `from_inner_literal`
  public constructors (the canonicalisation logic was private
  inside `extract_from_parsed` pre-0.14). The wishlist's
  caveat claiming `FlowTracker` was "mutate-only" was
  verified wrong — `FlowTracker<E, S>` already exposes `get`,
  `snapshot_stats`, `flows`, `iter_active`. No refactor; the
  specialised impl calls them directly.
- **Plan 162 — `DestUnreachableKind`** unified v4/v6 vocabulary
  for the ~17 ICMPv4 + ~8 ICMPv6 Destination Unreachable
  codes. Maps down to 7 operationally-distinguishable
  variants (Host / Port / Network / Protocol /
  AdministrativelyProhibited / FragmentationNeeded / Other).
  Plus `IcmpType::dest_unreachable_kind` + `as_str` (stable
  metric-label slug). Plus the wishlist's plan 166 absorbed:
  `icmp::types` was promoted from private to `pub mod` so
  `flowscope::icmp::types::Icmpv6DestUnreachCode` resolves
  (was a rustdoc + autocomplete bait-and-switch).
  `DestUnreachableKind` re-exported at the crate root and in
  the prelude.
- **Plan 164 — `flowscope::correlate::RollingRate<K, V>`**.
  Per-key per-second rate over a sliding window. Sibling to
  `TimeBucketedCounter` but generic over `V` (bytes/sec,
  request count, latency-sum). Same bucket-reuse zero-alloc
  discipline. Plus the small sealed-style `RateValue` trait
  implemented for `u64` / `u32` / `i64` / `i32` / `f64` /
  `f32` (custom newtype wrappers can implement it for
  semantic distinction). Drops the wishlist's incorrect
  `V: From<u64> + Into<f64>` bound (doesn't hold for `u64`).
- **Plan 165 — `flowscope::well_known::LabelTable`**. Site-
  custom port label extensibility. `new()` inherits the
  built-in ~80-entry table; `standalone()` is whitelist-only.
  `Send + Sync + Clone`. Labels are `&'static str` (use
  `Box::leak` for runtime-loaded strings). Plus
  `FiveTupleKey::protocol_label_with` / `app_label_with`
  companions.
- **Plan 163 — `L4Proto::canonical_name`** lowercase always-
  Some sibling to the existing uppercase `proto_str` (which
  is EVE/Suricata schema-shaped + `Option`). Plus
  `FiveTupleKey::app_label` always-Some companion to
  `protocol_label()` with L4 fallback. Removes the
  `is_tcp: bool` workaround from netring's bandwidth-by-app
  primitive.
- **Plan 160 — `KeyIndexed::drain_expired` + `drain_expired_into`**.
  Returns expired entries as owned `(K, V)` pairs for
  inspection. Sibling to `evict_expired` (which discards).
  Honest allocation contract: ships `Vec<(K, V)>` return +
  reusable-`&mut Vec` variant rather than the wishlist's
  misleading `impl Iterator + '_` (the `lru::LruCache` has
  no `drain()`, so a Vec is unavoidable).
- **Plan 168 — `FlowStats` per-`FlowSide` accessors**.
  `bytes_for` / `pkts_for` / `mean_pkt_size_for` /
  `direction_skew` methods. `direction_skew` is
  `(bytes_init - bytes_resp) / total_bytes`, clamped to
  `[-1, 1]` — positive = initiator-heavy (uploads), negative
  = responder-heavy (downloads).
- **Plan 167 — discoverability sweep**. Pure DX. Prelude
  expanded with `TimeBucketedCounter`, `TimeBucketedSet`,
  `KeyIndexed`, `BurstDetector`, `Ewma`, `TopK`, `RollingRate`,
  `FlowStateMap`, `IcmpType`, `IcmpMessage`, `IcmpInner`,
  `DestUnreachableKind`, `LabelTable` (~13 new exports). New
  `docs/discoverability.md` one-page tour grouped by use
  case ("count things per key over time" / "react to ICMP
  errors" / "emit structured anomalies" / …).

Pre-release polish extension (plans 170-174, scope-extended
after the audit pass per user instruction "do not defer
features if you think they have values"):

- **Plan 170 — `IcmpType::mtu_signal()` + `MtuSignalKind`.**
  Reverses wishlist §13's defer-to-0.15. Unified v4
  `FragmentationNeeded` + v6 `PacketTooBig` signal with
  preserved next-hop MTU (`Option<u16>` for v4 RFC 1191,
  `u32` for v6). Sibling to `DestUnreachableKind`. Re-exported
  at crate root + in prelude.
- **Plan 171 — `RollingRate` completeness.** Adds `sum(k, now)
  -> V` (raw window sum without per-sec divide),
  `top_k(n, now) -> Vec<(K, f64)>` (sorted top-N built-in),
  `clear()` (reset), `len(now)` (in-window key count). `is_empty`
  doc clarified as storage-state vs `len`'s in-window-state.
  `with_capacity` LRU variant deferred — storage shape
  (`VecDeque<(Timestamp, HashMap<K, V>)>`) is per-time-bucket
  not per-key, ~80 LoC of cross-bucket bookkeeping to bound;
  `evict_expired` already bounds memory to "K cardinality per
  window".
- **Plan 172 — `LabelTable` completeness + `override_count`
  removal.** `remove`, `contains`, `len`, `is_empty`. **Only
  breaking change in 0.14**: `override_count` removed in
  favor of idiomatic `len()`. Safe — method shipped on master
  ~hours ago, never on crates.io.
- **Plan 173 — `FlowStats::throughput_bps*` accessors.**
  Lifetime-average overall + per-side throughput with
  safe-divide built in. Replaces the `as f64 /
  duration_secs().max(EPSILON)` pattern at every monitor call
  site. Zero-duration flows return `0.0`, not NaN.
- **Plan 174 — DX sweep.** Three runnable examples under
  `examples/04-observability/`: `bandwidth_by_app.rs`
  (RollingRate + top_k + LabelTable + app_label_with),
  `icmp_explained_drops.rs` (lookup_inner +
  DestUnreachableKind + MtuSignalKind), `direction_skew_anomaly.rs`
  (direction_skew + bytes_for + throughput_bps_for). Plus
  rustdoc "see also" cross-links across sibling primitives
  (`RollingRate` ↔ `TimeBucketedCounter`/`TopK`/`Ewma`;
  `DestUnreachableKind` ↔ `MtuSignalKind`; `app_label` ↔
  `app_label_with`; `evict_expired` ↔ `drain_expired`).

Test count after the polish round: **920 passing** (up from
884 mid-cycle, +36 polish; up from 809 at 0.13.0 release,
+111 cycle-wide). Zero clippy warnings under `--all-features
--all-targets -D warnings`, zero rustdoc warnings. All 13 CI
feature-matrix combinations build clean.

New module registered: `src/correlate/rolling_rate.rs`.

**0.13.0 cycle** (netring 0.21 adoption — Send+Sync driver +
canonical anomaly value + broadcast + DX, shipped 2026-06).

Plans 147 / 149 / 150 / 152 / 153 / 154 / 155 / 156. Triggered
by the netring 0.21 adoption wishlist (wishlist file retired
after cycle release).

Headlines:

- **Plan 156 structural fix (no `unsafe`)** — `Driver<E>` is
  `Send + Sync` unconditionally. The 0.12 CHANGELOG + doc
  comments claimed it was `!Send` because `FlowTracker` held
  `Rc<RefCell>` state, but that was incorrect — direct grep
  found zero `Rc<RefCell>` in tree. The real cause was a
  missing `+ Send` bound on the `Vec<Box<dyn ErasedSlot<_>>>`
  trait object. Fixed structurally: 1-line trait-object bound
  + `P: Send + Sync` audit at builder registration sites.
  Effort dropped from the wishlist's 3-4 days (unsafe newtype
  + Miri audit) to ~3 hours. Stale doc comments cleaned up at
  5 sites (`src/driver/{slot,mod}.rs` + 0.12 retired plans).
- **Plan 147** — `flowscope::OwnedAnomaly` canonical detector-
  output value (six fields + `SmallVec<[..; 4]>` for
  observations + metrics; zero-alloc typical case) +
  `flowscope::DetectorScore` trait (`name()` +
  `into_anomaly(ts)`) implemented on `ScanScore<K>`,
  `BeaconScore<K>`, `DgaScore`. Per-score `into_anomaly`
  inherent methods on each. `EveJsonWriter::write_owned_anomaly`
  + `FlowEventNdjsonWriter::write_owned_anomaly`. New
  `EveOptions::custom_anomaly_type` field (default
  `"applayer"`). Absorbs wishlist 147 + 148 + 151 into one
  coherent ship.
- **Plan 149** — `SlotHandle::drain_n(out, max) -> usize` for
  bounded back-pressure. `swap`/`SlotBuf` micro-optimisation
  variants deferred to 0.14 (SegQueue::pop is ~10ns; downstream
  emit dwarfs it).
- **Plan 150** — `flowscope::driver::BroadcastSlotHandle<M, K>`
  fan-out delivery + `DriverBuilder::session_on_ports_broadcast_each`.
  `Arc<BroadcastInner>` holds `Mutex<Vec<Weak<SegQueue<...>>>>`.
  Each `Clone` is a separate subscriber; push fans out to all
  live queues; dead `Weak`s prune inline. New `M: Clone` bound
  on the broadcast variant (every shipped parser message
  already derives `Clone`).
- **Plan 152** — `PcapFlowSource::with_speed_factor(f64)` for
  time-realistic replay. Tokio-blocking caveat documented.
  `replay_at_wall_clock` from the wishlist dropped — low value.
- **Plan 153** — `flowscope::test_helpers::events` synthetic-
  event constructors (under existing `test-helpers` feature).
  Includes a `::driver` sub-module for the typed `Event<K>`.
- **Plan 154** — `flowscope::correlate::FlowStateMap<T, K>`
  per-flow typed state, layered over `KeyIndexed<K, T>`
  (~80 LoC instead of the originally-proposed 200). Plus
  `KeyIndexed::get_mut` (mutable TTL-aware lookup) and a fix:
  `KeyIndexed::new_unbounded` now uses `lru::LruCache::unbounded()`
  instead of `LruCache::new(usize::MAX)` (the latter caused
  hashbrown capacity overflow — a regression I caught during
  154 implementation, was shipped in 0.12).
- **Plan 155** — `examples/00-getting-started/sharded_capture.rs`
  + `docs/sharded.md` recipe. Built on 156's Send+Sync driver.

Test count after the 0.13 cycle: **809 passing** (up from 772 at
0.12.0 release, +37 new), zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings. New modules registered: `src/anomaly.rs`,
`src/correlate/flow_state_map.rs`, `src/driver/broadcast.rs`.

**0.12.0 cycle** (cross-thread + structured-output + pre-1.0
debt retirement cycle, shipped 2026-06).

- **Base** (shipped first): plans 122 / 123 / 124 / 126 / 127 +
  Phase 7 small wins. Triggered by the netring 0.21 dependency
  wishlist (per-CPU sharded capture; multi-thread tokio runtime
  ask; SIEM EVE-format ingest).
- **Expanded scope** (post-strategic-review audit): plans 130 /
  131 / 132 / 143 / 144 / 146 — pre-1.0 API debt retirement
  (trait shape cleanup, error/features pruning, doc overhaul)
  + named detectors (Beacon / PortScan / DGA) + TLS
  modernisation (ECH) + DFIR / IR sinks (file hashes).

Headlines (base):

Headlines:

- **Plan 122 pre-1.0 break** — `SlotHandle<M, K>` transitions
  from `!Send + !Sync` to `Send + Sync`. Backing storage moved
  from `Rc<RefCell<Vec<SlotMessage>>>` to
  `Arc<crossbeam_queue::SegQueue<SlotMessage>>` (lock-free
  MPMC). New always-on dep `crossbeam-queue = "0.3"`. Generic
  bounds tightened from `M: 'static, K: 'static` to
  `M: Send + 'static, K: Send + 'static` — every shipped
  parser already meets this. Bench gate
  `track_into_5_slots_steady_state` confirmed at **0.000
  allocs/pkt** post-change. **0.13 update (plan 156):** the
  whole `Driver<E>` is now also `Send + Sync` — the 0.12 doc
  claim about `Rc<RefCell>` was incorrect; the actual `!Send`
  source was a missing `+ Send` bound on the slot trait
  object. Fixed structurally with no `unsafe`.
- **Plan 123** — `flowscope::emit::EveJsonWriter` behind
  `emit-eve` feature. Suricata 7.x EVE schema:
  `event_type: "flow"` for `Ended`, `"anomaly"` for
  `FlowAnomaly` / `TrackerAnomaly`, `"stats"` for `Tick`
  (off by default). Every record carries a `flow_hash` field
  (FNV-1a over `(proto, sorted endpoints)`, direction-
  invariant). Schema-compatible with Filebeat's Suricata
  module, Splunk Suricata TA, Tenzir's `read_suricata`, ECS-
  converting pipelines. See `docs/eve-format.md`.
- **Plan 124** — `Driver::<E>::deferred()` returns
  `DeferredDriverBuilder<E>`, a mirror of `DriverBuilder<E>`
  minus `build()` plus `build_with(ext)`. For consumer-built
  monitor chains (netring's `MonitorBuilder`) that need to
  register protocol parsers *before* the extractor instance
  is known. Compile-time guarantee preserved by type-system
  separation — no panicking `build()`.
- **Plan 126** — `flowscope::AnomalyFields` trait. Structured
  field accessors (`src_ip` / `src_port` / `dest_ip` /
  `dest_port` / `proto_str` / `app_proto_str` /
  `anomaly_type` / `anomaly_event`) used by `EveJsonWriter`
  and consumable by any future field-aware emitter. Shipped
  impls on `FiveTupleKey`, `L4Proto`, `AnomalyKind`. All 8
  methods default to `None` — partial impls work for custom
  keys.
- **Plan 127** — `Timestamp::write_iso8601<W: fmt::Write>`
  (alloc-free) + `to_iso8601() -> String`. Pure Howard
  Hinnant `civil_from_days` — no chrono dep required.
  Optional `chrono` feature adds `From<DateTime<Utc>>` for
  `Timestamp` and `TryFrom<Timestamp>` for `DateTime<Utc>`
  with `ChronoOutOfRange` error.
- **Phase 7 small wins** —
  `TimeBucketedCounter::new_unbounded(window, bucket)`,
  `TimeBucketedSet::new_unbounded(window, bucket)`,
  `KeyIndexed::new_unbounded(ttl)`. 3 trivial delegates,
  retire netring's duplicated `correlate` module.

Headlines (expanded):

- **Plan 130** — pre-1.0 trait shape cleanup. Split
  `AnomalyFields` into `KeyFields` (5-tuple accessors) +
  `AnomalyFields` (anomaly classification). Emit writers
  (CSV / NDJSON / Zeek / EVE) become generic over
  `K: KeyFields`. `Event::tcp()` cross-variant accessor.
  `From<Timestamp> for chrono::DateTime<Utc>` (infallible —
  `ChronoOutOfRange` deleted). `DriverBuilder` Send-bound
  parity with `DeferredDriverBuilder`.
  `TopK::new_unbounded()` + `BurstDetector::new_unbounded()`
  complete the `correlate::*::new_unbounded` family.
- **Plan 131** — `Error::Module::Pipeline` removed (was dead
  code since 0.11). Five new variants added (Driver / Emit /
  Detect / Aggregate / Correlate). `ja3` + `ja4` features
  collapsed into `tls-fingerprints`. `tracing-messages`
  deleted — per-message emission is always-on under
  `tracing`; filter at runtime via `EnvFilter`.
- **Plan 132** — doc overhaul. Migration recipes for plans
  130 / 131 appended to `docs/migration-0.11-to-0.12.md`
  §7-§12.
- **Plan 143** — `flowscope::detect::patterns` module:
  `BeaconDetector<K>` (RITA-style composite CV score),
  `PortScanDetector<K>` (Threshold Random Walk, Jung 2004),
  `DgaScorer` (bigram log-likelihood with embedded English
  baseline corpus compiled at first use). Always-on; no
  Cargo feature gate. Examples:
  `examples/03-detection/{c2_beacon_finder,dga_finder}.rs`.
- **Plan 144** — TLS ECH (Encrypted Client Hello) signal
  extraction. `TlsClientHello` gains `ech_present` /
  `ech_config_id` / `sni_is_outer`; `TlsServerHello` gains
  `ech_retry_configs`; `TlsHandshake` gains `EchOutcome`
  (NotOffered / Accepted / Rejected / Unknown) +
  `ech_config_id`. Required `TlsClientHello` /
  `TlsServerHello` to become `#[non_exhaustive]` + derive
  `Default`; `TlsVersion` derives `Default` with `Tls1_3`
  as the `#[default]` variant. Reference:
  `draft-ietf-tls-esni-22`.
- **Plan 146** — `flowscope::detect::file` module behind the
  new `file-hash` Cargo feature: `Sha256Sink` + `Md5Sink`
  streaming hash sinks for reassembled payload windows,
  plus a 16-format `FileType` magic-byte classifier
  (`Pe` / `Elf` / `MachO` / `Pdf` / `Png` / `Jpeg` / `Gif` /
  `Webp` / `Zip` / `Gzip` / `Bzip2` / `Xz` / `Mp4` / `Mp3` /
  `Sqlite3` / `Unknown`). With `tls-fingerprints` enabled,
  adds zero new transitive deps.

Test count after the 0.12 cycle: 772 passing, zero clippy
warnings under `--all-features --all-targets -D warnings`,
zero rustdoc warnings. EVE example
(`examples/05-export/eve_writer.rs`) verified end-to-end
against `tests/data/mixed_short.pcap`.

CI feature matrix changes: base added `chrono` + `emit-eve`;
expanded collapsed `ja3` + `ja4` into a single `tls-fingerprints`
entry and deleted `tracing-messages`
(no CI matrix entry). Cross-`SlotHandle` Send+Sync compile
assertions in `tests/driver_send.rs` (via `static_assertions`).
Migration recipes: `docs/migration-0.11-to-0.12.md`.

**0.11.0 cycle** (zero-allocation cycle, shipped 2026-06).
Plans 118 / 119 / 120 / 121. Triggered by the netring 0.19
dependency audit; collapses the closed-`M` sum-type `Driver<E,
M>` shape into a typed-slot-drain shape and deletes every 0.9-
era legacy driver type.

Headlines:

- **Plan 121 architectural keystone** — `flowscope::driver`
  becomes the typed-slot shape: `Driver<E>` emits flow-lifecycle
  `Event<K>` only; per-parser typed messages flow through
  `SlotHandle<P::Message, E::Key>` returned by the builder at
  registration time. No closed-`M` sum type, no lift closures,
  zero per-message Box. `flowscope::driver_unified` was renamed
  to `flowscope::driver` at the crate root; the old
  `flowscope::driver` (`FlowDriver`) moved to
  `flowscope::flow_driver`. Public driver-shaped types: 6
  (down from 14 in 0.9).
- **Plan 119** — `Driver::track_into(view, &mut Vec<Event>)` +
  parser API break: `SessionParser` and `DatagramParser` take
  `&mut Vec<Self::Message>` (same idiom as `httparse::Request::parse`).
  Eliminates the per-packet `Vec::new()` at every dispatch
  layer. Bench gate row `track_into` with **5 HTTP slots**:
  **0.000 allocs/packet** in steady state.
- **Plan 120** — HTTP / DNS / TLS payload-type Bytes audit.
  HTTP/1.1 GET parse: **28 → 7 allocs** (-75%) by sharing one
  Arc-backed Bytes for the whole header region and slicing
  zero-copy.
- **Plan 118 §4 small wins** — `Event::FlowPacket::frame`
  field deleted (was `view.frame.to_vec()` clone per packet =
  1.5 GB/sec at 1 Mpps). `parser_kinds::TLS_HANDSHAKE`
  constant added.

Public surface after the cycle: `Driver<E>`, `DriverBuilder<E>`,
`Event<K>`, `SlotHandle<M, K>`, `SlotMessage<M, K>` for the
typed driver; `FlowDriver`, `FlowSessionDriver`,
`FlowDatagramDriver` kept as raw sync primitives.

The typed `Driver<E>` is `Send + Sync` since 0.13 (plan 156 —
strictly structural; no `unsafe`). `SlotHandle<M, K>` is
`Send + Sync` since 0.12. Move the driver to a tokio task on
a worker core, share a handle via `Arc` with multiple drainers,
the driver runs on the capture thread, or share via `Arc` with
multiple drainers (competitive-consumer semantics — each clone
pops from the same `SegQueue`).

**0.10.0 cycle** (shipped 2026-06). Plan-of-record in
`plans/INDEX.md`. Triggered by the 0.9 examples-writing
postmortem (plan 100). Shipped:

- **Plan 110 sub-B** — quick-win helper sweep. New methods on
  `Timestamp` (`to_unix_f64` / `from_unix_f64` / `relative_to`
  / `from_system_time`), `FlowStats` (rollup helpers),
  `EndReason::as_str()`, `LayerKind::is_l2 / l3 / l4 / tunnel`,
  `Layer<'_>::Display`, `LayerStack::depth / iter_kinds`,
  `KeyIndexed::peek`.
- **Plan 102 sub-D** — `flowscope::well_known` curated
  `(L4Proto, port) → label` table (~70 entries) + accessors on
  `FiveTupleKey` (`well_known_port` / `protocol_label`).
- **Plan 101** — `flowscope::emit` structured event sinks:
  `FlowEventCsvWriter` (RFC-4180 quoting), `ZeekConnLogWriter`
  (tab-separated, `#fields`/`#types`/`#close` headers, UID
  generation) behind `emit`; `FlowEventNdjsonWriter` behind
  `emit-ndjson` (pulls `serde_json`). Plus
  `EndReason::as_zeek_state()`.
- **Plan 102 sub-C** — `flowscope::detect` (Shannon entropy +
  5 light primitives + `NgramDist`).
- **Plan 102 sub-B** — `flowscope::aggregate` (Histogram +
  Percentile / t-digest) behind `aggregate` feature.
- **Plan 110 sub-A** — rustdoc landing pages on
  `flowscope::http` / `tls` / `dns` / `icmp` with curated
  convenience-accessor tables. Plus 9 new HTTP accessors
  (`HttpRequest::referer/accept/content_type/content_length`;
  `HttpResponse::status_class/is_success/is_redirect/
  is_client_error/is_server_error`).
- **Plan 113 sub-A** — `flowscope::detect::signatures` (10
  pure-function magic-byte recognizers + `registry()`).
- **Plan 102 sub-A** — `correlate` extensions (`TimeBucketedSet`
  / `BurstDetector` / `BurstHit` / `TopK` / `Ewma`).
- **Plan 106** — parser ergonomics (`BufferedFrameDrain` +
  `AccumulatingSessionParser` + `PerDatagramParser` +
  `FrameDrainError`).
- **Plan 107** — exchange aggregators (`HttpExchangeParser` +
  `HttpExchange` + `HttpOutcome`; `DnsExchangeParser` +
  `DnsExchange` + `DnsOutcome`).
- **Plan 116 PR 1–4 (partial)** — unified
  `flowscope::driver_unified::{Driver, Event, DriverBuilder,
  Pipeline, PipelineBuilder}`. One `Driver<E, M>` with
  session + datagram + heuristic routing under one
  `Event<K, M>` stream. Includes plan 113 sub-B (heuristic
  routing — `session_heuristic` / `datagram_heuristic` with
  per-flow Probing/Pinned/GaveUp state, `PROBE_BUFFER_CAP`
  64 B, `DEFAULT_PROBE_PACKETS` 4) and a
  `examples/unified_driver_demo.rs` showcase. The 0.9-era
  `FlowSessionDriver` / `FlowDatagramDriver` /
  `FlowMultiSessionDriver` / `Pipeline` (legacy) types stay
  shipped in 0.10 for migration; PR 5 (deletion sweep) is
  deferred to the next major release.

The 0.10 cycle's user-priority plan (116) is substantially
complete. Plan 113 is fully complete (sub-A + sub-B both
landed). Plans 101, 102, 106, 107, 110 are fully complete.

Test count after 0.10 work-in-progress: ~430 passing, zero
clippy warnings under `--all-features --all-targets -D
warnings`, zero rustdoc warnings.

**0.9.0 cycle** (in progress at 2026-06). Plan-of-record in
`plans/INDEX.md`. Shipped so far:

- **Plan 96** — unified `flowscope::Error` (5 module enums
  collapsed; source-chain preserved; `(module, code)` matching).
- **Plan 94 Tier 3** — public `flowscope::layers` per-packet
  view (zero-copy, Layers/Layer/LayerKind + Eth/VLAN/MPLS/
  IPv4/IPv6/ARP/TCP/UDP/ICMPv4/ICMPv6 slices, dynamic walk +
  direct accessors, `PacketView::layers()`; tunnel walking for
  VXLAN/GTP-U/GRE/IP-in-IP via `Layers::has_tunnel()` /
  `Layers::truncated()`).
- **Plan 94 Tier 1** — `flowscope::Pipeline` high-level entry
  point + `flowscope::prelude` (one-import API) + `.reset()`
  + `.run_iter()` over `OwnedPacketView`.
- **Plan 75** — `FlowTracker::with_auto_sweep(interval)` for
  live/offline parity.
- **Plan 99** — MSRV 1.85 → 1.88 + let-chain idiom sweep.
- **Plan 81** — `flowscope::correlate` module
  (`TimeBucketedCounter`, `KeyIndexed`, `SequencePattern`).
- **Plan 97** — TLS modernization: `ja4` feature (FoxIO v1
  client fingerprint) + `TlsHandshakeParser` aggregator
  (one `TlsHandshake` event per handshake with
  SNI / ALPN / JA3 / JA4 / version / cipher /
  `resumption_attempted` / `HandshakeOutcome`).
- **Plan 92** — `FlowMultiSessionDriver<E, M>` composite
  driver (port-set + broadcast routing; user-supplied sum-type
  lifting).
- **Plan 74** — `SegmentBufferReassembler` with OOO hole-fill
  (BTreeMap-backed pending queue; deadline expiry; strict
  RFC 5722 overlap).

- **Plan 94 Tier 2** — driver builders: additive
  `Driver::builder(extractor)` chainable entry on
  `FlowSessionDriver` + `FlowDatagramDriver`. Constructor
  deletion deferred to a follow-up cycle.
- **Plan 94 Tier 3 fast path** — `LayerParser` + `LayerStack`
  zero-allocation parsing (gopacket `DecodingLayerParser`
  shape) with caller-owned scratch + `.only(kinds)` mask.

The 0.9 cycle is complete; all eight implementation plans
shipped. The plan-of-record umbrella (93) lingers as the
durable audit; the implementation plans (74, 75, 81, 92, 94,
96, 97, 99) are retired per project convention.

Test counts: 508 passing, zero clippy warnings under
`--all-features --all-targets -D warnings`, zero rustdoc
warnings.

(0.5.0 historical: TCP rich diagnostics, periodic ticks,
parser identity. 0.8.0 historical: serde wire-format lock,
ICMP correlation, programmatic flow termination, snapshot
iterator, multi-protocol monitor recipe. See CHANGELOG.md.)

### Modules

```
src/
├── lib.rs                       # re-exports + feature wiring
├── error.rs                     # flowscope::Error / ErrorKind / Module / ErrorCode (plan 96, 0.9.0)
├── prelude.rs                   # flowscope::prelude::* (plan 94, 0.9.0)
├── anomaly_fields.rs            # AnomalyFields trait (plan 126, 0.12.0)
├── anomaly.rs                   # OwnedAnomaly value + DetectorScore trait (plan 147, 0.13.0)
├── timestamp.rs                 # Timestamp + write_iso8601 + to_iso8601 + chrono interop (plan 127, 0.12.0)
├── view.rs                      # PacketView<'a> #[non_exhaustive] = (frame, ts, rx_metadata) + .layers() + .with_rx_metadata (issue #2, 0.17)
├── rx_metadata.rs               # RxMetadata + RxHash + RssHashType + VlanTag + VlanProto + ChecksumStatus (issue #2, 0.17)
├── mac_addr.rs                  # MacAddr #[repr(transparent)] newtype + Display + FromStr + predicates (issue #1, 0.17)
├── extractor.rs                 # FlowExtractor trait + Extracted/Orientation + AnomalyFields for L4Proto (0.12.0)
├── layers/                      # Per-packet layered view (plan 94 Tier 3, 0.9.0)
│   ├── mod.rs                   # Layers + Layer + accessors + tunnel walk + dynamic walk
│   ├── kind.rs                  # LayerKind enum + .layer_number()
│   ├── eth.rs                   # EthernetSlice + VlanSlice + MplsSlice
│   ├── ip.rs                    # Ipv4Slice + Ipv6Slice + ArpSlice
│   ├── transport.rs             # TcpSlice + UdpSlice + Icmpv4Slice + Icmpv6Slice + TcpFlagsView + TcpOption
│   └── tunnel.rs                # GreSlice + VxlanSlice + GtpUSlice
├── correlate/                   # flowscope::correlate (plan 81, 0.9.0; extended in plan 102 sub-A, 0.10)
│   ├── mod.rs                   # public re-exports
│   ├── bucketed.rs              # TimeBucketedCounter<K>
│   ├── burst.rs                 # BurstDetector<K, E> + BurstHit<K>             (plan 102 sub-A, 0.10)
│   ├── ewma.rs                  # Ewma<K>                                       (plan 102 sub-A, 0.10)
│   ├── flow_state_map.rs        # FlowStateMap<T, K> per-flow typed state       (plan 154, 0.13.0)
│   ├── indexed.rs               # KeyIndexed<K, V>  (.peek 0.10; .get_mut + new_unbounded fix plan 154, 0.13.0; .drain_expired + .drain_expired_into plan 160, 0.14.0)
│   ├── neighbor_table.rs        # NeighborTable<L3, L4> + NeighborBinding + NeighborEvent + ArpTable alias (issue #1, 0.17)
│   ├── rolling_rate.rs          # RollingRate<K, V> + RateValue trait — per-key per-second rate (plan 164, 0.14.0)
│   ├── sequence.rs              # SequencePattern + KeylessSequencePattern
│   ├── set.rs                   # TimeBucketedSet<K, V>                         (plan 102 sub-A, 0.10)
│   ├── topk.rs                  # TopK<K> (Misra-Gries)                         (plan 102 sub-A, 0.10)
│   ├── hyperloglog.rs           # HyperLogLog<K> cardinality sketch
│   ├── mergeable.rs             # Mergeable trait
│   └── welford.rs               # WelfordStats — running stats (count/mean/var/min/max) (issue #15, 0.18)
├── classify.rs                  # classify_first_bytes → WireProtocol — protocol from the first bytes (#165, 0.23)
├── http2/                       # `http2` feature — HTTP/2 + HPACK + gRPC (#170/#171, 0.23)
│   ├── session.rs               # Http2Session — SessionParser adapter for the typed Driver (#196, 0.23)
│   ├── error.rs                 # Http2Error
│   ├── frame.rs                 # frame header + padding/priority/promised-id stripping + SETTINGS
│   ├── grpc.rs                  # GrpcCall + GrpcStatus + is_grpc_content_type
│   ├── hpack.rs                 # RFC 7541 decoder: static + dynamic table, integer/string codings
│   ├── huffman.rs               # RFC 7541 Appendix B canonical Huffman table
│   └── stream.rs                # Http2Parser + Http2Event + StreamHead + Http2Config
├── detect/                      # flowscope::detect (plan 102 sub-C, 0.10)
│   ├── mod.rs                   # shannon_entropy + 5 light primitives + NgramDist
│   ├── signatures.rs            # 10 magic-byte recognizers + registry          (plan 113 sub-A, 0.10)
│   ├── patterns/                # Named detectors (plan 143, 0.12.0; always-on)
│   │   ├── mod.rs               # public re-exports
│   │   ├── beacon.rs            # BeaconDetector<K> — RITA CV composite score
│   │   ├── portscan.rs          # PortScanDetector<K> — TRW (Jung 2004); capacity-bounded since #187, 0.23
│   │   └── dga.rs               # DgaScorer — bigram log-likelihood + embedded baseline
│   ├── fingerprint.rs           # FingerprintBuilder + FlowFingerprint (issue #4, 0.17; `fingerprint` feature)
│   └── file/                    # File hash sinks (plan 146, 0.12.0; `file-hash` feature)
│       ├── mod.rs               # FileHashSink trait + re-exports
│       ├── types.rs             # FileHashEvent + FileType + magic-byte classify
│       ├── sha256.rs            # Sha256Sink (sha2 crate)
│       └── md5.rs               # Md5Sink (md-5 crate)
├── aggregate/                   # flowscope::aggregate (plan 102 sub-B, 0.10; `aggregate` feature)
│   ├── mod.rs                   # public re-exports
│   ├── histogram.rs             # Histogram + HistogramError
│   └── percentile.rs            # Percentile (wraps `tdigest` crate)
├── emit/                        # flowscope::emit (plan 101, 0.10; `emit` / `emit-ndjson` / `emit-eve` features)
│   ├── mod.rs                   # public re-exports
│   ├── csv.rs                   # FlowEventCsvWriter + CsvOptions
│   ├── eve.rs                   # EveJsonWriter + EveOptions + flow_hash (plan 123, 0.12.0; .write_owned_anomaly + .custom_anomaly_type plan 147, 0.13.0)
│   ├── ndjson.rs                # FlowEventNdjsonWriter + NdjsonOptions (gated on `emit-ndjson`; .write_owned_anomaly plan 147, 0.13.0)
│   └── zeek.rs                  # ZeekConnLogWriter + ZeekOptions
├── well_known/                  # flowscope::well_known (plan 102 sub-D, 0.10)
│   └── mod.rs                   # protocol_label / entries / curated table + LabelTable site-custom overrides (plan 165, 0.14.0)
├── layers/fast.rs               # LayerParser + LayerStack zero-alloc (plan 94 Tier 3 fast path, 0.9.0)
├── driver/                      # flowscope::driver — typed Driver<E> + SlotHandle<M, K> (plan 121, 0.11.0; Send+Sync since plan 156, 0.13.0)
│   ├── mod.rs                   # public re-exports (Driver / DriverBuilder / Event / SlotHandle / SlotMessage / SlotDrain / BroadcastSlotHandle). DeferredDriverBuilder removed in #98 (0.20)
│   ├── broadcast.rs             # BroadcastSlotHandle<M, K> + BroadcastInner — fan-out delivery (plan 150, 0.13.0; impls SlotDrain #101)
│   ├── slot.rs                  # SlotHandle<M, K> + SlotMessage<M, K> + SlotDrain trait — Arc<crossbeam_queue::SegQueue> backing (Send + Sync, plan 122, 0.12.0; .drain_n added plan 149, 0.13.0; SlotDrain added #101, 0.20)
│   ├── typed.rs                 # Driver<E> + DriverBuilder<E> + Event<K> + map_flow_event + run_pcap (plan 124, 0.12.0; .session_on_ports_broadcast_each added plan 150, 0.13.0; DeferredDriverBuilder removed #98, 0.20)
│   ├── typed_slot.rs            # TypedConcreteSlot + TypedConcreteDatagramSlot + TypedBroadcastSlot (plan 150 broadcast variant, 0.13.0)
│   └── typed_slot_heuristic.rs  # TypedHeuristicSessionSlot + TypedHeuristicDatagramSlot (FlowDetection FSM)
├── segment_reassembler.rs       # SegmentBufferReassembler OOO hole-fill (plan 74, 0.9.0)
├── extract/                     # built-in extractors (extractors feature)
│   ├── parse.rs                 # internal etherparse wrappers
│   ├── five_tuple.rs            # FiveTuple { proto, a, b }
│   ├── ip_pair.rs               # IpPair (proto-agnostic, useful for ICMP)
│   ├── mac_pair.rs              # MacPair (L2 only; MacAddr-typed since issue #1, 0.17)
│   ├── encap_vlan.rs            # StripVlan<E>
│   ├── encap_mpls.rs            # StripMpls<E>
│   ├── encap_vxlan.rs           # InnerVxlan<E>
│   ├── encap_gtp.rs             # InnerGtpU<E>
│   ├── encap_gre.rs             # InnerGre<E>            (plan 50.1)
│   ├── auto_detect.rs           # AutoDetectEncap<E>     (plan 50.3)
│   ├── flow_label.rs            # FlowLabel<E>           (plan 50.2)
│   └── tagged.rs                # Tagged<E, T> + TaggedKey + Tagger trait — per-packet tag prefix (issue #5, 0.17)
├── event.rs                     # FlowEvent / FlowSide / EndReason / FlowStats
│                                # AnomalyKind / OverflowPolicy   (0.2.0)
│                                # FlowStats::{bytes_for,pkts_for,mean_pkt_size_for,direction_skew} (plan 168, 0.14.0)
│                                # FlowStats::throughput_bps{,_pps,_for,_pps_for} safe-divide accessors (plan 173, 0.14.0)
│                                # EventMask bitflags — tracker load-shedding (issue #79, 0.20.0)
│                                # FlowEvent::{Started,Packet} carry orientation; FlowStats::initiator_orientation + side_for/orientation_for (issue #118, 0.20.0)
│                                # FlowStats::source_idx_{forward,reverse} + source_idx_for + capture_leg_inconsistent — per-direction capture leg (issue #120, 0.20.0)
│                                # FlowStats::direction_flipped + FlowTrackerConfig::infer_tcp_initiator — SYN-based initiator inference (issue #122, 0.20.0)
├── history.rs                   # HistoryString (Zeek-style ShAdaFf)
├── tcp_state.rs                 # TCP state machine (transitions + idle policy)
├── tracker.rs                   # FlowTracker<E, S>     (manual_tick alias added in 50.4)
│                                # hot-cache fast path   (plan 41, 0.2.0)
│                                # snapshot_stats / snapshot_history / forget (0.2.0)
│                                # specialised impl<S> FlowTracker<FiveTuple, S>: lookup_inner + stats_for_inner (plan 161, 0.14.0)
├── reassembler.rs               # Reassembler trait + BufferedReassembler
│                                # buffer cap + OverflowPolicy (plan 42 §1, 0.2.0)
├── driver.rs                    # FlowDriver<E, F, S = ()> (sync wrapper)
│                                # diagnostics patch + BufferOverflow synthesis +
│                                # with_emit_anomalies      (plan 42 §2/§3, 0.2.0)
├── session.rs                   # SessionParser / DatagramParser traits + factories + SessionEvent (crate-private engine carrier since #100, 0.20)
│                                # + AccumulatingSessionParser / PerDatagramParser /
│                                #   BufferedFrameDrain / FrameDrainError (plan 106, 0.10)
├── session_driver.rs            # FlowSessionDriver — crate-PRIVATE session-dispatch engine
│                                # (was public through 0.19; demoted in #99, 0.20). Used by
│                                # the typed driver slots + pcap source. Wraps FlowDriver.
├── datagram_driver.rs           # FlowDatagramDriver — crate-PRIVATE UDP engine (private since #99, 0.20)
├── dedup.rs                     # Dedup — content-hash + window dedup (plan 49, 0.3.0)
├── obs.rs                       # metrics / tracing hooks (plan 40, 0.2.0)
│                                # (former tracing-messages sub-feature removed in 0.12, plan 131 — always-on under `tracing`)
├── http/                        # `http` feature
│   ├── access.rs                # HttpAccessLog + HttpAccessRecord + HttpAccessOutcome (#168, 0.23)
│   ├── engine.rs                # THE streaming state machine — one engine, two front-ends (#160, 0.23; was parser.rs)
│   ├── exchange.rs              # HttpExchangeParser + HttpExchange + HttpOutcome (plan 107, 0.10)
│   ├── poison.rs                # HttpPoison typed refusal reasons (#163, 0.23)
│   ├── proxy.rs                 # HttpProxyParser + HttpEvent + HttpProxyConfig + HttpProxySession (#161/#164, 0.23)
│   ├── session.rs               # HttpParser — the aggregating telemetry front-end over engine.rs
│   └── types.rs                 # HttpRequest / HttpResponse / HttpConfig / RequestHead / ResponseHead / BodyFraming / SmugglingPolicy / Authority
│                                # + 9 new accessors                              (plan 110 sub-A, 0.10)
├── tls/                         # `tls` feature
│   ├── parser.rs                # internal step() machine (tls-parser-based)
│   ├── session.rs               # TlsParser (SessionParser, the only public shape since 0.9.0)
│   ├── handshake.rs             # TlsHandshakeParser aggregator (plan 97, 0.9.0); adds `certificate_chain` + `ja4x` field (issue #24, 0.18)
│   ├── fingerprint.rs           # JA3 (gated by `tls-fingerprints` feature; was `ja3` pre-0.12)
│   ├── ja4.rs                   # JA4 (gated by `tls-fingerprints` feature; was `ja4`; plan 97, 0.9.0)
│   ├── ja4s.rs                  # JA4S server-fingerprint (gated by `ja4plus`, FoxIO License 1.1; 0.15)
│   ├── ja4x.rs                  # JA4X x509 cert fingerprint (gated by `ja4plus`; issue #24, 0.18)
│   └── types.rs                 # TlsClientHello / TlsServerHello / TlsAlert / TlsConfig
├── dns/                         # `dns` feature
│   ├── parser.rs                # parse_message / parse_message_at (simple-dns-based)
│   ├── correlator.rs            # Correlator<S> — query/response matching
│   ├── datagram.rs              # DnsUdpParser (DatagramParser; correlating, plan 37)
│   ├── exchange.rs              # DnsExchangeParser + DnsExchange + DnsOutcome   (plan 107, 0.10)
│   ├── session.rs               # DnsTcpParser (SessionParser, RFC 1035 §4.2.2 framing)
│   └── types.rs                 # DnsQuery / DnsResponse / DnsRdata / DnsConfig
├── icmp/                        # `icmp` feature (`mod types` promoted to `pub mod` in plan 162, 0.14.0)
│   ├── parser.rs                # parse_v4 / parse_v6 stateless decoders
│   ├── datagram.rs              # IcmpParser (DatagramParser, plan 76, 0.7.0)
│   └── types.rs                 # IcmpMessage / IcmpType variants + DestUnreachableKind + IcmpType::dest_unreachable_kind (plan 162, 0.14.0) + MtuSignalKind + IcmpType::mtu_signal (plan 170, 0.14.0)
├── arp/                         # `arp` feature (issue #1, 0.17)
│   ├── mod.rs                   # public re-exports + module doc
│   ├── parser.rs                # arp::parse(payload) + arp::parse_frame(frame) + ArpParser marker
│   └── types.rs                 # ArpMessage + ArpOp + is_gratuitous + is_likely_spoof
├── ndp/                         # `ndp` feature (issue #6, 0.18)
├── dhcp/                        # `dhcp` feature — RFC 2132 + Fingerbank fingerprint (issue #11, 0.18)
├── lldp/                        # `lldp` feature — L2 asset discovery (issue #23, 0.18)
├── cdp/                         # `cdp` feature — Cisco Discovery Protocol (issue #25, 0.18)
├── ssh/                         # `ssh` feature — banner + KEXINIT + HASSH (issue #7, 0.18)
├── tcp_fingerprint/             # `tcp_fingerprint` feature — p0f-style passive OS (issue #9, 0.18)
├── ntp/                         # `ntp` feature — UDP/123 monlist amplification detection (issue #14, 0.18)
├── ssdp/                        # `ssdp` feature — UPnP / IoT asset discovery (issue #14, 0.18)
├── tftp/                        # `tftp` feature — device-config theft visibility (issue #14, 0.18)
├── mdns/                        # `mdns` feature — RFC 6762 + RFC 6763 DNS-SD service walker (issue #14, 0.18)
│   ├── mod.rs                   # MDNS_PORT + MDNS_MULTICAST_V4/V6 + looks_like_mdns
│   ├── service.rs               # ServiceRecord + extract_services (PTR walker)
│   └── datagram.rs              # MdnsParser (thin DnsUdpParser wrapper)
├── netbios_ns/                  # `netbios-ns` feature — NBNS RFC 1002 §4.2 (issue #14, 0.18)
│   ├── mod.rs                   # NBNS_PORT + types
│   ├── name.rs                  # RFC 1001 §14.1 first-level encoding
│   └── parser.rs                # parse(payload) → NbnsMessage with opcode/queried_name/answer_addresses
├── ftp/                         # `ftp` feature — TCP/21 USER/PASS aggregation + AUTH-TLS upgrade (issue #14, 0.18)
├── smtp/                        # `smtp` feature — TCP/25+587 MAIL FROM/RCPT TO + AUTH PLAIN/LOGIN base64 decode + STARTTLS (issue #14, 0.18)
├── wireguard/                   # `wireguard` feature — passive WG handshake detection (issue #14, 0.18)
├── modbus/                      # `modbus` feature — TCP/502 ICS visibility (issue #14, 0.18)
├── stun/                        # `stun` feature — RFC 5389 WebRTC peer / NAT discovery (issue #14, 0.18)
├── rdp/                         # `rdp` feature — X.224 negotiation metadata-only (issue #14, 0.18)
├── snmp/                        # `snmp` feature — v1/v2c via rusticata snmp-parser (issue #14, 0.18)
├── radius/                      # `radius` feature — RFC 2865/2866 via rusticata radius-parser (issue #14, 0.18)
├── asset/                       # `asset` feature — Asset + Inventory composition (issue #27, 0.18)
│   ├── core.rs                  # Asset + AssetCapabilities + AssetSourceSet + per-parser from_* adapters
│   └── inventory.rs             # LRU-bounded Inventory<MacAddr, Asset>
├── analysis/                    # `analysis` feature — risk/IOC/L7 → enriched flow records (issue #83, 0.19+)
│   ├── summary.rs               # L7Summary curated facts + observe_tls/http/dns (gated per parser)
│   ├── analyzed_flow.rs         # AnalyzedFlow<K> = key + FlowStats + L7Summary + FlowRisk + IocMatch hits
│   └── analyzer.rs              # FlowAnalyzer<K> bounded accumulator (observe_* / finalize / snapshot / evict)
├── ipfix/                       # `ipfix` feature (scoped piece of #16, 0.18)
│   ├── registry.rs              # IANA IE table + lookup_by_id/name
│   ├── types.rs                 # FlowEndReason + encode_tcp_control_bits
│   ├── record.rs                # FlowRecord IE-keyed canonical flow record + from_parts
│   └── wire/                    # `ipfix-export` feature — RFC 7011 binary encoder (issue #28, 0.18)
│       ├── constants.rs         # IPFIX_VERSION + MESSAGE_HEADER_LEN + Set IDs + FIELD_LENGTH_VARIABLE
│       ├── templates.rs         # TemplateDefinition + FieldSpec + TemplateRegistry + default IPv4/IPv6 templates
│       └── builder.rs           # MessageBuilder + EncodeError
├── ml_features/                 # `ml-features` feature — CICFlowMeter feature vector (issue #15, 0.18)
│   ├── conn_state.rs            # TcpFlagCounts + count_tcp_flags
│   └── features.rs              # CicFlowFeatures + from_flow_record + with_iat
├── nprint/                      # `ml-features-nprint` feature — per-packet ternary header-bit matrix (issue #30, 0.18)
│   ├── matrix.rs                # NPrintMatrix + NPrintConfig + push_view
│   └── row.rs                   # NPrintRow + bits_per_row + encode_from_layers (Eth/IPv4/TCP/UDP)
├── dnp3/                        # `dnp3` feature — DNP3 OT/SCADA metadata (issue #29, 0.18)
│   ├── parser.rs                # parse(&[u8]) — link header + first-block app header + IIN bits
│   ├── session.rs               # DnpParser SessionParser over TCP/20000
│   └── types.rs                 # DnpMessage / DnpLinkFunctionKind / DnpApplication / DnpAppFunctionKind / DnpInternalIndications
├── kerberos/                    # `kerberos` feature — Kerberos AS/TGS/KRB-ERROR (issue #13, 0.18)
│   ├── parser.rs                # First-byte dispatch on APP-tag → rusticata kerberos-parser
│   ├── datagram.rs              # KerberosUdpParser DatagramParser (UDP/88)
│   ├── session.rs               # KerberosTcpParser SessionParser (RFC 4120 §7.2.2 length-prefix)
│   └── types.rs                 # KerberosMessage / KerberosMessageKind (+ kerberoast_suspect)
├── ldap/                        # `ldap` feature — LDAP RFC 4511 (issue #13, 0.18)
│   ├── parser.rs                # parse_ldap_message wrap + from_parsed
│   ├── session.rs               # LdapParser SessionParser (TCP/389)
│   └── types.rs                 # LdapMessage / LdapOperation / LdapAuthKind (+ search_attributes_spn_query)
├── smb/                         # `smb` feature — SMB2/3 lateral-movement (issue #12, 0.18; M1+M2+M3)
│   ├── parser.rs                # SMB2 64-byte header + TREE_CONNECT path + CREATE filename + READ/WRITE size + NTLM identity scan + DCE-RPC BIND UUIDs
│   ├── session.rs               # SmbParser SessionParser + NBSS framing (TCP/445)
│   └── types.rs                 # SmbMessage / SmbDialect / SmbCommand / NtlmAuth
├── quic/                        # `quic` feature — QUIC Initial passive decrypt (issue #3, 0.18)
│   ├── parser.rs                # quic-parser pipeline + tls-parser ClientHello → SNI/ALPN
│   ├── datagram.rs              # QuicUdpParser DatagramParser (UDP/443) + QuicConfig bounds + pending_dropped/tracked (#184, 0.23)
│   └── types.rs                 # QuicInitial
└── pcap/                        # `pcap` feature
    └── source.rs                # PcapFlowSource — offline replay
```

The legacy `HttpFactory` / `TlsFactory` callback-handler shape
(`factory.rs` modules) was removed in 0.9.0 — the
`SessionParser` typed-stream shape is the only public surface.

### Tests

- `tests/parser_proptest.rs` — 11 splitting-invariance / no-panic
  proptests across all four parsers (HTTP / TLS / DNS-UDP / DNS-TCP).
  Run with `PROPTEST_CASES=10000` for stress testing.
- `tests/proptest_invariants.rs` — tracker-level proptests
  (FiveTuple canonicalization, TCP state machine).
- `tests/{http,tls,dns}_parser.rs` — fixture-based unit tests per parser
  (TLS rewritten on 0.9 to drive the SessionParser shape after the
  callback-factory removal).
- `tests/{http,pcap}_pcap.rs`, `tests/pcap_integration.rs`,
  `tests/pcap_fixtures.rs` — pcap-driven integration tests.
- `tests/length_prefixed_example.rs` — typed `Driver<E>` + session
  slot with a custom protocol parser, paired with
  `tests/fixtures/length_prefixed/sample.pcap` (0.2.0).
- `tests/metrics_integration.rs` — DebuggingRecorder snapshot test
  for the `metrics` feature (0.2.0).
- `tests/round_trip.rs` — synthesize→pcap→PcapFlowSource→
  FlowSessionDriver→assert byte-equality regression test. Three
  hand-written variants plus a proptest (0.3.0).
- `tests/driver.rs` — typed `Driver<E>` + `SlotHandle` /
  port routing / heuristic / broadcast / force_close
  (plan 121, 0.11.0).
- `tests/driver_send.rs` — `static_assertions::assert_impl_all!`
  on `SlotHandle: Send + Sync` + cross-thread drain +
  competitive-consumer clone semantics (plan 122, 0.12.0).
- `tests/driver_broadcast.rs` — `BroadcastSlotHandle` fan-out
  semantics + the `SlotDrain` trait generic over both handle
  types (#101, 0.20). (The former `tests/driver_deferred.rs`
  was deleted with `DeferredDriverBuilder` in #98.)
- `tests/anomaly_fields.rs` — `AnomalyFields` impls on
  `FiveTupleKey` / `L4Proto` / `AnomalyKind` (plan 126,
  0.12.0).
- `tests/layers.rs` + `tests/layers_extended.rs` — Tier 3
  per-packet view (direct slices, dynamic walk, tunnel walking,
  ARP/MPLS/ICMP).
- `tests/auto_sweep.rs` — `FlowTracker::with_auto_sweep` (plan
  75, 0.9.0).
- `tests/orientation_axis.rs` — canonical `Orientation` on
  `Started`/`Packet` is stable across arrival order while
  `FlowSide` flips under a tap-merge race; `FlowStats`
  `side_for`/`orientation_for` axis translation (issue #118);
  per-direction capture-leg binding + `capture_leg_inconsistent`
  IOC on a merged flow (issue #120); SYN-based initiator
  inference flips a `SYN+ACK`-first flow + `direction_flipped`
  (issue #122, 0.20.0).
- `tests/error_chain.rs` — unified `flowscope::Error` source
  chain across pcap I/O, ICMP, DNS (plan 96, 0.9.0).
- `tests/quick_wins.rs` — Timestamp/FlowStats/EndReason/
  LayerKind/Layer/LayerStack/KeyIndexed helpers (plan 110
  sub-B, 0.10).
- `tests/well_known.rs` — `FiveTupleKey` `well_known_port` /
  `protocol_label` (plan 102 sub-D, 0.10).
- `tests/emit_csv.rs`, `tests/emit_ndjson.rs`,
  `tests/emit_zeek.rs` — three writers in `flowscope::emit`
  (plan 101, 0.10).
- `tests/emit_eve.rs` — Suricata EVE JSON writer:
  flow / anomaly / stats event_types + flow_hash
  determinism + direction-invariance + severity mapping
  + every-line-is-valid-JSON (plan 123, 0.12.0).
- `tests/parser_helpers.rs` — `BufferedFrameDrain` /
  `AccumulatingSessionParser` / `PerDatagramParser` (plan
  106, 0.10).
- `tests/http_exchange.rs`, `tests/dns_exchange.rs` —
  exchange aggregators (plan 107, 0.10).
- `tests/http_smuggling.rs` — RFC 9112 §6.3 regression corpus:
  CL.TE / TE.CL / TE.TE, duplicate + conflicting `Content-Length`,
  obs-fold, bare CR, duplicate `Host`, request-target authority.
  Each asserts the **typed** `HttpPoison`, not just "it failed"
  (#163, 0.23).
- `tests/bounded_memory.rs` — the adversarial suite behind
  `docs/bounded-memory.md`: slow drip, endless head, 64 MiB body,
  unterminated chunk/trailer framing, unbounded pipelining, a caller
  that never drains, post-poison and post-tunnel accumulation
  (#169, 0.23).
- `tests/http_access_log.rs` — inline access records → EVE
  `event_type: "http"`, plus exact-label metric assertions
  (#168, 0.23).
- `tests/http_proxy_driver.rs` — `HttpProxySession` through the typed
  `Driver`: events reach the slot, and a framing violation drops the
  parser with `ParserClosed { ParseError }` (#164, 0.23).
- `tests/http2_streams.rs` + `tests/http2_proptest.rs` — HTTP/2
  end-to-end routing and the split-invariance / bounded-state /
  terminal-failure properties (#170, 0.23).
- `tests/http2_driver.rs` — `Http2Session` through the typed `Driver`:
  per-stream events reach the slot, a framing violation drops the
  parser with `ParserClosed { ParseError }`, and a mid-stream join is
  **not** a parse error (#196, 0.23).
- `tests/classify_proptest.rs` — prefix safety for
  `classify_first_bytes`: a short peek never decides differently from
  the full input (#165, 0.23).
- `tests/driver_heuristic.rs` — probe replay, `NoMatch` fast-fail,
  and bounded probe state on heuristic slots (#166, 0.23).
- `benches/{extractor,tracker,reassembler,session_driver,dedup}.rs`
  — criterion benchmark harness (0.3.0). Run with
  `cargo bench --all-features`; baselines in
  `docs/performance.md`.

## Build & Test

```bash
# Default features
cargo test

# All features (incl. tls-fingerprints, dns, pcap, metrics, tracing)
cargo test --all-features

# Just one module
cargo test --features http
cargo test --features dns

# Stress proptests
PROPTEST_CASES=10000 cargo test --features http,tls,dns --test parser_proptest

# Lint
cargo clippy --all-features --all-targets -- -D warnings
cargo fmt --all -- --check
cargo doc --all-features --no-deps
```

## Architecture

### Three layers, one trait per layer

1. **Extractor** (`FlowExtractor`) — turns a frame into a flow key +
   metadata. User-pluggable. Built-in extractors (5-tuple etc.) and
   decap combinators wrap each other (`StripVlan(InnerVxlan(FiveTuple))`).
2. **Tracker** (`FlowTracker<E, S>`) — bidirectional flow accounting
   on top of an extractor. TCP state machine with Suricata-style idle
   timeouts and LRU eviction. Emits `FlowEvent` lifecycle. Hot-cache
   fast path for monoflow workloads (0.2.0).
3. **Reassembler** / **SessionParser** / **DatagramParser** — three
   API shapes for consuming TCP / UDP payloads. Pick by use case
   ([recipes.md](docs/recipes.md) walks through the
   decision tree).

### One L7 API shape — sync / async parity

Every shipped L7 parser exposes the typed-stream shape only
(`SessionParser` for TCP, `DatagramParser` for UDP). The legacy
`*Factory<H>` callback-handler shape that shipped through 0.8
was removed in 0.9.

- **`SessionParser` / `DatagramParser`** — typed message stream.
  `feed_initiator` / `feed_responder` / `parse` return
  `Vec<Self::Message>`; both traits have a defaulted `on_tick`.
- A consumer who wants callback ergonomics writes a
  `driver.track_into(view, &mut events)` + `slot.drain(&mut msgs)`
  loop and dispatches on the typed `SlotMessage`s + `Event<K>`.

Two driver helpers:

- Sync, no runtime: the typed **`driver::Driver<E>`** with one
  session/datagram slot per parser
  (`builder.session_on_ports(parser, ports)` /
  `datagram_on_ports`). This replaced the per-parser
  `FlowSessionDriver` / `FlowDatagramDriver` in 0.20 (#99); the
  parser-dispatch engine survives as a crate-private detail.
- Async tokio: **`flow_stream(...).session_stream(parser)`** in
  netring.

Both produce typed L7 messages for the same wire bytes.

For the highest-level convenience, marquee parsers each ship
a one-call pcap iterator:

```rust,no_run
for (key, hello) in flowscope::tls::client_hellos_from_pcap("trace.pcap")? { … }
for (key, init)  in flowscope::quic::initials_from_pcap("trace.pcap")? { … }
for (key, msg)   in flowscope::smb::messages_from_pcap("trace.pcap")? { … }
```

These are the strongly-typed front door over the generic
`flowscope::pcap::session_messages::<P>` /
`datagram_messages::<P>` building block. For unsurveyed
parsers, call `pcap::session_messages::<P>(path)` /
`datagram_messages::<P>(path)` directly (they yield
`(FiveTupleKey, P::Message)`). The
old 0.10-era `flowscope::Pipeline` type was removed in
plan 121 (0.11); the typed-driver shape replaced it.

### Reassembly observability (0.2.0)

`BufferedReassembler` ships an optional per-side cap with two
overflow policies:

- `OverflowPolicy::SlidingWindow` (default): drop oldest bytes;
  flow stays alive; parser must resync.
- `OverflowPolicy::DropFlow`: poison the reassembler; the driver
  synthesises an `Ended { reason: BufferOverflow }` event for the
  flow on the next tick.

`FlowStats` carries per-side reassembly diagnostics
(`reassembly_dropped_ooo_*`, `reassembly_bytes_dropped_oversize_*`)
on every `Ended` event. For live signal, `FlowDriver::with_emit_anomalies(true)`
emits `FlowEvent::FlowAnomaly { key, kind: AnomalyKind::… }` and
`FlowEvent::TrackerAnomaly { kind, .. }` events inline,
coalesced per (flow, side, kind) per tick.

### Observability features (0.2.0)

`metrics` and `tracing` Cargo features wire the tracker and driver
into the standard observability ecosystem. Both zero-cost when off
(every entry point compile-time stubbed). Metric vocabulary in
[docs/observability.md](docs/observability.md).

### Design constraints

- **Runtime-free in core.** Tokio is forbidden in `flowscope`'s deps.
  Async lives in `netring` (which depends on flowscope, not the other
  way around). This is a hard project rule; PRs adding tokio to
  flowscope are wrong-shaped.
- **No `unsafe` outside well-justified zero-copy spots.** Buffer
  handling uses `Bytes` / `Vec<u8>` with safe slicing.
- **Deterministic state machines.** No background threads, no global
  state. Every parser holds its state and returns messages
  synchronously.
- **Bounded memory.** Tracker has `max_flows`; reassemblers have
  optional `max_buffer`; correlator has `max_pending`. No unbounded
  growth.
- **`#[non_exhaustive]` on every public struct/enum that may grow.**
  Added project-wide in 0.2.0. Construct via `::default()` and mutate;
  do not rely on struct-literal construction from outside the crate.
  All future additions are additive.
- **Single vocabulary across event stream and metrics.** `AnomalyKind`
  is the source of truth for both `FlowEvent::FlowAnomaly` /
  `TrackerAnomaly` carriers and the
  `flowscope_anomalies_total` metric labels. Adding a variant
  requires adding the corresponding metric label arm in
  `src/obs.rs::anomaly_label`.
- **Trait stability lock.** `SessionParser` / `DatagramParser` shape
  was committed in 0.1.0. `Reassembler` grew default-zero diagnostic
  methods in 0.2.0 (purely additive). Future additions stay additive;
  breaking changes need a major bump.

## Documentation

`docs/` is the only documentation tree, and everything in it is
**published reference material** for users of the library — it ships
inside the crates.io package. Forward-looking work lives in the issue
tracker, not in files.

**Convention**: nothing internal goes in `docs/`. Per-cycle
plan-of-record syntheses, wishlists, upstream-feedback records,
design proposals, and audit reports are working artifacts — keep them
in the tracker or in a branch, and let `CHANGELOG.md` plus `git log`
be the durable record. The `plans/` directory was retired in 0.23
along with the last shipped plan file; a stale 0.18-cycle examples
audit that had been shipping to crates.io users went with it.

### `docs/` inventory

Read in order:

- `getting-started.md` — install + three minimal pipelines.
- `concepts.md` — the four layers + event model.
- `recipes.md` — picking an API, custom parsers, multi-protocol
  monitoring, cross-protocol correlation, structured output.
- `observability.md` — metric vocabulary, cardinality, tracing
  targets, severity routing.
- `performance.md` — criterion bench methodology + how to
  regression-test. Numbers are explicitly point-in-time.
- `design.md` — why flowscope is shaped the way it is
  (runtime-free, run-to-completion threading, layered traits,
  locked serde format).

Reference, by topic: `discoverability.md`, `bounded-memory.md`,
`tls-routing.md`, `tls-ech.md`, `eve-format.md`,
`detect-patterns.md`, `file-hash.md`, `sharded.md`.

Migration: one guide per breaking cycle, `migration-0.19-to-0.20.md`
onward. Guides for cycles older than 0.19 were retired in 0.23 —
each published version's `.crate` tarball still carries the guide
that was current for it.

## Pre-publish checklist

For the next `cargo publish` of flowscope:

1. Bump `Cargo.toml` `version` if user-facing changes have landed.
2. Update `CHANGELOG.md` with the new release section.
3. `cargo test --all-features` clean.
4. `cargo clippy --all-features --all-targets -- -D warnings` clean.
5. `cargo fmt --check` clean.
6. `cargo doc --all-features --no-deps` zero warnings.
7. `cargo machete` no unused deps.
8. `cargo publish --dry-run` packages and verifies.
9. `cargo publish`.
10. Tag the release in git: `git tag 0.x.y && git push origin 0.x.y`
    (no `v` prefix — matches the 0.1.0 / 0.2.0 / 0.3.0 / 0.4.0 /
    0.5.0 tags).

## Intra-doc links for re-exporters

See `docs/recipes.md` → "Re-exporting flowscope types" for
the recipe. The source of truth lives in `docs/` so downstream
re-exporters find it on docs.rs; keeping a copy here would just
drift.

## Relationship to netring

netring (the published Linux-capture crate) has flowscope as a
non-optional dep. Specifically:

- `netring` re-exports `flowscope::Timestamp` and `flowscope::PacketView`
  unconditionally — they're fundamental types every netring user
  may touch.
- `netring`'s `parse` / `flow` features turn on flowscope's
  `extractors` / `tracker` / `reassembler` / `session` features.
- The async stream adapters (`flow_stream`, `session_stream`,
  `datagram_stream`, `flow_broadcast`, `conversation`) live in
  netring because they depend on tokio + `AsyncCapture`. They
  consume flowscope's traits.
- The 0.2.0 `FlowEvent::key()` signature change (`&K` → `Option<&K>`)
  needs a matching netring update if netring's adapters call
  `event.key()`.
- `FlowEvent::FlowAnomaly` / `TrackerAnomaly` and
  `EndReason::BufferOverflow` flow through
  the async adapters verbatim — no netring changes needed for those.

If you add a new public API in flowscope, consider whether netring
needs a corresponding re-export under `netring::flow::*`.

## Key files

- `README.md` — front page (also published as the crates.io readme).
- `CHANGELOG.md` — release history.
- `docs/` — published reference docs (see [Documentation](#documentation)
  for the full inventory).
- `Cargo.toml` — package manifest. `exclude` keeps `CLAUDE.md` and
  `fuzz/` out of the published package; `docs/` IS published.
- `src/lib.rs` — top-level rustdoc + feature/module wiring.
- `src/session.rs` — the strategic 1.0 abstraction
  (`SessionParser` / `DatagramParser`).
- `src/driver/` — the typed `Driver<E>` + per-parser slots; the
  public sync mirror of netring's `session_stream` / `datagram_stream`.
- `src/session_driver.rs` / `src/datagram_driver.rs` — crate-private
  session/datagram parser-dispatch engines (the public
  `FlowSessionDriver` / `FlowDatagramDriver` were removed in 0.20, #99).
  Retained because the typed driver slots + the `pcap` source need them.
- `src/dedup.rs` — content-hash dedup primitive.
- `src/obs.rs` — metrics + tracing hooks; metric-name constants
  exported here.
