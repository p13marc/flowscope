# RFC 175 — Driver & event convergence for 1.0 (issue #84)

**Status:** Draft for review — *no code changed yet.*
**Issue:** #84 ("converge the two driver families + three event enums into one driver").
**Effort:** L. The keystone of the 1.0 API cleanup.
**Blast radius:** flowscope public API + netring (the only known consumer).

> This is a forward-looking design doc, so it lives in `plans/`
> (excluded from the published package) per the docs-vs-plans
> convention, not in `docs/`. Move to `docs/` only if we decide the
> migration recipe should ship on docs.rs.

---

## 1. The problem, precisely

flowscope ships **two parallel public driver families** and **three
event enums**. A new user has to learn all of it to pick an entry
point.

### Three event enums (full maps in §A)

| Enum | Layer | Variants | serde | Messages | Consumed by |
|------|-------|----------|-------|----------|-------------|
| `FlowEvent<K>` (`event.rs:861`) | tracker | 8 (Started/Packet/Established/StateChange/Ended/FlowAnomaly/TrackerAnomaly/Tick) | yes | — | emitters (`emit/*`), `FlowDriver`, raw `FlowTracker` |
| `SessionEvent<K,M>` (`session.rs:719`) | session driver | 6 (Started/**Application{M}**/Closed/FlowAnomaly/TrackerAnomaly/FlowTick) | yes | in-stream (`Application.message`) | `Flow{Session,Datagram}Driver` |
| `Event<K>` (`driver/typed.rs:71`) | typed driver | 8 (FlowStarted/FlowEstablished/FlowPacket/FlowEnded/FlowTick/**ParserClosed**/FlowAnomaly/TrackerAnomaly) | **no** | via `SlotHandle` (out of band) | `Driver<E>` |

The three overlap almost entirely on lifecycle; they differ in three
substantive ways:

- **`SessionEvent` adds `Application{message: M, parser_kind}`** — the
  only "message in the event stream" model. Everything else routes
  messages out of band.
- **`Event<K>` adds `ParserClosed`** (a slot/ parser self-termination
  signal with no `FlowEvent` source) and enriches two variants
  (`FlowPacket.tcp: Option<TcpInfo>`, `FlowEnded.ts`, plus `ts` on
  every variant → a uniform `timestamp()` accessor).
- **`FlowEvent` is the only one with `Packet` + `StateChange`**
  granularity and the only one wired into `emit/*` (all `write_event`
  signatures take `&FlowEvent<K>`).

There is exactly one converter today: a private
`map_flow_event(FlowEvent → Option<Event>)` (`typed.rs:1103`) that
drops `StateChange` and synthesizes `Event::FlowEnded.ts` from
`stats.last_seen`. No `From`/`Into` impls exist between any pair.

### Two driver families (full maps in §B)

**Family A — `Flow*Driver` trio** (emits `FlowEvent` / `SessionEvent`):
- `FlowDriver<E,F,S>` (`flow_driver.rs:61`) — tracker + reassembler
  factory; **6 constructors** + 4 chainable `with_*` setters.
- `FlowSessionDriver<E,P,S>` (`session_driver.rs:112`) — wraps
  `FlowDriver`, adds `SessionParser` dispatch; **10 constructors**.
- `FlowDatagramDriver<E,P,S>` (`datagram_driver.rs:103`) — same with a
  no-op reassembler + `DatagramParser`; **10 constructors**. A
  **~95 % structural twin** of `FlowSessionDriver` (identical struct
  shape, identical 10-constructor explosion, identical operational
  surface; the only real difference is reassembly-vs-noop and the
  `feed_*` vs `parse` body).

**Family B — typed slot (plan 121)** (emits `Event<K>`):
- `Driver<E>` (`driver/typed.rs:208`) — multi-parser via `SlotHandle`,
  `Send + Sync`, builder-only (no constructor explosion).
- `DriverBuilder<E>` vs `DeferredDriverBuilder<E>` — share 6 config
  setters + 8 of 9 registration methods + 7 of 9 fields; diverge only
  in (a) `DriverBuilder` stores `extractor` + eager slots while
  `Deferred` stores materializer closures, (b)
  `session_on_ports_broadcast_each` is **DriverBuilder-only**, (c)
  `build()` vs `build_with(ext)`. The two-type split is deliberate
  (plan 124): `Deferred` has *no* `build()`, so the type system
  forbids finalizing without an extractor.
- `SlotHandle<M,K>` vs `BroadcastSlotHandle<M,K>` — duplicate
  `drain`/`drain_n`/`pending`/`parser_kind`; differ by semantics
  (MPMC competitive-consumer vs fan-out) and bounds (`Broadcast`
  additionally requires `M: Sync + Clone`). `SlotHandle` adds
  `drain_replacing`/`clear`; `Broadcast` adds `subscribers`.

### Constructor explosion

`FlowSessionDriver` + `FlowDatagramDriver` carry **10 constructors
each** (5 capability tiers × {default-config, `_and_config`}),
`FlowDriver` carries 6. That is **26 constructors** for what is
conceptually "extractor + parser(s) + optional config/state".

---

## 2. The de-risking finding (changes the whole calculus)

A flat `grep` says netring references the convergence targets ~130×
(`DriverBuilder` 58, `FlowEvent` 56, `SessionEvent` 54,
`Flow{Session,Datagram}Driver` 21). That overstates the pain. netring
runs **two completely separate paths**:

1. **Live/production `Monitor`** — *already* on the target shape:
   `flowscope::driver::Driver<FiveTuple>` + `Event<K>` (imported as
   `FsEvent`) + `SlotHandle`. It **never** uses `FlowEvent` or
   `SessionEvent`. This is the heaviest single consumer of the *good*
   API (`run.rs` has three 8-variant `Event` match blocks).
2. **Offline / async-stream layer** — `async_adapters/*` + `pcap_flow.rs`.
   This is where *all* `FlowEvent`/`SessionEvent` usage lives. The
   async adapters drive a **raw `FlowTracker`** and translate
   `FlowEvent → SessionEvent` themselves; only `pcap_flow.rs` actually
   instantiates `Flow{Session,Datagram}Driver` (one file, ~8 sites).

Consequences for the plan:

- **The `Driver<E>`/`Event<K>` convergence is already adopted by
  netring's live path.** Making it *the* driver is mostly a flowscope
  internal cleanup + a small netring builder-call change.
- **`deferred()` / `DeferredDriverBuilder` / `build_with` are used
  nowhere in netring.** We can reshape the builder freely.
- **`FlowEvent`/`SessionEvent` churn is confined to netring's
  offline/async layer** (≈10 files), independent of the live monitor.
- `SlotHandle` is the single most-spread type (~26 `protocol/builtin/*`
  `register` impls return it) — but its *shape* isn't changing, so
  that spread is inert for this RFC.

---

## 3. Proposed 1.0 end-state

Two layers, two enums, one driver, one builder. Concretely:

### 3.1 Events — retire `SessionEvent`, keep a clean 2-enum split

Reject the literal "one enum" reading; adopt **two enums on two
layers**, deleting the genuinely-redundant third:

- **`FlowEvent<K>` stays** — the *tracker* primitive. It is the
  lowest layer (`FlowTracker::track` returns `SmallVec<FlowEvent>`),
  the serde-locked wire vocabulary, and the emitter input. Keep it.
- **`Event<K>` is THE consumer/driver event** — emitted by the one
  `Driver<E>`. Messages stay out-of-band via `SlotHandle`.
- **`SessionEvent<K,M>` is retired.** Its only unique contribution is
  the in-stream `Application{message}` arm, and the typed-slot model
  is its chosen successor (netring's live path already uses slots, not
  `SessionEvent`).

This kills "learn three enums": a consumer learns `Event<K>` (driver)
and may drop to `FlowEvent<K>` (tracker/emit). That is honest layering,
not redundancy.

**Required to make `Event<K>` carry its new weight:**

1. **Add `serde` to `Event<K>`** (today it has none). Needed if any
   consumer/emit path serializes it.
2. **Decide `StateChange`** (§5 Q3): `Event<K>` currently has no
   equivalent (`map_flow_event` drops it). Either add
   `Event::FlowStateChange` or document the drop as intentional.
3. **Emitter story** (§5 Q4): `emit/*` `write_event` takes
   `&FlowEvent<K>`. A `Driver<E>` user holds `Event<K>`. Add
   `write_event` overloads (or a shared lifecycle trait) so `Event<K>`
   emits without a manual round-trip. The `KeyFields`/`AnomalyFields`
   machinery already lives on the *payload* types, so this is additive.

### 3.2 Drivers — one driver, keep `FlowDriver` as the primitive

- **`Driver<E>` is the one public driver.** Single-parser is just
  `Driver<E>` with one slot.
- **Delete `FlowSessionDriver` + `FlowDatagramDriver`.** They are the
  ~95 %-twin wrappers; their single-parser convenience is subsumed and
  their 20 constructors evaporate. Their reassembly-vs-noop distinction
  becomes a builder choice (`session_*` vs `datagram_*` registration,
  which already exists on `DriverBuilder`).
- **Keep `FlowDriver` as the documented low-level primitive** (issue
  guardrail; it is the run-to-completion engine `Driver<E>` wraps).
  Optionally trim its 6 constructors to `new` + `with_config` and a
  builder, but that is secondary.

### 3.3 Builder — collapse to one, extractor-at-`build`

Unify on the **deferred shape** (the mechanism already exists):

- One `DriverBuilder<E>` = today's `DeferredDriverBuilder` mechanism
  (pre-allocated slot queues + materializer closures), renamed.
- `Driver::builder()` takes **no** extractor; `build(self, extractor)`
  finalizes. Compile-time-safe with no second type and no panic path
  (the extractor is a required `build` argument). `Driver::deferred()`
  and `DeferredDriverBuilder` are deleted.
- Add `session_on_ports_broadcast_each` to the unified builder
  (closes the parity gap).

netring impact: the 3 live build sites change
`Driver::builder(FiveTuple::bidirectional()).build()` →
`Driver::builder().build(FiveTuple::bidirectional())`. The ~26
`register(&mut DriverBuilder<FiveTuple>)` signatures keep the **same
type name** — no per-protocol churn.

> Alternative considered: keep two builder types but add
> `broadcast_each` to `Deferred` (minimal churn, preserves the
> plan-124 split). Rejected as the primary recommendation because it
> leaves the duplication the issue explicitly calls out — but it is the
> safe fallback if the extractor-at-`build` ergonomics are unwanted
> (§5 Q5).

### 3.4 Slot handles — keep both, share a trait

`SlotHandle` (MPMC) and `BroadcastSlotHandle` (fan-out) have
genuinely different semantics and bounds; merging them into one type
would muddy both. Instead extract a `SlotDrain` trait
(`drain`/`drain_n`/`pending`/`parser_kind`) both implement, so
downstream drain loops can be generic and the duplication is removed
without collapsing the types. Low priority; can land independently.

---

## 4. Migration plan (sequenced, two-crate, coordinated)

The break must land in flowscope and netring together (per policy).
Recommended ordering — each step compiles and tests green on its own
where possible:

**Phase 0 — flowscope, non-breaking groundwork**
1. Add `serde` derive to `Event<K>` + resolve `StateChange` (Q3).
2. Add `Event<K>` support to `emit/*` (additive `write_event`
   overloads or shared trait). Add `From<FlowEvent<K>> for Event<K>`
   (promote `map_flow_event`, decide the `StateChange`/`ts` handling
   publicly).
3. Add `session_on_ports_broadcast_each` to `DeferredDriverBuilder`
   (parity), so the merged builder loses nothing.
*All additive — ships in a normal minor, de-risks the breaking step.*

**Phase 1 — flowscope, the breaking collapse (one PR series)**
4. Collapse the builders: rename `DeferredDriverBuilder`→`DriverBuilder`
   shape, `Driver::builder()` no-arg + `build(ext)`; delete the eager
   builder + `Driver::deferred()`.
5. Delete `FlowSessionDriver` + `FlowDatagramDriver`.
6. Retire `SessionEvent` (see Q2 for "delete vs move to netring").
7. CHANGELOG + `docs/migration-0.20-to-0.21.md` recipe.
8. Bench gate: confirm `track_into` stays at **0.000 allocs/packet**
   (the `Event<K>` path already has `track_into`; the builder change
   is registration-time only).

**Phase 2 — netring, coordinated**
9. Live path: 3 build sites `builder(ext).build()` → `builder().build(ext)`.
   `register` signatures unchanged. (Small, mechanical.)
10. Offline/async layer: replace `SessionEvent` (netring constructs it
    in `session_stream`/`datagram_stream`/`pcap_flow`/`multi_streams`)
    with either flowscope's `Event<K>` + slot drain, or a netring-local
    event type (Q2). Replace `Flow{Session,Datagram}Driver` in
    `pcap_flow.rs` (1 file) with `Driver<E>`.
11. `FlowEvent` matches in the async adapters stay valid (FlowEvent is
    kept) — only the `SessionEvent` *output* type changes.

**Phase 3 — release**
12. Coordinated flowscope + netring minor-breaking release; migration
    recipe in both CHANGELOGs.

### Effort reality

- **flowscope:** medium. Deletions are large but mechanical; the real
  design work is the `Event<K>` serde/emit/`StateChange` decisions
  (Phase 0).
- **netring live path:** tiny (3 build sites).
- **netring offline/async layer:** medium-localized (~10 files, all in
  `async_adapters/` + `pcap_flow.rs`), and *independent* of the live
  path — can be done as its own netring PR.

---

## 5. Open decisions (your call)

These change what gets built; flagging rather than presuming.

- **Q1 — Driver families: delete or deprecate-one-release?**
  Recommend **delete** `FlowSessionDriver`/`FlowDatagramDriver` (pre-1.0
  blesses it; they are isolated to `pcap_flow.rs` in netring). Keep
  `FlowDriver`. Alternative: `#[deprecated]` for one release, delete in
  1.1 — softer but drags two dead types into 1.0.

- **Q2 — `SessionEvent`: delete outright, or relocate to netring?**
  netring is the only consumer and it *constructs* `SessionEvent` in
  its async adapters. Options: (a) delete from flowscope, netring
  defines its own session-event type for its stream adapters; (b) keep
  a minimal `SessionEvent` in flowscope purely as the async-adapter
  contract. Recommend **(a)** — it is a netring-stream concern, not a
  core flowscope primitive.

- **Q3 — `StateChange` in `Event<K>`?** Add `Event::FlowStateChange`
  for parity with `FlowEvent`, or keep dropping it (current behavior;
  `FlowEstablished` covers the common case). Recommend **add it** for a
  lossless `From<FlowEvent>`.

- **Q4 — emitter surface for `Event<K>`.** Add `write_event(&Event<K>)`
  overloads, or a shared `LifecycleEvent` trait both enums implement.
  Recommend the **shared trait** (one impl site, future-proof).

- **Q5 — builder shape.** Extractor-at-`build` single builder
  (recommended, §3.3) vs keep-two-builders-plus-parity (safe fallback).

- **Q6 — scope of the first PR.** Land Phase 0 (additive) now and
  schedule Phases 1–3 as the breaking 0.21 cycle, or do the whole thing
  in one 0.21 series. Recommend **Phase 0 now** — it is pure upside and
  shrinks the eventual break.

---

## Appendix A — event enum maps

*(Condensed; full field lists verified against source.)*

`FlowEvent<K>` `event.rs:861` — `#[derive(Debug,Clone)]`,
`#[non_exhaustive]`, serde `tag="type"`. Variants: `Started{key,side,
ts,l4}`, `Packet{key,side,len,ts}`, `Established{key,ts,l4}`,
`StateChange{key,from,to,ts}`, `Ended{key,reason,stats,history,l4}`,
`FlowAnomaly{key,kind,ts}`, `TrackerAnomaly{kind,ts}`,
`Tick{key,stats,ts}`. Methods: `key()->Option<&K>`,
`anomaly_kind()->Option<&AnomalyKind>`. Tracker emits the first 5;
driver synthesizes `FlowAnomaly`/`TrackerAnomaly`/`Tick`.

`SessionEvent<K,M>` `session.rs:719` — same derives + serde. Variants:
`Started{key,ts}`, `Application{key,side,message:M,ts,parser_kind}`,
`Closed{key,reason,stats,l4}`, `FlowAnomaly{key,kind,ts}`,
`TrackerAnomaly{kind,ts}`, `FlowTick{key,stats,ts}`. Only
`anomaly_kind()` (no `key()`). Does not wrap `FlowEvent`; duplicates a
coarser subset + adds `Application`.

`Event<K>` `driver/typed.rs:71` — `#[derive(Debug,Clone)]`,
`#[non_exhaustive]`, **no serde**. Variants: `FlowStarted{key,ts,l4}`,
`FlowEstablished{key,ts,l4}`, `FlowPacket{key,side,len,ts,tcp}`,
`FlowEnded{key,reason,stats,history,l4,ts}`, `FlowTick{key,stats,ts}`,
`ParserClosed{key,parser_kind,reason,ts}`, `FlowAnomaly{key,kind,ts}`,
`TrackerAnomaly{kind,ts}`. Methods: `key()`, `tcp()`, `timestamp()`.
`map_flow_event` (`typed.rs:1103`) maps `FlowEvent→Option<Event>`,
dropping `StateChange`, injecting `FlowPacket.tcp`, synthesizing
`FlowEnded.ts = stats.last_seen`.

Emitters (`emit/{csv,ndjson,zeek,eve}.rs`) all take `&FlowEvent<K>`;
`KeyFields`/`AnomalyFields` are impl'd on `FiveTupleKey`/`L4Proto`/
`AnomalyKind` (payload types), not on the event enums.

## Appendix B — driver/builder maps

`FlowDriver<E,F,S>` `flow_driver.rs:61` — 6 ctors (`new`,`with_config`,
`with_state`,`with_state_and_config`,`with_state_init`,
`with_state_init_and_config`); setters `with_emit_anomalies`,
`with_idle_timeout_fn`, `with_dedup`, `with_monotonic_timestamps`; ops
`track`/`sweep`/`finish`/`force_close`/`tracker(_mut)`/
`snapshot_flow_stats` + reassembler accessors. Emits `FlowEvent`.

`FlowSessionDriver` `session_driver.rs:112` / `FlowDatagramDriver`
`datagram_driver.rs:103` — 10 ctors each (5 tiers × 2 configs),
identical operational surface, emit `SessionEvent`. ~95 % twins;
differ only in `BufferedReassemblerFactory` vs `NoopReassemblerFactory`
and `feed_*` (reassembled) vs `parse` (per-datagram).

`Driver<E>` `driver/typed.rs:208` — `builder`/`deferred`/`track`/
`track_into`/`sweep(_into)`/`finish(_into)`/`run_pcap`/`force_close(_into)`/
`tracker(_mut)`. Emits `Event`. `DriverBuilder` vs
`DeferredDriverBuilder`: share all config setters + 8/9 registration
methods; diverge in extractor storage, `broadcast_each`
(DriverBuilder-only), and `build()`/`build_with()`.

`SlotHandle<M,K>` `driver/slot.rs:56` (MPMC; `drain`/`drain_n`/`pending`/
`parser_kind`/`drain_replacing`/`clear`) vs `BroadcastSlotHandle<M,K>`
`driver/broadcast.rs:38` (fan-out; same drain four + `subscribers`;
requires `M: Sync + Clone`).

## Appendix C — netring consumption (the two paths)

**Live `Monitor` (already on target shape):** `Driver<FiveTuple>` +
`Event<K>` (`run.rs` import `use flowscope::driver::Event as FsEvent`;
three 8-variant match blocks at `run.rs:1703/2374/2611`). Builds via
`Driver::builder(...).build()` at `monitor/mod.rs:1595/2102/3098`
(+2 tests). `register(&mut DriverBuilder<FiveTuple>)` in ~28
`protocol/builtin/*` files calling `session_on_ports`(12)/
`datagram_on_ports`(11)/`session_on_ports_broadcast_each`(1, http) and
returning `SlotHandle`(~26)/`BroadcastSlotHandle`(1). No `deferred()`,
no `build_with`.

**Offline/async layer (all `FlowEvent`/`SessionEvent`):**
`async_adapters/{flow_stream,session_stream,datagram_stream,
flow_broadcast,conversation,multi_streams}.rs` drive a raw
`FlowTracker`, match `FlowEvent`, emit `SessionEvent`. `pcap_flow.rs`
instantiates `Flow{Session,Datagram}Driver` (the only file that does).
`lib.rs` re-exports `FlowEvent`/`SessionEvent`/`Flow{Session,Datagram}Driver`.
