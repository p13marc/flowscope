# Plan 157 — 0.13 cycle umbrella

**Status:** drafting, 2026-06-11. Triggered by the netring-side
[`flowscope-0.13-wishlist.md`](../flowscope-0.13-wishlist.md)
(10 asks: plans 147–156). This umbrella synthesises my own
verification pass against the 0.12.0 source, calls out where the
wishlist's premise was incorrect, and lays out the corrected plan
set.

The user has explicitly authorised breaking-change cycles to land
the best designs, which materially changes the answer for two of
the plans (147+151 collapse into one, 156 becomes structural and
trivial rather than `unsafe`-newtype gymnastics).

---

## §1 Headline finding — Plan 156's premise was wrong

The wishlist argues that `Driver<E>` is `!Send` because the
*central tracker* holds `Rc<RefCell>` interior-mutability state,
and that fixing this requires an unsafe `Arc<UnsafeCell>` newtype
(`SendCell<T>`). I verified directly: this is **incorrect**.

- `grep -rn 'Rc<\|RefCell\|UnsafeCell\|unsafe impl Send' src/`
  finds **zero** matches in `src/tracker.rs`, `src/flow_driver.rs`,
  `src/driver/*.rs` (other than stale doc comments and one
  test-only `CountingFactory`).
- A direct compile-time probe (`fn assert_send<T: Send>()`)
  proves `FlowTracker<FiveTuple>: Send` and
  `FlowDriver<FiveTuple, NoopReassemblerFactory>: Send` today —
  unconditionally.
- The same probe on `Driver<FiveTuple>` fails with a clear
  error: it's the **trait object** `Vec<Box<dyn ErasedSlot<E::Key>>>`
  on `src/driver/typed.rs:205` that lacks a `+ Send` bound. The
  underlying concrete `ErasedSlot` impls (`TypedConcreteSlot`,
  `TypedConcreteDatagramSlot`, `TypedHeuristicSessionSlot`,
  `TypedHeuristicDatagramSlot`) are all already Send-compatible —
  every field is `Arc<SegQueue<_>>`, `FlowSessionDriver`, scratch
  `Vec`s, `&'static str`, `Option<smallvec::SmallVec<...>>`.

The fix is one bound addition:

```rust
// src/driver/typed.rs:205 — before
slots: Vec<Box<dyn ErasedSlot<E::Key>>>,
// after
slots: Vec<Box<dyn ErasedSlot<E::Key> + Send>>,
```

…plus a constructor-side `where Self: Send` audit. No `unsafe`,
no `SendCell` newtype, no `SendMode` knob, no runtime
overhead, no public-API enum.

**Stale doc comments to clean up** as part of the same PR:
- `src/driver/slot.rs:45` — *"!Send (the central FlowTracker
  holds Rc<RefCell> state)"*
- `src/driver/mod.rs:28` — *"Rc<RefCell<…>>"*
- `src/driver/mod.rs:40` — *"Rc<RefCell internals)"*
- `CLAUDE.md` Plan 121/122 headlines — *"central FlowTracker
  holds Rc<RefCell> internals"*

These are wrong; they were probably copied forward from a pre-
0.11 design that never made it to master. The 0.12.0 release
shipped with them in place.

**This collapses Plan 156's effort from the wishlist's 3-4 days
(with the unsafe path + Miri audit) down to ~2 hours of
mechanical work + tests.** It also unblocks every downstream
that uses tokio's default multi-thread runtime, *without* an
opt-in knob — `Driver<E>: Send` becomes unconditional.

See [plan 156](./156-send-driver.md) for the full breakdown.

---

## §2 Asks at a glance — corrected after consolidation pass

| # | Plan | Title | Priority | Effort | Disposition |
|---|---|---|---|---|---|
| 147 | [147](./147-owned-anomaly-eve.md) | `OwnedAnomaly` + `DetectorScore` trait + emit-writer methods + per-score `into_anomaly` | **P0** | ~2 days | **Absorbs wishlist 147+148+151.** One coherent shape. |
| 148 | — | — | — | — | **Dissolved into 147.** See §3.2 |
| 149 | [149](./149-slothandle-drain-n.md) | `SlotHandle::drain_n` bounded drain | **P1** | ~0.5 day | **Narrowed.** Dropped `swap`/`SlotBuf` until benchmarks justify. |
| 150 | [150](./150-broadcast-slothandle.md) | `BroadcastSlotHandle<M, K>` | **P1** | ~2 days | as-proposed; `Mutex<Vec<Weak>>` baseline, `ArcSwap` later if profiling warrants |
| 151 | — | — | — | — | **Merged into 147** |
| 152 | [152](./152-pcap-replay-pacing.md) | `PcapFlowSource::with_speed_factor` | **P2** | ~0.5 day | Dropped `replay_at_wall_clock`. Added tokio-blocking caveat. |
| 153 | [153](./153-test-helpers-events.md) | `flowscope::test_helpers::events` synthetic constructors | **P2** | ~0.5 day | as-proposed |
| 154 | [154](./154-flow-state-map.md) | `FlowStateMap<T, K>` | **P2** | ~0.5 day | **Simplified.** Layered over `KeyIndexed<K, T>`. |
| 155 | [155](./155-sharded-recipe.md) | Sharded-driver example + recipe | **P3** | ~1 day | as-proposed |
| 156 | [156](./156-send-driver.md) | `Driver<E>: Send + Sync` unconditionally | **P0** | ~3 hours | **Structural one-line bound + parser `Send+Sync` audit.** NOT the wishlist's unsafe path |

**Corrected total effort: ~7 days** (down from the wishlist's
12; down from the round-1 draft's 8 after the consolidation
pass).

- Plan 156 alone drops from 3-4 days → 3 hours.
- Plans 147 + 148 + 151 fuse to ~2 days (was ~3.5 split).
- Plan 149 narrows to 0.5 day (was 1 day).
- Plan 154 simplifies to 0.5 day (was 2 days).

**P0 alone** (147, 156): **~2.5 days**. Ship as 0.13.0 alpha.

**P0 + P1** (147, 149, 150, 156): **~5 days**. Ship as 0.13.0.

**Everything** (P0/P1/P2/P3): ~7 days. Ship as 0.13.0 + 0.13.1.

---

## §3 Counter-proposals — design notes

### §3.1 Combine plans 147 (custom EVE anomaly) + 151 (`OwnedAnomaly`)

The wishlist proposes both:

- **Plan 147**: `EveJsonWriter::write_anomaly_custom(kind: &str,
  severity, ts, key: Option<&K>, observations, metrics)` — six
  positional args.
- **Plan 151**: `OwnedAnomaly { kind, severity, ts, key fields,
  observations, metrics, flowscope_kind }` + a builder API.

These are the same six fields. Shipping both means consumers see
two paths and have to choose:

- For one-off in-loop emission: `write_anomaly_custom(...)` with
  six args.
- For retention/storage/cross-process: `OwnedAnomaly` value type.

The two paths converge in `write_owned_anomaly` regardless, so
the value-type approach is strictly cleaner:

```rust
let a = OwnedAnomaly::new("PortScanTRW", Severity::Warning, ts)
    .with_key(&five_tuple_key)
    .with_observation("scanner_log_likelihood", "3.7")
    .with_metric("hosts_probed", 47.0);
eve.write_owned_anomaly(&a)?;
```

The builder API is no more verbose than the six-arg method, *and*
the value survives past the call site. So:

- **Drop** `write_anomaly_custom`.
- **Ship** `OwnedAnomaly` + `EveJsonWriter::write_owned_anomaly`
  + `FlowEventNdjsonWriter::write_owned_anomaly`.

One method per writer, one value type, one builder. Less surface,
more capability.

### §3.2 Dissolve wishlist Plan 148 into the output-side trait `DetectorScore`

**Round 1 (draft):** I narrowed wishlist 148 to drop
`verdict()`, keep `Input<'a>` GAT + `observe(...)` + a
`Score: Into<OwnedAnomaly>` bound.

**Round 2 (this consolidation pass):** dropping the *whole*
input-side trait is even cleaner. The three detectors'
inputs are genuinely heterogeneous:

| Detector | Input | Output |
|---|---|---|
| `PortScanDetector<K>` | `observe(K, bool)` from TCP outcomes | `ScanScore<K>` (always) |
| `BeaconDetector<K>` | `observe(K, ts, bytes)` from flow stats | `Option<BeaconScore<K>>` |
| `DgaScorer` | `score(&str)` from DNS qname SLDs | `DgaScore` (pure) |

Each detector's *dispatch* is inherently per-detector — the
upstream event sources differ (TCP handshake completion vs flow
inter-arrival vs DNS qname). Trying to unify *input* is wrong-
shaped work; a wrapper macro can't generically know how to feed
all three. The *output*, however, IS uniform: every score
converts to `OwnedAnomaly`.

So the trait moves to the score side:

```rust
pub trait DetectorScore {
    fn name(&self) -> &'static str;
    fn into_anomaly(self, ts: Timestamp) -> OwnedAnomaly;
}

impl<K: KeyFields + Clone> DetectorScore for ScanScore<K> { … }
impl<K: KeyFields + Clone> DetectorScore for BeaconScore<K> { … }
impl                        DetectorScore for DgaScore        { … }
```

Consumer code:

```rust
// Per-detector dispatch (necessary; inputs differ).
let score = port_scan.observe(key, success);

// Uniform emit (via DetectorScore).
eve.write_owned_anomaly(&score.into_anomaly(ts))?;

// Generic-over-score routing through DetectorScore:
fn emit<S: DetectorScore>(eve: &mut EveJsonWriter<W>, s: S, ts: Timestamp) -> io::Result<()> {
    eve.write_owned_anomaly(&s.into_anomaly(ts))
}
```

netring's `detector!` macro stays per-detector for the feed
side (which it has to be), but the emit side is uniform via
`DetectorScore`. The macro shrinks ~30% vs the round-1 draft.

The `DetectorScore` trait + per-score impls ship together in
Plan 147 (combined with `OwnedAnomaly` + writer methods). No
separate Plan 148 file.

### §3.3 Narrow Plan 149 to `drain_n` alone — drop `swap`/`SlotBuf`

Round 1 (draft): ship `drain_n` + an opaque `SlotBuf<M,K>`
newtype for atomic-swap drain.

Round 2 (this pass): drop `swap`/`SlotBuf` entirely from 0.13.
Rationale:

- `SegQueue::pop()` is ~10-15ns per call. Draining 10K messages
  in a loop costs ~150µs. Downstream emit (JSON serialisation +
  I/O) dwarfs this by 10-100×. The micro-optimisation isn't
  felt.
- `SlotBuf` introduces a new public newtype + pool-management
  semantics + a documented clone-race contract. That's
  significant API surface for an optimisation that doesn't
  materially help.
- If a future benchmark proves drain_n is the bottleneck (it
  almost certainly won't be), `swap`/`SlotBuf` can be added
  additively in 0.14 with the same shape.

drain_n alone is the real P1 win — it's the bounded-batch back-
pressure tool that netring's Phase C sharded runloop needs.

### §3.4 Drop `PcapFlowSource::replay_at_wall_clock`

The wishlist proposes two pcap pacing knobs: `with_speed_factor`
(rate) and `replay_at_wall_clock` (timestamp rewrite). The
second is niche — consumers wanting "play as if it started now"
can apply the offset themselves at the consumer layer.
`with_speed_factor` is the high-value addition. Plan 152 also
documents the tokio-blocking caveat explicitly (the iterator
uses `std::thread::sleep`).

### §3.5 Simplify Plan 154 — layer over `KeyIndexed<K, T>`

`KeyIndexed<K, V>` (shipped 0.12 with `new_unbounded`) already
implements the TTL + LRU + per-key-timestamp machinery that
FlowStateMap needs. Wrapping it cuts FlowStateMap from ~200 LoC
to ~80 LoC.

### §3.6 Tighten Plan 147 with `SmallVec` + `&'static str` labels

`OwnedAnomaly`'s `observations` and `metrics` use
`SmallVec<[..; 4]>` instead of `Vec`. Typical detectors produce
2-5 of each — well under the inline threshold. Zero allocations
in the hot construction path.

Labels switch from `Cow<'static, str>` to `&'static str` — every
shipped detector's label is a compile-time constant, and the
ergonomic loss for runtime labels (rare) is one extra
`Box::leak` if needed.

### §3.7 Don't gate plans 143/146 behind features (already shipped)

This isn't on the wishlist; flagging it as a follow-up since I
noticed during the audit. The 0.12 cycle shipped `detect::patterns`
(plan 143) without a feature gate (always on under `tracker`).
That's the right call — they're pure-Rust, no extra deps, small
LoC. Just noting it so the 0.13 cycle doesn't accidentally add
a `detect-patterns` feature gate when wiring `DetectorScore` impls.

---

## §4 Backwards-compatibility ledger

The user authorised breaking-change cycles. Here's what each plan
breaks:

| Plan | Break | Migration |
|---|---|---|
| 147+151 | Add `OwnedAnomaly` — non-breaking | n/a |
| 148 | New trait `Detector`; existing direct calls unchanged | n/a |
| 149 | Add `drain_n`, `swap`, `SlotBuf<M,K>` — non-breaking | n/a |
| 150 | Add `BroadcastSlotHandle<M,K>` + builder variants — non-breaking | n/a |
| 152 | Add `with_speed_factor` — non-breaking | n/a |
| 153 | Add `test_helpers::events` module — non-breaking | n/a |
| 154 | Add `FlowStateMap<T,K>` — non-breaking | n/a |
| 155 | Pure docs — non-breaking | n/a |
| 156 | **`Driver<E>: Send` unconditionally** — additive on the type but tightens implicit bounds. Code that *relied* on `!Send` (rare; would have to use a `PhantomData<*const ()>` workaround) breaks. | None expected in practice. |

Net: **0.13 is effectively additive**. The "break" I'm green-lit
for goes unused. The `Send` change tightens bounds but loosens
constraints (more code works on Driver, none stops working).

The one *user-visible* change that consumers should be told
about in the CHANGELOG: the doc comments saying "Driver<E> is
!Send" become "Driver<E> is Send".

---

## §5 Phasing for 0.13

Suggested 4-PR series (was 5 in round 1; consolidation drops
Plan 148 into Plan 147).

| PR | Plans | Reason for ordering |
|---|---|---|
| 1 | **156** | One-line structural fix. Ships Send+Sync `Driver<E>` first so subsequent plans can lean on it. |
| 2 | **147** | `OwnedAnomaly` + `DetectorScore` + per-score impls + EVE/NDJSON writer methods. The biggest plan; ships the whole detector-output story coherently. |
| 3 | **149, 150** | `SlotHandle::drain_n` + `BroadcastSlotHandle`. Both touch the slot module. |
| 4 | **152, 153, 154, 155** + CHANGELOG/CLAUDE.md sweep | DX additions + release-shape doc updates. All independent. |

Each PR is independently reviewable + ships clean. PRs 1-3 are
the P0/P1 minimum-viable cycle (ship as 0.13.0). PR 4 can be a
post-release 0.13.1 if release calendar pressure dictates.

---

## §6 Open questions answered

The wishlist's §15 lists 8 design questions. My calls:

| # | Question | Verdict |
|---|---|---|
| Q1 | Plan 147 `anomaly.type` policy | `&'static str` in `EveOptions::custom_anomaly_type`, default `"applayer"`. |
| Q2 | Plan 148 `Input<'a>` GAT vs `dyn Any` | **Neither — drop the input-side trait entirely.** Per-detector dispatch is per-detector by necessity. The output-side `DetectorScore` trait carries the uniform-routing benefit. |
| Q3 | Plan 149 `swap_into` API leakage | **Drop `swap` entirely from 0.13.** Ship `drain_n` alone. `swap` is a v0.14 follow-up if benchmarks justify. |
| Q4 | Plan 150 broadcast subscriber Mutex | `Mutex<Vec<Weak>>`. Profile later if churn shows up. |
| Q5 | Plan 151 `OwnedAnomaly` `Cow` vs `String` | `Cow<'static, str>` for `kind` and observation *values*; `&'static str` for observation/metric *labels* (compile-time constants). `SmallVec<[..; 4]>` for the observations/metrics vectors. |
| Q6 | Plan 154 `FlowStateMap` default tick cadence | Tie sweep to `idle_timeout`; consumer drives `sweep()` from a tick hook. |
| Q7 | Plan 155 `core_affinity` | Skip in shipped example; mention in recipe doc. |
| Q8 | Plan 156 alternative | **None of A/B/C.** The premise is wrong; no `unsafe`, no shards, no `dashmap`. Add `+ Send + Sync` to the trait object + a `P: Send + Sync` bound on builder methods. |

---

## §7 What stays out of 0.13

Echoing the wishlist's §14 + my own pass:

- **`cargo semver-checks` CI.** Defer to whoever drives the
  1.0 push.
- **`flowscope-export` sister crate.** No consumer ask; sketch
  only in §12 of the wishlist.
- **JA4+ family / IPFIX / HTTP/2 / QUIC.** Same reasons as the
  0.12 cycle deferral. Captured in
  [`INDEX.md`](./INDEX.md) under "Deferred to a future cycle".
- **Pre-1.0 stability audit.** Discussion item for 0.14 / 0.15.

Plus my own additions:

- **`detect-patterns` feature gate.** Not adding one; the
  patterns are always-on under `tracker`.
- **`replay_at_wall_clock` on `PcapFlowSource`.** Dropped from
  plan 152 (low value; consumer-side trivial).

---

## §8 References

- Source wishlist: [`0.13-wishlist-from-netring.md`](./0.13-wishlist-from-netring.md)
- Plan files:
  [147](./147-owned-anomaly-eve.md) (absorbs wishlist 147+148+151) ·
  [149](./149-slothandle-drain-n.md) ·
  [150](./150-broadcast-slothandle.md) ·
  [152](./152-pcap-replay-pacing.md) ·
  [153](./153-test-helpers-events.md) ·
  [154](./154-flow-state-map.md) ·
  [155](./155-sharded-recipe.md) ·
  [156](./156-send-driver.md)
- Verification source-anchors:
  `src/driver/typed.rs:205` (the `+ Send` site) ·
  `src/driver/typed_slot.rs:37-53` (`ErasedSlot` trait) ·
  `src/driver/slot.rs:55-131` (`SlotHandle`) ·
  `src/detect/patterns/{portscan,beacon,dga}.rs` (detector APIs) ·
  `src/emit/eve.rs:112-184` (EVE writer) ·
  `src/anomaly_fields.rs:45-104` (KeyFields / AnomalyFields) ·
  `src/correlate/indexed.rs` (KeyIndexed foundation for FlowStateMap)
