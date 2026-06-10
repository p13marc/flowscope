# flowscope 0.12 — wishlist driven by netring 0.21

**Date:** 2026-06-10
**Source:** Distilled from [`netring-0.21-roadmap.md`](./netring-0.21-roadmap.md) §5 and the verification work in [`netring-api-evolution-justification.md`](./netring-api-evolution-justification.md). Plans are written in flowscope's existing 12-section template so they can be dropped into [`flowscope/plans/`](../../flowscope/plans/) as-is.

## How to read this doc

1. **§1 — Asks at a glance.** One-line summary table.
2. **§2 — Verification.** What I confirmed by reading flowscope source before writing each ask. Catches "this is already shipped" and "this is intentionally deferred — here's why we're triggering the revisit."
3. **§3–§9 — Detailed plan files (122–127).** Six full plans formatted per flowscope's `NN-*.md` template. Each is independently shippable; the order minimizes lockstep migrations.
4. **§10 — Deferred-from-this-cycle.** What I considered but kicked out.

The asks total ~12 days of flowscope work for a 0.12 cycle. **All P0/P1 unblock netring 0.21 phases; deferring them pushes netring 0.21 work to flowscope 0.13.**

---

## §1 Asks at a glance

| # | Plan | Title | Priority | Effort | Unblocks |
|---|---|---|---|---|---|
| 122 | [§3](#plan-122--flowscope-mt-feature--sendable-slothandle) | `flowscope-mt` feature — `Send`-able `SlotHandle` (lock-free) | **P0** | ~3 days | netring 0.21 Phase C (sharding), multi-thread tokio runtime |
| 123 | [§4](#plan-123--flowscopeemiteve--suricata-eve-json-writer) | `flowscope::emit::eve` — Suricata EVE JSON writer | **P1** | ~3 days | netring 0.21 Phase B.2 (EveSink) |
| 124 | [§5](#plan-124--driverregister_protocolsslice-batch-registration) | `Driver::register_protocols(slice)` batch registration | **P1** | ~1 day | netring 0.21 Phase E (pcap_source) |
| 125 | [§6](#plan-125--correlate-new_unbounded-constructors) | `correlate::*::new_unbounded(window, bucket)` constructors | **P2** | ~half day | netring 0.21 Phase G (drop netring's correlate.rs) |
| 126 | [§7](#plan-126--anomalyfields-trait--key--l4proto--anomalykind-eve-bridge) | `AnomalyFields` trait — `FiveTupleKey` + `L4Proto` + `AnomalyKind` EVE bridge | **P2** | ~2 days | netring 0.21 Phase B.1 (AnomalyKey trait) |
| 127 | [§8](#plan-127--timestamp-iso-8601-rfc-3339-rendering--chrono-feature) | `Timestamp::write_iso8601`, `from_chrono`, `to_chrono` | **P3** | ~half day | EVE/NDJSON timestamp rendering ergonomics |

Cumulative effort: **~10 days**. Single-cycle.

---

## §2 Verification: each ask checked against current flowscope source

Before writing the plans, I confirmed each ask against `/var/home/mpardo/git/flowscope/`:

### Plan 122 (`flowscope-mt`) — confirmed needed

Existing `SlotHandle<M, K>` at [`src/driver/slot.rs:57-64`](../../flowscope/src/driver/slot.rs) uses `Rc<RefCell<SlotBuf<M, K>>>` — `!Send + !Sync` by design (docstring says so explicitly).

Flowscope's [`plans/INDEX.md:170-174`](../../flowscope/plans/INDEX.md) "Deferred items" list says:

> **Per-slot `Arc<Mutex<…>>` slot bufs (Send slot handles)** — the typed `SlotHandle<M, K>` is `Rc<RefCell>`-backed and intentionally `!Send`. Cross-task delivery is netring's job (drain inside the event loop, post over channels). Revisit if a consumer needs a Send variant.

**netring 0.21 is now that consumer.** Two concrete needs:

1. **Phase C (sharding)** — N per-CPU shards each running a `current_thread` runtime on its own OS thread. Each shard owns its full driver + handles. The handles never cross shards but must be `Send` because `std::thread::spawn` needs `Send` for the moved closure.
2. **Multi-thread tokio runtime users** — today users must wrap Monitor in `LocalSet::run_until` to keep the `!Send` future pinned. A `Send` future would let `tokio::spawn(monitor.run_for(d))` work directly on the default runtime.

Mutex isn't the right answer — at 1–2 Mpps the lock overhead bites. Better: a lock-free queue via `crossbeam_queue::SegQueue` (Send + Sync, ~5ns per push/pop on uncontended workloads). See the plan for the full design.

### Plan 123 (`flowscope::emit::eve`) — confirmed flowscope is the right home

flowscope already owns [`src/emit/`](../../flowscope/src/emit/) with `csv.rs`, `ndjson.rs`, `zeek.rs`. EVE is a sibling. Putting it in flowscope (not netring) means:
- Offline pcap users get EVE without depending on netring.
- The format work lives next to the other format writers — one place to keep the schema in lockstep when flowscope changes `AnomalyKind`.
- netring's `EveSink` is then a thin `AnomalySink → EveJsonWriter` adapter, not a duplicate of the schema work.

### Plan 124 (`register_protocols(slice)`) — confirmed feasible

Current driver builder at [`src/driver/typed.rs`](../../flowscope/src/driver/typed.rs) takes one protocol per method call (`session_on_ports`, `datagram_on_ports`, `session_heuristic`, etc.). Each call returns a typed `SlotHandle<M, K>`.

The friction in netring: `MonitorBuilder::protocol::<P>()` mutates the `driver_builder` mid-chain, which forces "all `.protocol::<P>()` calls before `.pcap_source()` or `.interface()` (since they need a driver built)." A batch API decouples "what protocols" from "where they get registered." Mostly cosmetic but enables Phase E pcap_source.

### Plan 125 (`new_unbounded`) — confirmed mismatch

Current `TimeBucketedCounter::new(window, bucket, capacity)` in [`src/correlate/bucketed.rs:44`](../../flowscope/src/correlate/bucketed.rs) takes 3 args. netring's at [`netring/src/correlate.rs`](../netring/src/correlate.rs) takes 2 args (no capacity). When netring 0.21 drops its duplicate and re-exports flowscope's, users see an API change.

The cleanest fix: ship `new_unbounded(window, bucket)` alongside `new(window, bucket, capacity)` in flowscope, matching netring's existing shape. netring just removes its file and re-exports. No user-facing API break.

### Plan 126 (`AnomalyFields` trait) — confirmed needed for EVE

EVE's anomaly schema wants top-level 5-tuple fields (`src_ip`, `src_port`, `dest_ip`, `dest_port`, `proto`, `app_proto`) plus a nested `anomaly` object. Today netring's `AnomalyWriter::with_key(&dyn Debug)` only exposes the key via `format!("{:?}")` — useless for serialization. flowscope's `FiveTupleKey` doesn't have an EVE-fields writer.

Best home: an `AnomalyFields` trait in flowscope that `FiveTupleKey` + `L4Proto` + `AnomalyKind` all implement. netring's `AnomalyKey` trait (Phase B.1) then delegates to it. No EVE-specific types in netring.

### Plan 127 (`Timestamp::write_iso8601`) — confirmed gap

flowscope's [`Timestamp`](../../flowscope/src/timestamp.rs) has `from_unix_f64` / `to_unix_f64` / `from_system_time` / `to_system_time` but **no ISO 8601 rendering**. EVE format requires `2026-06-10T12:34:56.789Z`. NDJSON dashboards expect the same.

Wall-clock formatting requires either chrono, or careful hand-rolled (leap year, etc.). The right scope is: add `write_iso8601(&mut impl Write)` hand-rolled (no chrono dep in default features) + optional `chrono` feature that adds `From<DateTime<Utc>>` / `Into<DateTime<Utc>>` for users who want to interop.

---

## §3 Plan 122 — `flowscope-mt` feature: Sendable `SlotHandle`

### Summary

Add an opt-in `mt` Cargo feature that introduces a second `SlotHandle` variant — `MtSlotHandle<M, K>` — backed by `Arc<crossbeam_queue::SegQueue<SlotMessage<M, K>>>` instead of `Rc<RefCell<SlotBuf<M, K>>>`. The new handle is `Send + Sync`, supports the same `drain` / `pending` / `clear` / `parser_kind` surface, and is selected at driver-builder time via a new `DriverBuilder::mt()` finalizer (or a builder-mode flag).

Existing `SlotHandle<M, K>` (Rc-backed) stays the default — no change for offline pcap users or single-thread netring runs. Multi-thread netring runs opt in with one builder call.

### Status

Not started.

### Prerequisites

None. Self-contained in `src/driver/`.

### Out of scope

- **Tokio integration.** No `tokio::sync::*` types in flowscope (hard rule).
- **Cross-thread driver itself.** The `Driver<E>` stays single-threaded — only the handle side is Send. The driver runs on one thread; handles can be moved to other threads to drain.
- **Lock-based fallback.** If `crossbeam-queue` isn't available, the feature won't compile; no Mutex variant.

### Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/driver/mt_slot.rs` | `MtSlotHandle<M, K>` + `MtSlotBuf<M, K>` |
| Modify | `src/driver/typed.rs` | `DriverBuilder::mt() -> MtDriverBuilder<E>`; `MtDriverBuilder` mirrors `DriverBuilder` but returns `MtSlotHandle` from `session_on_ports` / `datagram_on_ports` / etc. |
| Modify | `src/driver/mod.rs` | `pub use mt_slot::MtSlotHandle;` when feature `mt` |
| Modify | `Cargo.toml` | Add `mt` feature, `crossbeam-queue = { version = "0.3", optional = true }` |
| Modify | `src/lib.rs` | `#[cfg(feature = "mt")] pub use driver::MtSlotHandle;` |
| New | `tests/driver_mt.rs` | Cross-thread drain test, Send/Sync assertion via static_assertions |

### API

New types (gated on `feature = "mt"`):

```rust
// src/driver/mt_slot.rs
use std::sync::Arc;
use crossbeam_queue::SegQueue;

use crate::Timestamp;
use crate::driver::slot::SlotMessage;

/// `Send + Sync` slot handle for use with `MtDriverBuilder`.
/// Backed by `Arc<SegQueue<SlotMessage<M, K>>>` — lock-free MPMC
/// queue with ~5–10ns push/pop on uncontended workloads.
pub struct MtSlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    pub(super) inner: Arc<SegQueue<SlotMessage<M, K>>>,
    pub(super) parser_kind: &'static str,
}

impl<M, K> MtSlotHandle<M, K>
where
    M: Send + 'static,
    K: Send + 'static,
{
    pub fn drain(&mut self, out: &mut Vec<SlotMessage<M, K>>) -> usize {
        let mut n = 0;
        while let Some(msg) = self.inner.pop() {
            out.push(msg);
            n += 1;
        }
        n
    }
    pub fn pending(&self) -> usize { self.inner.len() }
    pub fn parser_kind(&self) -> &'static str { self.parser_kind }
    pub fn clear(&mut self) { while self.inner.pop().is_some() {} }
}

// Clone hands out another consumer to the same queue (MPMC).
impl<M, K> Clone for MtSlotHandle<M, K> where M: Send + 'static, K: Send + 'static { … }
```

Builder finalizer:

```rust
// src/driver/typed.rs
impl<E: FlowExtractor> DriverBuilder<E> {
    /// Promote this builder to its multi-thread variant. All
    /// subsequent `session_on_ports` / `datagram_on_ports` /
    /// `session_heuristic` calls return `MtSlotHandle` instead
    /// of `SlotHandle`. The built driver is unchanged — only the
    /// handle representation differs.
    #[cfg(feature = "mt")]
    pub fn mt(self) -> MtDriverBuilder<E> { … }
}
```

`MtDriverBuilder` mirrors `DriverBuilder`'s methods but returns `MtSlotHandle`. The internal slot impl writes via `SegQueue::push` instead of `RefCell::borrow_mut().push`. Cost per emitted message: ~5–10ns vs ~1–2ns for Rc/RefCell — meaningful at 10 Mpps, negligible at 1 Mpps.

### Implementation steps

1. Add `crossbeam-queue = { version = "0.3", optional = true }` and `mt = ["dep:crossbeam-queue"]` to `Cargo.toml`. Verify `cargo build --features mt` compiles.
2. Create `src/driver/mt_slot.rs` with `MtSlotHandle` + `MtSlotBuf` (the `MtSlotBuf` is just the `Arc<SegQueue>` newtype the slot uses internally for symmetry with `SlotBuf`).
3. Add `cfg(feature = "mt")] mod mt_slot;` + `pub use mt_slot::MtSlotHandle;` to `src/driver/mod.rs`.
4. In `src/driver/typed.rs`, copy the `DriverBuilder<E>` impl into `MtDriverBuilder<E>` behind `#[cfg(feature = "mt")]`. Each per-protocol method (`session_on_ports`, `datagram_on_ports`, `session_heuristic`) constructs an `MtSlotHandle` instead of a `SlotHandle` and the internal slot's `emit_message` pushes onto the SegQueue.
5. Add `static_assertions::assert_impl_all!(MtSlotHandle<u32, u32>: Send, Sync);` in `tests/driver_mt.rs`.
6. Write `tests/driver_mt.rs::concurrent_drain` — spawn a thread with the handle, run the driver on the main thread, assert all messages arrive across the thread boundary.
7. Document the perf cost in the `MtSlotHandle` rustdoc: "~5–10 ns per drained message (SegQueue MPMC) vs ~1–2 ns for `SlotHandle` (Rc/RefCell). The Send-ability is worth the cost when sharding or running on a multi-thread runtime; not worth it for single-thread tokio."
8. Update `docs/concepts.md` with a "single-thread vs multi-thread handles" section.
9. CHANGELOG entry under `## 0.12.0` with the migration recipe: "single-thread users: nothing changes; multi-thread users: add `mt` to your `[dependencies] flowscope = { features = ["mt"] }`, swap `let builder = Driver::builder(ext);` for `let builder = Driver::builder(ext).mt();`."

### Tests

- **Unit**: `mt_slot::tests` — `drain_returns_pushed`, `pending_counts`, `clear_drops_all`, `concurrent_push_and_drain` (one thread pushes 10k, another drains, all received).
- **Integration**: `tests/driver_mt.rs::send_sync_assertions`, `tests/driver_mt.rs::cross_thread_drain_basic`.
- **Bench addition**: `benches/zero_alloc.rs::driver_track_mt_with_5_http_slots` — measures the allocator overhead of the SegQueue path. Expected: ~0 allocs steady-state (SegQueue grows on push but reuses freed blocks).

### Acceptance criteria

- `cargo build --features mt` clean.
- `cargo test --features mt` passes.
- `cargo clippy --features mt --all-targets -- -D warnings` clean.
- `static_assertions::assert_impl_all!(MtSlotHandle<u32, u32>: Send, Sync);` compiles.
- New cross-thread test demonstrates handle moving across threads.
- Existing single-threaded `SlotHandle` tests unchanged.
- CHANGELOG migration recipe verified by manually porting one netring sharded test.

### Risks

- **R1: SegQueue allocator pressure.** SegQueue internally grows by linked-list blocks (~8 messages per block). For zero-alloc steady state, we need to verify that push/pop reuse freed blocks. Bench addition catches this; fallback is `ArrayQueue` (bounded) with a per-slot capacity knob.
- **R2: `Clone` semantics differ.** Today's `SlotHandle::clone` hands out a second handle to the same Rc-backed buffer; the new `MtSlotHandle::clone` hands out a second consumer to the same SegQueue. With SegQueue being MPMC, both consumers race for messages. Document explicitly: "cloned `MtSlotHandle`s race for the queue's messages — only clone if you want competitive consumption." For single-consumer scenarios (the common case), use one handle.

### Effort

- LOC delta: +250 (mt_slot.rs ~150, typed.rs additions ~80, tests ~80, Cargo.toml + docs ~20).
- Time estimate: **3 days** including bench and migration docs.

### Provenance

Triggered by netring 0.21 Phase C (per-CPU sharding) per [`netring-0.20-phase-F3-handler-cloning-analysis.md`](./netring-0.20-phase-F3-handler-cloning-analysis.md). Also unblocks the multi-thread runtime use case documented in netring's [`src/monitor/mod.rs:32-37`](../netring/src/monitor/mod.rs).

---

## §4 Plan 123 — `flowscope::emit::eve`: Suricata EVE JSON writer

### Summary

Add `EveJsonWriter<W>` to `flowscope::emit`, mirroring the existing `FlowEventNdjsonWriter` / `ZeekConnLogWriter` / `FlowEventCsvWriter` shape. Emits one JSON line per event in [Suricata EVE format](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html), schema-compatible with Filebeat's Suricata module, Splunk's Suricata TA, Tenzir's `read_suricata`, and Elastic Common Schema.

Behind `emit-eve` feature (gated like `emit-ndjson`).

### Status

Not started.

### Prerequisites

- Plan 126 (AnomalyFields trait) for clean 5-tuple field extraction. Can be developed in parallel but lands second.
- Plan 127 (`Timestamp::write_iso8601`) for the timestamp field. Can be developed in parallel but lands second.

### Out of scope

- **Suricata rule alerts.** EVE's `event_type: "alert"` carries Suricata SID/GID/rev metadata that flowscope doesn't have. We emit `event_type: "anomaly"` and `event_type: "flow"` only.
- **Custom EVE event types** (HTTP, DNS, TLS per-message). 0.13 can add `eve_http`, `eve_dns`, `eve_tls` emitters if a consumer asks; 0.12 only ships the lifecycle + anomaly emit.
- **HEC (HTTP Event Collector) push.** Output is `impl Write` only.

### Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/emit/eve.rs` | `EveJsonWriter`, `EveOptions`, EVE schema renderer |
| Modify | `src/emit/mod.rs` | `mod eve; pub use eve::{EveJsonWriter, EveOptions};` |
| Modify | `Cargo.toml` | `emit-eve = ["dep:serde_json", "serde"]` |
| New | `tests/emit_eve.rs` | Schema fixtures vs golden JSON, severity-numeric mapping test |
| New | `docs/eve-format.md` | Mapping table from flowscope events to EVE fields |

### API

```rust
// src/emit/eve.rs
pub struct EveJsonWriter<W: Write> {
    sink: W,
    options: EveOptions,
    flow_id_counter: u64,
    scratch: serde_json::Map<String, serde_json::Value>,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct EveOptions {
    /// Pretty-print one indented JSON per event (default `false`).
    /// NOT valid EVE — each record spans multiple lines. Use only
    /// for human inspection.
    pub pretty: bool,
    /// Interface name to embed as `in_iface` (default empty).
    pub in_iface: String,
    /// Include `event_type: "flow"` records for FlowEnded
    /// (default `true`).
    pub include_flow: bool,
    /// Include `event_type: "anomaly"` for FlowAnomaly /
    /// TrackerAnomaly (default `true`).
    pub include_anomalies: bool,
    /// Include `event_type: "stats"` for FlowTick
    /// (default `false`; high cardinality).
    pub include_stats: bool,
    /// Override `event_type: "alert"` severity numeric for
    /// flowscope's anomaly severity (default: high=1, low=4 per
    /// EVE convention — note this is INVERTED from flowscope's
    /// Severity enum where Critical > Warning > Info).
    pub severity_numeric: fn(crate::event::Severity) -> u8,
}

impl<W: Write> EveJsonWriter<W> {
    pub fn new(sink: W, options: EveOptions) -> Self { … }
    /// Emit one event. Skipped variants (per options) produce
    /// no output. Returns `Err` only on the underlying write
    /// failure.
    pub fn write_event<K: AnomalyFields>(&mut self, ev: &FlowEvent<K>) -> io::Result<()> { … }
    pub fn flush(&mut self) -> io::Result<()> { … }
}
```

EVE schema produced (for `event_type: "anomaly"`):

```json
{
  "timestamp": "2026-06-10T12:34:56.789Z",
  "flow_id": 1234567890,
  "in_iface": "eth0",
  "event_type": "anomaly",
  "src_ip": "10.0.0.1", "src_port": 12345,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "anomaly": {
    "type": "stream",
    "event": "out_of_window",
    "code": 0
  }
}
```

For `event_type: "flow"`:

```json
{
  "timestamp": "2026-06-10T12:34:56.789Z",
  "flow_id": 1234567890,
  "event_type": "flow",
  "src_ip": "10.0.0.1", "src_port": 12345,
  "dest_ip": "10.0.0.2", "dest_port": 80,
  "proto": "TCP",
  "flow": {
    "pkts_toserver": 7,
    "pkts_toclient": 5,
    "bytes_toserver": 2400,
    "bytes_toclient": 14000,
    "start": "2026-06-10T12:34:50.000Z",
    "end": "2026-06-10T12:34:56.789Z",
    "age": 6,
    "state": "established",
    "reason": "fin",
    "alerted": false
  }
}
```

### Implementation steps

1. Add `emit-eve` feature to `Cargo.toml`.
2. Create `src/emit/eve.rs` with the writer + options.
3. Map flowscope's `EndReason` to EVE's flow.reason strings ("fin" / "rst" / "timeout" / "eviction" / "forced").
4. Map flowscope's `AnomalyKind` to EVE's `anomaly.type` ("stream" / "decode" / "applayer") + `anomaly.event` (the kind string). Document the mapping in `docs/eve-format.md`.
5. Severity-numeric mapping: flowscope's `Severity::Critical = 1, Error = 2, Warning = 3, Info = 4` so the EVE `severity` field ports without inversion. Document explicitly that this is opposite of flowscope's Rust enum order (Critical > Error > Warning > Info > Min).
6. `flow_id` generation: hash the `FiveTupleKey` (proto + sorted IP/port pair) with a stable hasher (fnv or rapidhash). Document the deterministic hash so two flowscope instances on the same traffic produce the same flow_id.
7. Timestamp rendering via `Timestamp::write_iso8601` (plan 127).
8. Tests: golden-JSON fixtures for FlowStarted, FlowEnded, FlowAnomaly, TrackerAnomaly. Use `serde_json::from_str(line).unwrap()` to verify each line parses back.
9. Doc the per-event allocation cost: one `serde_json::Map` per emit (the scratch), reused across calls.

### Tests

- `eve_anomaly_event_matches_golden_fixture`.
- `eve_flow_event_includes_expected_fields`.
- `eve_severity_numeric_mapping_critical_is_1_info_is_4`.
- `eve_flow_id_deterministic_for_same_5tuple`.
- `eve_pretty_print_is_multiline`.
- `eve_disabled_event_types_produce_no_output`.

### Acceptance criteria

- `cargo build --features emit-eve` clean.
- `cargo test --features emit-eve` passes.
- Golden fixtures match a hand-validated reference (cross-check against `suricata --runmode single -r tests/fixtures/sample.pcap` if available).
- `docs/eve-format.md` documents the field mapping.
- Example: `examples/emit_eve_pcap.rs` writes an `eve.json` from a pcap, suitable for `cat eve.json | jq 'select(.event_type=="anomaly")'`.

### Risks

- **R1: serde_json wire-format drift.** The serde_json `Map` insertion order is preserved on the `preserve_order` feature flag. Without that flag, field order is hash-based and may not match Suricata's. EVE consumers shouldn't rely on field order, but human readability suffers. **Mitigation**: enable `preserve_order` on serde_json behind the `emit-eve` feature.
- **R2: ECS field-name drift.** Elastic's ECS sometimes renames fields. The flowscope EVE writer ships v1 fixed to Suricata 7.x EVE; users who want ECS-strict can pipe through Logstash. Document the schema version explicitly.

### Effort

- LOC delta: +500 (eve.rs ~250, tests ~150, docs + example ~100).
- Time estimate: **3 days**.

### Provenance

Triggered by netring 0.21 §3.2. Filebeat's Suricata module, Splunk Suricata TA, and Tenzir's read_suricata all parse EVE natively — shipping EVE makes flowscope-produced traffic data immediately useful to existing SIEM operators without translation work.

---

## §5 Plan 124 — `Driver::register_protocols(slice)` batch registration

### Summary

Add a batch-registration shape to `DriverBuilder`: `register_protocols([&dyn ProtocolDescriptor])` that takes a slice of "protocol specifications" (extractor type, port set, parser instance) and returns a `Vec<SlotHandle>` in the same order. Lets consumers (netring's `MonitorBuilder`) defer driver construction past the per-protocol registration step.

The existing per-protocol methods (`session_on_ports`, `datagram_on_ports`, `session_heuristic`) stay — this is additive.

### Status

Not started.

### Prerequisites

None.

### Out of scope

- **Trait-object–based parser registration.** Each `ProtocolDescriptor` is still strongly typed at construction (the slice is `&[ProtocolDescriptor]` not `Box<dyn Any>`). The batching is a registration-shape change, not a type-erasure change.
- **Runtime-discovered parsers.** No dlopen, no plugin loading.

### Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/driver/registration.rs` | `ProtocolDescriptor` enum + batch register impl |
| Modify | `src/driver/typed.rs` | `DriverBuilder::register_protocols(&[ProtocolDescriptor]) -> Vec<SlotHandle<…>>` |

### API

```rust
// src/driver/registration.rs
pub enum ProtocolDescriptor<'a> {
    SessionOnPorts {
        parser_factory: Box<dyn FnOnce() -> Box<dyn AnySessionParser> + 'a>,
        ports: &'a [u16],
    },
    DatagramOnPorts {
        parser_factory: Box<dyn FnOnce() -> Box<dyn AnyDatagramParser> + 'a>,
        ports: &'a [u16],
    },
    SessionHeuristic {
        parser_factory: Box<dyn FnOnce() -> Box<dyn AnySessionParser> + 'a>,
        signature: SignatureFn,
    },
    // …
}
```

Honestly this gets ugly fast because each parser has its own `Message` associated type. The clean API needs HRTB or a sealed trait.

**Revised, simpler proposal:** instead of a polymorphic `ProtocolDescriptor`, ship a builder-state snapshot. `DriverBuilder::snapshot() -> DriverSnapshot<E>` that returns a value the caller can pass around, then `.build_from_snapshot(snapshot) -> Driver<E>` builds the driver later. No new descriptor type; just defer construction.

The two patterns to support:

1. **Synchronous flow** (current):
   ```rust
   let mut b = Driver::builder(ext);
   let h1 = b.session_on_ports(HttpParser::default(), [80]);
   let h2 = b.datagram_on_ports(DnsUdpParser::default(), [53]);
   let driver = b.build();
   ```

2. **Deferred flow** (new):
   ```rust
   let mut b = Driver::builder(ext);
   let h1 = b.session_on_ports(HttpParser::default(), [80]);
   let h2 = b.datagram_on_ports(DnsUdpParser::default(), [53]);
   // … some time later, after the source is known:
   let driver = b.build();   // identical
   ```

Wait — that's already the current API. What netring actually needs is for **the registration calls to NOT need the `Driver::builder(ext)` step to have happened yet**. In netring's `MonitorBuilder::protocol::<P>()` chain, the user might call `.protocol::<P>()` before they've picked the extractor (which happens at `.build()`).

The real ask is **`DriverBuilder::new()` that defers extractor selection**:

```rust
let mut b = DriverBuilder::new();              // extractor undetermined
let h1 = b.session_on_ports(HttpParser::default(), [80]);
b.with_extractor(FiveTuple::bidirectional());  // pick later
let driver = b.build();
```

This is cleaner: `DriverBuilder` becomes a state machine `{extractor: Option<E>, slots: …}`. `session_on_ports` doesn't need the extractor type because slot construction only needs `E::Key` at the type level, which the builder can carry as a generic.

Actually, simpler: ship `DriverBuilder::with_extractor(self, ext) -> Driver<E>` as the finalizer instead of `.build()`. The builder is generic from creation but the extractor instance is provided last.

### API (revised — extractor-late builder)

```rust
// src/driver/typed.rs
impl<E: FlowExtractor> DriverBuilder<E> {
    /// Construct a builder without immediately committing to a
    /// concrete extractor instance. The extractor type `E` is
    /// fixed at builder creation; the *instance* is provided at
    /// build time. Useful for consumers (netring's MonitorBuilder)
    /// that determine the extractor after registering protocols.
    pub fn deferred() -> Self { … }

    /// Build with a caller-supplied extractor instance. Requires
    /// that the builder was created via `deferred()`. Equivalent
    /// to constructing via `Driver::builder(ext)` then `.build()`
    /// up front, but flexible about when the extractor is chosen.
    pub fn build_with(self, ext: E) -> Driver<E> { … }
}
```

This is small, additive, and exactly what netring needs.

### Implementation steps

1. Add `DriverBuilder::deferred()` constructor that initializes `extractor: Option<E>` as `None`.
2. Modify `build()` to call `extractor.expect("builder created without extractor; use build_with(ext) instead")`.
3. Add `build_with(self, ext)` that stamps the extractor and delegates to `build()`.
4. Update netring's `MonitorBuilder::protocol::<P>()` to use `DriverBuilder::deferred()` (after this lands).
5. Tests: builder with deferred-then-build_with produces same Driver as up-front build.

### Tests

- `deferred_builder_produces_same_driver_as_immediate`.
- `deferred_builder_build_without_extractor_panics`.

### Acceptance criteria

- New tests pass; existing tests unaffected.
- netring's MonitorBuilder can call `.protocol::<P>()` before any `.interface(...)` / `.pcap_source(...)` and the driver is built correctly at `.build()` time.

### Risks

- **R1: Builder validation looser.** Calling `build()` without an extractor today is a compile-time error; the deferred path makes it a runtime panic. Mitigate by linting at netring's call site: `MonitorBuilder::build()` always calls `build_with(ext)`.

### Effort

- LOC delta: +50.
- Time estimate: **1 day** including netring-side integration tests.

### Provenance

Triggered by netring 0.21 §4.2 (`MonitorBuilder::pcap_source(path)`). Today the netring builder mutates the driver_builder mid-chain, which forces "register all protocols before specifying the source." Deferred extractor selection breaks that ordering constraint.

---

## §6 Plan 125 — `correlate::*::new_unbounded` constructors

### Summary

Add `new_unbounded(window, bucket)` overloads to `TimeBucketedCounter`, `KeyIndexed`, `TimeBucketedSet`, `BurstDetector`, `TopK` — matching the existing 2-arg shape netring's `correlate.rs` uses today. Lets netring 0.21 Phase G drop its duplicate `correlate` module without changing user-visible signatures.

### Status

Not started.

### Prerequisites

None.

### Out of scope

- **Removing the existing `new(window, bucket, capacity)` ctor.** Pre-1.0 we *could* but there's no win — capacity-bounded callers already use it.

### Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/correlate/bucketed.rs` | Add `new_unbounded(w, b) -> Self` that calls `new(w, b, usize::MAX)` |
| Modify | `src/correlate/indexed.rs` | Same |
| Modify | `src/correlate/set.rs` | Same |
| Modify | `src/correlate/burst.rs` | Same |
| Modify | `src/correlate/topk.rs` | TopK already takes K explicitly; no change needed (verify) |

### API

```rust
impl<K> TimeBucketedCounter<K> where K: Hash + Eq + Clone {
    /// Unbounded capacity. Equivalent to `new(window, bucket, usize::MAX)`.
    pub fn new_unbounded(window: Duration, bucket: Duration) -> Self {
        Self::new(window, bucket, usize::MAX)
    }
}
```

(Identical signature shape for the other three primitives.)

### Implementation steps

1. Add the four `new_unbounded` constructors. Each is a 3-line delegate.
2. Add a doc cross-ref between `new` and `new_unbounded`: "see `new_unbounded(window, bucket)` if you don't want to bound the cache".
3. CHANGELOG: "Added `TimeBucketedCounter::new_unbounded`, `KeyIndexed::new_unbounded`, `TimeBucketedSet::new_unbounded`, `BurstDetector::new_unbounded` — convenience constructors matching the pre-0.10 2-arg shape. Lets downstream crates (netring) drop duplicate primitives and re-export flowscope's directly."

### Tests

- `new_unbounded_equivalent_to_new_with_usize_max`.

### Acceptance criteria

- New constructors compile + dispatch through to the existing impl.
- netring 0.21 Phase G can rewrite `MonitorBuilder::counter::<K>(window, bucket)` to call `flowscope::correlate::TimeBucketedCounter::new_unbounded(window, bucket)` without changing the public netring signature.

### Risks

None.

### Effort

- LOC delta: +30.
- Time estimate: **half day**.

### Provenance

Triggered by netring 0.21 §5.4 / Phase G. The signature mismatch (3-arg flowscope vs 2-arg netring) blocks the cleanup.

---

## §7 Plan 126 — `AnomalyFields` trait — `FiveTupleKey` + `L4Proto` + `AnomalyKind` EVE bridge

### Summary

Introduce a small `AnomalyFields` trait that lets `EveJsonWriter` (plan 123) and downstream consumers (netring's `EveSink`) pull structured fields off a key without going through `Debug` formatting. Default impls on `FiveTupleKey` (5-tuple fields), `L4Proto` (proto string), and `AnomalyKind` (anomaly.type + anomaly.event).

### Status

Not started.

### Prerequisites

None.

### Out of scope

- **Generalized key-fields trait** for arbitrary user-defined keys. Users with custom extractors implement `AnomalyFields` themselves; the trait shape is small enough to do so.

### Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/anomaly_fields.rs` | `AnomalyFields` trait + default impls |
| Modify | `src/lib.rs` | `pub use anomaly_fields::AnomalyFields;` (feature-gated on `emit-eve` or always-on?) |
| Modify | `src/extract/five_tuple.rs` | `impl AnomalyFields for FiveTupleKey` |
| Modify | `src/extractor.rs` | `impl AnomalyFields for L4Proto` |
| Modify | `src/event.rs` | `impl AnomalyFields for AnomalyKind` |

### API

```rust
// src/anomaly_fields.rs
use std::net::IpAddr;
use crate::Timestamp;

/// Structured access to anomaly-relevant fields of a key or value.
/// Implemented for `FiveTupleKey`, `L4Proto`, `AnomalyKind`, and
/// extensible by downstream crates for custom key types.
///
/// Methods return `None` when the field isn't applicable (e.g.
/// `src_port()` for an `IpAddr`-only key). EVE/NDJSON writers
/// emit only fields whose `Some(…)` is returned.
pub trait AnomalyFields {
    fn src_ip(&self) -> Option<IpAddr> { None }
    fn src_port(&self) -> Option<u16> { None }
    fn dest_ip(&self) -> Option<IpAddr> { None }
    fn dest_port(&self) -> Option<u16> { None }
    fn proto_str(&self) -> Option<&'static str> { None }
    fn app_proto_str(&self) -> Option<&'static str> { None }
    /// `anomaly.type` per EVE: "stream" | "decode" | "applayer".
    fn anomaly_type(&self) -> Option<&'static str> { None }
    /// `anomaly.event` per EVE: the event slug, e.g. "out_of_window".
    fn anomaly_event(&self) -> Option<&'static str> { None }
}

impl AnomalyFields for FiveTupleKey {
    fn src_ip(&self) -> Option<IpAddr> { Some(self.a.ip()) }
    fn src_port(&self) -> Option<u16> { Some(self.a.port()) }
    fn dest_ip(&self) -> Option<IpAddr> { Some(self.b.ip()) }
    fn dest_port(&self) -> Option<u16> { Some(self.b.port()) }
    fn proto_str(&self) -> Option<&'static str> { self.proto.proto_str() }
}

impl AnomalyFields for L4Proto {
    fn proto_str(&self) -> Option<&'static str> {
        Some(match self {
            L4Proto::Tcp => "TCP",
            L4Proto::Udp => "UDP",
            L4Proto::Icmp => "ICMP",
            L4Proto::IcmpV6 => "ICMPv6",
            _ => return None,
        })
    }
}

impl AnomalyFields for AnomalyKind {
    fn anomaly_type(&self) -> Option<&'static str> {
        Some(match self {
            // stream/state anomalies
            AnomalyKind::SegmentOutOfWindow
            | AnomalyKind::ReassemblyOverflow
            | AnomalyKind::TcpRstAfterFin
            | AnomalyKind::TcpStateTransition => "stream",
            // decode anomalies
            AnomalyKind::MalformedFrame
            | AnomalyKind::TruncatedPacket => "decode",
            // application-layer anomalies
            AnomalyKind::ParserError
            | AnomalyKind::HttpProtocolViolation
            | AnomalyKind::DnsProtocolViolation
            | AnomalyKind::TlsHandshakeAlert => "applayer",
            _ => return None,
        })
    }
    fn anomaly_event(&self) -> Option<&'static str> {
        // The Display impl on AnomalyKind already produces a stable
        // snake_case slug; reuse it.
        Some(self.as_str())
    }
}
```

### Implementation steps

1. Create `src/anomaly_fields.rs` with the trait.
2. Implement on `FiveTupleKey`, `L4Proto`, `AnomalyKind`.
3. Re-export from `lib.rs`.
4. Update plan 123's `EveJsonWriter::write_event` to call `.src_ip()` etc. instead of formatting the key as `Debug`.
5. Document the trait extensibility in `docs/anomaly-fields.md`.
6. CHANGELOG: "Added `AnomalyFields` trait — structured field access for emit writers. Default impls on `FiveTupleKey`, `L4Proto`, `AnomalyKind`."

### Tests

- `anomaly_fields_for_five_tuple_returns_split_ip_port`.
- `anomaly_fields_for_proto_returns_uppercase_str`.
- `anomaly_fields_for_kind_classifies_into_stream_decode_applayer`.

### Acceptance criteria

- Trait + impls compile.
- `EveJsonWriter` uses the trait (plan 123 depends on this).
- Custom key type with hand-rolled `AnomalyFields` impl exercises the EVE path correctly.

### Risks

- **R1: AnomalyKind variant coverage drift.** Adding a new variant requires also adding the `anomaly_type` arm; CHANGELOG convention already requires touching `src/obs.rs::anomaly_label` for new variants — this would add a third site. **Mitigation**: in `obs.rs` add a single `match` over `AnomalyKind` that drives both labels and EVE classification; new variants raise an exhaustiveness warning that catches drift.

### Effort

- LOC delta: +150.
- Time estimate: **2 days**.

### Provenance

Triggered by netring 0.21 §2.7 (AnomalyKey trait). Pushes the structured-field knowledge into flowscope where the key types are owned. netring's `AnomalyKey` trait becomes a thin re-export.

---

## §8 Plan 127 — `Timestamp` ISO 8601 / RFC 3339 rendering + `chrono` feature

### Summary

Add three things to `Timestamp`:

1. **`write_iso8601(&mut impl Write) -> io::Result<()>`** — hand-rolled ISO 8601 / RFC 3339 emit (no chrono dep). Used by EVE/NDJSON writers.
2. **`to_iso8601(&self) -> String`** — allocating wrapper for convenience.
3. **`#[cfg(feature = "chrono")] From<DateTime<Utc>> + TryInto<DateTime<Utc>>`** — opt-in chrono interop for users who already depend on chrono.

### Status

Not started.

### Prerequisites

None.

### Out of scope

- **Other date formats** (Unix-ms, Unix-µs, RFC 2822). Unix-f64 is already on `Timestamp`; the rest belong in user code.
- **`time` crate interop.** Add if asked.

### Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/timestamp.rs` | Add `write_iso8601` + `to_iso8601` methods; chrono `From`/`TryInto` behind cfg |
| Modify | `Cargo.toml` | `chrono = { version = "0.4", default-features = false, optional = true }` |
| Modify | `Cargo.toml` | Add `chrono` feature with `dep:chrono` |

### API

```rust
impl Timestamp {
    /// Write ISO 8601 / RFC 3339 representation: e.g. "2026-06-10T12:34:56.789Z".
    /// Nanosecond precision; Z (UTC) suffix. Hand-rolled — no
    /// chrono dependency. Zero allocations.
    pub fn write_iso8601<W: Write>(&self, w: &mut W) -> io::Result<()> { … }

    /// Allocating wrapper around `write_iso8601`. Returns the
    /// rendered string.
    pub fn to_iso8601(&self) -> String { … }
}

#[cfg(feature = "chrono")]
impl From<chrono::DateTime<chrono::Utc>> for Timestamp { … }

#[cfg(feature = "chrono")]
impl TryFrom<Timestamp> for chrono::DateTime<chrono::Utc> {
    type Error = chrono::OutOfRange;
    …
}
```

### Implementation steps

1. Implement `write_iso8601` using `chrono`-free logic:
   - Treat `sec` as a Unix epoch second.
   - Compute year/month/day/hour/minute/second via the standard division (the algorithm is small; see e.g. [howardhinnant.github.io/date_algorithms.html](https://howardhinnant.github.io/date_algorithms.html)).
   - Write `YYYY-MM-DDTHH:MM:SS.NNNNNNNNNZ` (9-digit fractional second).
2. Allocating wrapper: `let mut s = String::with_capacity(30); self.write_iso8601(&mut s).unwrap(); s`.
3. Add `chrono` feature + impls behind `#[cfg(feature = "chrono")]`.
4. Tests: known epoch values (`Timestamp::new(0, 0)` → `"1970-01-01T00:00:00.000000000Z"`), plus a fixture date, plus a chrono round-trip if feature is on.

### Tests

- `write_iso8601_epoch_zero`.
- `write_iso8601_known_date`.
- `to_iso8601_matches_write_iso8601`.
- `chrono_roundtrip_preserves_nanos` (gated).

### Acceptance criteria

- ISO 8601 rendering deterministic.
- `write_iso8601` allocates zero bytes (test via [counting allocator from `benches/support/counting_allocator.rs`](../../flowscope/benches/support/counting_allocator.rs)).
- chrono feature off by default; building without it still works.

### Risks

- **R1: Date algorithm correctness.** Year/month/day from epoch seconds is non-trivial. **Mitigation**: cross-check 50 fixture dates against `chrono::DateTime::from_timestamp` in the test suite (which means tests require chrono feature; build without chrono uses the same impl, only tests differ).

### Effort

- LOC delta: +150 (date algorithm ~80, chrono interop ~30, tests ~40).
- Time estimate: **half day**.

### Provenance

EVE format requires ISO 8601 timestamps. NDJSON dashboards expect the same. Today's `Timestamp::Display` is `"sec.nsec"` — useful for debugging but not for log shippers.

---

## §9 Cross-cutting: CHANGELOG + migration

When all six plans land, the flowscope 0.12.0 CHANGELOG header reads roughly:

> **0.12.0 — multi-thread + EVE + correlate ergonomics cycle**
>
> Triggered by the netring 0.21 wishlist. Adds the Send-able `MtSlotHandle` for multi-thread runtimes and per-CPU sharding (plan 122), the Suricata EVE JSON writer for ELK/Splunk/Tenzir interop (plan 123), batch-shape `DriverBuilder::deferred()` for late extractor selection (plan 124), `new_unbounded` correlate constructors for downstream API parity (plan 125), `AnomalyFields` trait for structured EVE field access (plan 126), and ISO 8601 timestamp rendering (plan 127).
>
> No breaking changes. All additions are behind opt-in features (`mt`, `emit-eve`, `chrono`) where they pull dependencies.

Migration recipes: each plan's CHANGELOG snippet is repeated in `docs/migration-0.11-to-0.12.md` alongside copy-paste examples.

---

## §10 Deferred from this cycle

Considered but not pulled in:

### D1 — Per-flow `KeyIndexed`-as-Ctx-state

netring's [`netring-0.21-roadmap.md`](./netring-0.21-roadmap.md) §2.12 raises the per-flow state question. The natural shape uses flowscope's `KeyIndexed<FiveTupleKey, T>`. But:
- The design needs more thought (auto-eviction on `FlowEnded`? on idle timeout?).
- Not blocking any 0.21 phase.
- **Defer to flowscope 0.13 + netring 0.22.**

### D2 — Driver-level `Send` (the whole `Driver<E>`, not just handles)

Plan 122 makes the *handles* Send. The `Driver<E>` itself stays `!Send` because it holds the central tracker's `FlowTracker<E>` which holds `Rc<RefCell<…>>` for the per-flow state machines.

Making `Driver<E>` Send would let users run the entire driver on a multi-thread runtime without `LocalSet`. Cost is much higher — every per-flow state mutation goes through a lock/queue. Defer until a consumer profiles and asks.

### D3 — `event_typed::FlowPacket` upstream

netring 0.21 §2.14 reintroduces `FlowPacket<P>` as a typed event. The work happens in netring, not flowscope — flowscope already emits `Event::FlowPacket { key, side, len, ts, tcp }` so the upstream side is done. Just netring's translation layer needs updating.

### D4 — `flowscope::detect::signatures::ssh_banner` (and friends)

Heuristic signatures for non-HTTP/TLS protocols. Useful but not blocking any 0.21 phase. Add upstream PRs as users ask.

### D5 — Wider `Bytes` use across DNS / TLS parsers

Plan 120 (zero-allocation cycle) already audited DNS + TLS payload types and decided the `28 / 14 allocs/parse` floor lives inside `simple-dns` / `tls-parser`. Rewriting those is per `plans/INDEX.md:163-169` "deferred until a consumer profiles and asks." netring 0.21 doesn't profile and doesn't ask.

### D6 — JA4 family beyond `JA3` / `JA4`

flowscope's `plans/INDEX.md:138-140` defers per-variant JA4 work until a consumer asks. netring's 0.21 roadmap doesn't.

---

## §11 References

### netring source

- [`netring-0.21-roadmap.md`](./netring-0.21-roadmap.md) §5 — the original flowscope ask list (P0–P3).
- [`netring-api-evolution-justification.md`](./netring-api-evolution-justification.md) — verification work behind each ask.
- [`netring-0.20-phase-F3-handler-cloning-analysis.md`](./netring-0.20-phase-F3-handler-cloning-analysis.md) — Phase F.3 sharding analysis (consumer for plan 122).

### flowscope source

- [`flowscope/src/driver/slot.rs`](../../flowscope/src/driver/slot.rs) — `SlotHandle<M, K>` current shape.
- [`flowscope/src/driver/typed.rs`](../../flowscope/src/driver/typed.rs) — `DriverBuilder` current shape.
- [`flowscope/src/emit/`](../../flowscope/src/emit/) — `csv.rs`, `ndjson.rs`, `zeek.rs` (plan 123's siblings).
- [`flowscope/src/correlate/`](../../flowscope/src/correlate/) — `bucketed.rs`, `indexed.rs`, `set.rs`, etc.
- [`flowscope/src/timestamp.rs`](../../flowscope/src/timestamp.rs) — current Timestamp API.
- [`flowscope/src/event.rs`](../../flowscope/src/event.rs) — `AnomalyKind`, `EndReason`, `FlowEvent`.
- [`flowscope/src/extract/five_tuple.rs`](../../flowscope/src/extract/five_tuple.rs) — `FiveTupleKey`.
- [`flowscope/plans/INDEX.md`](../../flowscope/plans/INDEX.md) — flowscope's plan conventions + deferred-items list.
- [`flowscope/CHANGELOG.md`](../../flowscope/CHANGELOG.md) — 0.11.0 / 0.11.1 release notes.

### External

- [Suricata EVE JSON Format — anomaly schema](https://docs.suricata.io/en/latest/output/eve/eve-json-format.html)
- [Suricata EVE JSON Output configuration](https://docs.suricata.io/en/latest/output/eve/eve-json-output.html)
- [Elastic Common Schema (ECS)](https://www.elastic.co/guide/en/ecs/current/index.html)
- [crossbeam-queue::SegQueue](https://docs.rs/crossbeam-queue/latest/crossbeam_queue/struct.SegQueue.html)
- [Crossfire SPSC/MPSC benchmarks (2026)](https://lib.rs/crates/crossfire)
- [Howard Hinnant — date algorithms](https://howardhinnant.github.io/date_algorithms.html)
- [Tenzir read_suricata pipeline](https://docs.tenzir.com/operators/read_suricata) (Tenzir docs, for the use case)
- [Filebeat Suricata module](https://www.elastic.co/guide/en/beats/filebeat/current/filebeat-module-suricata.html)

---

## §12 Open questions

1. **Plan 122 — clone semantics for `MtSlotHandle`.** Should `Clone` hand out a *competitive* consumer (current proposal — both consumers race for messages) or a *broadcast* consumer (both see every message)? Broadcast adds buffering complexity; competitive is the default for SegQueue. **Recommendation:** competitive (matches the underlying queue). Document explicitly.

2. **Plan 123 — `flow_id` deterministic hash.** Should flowscope's `flow_id` derive deterministically from the 5-tuple (same input → same `flow_id`), or be a monotonic counter (one per emit)? Suricata uses a per-flow numeric ID assigned at flow creation; consumers correlate via that. **Recommendation:** monotonic counter per `EveJsonWriter` instance, plus a separate `flow_hash: u64` field carrying the deterministic 5-tuple hash. Users pick whichever fits their pipeline.

3. **Plan 124 — should `DriverBuilder::deferred()` be the default?** Pre-1.0 we could swap. Probably not — single-thread Rc-backed users vastly outnumber the deferred-extractor case. **Recommendation:** keep `Driver::builder(ext)` as the eager path, add `DriverBuilder::deferred()` as the late-bind path.

4. **Plan 126 — `AnomalyFields` always-on vs `emit-eve`-gated?** If always-on, it adds a tiny trait surface to the always-on API. If gated, downstream crates must enable `emit-eve` even if they don't use EVE. **Recommendation:** always-on (the trait has zero deps and the default-method impls cost nothing).

5. **Plan 127 — `chrono` feature dependency tier.** `chrono = "0.4"` with `default-features = false` pulls in `num-traits` only. Light enough to be optional. **Recommendation:** behind `chrono` feature; never in default.

6. **Plan-numbering reuse.** flowscope's `plans/INDEX.md:200-205` lists retired numbers. The next free number is 122+. These six plans claim 122–127. The deferred items D1–D6 stay in the INDEX's "deferred" list under their own narrative; no plan number reservation needed.
