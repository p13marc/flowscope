# Plan 40 — Observability (`metrics` + `tracing`)

## Summary

Wire `metrics` counters and `tracing` spans into the flowscope
tracker + driver. Operators get drop-in Prometheus / OpenTelemetry
/ log integration without writing per-flow instrumentation. Both
features are opt-in (compile-time gated); zero overhead when off.

This plan coordinates with Plan 42 (reassembly observability) — they
share the `AnomalyKind` vocabulary so the metric labels and the
event-stream variants name the same things.

## Status

Not started.

## Prerequisites

- Plan 42 (reassembly observability) — recommended; the
  `flowscope_anomalies_total` counter shares its `AnomalyKind`
  enum. If Plan 40 ships first, the anomaly metric is added later
  by 42.
- Some form of profiling / micro-bench so the `tracing` overhead
  can be measured (ad-hoc; doesn't need a full bench harness).

## Out of scope

- Custom dashboards or scrapers. Ship metric names; users wire
  Prometheus / Grafana / etc.
- Distributed tracing of cross-process flows.
- `flowscope-export` (NetFlow/IPFIX) — see Plan 32 (sister crate
  candidate).
- Per-packet `tracing::debug!` spans by default. Too expensive; opt
  in via a runtime knob.

---

## Goals

1. **Counters** for: flows created, flows ended (per reason), flows
   evicted (separate from ended), unmatched packets, anomalies (per
   kind).
2. **Histograms** for: per-flow byte counts on Ended, per-flow
   duration on Ended, per-flow packet counts on Ended.
3. **Gauges** for: live flow count, reassembler buffer occupancy
   (sum across flows).
4. **Tracing spans** (opt-in): one span per flow lifetime, fields
   for endpoints + protocol + final stats. `INFO`-level for new flows;
   `DEBUG` for per-packet (off by default).

---

## API — metric names

Behind a `metrics` Cargo feature on `flowscope`:

```
flowscope_flows_created_total{l4="tcp"}        counter
flowscope_flows_created_total{l4="udp"}        counter
flowscope_flows_created_total{l4="other"}      counter

flowscope_flows_ended_total{reason="fin"}              counter
flowscope_flows_ended_total{reason="rst"}              counter
flowscope_flows_ended_total{reason="idle"}             counter
flowscope_flows_ended_total{reason="evicted"}          counter
flowscope_flows_ended_total{reason="buffer_overflow"}  counter

flowscope_flows_active                          gauge
flowscope_packets_unmatched_total              counter

flowscope_bytes_total{side="initiator"}        counter (sum across all ended flows)
flowscope_bytes_total{side="responder"}        counter

flowscope_flow_duration_seconds                histogram (per Ended event)
flowscope_flow_packets                         histogram (per Ended event)
flowscope_flow_bytes                           histogram (per Ended event)

# Anomalies — Plan 42 vocabulary
flowscope_anomalies_total{kind="buffer_overflow"}            counter
flowscope_anomalies_total{kind="ooo_segment"}                counter
flowscope_anomalies_total{kind="flow_table_eviction"}        counter

# Reassembler diagnostics (cumulative, from FlowStats on Ended)
flowscope_reassembly_dropped_ooo_total{side="initiator"}             counter
flowscope_reassembly_dropped_ooo_total{side="responder"}             counter
flowscope_reassembly_bytes_dropped_oversize_total{side="initiator"}  counter
flowscope_reassembly_bytes_dropped_oversize_total{side="responder"}  counter
```

> **Naming.** Prefix `flowscope_` (was `netring_flow_` in the
> pre-consolidation draft of this plan; the rename matches the
> single-crate world).

### Cardinality discipline

- **Never** use a flow key (5-tuple, MAC, IP) as a label value. That
  produces one time series per flow.
- Coarse labels only: `l4` (tcp/udp/other), `reason`, `kind`, `side`.
- Histograms have no label-induced cardinality beyond the side
  count.

### Implementation pattern

```rust
#[cfg(feature = "metrics")]
pub(crate) mod obs {
    use crate::{AnomalyKind, EndReason, FlowStats, FlowSide};
    use crate::extractor::L4Proto;

    pub fn record_flow_created(l4: Option<L4Proto>) {
        metrics::counter!("flowscope_flows_created_total", "l4" => l4_label(l4)).increment(1);
        metrics::gauge!("flowscope_flows_active").increment(1.0);
    }

    pub fn record_flow_ended(reason: EndReason, stats: &FlowStats) {
        metrics::counter!("flowscope_flows_ended_total", "reason" => reason_label(reason)).increment(1);
        metrics::gauge!("flowscope_flows_active").decrement(1.0);
        metrics::counter!("flowscope_bytes_total", "side" => "initiator")
            .increment(stats.bytes_initiator);
        metrics::counter!("flowscope_bytes_total", "side" => "responder")
            .increment(stats.bytes_responder);
        let duration = stats.last_seen.duration_since(stats.started)
            .unwrap_or_default().as_secs_f64();
        metrics::histogram!("flowscope_flow_duration_seconds").record(duration);
        metrics::histogram!("flowscope_flow_packets")
            .record((stats.packets_initiator + stats.packets_responder) as f64);
        metrics::histogram!("flowscope_flow_bytes")
            .record((stats.bytes_initiator + stats.bytes_responder) as f64);
        // Reassembly diagnostics.
        if stats.reassembly_dropped_ooo_initiator > 0 {
            metrics::counter!("flowscope_reassembly_dropped_ooo_total", "side" => "initiator")
                .increment(stats.reassembly_dropped_ooo_initiator);
        }
        // ... mirror for responder + bytes_dropped_oversize ...
    }

    pub fn record_packet_unmatched() {
        metrics::counter!("flowscope_packets_unmatched_total").increment(1);
    }

    pub fn record_anomaly(kind: &AnomalyKind) {
        metrics::counter!("flowscope_anomalies_total", "kind" => anomaly_label(kind)).increment(1);
    }

    fn l4_label(l4: Option<L4Proto>) -> &'static str { /* ... */ }
    fn reason_label(reason: EndReason) -> &'static str { /* ... */ }
    fn anomaly_label(kind: &AnomalyKind) -> &'static str { /* ... */ }
}

#[cfg(not(feature = "metrics"))]
pub(crate) mod obs {
    use crate::{AnomalyKind, EndReason, FlowStats};
    use crate::extractor::L4Proto;
    #[inline(always)] pub fn record_flow_created(_: Option<L4Proto>) {}
    #[inline(always)] pub fn record_flow_ended(_: EndReason, _: &FlowStats) {}
    #[inline(always)] pub fn record_packet_unmatched() {}
    #[inline(always)] pub fn record_anomaly(_: &AnomalyKind) {}
}
```

All label values are `&'static str` — no per-call allocations.

---

## API — tracing spans

Behind a `tracing` Cargo feature:

```rust
#[cfg(feature = "tracing")]
fn open_flow_span<K: std::fmt::Debug>(key: &K, l4: Option<L4Proto>) -> tracing::Span {
    tracing::info_span!("flowscope.flow", l4 = ?l4, key = ?key)
}
```

One span per flow on creation; closes when `Ended` fires. Span
fields are populated lazily via `record!` on state transitions.

Per-packet `debug!` events are off by default; gated by an
environment variable check (`FLOWSCOPE_TRACE_PACKETS=1`) at startup
or a feature flag.

---

## Files

### MODIFIED

- `Cargo.toml` — add optional `metrics` and `tracing` deps; wire
  `metrics` and `tracing` features.
- `src/lib.rs` — register the `obs` module; export public metric
  name constants for downstream config.
- `src/tracker.rs` — `obs` calls at each state transition (created,
  ended, evicted, unmatched).
- `src/driver.rs` — `obs::record_anomaly` calls when emitting a
  `FlowEvent::Anomaly` (Plan 42).

### NEW

- `src/obs.rs` — the obs module (both feature variants).
- `docs/OBSERVABILITY.md` — per-metric documentation, recommended
  Prometheus scrape config, Grafana panel queries, label cardinality
  notes.

---

## Cargo.toml deltas

```toml
[features]
# (existing features unchanged)
metrics = ["dep:metrics"]
tracing = ["dep:tracing"]

[dependencies]
metrics = { version = "0.24", optional = true }
tracing = { version = "0.1", default-features = false, features = ["std", "attributes"], optional = true }
```

Both are zero-overhead when off (compile-time stripped via
`#[inline(always)]` no-op stubs).

---

## Implementation steps

1. **Land the `obs` module** with both feature variants.
2. **Wire calls** at each state transition:
   - `FlowTracker::track` / `track_with_payload` — created,
     ended, unmatched.
   - `FlowTracker::sweep` — ended (idle/evicted).
   - `FlowDriver::track` / `sweep` — anomaly (when Plan 42 is wired).
3. **Add tracing spans** via a separate `#[cfg(feature = "tracing")]`
   gate. One span per flow created on first sight; `record!` on
   state transitions; `Drop` of the span guard on Ended.
4. **Document** every metric + label dimension in
   `docs/OBSERVABILITY.md`. Include recommended Prometheus relabeling
   rules and a sample Grafana JSON.
5. **Export** the metric names as public constants:
   ```rust
   pub const METRIC_FLOWS_CREATED: &str = "flowscope_flows_created_total";
   pub const METRIC_FLOWS_ENDED: &str = "flowscope_flows_ended_total";
   pub const METRIC_ANOMALIES: &str = "flowscope_anomalies_total";
   // ...
   ```
6. **Measure overhead**: profile a representative workload with and
   without each feature active; document deltas in
   `docs/PERFORMANCE.md` (created by Plan 41).

---

## Tests

- Compile-only tests covering all four feature combinations
  (metrics on/off × tracing on/off).
- Integration test using `metrics-util::debugging::DebuggingRecorder`
  to snapshot counter values after driving a synthetic pcap; assert
  expected counts.
- Tracing test using `tracing-test` (or `tracing-subscriber`'s
  `with_default`) to capture the per-flow span emission.

---

## Acceptance criteria

- [ ] `metrics` feature compiles cleanly and zero-cost when off.
- [ ] `tracing` feature compiles cleanly and zero-cost when off.
- [ ] All counters / gauges / histograms populate as documented.
- [ ] `flowscope_anomalies_total` aligns with `AnomalyKind` from
      Plan 42 (single vocabulary).
- [ ] `docs/OBSERVABILITY.md` lists every metric, every label,
      cardinality notes, sample queries.
- [ ] Overhead measurement documented in PERFORMANCE.md (target:
      <5% with `metrics`; <10% with `tracing` at INFO).
- [ ] `cargo clippy --all-features --all-targets -- -D warnings` clean.

---

## Risks

1. **`metrics` crate label allocations.** `metrics::counter!`
   accepts string labels which can allocate. Use `&'static str`
   labels everywhere; verify with `cargo expand`.
2. **`tracing` overhead.** Per-flow spans are cheap (one allocation
   per flow on creation). Per-packet `debug!` is expensive — gate
   behind an env var so it stays off in production.
3. **Cardinality explosion.** Don't use flow keys as label values
   — that creates one time series per flow. Stick to coarse labels.
4. **`metrics` ABI churn.** It changed between 0.21 and 0.24. Pin
   the dep; coordinate with netring's `metrics` use if it overlaps.
5. **Plan 42 coordination.** The `AnomalyKind` enum lives in
   flowscope; the metric label generator (`anomaly_label`) is one
   match arm per variant. Keep them in lock-step — add a `#[non_exhaustive]`
   reminder test that fails if a new variant is added without a
   corresponding label arm.
6. **Histogram bucket choice.** `metrics` 0.24 uses recorder-side
   bucket configuration. Document the recommended buckets for
   duration / packets / bytes histograms in OBSERVABILITY.md, but
   leave the choice to the consumer.

---

## Effort

- LOC: ~250 (mostly the obs module + wiring + docs).
- Time: 1.5 days (most effort is OBSERVABILITY.md and verifying
  overhead).

---

## Provenance

Original draft predated the consolidation from `netring-flow*`
workspace into the single `flowscope` crate; metric prefixes have
been renamed `netring_flow_*` → `flowscope_*`. The `AnomalyKind`
coordination with Plan 42 is new — that vocabulary didn't exist
in the original draft.
