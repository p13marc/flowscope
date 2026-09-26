//! Observability hooks — `metrics` counters and `tracing` events.
//!
//! Two independent feature gates:
//!
//! - `metrics` — emits Prometheus / OpenTelemetry-style counters,
//!   gauges, and histograms via the [`metrics`] crate. Behind a
//!   `MetricRecorder` install (handled by the consumer), the
//!   counters end up wherever the recorder routes them.
//! - `tracing` — emits structured events at flow-lifecycle
//!   transitions via the [`tracing`] crate.
//!
//! Both are zero-cost when off (every entry point is a no-op
//! `#[inline(always)]` stub).
//!
//! # Metric vocabulary
//!
//! | Metric | Type | Labels |
//! |--------|------|--------|
//! | `flowscope_flows_created_total` | counter | `l4` (`tcp`/`udp`/`other`) |
//! | `flowscope_flows_ended_total` | counter | `reason` (`fin`/`rst`/`idle`/`evicted`/`force_closed`) |
//! | `flowscope_flows_active` | gauge | — |
//! | `flowscope_packets_unmatched_total` | counter | — |
//! | `flowscope_bytes_total` | counter | `side` (`initiator`/`responder`) |
//! | `flowscope_flow_duration_seconds` | histogram | — |
//! | `flowscope_flow_packets` | histogram | — |
//! | `flowscope_flow_bytes` | histogram | — |
//! | `flowscope_anomalies_total` | counter | `kind` (`buffer_overflow`/`ooo_segment`/`out_of_window_segment`/`stream_gap`/`flow_table_eviction`/`parse_error`/`retransmit`/`reassembler_high_watermark`/`tcp_rexmit_inconsistency`/`global_memcap_hit`) |
//! | `flowscope_reassembly_dropped_ooo_total` | counter | `side` |
//! | `flowscope_reassembly_bytes_dropped_oversize_total` | counter | `side` |
//! | `flowscope_reassembler_high_watermark_bytes` | histogram | `side` |
//! | `flowscope_retransmits_total` | counter | `side` |
//! | `flowscope_parser_closed_total` | counter | `parser_kind`, `reason` |
//! | `flowscope_parser_side_stopped_total` | counter | `parser_kind`, `side`, `reason` |
//! | `flowscope_flow_ticks_total` | counter | — |
//! | `flowscope_http_messages_total` | counter | `direction` (`request`/`response`) |
//! | `flowscope_http_poisoned_total` | counter | `reason` ([`HttpPoison`](crate::http::HttpPoison) slug) |
//!
//! Since 0.25 a parser giving up never ends its flow, so
//! `flowscope_flows_ended_total` only carries transport reasons. What
//! 0.24 counted there as `reason="parse_error"` / `"parser_done"` /
//! `"buffer_overflow"` is now `flowscope_parser_closed_total` with the
//! same `reason` (plus `stream_gap`, and the transport reason for
//! parsers closed at their flow's end), or
//! `flowscope_parser_side_stopped_total` when only one side stopped.
//!
//! # Cardinality
//!
//! All label values are `&'static str` enums. **Never** pass a flow
//! key as a label value — that creates one time series per flow.

use crate::{
    event::{AnomalyKind, EndReason, FlowStats},
    extractor::L4Proto,
};

/// `flowscope_flows_created_total` — incremented on every new flow.
pub const METRIC_FLOWS_CREATED: &str = "flowscope_flows_created_total";
/// `flowscope_flows_ended_total` — incremented on every Ended event.
pub const METRIC_FLOWS_ENDED: &str = "flowscope_flows_ended_total";
/// `flowscope_flows_active` — gauge of live flows in the tracker.
pub const METRIC_FLOWS_ACTIVE: &str = "flowscope_flows_active";
/// `flowscope_packets_unmatched_total` — counter of packets the
/// extractor couldn't classify.
pub const METRIC_PACKETS_UNMATCHED: &str = "flowscope_packets_unmatched_total";
/// `flowscope_bytes_total{side=...}` — total bytes per side
/// (cumulative across all ended flows).
pub const METRIC_BYTES: &str = "flowscope_bytes_total";
/// `flowscope_flow_duration_seconds` — histogram of per-flow
/// durations.
pub const METRIC_FLOW_DURATION_SECONDS: &str = "flowscope_flow_duration_seconds";
/// `flowscope_flow_packets` — histogram of per-flow packet counts.
pub const METRIC_FLOW_PACKETS: &str = "flowscope_flow_packets";
/// `flowscope_flow_bytes` — histogram of per-flow byte totals.
pub const METRIC_FLOW_BYTES: &str = "flowscope_flow_bytes";
/// `flowscope_anomalies_total{kind=...}` — counter of anomaly events
/// emitted by `FlowDriver` when `with_emit_anomalies(true)`.
pub const METRIC_ANOMALIES: &str = "flowscope_anomalies_total";
/// `flowscope_reassembly_dropped_ooo_total{side=...}` — cumulative
/// out-of-order segment drops.
pub const METRIC_REASSEMBLY_DROPPED_OOO: &str = "flowscope_reassembly_dropped_ooo_total";
/// `flowscope_reassembly_bytes_dropped_oversize_total{side=...}` —
/// cumulative bytes dropped due to per-side buffer cap.
pub const METRIC_REASSEMBLY_BYTES_DROPPED_OVERSIZE: &str =
    "flowscope_reassembly_bytes_dropped_oversize_total";
/// `flowscope_reassembler_high_watermark_bytes{side=...}` —
/// histogram of peak buffer occupancy per ended flow.
pub const METRIC_REASSEMBLER_HIGH_WATERMARK: &str = "flowscope_reassembler_high_watermark_bytes";
/// `flowscope_retransmits_total{side=...}` — cumulative TCP segment
/// retransmits classified by the per-side reassembler.
pub const METRIC_RETRANSMITS: &str = "flowscope_retransmits_total";
/// `flowscope_parser_closed_total{parser_kind=..., reason=...}` — a
/// session / datagram parser was closed for a flow: early
/// (`parse_error` / `parser_done` / `stream_gap` / `buffer_overflow`)
/// or at the flow's end (the transport reason). Replaces the
/// parser-related `reason` labels `flowscope_flows_ended_total` had
/// before 0.25 (a parser close no longer ends a flow). New in 0.25.0.
pub const METRIC_PARSER_CLOSED: &str = "flowscope_parser_closed_total";
/// `flowscope_parser_side_stopped_total{parser_kind=..., side=...,
/// reason=...}` — a session parser stopped reading one side of a
/// flow (`stream_gap` / `buffer_overflow`). New in 0.25.0.
pub const METRIC_PARSER_SIDE_STOPPED: &str = "flowscope_parser_side_stopped_total";
/// Counter: bytes the reassembler never saw and skipped as gaps
/// (Zeek's `missed_bytes`), labelled by `side`. New in 0.25.0.
pub const METRIC_REASSEMBLY_GAP_BYTES: &str = "flowscope_reassembly_gap_bytes_total";
/// `flowscope_flow_ticks_total` — total [`crate::FlowEvent::Tick`]
/// events emitted across all flows. Fires once per tick per live
/// flow when [`crate::FlowTrackerConfig::flow_tick_interval`] is
/// `Some`.
pub const METRIC_FLOW_TICKS: &str = "flowscope_flow_ticks_total";

/// HTTP messages framed by the streaming parser, labelled
/// `direction` = `request` | `response`. Issue #168.
pub const METRIC_HTTP_MESSAGES: &str = "flowscope_http_messages_total";

/// Connections the streaming HTTP parser refused, labelled `reason`
/// with the [`HttpPoison`](crate::http::HttpPoison) slug. A rising
/// count here is either an attack or a broken client — both worth an
/// alert. Issue #168.
pub const METRIC_HTTP_POISONED: &str = "flowscope_http_poisoned_total";

// These label functions are hoisted out of the `metrics` cfg gate
// so the `Display` impls on `L4Proto`, `EndReason`, `AnomalyKind`
// (plan 77) can call them under any feature set. They're pure data;
// zero runtime cost.

pub(crate) fn l4_label(l4: Option<L4Proto>) -> &'static str {
    match l4 {
        Some(L4Proto::Tcp) => "tcp",
        Some(L4Proto::Udp) => "udp",
        _ => "other",
    }
}

pub(crate) fn reason_label(reason: EndReason) -> &'static str {
    match reason {
        EndReason::Fin => "fin",
        EndReason::Rst => "rst",
        EndReason::IdleTimeout => "idle",
        EndReason::Evicted => "evicted",
        EndReason::BufferOverflow => "buffer_overflow",
        EndReason::ParseError => "parse_error",
        EndReason::ParserDone => "parser_done",
        EndReason::ForceClosed => "force_closed",
        EndReason::StreamGap => "stream_gap",
    }
}

pub(crate) fn anomaly_label(kind: &AnomalyKind) -> &'static str {
    match kind {
        AnomalyKind::BufferOverflow { .. } => "buffer_overflow",
        AnomalyKind::OutOfOrderSegment { .. } => "ooo_segment",
        AnomalyKind::FlowTableEvictionPressure { .. } => "flow_table_eviction",
        AnomalyKind::SessionParseError { .. } => "parse_error",
        AnomalyKind::RetransmittedSegment { .. } => "retransmit",
        AnomalyKind::ReassemblerHighWatermark { .. } => "reassembler_high_watermark",
        AnomalyKind::TcpRexmitInconsistency { .. } => "tcp_rexmit_inconsistency",
        AnomalyKind::GlobalMemcapHit { .. } => "global_memcap_hit",
        AnomalyKind::StreamGap { .. } => "stream_gap",
        AnomalyKind::OutOfWindowSegment { .. } => "out_of_window_segment",
    }
}

#[cfg(feature = "metrics")]
pub(crate) fn record_flow_created(l4: Option<L4Proto>) {
    metrics::counter!(METRIC_FLOWS_CREATED, "l4" => l4_label(l4)).increment(1);
    metrics::gauge!(METRIC_FLOWS_ACTIVE).increment(1.0);
}

#[cfg(feature = "metrics")]
pub(crate) fn record_flow_ended(reason: EndReason, stats: &FlowStats) {
    metrics::counter!(METRIC_FLOWS_ENDED, "reason" => reason_label(reason)).increment(1);
    metrics::gauge!(METRIC_FLOWS_ACTIVE).decrement(1.0);
    metrics::counter!(METRIC_BYTES, "side" => "initiator").increment(stats.bytes_initiator);
    metrics::counter!(METRIC_BYTES, "side" => "responder").increment(stats.bytes_responder);
    let duration = duration_seconds(stats);
    metrics::histogram!(METRIC_FLOW_DURATION_SECONDS).record(duration);
    metrics::histogram!(METRIC_FLOW_PACKETS)
        .record((stats.packets_initiator + stats.packets_responder) as f64);
    metrics::histogram!(METRIC_FLOW_BYTES)
        .record((stats.bytes_initiator + stats.bytes_responder) as f64);
    // NOTE: reassembly diagnostics are emitted separately by
    // [`record_reassembly_diagnostics`]. The tracker calls
    // `record_flow_ended` with unpatched stats; the driver fills in
    // reassembler-derived fields after the fact and then calls
    // [`record_reassembly_diagnostics`].
}

/// Emit reassembly-diagnostic metrics after the driver has patched
/// per-side reassembler counters into `stats`. Split from
/// [`record_flow_ended`] because the tracker calls the latter from
/// inside `track_with_payload`/`sweep` *before* the driver gets a
/// chance to patch reassembler-derived fields.
#[cfg(all(feature = "metrics", feature = "reassembler"))]
pub(crate) fn record_reassembly_diagnostics(stats: &FlowStats) {
    if stats.reassembly_dropped_ooo_initiator > 0 {
        metrics::counter!(METRIC_REASSEMBLY_DROPPED_OOO, "side" => "initiator")
            .increment(stats.reassembly_dropped_ooo_initiator);
    }
    if stats.reassembly_dropped_ooo_responder > 0 {
        metrics::counter!(METRIC_REASSEMBLY_DROPPED_OOO, "side" => "responder")
            .increment(stats.reassembly_dropped_ooo_responder);
    }
    if stats.reassembly_bytes_dropped_oversize_initiator > 0 {
        metrics::counter!(METRIC_REASSEMBLY_BYTES_DROPPED_OVERSIZE, "side" => "initiator")
            .increment(stats.reassembly_bytes_dropped_oversize_initiator);
    }
    if stats.reassembly_bytes_dropped_oversize_responder > 0 {
        metrics::counter!(METRIC_REASSEMBLY_BYTES_DROPPED_OVERSIZE, "side" => "responder")
            .increment(stats.reassembly_bytes_dropped_oversize_responder);
    }
    if stats.reassembler_high_watermark_initiator > 0 {
        metrics::histogram!(METRIC_REASSEMBLER_HIGH_WATERMARK, "side" => "initiator")
            .record(stats.reassembler_high_watermark_initiator as f64);
    }
    if stats.reassembler_high_watermark_responder > 0 {
        metrics::histogram!(METRIC_REASSEMBLER_HIGH_WATERMARK, "side" => "responder")
            .record(stats.reassembler_high_watermark_responder as f64);
    }
    if stats.retransmits_initiator > 0 {
        metrics::counter!(METRIC_RETRANSMITS, "side" => "initiator")
            .increment(stats.retransmits_initiator);
    }
    if stats.retransmits_responder > 0 {
        metrics::counter!(METRIC_RETRANSMITS, "side" => "responder")
            .increment(stats.retransmits_responder);
    }
    if stats.reassembly_gap_bytes_initiator > 0 {
        metrics::counter!(METRIC_REASSEMBLY_GAP_BYTES, "side" => "initiator")
            .increment(stats.reassembly_gap_bytes_initiator);
    }
    if stats.reassembly_gap_bytes_responder > 0 {
        metrics::counter!(METRIC_REASSEMBLY_GAP_BYTES, "side" => "responder")
            .increment(stats.reassembly_gap_bytes_responder);
    }
}

#[cfg(all(not(feature = "metrics"), feature = "reassembler"))]
#[inline(always)]
pub(crate) fn record_reassembly_diagnostics(_stats: &FlowStats) {}

/// Increment the per-tick counter. Called by [`crate::FlowDriver`]
/// each time it emits a [`crate::FlowEvent::Tick`].
#[cfg(all(feature = "metrics", feature = "reassembler"))]
pub(crate) fn record_flow_tick(_stats: &FlowStats) {
    metrics::counter!(METRIC_FLOW_TICKS).increment(1);
}

#[cfg(all(not(feature = "metrics"), feature = "reassembler"))]
#[inline(always)]
pub(crate) fn record_flow_tick(_stats: &FlowStats) {}

#[cfg(feature = "metrics")]
pub(crate) fn record_packet_unmatched() {
    metrics::counter!(METRIC_PACKETS_UNMATCHED).increment(1);
}

#[cfg(all(
    feature = "metrics",
    feature = "session",
    feature = "extractors",
    feature = "reassembler"
))]
pub(crate) fn record_parser_closed(kind: crate::ParserKind, reason: EndReason) {
    metrics::counter!(
        METRIC_PARSER_CLOSED,
        "parser_kind" => kind.as_str(),
        "reason" => reason_label(reason)
    )
    .increment(1);
}

#[cfg(all(
    not(feature = "metrics"),
    feature = "session",
    feature = "extractors",
    feature = "reassembler"
))]
#[inline(always)]
pub(crate) fn record_parser_closed(_kind: crate::ParserKind, _reason: EndReason) {}

#[cfg(all(
    feature = "metrics",
    feature = "session",
    feature = "extractors",
    feature = "reassembler"
))]
pub(crate) fn record_parser_side_stopped(
    kind: crate::ParserKind,
    side: crate::FlowSide,
    reason: EndReason,
) {
    metrics::counter!(
        METRIC_PARSER_SIDE_STOPPED,
        "parser_kind" => kind.as_str(),
        "side" => side.as_str(),
        "reason" => reason_label(reason)
    )
    .increment(1);
}

#[cfg(all(
    not(feature = "metrics"),
    feature = "session",
    feature = "extractors",
    feature = "reassembler"
))]
#[inline(always)]
pub(crate) fn record_parser_side_stopped(
    _kind: crate::ParserKind,
    _side: crate::FlowSide,
    _reason: EndReason,
) {
}

#[cfg(all(feature = "metrics", feature = "reassembler"))]
pub(crate) fn record_anomaly(kind: &AnomalyKind) {
    metrics::counter!(METRIC_ANOMALIES, "kind" => anomaly_label(kind)).increment(1);
}

#[cfg(feature = "metrics")]
fn duration_seconds(stats: &FlowStats) -> f64 {
    let start = stats.started.to_duration();
    let end = stats.last_seen.to_duration();
    end.saturating_sub(start).as_secs_f64()
}

// No-op stubs when the feature is off. `#[inline(always)]` so the
// compiler strips the call entirely.

#[cfg(not(feature = "metrics"))]
#[inline(always)]
pub(crate) fn record_flow_created(_l4: Option<L4Proto>) {}

#[cfg(not(feature = "metrics"))]
#[inline(always)]
pub(crate) fn record_flow_ended(_reason: EndReason, _stats: &FlowStats) {}

#[cfg(not(feature = "metrics"))]
#[inline(always)]
pub(crate) fn record_packet_unmatched() {}

#[cfg(all(not(feature = "metrics"), feature = "reassembler"))]
#[inline(always)]
pub(crate) fn record_anomaly(_kind: &AnomalyKind) {}

// ── tracing hooks ─────────────────────────────────────────────────
//
// Keys are intentionally omitted from the trace events because
// `FlowExtractor::Key` is not bound to `Debug`. Operators correlate
// flows by timestamp + the structured fields below; the canonical
// flowscope.flow span identity is the (l4, reason) pair plus
// timestamp.

#[cfg(feature = "tracing")]
pub(crate) fn trace_flow_started(l4: Option<L4Proto>) {
    tracing::info!(target: "flowscope.flow", ?l4, "flow started");
}

#[cfg(feature = "tracing")]
pub(crate) fn trace_flow_ended(reason: EndReason, stats: &FlowStats) {
    tracing::info!(
        target: "flowscope.flow",
        ?reason,
        packets = stats.packets_initiator + stats.packets_responder,
        bytes = stats.bytes_initiator + stats.bytes_responder,
        "flow ended"
    );
}

#[cfg(all(feature = "tracing", feature = "reassembler"))]
pub(crate) fn trace_anomaly(kind: &AnomalyKind) {
    // Plan 82: emit severity as a structured field so subscribers
    // can route on it (info / warning / error / critical). Event
    // level stays at warn! — anomalies are always at least notable
    // — but consumers can filter by the field.
    tracing::warn!(
        target: "flowscope.anomaly",
        severity = %kind.severity(),
        ?kind,
        "anomaly"
    );
}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn trace_flow_started(_l4: Option<L4Proto>) {}

#[cfg(not(feature = "tracing"))]
#[inline(always)]
pub(crate) fn trace_flow_ended(_reason: EndReason, _stats: &FlowStats) {}

#[cfg(all(not(feature = "tracing"), feature = "reassembler"))]
#[inline(always)]
pub(crate) fn trace_anomaly(_kind: &AnomalyKind) {}

// ── per-message tracing (Plan 56; revised under plan 131) ──────────
//
// Plan 131 collapsed the former `tracing-messages` Cargo feature
// into always-on under `tracing` + `session` (+ `reassembler` for
// the callers). The bound on `SessionParser::Message` was already
// `Debug`; the feature gate was redundant clutter. To filter the
// "flowscope.message" target out at runtime, wire your
// `tracing-subscriber` `EnvFilter` (e.g.
// `EnvFilter::new("info,flowscope.message=warn")`).

// Gated on `extractors` too: the only callers are the crate-private
// session/datagram engines, which compile only alongside the typed
// `driver` module (see #99, 0.20).
#[cfg(all(
    feature = "tracing",
    feature = "extractors",
    feature = "reassembler",
    feature = "session"
))]
pub(crate) fn trace_session_message<M: std::fmt::Debug>(side: crate::event::FlowSide, msg: &M) {
    tracing::trace!(
        target: "flowscope.message",
        ?side,
        message = ?msg,
        "session message"
    );
}

// Stub for `tracing` off / `session` off — keep the function name
// stable so the call sites don't need cfg gates.
#[cfg(all(
    feature = "extractors",
    feature = "reassembler",
    feature = "session",
    not(feature = "tracing")
))]
#[inline(always)]
pub(crate) fn trace_session_message<M>(_side: crate::event::FlowSide, _msg: &M) {}

// ── Streaming HTTP path (issue #168) ──────────────────────────────
//
// The inline path gets the same counters as the telemetry path, so
// switching a deployment from observing to proxying does not create
// a monitoring gap.

/// Count one framed HTTP message.
#[cfg(all(feature = "metrics", feature = "http"))]
pub(crate) fn record_http_message(is_request: bool) {
    let direction = if is_request { "request" } else { "response" };
    metrics::counter!(METRIC_HTTP_MESSAGES, "direction" => direction).increment(1);
}

#[cfg(all(not(feature = "metrics"), feature = "http"))]
pub(crate) fn record_http_message(_is_request: bool) {}

/// Count one refused connection, by reason.
#[cfg(all(feature = "metrics", feature = "http"))]
pub(crate) fn record_http_poisoned(reason: crate::http::HttpPoison) {
    metrics::counter!(METRIC_HTTP_POISONED, "reason" => reason.as_str()).increment(1);
}

#[cfg(all(not(feature = "metrics"), feature = "http"))]
pub(crate) fn record_http_poisoned(_reason: crate::http::HttpPoison) {}
