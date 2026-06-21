//! `flowscope::ml_features` — CICFlowMeter-compatible per-flow
//! feature vector subset for ML pipelines.
//!
//! Gated by the `ml-features` Cargo feature. Issue #15 scoped
//! sub-piece — ships the slice of the ~80 CICFlowMeter
//! features that's computable from a finalised [`crate::FlowRecord`]
//! (totals + per-direction byte/packet counts + TCP flag
//! counts + Zeek-style `conn_state` derivation). The
//! per-packet IAT (Inter-Arrival Time) features are NOT here
//! — they need per-packet timestamps which the tracker
//! aggregates away. Use the [`crate::detect::fingerprint`]
//! first-N packet IAT baseline for those.
//!
//! ## What ships
//!
//! [`CicFlowFeatures`] carries:
//!
//! - **Flow duration** (`flow_duration_us`) — flow lifetime in
//!   microseconds.
//! - **Totals** — `total_fwd_packets` / `total_bwd_packets` /
//!   `total_fwd_bytes` / `total_bwd_bytes`.
//! - **Per-direction means** — `fwd_packet_length_mean` /
//!   `bwd_packet_length_mean` / `mean_packet_length`.
//! - **Throughput** — `flow_bytes_per_sec` /
//!   `flow_packets_per_sec`.
//! - **Down/Up ratio** — `down_up_ratio` (responder bytes /
//!   initiator bytes; both directions read as
//!   responder-to-initiator).
//! - **TCP flag counts** — `tcp_fin_flag_count` /
//!   `tcp_syn_flag_count` / `tcp_rst_flag_count` /
//!   `tcp_psh_flag_count` / `tcp_ack_flag_count` /
//!   `tcp_urg_flag_count` / `tcp_ece_flag_count` /
//!   `tcp_cwr_flag_count`.
//! - **Zeek conn_state** — see
//!   [`EndReason::as_zeek_state`](crate::EndReason::as_zeek_state)
//!   for the mapping ("SF", "S0", "REJ", "RSTO", …).
//!
//! ## What does NOT ship (per-packet state required)
//!
//! - Flow IAT mean / std / max / min.
//! - Fwd/Bwd IAT total / mean / std / max / min.
//! - Active/Idle min / mean / max / std.
//! - Per-direction packet-length **std / min / max**.
//! - Bulk + subflow features.
//! - nPrint per-packet header-bit matrix.
//!
//! These need a per-packet IAT tracker — out of scope for
//! the `FlowRecord`-fed pipeline. The
//! [`crate::detect::fingerprint::FlowFingerprint`] first-N
//! baseline is the existing shipped path; a `cicflow-full`
//! feature on top of it would close the gap later.
//!
//! ## Usage
//!
//! ```rust,ignore
//! use flowscope::{FlowRecord, ml_features::CicFlowFeatures};
//!
//! let rec = FlowRecord::from_parts(stats, key, end_reason);
//! let feats = CicFlowFeatures::from_flow_record(&rec);
//! println!("down/up ratio: {:.2}", feats.down_up_ratio);
//! ```

mod conn_state;
mod features;

pub use conn_state::{TcpFlagCounts, count_tcp_flags};
pub use features::CicFlowFeatures;
