# Plan 168 — `FlowSide`-aware accessors on `FlowStats`

## Summary

Pure sugar over existing `FlowStats` fields. Four convenience
methods for the common "report directional bandwidth"
question:

- `bytes_for(side) -> u64`
- `pkts_for(side) -> u64`
- `mean_pkt_size_for(side) -> f64`
- `direction_skew() -> f64`

All read existing fields; no new state, no perf concern.

## Status

Not started. P3 for 0.14.

## Prerequisites

None.

## Out of scope

- **`FlowSide`-aware retransmit accessors.** Possible parallel
  (`retransmits_for(side)`), but the existing
  `FlowStats.retransmits_initiator` / `retransmits_responder`
  fields are already named clearly. Skip.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/event.rs` | Add four methods to `impl FlowStats` |
| Modify | `tests/quick_wins.rs` (or `event.rs` tests inline) | Per-method tests |

## API

```rust
// src/event.rs

impl FlowStats {
    /// Bytes attributed to the given side.
    ///
    /// Plan 168 (0.14).
    pub fn bytes_for(&self, side: FlowSide) -> u64 {
        match side {
            FlowSide::Initiator => self.bytes_initiator,
            FlowSide::Responder => self.bytes_responder,
        }
    }

    /// Packets attributed to the given side.
    ///
    /// Plan 168 (0.14).
    pub fn pkts_for(&self, side: FlowSide) -> u64 {
        match side {
            FlowSide::Initiator => self.packets_initiator,
            FlowSide::Responder => self.packets_responder,
        }
    }

    /// Mean packet size for the given side, in bytes.
    /// Returns `0.0` if the side has zero packets.
    ///
    /// Plan 168 (0.14).
    pub fn mean_pkt_size_for(&self, side: FlowSide) -> f64 {
        let pkts = self.pkts_for(side);
        if pkts == 0 {
            return 0.0;
        }
        self.bytes_for(side) as f64 / pkts as f64
    }

    /// Direction skew. `(bytes_initiator - bytes_responder) /
    /// total_bytes`, in `[-1.0, 1.0]`. Returns `0.0` for empty
    /// flows.
    ///
    /// Positive → initiator-heavy (uploads); negative →
    /// responder-heavy (downloads); zero → balanced.
    ///
    /// Useful for detecting one-sided flows (DoS, scans,
    /// CDN downloads).
    ///
    /// Plan 168 (0.14).
    pub fn direction_skew(&self) -> f64 {
        let total = self.total_bytes();
        if total == 0 {
            return 0.0;
        }
        let init = self.bytes_initiator as f64;
        let resp = self.bytes_responder as f64;
        (init - resp) / total as f64
    }
}
```

## Implementation steps

1. Add the four methods to `impl FlowStats` in `src/event.rs`.
2. Tests covering: zero-flow defaults, balanced flow,
   initiator-heavy, responder-heavy, both-sides-non-zero
   skew arithmetic.

## Tests

- `bytes_for_returns_per_side_count`.
- `pkts_for_returns_per_side_count`.
- `mean_pkt_size_for_zero_packets_returns_zero`.
- `mean_pkt_size_for_balanced_flow`.
- `direction_skew_empty_flow_returns_zero`.
- `direction_skew_initiator_only_returns_one`.
- `direction_skew_responder_only_returns_negative_one`.
- `direction_skew_balanced_returns_zero`.
- `direction_skew_clamps_to_unit_range`.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.

## Risks

None. Pure sugar over existing fields.

## Effort

- LOC delta: +90 (methods + tests + rustdoc).
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 168. Pure sugar — strictly additive.
