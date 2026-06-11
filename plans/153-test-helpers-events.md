# Plan 153 — `flowscope::test_helpers::events` constructors

## Summary

Add an `events` submodule under the existing `test_helpers`
module (gated on the `test-helpers` feature) with synthetic-
event constructors for each `FlowEvent` and each `driver::Event`
variant. Defaults minimal-required fields. Saves downstream test
crates from the field-init dance.

## Status

Not started. P2 for 0.13.

## Prerequisites

None.

## Out of scope

- **`PacketView` synthesis.** Covered by existing
  `test_helpers::extract::parse::test_frames`.
- **Fuzz harnesses.** Existing proptest helpers cover them.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/test_helpers/events.rs` | Constructor module |
| Modify | `src/test_helpers.rs` (or `src/test_helpers/mod.rs`) | `pub mod events;` |

## API

```rust
// src/test_helpers/events.rs (gated on `test-helpers` feature)
use crate::Timestamp;
use crate::event::{AnomalyKind, EndReason, FlowEvent, FlowSide, FlowStats};

/// `FlowEvent::Started` with `l4 = None`.
pub fn started<K>(key: K, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::Established` with `l4 = None`.
pub fn established<K>(key: K, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::Ended` with `EndReason::IdleTimeout` + empty stats.
pub fn ended<K>(key: K, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::Ended` with supplied reason + stats.
pub fn ended_with<K>(
    key: K, reason: EndReason, stats: FlowStats, ts: Timestamp,
) -> FlowEvent<K> { … }

/// `FlowEvent::Tick` with empty stats.
pub fn tick<K>(key: K, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::FlowAnomaly`.
pub fn flow_anomaly<K>(key: K, kind: AnomalyKind, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::TrackerAnomaly`.
pub fn tracker_anomaly<K>(kind: AnomalyKind, ts: Timestamp) -> FlowEvent<K> { … }

/// `FlowEvent::FlowPacket` minimal: side, len, ts.
pub fn packet<K>(
    key: K, side: FlowSide, len: usize, ts: Timestamp,
) -> FlowEvent<K> { … }

pub mod driver {
    use crate::driver::Event;
    use crate::{L4Proto, Timestamp};

    pub fn flow_started<K>(
        key: K, l4: Option<L4Proto>, ts: Timestamp,
    ) -> Event<K> { … }

    pub fn flow_established<K>(
        key: K, l4: Option<L4Proto>, ts: Timestamp,
    ) -> Event<K> { … }

    pub fn flow_ended<K>(key: K, ts: Timestamp) -> Event<K> { … }

    // … FlowTick, ParserClosed, FlowAnomaly, TrackerAnomaly
}
```

## Implementation steps

1. Write the constructor module.
2. Re-export under `test_helpers` root.
3. Tests: each constructor produces a matchable variant.

## Tests

- `started_constructs_flow_started_variant`.
- `ended_with_supplied_reason_and_stats`.
- `flow_anomaly_kind_round_trips`.
- `driver_flow_started_default_l4_none`.

## Acceptance criteria

- `cargo test --features test-helpers,extractors` clean.
- netring's existing `dummy_flow_started` helpers can be
  replaced with `flowscope::test_helpers::events::driver::flow_started`.

## Risks

**R1: `#[non_exhaustive]` interaction.** Future field additions
to event variants would break the constructors' field-init
expressions. Mitigation: constructors use `Default::default()`
for non-required fields; only public required fields are
positional. Adding a non-`Default` field is a flowscope-internal
API call.

## Effort

- LOC delta: +250.
- Time estimate: **0.5 day**.

## Provenance

Wishlist plan 153.
