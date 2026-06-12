# Plan 162 — `DestUnreachableKind` enum + ICMP module hygiene

> **Absorbs wishlist Plan 166** (`flowscope::icmp::types`
> re-export hygiene). Both touch `src/icmp/mod.rs`; ship them
> together.

## Summary

Unified v4/v6 vocabulary for ICMP Destination Unreachable
codes. Replaces the ~30-line classifier every consumer writes
with a single `IcmpType::dest_unreachable_kind() -> Option<DestUnreachableKind>`
call.

Also fixes the `flowscope::icmp::types` private-module
gotcha (was wishlist plan 166): promote `mod types;` to
`pub mod types`, keep the `pub use types::*;` shim. Both paths
work after.

## Status

Not started. P0 for 0.14.

## Prerequisites

None.

## Out of scope

- **`PacketTooBig` collation.** v6 `PacketTooBig` is type 2,
  not a code under DU. Operationally similar to v4's
  `FragmentationNeeded` (MTU mismatch), but structurally
  separate. Keep `DestUnreachableKind` tight to actual DU
  codes; add a parallel `IcmpType::mtu_signal() -> Option<MtuSignalKind>`
  in 0.15 if a consumer asks.
- **MTU value preservation.** v4's `FragmentationNeeded { mtu: Option<u16> }`
  carries the MTU; the unified `FragmentationNeeded` variant
  is MTU-less. Consumers wanting the MTU match on
  `Icmpv4Type` directly.

## Files

| Action | Path | Purpose |
|---|---|---|
| Modify | `src/icmp/types.rs` | Add `DestUnreachableKind` enum + `IcmpType::dest_unreachable_kind` method + `DestUnreachableKind::as_str` |
| Modify | `src/icmp/mod.rs` | (a) promote `mod types` → `pub mod types`; (b) add `pub use types::DestUnreachableKind` (verify glob already covers it) |
| Modify | `src/lib.rs` | `pub use icmp::DestUnreachableKind` at crate root (parallel to `OwnedAnomaly`) |
| Modify | `src/prelude.rs` | Add `DestUnreachableKind` to the icmp-feature-gated prelude |
| Modify | `tests/icmp_types.rs` (or new) | Mapping table tests for every v4/v6 DU code variant |

## API

### `DestUnreachableKind` enum

```rust
// src/icmp/types.rs

/// Unified v4/v6 vocabulary for ICMP Destination Unreachable
/// codes. Maps the ~17 v4 `Icmpv4DestUnreachCode` variants
/// and the ~8 v6 `Icmpv6DestUnreachCode` variants down to
/// the operationally-distinguishable set.
///
/// Match on the concrete `Icmpv4DestUnreachCode` /
/// `Icmpv6DestUnreachCode` instead if you need the exact
/// v4/v6 code or, for v4 `FragmentationNeeded`, the MTU.
///
/// Plan 162 (0.14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum DestUnreachableKind {
    /// v4: `Host` / `DestHostUnknown` / `SourceHostIsolated`
    /// v6: `AddressUnreachable`
    Host,
    /// v4: `Port`
    /// v6: `PortUnreachable`
    Port,
    /// v4: `Net` / `DestNetworkUnknown`
    /// v6: `NoRoute`
    Network,
    /// v4: `Protocol`
    /// v6: no equivalent
    Protocol,
    /// v4: `NetworkProhibited` / `HostProhibited` /
    /// `CommunicationProhibited` / `PrecedenceCutoffInEffect`
    /// v6: `AdminProhibited` / `RejectRouteToDestination` /
    /// `SourceAddressFailedIngressPolicy`
    AdministrativelyProhibited,
    /// v4: `FragmentationNeeded { mtu }` (mtu lost in the
    /// canonical mapping — match on `Icmpv4Type` directly if
    /// you need the MTU).
    /// v6: no exact equivalent (v6's `PacketTooBig` is type
    /// 2, not a code under DU).
    FragmentationNeeded,
    /// Anything else (v4 `SourceRouteFailed`, `NetworkTos`,
    /// `HostTos`, `HostPrecedenceViolation`, `Other`;
    /// v6 `BeyondScopeOfSource`, `Other`).
    Other,
}

impl DestUnreachableKind {
    /// Stable short slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Host => "host_unreachable",
            Self::Port => "port_unreachable",
            Self::Network => "network_unreachable",
            Self::Protocol => "protocol_unreachable",
            Self::AdministrativelyProhibited => "administratively_prohibited",
            Self::FragmentationNeeded => "fragmentation_needed",
            Self::Other => "dest_unreachable_other",
        }
    }
}
```

### `IcmpType::dest_unreachable_kind` accessor

```rust
// src/icmp/types.rs

impl IcmpType {
    /// Classify a Destination Unreachable into the unified
    /// v4/v6 vocabulary. Returns `None` for non-DU types
    /// (Echo, TimeExceeded, ParameterProblem, etc.).
    ///
    /// Plan 162 (0.14).
    pub fn dest_unreachable_kind(&self) -> Option<DestUnreachableKind> {
        use DestUnreachableKind::*;
        match self {
            IcmpType::V4(Icmpv4Type::DestUnreach { code, .. }) => match code {
                Icmpv4DestUnreachCode::Host
                | Icmpv4DestUnreachCode::DestHostUnknown
                | Icmpv4DestUnreachCode::SourceHostIsolated => Some(Host),
                Icmpv4DestUnreachCode::Port => Some(Port),
                Icmpv4DestUnreachCode::Net
                | Icmpv4DestUnreachCode::DestNetworkUnknown => Some(Network),
                Icmpv4DestUnreachCode::Protocol => Some(Protocol),
                Icmpv4DestUnreachCode::NetworkProhibited
                | Icmpv4DestUnreachCode::HostProhibited
                | Icmpv4DestUnreachCode::CommunicationProhibited
                | Icmpv4DestUnreachCode::PrecedenceCutoffInEffect => {
                    Some(AdministrativelyProhibited)
                }
                Icmpv4DestUnreachCode::FragmentationNeeded { .. } => {
                    Some(FragmentationNeeded)
                }
                _ => Some(Other),
            },
            IcmpType::V6(Icmpv6Type::DestUnreach { code, .. }) => match code {
                Icmpv6DestUnreachCode::AddressUnreachable => Some(Host),
                Icmpv6DestUnreachCode::PortUnreachable => Some(Port),
                Icmpv6DestUnreachCode::NoRoute => Some(Network),
                Icmpv6DestUnreachCode::AdminProhibited
                | Icmpv6DestUnreachCode::RejectRouteToDestination
                | Icmpv6DestUnreachCode::SourceAddressFailedIngressPolicy => {
                    Some(AdministrativelyProhibited)
                }
                _ => Some(Other),
            },
            _ => None,
        }
    }
}
```

(Adjust the match arms to whatever the actual `IcmpType` /
`Icmpv4Type` / `Icmpv6Type` enum shapes are — survey
indicates `DestUnreach { code, … }` is the right shape.)

### ICMP module hygiene (was Plan 166)

```rust
// src/icmp/mod.rs — before
mod types;
pub use types::*;

// after
pub mod types;
pub use types::*;  // backward-compat shim stays
```

Now both `flowscope::icmp::Icmpv6DestUnreachCode` and
`flowscope::icmp::types::Icmpv6DestUnreachCode` resolve; the
rustdoc-suggested path stops lying.

### Crate-root + prelude exports

```rust
// src/lib.rs
#[cfg(feature = "icmp")]
pub use icmp::DestUnreachableKind;

// src/prelude.rs (inside the icmp-feature-gated block)
#[cfg(feature = "icmp")]
pub use crate::icmp::DestUnreachableKind;
```

## Implementation steps

1. Add `DestUnreachableKind` enum + impl block.
2. Add `IcmpType::dest_unreachable_kind` method.
3. Promote `mod types` → `pub mod types` in `src/icmp/mod.rs`.
4. Wire crate-root + prelude exports.
5. Tests covering every v4 + v6 variant's mapping (parameterised).
6. Update `docs/recipes.md` with a 0.14 ICMP recipe.

## Tests

- `every_v4_dest_unreach_code_maps_to_some_kind` (parameterised).
- `every_v6_dest_unreach_code_maps_to_some_kind` (parameterised).
- `dest_unreachable_kind_returns_none_for_echo_request`.
- `dest_unreachable_kind_returns_none_for_time_exceeded`.
- `as_str_returns_stable_slug` (lock the slug strings as a
  regression contract).
- `v4_fragmentation_needed_loses_mtu_in_kind` (documents the
  trade-off explicitly).
- `types_module_is_publicly_reachable` (compile-time check
  that `use flowscope::icmp::types::Icmpv4DestUnreachCode`
  works after the hygiene fix).

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings`
  clean.
- netring 0.22's `IcmpError.kind: DestUnreachableKind`
  becomes a single `evt.icmp_type.dest_unreachable_kind()`
  call.
- `use flowscope::icmp::types::Icmpv6DestUnreachCode`
  compiles (Plan 166 fix verified).

## Risks

**R1: Mapping disagreements with downstream tooling.** What
v4 `SourceHostIsolated` maps to is a judgement call. The
proposed mapping follows the operational FAQ
("this destination unreachable means the host is unreachable").
Mitigation: documented in rustdoc; consumers wanting the exact
code match on `Icmpv4DestUnreachCode` directly.

**R2: MTU loss in `FragmentationNeeded`.** v4 carries the MTU;
the unified kind doesn't. Mitigation: documented; consumers
wanting the MTU don't use the unified kind. The 0.15 cycle's
`mtu_signal()` (if a consumer asks) would carry the MTU
through.

## Effort

- LOC delta: +300 (enum + impl + module promotion + crate-
  root + tests + docs).
- Time estimate: **1 day**.

## Provenance

Wishlist plans 162 + 166 combined.
