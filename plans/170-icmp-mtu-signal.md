# Plan 170 — `IcmpType::mtu_signal()` + `MtuSignalKind`

**Cycle:** 0.14.0 pre-release polish
**Priority:** P0 (operationally critical for blackhole/PMTUD monitors)
**Effort:** ~half day
**Status:** drafted

## Motivation

Plan 162 (`DestUnreachableKind`) deliberately scoped to **Destination
Unreachable codes only**. The wishlist §13 question 2 explicitly
deferred MTU-mismatch handling:

> v4 `FragmentationNeeded { mtu }` is a DU code; v6 `PacketTooBig`
> is a separate type 2 message, not under DU. Two reasonable
> answers: map both into `FragmentationNeeded`, or ship
> `DestUnreachableKind` first and add a parallel
> `IcmpType::mtu_signal()` in 0.15 if asked.
> My pick: the second.

Reversing that decision for 0.14 because:

1. **Operationally identical signal.** v4 FragNeeded and v6
   PacketTooBig are the same control-plane event ("path MTU
   too small for this packet"). The fact that ICMPv6 moved
   `PacketTooBig` to its own type rather than keeping it under
   DU is a wire-format detail every monitor consumer has to
   re-derive.
2. **Path MTU Discovery (PMTUD) is non-optional in IPv6.** Any
   monitor that watches dual-stack traffic needs this signal.
   Blackhole detection ("PMTUD failed → connection stalls
   silently") depends on it.
3. **`DestUnreachableKind::FragmentationNeeded` loses the MTU.**
   This is documented as a known wart in plan 162. `mtu_signal`
   preserves the MTU on both protocol versions.
4. **No 0.15 release pressure.** User explicitly directed
   "do not defer features if you think they have values".

## Proposed shape

```rust
// flowscope::icmp::MtuSignalKind
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub enum MtuSignalKind {
    /// ICMPv4 Destination Unreachable, code 4
    /// ("Fragmentation needed but DF set"). The `mtu` field
    /// carries the next-hop MTU from RFC 1191 if the sender
    /// is RFC 1191-compliant; older senders may report 0.
    FragmentationNeeded { next_hop_mtu: Option<u16> },
    /// ICMPv6 type 2 (Packet Too Big). The `mtu` field is
    /// mandatory in v6 and never 0.
    PacketTooBig { next_hop_mtu: u32 },
}

impl MtuSignalKind {
    /// Stable short slug for metric labels.
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::FragmentationNeeded { .. } => "fragmentation_needed",
            Self::PacketTooBig { .. }        => "packet_too_big",
        }
    }

    /// Unified accessor — both variants in `u32`, even when
    /// the v4 value was unknown (returns `None`).
    pub fn next_hop_mtu(&self) -> Option<u32> {
        match self {
            Self::FragmentationNeeded { next_hop_mtu } => next_hop_mtu.map(u32::from),
            Self::PacketTooBig { next_hop_mtu }        => Some(*next_hop_mtu),
        }
    }
}

impl IcmpType {
    /// Classify a PMTU signal across v4/v6 boundaries. Returns
    /// `None` for non-MTU types.
    pub fn mtu_signal(&self) -> Option<MtuSignalKind>;
}
```

## Files touched

- `src/icmp/types.rs` — new enum + `IcmpType::mtu_signal()` method
- `src/icmp/mod.rs` — already `pub mod types`; no change
- `src/lib.rs` — re-export at crate root: `pub use icmp::MtuSignalKind`
- `src/prelude.rs` — add to prelude under `#[cfg(feature = "icmp")]`

## Tests

- `tests/icmp.rs` (extend existing) — v4 FragNeeded with mtu present + absent;
  v6 PacketTooBig with valid mtu; non-MTU types return None.

## Acceptance criteria

- `IcmpType::mtu_signal()` returns Some for v4 DU code 4 and v6 type 2.
- `MtuSignalKind::as_str()` returns stable labels.
- Re-exported at crate root and in prelude.
- No clippy warnings, no rustdoc warnings.

## Non-goals

- A parallel `mtu_signal_kind` on `Icmpv4DestUnreachCode` directly —
  the `IcmpType::mtu_signal()` shape covers the use case.
- Folding `mtu_signal` into `DestUnreachableKind` retroactively —
  would break existing matches against `FragmentationNeeded`.
