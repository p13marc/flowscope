# Plan 126 — `AnomalyFields` trait: structured field access

## Summary

Introduce a small always-on `AnomalyFields` trait that lets
emit writers (EVE, NDJSON, custom) pull structured fields off a
flow key + an `AnomalyKind` without going through `Debug`
formatting. Default implementations on `FiveTupleKey` (5-tuple
fields), `L4Proto` (proto string), and `AnomalyKind` (anomaly
classification per the Suricata EVE schema).

Downstream crates (netring's `AnomalySink` / `EveSink`)
delegate to this trait instead of carrying their own EVE
field extraction.

## Status

Not started.

## Prerequisites

None.

## Out of scope

- **A `Display`-replacement `Debug` mod.** This trait is for
  *structured* access; the existing `Debug` and `Display`
  impls stay.
- **App-protocol detection.** `app_proto_str()` returns `None`
  by default. The slot wrapper (`SlotMessage<M, K>`) carries
  the parser_kind alongside the message; consumers wanting
  `app_proto: "http"` thread that themselves. We don't try to
  re-derive it inside `AnomalyFields`.
- **JSON serialisation.** The trait exposes typed accessors
  (`IpAddr`, `u16`, `&'static str`); the EVE writer (plan 123)
  is responsible for serialising. Keeps `AnomalyFields`
  dependency-free.

## Files

| Action | Path | Purpose |
|---|---|---|
| New | `src/anomaly_fields.rs` | Trait + default impls |
| Modify | `src/lib.rs` | `pub mod anomaly_fields;` + `pub use anomaly_fields::AnomalyFields;` |
| Modify | `src/extract/five_tuple.rs` | `impl AnomalyFields for FiveTupleKey` |
| Modify | `src/extractor.rs` | `impl AnomalyFields for L4Proto` |
| Modify | `src/event.rs` | `impl AnomalyFields for AnomalyKind` |
| New | `docs/anomaly-fields.md` | Extension recipe for custom keys |

## API

```rust
// src/anomaly_fields.rs
use std::net::IpAddr;

/// Structured access to flow-key / anomaly-kind fields for
/// emit writers (EVE, NDJSON, custom).
///
/// All methods default to `None` so implementors only override
/// the fields they actually carry. Emit writers MUST tolerate
/// `None` returns — they correspond to "field not applicable
/// for this key type" (e.g. `src_port()` on an IP-only key).
///
/// # Implementing for custom keys
///
/// Custom `FlowExtractor::Key` types should implement this
/// trait if they want to flow through EVE / NDJSON without
/// fallback `Debug` formatting:
///
/// ```ignore
/// use std::net::IpAddr;
/// use flowscope::AnomalyFields;
///
/// pub struct MyKey { src: IpAddr, dst: IpAddr }
///
/// impl AnomalyFields for MyKey {
///     fn src_ip(&self) -> Option<IpAddr> { Some(self.src) }
///     fn dest_ip(&self) -> Option<IpAddr> { Some(self.dst) }
/// }
/// ```
pub trait AnomalyFields {
    /// Source IP for the flow.
    fn src_ip(&self) -> Option<IpAddr> { None }

    /// Source port (TCP/UDP).
    fn src_port(&self) -> Option<u16> { None }

    /// Destination IP for the flow.
    fn dest_ip(&self) -> Option<IpAddr> { None }

    /// Destination port (TCP/UDP).
    fn dest_port(&self) -> Option<u16> { None }

    /// L4 protocol as a static EVE-compatible label: `"TCP"` /
    /// `"UDP"` / `"ICMP"` / `"ICMPv6"`.
    fn proto_str(&self) -> Option<&'static str> { None }

    /// Application-layer protocol label, e.g. `"http"` / `"dns"` /
    /// `"tls"`. Default `None`; emit writers thread the parser
    /// kind from `SlotMessage` instead.
    fn app_proto_str(&self) -> Option<&'static str> { None }

    /// EVE `anomaly.type` classification. Suricata schema:
    /// `"stream"` (transport-layer state), `"decode"` (frame
    /// integrity), `"applayer"` (parser-driven). Default `None`
    /// — only implemented on `AnomalyKind`.
    fn anomaly_type(&self) -> Option<&'static str> { None }

    /// EVE `anomaly.event` — the stable slug. Default `None`;
    /// `AnomalyKind` implements via `short_kind()`.
    fn anomaly_event(&self) -> Option<&'static str> { None }
}
```

### Impl on `FiveTupleKey`

```rust
// src/extract/five_tuple.rs
impl crate::AnomalyFields for FiveTupleKey {
    fn src_ip(&self) -> Option<std::net::IpAddr> { Some(self.a.ip()) }
    fn src_port(&self) -> Option<u16> { Some(self.a.port()) }
    fn dest_ip(&self) -> Option<std::net::IpAddr> { Some(self.b.ip()) }
    fn dest_port(&self) -> Option<u16> { Some(self.b.port()) }
    fn proto_str(&self) -> Option<&'static str> { self.proto.proto_str() }
}
```

### Impl on `L4Proto`

```rust
// src/extractor.rs
impl crate::AnomalyFields for L4Proto {
    fn proto_str(&self) -> Option<&'static str> {
        Some(match self {
            L4Proto::Tcp    => "TCP",
            L4Proto::Udp    => "UDP",
            L4Proto::Icmp   => "ICMP",
            L4Proto::IcmpV6 => "ICMPv6",
            L4Proto::Sctp   => "SCTP",
            L4Proto::Other(_) => return None,
        })
    }
}
```

### Impl on `AnomalyKind`

**Note**: only the 6 actual variants shipping in 0.11.1 are
classified. Mappings derived from Suricata EVE conventions.

```rust
// src/event.rs
impl crate::AnomalyFields for AnomalyKind {
    fn anomaly_type(&self) -> Option<&'static str> {
        Some(match self {
            // Transport-layer / reassembly state machine.
            AnomalyKind::BufferOverflow { .. }
            | AnomalyKind::OutOfOrderSegment { .. }
            | AnomalyKind::RetransmittedSegment { .. }
            | AnomalyKind::ReassemblerHighWatermark { .. } => "stream",
            // Parser-driven application-layer anomaly.
            AnomalyKind::SessionParseError { .. } => "applayer",
            // Tracker-global capacity pressure. Suricata's EVE
            // schema doesn't have a "system" type — we map to
            // "stream" as the closest fit (capacity affects the
            // stream-tracking layer).
            AnomalyKind::FlowTableEvictionPressure { .. } => "stream",
            // _ => return None,  // when new variants land,
            //                      they default to None until
            //                      classified. CHANGELOG
            //                      convention requires updating
            //                      this `match` in the same PR.
        })
    }

    fn anomaly_event(&self) -> Option<&'static str> {
        Some(self.short_kind())
    }
}
```

Once new `AnomalyKind` variants are added, this `match` raises
an exhaustiveness warning — same mechanism as
`src/obs.rs::anomaly_label`. Convention: adding a variant
requires updating both arms in the same change.

## Implementation steps

1. Create `src/anomaly_fields.rs` with the trait + extensive
   rustdoc + a doctest showing how to impl for a custom key.
2. Add `pub mod anomaly_fields;` and the re-export to
   `src/lib.rs`.
3. Implement on `FiveTupleKey` in
   `src/extract/five_tuple.rs`.
4. Implement on `L4Proto` in `src/extractor.rs`.
5. Implement on `AnomalyKind` in `src/event.rs`.
6. Update `src/obs.rs::anomaly_label` and `AnomalyFields` for
   `AnomalyKind`'s exhaustiveness comment block — pair them so
   the next variant addition trips both.
7. Add `docs/anomaly-fields.md` with the custom-key recipe.
8. CHANGELOG entry.

## Tests

In `src/anomaly_fields.rs` (or `tests/anomaly_fields.rs`):

- `five_tuple_key_returns_split_ip_port_proto`
- `l4proto_other_returns_none`
- `anomaly_kind_classifies_buffer_overflow_as_stream`
- `anomaly_kind_classifies_session_parse_error_as_applayer`
- `anomaly_kind_classifies_flow_table_eviction_as_stream`
- `anomaly_kind_event_matches_short_kind` — the event string
  matches the existing `AnomalyKind::short_kind` / metrics
  label; confirms the single-source-of-truth invariant.
- `custom_key_default_impl_returns_none` — a no-override impl
  yields `None` everywhere.

## Acceptance criteria

- `cargo test --all-features` clean.
- `cargo clippy --all-features --all-targets -- -D warnings` clean.
- `cargo doc --all-features --no-deps` clean; the doctest on
  the trait builds.
- Plan 123 (EVE writer) can build on top — `EveJsonWriter` calls
  `key.src_ip()`, `kind.anomaly_type()`, etc., without going
  through `Debug`.
- `docs/anomaly-fields.md` shows the custom-key recipe.

## Risks

- **R1: `AnomalyKind` variant coverage drift.** Adding a new
  variant requires also updating the `anomaly_type` match arm.
  Mitigation: same convention already applies to
  `src/obs.rs::anomaly_label`. Document both sites under the
  "single vocabulary across event stream and metrics" entry in
  INDEX.md's Conventions section, expanding to include
  `anomaly_fields.rs`.
- **R2: Trait shape locked at 0.12.** Future EVE fields
  (`pkts_toserver` per-flow, `bytes_toserver`, etc.) belong on
  a different trait (per-flow stats, not per-anomaly). Mitigate
  by being explicit in the trait name and rustdoc: it's about
  anomaly schema, not full flow schema.
- **R3: `app_proto_str` returns `None` everywhere by default.**
  Consumers may want `app_proto: "http"` to flow through. The
  EVE writer (plan 123) reads `parser_kind` from
  `SlotMessage<M, K>` instead and writes that as `app_proto`.
  Document explicitly that `AnomalyFields::app_proto_str`
  isn't the right path for that — it's only for keys that
  carry app-layer hints natively (custom keys).

## Effort

| Step | LoC | Hours |
|---|---|---|
| `anomaly_fields.rs` + trait + doc | 100 | 3 |
| Impl on `FiveTupleKey` | 15 | 0.5 |
| Impl on `L4Proto` | 20 | 0.5 |
| Impl on `AnomalyKind` | 40 | 1.5 |
| Tests | 80 | 2 |
| `docs/anomaly-fields.md` + CHANGELOG | 40 | 0.5 |
| **Total** | **~295** | **~8 hours (1 day)** |

Wishlist's "2 days" was conservative; the trait shape is small
and uncontroversial.

## Provenance

Triggered by netring 0.21's `AnomalyKey` trait ask. Pushes the
structured-field knowledge into flowscope where the key types
are owned; netring's `AnomalyKey` collapses to a re-export.
Independent of any specific emit writer — useful for NDJSON
and custom emitters too, not just EVE (plan 123).
