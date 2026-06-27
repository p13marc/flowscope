# Migrating from 0.19 to 0.20

The 0.20 cycle is mostly additive (NSM primitives + a 1.0-prep
issue batch). There is **one breaking output-schema change** —
the EVE `flow_hash` field — plus a feature-umbrella fix that may
change what `--features full` pulls in.

## Breaking change — EVE `flow_hash` removed; `community_id` is canonical (#88)

`EveJsonWriter` no longer emits the proprietary 64-bit FNV-1a
`flow_hash` field. The standard Corelight **Community ID**
(`community_id`) is now the sole, portable flow identifier in EVE
output. This applies to both the event-driven path
(`write_event`) and the FlowRecord path (`write_flow_record`).

`community_id` is emitted **only when the crate is built with the
`community-id` feature** (it needs SHA-1 + base64). If you relied
on `flow_hash` being present unconditionally, enable the feature:

```diff
  # Cargo.toml
- flowscope = { version = "0.20", features = ["emit-eve"] }
+ flowscope = { version = "0.20", features = ["emit-eve", "community-id"] }
```

**Dashboard / pipeline migration.** Re-key any correlation on the
new field:

```diff
- | where flow_hash="9f3c0bb2a17f5048"
+ | where community_id="1:wCb3Oy8JZ7qWp0pXm1mUg6yQ7sE="
```

`community_id` is direction-invariant and deterministic (same
guarantees `flow_hash` had) and additionally interoperable with
Zeek / Suricata / Security Onion / Arkime, which all key on it.

**Still need the FNV hash in-process?** It remains available — it
just isn't serialized:

```rust
use flowscope::KeyFields;
let h: Option<u64> = key.stable_hash();      // generic, Option
let h: u64        = five_tuple.stable_hash(); // FiveTupleKey, infallible
```

Treat it as a non-portable sharding / in-memory keying value, not
a cross-tool identifier.

**`FlowRecord` gains `community_id`.** `FlowRecord` now carries a
`community_id: Option<String>` field, populated by `from_parts` /
`from_key_fields` when the `community-id` feature is on. This is
additive (the struct is `#[non_exhaustive]`) and means the
NDJSON / CSV / EVE FlowRecord paths all surface the id.

## Behavior change — `l7` / `full` feature umbrellas corrected (#87)

Before 0.20, `full` carried *fewer* parsers than `l7` and was not
a superset (a long-standing bug masked by `--all-features`).

- **`l7`** now enables **every license-clean protocol parser**
  (the previous 15 plus quic / smb / ldap / kerberos / smtp / ftp
  / snmp / radius / modbus / dnp3 / stun / rdp / wireguard /
  netbios-ns).
- **`full`** is now `l7` + every license-clean capability
  (`tcp_fingerprint`, `asset`, `analysis`, `ml-features`,
  `ml-features-nprint`, `ipfix`, `ipfix-export`, plus the existing
  observability / emit / aggregate / file-hash / fingerprint /
  community-id / pcap / serde / chrono groups). It deliberately
  **excludes** the FoxIO-licensed `ja4plus` suite so `full` stays
  royalty-free-clean.

If you built with `--features full` and want the old, smaller set,
pin the specific parser features you actually use instead of the
umbrella. If you relied on `full` and were silently *missing* the
Tier-2 parsers, they now build in — no action needed.

Compile-time guards in `src/feature_umbrellas.rs` plus new `l7` /
`full` CI matrix entries keep the invariant (`full ⊇ l7`, every
parser in an umbrella) from regressing.

## Additive — per-packet `source_idx` builders (#69)

New one-call builders for the most common live-capture metadata
field (no behavior change):

```rust
use flowscope::{PacketView, RxMetadata, Timestamp};

// On a view (hot path):
let view = PacketView::new(frame, ts).with_source_idx(nic_index);

// Constructing RxMetadata cross-crate (RxMetadata is #[non_exhaustive]):
let meta = RxMetadata::from_source_idx(nic_index);
```

These replace the old three-step
`let mut m = RxMetadata::default(); m.source_idx = n; view.with_rx_metadata(m)`.
