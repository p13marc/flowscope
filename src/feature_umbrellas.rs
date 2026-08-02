//! Compile-time guards on the `l7` / `full` Cargo umbrellas (issue #87).
//!
//! Background: before this guard, `full` silently carried *fewer* parsers
//! than `l7` (it was not a superset), so `--features full` quietly omitted
//! most of the Tier-2 protocol work. `--all-features` (docs.rs / CI) masked
//! the gap. These `compile_error!`s make any future drift a hard build
//! failure instead of a silent regression.
//!
//! Invariants enforced:
//!
//! 1. **`l7` enables every license-clean protocol parser.** (The only
//!    parser-ish feature deliberately excluded is the FoxIO-licensed
//!    `ja4plus` suite.)
//! 2. **`full` is a superset of `l7`** — it pulls `l7` directly, and that
//!    edge is itself asserted below.
//! 3. **`full` enables every license-clean capability** (parsers via `l7`,
//!    plus the non-l7 parser/fingerprint/asset/ml/ipfix/observability/emit
//!    groups). `ja4plus` stays excluded so `full` is royalty-free-clean.
//! 4. **Each coarse tier enables its own members** (issue #87) —
//!    `parsers-core` / `parsers-l2l3` / `parsers-tier2` / `ml` / `export` /
//!    `nsm`. `l7` / `full` are recomposed from these tiers, so the leaves
//!    are already covered transitively; the tier guards pin membership even
//!    when a tier is built on its own.
//!
//! This module is intentionally empty at runtime — it exists only for its
//! `cfg`-gated `compile_error!` arms.

// ── 1. `l7` ⊇ every license-clean parser ──────────────────────────────
macro_rules! l7_requires {
    ($($feat:literal),* $(,)?) => {
        $(
            #[cfg(all(feature = "l7", not(feature = $feat)))]
            compile_error!(concat!("`l7` umbrella must enable `", $feat, "`"));
        )*
    };
}

l7_requires!(
    "http",
    "http2",
    "tls",
    "tls-fingerprints",
    "dns",
    "icmp",
    "arp",
    "ndp",
    "dhcp",
    "lldp",
    "cdp",
    "ssh",
    "ntp",
    "ssdp",
    "tftp",
    "mdns",
    "netbios-ns",
    "ftp",
    "smtp",
    "wireguard",
    "modbus",
    "stun",
    "rdp",
    "snmp",
    "radius",
    "quic",
    "smb",
    "ldap",
    "kerberos",
    "dnp3",
);

// ── 2. `full` ⊇ `l7` ──────────────────────────────────────────────────
#[cfg(all(feature = "full", not(feature = "l7")))]
compile_error!("`full` umbrella must be a superset of `l7` (enable `l7`)");

// ── 3. `full` ⊇ every license-clean capability beyond `l7` ─────────────
macro_rules! full_requires {
    ($($feat:literal),* $(,)?) => {
        $(
            #[cfg(all(feature = "full", not(feature = $feat)))]
            compile_error!(concat!("`full` umbrella must enable `", $feat, "`"));
        )*
    };
}

full_requires!(
    "tcp_fingerprint",
    "asset",
    "analysis",
    "ml-features",
    "ml-features-nprint",
    "ipfix",
    "ipfix-export",
    "pcap",
    "metrics",
    "tracing",
    "serde",
    "emit",
    "emit-ndjson",
    "emit-eve",
    "aggregate",
    "chrono",
    "file-hash",
    "fingerprint",
    "community-id",
);

// ── 4. Coarse tiers ⊇ their members (issue #87) ───────────────────────
// `l7` / `full` are recomposed from these tiers, so the invariants above
// already cover the leaves transitively. These extra guards pin each
// tier's own membership so a tier can't silently lose a parser even when
// built on its own (`--features parsers-tier2`).
macro_rules! tier_requires {
    ($tier:literal => $($feat:literal),* $(,)?) => {
        $(
            #[cfg(all(feature = $tier, not(feature = $feat)))]
            compile_error!(concat!("`", $tier, "` tier must enable `", $feat, "`"));
        )*
    };
}

tier_requires!("parsers-core" => "http", "http2", "tls", "dns", "icmp");
tier_requires!("parsers-l2l3" => "arp", "ndp", "lldp", "cdp", "dhcp");
tier_requires!("parsers-tier2" =>
    "ssh", "ntp", "ssdp", "tftp", "mdns", "netbios-ns", "ftp", "smtp",
    "wireguard", "modbus", "stun", "rdp", "snmp", "radius", "quic",
    "smb", "ldap", "kerberos", "dnp3",
);
tier_requires!("ml" => "ml-features", "ml-features-nprint");
tier_requires!("export" =>
    "ipfix", "ipfix-export", "emit", "emit-ndjson", "emit-eve");
tier_requires!("nsm" => "fingerprint", "tls-fingerprints", "analysis");
