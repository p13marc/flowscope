//! `flowscope::fingerprint` — one import site for the whole JA4+
//! fingerprint family (issue #136).
//!
//! The individual fingerprints live in their protocol modules
//! (`tls::ja4`, `http::ja4h`, `ssh::ja4ssh`, `tcp_fingerprint::ja4t`,
//! the crate-root `ja4l`) so each sits next to the parser that
//! feeds it. This module re-exports them under one namespace so a
//! consumer building a fingerprint pipeline imports from one place
//! and — crucially — sees the **license split** in one place.
//!
//! # License split (verified against the FoxIO License FAQ, 2026)
//!
//! flowscope is MIT/Apache-2.0. Two fingerprint groups sit under
//! **different** licenses and **different** Cargo features:
//!
//! | Group | Fingerprints | Feature | License |
//! |---|---|---|---|
//! | **Royalty-free** | JA3, JA4 (TLS client), JA4-over-QUIC | `tls-fingerprints` | BSD-3 (JA3) + FoxIO's patent-free JA4-client grant |
//! | **FoxIO 1.1** | JA4S, JA4X, JA4H, JA4SSH, JA4T, JA4L/LS | `ja4plus` | [FoxIO License 1.1](https://github.com/FoxIO-LLC/ja4/blob/main/License%20FAQ.md) — source-available, **not for monetization** without an OEM license; patent-pending |
//!
//! FoxIO explicitly disclaims patent pursuit for **plain JA4**
//! (TLS client) and it is BSD-3, so it rides `tls-fingerprints`
//! alongside JA3 and is included in the `l7` / `full` umbrellas.
//! Everything else in the JA4+ suite is FoxIO 1.1: the `ja4plus`
//! feature is **off by default and deliberately excluded from
//! `l7` / `full`**, so a default or `--features full` build stays
//! license-clean for commercial use. Turning on `ja4plus` opts
//! into the FoxIO terms — see `LICENSE-FoxIO-1.1` + `NOTICE`.
//!
//! # What's here
//!
//! - **Royalty-free (`tls-fingerprints`):** [`ja3_fingerprint`] /
//!   [`ja3_canonical`], [`ja4_fingerprint`] / [`ja4_parts`] /
//!   [`Ja4Parts`], [`ja4_quic`] / [`ja4_quic_parts`].
//! - **FoxIO 1.1 (`ja4plus`, + the protocol's own feature):**
//!   [`ja4s_fingerprint`] / [`Ja4sParts`], [`ja4x_for_chain`] /
//!   [`ja4x_for_der`], [`ja4h_fingerprint`] / [`Ja4hParts`]
//!   (needs `http`), [`Ja4sshAccumulator`] (needs `ssh`),
//!   [`ja4t`] / [`Ja4tParts`] (needs `tcp_fingerprint`),
//!   [`ja4l`] / [`ja4l_client`] / [`ja4l_server`].
//!
//! Most fingerprints are also surfaced pre-computed on the
//! per-flow aggregate events ([`TlsHandshake`](crate::tls::TlsHandshake)
//! carries `ja3` / `ja4` / `ja4s` / `ja4x`); reach for the
//! standalone functions here when you hold a raw parsed value
//! (a `TlsClientHello`, a cert DER, an `HttpRequest`).
//!
//! # ja4db enrichment
//!
//! FoxIO's community database ([`ja4db.com/api/read/`](https://ja4db.com/api/read/))
//! maps fingerprints → application / OS / device. It is **not**
//! bundled: flowscope is runtime-free (no HTTP client in core), so
//! fetching the DB is a consumer-side concern. Load it offline and
//! key a lookup by the `String` a `*_fingerprint` function returns
//! — a natural feed for the [`detect::IocSet`](crate::detect) /
//! asset layers.

// ─── Royalty-free: JA3 + JA4 client (tls-fingerprints) ───────────

#[cfg(feature = "tls-fingerprints")]
pub use crate::tls::{
    Ja4Parts, ja3_canonical, ja3_fingerprint, ja4_fingerprint, ja4_parts, ja4_quic, ja4_quic_parts,
};

// ─── FoxIO License 1.1: the rest of the JA4+ suite (ja4plus) ─────

#[cfg(feature = "ja4plus")]
pub use crate::tls::{Ja4sParts, ja4s_fingerprint, ja4s_parts, ja4x_for_chain, ja4x_for_der};

#[cfg(all(feature = "ja4plus", feature = "http"))]
pub use crate::http::{Ja4hParts, ja4h_fingerprint, ja4h_parts};

#[cfg(all(feature = "ja4plus", feature = "ssh"))]
pub use crate::ssh::{DEFAULT_PACKET_COUNT as JA4SSH_DEFAULT_PACKET_COUNT, Ja4sshAccumulator};

#[cfg(all(feature = "ja4plus", feature = "tcp_fingerprint"))]
pub use crate::tcp_fingerprint::{Ja4tParts, ja4t, ja4t_from_parts, ja4t_from_tcp};

#[cfg(feature = "ja4plus")]
pub use crate::ja4l::{half_latency_micros, ja4l, ja4l_client, ja4l_from_timestamps, ja4l_server};
