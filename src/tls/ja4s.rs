// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// JA4S is part of the JA4+ suite, (c) FoxIO, LLC, licensed under the FoxIO
// License 1.1 (see LICENSE-FoxIO-1.1 and NOTICE at the crate root) — NOT under
// flowscope's MIT/Apache-2.0 terms. JA4+ methods are patent pending. "JA4+" is
// a trademark of FoxIO, LLC. This file compiles only under the opt-in
// `ja4plus` feature; commercial use requires a FoxIO OEM license.

//! JA4S server fingerprint (FoxIO, 2023).
//!
//! The ServerHello counterpart to [JA4](super::ja4): a fingerprint of
//! the server's *response* to a ClientHello. Pairs with JA4 to identify
//! a specific client↔server software combination.
//!
//! Format: `[t|q][version][ext_count][alpn] _ [cipher] _ [ext_hash]`
//!
//! Where:
//! - `t`/`q` = TCP/QUIC transport (flowscope observes TCP today).
//! - `version` = the negotiated TLS version (from the ServerHello
//!   `supported_versions` extension if present, else `legacy_version`),
//!   2-digit (`13`, `12`, …).
//! - `ext_count` = 2-digit count of ServerHello extensions after GREASE
//!   removal.
//! - `alpn` = first + last char of the server's chosen ALPN (or `00`).
//! - `cipher` = the single cipher suite the server selected, 4 hex.
//! - `ext_hash` = first 12 hex chars of SHA-256 over the comma-joined
//!   extension list **in the order the server sent them** (GREASE
//!   removed). Unlike JA4's client side, the list is *not* sorted —
//!   servers don't shuffle, so their order is itself a signal.
//!
//! Source: <https://github.com/FoxIO-LLC/ja4>

use super::{
    ja4::{
        alpn_code, count_non_grease, is_grease_version, non_grease_hex_joined, sha256_prefix,
        version_to_two_digits,
    },
    types::{TlsServerHello, TlsVersion},
};

/// Parts of a JA4S fingerprint, before assembly into the
/// underscore-joined string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4sParts {
    /// The `[t|q][version][ext_count][alpn]` header section.
    pub header: String,
    /// The server's selected cipher suite, 4 hex chars.
    pub cipher: String,
    /// 12-hex-char SHA-256 prefix over the (unsorted) extension list.
    pub extension_hash: String,
}

impl std::fmt::Display for Ja4sParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}_{}_{}", self.header, self.cipher, self.extension_hash)
    }
}

/// Compute the JA4S server fingerprint for `sh`.
///
/// Returns the underscore-joined string (e.g.
/// `t130200_1301_a56c5b993250`).
pub fn ja4s(sh: &TlsServerHello) -> String {
    ja4s_parts(sh).to_string()
}

/// Return the JA4S parts before assembly.
pub fn ja4s_parts(sh: &TlsServerHello) -> Ja4sParts {
    Ja4sParts {
        header: build_header(sh),
        cipher: format!("{:04x}", sh.cipher_suite),
        // Server extension order is meaningful → do NOT sort.
        extension_hash: sha256_prefix(&non_grease_hex_joined(sh.extension_types.iter().copied())),
    }
}

fn build_header(sh: &TlsServerHello) -> String {
    // Transport: TCP only (flowscope doesn't observe QUIC yet).
    let transport = 't';

    // Negotiated version: the supported_versions value (TLS 1.3) wins,
    // else the legacy ServerHello version. GREASE shouldn't appear in a
    // server's pick, but filter defensively.
    let version = pick_version(sh);
    let version_code = version_to_two_digits(version);

    let ext_count = count_non_grease(sh.extension_types.iter().copied()).min(99);
    let alpn = alpn_code(sh.alpn.as_deref());

    format!("{transport}{version_code}{ext_count:02}{alpn}")
}

fn pick_version(sh: &TlsServerHello) -> TlsVersion {
    match sh.supported_version {
        Some(v) if !is_grease_version(v) => v,
        _ => sh.legacy_version,
    }
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn sample_sh() -> TlsServerHello {
        TlsServerHello {
            record_version: TlsVersion::Tls1_2,
            legacy_version: TlsVersion::Tls1_2,
            random: [0u8; 32],
            session_id: Bytes::new(),
            cipher_suite: 0x1301, // TLS_AES_128_GCM_SHA256
            compression: 0,
            alpn: Some("h2".to_string()),
            supported_version: Some(TlsVersion::Tls1_3),
            extension_types: vec![43, 51], // supported_versions, key_share
            ech_retry_configs: false,
        }
    }

    #[test]
    fn header_uses_negotiated_version_ext_count_and_alpn() {
        let parts = ja4s_parts(&sample_sh());
        // t = TCP, 13 = negotiated TLS 1.3, 02 = two extensions, h2 alpn.
        assert_eq!(parts.header, "t1302h2");
        // Cipher is the single chosen suite.
        assert_eq!(parts.cipher, "1301");
        assert_eq!(parts.extension_hash.len(), 12);
    }

    #[test]
    fn falls_back_to_legacy_version_without_supported_versions() {
        let mut sh = sample_sh();
        sh.supported_version = None; // TLS 1.2 style — legacy_version is the truth
        let parts = ja4s_parts(&sh);
        assert!(parts.header.starts_with("t12"), "header = {}", parts.header);
    }

    #[test]
    fn no_alpn_renders_double_zero() {
        let mut sh = sample_sh();
        sh.alpn = None;
        let parts = ja4s_parts(&sh);
        assert!(parts.header.ends_with("00"), "header = {}", parts.header);
    }

    #[test]
    fn alpn_first_and_last_char() {
        let mut sh = sample_sh();
        sh.alpn = Some("http/1.1".to_string());
        let parts = ja4s_parts(&sh);
        // FoxIO: first + last char → "h1".
        assert!(parts.header.ends_with("h1"), "header = {}", parts.header);
    }

    #[test]
    fn grease_excluded_from_ext_count_and_hash() {
        let mut sh = sample_sh();
        let clean = ja4s_parts(&sh);
        // Insert a GREASE extension; count + hash must be unchanged.
        sh.extension_types.insert(0, 0x0a0a);
        let greased = ja4s_parts(&sh);
        assert_eq!(clean.header, greased.header, "GREASE changed the header");
        assert_eq!(
            clean.extension_hash, greased.extension_hash,
            "GREASE changed the extension hash"
        );
    }

    #[test]
    fn extension_order_is_significant() {
        // Unlike JA4 client (sorted), JA4S hashes the server's order, so
        // a different order yields a different hash.
        let mut a = sample_sh();
        let mut b = sample_sh();
        a.extension_types = vec![43, 51];
        b.extension_types = vec![51, 43];
        assert_ne!(ja4s_parts(&a).extension_hash, ja4s_parts(&b).extension_hash);
    }

    #[test]
    fn display_is_underscore_joined() {
        let s = ja4s(&sample_sh());
        assert_eq!(s.matches('_').count(), 2);
    }
}
