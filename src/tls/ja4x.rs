// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// JA4X is part of the JA4+ suite, (c) FoxIO, LLC, licensed under the FoxIO
// License 1.1 (see LICENSE-FoxIO-1.1 and NOTICE at the crate root) — NOT under
// flowscope's MIT/Apache-2.0 terms. JA4+ methods are patent pending. "JA4+" is
// a trademark of FoxIO, LLC. This file compiles only under the opt-in
// `ja4plus` feature; commercial use requires a FoxIO OEM license.

//! JA4X — X.509 certificate fingerprint (FoxIO, 2023).
//!
//! Computes a per-certificate fingerprint over the issuer
//! and subject Distinguished Name (DN) attribute OIDs plus
//! the certificate extension OIDs:
//!
//! ```text
//! JA4X = SHA256-hex-12(issuer_oids) _
//!        SHA256-hex-12(subject_oids) _
//!        SHA256-hex-12(extension_oids)
//! ```
//!
//! Each OID list is the comma-separated dotted-decimal
//! representation in **wire order** (no sorting — server-
//! emitted ordering is itself a fingerprint signal,
//! mirroring JA4S's extension-list rationale).
//!
//! Format: three underscore-joined 12-hex-char SHA-256
//! prefixes — e.g.
//! `a564fbbd9b48_5e2c5a8f4f17_8c0e391b6d8b`.
//!
//! # API
//!
//! - [`ja4x_for_der`] — compute JA4X for one DER-encoded
//!   X.509 certificate. Returns `None` if DER parsing
//!   fails.
//! - [`ja4x_for_chain`] — compute JA4X for each cert in
//!   the chain. Returns one fingerprint per cert; the
//!   leaf (index 0 per RFC 5246 §7.4.2) is typically the
//!   one consumers want.
//!
//! # Source
//!
//! - <https://github.com/FoxIO-LLC/ja4/blob/main/technical_details/JA4X.md>

use bytes::Bytes;
use sha2::{Digest, Sha256};
use x509_parser::prelude::{FromDer, X509Certificate};

/// Compute JA4X for one DER-encoded X.509 certificate.
/// Returns `None` if DER parsing fails.
pub fn ja4x_for_der(der: &[u8]) -> Option<String> {
    let (_remaining, cert) = X509Certificate::from_der(der).ok()?;
    Some(format!(
        "{}_{}_{}",
        sha256_prefix_12(&dn_oids_joined(&cert, DnSelector::Issuer)),
        sha256_prefix_12(&dn_oids_joined(&cert, DnSelector::Subject)),
        sha256_prefix_12(&extension_oids_joined(&cert)),
    ))
}

/// Compute JA4X for each cert in a chain — leaf first per
/// RFC 5246 §7.4.2. Skips certs that fail DER parsing
/// (returns `None` in their slot).
pub fn ja4x_for_chain(chain: &[Bytes]) -> Vec<Option<String>> {
    chain.iter().map(|b| ja4x_for_der(b)).collect()
}

#[derive(Clone, Copy)]
enum DnSelector {
    Issuer,
    Subject,
}

fn dn_oids_joined(cert: &X509Certificate<'_>, which: DnSelector) -> String {
    let name = match which {
        DnSelector::Issuer => cert.issuer(),
        DnSelector::Subject => cert.subject(),
    };
    let mut out = String::new();
    let mut first = true;
    for rdn in name.iter() {
        for atv in rdn.iter() {
            if !first {
                out.push(',');
            }
            first = false;
            out.push_str(&atv.attr_type().to_id_string());
        }
    }
    out
}

fn extension_oids_joined(cert: &X509Certificate<'_>) -> String {
    let mut out = String::new();
    let mut first = true;
    for ext in cert.extensions() {
        if !first {
            out.push(',');
        }
        first = false;
        out.push_str(&ext.oid.to_id_string());
    }
    out
}

/// First 12 hex chars of SHA-256 over `input`.
fn sha256_prefix_12(input: &str) -> String {
    let mut h = Sha256::new();
    h.update(input.as_bytes());
    let digest = h.finalize();
    let mut out = String::with_capacity(12);
    for b in &digest[..6] {
        use std::fmt::Write;
        let _ = write!(out, "{:02x}", b);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A 1024-bit RSA self-signed cert generated for these
    /// tests. Encoded as DER. The subject / issuer DN
    /// contains CN=example.local, plus one Basic
    /// Constraints + one Subject Key Identifier extension.
    const SAMPLE_DER: &[u8] = include_bytes!("../../tests/fixtures/x509/sample.der");

    #[test]
    fn ja4x_decodes_sample_cert() {
        let fp = ja4x_for_der(SAMPLE_DER).expect("parse");
        // Format: 12 hex + _ + 12 hex + _ + 12 hex.
        let parts: Vec<_> = fp.split('_').collect();
        assert_eq!(parts.len(), 3);
        for p in &parts {
            assert_eq!(p.len(), 12);
            assert!(p.chars().all(|c| c.is_ascii_hexdigit()));
        }
    }

    #[test]
    fn ja4x_for_chain_handles_empty() {
        let chain: Vec<Bytes> = Vec::new();
        let result = ja4x_for_chain(&chain);
        assert!(result.is_empty());
    }

    #[test]
    fn ja4x_for_chain_handles_invalid_der() {
        let bogus: Vec<Bytes> = vec![Bytes::from_static(b"not-a-cert")];
        let result = ja4x_for_chain(&bogus);
        assert_eq!(result.len(), 1);
        assert!(result[0].is_none());
    }

    #[test]
    fn sha256_prefix_12_known_value() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb924…
        // Take the first 6 bytes → 12 hex chars.
        assert_eq!(sha256_prefix_12(""), "e3b0c44298fc");
    }
}
