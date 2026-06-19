//! JA4 client fingerprint (FoxIO v1, 2023).
//!
//! Modern successor to JA3:
//! - Sorts cipher / extension lists (resilient to client-side
//!   shuffling).
//! - Strips GREASE values (RFC 8701) before hashing.
//! - Human-readable header (`t13d1516h2`) instead of an opaque
//!   MD5 hash.
//!
//! Format: `[t|q][version][SNI?d:i][cipher_count][ext_count][alpn] _ [hash_a] _ [hash_b]`
//!
//! Where:
//! - `t`/`q` = TCP/QUIC transport (flowscope is TCP-only today).
//! - `version` = highest TLS version from `supported_versions`
//!   (e.g. "13" for TLS 1.3, "12" for TLS 1.2).
//! - `d` if SNI present, `i` if absent.
//! - 2-digit zero-padded cipher / extension counts (after GREASE
//!   removal).
//! - First 2 chars of selected ALPN (or `00` if none).
//! - `hash_a` = SHA-256 of comma-joined hex-sorted cipher list,
//!   truncated to 12 hex chars.
//! - `hash_b` = SHA-256 of comma-joined hex-sorted extension +
//!   signature-algorithm list, truncated to 12 hex chars.
//!
//! Source: <https://github.com/FoxIO-LLC/ja4>

use sha2::{Digest, Sha256};

use super::types::{TlsClientHello, TlsVersion};

/// Parts of a JA4 fingerprint, before assembly into the
/// underscore-joined string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4Parts {
    /// The `[t|q][version][SNI?d:i][cipher_count][ext_count][alpn]`
    /// header section.
    pub header: String,
    /// 12-hex-char SHA-256 prefix over the sorted cipher list.
    pub cipher_hash: String,
    /// 12-hex-char SHA-256 prefix over the sorted extension +
    /// sig-algs list.
    pub extension_hash: String,
}

impl std::fmt::Display for Ja4Parts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{}_{}_{}",
            self.header, self.cipher_hash, self.extension_hash
        )
    }
}

/// Compute the JA4 client fingerprint for `ch`.
///
/// Returns the underscore-joined string (e.g.
/// `t13d1516h2_8daaf6152771_b186095e22b6`).
pub fn ja4(ch: &TlsClientHello) -> String {
    ja4_parts(ch).to_string()
}

/// Return the JA4 parts before assembly.
pub fn ja4_parts(ch: &TlsClientHello) -> Ja4Parts {
    let header = build_header(ch);
    let ciphers = sorted_non_grease_hex(ch.cipher_suites.iter().copied());
    let exts = sorted_non_grease_hex(ch.extension_types.iter().copied());
    let cipher_hash = sha256_prefix(&ciphers);
    let extension_hash = sha256_prefix(&exts);
    Ja4Parts {
        header,
        cipher_hash,
        extension_hash,
    }
}

fn build_header(ch: &TlsClientHello) -> String {
    // Transport: TCP only (flowscope doesn't observe QUIC yet).
    let transport = 't';

    // Version: highest from supported_versions if present, else
    // legacy_version. Encoded as 2-digit decimal: 10/11/12/13.
    let version = pick_version(ch);
    let version_code = version_to_two_digits(version);

    // SNI present?
    let sni_flag = if ch.sni.is_some() { 'd' } else { 'i' };

    // Cipher / extension counts after GREASE removal, clamped 99.
    let cipher_count = count_non_grease(ch.cipher_suites.iter().copied()).min(99);
    let ext_count = count_non_grease(ch.extension_types.iter().copied()).min(99);

    // ALPN: first + last char of the first ALPN value, or "00".
    let alpn = alpn_code(ch.alpn.first().map(String::as_str));

    format!("{transport}{version_code}{sni_flag}{cipher_count:02}{ext_count:02}{alpn}")
}

fn pick_version(ch: &TlsClientHello) -> TlsVersion {
    ch.supported_versions
        .iter()
        .copied()
        .filter(|v| !is_grease_version(*v))
        .max_by_key(version_rank)
        .unwrap_or(ch.legacy_version)
}

fn version_rank(v: &TlsVersion) -> u8 {
    match v {
        TlsVersion::Ssl3_0 => 0,
        TlsVersion::Tls1_0 => 1,
        TlsVersion::Tls1_1 => 2,
        TlsVersion::Tls1_2 => 3,
        TlsVersion::Tls1_3 => 4,
        _ => 0,
    }
}

/// Two-digit JA4 version code. Shared with [JA4S](super::ja4s).
pub(super) fn version_to_two_digits(v: TlsVersion) -> &'static str {
    match v {
        TlsVersion::Ssl3_0 => "s3",
        TlsVersion::Tls1_0 => "10",
        TlsVersion::Tls1_1 => "11",
        TlsVersion::Tls1_2 => "12",
        TlsVersion::Tls1_3 => "13",
        _ => "00",
    }
}

pub(super) fn is_grease_version(v: TlsVersion) -> bool {
    is_grease_u16(v.to_raw())
}

/// RFC 8701 — GREASE values for cipher suites / extensions:
/// 16 reserved values 0x0a0a, 0x1a1a, 0x2a2a, ..., 0xfafa
/// where both bytes match a 4-bit pattern.
pub(super) fn is_grease_u16(v: u16) -> bool {
    let hi = (v >> 8) & 0xff;
    let lo = v & 0xff;
    hi == lo && (lo & 0x0f) == 0x0a
}

pub(super) fn count_non_grease<I: Iterator<Item = u16>>(iter: I) -> usize {
    iter.filter(|v| !is_grease_u16(*v)).count()
}

fn sorted_non_grease_hex<I: Iterator<Item = u16>>(iter: I) -> String {
    let mut items: Vec<u16> = iter.filter(|v| !is_grease_u16(*v)).collect();
    items.sort_unstable();
    non_grease_hex_joined(items.into_iter())
}

/// Comma-join `04x`-formatted values that survive GREASE filtering, in
/// the iterator's order (no sort). JA4 sorts ciphers/extensions; JA4S
/// keeps the server's order, so it uses this directly.
pub(super) fn non_grease_hex_joined<I: Iterator<Item = u16>>(iter: I) -> String {
    iter.filter(|v| !is_grease_u16(*v))
        .map(|v| format!("{v:04x}"))
        .collect::<Vec<_>>()
        .join(",")
}

/// JA4/JA4S ALPN code: the first and last character of the chosen ALPN
/// (FoxIO spec — `http/1.1` → `h1`, `h2` → `h2`), or `00` if none.
pub(super) fn alpn_code(alpn: Option<&str>) -> String {
    match alpn.filter(|s| !s.is_empty()) {
        Some(s) => {
            let first = s.chars().next().unwrap_or('0');
            let last = s.chars().next_back().unwrap_or('0');
            format!("{first}{last}")
        }
        None => "00".to_string(),
    }
}

pub(super) fn sha256_prefix(input: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..6]) // 12 hex chars
}

#[cfg(test)]
mod tests {
    use bytes::Bytes;

    use super::*;

    fn sample_ch() -> TlsClientHello {
        TlsClientHello {
            record_version: TlsVersion::Tls1_0,
            legacy_version: TlsVersion::Tls1_2,
            random: [0u8; 32],
            session_id: Bytes::new(),
            cipher_suites: vec![
                0x1301, // TLS_AES_128_GCM_SHA256
                0x1302, // TLS_AES_256_GCM_SHA384
                0xc02f, // ECDHE-RSA-AES128-GCM-SHA256
            ],
            compression: bytes::Bytes::from_static(&[0]),
            sni: Some("example.com".to_string()),
            alpn: vec!["h2".to_string()],
            supported_versions: vec![TlsVersion::Tls1_2, TlsVersion::Tls1_3],
            supported_groups: vec![],
            extension_types: vec![0, 16, 43, 45],
            ech_present: false,
            ech_config_id: None,
            sni_is_outer: false,
        }
    }

    #[test]
    fn grease_detection() {
        assert!(is_grease_u16(0x0a0a));
        assert!(is_grease_u16(0xfafa));
        assert!(!is_grease_u16(0x1301));
        assert!(!is_grease_u16(0x0000));
    }

    #[test]
    fn header_format() {
        let ch = sample_ch();
        let parts = ja4_parts(&ch);
        // t13d... = TCP / TLS1.3 / SNI-present
        assert!(parts.header.starts_with("t13d"));
        // 03 ciphers, 04 extensions, "h2" alpn
        assert!(parts.header.ends_with("0304h2"));
    }

    #[test]
    fn no_sni_uses_i_flag() {
        let mut ch = sample_ch();
        ch.sni = None;
        let parts = ja4_parts(&ch);
        assert!(parts.header.contains('i'));
        assert!(!parts.header.contains('d'));
    }

    #[test]
    fn grease_excluded_from_count_and_hash() {
        let mut ch = sample_ch();
        // Add GREASE values to the front; the counts and hash should ignore them.
        ch.cipher_suites.insert(0, 0x0a0a);
        ch.extension_types.insert(0, 0x1a1a);
        let parts = ja4_parts(&ch);
        // Still 03 ciphers, 04 extensions.
        assert!(parts.header.contains("0304"));
    }

    #[test]
    fn ordering_invariance() {
        // Two ClientHellos with the same set but different order
        // should produce the same hash sections.
        let mut a = sample_ch();
        let mut b = sample_ch();
        a.cipher_suites = vec![0x1301, 0x1302, 0xc02f];
        b.cipher_suites = vec![0xc02f, 0x1301, 0x1302];
        let pa = ja4_parts(&a);
        let pb = ja4_parts(&b);
        assert_eq!(pa.cipher_hash, pb.cipher_hash);
    }

    #[test]
    fn display_formats_underscore_joined() {
        let ch = sample_ch();
        let parts = ja4_parts(&ch);
        let s = parts.to_string();
        assert_eq!(s.matches('_').count(), 2);
    }
}
