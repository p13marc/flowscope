//! JA4H — FoxIO HTTP client fingerprint.
//!
//! Gated by the `ja4plus` feature (FoxIO License 1.1 — patent
//! pending; non-commercial; see LICENSE-FoxIO-1.1 + NOTICE).
//! Commercial use requires a FoxIO OEM license.
//!
//! JA4H is the HTTP analogue of JA3 / JA4 — it fingerprints
//! the client's HTTP/1.x request defaults (method, version,
//! ordered header names, cookie names + values, primary
//! `Accept-Language`) without touching the request body.
//!
//! # Format
//!
//! `<a>_<b>_<c>_<d>` where:
//!
//! - **a** (12 chars): `<m><m><v><v><c|n><r|n><nn><LLLL>`
//!   - 2 lowercase chars of HTTP method (e.g. `ge` for GET).
//!   - 2 chars of HTTP version (`11` / `10`).
//!   - `c` if a `Cookie:` header is present, else `n`.
//!   - `r` if a `Referer:` header is present, else `n`.
//!   - 2-digit total header count (capped at 99).
//!   - 4-char primary `Accept-Language` (lowercased, stripped
//!     of `-`, padded with `0`; `0000` if absent).
//! - **b** (12 chars): SHA-256 truncated, of the comma-joined
//!   header-name list (preserving wire order; `Cookie` and
//!   `Referer` excluded).
//! - **c** (12 chars): SHA-256 truncated, of the comma-joined
//!   cookie names in alphabetical order. `000000000000` if
//!   no cookies.
//! - **d** (12 chars): SHA-256 truncated, of the comma-joined
//!   `name=value` cookie pairs in alphabetical order.
//!   `000000000000` if no cookies.
//!
//! Issue #10 (0.18).

use sha2::{Digest, Sha256};

use crate::http::types::{HttpRequest, HttpVersion};

/// Decomposed JA4H pieces. Each section is the operational
/// signal — the joined string is what tools usually display.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct Ja4hParts {
    /// `a` section — see module docs for the field layout.
    pub a: String,
    /// `b` section — header-name SHA-256 (first 12 chars).
    pub b: String,
    /// `c` section — sorted cookie-name SHA-256 (first 12).
    pub c: String,
    /// `d` section — sorted `name=value` cookie SHA-256.
    pub d: String,
}

impl Ja4hParts {
    /// Re-join into the FoxIO `a_b_c_d` form.
    pub fn fingerprint(&self) -> String {
        format!("{}_{}_{}_{}", self.a, self.b, self.c, self.d)
    }
}

/// Compute the full `a_b_c_d` JA4H fingerprint.
pub fn ja4h(req: &HttpRequest) -> String {
    ja4h_parts(req).fingerprint()
}

/// Compute JA4H with each section preserved for callers that
/// want to index sub-sections (e.g. all clients with the same
/// `a` section).
pub fn ja4h_parts(req: &HttpRequest) -> Ja4hParts {
    let mut method_chars = String::new();
    for &b in req.method.iter().take(2) {
        method_chars.push(b.to_ascii_lowercase() as char);
    }
    while method_chars.len() < 2 {
        method_chars.push('0');
    }

    let version = match req.version {
        HttpVersion::Http1_0 => "10",
        HttpVersion::Http1_1 => "11",
    };

    let mut has_cookie = false;
    let mut has_referer = false;
    let mut cookie_value: Option<&[u8]> = None;
    let mut lang_raw: Option<String> = None;
    let mut header_names: Vec<String> = Vec::new();
    let total_headers = req.headers.len();

    for (name, value) in &req.headers {
        let lower_name: String = name
            .iter()
            .map(|b| b.to_ascii_lowercase() as char)
            .collect();
        match lower_name.as_str() {
            "cookie" => {
                has_cookie = true;
                cookie_value = Some(value.as_ref());
                continue;
            }
            "referer" => {
                has_referer = true;
                continue;
            }
            "accept-language" if lang_raw.is_none() => {
                lang_raw = primary_lang(value);
            }
            _ => {}
        }
        header_names.push(lower_name);
    }

    let lang_code = lang_raw
        .map(|s| pad_lang(&s))
        .unwrap_or_else(|| "0000".to_string());

    let header_count = total_headers.min(99);
    let a = format!(
        "{}{}{}{}{:02}{}",
        method_chars,
        version,
        if has_cookie { "c" } else { "n" },
        if has_referer { "r" } else { "n" },
        header_count,
        lang_code,
    );

    let b = sha256_first_12(header_names.join(",").as_bytes());

    let (c, d) = match cookie_value {
        None => ("000000000000".to_string(), "000000000000".to_string()),
        Some(bytes) => {
            let mut pairs = parse_cookies(bytes);
            pairs.sort_by(|a, b| a.0.cmp(&b.0));
            let names_csv = pairs
                .iter()
                .map(|(n, _)| n.as_str())
                .collect::<Vec<_>>()
                .join(",");
            let pairs_csv = pairs
                .iter()
                .map(|(n, v)| format!("{n}={v}"))
                .collect::<Vec<_>>()
                .join(",");
            if pairs.is_empty() {
                ("000000000000".to_string(), "000000000000".to_string())
            } else {
                (
                    sha256_first_12(names_csv.as_bytes()),
                    sha256_first_12(pairs_csv.as_bytes()),
                )
            }
        }
    };

    Ja4hParts { a, b, c, d }
}

fn sha256_first_12(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let hex = hex::encode(digest);
    hex[..12].to_string()
}

/// Parse `Cookie:` header bytes into `(name, value)` pairs.
/// Splits on `;` then on the first `=`; trims surrounding
/// whitespace; skips entries without `=` or with empty
/// names. Non-UTF-8 cookies are silently skipped.
fn parse_cookies(bytes: &[u8]) -> Vec<(String, String)> {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };
    s.split(';')
        .filter_map(|cookie| {
            let cookie = cookie.trim();
            if cookie.is_empty() {
                return None;
            }
            let (name, value) = cookie.split_once('=')?;
            let name = name.trim();
            if name.is_empty() {
                return None;
            }
            Some((name.to_string(), value.trim().to_string()))
        })
        .collect()
}

/// Pull the primary language tag from an `Accept-Language`
/// header value. Returns the first language tag (before any
/// `;q=` quality marker), or `None` on malformed input.
fn primary_lang(value: &[u8]) -> Option<String> {
    let s = std::str::from_utf8(value).ok()?;
    let first = s.split(',').next()?.trim();
    let stripped = first.split(';').next().unwrap_or(first).trim();
    if stripped.is_empty() {
        None
    } else {
        Some(stripped.to_ascii_lowercase())
    }
}

/// Normalise a language tag to JA4H's 4-character form:
/// lowercase, with `-`/`_` stripped, padded with `0` to 4
/// chars, truncated to 4 chars.
fn pad_lang(raw: &str) -> String {
    let cleaned: String = raw.chars().filter(|c| !matches!(*c, '-' | '_')).collect();
    let mut out: String = cleaned.chars().take(4).collect();
    while out.len() < 4 {
        out.push('0');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;

    fn req(method: &[u8], version: HttpVersion, headers: &[(&str, &str)]) -> HttpRequest {
        HttpRequest {
            method: Bytes::copy_from_slice(method),
            path: Bytes::from_static(b"/"),
            version,
            headers: headers
                .iter()
                .map(|(k, v)| {
                    (
                        Bytes::copy_from_slice(k.as_bytes()),
                        Bytes::copy_from_slice(v.as_bytes()),
                    )
                })
                .collect(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn minimal_get_no_cookie_no_referer_no_lang() {
        // Method=GET (ge), HTTP/1.1 (11), n n, 1 header,
        // no Accept-Language (0000).
        let r = req(b"GET", HttpVersion::Http1_1, &[("Host", "example.com")]);
        let p = ja4h_parts(&r);
        assert!(p.a.starts_with("ge11nn"));
        assert_eq!(&p.a[6..8], "01");
        assert!(p.a.ends_with("0000"));
        assert_eq!(p.c, "000000000000");
        assert_eq!(p.d, "000000000000");
    }

    #[test]
    fn cookie_present_sets_c_marker_and_hashes() {
        let r = req(
            b"GET",
            HttpVersion::Http1_1,
            &[
                ("Host", "example.com"),
                ("Cookie", "session=abc; theme=dark"),
            ],
        );
        let p = ja4h_parts(&r);
        // c flag in `a`.
        assert_eq!(&p.a[4..5], "c");
        assert_ne!(p.c, "000000000000");
        assert_ne!(p.d, "000000000000");
        assert_eq!(p.c.len(), 12);
        assert_eq!(p.d.len(), 12);
    }

    #[test]
    fn referer_present_sets_r_marker() {
        let r = req(
            b"GET",
            HttpVersion::Http1_1,
            &[("Host", "example.com"), ("Referer", "https://prev/")],
        );
        let p = ja4h_parts(&r);
        assert_eq!(&p.a[5..6], "r");
        // Referer is excluded from the b hash — its header
        // name shouldn't be in the SHA-256'd input.
    }

    #[test]
    fn accept_language_picked_and_padded() {
        let r = req(
            b"GET",
            HttpVersion::Http1_1,
            &[
                ("Host", "example.com"),
                ("Accept-Language", "en-US,en;q=0.9"),
            ],
        );
        let p = ja4h_parts(&r);
        // en-US -> enus (4 chars).
        assert!(p.a.ends_with("enus"), "expected enus suffix, got {}", p.a);
    }

    #[test]
    fn accept_language_short_tag_padded_with_zeros() {
        let r = req(
            b"GET",
            HttpVersion::Http1_1,
            &[("Host", "example.com"), ("Accept-Language", "de")],
        );
        let p = ja4h_parts(&r);
        assert!(p.a.ends_with("de00"));
    }

    #[test]
    fn cookie_order_is_alphabetical_in_hashes() {
        // Reverse-order cookie input — sorted output, so the
        // hash should be the same as a sorted input.
        let r1 = req(
            b"GET",
            HttpVersion::Http1_1,
            &[("Cookie", "zoo=zebra; alpha=apple; mid=middle")],
        );
        let r2 = req(
            b"GET",
            HttpVersion::Http1_1,
            &[("Cookie", "alpha=apple; mid=middle; zoo=zebra")],
        );
        let p1 = ja4h_parts(&r1);
        let p2 = ja4h_parts(&r2);
        assert_eq!(p1.c, p2.c);
        assert_eq!(p1.d, p2.d);
    }

    #[test]
    fn deterministic_format() {
        let r = req(
            b"POST",
            HttpVersion::Http1_1,
            &[
                ("Host", "example.com"),
                ("Content-Type", "application/json"),
                ("Accept-Language", "fr-FR"),
            ],
        );
        let fp1 = ja4h(&r);
        let fp2 = ja4h(&r);
        assert_eq!(fp1, fp2);
        assert!(fp1.starts_with("po11nn03frfr"));
        // Format: a (12 chars) _ b (12) _ c (12) _ d (12).
        let parts: Vec<&str> = fp1.split('_').collect();
        assert_eq!(parts.len(), 4);
        assert!(parts.iter().all(|p| p.len() == 12));
    }

    #[test]
    fn header_count_caps_at_99() {
        // Pile on 150 headers — should still report 99.
        let mut headers: Vec<(String, String)> = Vec::new();
        for i in 0..150 {
            headers.push((format!("X-Custom-{i}"), "v".into()));
        }
        let r = HttpRequest {
            method: Bytes::from_static(b"GET"),
            path: Bytes::from_static(b"/"),
            version: HttpVersion::Http1_1,
            headers: headers
                .iter()
                .map(|(k, v)| {
                    (
                        Bytes::copy_from_slice(k.as_bytes()),
                        Bytes::copy_from_slice(v.as_bytes()),
                    )
                })
                .collect(),
            body: Bytes::new(),
        };
        let p = ja4h_parts(&r);
        assert_eq!(&p.a[6..8], "99");
    }

    #[test]
    fn short_method_bytes_padded() {
        // A single-char method (uncommon but legal per HTTP
        // grammar) — pad to 2 chars with `0`.
        let r = req(b"X", HttpVersion::Http1_1, &[("Host", "x")]);
        let p = ja4h_parts(&r);
        assert!(p.a.starts_with("x0"));
    }

    #[test]
    fn http_1_0_version_section() {
        let r = req(b"GET", HttpVersion::Http1_0, &[("Host", "x")]);
        let p = ja4h_parts(&r);
        assert_eq!(&p.a[2..4], "10");
    }
}
