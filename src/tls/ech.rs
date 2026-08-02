//! ECH (Encrypted ClientHello) GREASE-vs-real detector.
//!
//! Builds on the per-ClientHello ECH signals shipped in 0.12.0
//! (plan 144 — `ech_present`, `ech_config_id`, `sni_is_outer`)
//! with the GREASE-vs-real classification asked for in issue #8.
//!
//! # Why a classification is needed
//!
//! Chrome and Firefox ship GREASE-ECH per
//! [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) and
//! [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) §6.2 — they
//! emit a structurally
//! valid `encrypted_client_hello` extension (RFC type `0xfe0d`)
//! on nearly every ClientHello with a random `config_id`, KDF,
//! AEAD, encapsulated key, and payload. **Presence of the
//! extension is not a signal of real ECH adoption** — on the
//! modern open web a majority of ClientHellos with the extension
//! are GREASE, not real ECH.
//!
//! Per the SIGCOMM 2025 measurement, real ECH adoption is around
//! 4.2% of the top-100K; the rest is GREASE noise.
//!
//! # What is observable passively
//!
//! Distinguishing GREASE from real ECH from the wire is
//! cryptographically impossible by design — that's the
//! whole point of GREASE. The only durable signals are:
//!
//! 1. **Cover SNI** — real ECH outer ClientHellos carry the
//!    public cover domain in plaintext SNI. Cloudflare's
//!    deployment uses `cloudflare-ech.com` (and subdomains)
//!    as the cover for every site behind their ECH service.
//!    A ClientHello whose outer SNI matches a known cover
//!    domain is highly likely to be real ECH.
//! 2. **Server-side retry_configs** — when ECH is rejected
//!    on the early handshake path (before EncryptedExtensions),
//!    the server may return `retry_configs` in plaintext —
//!    captured by [`crate::tls::TlsServerHello::ech_retry_configs`].
//!    This is the strongest "real ECH happened" signal,
//!    but it only fires on rejection.
//!
//! Inner SNI recovery is out of scope and impossible without
//! the ECH private key.
//!
//! # Vocabulary
//!
//! The [`EchState`] vocabulary follows the
//! [`nginx $ssl_ech_status`](https://nginx.org/en/docs/http/ngx_http_ssl_module.html)
//! shape, simplified for what is passively observable:
//!
//! | Variant | Meaning |
//! |---------|---------|
//! | [`EchState::NotPresent`] | `encrypted_client_hello` extension absent |
//! | [`EchState::LikelyReal`] | extension present + outer SNI matches known cover domain |
//! | [`EchState::LikelyGrease`] | extension present, no corroborating signal — most likely GREASE |
//! | [`EchState::Rejected`] | server sent plaintext `retry_configs` (handshake-level signal only) |
//!
//! Issue #8 (0.18). See also
//! [RFC 9849](https://www.rfc-editor.org/rfc/rfc9849) (ECH,
//! published March 2026 — formerly `draft-ietf-tls-esni`) and
//! [RFC 8701](https://www.rfc-editor.org/rfc/rfc8701) (GREASE).

/// Classification of the `encrypted_client_hello` extension on
/// a TLS ClientHello.
///
/// Returned by [`crate::tls::TlsClientHello::ech_state`] and
/// (refined with server-side signals) by
/// [`crate::tls::TlsHandshake::ech_state`].
///
/// `#[non_exhaustive]` — future ECH revisions may add states
/// (e.g. inner-form detection if a side-channel becomes
/// available).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(rename_all = "snake_case"))]
#[non_exhaustive]
pub enum EchState {
    /// No `encrypted_client_hello` extension on the
    /// ClientHello. Either ECH-unaware client or ECH disabled
    /// at this client.
    NotPresent,
    /// Extension present and outer SNI matches a known ECH
    /// cover domain (see [`is_ech_cover_domain`]) — strong
    /// signal of real ECH adoption.
    LikelyReal,
    /// Extension present with no other corroborating signal
    /// — most likely GREASE-ECH per RFC 8701 / draft-25 §6.2,
    /// which Chrome / Firefox emit on nearly every ClientHello.
    /// Not a definitive "GREASE" classification — a real ECH
    /// deployment with a cover domain not on the known-cover
    /// list will also land here.
    LikelyGrease,
    /// Extension present and the server returned plaintext
    /// `retry_configs` in the response — explicit rejection
    /// of a real ECH attempt. Only observable from
    /// [`crate::tls::TlsHandshake::ech_state`], not from a
    /// ClientHello in isolation.
    Rejected,
}

impl EchState {
    /// Stable slug for metric labels and JSON emission.
    ///
    /// | Variant | Slug |
    /// |---------|------|
    /// | [`Self::NotPresent`] | `"not_present"` |
    /// | [`Self::LikelyReal`] | `"likely_real"` |
    /// | [`Self::LikelyGrease`] | `"likely_grease"` |
    /// | [`Self::Rejected`] | `"rejected"` |
    pub fn as_str(&self) -> &'static str {
        match self {
            EchState::NotPresent => "not_present",
            EchState::LikelyReal => "likely_real",
            EchState::LikelyGrease => "likely_grease",
            EchState::Rejected => "rejected",
        }
    }
}

impl std::fmt::Display for EchState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Known ECH cover-domain suffixes — domains where a public
/// ECH service publishes its outer/cover SNI.
///
/// Currently shipped:
///
/// - `cloudflare-ech.com` — Cloudflare's public ECH cover.
///   Every site behind Cloudflare's ECH service emits an outer
///   SNI under this domain.
///
/// Mozilla's research cover deployments are intentionally not
/// included — they're test/internal infrastructure rather than
/// public ECH services.
///
/// The list is matched as case-insensitive suffix match — an
/// SNI of `public.cloudflare-ech.com` matches the
/// `cloudflare-ech.com` suffix.
pub fn ech_cover_domains() -> &'static [&'static str] {
    &["cloudflare-ech.com"]
}

/// `true` iff the SNI's lowercased form ends with a known ECH
/// cover-domain suffix (see [`ech_cover_domains`]).
///
/// Suffix matching is required because Cloudflare's cover SNIs
/// take the form `<random>.cloudflare-ech.com`.
///
/// ```
/// use flowscope::tls::ech::is_ech_cover_domain;
/// assert!(is_ech_cover_domain("cloudflare-ech.com"));
/// assert!(is_ech_cover_domain("public.cloudflare-ech.com"));
/// assert!(is_ech_cover_domain("CLOUDFLARE-ECH.COM"));
/// assert!(!is_ech_cover_domain("example.com"));
/// assert!(!is_ech_cover_domain(""));
/// // Substring-but-not-suffix doesn't match.
/// assert!(!is_ech_cover_domain("cloudflare-ech.com.attacker.tld"));
/// ```
pub fn is_ech_cover_domain(sni: &str) -> bool {
    if sni.is_empty() {
        return false;
    }
    let lower = sni.to_ascii_lowercase();
    for &suffix in ech_cover_domains() {
        if lower == suffix {
            return true;
        }
        if lower.len() > suffix.len() + 1 {
            let dot_offset = lower.len() - suffix.len() - 1;
            if &lower[dot_offset..dot_offset + 1] == "." && &lower[dot_offset + 1..] == suffix {
                return true;
            }
        }
    }
    false
}

/// Classify a ClientHello's ECH state from the two
/// passively-observable inputs: whether the extension was
/// present, and the outer SNI.
///
/// Used by [`crate::tls::TlsClientHello::ech_state`]; exposed
/// here for callers who want to classify ECH state from raw
/// values without holding a `TlsClientHello`.
pub fn classify_client_hello(ech_present: bool, sni: Option<&str>) -> EchState {
    if !ech_present {
        return EchState::NotPresent;
    }
    match sni {
        Some(s) if is_ech_cover_domain(s) => EchState::LikelyReal,
        _ => EchState::LikelyGrease,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_vocabulary_locked() {
        assert_eq!(EchState::NotPresent.as_str(), "not_present");
        assert_eq!(EchState::LikelyReal.as_str(), "likely_real");
        assert_eq!(EchState::LikelyGrease.as_str(), "likely_grease");
        assert_eq!(EchState::Rejected.as_str(), "rejected");
    }

    #[test]
    fn cover_domain_known_suffix() {
        assert!(is_ech_cover_domain("cloudflare-ech.com"));
        assert!(is_ech_cover_domain("public.cloudflare-ech.com"));
        assert!(is_ech_cover_domain("foo.bar.cloudflare-ech.com"));
    }

    #[test]
    fn cover_domain_case_insensitive() {
        assert!(is_ech_cover_domain("CLOUDFLARE-ECH.COM"));
        assert!(is_ech_cover_domain("Public.CloudFlare-Ech.Com"));
    }

    #[test]
    fn cover_domain_unknown() {
        assert!(!is_ech_cover_domain("example.com"));
        assert!(!is_ech_cover_domain("google.com"));
        assert!(!is_ech_cover_domain(""));
    }

    #[test]
    fn cover_domain_suffix_not_substring() {
        // Attacker can't trick us with a substring match.
        assert!(!is_ech_cover_domain("cloudflare-ech.com.attacker.tld"));
        // Or by sneaking the cover into a longer host part.
        assert!(!is_ech_cover_domain("fakecloudflare-ech.com"));
    }

    #[test]
    fn classify_no_extension_is_not_present() {
        assert_eq!(classify_client_hello(false, None), EchState::NotPresent);
        assert_eq!(
            classify_client_hello(false, Some("example.com")),
            EchState::NotPresent
        );
        // Even an SNI matching the cover set doesn't matter
        // when the extension is absent.
        assert_eq!(
            classify_client_hello(false, Some("cloudflare-ech.com")),
            EchState::NotPresent
        );
    }

    #[test]
    fn classify_extension_present_known_cover_is_likely_real() {
        assert_eq!(
            classify_client_hello(true, Some("cloudflare-ech.com")),
            EchState::LikelyReal
        );
        assert_eq!(
            classify_client_hello(true, Some("a.cloudflare-ech.com")),
            EchState::LikelyReal
        );
    }

    #[test]
    fn classify_extension_present_other_sni_is_likely_grease() {
        // The Chrome/Firefox GREASE-ECH case: ext present on a
        // ClientHello with a normal SNI.
        assert_eq!(
            classify_client_hello(true, Some("example.com")),
            EchState::LikelyGrease
        );
        assert_eq!(classify_client_hello(true, None), EchState::LikelyGrease);
    }
}
