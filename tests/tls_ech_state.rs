//! Issue #8 — ECH state detector. Verify the GREASE-vs-real
//! classification on `TlsClientHello::ech_state()` and the
//! handshake-level refinement on `TlsHandshake::ech_state()`.
//!
//! `TlsClientHello` / `TlsHandshake` are `#[non_exhaustive]`,
//! so tests construct them via `Default::default()` and then
//! mutate fields — same idiom downstream code uses.

#![cfg(feature = "tls")]

use flowscope::tls::{
    EchState, TlsClientHello, TlsHandshake,
    ech::{classify_client_hello, ech_cover_domains, is_ech_cover_domain},
    handshake::EchOutcome,
};

fn ch_with(present: bool, sni: Option<&str>) -> TlsClientHello {
    let mut ch = TlsClientHello::default();
    ch.ech_present = present;
    ch.sni = sni.map(str::to_string);
    ch
}

fn hs_with(outcome: EchOutcome, sni: Option<&str>) -> TlsHandshake {
    let mut hs = TlsHandshake::default();
    hs.ech_outcome = outcome;
    hs.sni = sni.map(str::to_string);
    hs
}

#[test]
fn client_hello_ext_absent_is_not_present() {
    assert_eq!(
        ch_with(false, Some("example.com")).ech_state(),
        EchState::NotPresent
    );
}

#[test]
fn client_hello_ext_present_known_cover_is_likely_real() {
    assert_eq!(
        ch_with(true, Some("a.cloudflare-ech.com")).ech_state(),
        EchState::LikelyReal
    );
}

#[test]
fn client_hello_ext_present_normal_sni_is_likely_grease() {
    // The Chrome/Firefox GREASE-ECH case — extension present
    // on a normal HTTPS ClientHello.
    assert_eq!(
        ch_with(true, Some("example.com")).ech_state(),
        EchState::LikelyGrease
    );
}

#[test]
fn client_hello_ext_present_no_sni_is_likely_grease() {
    assert_eq!(ch_with(true, None).ech_state(), EchState::LikelyGrease);
}

#[test]
fn handshake_not_offered_is_not_present() {
    assert_eq!(
        hs_with(EchOutcome::NotOffered, Some("example.com")).ech_state(),
        EchState::NotPresent
    );
}

#[test]
fn handshake_rejected_is_rejected() {
    assert_eq!(
        hs_with(EchOutcome::Rejected, Some("example.com")).ech_state(),
        EchState::Rejected
    );
}

#[test]
fn handshake_accepted_with_cover_sni_is_likely_real() {
    assert_eq!(
        hs_with(EchOutcome::Accepted, Some("cloudflare-ech.com")).ech_state(),
        EchState::LikelyReal
    );
}

#[test]
fn handshake_accepted_with_non_cover_sni_is_likely_grease() {
    // The handshake reached ServerHello without retry_configs,
    // so EchOutcome::Accepted — but outer SNI doesn't match
    // the cover set. Most-likely GREASE that the server simply
    // ignored.
    assert_eq!(
        hs_with(EchOutcome::Accepted, Some("example.com")).ech_state(),
        EchState::LikelyGrease
    );
}

#[test]
fn handshake_unknown_falls_through_to_sni_classification() {
    assert_eq!(
        hs_with(EchOutcome::Unknown, Some("public.cloudflare-ech.com")).ech_state(),
        EchState::LikelyReal
    );
}

#[test]
fn slug_vocabulary_locked() {
    assert_eq!(EchState::NotPresent.as_str(), "not_present");
    assert_eq!(EchState::LikelyReal.as_str(), "likely_real");
    assert_eq!(EchState::LikelyGrease.as_str(), "likely_grease");
    assert_eq!(EchState::Rejected.as_str(), "rejected");
}

#[test]
fn cover_domains_contains_cloudflare() {
    assert!(
        ech_cover_domains().contains(&"cloudflare-ech.com"),
        "Cloudflare cover domain must be in the curated list"
    );
}

#[test]
fn classify_client_hello_function_matches_method() {
    // The free function and the method on TlsClientHello must
    // agree — the method is just a thin wrapper.
    for (present, sni) in [
        (false, None),
        (false, Some("example.com")),
        (true, None),
        (true, Some("example.com")),
        (true, Some("cloudflare-ech.com")),
    ] {
        assert_eq!(
            ch_with(present, sni).ech_state(),
            classify_client_hello(present, sni),
            "mismatch for (present={present}, sni={sni:?})"
        );
    }
}

#[test]
fn cover_domain_predicate_rejects_substring_attack() {
    assert!(!is_ech_cover_domain("cloudflare-ech.com.attacker.tld"));
    assert!(!is_ech_cover_domain("fakecloudflare-ech.com"));
}
