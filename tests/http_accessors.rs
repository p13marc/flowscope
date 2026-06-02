//! Plan 78 — convenience accessors on `HttpRequest`,
//! `HttpResponse`, and `TlsClientHello`. Each accessor's happy
//! path + the case-insensitivity + non-UTF-8 + multi-value
//! edge cases.

#![cfg(any(feature = "http", feature = "tls"))]

#[cfg(feature = "http")]
mod http_request {
    use bytes::Bytes;
    use flowscope::http::{HttpRequest, HttpVersion};

    fn fixture_with(headers: Vec<(&str, &[u8])>) -> HttpRequest {
        HttpRequest {
            method: "GET".to_string(),
            path: "/".to_string(),
            version: HttpVersion::Http1_1,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_vec()))
                .collect(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn host_happy_path() {
        let req = fixture_with(vec![("Host", b"example.com")]);
        assert_eq!(req.host(), Some("example.com"));
    }

    #[test]
    fn host_case_insensitive() {
        for spelling in ["Host", "HOST", "host", "HoSt"] {
            let req = fixture_with(vec![(spelling, b"example.com")]);
            assert_eq!(req.host(), Some("example.com"), "spelling: {spelling}");
        }
    }

    #[test]
    fn host_absent_is_none() {
        let req = fixture_with(vec![("User-Agent", b"curl/8.0")]);
        assert!(req.host().is_none());
    }

    #[test]
    fn host_non_utf8_value_is_none_via_str_accessor() {
        // Invalid UTF-8 byte 0xff in the Host header.
        let req = fixture_with(vec![("Host", &[0xff, 0x00, 0xff][..])]);
        assert!(req.host().is_none());
        // But the raw `header()` returns the bytes.
        assert_eq!(req.header("host"), Some(&[0xff, 0x00, 0xff][..]));
    }

    #[test]
    fn user_agent_happy_path() {
        let req = fixture_with(vec![("User-Agent", b"Mozilla/5.0")]);
        assert_eq!(req.user_agent(), Some("Mozilla/5.0"));
    }

    #[test]
    fn cookie_returns_raw_value() {
        let req = fixture_with(vec![("Cookie", b"sid=abc; theme=dark")]);
        assert_eq!(req.cookie(), Some("sid=abc; theme=dark"));
    }

    #[test]
    fn header_generic_lookup() {
        let req = fixture_with(vec![
            ("Authorization", b"Bearer xyz"),
            ("X-Custom", b"value"),
        ]);
        assert_eq!(req.header("authorization"), Some(&b"Bearer xyz"[..]));
        assert_eq!(req.header("X-CUSTOM"), Some(&b"value"[..]));
        assert!(req.header("Missing").is_none());
    }

    #[test]
    fn headers_all_yields_all_matches_in_order() {
        let req = fixture_with(vec![
            ("X-Forwarded-For", b"1.2.3.4"),
            ("Accept", b"*/*"),
            ("X-Forwarded-For", b"5.6.7.8"),
        ]);
        let collected: Vec<&[u8]> = req.headers_all("x-forwarded-for").collect();
        assert_eq!(collected, vec![&b"1.2.3.4"[..], &b"5.6.7.8"[..]]);
    }
}

#[cfg(feature = "http")]
mod http_response {
    use bytes::Bytes;
    use flowscope::http::{HttpResponse, HttpVersion};

    fn fixture_with(headers: Vec<(&str, &[u8])>) -> HttpResponse {
        HttpResponse {
            status: 200,
            reason: "OK".to_string(),
            version: HttpVersion::Http1_1,
            headers: headers
                .into_iter()
                .map(|(k, v)| (k.to_string(), v.to_vec()))
                .collect(),
            body: Bytes::new(),
        }
    }

    #[test]
    fn content_type_happy_path() {
        let resp = fixture_with(vec![("Content-Type", b"application/json")]);
        assert_eq!(resp.content_type(), Some("application/json"));
    }

    #[test]
    fn content_length_parses_clean_number() {
        let resp = fixture_with(vec![("Content-Length", b"1234")]);
        assert_eq!(resp.content_length(), Some(1234));
    }

    #[test]
    fn content_length_handles_whitespace() {
        let resp = fixture_with(vec![("Content-Length", b"  4096  ")]);
        assert_eq!(resp.content_length(), Some(4096));
    }

    #[test]
    fn content_length_rejects_nonnumeric() {
        let resp = fixture_with(vec![("Content-Length", b"chunked-ish")]);
        assert!(resp.content_length().is_none());
    }

    #[test]
    fn content_length_rejects_overflow() {
        // u64::MAX is 18446744073709551615; one more overflows.
        let resp = fixture_with(vec![("Content-Length", b"18446744073709551616")]);
        assert!(resp.content_length().is_none());
    }

    #[test]
    fn set_cookie_iter_yields_each_header() {
        let resp = fixture_with(vec![
            ("Set-Cookie", b"a=1"),
            ("X-Other", b"_"),
            ("Set-Cookie", b"b=2"),
            ("set-cookie", b"c=3"), // lowercase, still matched
        ]);
        let cookies: Vec<&str> = resp.set_cookie().collect();
        assert_eq!(cookies, vec!["a=1", "b=2", "c=3"]);
    }

    #[test]
    fn set_cookie_skips_non_utf8() {
        let resp = fixture_with(vec![
            ("Set-Cookie", b"a=1"),
            ("Set-Cookie", &[0xff][..]),
            ("Set-Cookie", b"c=3"),
        ]);
        let cookies: Vec<&str> = resp.set_cookie().collect();
        assert_eq!(cookies, vec!["a=1", "c=3"]);
    }
}

#[cfg(feature = "tls")]
mod tls_client_hello {
    use flowscope::tls::{TlsClientHello, TlsVersion};

    fn fixture(sni: Option<&str>) -> TlsClientHello {
        TlsClientHello {
            record_version: TlsVersion::Tls1_0,
            legacy_version: TlsVersion::Tls1_2,
            random: [0; 32],
            session_id: bytes::Bytes::new(),
            cipher_suites: vec![],
            compression: vec![0],
            sni: sni.map(str::to_string),
            alpn: vec![],
            supported_versions: vec![],
            supported_groups: vec![],
            extension_types: vec![],
        }
    }

    #[test]
    fn sni_method_returns_value_when_present() {
        let hello = fixture(Some("example.com"));
        assert_eq!(hello.sni(), Some("example.com"));
    }

    #[test]
    fn sni_method_returns_none_when_absent() {
        let hello = fixture(None);
        assert!(hello.sni().is_none());
    }

    #[test]
    fn sni_method_matches_field() {
        let hello = fixture(Some("api.foo.com"));
        assert_eq!(hello.sni(), hello.sni.as_deref());
    }
}
