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
            method: Bytes::from_static(b"GET"),
            path: Bytes::from_static(b"/"),
            version: HttpVersion::Http1_1,
            headers: headers
                .into_iter()
                .map(|(k, v)| {
                    (
                        Bytes::copy_from_slice(k.as_bytes()),
                        Bytes::copy_from_slice(v),
                    )
                })
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
    fn referer_returns_first_header() {
        let req = fixture_with(vec![("Referer", b"https://example.com/")]);
        assert_eq!(req.referer(), Some("https://example.com/"));
    }

    #[test]
    fn accept_returns_first_header() {
        let req = fixture_with(vec![("Accept", b"text/html, application/json")]);
        assert_eq!(req.accept(), Some("text/html, application/json"));
    }

    #[test]
    fn request_content_type_and_length() {
        let req = fixture_with(vec![
            ("Content-Type", b"application/json"),
            ("Content-Length", b"42"),
        ]);
        assert_eq!(req.content_type(), Some("application/json"));
        assert_eq!(req.content_length(), Some(42));
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
            reason: Bytes::from_static(b"OK"),
            version: HttpVersion::Http1_1,
            headers: headers
                .into_iter()
                .map(|(k, v)| {
                    (
                        Bytes::copy_from_slice(k.as_bytes()),
                        Bytes::copy_from_slice(v),
                    )
                })
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

    fn fixture_with_status(status: u16, headers: Vec<(&str, &[u8])>) -> HttpResponse {
        let mut resp = fixture_with(headers);
        resp.status = status;
        resp
    }

    #[test]
    fn status_class_buckets() {
        assert_eq!(fixture_with_status(100, vec![]).status_class(), Some(1));
        assert_eq!(fixture_with_status(200, vec![]).status_class(), Some(2));
        assert_eq!(fixture_with_status(301, vec![]).status_class(), Some(3));
        assert_eq!(fixture_with_status(404, vec![]).status_class(), Some(4));
        assert_eq!(fixture_with_status(503, vec![]).status_class(), Some(5));
        assert_eq!(fixture_with_status(0, vec![]).status_class(), None);
        assert_eq!(fixture_with_status(999, vec![]).status_class(), None);
    }

    #[test]
    fn is_success_redirect_client_server_error_predicates() {
        assert!(fixture_with_status(200, vec![]).is_success());
        assert!(!fixture_with_status(404, vec![]).is_success());
        assert!(fixture_with_status(301, vec![]).is_redirect());
        assert!(!fixture_with_status(200, vec![]).is_redirect());
        assert!(fixture_with_status(404, vec![]).is_client_error());
        assert!(!fixture_with_status(503, vec![]).is_client_error());
        assert!(fixture_with_status(503, vec![]).is_server_error());
        assert!(!fixture_with_status(200, vec![]).is_server_error());
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
        // TlsClientHello is #[non_exhaustive] since 0.12 plan 144 —
        // construct via Default + mutate (the documented pattern).
        let mut hello = TlsClientHello::default();
        hello.record_version = TlsVersion::Tls1_0;
        hello.legacy_version = TlsVersion::Tls1_2;
        hello.compression = bytes::Bytes::from_static(&[0]);
        hello.sni = sni.map(str::to_string);
        hello
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
