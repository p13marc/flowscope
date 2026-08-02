//! Request-smuggling regression suite for the streaming HTTP parser.
//!
//! Every case here is a way to make two HTTP implementations disagree
//! about where a message ends. A proxy that resolves the ambiguity
//! differently from its backend lets an attacker prepend bytes to
//! somebody else's request — the CL.TE / TE.CL / TE.TE family from
//! PortSwigger's "HTTP Desync Attacks".
//!
//! The contract asserted here is that flowscope **names** the problem
//! (a typed [`HttpPoison`]) rather than silently picking one reading,
//! so a proxy can fail the connection instead of forwarding it.

#![cfg(feature = "http")]

use bytes::Bytes;
use flowscope::FlowSide;
use flowscope::http::{
    HttpEvent, HttpPoison, HttpProxyConfig, HttpProxyParser, Normalization, SmugglingPolicy,
};

/// Feed one request and report how the parser resolved it.
fn parse_with(policy: SmugglingPolicy, wire: &[u8]) -> (Vec<HttpEvent>, Option<HttpPoison>) {
    let mut cfg = HttpProxyConfig::default();
    cfg.smuggling = policy;
    let mut p = HttpProxyParser::with_config(cfg);
    p.push(FlowSide::Initiator, &Bytes::copy_from_slice(wire));
    let mut evs = Vec::new();
    while let Some(ev) = p.next_event() {
        evs.push(ev);
    }
    (evs, p.poison())
}

fn poison_of(policy: SmugglingPolicy, wire: &[u8]) -> Option<HttpPoison> {
    parse_with(policy, wire).1
}

fn head_of(evs: &[HttpEvent]) -> Option<flowscope::http::RequestHead> {
    evs.iter().find_map(|e| match e {
        HttpEvent::RequestHead(h) => Some(h.clone()),
        _ => None,
    })
}

// ── CL.TE / TE.CL: both framing headers present ───────────────────

const CL_TE: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\n\
                       Transfer-Encoding: chunked\r\n\r\n0\r\n\r\nX";

#[test]
fn content_length_with_transfer_encoding_is_refused() {
    // The classic desync: one hop reads 6 body bytes, the other reads
    // a zero-size chunk and treats "X" as the next request.
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, CL_TE),
        Some(HttpPoison::ContentLengthWithTransferEncoding)
    );
}

#[test]
fn normalize_drops_content_length_and_records_it() {
    // RFC 9112 §6.3.3: chunked wins and the length is dropped. The
    // head records that, because its raw bytes are now unsafe to
    // forward verbatim.
    let (evs, poison) = parse_with(SmugglingPolicy::Normalize, CL_TE);
    assert_eq!(poison, None);
    let head = head_of(&evs).expect("head");
    assert_eq!(head.framing, flowscope::http::BodyFraming::Chunked);
    assert!(head.applied.contains(&Normalization::StrippedContentLength));
}

#[test]
fn observe_never_poisons_on_a_framing_ambiguity() {
    // Passive telemetry keeps observing: it is not in a position to
    // be exploited, and dropping the flow would only lose visibility.
    //
    // Heads only — what is under test is the framing *decision*. (A
    // body whose framing nobody can agree on will of course produce
    // leftovers that do not parse as the next message; that is a
    // consequence of the ambiguity, not a policy choice.)
    let heads: &[&[u8]] = &[
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, identity\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: xchunked\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\nTransfer-Encoding: identity\r\n\r\n",
        b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: +3\r\n\r\n",
        DUP_HOST,
    ];
    for wire in heads {
        assert_eq!(
            poison_of(SmugglingPolicy::Observe, wire),
            None,
            "Observe must not poison on {:?}",
            String::from_utf8_lossy(&wire[..wire.len().min(60)])
        );
    }
}

#[test]
fn telemetry_parser_never_poisons_on_the_smuggling_corpus() {
    // The passive front-end is hard-wired to Observe, so none of
    // these can tear down a monitored flow.
    use flowscope::SessionParser;
    use flowscope::http::HttpParser;
    for wire in [
        CL_TE,
        DUP_CL_DIFFERENT,
        TE_NOT_FINAL,
        TE_UNKNOWN_CODING,
        TE_DUPLICATED,
        CL_PLUS_SIGN,
        DUP_HOST,
    ] {
        let mut p = HttpParser::default();
        let mut out = Vec::new();
        p.feed_initiator(wire, flowscope::Timestamp::default(), &mut out);
        p.fin_initiator(&mut out);
        assert!(!p.is_poisoned(), "telemetry must keep observing");
    }
}

// ── duplicated Content-Length ─────────────────────────────────────

const DUP_CL_SAME: &[u8] =
    b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 3\r\n\r\nabc";
const DUP_CL_DIFFERENT: &[u8] =
    b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3\r\nContent-Length: 4\r\n\r\nabcd";
const CL_LIST_SAME: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 3, 3\r\n\r\nabc";

#[test]
fn identical_content_lengths_collapse() {
    let (evs, poison) = parse_with(SmugglingPolicy::Strict, DUP_CL_SAME);
    assert_eq!(poison, None, "agreeing values are not ambiguous");
    let head = head_of(&evs).expect("head");
    assert_eq!(head.framing, flowscope::http::BodyFraming::ContentLength(3));
    assert!(
        head.applied
            .contains(&Normalization::CollapsedContentLength)
    );
}

#[test]
fn comma_separated_identical_lengths_collapse() {
    let (evs, poison) = parse_with(SmugglingPolicy::Strict, CL_LIST_SAME);
    assert_eq!(poison, None);
    assert_eq!(
        head_of(&evs).expect("head").framing,
        flowscope::http::BodyFraming::ContentLength(3)
    );
}

#[test]
fn differing_content_lengths_are_refused() {
    for policy in [SmugglingPolicy::Strict, SmugglingPolicy::Normalize] {
        assert_eq!(
            poison_of(policy, DUP_CL_DIFFERENT),
            Some(HttpPoison::ConflictingContentLength),
            "{policy:?} must refuse contradictory lengths"
        );
    }
}

// ── Content-Length that is not a plain number ─────────────────────

const CL_PLUS_SIGN: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: +3\r\n\r\nabc";
const CL_HEX: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nContent-Length: 0x3\r\n\r\nabc";

#[test]
fn non_decimal_content_length_is_refused() {
    // `+3` parses as 3 for a permissive recipient and fails for a
    // strict one — the two then disagree about the body length.
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, CL_PLUS_SIGN),
        Some(HttpPoison::InvalidContentLength)
    );
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, CL_HEX),
        Some(HttpPoison::InvalidContentLength)
    );
}

// ── TE.TE: obfuscated Transfer-Encoding ───────────────────────────

const TE_NOT_FINAL: &[u8] =
    b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n";
const TE_UNKNOWN_CODING: &[u8] =
    b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: xchunked\r\n\r\n0\r\n\r\n";
const TE_DUPLICATED: &[u8] = b"POST /a HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\
                               Transfer-Encoding: identity\r\n\r\n0\r\n\r\n";

#[test]
fn chunked_must_be_the_final_coding() {
    // §6.3 rule 3: if chunked is not last, the length is undefined.
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, TE_NOT_FINAL),
        Some(HttpPoison::NonFinalChunked)
    );
}

#[test]
fn unknown_transfer_coding_is_refused() {
    // `xchunked` is ignored by one hop and read as chunked by a hop
    // doing a substring match.
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, TE_UNKNOWN_CODING),
        Some(HttpPoison::UnknownTransferCoding)
    );
}

#[test]
fn duplicated_transfer_encoding_is_refused() {
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, TE_DUPLICATED),
        Some(HttpPoison::DuplicateTransferEncoding)
    );
}

// ── line-ending tricks ────────────────────────────────────────────

#[test]
fn obs_fold_is_refused() {
    // A folded header value (RFC 9112 §5.2, deprecated) is joined by
    // some parsers and treated as a new header by others.
    let wire = b"POST /a HTTP/1.1\r\nHost: h\r\nX-Thing: one\r\n two\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, wire),
        Some(HttpPoison::ObsFold)
    );
}

#[test]
fn bare_cr_in_the_head_is_refused() {
    let wire = b"POST /a HTTP/1.1\r\nHost: h\rX-Evil: 1\r\nContent-Length: 0\r\n\r\n";
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, wire),
        Some(HttpPoison::BareCr)
    );
}

// ── routing-key ambiguity ─────────────────────────────────────────

const DUP_HOST: &[u8] = b"GET /a HTTP/1.1\r\nHost: one.example\r\nHost: two.example\r\n\r\n";

#[test]
fn duplicate_host_is_refused() {
    // Two hops could route this to two different backends.
    assert_eq!(
        poison_of(SmugglingPolicy::Strict, DUP_HOST),
        Some(HttpPoison::DuplicateHost)
    );
}

#[test]
fn absolute_form_authority_wins_over_host() {
    // RFC 9112 §3.2. A proxy routing on Host while the backend routes
    // on the absolute form is exploitable.
    let wire = b"GET http://real.example/a HTTP/1.1\r\nHost: decoy.example\r\n\r\n";
    let (evs, poison) = parse_with(SmugglingPolicy::Strict, wire);
    assert_eq!(poison, None);
    let authority = head_of(&evs).expect("head").authority().expect("authority");
    assert_eq!(authority.host, "real.example");
}

#[test]
fn authority_is_ascii_lowercased_never_unicode_folded() {
    // U+212A KELVIN SIGN folds to `k` under Unicode rules, so a
    // Unicode-lowercasing hop and an ASCII-lowercasing hop disagree
    // about the host. Non-ASCII is refused outright.
    let wire = "GET /a HTTP/1.1\r\nHost: \u{212A}elvin.example\r\n\r\n".as_bytes();
    let (evs, _) = parse_with(SmugglingPolicy::Strict, wire);
    let err = head_of(&evs)
        .expect("head")
        .authority()
        .expect_err("non-ASCII authority must be refused");
    assert_eq!(err, HttpPoison::NonAsciiAuthority);

    // Plain ASCII still lowercases.
    let wire = b"GET /a HTTP/1.1\r\nHost: Example.COM:8443\r\n\r\n";
    let (evs, _) = parse_with(SmugglingPolicy::Strict, wire);
    let authority = head_of(&evs).expect("head").authority().expect("authority");
    assert_eq!(authority.host, "example.com");
    assert_eq!(authority.port, Some(8443));
}

#[test]
fn ipv6_authority_keeps_its_brackets_out_of_the_host() {
    let wire = b"GET http://[2001:DB8::1]:8080/a HTTP/1.1\r\nHost: h\r\n\r\n";
    let (evs, _) = parse_with(SmugglingPolicy::Strict, wire);
    let authority = head_of(&evs).expect("head").authority().expect("authority");
    assert_eq!(authority.host, "2001:db8::1");
    assert_eq!(authority.port, Some(8080));
}

// ── responses ─────────────────────────────────────────────────────

#[test]
fn response_without_a_request_is_refused() {
    let mut p = HttpProxyParser::new();
    p.push(
        FlowSide::Responder,
        &Bytes::from_static(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n"),
    );
    while p.next_event().is_some() {}
    assert_eq!(p.poison(), Some(HttpPoison::UnexpectedResponse));
}

#[test]
fn response_smuggling_headers_are_refused_too() {
    // The same §6.3 rules apply to the server's side of the wire.
    let mut p = HttpProxyParser::new();
    p.push(
        FlowSide::Initiator,
        &Bytes::from_static(b"GET /a HTTP/1.1\r\nHost: h\r\n\r\n"),
    );
    while p.next_event().is_some() {}
    p.push(
        FlowSide::Responder,
        &Bytes::from_static(
            b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
        ),
    );
    while p.next_event().is_some() {}
    assert_eq!(
        p.poison(),
        Some(HttpPoison::ContentLengthWithTransferEncoding)
    );
}

// ── the contract itself ───────────────────────────────────────────

#[test]
fn a_poisoned_connection_forwards_nothing_further() {
    let mut p = HttpProxyParser::new();
    p.push(FlowSide::Initiator, &Bytes::copy_from_slice(CL_TE));
    while p.next_event().is_some() {}
    assert!(p.is_poisoned());
    // The whole point: no further bytes are accepted or framed, so a
    // proxy cannot be tricked into relaying the smuggled remainder.
    let more = Bytes::from_static(b"GET /smuggled HTTP/1.1\r\nHost: h\r\n\r\n");
    assert_eq!(p.push(FlowSide::Initiator, &more), 0);
    assert!(p.next_event().is_none());
}

#[test]
fn poison_reasons_are_distinct_and_stable() {
    // The slug is what a consumer logs or maps to a status code, so
    // it must identify the specific violation.
    let cases: &[(&[u8], &str)] = &[
        (CL_TE, "content-length-with-transfer-encoding"),
        (DUP_CL_DIFFERENT, "conflicting-content-length"),
        (TE_NOT_FINAL, "non-final-chunked"),
        (TE_UNKNOWN_CODING, "unknown-transfer-coding"),
        (TE_DUPLICATED, "duplicate-transfer-encoding"),
        (CL_PLUS_SIGN, "invalid-content-length"),
        (DUP_HOST, "duplicate-host"),
    ];
    for (wire, slug) in cases {
        let poison = poison_of(SmugglingPolicy::Strict, wire).expect("must poison");
        assert_eq!(poison.as_str(), *slug);
    }
}

#[test]
fn well_formed_traffic_is_untouched_by_the_defenses() {
    // The defenses must not cost anything on ordinary traffic.
    let wire: &[u8] =
        b"POST /submit HTTP/1.1\r\nHost: api.example\r\nContent-Length: 5\r\n\r\nhello\
                        GET /next HTTP/1.1\r\nHost: api.example\r\n\r\n";
    let (evs, poison) = parse_with(SmugglingPolicy::Strict, wire);
    assert_eq!(poison, None);
    let heads = evs
        .iter()
        .filter(|e| matches!(e, HttpEvent::RequestHead(_)))
        .count();
    assert_eq!(heads, 2);
    for ev in &evs {
        if let HttpEvent::RequestHead(h) = ev {
            assert!(h.applied.is_empty(), "nothing to normalize");
        }
    }
}
