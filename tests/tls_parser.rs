//! Parser tests using hand-crafted synthetic TLS records.
//!
//! Drives the `SessionParser` API (`TlsParser::feed_initiator`
//! / `feed_responder`) and collects emitted `TlsMessage`
//! variants.

use flowscope::{
    SessionParser, Timestamp,
    tls::{TlsAlert, TlsClientHello, TlsMessage, TlsParser, TlsServerHello, TlsVersion},
};

#[derive(Default)]
struct Captured {
    client_hellos: Vec<TlsClientHello>,
    server_hellos: Vec<TlsServerHello>,
    alerts: Vec<TlsAlert>,
    #[cfg(feature = "tls-fingerprints")]
    ja3s: Vec<(String, String)>,
}

impl Captured {
    fn ingest(&mut self, msgs: Vec<TlsMessage>) {
        for m in msgs {
            match m {
                TlsMessage::ClientHello(ch) => self.client_hellos.push(*ch),
                TlsMessage::ServerHello(sh) => self.server_hellos.push(*sh),
                TlsMessage::Alert(a) => self.alerts.push(a),
                #[cfg(feature = "tls-fingerprints")]
                TlsMessage::Ja3 { hash, canonical } => self.ja3s.push((hash, canonical)),
                #[cfg(feature = "tls-fingerprints")]
                TlsMessage::Ja4 { .. } => {}
                #[cfg(feature = "ja4plus")]
                TlsMessage::Ja4s { .. } => {}
                TlsMessage::Certificate { .. } => {}
                _ => {}
            }
        }
    }
}

// ── synthetic TLS record builders ──────────────────────────────

fn record(content_type: u8, version: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(content_type);
    out.extend_from_slice(&version.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

fn handshake(msg_type: u8, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + body.len());
    out.push(msg_type);
    let len = body.len() as u32;
    out.push((len >> 16) as u8);
    out.push((len >> 8) as u8);
    out.push(len as u8);
    out.extend_from_slice(body);
    out
}

fn client_hello_with_sni(host: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let mut exts = Vec::new();
    let host_bytes = host.as_bytes();
    let mut sni_data = Vec::new();
    let server_name_list_len = (3 + host_bytes.len()) as u16;
    sni_data.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_data.push(0);
    sni_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(host_bytes);
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_data);

    let alpn_list = b"\x02h2";
    let mut alpn_data = Vec::new();
    alpn_data.extend_from_slice(&(alpn_list.len() as u16).to_be_bytes());
    alpn_data.extend_from_slice(alpn_list);
    exts.extend_from_slice(&16u16.to_be_bytes());
    exts.extend_from_slice(&(alpn_data.len() as u16).to_be_bytes());
    exts.extend_from_slice(&alpn_data);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let hs = handshake(1, &body);
    record(22, 0x0303, &hs)
}

fn client_hello_with_ech(host: &str, config_id: u8) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&2u16.to_be_bytes());
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(1);
    body.push(0);

    let mut exts = Vec::new();
    // SNI (outer / cover)
    let host_bytes = host.as_bytes();
    let mut sni_data = Vec::new();
    let server_name_list_len = (3 + host_bytes.len()) as u16;
    sni_data.extend_from_slice(&server_name_list_len.to_be_bytes());
    sni_data.push(0);
    sni_data.extend_from_slice(&(host_bytes.len() as u16).to_be_bytes());
    sni_data.extend_from_slice(host_bytes);
    exts.extend_from_slice(&0u16.to_be_bytes());
    exts.extend_from_slice(&(sni_data.len() as u16).to_be_bytes());
    exts.extend_from_slice(&sni_data);

    // ECH (extension type 0xfe0d, outer form).
    // Body layout (RFC draft §5.1):
    //   1B  ECHClientHelloType (0 = outer)
    //   1B  HPKE config_id
    //   2B  HPKE KDF
    //   2B  HPKE AEAD
    //   2B  enc.len + enc bytes (use 0 bytes for the smoke test)
    //   2B  payload.len + payload bytes
    let mut ech_body = Vec::new();
    ech_body.push(0); // outer
    ech_body.push(config_id);
    ech_body.extend_from_slice(&0x0001u16.to_be_bytes()); // KDF
    ech_body.extend_from_slice(&0x0001u16.to_be_bytes()); // AEAD
    ech_body.extend_from_slice(&0u16.to_be_bytes()); // enc.len
    ech_body.extend_from_slice(&0u16.to_be_bytes()); // payload.len
    exts.extend_from_slice(&0xfe0du16.to_be_bytes());
    exts.extend_from_slice(&(ech_body.len() as u16).to_be_bytes());
    exts.extend_from_slice(&ech_body);

    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let hs = handshake(1, &body);
    record(22, 0x0303, &hs)
}

fn server_hello() -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x0303u16.to_be_bytes());
    body.extend_from_slice(&[0u8; 32]);
    body.push(0);
    body.extend_from_slice(&0x1301u16.to_be_bytes());
    body.push(0);
    body.extend_from_slice(&0u16.to_be_bytes());
    let hs = handshake(2, &body);
    record(22, 0x0303, &hs)
}

fn alert_record(level: u8, desc: u8) -> Vec<u8> {
    record(21, 0x0303, &[level, desc])
}

// ── tests ──────────────────────────────────────────────────────

fn feed_init(parser: &mut TlsParser, captured: &mut Captured, bytes: &[u8]) {
    let mut out = Vec::new();
    parser.feed_initiator(bytes, Timestamp::default(), &mut out);
    captured.ingest(out);
}

fn feed_resp(parser: &mut TlsParser, captured: &mut Captured, bytes: &[u8]) {
    let mut out = Vec::new();
    parser.feed_responder(bytes, Timestamp::default(), &mut out);
    captured.ingest(out);
}

#[test]
fn ech_extension_marks_present_and_captures_config_id() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = client_hello_with_ech("cover.example.com", 7);
    feed_init(&mut parser, &mut captured, &bytes);
    assert_eq!(captured.client_hellos.len(), 1);
    let ch = &captured.client_hellos[0];
    assert!(ch.ech_present, "ECH extension should be detected");
    assert_eq!(ch.ech_config_id, Some(7));
    assert!(
        ch.sni_is_outer,
        "when ECH is present, the parsed SNI is the outer cover"
    );
    // SNI carries the outer cover (it's still the SNI extension
    // bytes; passive observers can't see the inner SNI).
    assert_eq!(ch.sni.as_deref(), Some("cover.example.com"));
}

#[test]
fn non_ech_client_hello_leaves_fields_default() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = client_hello_with_sni("example.com");
    feed_init(&mut parser, &mut captured, &bytes);
    let ch = &captured.client_hellos[0];
    assert!(!ch.ech_present);
    assert!(ch.ech_config_id.is_none());
    assert!(!ch.sni_is_outer);
}

#[test]
fn parses_client_hello_with_sni() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = client_hello_with_sni("example.com");
    feed_init(&mut parser, &mut captured, &bytes);
    assert_eq!(captured.client_hellos.len(), 1);
    assert_eq!(
        captured.client_hellos[0].sni.as_deref(),
        Some("example.com")
    );
    assert_eq!(captured.client_hellos[0].alpn, vec!["h2".to_string()]);
    assert_eq!(captured.client_hellos[0].cipher_suites, vec![0x1301]);
}

#[test]
fn parses_server_hello() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = server_hello();
    feed_resp(&mut parser, &mut captured, &bytes);
    assert_eq!(captured.server_hellos.len(), 1);
    assert_eq!(captured.server_hellos[0].cipher_suite, 0x1301);
    assert_eq!(captured.server_hellos[0].legacy_version, TlsVersion::Tls1_2);
}

#[test]
fn parses_alert() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = alert_record(2, 40);
    feed_init(&mut parser, &mut captured, &bytes);
    assert_eq!(captured.alerts.len(), 1);
    assert_eq!(captured.alerts[0].description, 40);
}

#[test]
fn record_split_across_segments() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let bytes = client_hello_with_sni("example.com");
    let mid = bytes.len() / 2;
    feed_init(&mut parser, &mut captured, &bytes[..mid]);
    assert!(
        captured.client_hellos.is_empty(),
        "should wait for full record"
    );
    feed_init(&mut parser, &mut captured, &bytes[mid..]);
    assert_eq!(captured.client_hellos.len(), 1);
    assert_eq!(
        captured.client_hellos[0].sni.as_deref(),
        Some("example.com")
    );
}

#[test]
fn change_cipher_spec_stops_parsing() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let mut combined = Vec::new();
    combined.extend_from_slice(&server_hello());
    combined.extend_from_slice(&record(20, 0x0303, &[0x01])); // ChangeCipherSpec
    combined.extend_from_slice(&server_hello());
    feed_resp(&mut parser, &mut captured, &combined);
    // Only the first ServerHello parses; the second is past CCS.
    assert_eq!(captured.server_hellos.len(), 1);
}

#[test]
fn malformed_doesnt_panic() {
    let mut parser = TlsParser::default();
    let mut captured = Captured::default();
    let mut bad = vec![22u8, 0x03, 0x03, 0x00, 0x10];
    bad.extend_from_slice(&[0xff; 16]);
    feed_init(&mut parser, &mut captured, &bad);
    // Should not panic; the parser enters Desynced state.
}

#[cfg(feature = "tls-fingerprints")]
#[test]
fn ja3_fires_when_enabled() {
    use flowscope::tls::TlsConfig;
    let mut cfg = TlsConfig::default();
    cfg.ja3 = true;
    let mut parser = TlsParser::with_config(cfg);
    let mut captured = Captured::default();
    let bytes = client_hello_with_sni("example.com");
    feed_init(&mut parser, &mut captured, &bytes);
    assert_eq!(captured.ja3s.len(), 1);
    assert!(!captured.ja3s[0].0.is_empty(), "expected non-empty hash");
}

#[cfg(feature = "tls-fingerprints")]
#[test]
fn ja4_fires_when_enabled() {
    use flowscope::tls::TlsConfig;
    let mut cfg = TlsConfig::default();
    cfg.ja4 = true;
    let mut parser = TlsParser::with_config(cfg);
    let captured = std::cell::RefCell::new(Vec::new());
    let mut out = Vec::new();
    parser.feed_initiator(
        &client_hello_with_sni("example.com"),
        Timestamp::default(),
        &mut out,
    );
    for msg in out {
        if let TlsMessage::Ja4 { fingerprint } = msg {
            captured.borrow_mut().push(fingerprint);
        }
    }
    assert_eq!(captured.borrow().len(), 1);
    assert!(captured.borrow()[0].starts_with('t'));
}

#[cfg(feature = "tls-fingerprints")]
#[test]
fn standalone_ja3_matches_message_hash_and_facade_reexports() {
    use flowscope::tls::TlsConfig;
    // Capture both the ClientHello and the parser-emitted JA3 so we
    // can prove the standalone fn (issue #136) yields the same hash.
    let mut cfg = TlsConfig::default();
    cfg.ja3 = true;
    let mut parser = TlsParser::with_config(cfg);
    let mut captured = Captured::default();
    feed_init(
        &mut parser,
        &mut captured,
        &client_hello_with_sni("example.com"),
    );
    let ch = captured.client_hellos.first().expect("client hello");
    let (msg_hash, _canonical) = captured.ja3s.first().cloned().expect("ja3 message");

    // Standalone fns (both the `tls::` home and the `fingerprint::`
    // facade re-export) agree with the message-emitted hash.
    assert_eq!(flowscope::tls::ja3_fingerprint(ch), msg_hash);
    assert_eq!(flowscope::fingerprint::ja3_fingerprint(ch), msg_hash);
    assert!(!flowscope::tls::ja3_canonical(ch).is_empty());

    // JA4 facade re-export matches the `tls::` fn and is transport 't'.
    let ja4_home = flowscope::tls::ja4_fingerprint(ch);
    assert_eq!(flowscope::fingerprint::ja4_fingerprint(ch), ja4_home);
    assert!(ja4_home.starts_with('t'));
}
