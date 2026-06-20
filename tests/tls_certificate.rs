//! Issue #24 prereq — TLS Certificate handshake surface.
//!
//! Verifies that [`flowscope::tls::TlsParser`] emits
//! `TlsMessage::Certificate { chain }` when the server's
//! `Certificate` handshake record (TLS 1.2) is decoded, and
//! that [`flowscope::tls::TlsHandshakeParser`] aggregates the
//! cert chain onto the per-handshake message.

#![cfg(feature = "tls")]

use flowscope::tls::{TlsHandshakeParser, TlsMessage, TlsParser};
use flowscope::{SessionParser, Timestamp};

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

fn certificate_record(cert_blobs: &[&[u8]]) -> Vec<u8> {
    // Cert handshake body:
    //   3B cert_chain_total_length
    //   per cert: 3B cert_length + cert bytes
    let mut chain_body = Vec::new();
    for c in cert_blobs {
        let l = c.len() as u32;
        chain_body.push((l >> 16) as u8);
        chain_body.push((l >> 8) as u8);
        chain_body.push(l as u8);
        chain_body.extend_from_slice(c);
    }
    let mut body = Vec::with_capacity(3 + chain_body.len());
    let t = chain_body.len() as u32;
    body.push((t >> 16) as u8);
    body.push((t >> 8) as u8);
    body.push(t as u8);
    body.extend_from_slice(&chain_body);

    let hs = handshake(11, &body); // 11 = Certificate
    record(0x16, 0x0303, &hs) // 0x16 = handshake; 0x0303 = TLS 1.2
}

#[test]
fn tls_parser_emits_certificate_message_for_server_side() {
    // Two fake "cert" blobs — the parser is opaque about DER
    // content, just slices the chain entries.
    let cert_a: &[u8] = b"\x30\x82\x01\x00FAKE_LEAF_DER_BYTES";
    let cert_b: &[u8] = b"\x30\x82\x02\x00FAKE_INTERMEDIATE_DER";
    let frame = certificate_record(&[cert_a, cert_b]);

    let mut p = TlsParser::default();
    let mut out = Vec::new();
    // Server side — TLS 1.2 cert chains arrive from the responder.
    p.feed_responder(&frame, Timestamp::default(), &mut out);

    let chains: Vec<_> = out
        .iter()
        .filter_map(|m| match m {
            TlsMessage::Certificate { chain } => Some(chain.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(chains.len(), 1, "expected one Certificate message");
    let chain = &chains[0];
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0].as_ref(), cert_a);
    assert_eq!(chain[1].as_ref(), cert_b);
}

#[test]
fn tls_handshake_parser_aggregates_certificate_chain() {
    let cert: &[u8] = b"\x30\x82\x01\x10HANDSHAKE_CERT";
    let frame = certificate_record(&[cert]);

    let mut p = TlsHandshakeParser::default();
    let mut out = Vec::new();
    p.feed_responder(&frame, Timestamp::default(), &mut out);
    // The handshake aggregator doesn't emit a TlsHandshake until
    // ServerHello/Alert arrives, but the certificate_chain should
    // accumulate into the in-flight handshake state. Force a
    // terminal Alert to flush:
    let alert_payload = vec![2, 40]; // fatal, handshake_failure
    let alert_record = record(0x15, 0x0303, &alert_payload);
    p.feed_responder(&alert_record, Timestamp::default(), &mut out);

    assert_eq!(out.len(), 1, "expected one terminal handshake");
    let hs = &out[0];
    assert_eq!(hs.certificate_chain.len(), 1);
    assert_eq!(hs.certificate_chain[0].as_ref(), cert);
}

#[test]
fn empty_when_no_certificate_record() {
    // A fatal-alert-only flow has no Certificate record. The
    // handshake aggregator's accumulator should keep
    // `certificate_chain` empty.
    let mut p = TlsHandshakeParser::default();
    let mut out = Vec::new();
    let alert_payload = vec![2, 40]; // fatal, handshake_failure
    let alert_record = record(0x15, 0x0303, &alert_payload);
    p.feed_responder(&alert_record, Timestamp::default(), &mut out);
    assert_eq!(out.len(), 1);
    assert!(out[0].certificate_chain.is_empty());
}
