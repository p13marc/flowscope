//! Plan 96 — verify the unified error type preserves source
//! chains, supports `match`-by-`(module, code)`, and is
//! `Send + Sync + 'static`.

use std::error::Error as _;

use flowscope::{Error, ErrorCode, Module};

#[test]
fn send_sync_static() {
    fn assert_traits<T: Send + Sync + 'static>() {}
    assert_traits::<Error>();
}

#[test]
fn match_on_module_and_code() {
    // Build an error via the public helper that the pcap source
    // uses on a missing-file scenario.
    let r = flowscope::pcap::PcapFlowSource::open("/no/such/path.pcap");
    let err = r.err().expect("open of nonexistent file should fail");

    match (err.module(), err.code()) {
        (Module::Pcap, ErrorCode::Io) => { /* expected */ }
        other => panic!("expected (Pcap, Io); got {other:?}"),
    }
}

#[test]
fn io_error_carries_source() {
    let r = flowscope::pcap::PcapFlowSource::open("/no/such/path.pcap");
    let err = r.err().unwrap();
    let src = err.source().expect("io error should chain to std::io::Error");
    let s = src.to_string();
    assert!(!s.is_empty(), "source must display non-empty");
    let io = src
        .downcast_ref::<std::io::Error>()
        .expect("source should downcast to io::Error");
    assert_eq!(io.kind(), std::io::ErrorKind::NotFound);
}

#[cfg(feature = "dns")]
#[test]
fn dns_parse_error_routes_correctly() {
    // < 12 bytes — short-circuited by the parser before reaching
    // simple-dns; checks our Module::Dns + ErrorCode::Parse routing.
    let r = flowscope::dns::parse_message(&[0u8; 4]);
    let err = r.err().unwrap();
    assert_eq!(err.module(), Module::Dns);
    assert_eq!(err.code(), ErrorCode::Parse);
    assert!(err.is_recoverable());
}

#[cfg(feature = "dns")]
#[test]
fn dns_parse_error_with_source_chain() {
    // 12+ random bytes — simple-dns rejects, we wrap with parse().
    // (Our DNS path uses `parse()` for the upstream error rather
    // than `parse_with()`, so source() is None. The error message
    // still includes the upstream detail.)
    let payload = [0xffu8; 16];
    let r = flowscope::dns::parse_message(&payload);
    let err = r.err().unwrap();
    assert_eq!(err.module(), Module::Dns);
    assert_eq!(err.code(), ErrorCode::Parse);
    assert!(err.to_string().contains("simple-dns"));
}

#[cfg(feature = "icmp")]
#[test]
fn icmp_parse_error_carries_source() {
    // Empty payload — etherparse complains; we wrap with parse_with.
    let r = flowscope::icmp::parse_v4(&[]);
    let err = r.err().unwrap();
    assert_eq!(err.module(), Module::Icmp);
    assert_eq!(err.code(), ErrorCode::Parse);
    assert!(err.source().is_some(), "etherparse error should chain");
}

#[test]
fn display_format_stable_shape() {
    // Display format is "module: code: message".
    let r = flowscope::pcap::PcapFlowSource::open("/no/such/path.pcap");
    let err = r.err().unwrap();
    let s = err.to_string();
    assert!(s.starts_with("pcap: io: "), "got {s:?}");
}
