//! Issue #85 — every per-module `ParseError` converts into the unified
//! `flowscope::Error` via `From`, carrying the right `(Module, ErrorCode)`,
//! and bubbles through `?` in a `crate::Result` context. This is the
//! "resolve the dual error philosophy" half of #85: the rich per-module
//! enum stays *and* a single unified view exists.

#![cfg(all(
    feature = "arp",
    feature = "dhcp",
    feature = "stun",
    feature = "snmp",
    feature = "dnp3",
))]

use flowscope::{ErrorCode, Module};

/// A truncated ARP payload converts to `Module::Arp` + `Truncated`.
#[test]
fn arp_parse_error_converts_to_unified_error() {
    let e = flowscope::arp::parse(&[]).expect_err("empty payload must fail");
    let err: flowscope::Error = e.into();
    assert_eq!(err.module(), Module::Arp);
    assert_eq!(err.code(), ErrorCode::Truncated);
    assert!(err.is_recoverable());
}

/// A truncated DHCP payload converts to `Module::Dhcp` + `Truncated`.
#[test]
fn dhcp_parse_error_converts_to_unified_error() {
    let e = flowscope::dhcp::parse(&[0u8; 8]).expect_err("short BOOTP must fail");
    let err: flowscope::Error = e.into();
    assert_eq!(err.module(), Module::Dhcp);
    assert_eq!(err.code(), ErrorCode::Truncated);
}

/// A non-STUN datagram (bad magic cookie) converts to `Module::Stun` +
/// `Parse` — distinguishable from a truncation.
#[test]
fn stun_not_my_protocol_is_parse_not_truncated() {
    // 20-byte header, valid length field, but wrong magic cookie.
    let mut buf = [0u8; 20];
    buf[0] = 0x00; // message type with clear top bits
    let e = flowscope::stun::parse(&buf).expect_err("bad cookie must fail");
    let err: flowscope::Error = e.into();
    assert_eq!(err.module(), Module::Stun);
    assert_eq!(err.code(), ErrorCode::Parse);
}

/// A rusticata-backed parser (SNMP) also bridges to the unified error.
#[test]
fn snmp_decode_error_converts_to_unified_error() {
    let e = flowscope::snmp::parse(&[0xff, 0xff, 0xff]).expect_err("garbage must fail");
    let err: flowscope::Error = e.into();
    assert_eq!(err.module(), Module::Snmp);
    assert_eq!(err.code(), ErrorCode::Parse);
}

/// One of the original #65 modules now bridges too (previously its
/// `ParseError` could never become a `crate::Error`).
#[test]
fn dnp3_parse_error_converts_to_unified_error() {
    let e = flowscope::dnp3::parse(&[]).expect_err("empty payload must fail");
    let err: flowscope::Error = e.into();
    assert_eq!(err.module(), Module::Dnp3);
    assert_eq!(err.code(), ErrorCode::Truncated);
}

/// The `?` operator bridges a module `ParseError` into a `crate::Result`
/// function via the `From` impl — the ergonomic payoff of the unification.
#[test]
fn question_mark_bubbles_module_error_into_crate_result() {
    fn accept(payload: &[u8]) -> flowscope::Result<()> {
        let _msg = flowscope::arp::parse(payload)?; // ParseError -> crate::Error via `?`
        Ok(())
    }
    // Err path: the conversion happened (we got a crate::Error, not a panic).
    let err = accept(&[]).expect_err("empty must fail");
    assert_eq!(err.module(), Module::Arp);
}
