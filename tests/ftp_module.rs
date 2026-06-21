//! FTP module integration tests (issue #14 sub-piece).

#![cfg(feature = "ftp")]

use flowscope::ftp::{FTP_PORT, FtpCommand, FtpMessage, FtpParser, FtpReplyClass, TransferKind};
use flowscope::{SessionParser, Timestamp};

fn ts() -> Timestamp {
    Timestamp::default()
}

#[test]
fn port_constant_matches_iana() {
    assert_eq!(FTP_PORT, 21);
}

#[test]
fn end_to_end_login_flow() {
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    p.feed_responder(b"220 vsFTPd 3.0.3\r\n", ts(), &mut events);
    p.feed_initiator(b"USER alice\r\n", ts(), &mut events);
    p.feed_responder(b"331 Please specify the password.\r\n", ts(), &mut events);
    p.feed_initiator(b"PASS hunter2\r\n", ts(), &mut events);
    p.feed_responder(b"230 Login successful.\r\n", ts(), &mut events);

    assert!(
        events
            .iter()
            .any(|m| matches!(m, FtpMessage::Banner { .. }))
    );
    assert!(events.iter().any(|m| matches!(
        m,
        FtpMessage::Credentials { user, pass } if user == "alice" && pass == "hunter2"
    )));
    assert!(
        events
            .iter()
            .any(|m| matches!(m, FtpMessage::Reply { code: 230, .. }))
    );
}

#[test]
fn tls_upgrade_sequence_emits_event() {
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    p.feed_responder(b"220 Ready\r\n", ts(), &mut events);
    p.feed_initiator(b"AUTH TLS\r\n", ts(), &mut events);
    p.feed_responder(b"234 AUTH command ok.\r\n", ts(), &mut events);
    assert!(events.iter().any(|m| matches!(m, FtpMessage::TlsUpgrade)));
}

#[test]
fn transfer_command_aggregation() {
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    p.feed_initiator(b"RETR config.xml\r\n", ts(), &mut events);
    p.feed_initiator(b"STOR data.bin\r\n", ts(), &mut events);
    p.feed_initiator(b"APPE log.txt\r\n", ts(), &mut events);
    let transfers: Vec<_> = events
        .iter()
        .filter_map(|m| match m {
            FtpMessage::Transfer { kind, filename } => Some((*kind, filename.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(transfers.len(), 3);
    assert!(transfers.iter().any(|(k, _)| *k == TransferKind::Download));
    assert!(transfers.iter().any(|(k, _)| *k == TransferKind::Upload));
    assert!(transfers.iter().any(|(k, _)| *k == TransferKind::Append));
}

#[test]
fn reply_class_classification() {
    assert_eq!(
        FtpReplyClass::classify(220),
        FtpReplyClass::PositiveCompletion
    );
    assert_eq!(
        FtpReplyClass::classify(331),
        FtpReplyClass::PositiveIntermediate
    );
    assert_eq!(
        FtpReplyClass::classify(425),
        FtpReplyClass::TransientNegative
    );
    assert_eq!(
        FtpReplyClass::classify(530),
        FtpReplyClass::PermanentNegative
    );
    assert_eq!(
        FtpReplyClass::classify(150),
        FtpReplyClass::PositivePreliminary
    );
    assert_eq!(FtpReplyClass::classify(999), FtpReplyClass::Other);
}

#[test]
fn command_is_transfer_predicate() {
    assert!(FtpCommand::Retr.is_transfer());
    assert!(FtpCommand::Stor.is_transfer());
    assert!(FtpCommand::Appe.is_transfer());
    assert!(FtpCommand::Stou.is_transfer());
    assert!(!FtpCommand::Pasv.is_transfer());
    assert!(!FtpCommand::Quit.is_transfer());
}

#[test]
fn malformed_lines_are_skipped() {
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    // Empty line.
    p.feed_initiator(b"\r\n", ts(), &mut events);
    // Valid line that follows.
    p.feed_initiator(b"USER bob\r\n", ts(), &mut events);
    assert!(events.iter().any(|m| matches!(
        m,
        FtpMessage::Command {
            verb: FtpCommand::User,
            ..
        }
    )));
}

#[test]
fn intermediate_multiline_220_does_not_steal_banner() {
    // Banner with multi-line continuation. We only surface the
    // final-line as banner — the intermediate `220-` lines
    // are dropped per the parser docs.
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    p.feed_responder(
        b"220-Welcome\r\n220-Please log in.\r\n220 vsFTPd 3.0.3\r\n",
        ts(),
        &mut events,
    );
    let banners: Vec<_> = events
        .iter()
        .filter_map(|m| match m {
            FtpMessage::Banner { banner } => Some(banner.clone()),
            _ => None,
        })
        .collect();
    assert_eq!(banners.len(), 1);
    assert_eq!(banners[0], "vsFTPd 3.0.3");
}

#[test]
fn split_bytes_across_feeds_correctly_reassembled() {
    let mut p = FtpParser::new();
    let mut events = Vec::new();
    p.feed_initiator(b"US", ts(), &mut events);
    p.feed_initiator(b"ER al", ts(), &mut events);
    p.feed_initiator(b"ice\r\nPA", ts(), &mut events);
    p.feed_initiator(b"SS secret\r\n", ts(), &mut events);
    assert!(events.iter().any(|m| matches!(
        m,
        FtpMessage::Credentials { user, pass } if user == "alice" && pass == "secret"
    )));
}

#[cfg(feature = "serde")]
#[test]
fn ftp_message_serializes_to_json() {
    let msg = FtpMessage::Credentials {
        user: "alice".into(),
        pass: "hunter2".into(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("credentials"));
    assert!(json.contains("alice"));
    assert!(json.contains("hunter2"));
}
