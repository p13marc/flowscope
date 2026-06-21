//! SMTP module integration tests (issue #14 sub-piece).

#![cfg(feature = "smtp")]

use base64::Engine;
use flowscope::smtp::{SMTP_PORT, SMTP_SUBMISSION_PORT, SmtpCommand, SmtpMessage, SmtpParser};
use flowscope::{SessionParser, Timestamp};

fn ts() -> Timestamp {
    Timestamp::default()
}

#[test]
fn port_constants_match_iana() {
    assert_eq!(SMTP_PORT, 25);
    assert_eq!(SMTP_SUBMISSION_PORT, 587);
}

#[test]
fn end_to_end_message_send() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();

    p.feed_responder(b"220 mail.example.com ESMTP\r\n", ts(), &mut events);
    p.feed_initiator(b"EHLO sender.example.org\r\n", ts(), &mut events);
    p.feed_responder(
        b"250-mail.example.com\r\n250-PIPELINING\r\n250 8BITMIME\r\n",
        ts(),
        &mut events,
    );
    p.feed_initiator(b"MAIL FROM:<alice@sender.org>\r\n", ts(), &mut events);
    p.feed_responder(b"250 OK\r\n", ts(), &mut events);
    p.feed_initiator(b"RCPT TO:<bob@receiver.com>\r\n", ts(), &mut events);
    p.feed_responder(b"250 OK\r\n", ts(), &mut events);
    p.feed_initiator(b"DATA\r\n", ts(), &mut events);
    p.feed_responder(b"354 End data with <CRLF>.<CRLF>\r\n", ts(), &mut events);
    p.feed_initiator(b"Subject: Test\r\n\r\nbody\r\n.\r\n", ts(), &mut events);
    p.feed_responder(b"250 Message accepted\r\n", ts(), &mut events);
    p.feed_initiator(b"QUIT\r\n", ts(), &mut events);

    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::Helo { domain, esmtp: true } if domain == "sender.example.org"
    )));
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::MailFrom { address } if address == "alice@sender.org"
    )));
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::RcptTo { address } if address == "bob@receiver.com"
    )));
    assert!(events.iter().any(|m| matches!(m, SmtpMessage::DataBegin)));
    assert!(
        events
            .iter()
            .any(|m| matches!(m, SmtpMessage::DataEnd { .. }))
    );
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::Command {
            verb: SmtpCommand::Quit,
            ..
        }
    )));
}

#[test]
fn starttls_upgrade_sequence() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();
    p.feed_responder(b"220 Ready\r\n", ts(), &mut events);
    p.feed_initiator(b"EHLO x\r\n", ts(), &mut events);
    p.feed_responder(b"250 STARTTLS\r\n", ts(), &mut events);
    p.feed_initiator(b"STARTTLS\r\n", ts(), &mut events);
    p.feed_responder(b"220 Go ahead\r\n", ts(), &mut events);
    assert!(events.iter().any(|m| matches!(m, SmtpMessage::TlsUpgrade)));
    let before = events.len();
    p.feed_initiator(b"\x16\x03\x01\x00\x00", ts(), &mut events);
    assert_eq!(events.len(), before, "post-upgrade bytes dropped");
}

#[test]
fn auth_plain_inline_credentials_captured() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();
    let blob = base64::engine::general_purpose::STANDARD.encode("\0alice\0secret");
    p.feed_initiator(
        format!("AUTH PLAIN {blob}\r\n").as_bytes(),
        ts(),
        &mut events,
    );
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::Credentials { user, pass, mechanism }
            if user == "alice" && pass == "secret" && mechanism == "PLAIN"
    )));
}

#[test]
fn auth_login_two_prompt_credentials_captured() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();
    p.feed_initiator(b"AUTH LOGIN\r\n", ts(), &mut events);
    p.feed_responder(b"334 VXNlcm5hbWU6\r\n", ts(), &mut events);
    let user = base64::engine::general_purpose::STANDARD.encode("bob");
    p.feed_initiator(format!("{user}\r\n").as_bytes(), ts(), &mut events);
    p.feed_responder(b"334 UGFzc3dvcmQ6\r\n", ts(), &mut events);
    let pass = base64::engine::general_purpose::STANDARD.encode("hunter2");
    p.feed_initiator(format!("{pass}\r\n").as_bytes(), ts(), &mut events);
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::Credentials { user, pass, mechanism }
            if user == "bob" && pass == "hunter2" && mechanism == "LOGIN"
    )));
}

#[test]
fn null_sender_extracted_as_empty() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();
    p.feed_initiator(b"MAIL FROM:<>\r\n", ts(), &mut events);
    assert!(events.iter().any(|m| matches!(
        m,
        SmtpMessage::MailFrom { address } if address.is_empty()
    )));
}

#[test]
fn helo_command_marks_esmtp_false() {
    let mut p = SmtpParser::new();
    let mut events = Vec::new();
    p.feed_initiator(b"HELO legacy.example.com\r\n", ts(), &mut events);
    assert!(
        events
            .iter()
            .any(|m| matches!(m, SmtpMessage::Helo { esmtp: false, .. }))
    );
}

#[cfg(feature = "serde")]
#[test]
fn smtp_message_serializes_to_json() {
    let msg = SmtpMessage::Credentials {
        mechanism: "PLAIN".into(),
        user: "alice".into(),
        pass: "secret".into(),
    };
    let json = serde_json::to_string(&msg).unwrap();
    assert!(json.contains("credentials"));
    assert!(json.contains("alice"));
}
