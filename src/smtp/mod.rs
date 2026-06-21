//! SMTP — TCP/25 + submission (TCP/587) parser.
//!
//! Gated by the `smtp` Cargo feature. Decodes the cleartext
//! SMTP control channel per RFC 5321 + RFC 4954 (AUTH).
//! Surfaces:
//!
//! - **Commands** (client → server): `EHLO`/`HELO`,
//!   `MAIL FROM`, `RCPT TO`, `DATA`, `STARTTLS`, `AUTH`,
//!   `RSET`, `QUIT`, etc.
//! - **Replies** (server → client): 3-digit reply codes with
//!   text; multi-line replies coalesced to their final-line
//!   text only.
//! - **MAIL FROM / RCPT TO addresses** ([`SmtpMessage::MailFrom`] /
//!   [`SmtpMessage::RcptTo`]): the envelope address with `<>`
//!   stripped. Together with EHLO domain and reply codes these
//!   form the canonical "named exfil" signal.
//! - **AUTH credentials** ([`SmtpMessage::Credentials`]): for
//!   AUTH PLAIN and AUTH LOGIN mechanisms, base64-decoded
//!   into `user` + `pass` strings when the wire shape is
//!   well-formed. PLAIN: single line `\0user\0pass`. LOGIN:
//!   two prompts (`334 VXNlcm5hbWU6` then `334 UGFzc3dvcmQ6`).
//!   Cleartext SMTP creds are a major detection-engineering
//!   signal (T1078, T1110).
//! - **STARTTLS upgrade** ([`SmtpMessage::TlsUpgrade`]):
//!   emitted when a `STARTTLS` command is followed by a
//!   `220` reply. After emission the parser stops draining;
//!   subsequent bytes are TLS-encrypted.
//! - **Mail begin / end** ([`SmtpMessage::DataBegin`] /
//!   [`SmtpMessage::DataEnd`]): client sent `DATA` and got
//!   `354`; ends when client sends `\r\n.\r\n`. The DATA
//!   body is not surfaced (MIME parsing is out of scope) —
//!   we report the body byte count via [`SmtpMessage::DataEnd::bytes`].
//!
//! # What this is NOT
//!
//! - DATA-body MIME parsing (headers, attachments). That's a
//!   separate parser scope.
//! - Post-STARTTLS traffic. Pair with `flowscope::tls` on
//!   the same flow for the encrypted handshake.
//! - SUBMISSION-only enforcement. The parser is port-agnostic
//!   — works on 25 / 587 / 2525.
//!
//! Issue #14 row 1 sub-piece.

mod parser;
mod session;
mod types;

pub use session::{PARSER_KIND, SMTP_PORT, SMTP_SUBMISSION_PORT, SmtpParser};
pub use types::{SmtpCommand, SmtpMessage};
