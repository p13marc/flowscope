//! FTP — TCP/21 control channel parser.
//!
//! Gated by the `ftp` Cargo feature. Decodes the cleartext
//! FTP control channel per RFC 959 + RFC 2228 (AUTH) + RFC
//! 2389 (FEAT) + RFC 2428 (EPRT/EPSV). Surfaces:
//!
//! - **Commands** (client → server): the command verb plus
//!   its argument string.
//! - **Replies** (server → client): the 3-digit reply code
//!   plus the text portion.
//! - **Credentials**: paired `USER` + `PASS` are emitted as
//!   one [`FtpMessage::Credentials`] event when both have
//!   been observed. Cleartext FTP creds are a major
//!   detection-engineering signal (T1078 / T1110).
//! - **TLS upgrade** ([`FtpMessage::TlsUpgrade`]): emitted
//!   when an `AUTH TLS` / `AUTH SSL` command is followed by
//!   a `234` reply ("Auth mechanism accepted"). After
//!   emission, the parser stops draining — subsequent bytes
//!   are TLS-encrypted.
//! - **Transfer commands** (`RETR`, `STOR`, `APPE`, `MKD`,
//!   `RMD`, `DELE`) are surfaced individually plus aggregated
//!   into [`FtpMessage::Transfer`] events for the
//!   convenience case.
//!
//! # Wire shape
//!
//! Every FTP line is `\r\n`-terminated. Commands are
//! `VERB [arg]\r\n`. Replies are `XYZ text\r\n` for single-
//! line, or `XYZ-text\r\n...XYZ text\r\n` for multi-line
//! (we surface only the final-line reply per RFC 959 §4.2).
//!
//! # What this is NOT
//!
//! - The data channel (PASV / EPSV established TCP). FTP-DATA
//!   is a separate flow on a different port and is not
//!   parsed here.
//! - Post-AUTH-TLS traffic. After the TLS upgrade the parser
//!   is dormant; pair with `flowscope::tls` on the same
//!   session for the encrypted handshake.
//!
//! Issue #14 (Tier-2 row 2 sub-piece).

mod parser;
mod session;
mod types;

pub use parser::extract_line;
pub use session::{FTP_PORT, FtpParser, PARSER_KIND};
pub use types::{FtpCommand, FtpMessage, FtpReplyClass, TransferKind};
