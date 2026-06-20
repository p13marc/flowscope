//! NTP / SNTP parser. RFC 5905.
//!
//! Gated by the `ntp` feature. Passively decodes the 48-byte
//! NTPv3 / NTPv4 header from UDP/123 datagrams. Operationally
//! interesting signals:
//!
//! - **Time-source asset discovery** — `stratum` + `ref_id`
//!   tell you what server it is and what its upstream is.
//! - **DDoS-amplification participants** — mode 7 (private,
//!   carries `monlist`) and mode 6 (control) are the
//!   historical NTP-amp vectors. Mode-7 query traffic is
//!   essentially never legitimate on the public internet
//!   today. The [`NtpMessage::is_amplification_risk`]
//!   predicate flags both.
//! - **Time-source spoof** — a server response (`mode = 4`)
//!   from a source where you don't expect one is a strong
//!   IOC for in-path time hijack (T1565.002 in MITRE
//!   ATT&CK).
//!
//! # Wire shape
//!
//! - [`parse`] — pure UDP payload.
//! - [`NtpParser`] — `DatagramParser` implementation.
//!
//! Issue #14 (Tier-2 sub-piece).

mod datagram;
mod parser;
mod types;

pub use datagram::{NtpParser, PARSER_KIND};
pub use parser::parse;
pub use types::{NtpLeapIndicator, NtpMessage, NtpMode, NtpTimestamp, REF_TIMESTAMP_EPOCH};
