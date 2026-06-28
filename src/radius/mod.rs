//! RADIUS — UDP/1812 (auth) + UDP/1813 (accounting).
//!
//! Gated by the `radius` Cargo feature. Decodes RADIUS
//! Access / Accounting messages per RFC 2865 + RFC 2866 via
//! the rusticata [`radius-parser`](https://crates.io/crates/radius-parser)
//! crate.
//!
//! # What this surfaces
//!
//! - **Code** — Access-Request / Access-Accept / Access-Reject
//!   / Access-Challenge / Accounting-Request / Accounting-Response
//!   / Status-Server / Status-Client / Other(u8).
//! - **Identifier** — request/response correlation byte.
//! - **Username** — the User-Name attribute (cleartext).
//!   The most operationally-valuable field for identity
//!   correlation.
//! - **Calling-Station-Id** — typically a MAC address (for
//!   wireless / 802.1X RADIUS) or a calling phone number.
//! - **Called-Station-Id** — typically the NAS SSID + BSSID
//!   for wireless RADIUS.
//! - **NAS-IP-Address** / **NAS-Identifier** — the NAS
//!   (Network Access Server / AP / switch) that initiated
//!   the auth.
//! - **Framed-IP-Address** — the assigned IP for the
//!   authenticating user (often the bridge between RADIUS
//!   auth and downstream flow attribution).
//!
//! # What this is NOT
//!
//! - **User-Password recovery** — the User-Password
//!   attribute is hashed with the shared secret +
//!   Authenticator (RFC 2865 §5.2). Cleartext recovery
//!   requires the shared secret, which a passive observer
//!   doesn't have. We surface the presence of the
//!   attribute via `has_user_password`; the bytes
//!   themselves are not surfaced.
//! - **CHAP / EAP attribute parsing** — surfaced as
//!   `Other` attributes if needed; this initial ship
//!   focuses on the most-common identity attributes.
//! - **RadSec (RADIUS over TLS, TCP/2083)** — not parsed.
//!
//! Issue #14 (Tier-2 row 4).

mod datagram;
mod parser;
mod types;

pub use datagram::{PARSER_KIND, RADIUS_ACCT_PORT, RADIUS_AUTH_PORT, RadiusParser};
pub use parser::{ParseError, parse};
pub use types::{RadiusCodeKind, RadiusMessage};
