// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// JA4L / JA4LS are part of the JA4+ suite, (c) FoxIO, LLC, licensed under the
// FoxIO License 1.1 (see LICENSE-FoxIO-1.1 and NOTICE at the crate root) — NOT
// under flowscope's MIT/Apache-2.0 terms. JA4+ methods are patent pending.
// "JA4+" is a trademark of FoxIO, LLC. This module compiles only under the
// opt-in `ja4plus` feature; commercial use requires a FoxIO OEM license.

//! JA4L / JA4LS latency fingerprint ("light distance") — FoxIO.
//!
//! Estimates the one-way latency between two hosts from the handshake timing,
//! pairing it with the observed TTL/hop-limit so an analyst can reason about
//! physical distance and detect proxies/VPNs (a TTL that disagrees with the
//! latency).
//!
//! Format (FoxIO): `{latency_microseconds}_{ttl}`
//!
//! - `latency_microseconds` — **half** the round-trip between the two timed
//!   packets, i.e. `(t_later − t_earlier) / 2`, truncated to whole µs.
//! - `ttl` — the IPv4 TTL / IPv6 hop-limit observed on the measuring side.
//!
//! The two standard measurements:
//! - **JA4L-C** (client): `(ACK − SYN-ACK) / 2`, with the client's TTL.
//! - **JA4L-S** (server): `(SYN-ACK − SYN) / 2`, with the server's TTL.
//!
//! The optional third field FoxIO appends from the TLS ClientHello/ServerHello
//! timing is **out of scope** here (it needs handshake-timestamp plumbing);
//! flowscope produces the two-field core, which is what the TTL/distance
//! analysis uses. Reference: FoxIO `zeek/ja4l/main.zeek`.
//!
//! Issue #77.

use crate::Timestamp;

/// Format a JA4L string from an already-computed one-way latency (µs) and TTL.
pub fn ja4l(latency_micros: u64, ttl: u8) -> String {
    format!("{latency_micros}_{ttl}")
}

/// One-way latency in microseconds = `(later − earlier) / 2`, truncated.
/// Returns `None` if `later < earlier` (out-of-order capture — the FoxIO
/// reference rejects negative durations rather than guessing).
pub fn half_latency_micros(earlier: Timestamp, later: Timestamp) -> Option<u64> {
    let a = earlier.to_duration();
    let b = later.to_duration();
    if b < a {
        return None;
    }
    Some(((b - a).as_micros() / 2) as u64)
}

/// JA4L from two packet timestamps + the measuring side's TTL. `None` on an
/// out-of-order (negative-duration) pair.
pub fn ja4l_from_timestamps(earlier: Timestamp, later: Timestamp, ttl: u8) -> Option<String> {
    Some(ja4l(half_latency_micros(earlier, later)?, ttl))
}

/// **JA4L-C** (client light distance): `(ACK − SYN-ACK) / 2` with the client
/// TTL. Pass the SYN-ACK and the client's ACK timestamps.
pub fn ja4l_client(synack: Timestamp, ack: Timestamp, client_ttl: u8) -> Option<String> {
    ja4l_from_timestamps(synack, ack, client_ttl)
}

/// **JA4L-S** (server light distance): `(SYN-ACK − SYN) / 2` with the server
/// TTL. Pass the SYN and the SYN-ACK timestamps.
pub fn ja4l_server(syn: Timestamp, synack: Timestamp, server_ttl: u8) -> Option<String> {
    ja4l_from_timestamps(syn, synack, server_ttl)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ts(secs: u32, nanos: u32) -> Timestamp {
        Timestamp::new(secs, nanos)
    }

    #[test]
    fn golden_format() {
        // From FoxIO Zeek baselines: ja4l "35_64" and "14_128".
        assert_eq!(ja4l(35, 64), "35_64");
        assert_eq!(ja4l(14, 128), "14_128");
    }

    #[test]
    fn half_latency_is_half_the_gap() {
        // 70 µs apart → 35 µs one-way.
        assert_eq!(half_latency_micros(ts(0, 0), ts(0, 70_000)), Some(35));
        // JA4L-S golden 18862: gap = 37_724 µs.
        let earlier = ts(0, 0);
        let later = ts(0, 37_724_000);
        assert_eq!(
            ja4l_server(earlier, later, 59),
            Some("18862_59".to_string())
        );
    }

    #[test]
    fn client_measurement() {
        let synack = ts(1, 0);
        let ack = ts(1, 28_000); // 28 µs later → 14 µs one-way
        assert_eq!(ja4l_client(synack, ack, 128), Some("14_128".to_string()));
    }

    #[test]
    fn out_of_order_is_none() {
        assert_eq!(half_latency_micros(ts(5, 0), ts(1, 0)), None);
        assert_eq!(ja4l_client(ts(5, 0), ts(1, 0), 64), None);
    }

    #[test]
    fn spans_seconds() {
        // 2 s apart → 1_000_000 µs one-way.
        assert_eq!(half_latency_micros(ts(10, 0), ts(12, 0)), Some(1_000_000));
    }
}
