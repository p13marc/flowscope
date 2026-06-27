//! [Community ID](https://github.com/corelight/community-id-spec) v1
//! flow hashing — the cross-tool standard for joining flows across
//! Zeek, Suricata, Security Onion, Arkime and friends.
//!
//! flowscope's native [`stable_hash`](crate::KeyFields::stable_hash)
//! (FNV-1a, 64-bit) is fast and direction-invariant but
//! flowscope-specific (non-portable). Community ID is the
//! *interoperable* id and the **canonical** flow identifier in
//! flowscope's EVE / NDJSON output since 0.19 (issue #88): an analyst
//! can take a `community_id` from a flowscope record and pivot directly
//! into the SIEM's existing Zeek/Suricata data. `stable_hash` is no
//! longer emitted — keep it for in-process sharding / keying only.
//!
//! ## Algorithm (spec v1)
//!
//! SHA-1 over the byte string
//!
//! ```text
//! seed(2, BE) ‖ a_ip ‖ b_ip ‖ proto(1) ‖ pad(1)=0 ‖ a_port(2, BE) ‖ b_port(2, BE)
//! ```
//!
//! where the endpoint pair is ordered canonically — `(a_ip, a_port)`
//! is the lexicographically smaller of `(src, sport)` / `(dst, dport)`
//! — so both directions of a flow produce the same id. The 20-byte
//! digest is base64-encoded and prefixed with the version tag `"1:"`.
//!
//! ## Scope
//!
//! TCP / UDP / SCTP are exact (this is the SIEM-pivot case). For
//! ICMP and other port-less protocols, flowscope's keys carry no
//! ports (they are `0`), so the spec's ICMP type/code-as-ports
//! special handling is **not** reproduced — the id is still stable
//! and direction-invariant, but will not match a Zeek/Suricata ICMP
//! Community ID. Documented limitation; revisit if a consumer needs
//! ICMP parity.
//!
//! Requires the `community-id` Cargo feature. The seed-fixed
//! [`KeyFields::stable_hash`](crate::KeyFields::stable_hash) /
//! [`shard_index`](crate::KeyFields::shard_index) helpers are
//! always-on and live in [`crate::anomaly_fields`].
//!
//! Issue #76.

use std::net::IpAddr;

use base64::Engine as _;
use sha1::{Digest, Sha1};

/// Compute the Corelight Community ID v1 string for one flow tuple.
///
/// `proto` is the IANA protocol number (TCP=6, UDP=17, …). `seed`
/// lets cooperating sensors namespace their ids (0 is the universal
/// default). Endpoints are ordered canonically inside, so passing
/// `(src, dst)` or `(dst, src)` yields the same result.
pub fn community_id_v1(
    proto: u8,
    src_ip: IpAddr,
    src_port: u16,
    dst_ip: IpAddr,
    dst_port: u16,
    seed: u16,
) -> String {
    // Canonical ordering: smaller (ip, port) first. IpAddr's Ord
    // compares within a family by octets, which matches the spec's
    // "compare addresses as byte strings" for a same-family flow.
    let ((a_ip, a_port), (b_ip, b_port)) = if (src_ip, src_port) <= (dst_ip, dst_port) {
        ((src_ip, src_port), (dst_ip, dst_port))
    } else {
        ((dst_ip, dst_port), (src_ip, src_port))
    };

    let mut h = Sha1::new();
    h.update(seed.to_be_bytes());
    feed_ip(&mut h, a_ip);
    feed_ip(&mut h, b_ip);
    h.update([proto, 0u8]); // proto + 1-byte padding
    h.update(a_port.to_be_bytes());
    h.update(b_port.to_be_bytes());
    let digest = h.finalize();

    let mut out = String::with_capacity(2 + 28);
    out.push_str("1:");
    base64::engine::general_purpose::STANDARD.encode_string(digest.as_slice(), &mut out);
    out
}

fn feed_ip(h: &mut Sha1, ip: IpAddr) {
    match ip {
        IpAddr::V4(v4) => h.update(v4.octets()),
        IpAddr::V6(v6) => h.update(v6.octets()),
    }
}

/// Generic helper: compute the Community ID for any
/// [`KeyFields`](crate::KeyFields). Returns `None` if the key lacks
/// any of (protocol id, src/dest ip, src/dest port). Used by the
/// EVE / NDJSON emit writers.
pub fn community_id_for_key<K: crate::KeyFields + ?Sized>(key: &K, seed: u16) -> Option<String> {
    Some(community_id_v1(
        key.protocol_identifier()?,
        key.src_ip()?,
        key.src_port()?,
        key.dest_ip()?,
        key.dest_port()?,
        seed,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn tcp_golden_vector() {
        // Canonical published vector (community-id-spec README):
        // 128.232.110.120:34855 -> 66.35.250.204:80 TCP, seed 0.
        let id = community_id_v1(6, ip("128.232.110.120"), 34855, ip("66.35.250.204"), 80, 0);
        assert_eq!(id, "1:LQU9qZlK+B5F3KDmev6m5PMibrg=");
    }

    #[test]
    fn direction_invariant() {
        let fwd = community_id_v1(6, ip("10.0.0.1"), 1111, ip("10.0.0.2"), 80, 0);
        let rev = community_id_v1(6, ip("10.0.0.2"), 80, ip("10.0.0.1"), 1111, 0);
        assert_eq!(fwd, rev);
    }

    #[test]
    fn seed_changes_id() {
        let s0 = community_id_v1(6, ip("10.0.0.1"), 1111, ip("10.0.0.2"), 80, 0);
        let s1 = community_id_v1(6, ip("10.0.0.1"), 1111, ip("10.0.0.2"), 80, 1);
        assert_ne!(s0, s1);
    }

    #[test]
    fn udp_golden_vector() {
        // Published vector: 192.168.1.52:54585 -> 8.8.8.8:53 UDP, seed 0.
        let id = community_id_v1(17, ip("192.168.1.52"), 54585, ip("8.8.8.8"), 53, 0);
        assert_eq!(id, "1:d/FP5EW3wiY1vCndhwleRRKHowQ=");
    }

    #[test]
    fn ipv6_is_stable_and_prefixed() {
        let id = community_id_v1(6, ip("fe80::1"), 5000, ip("fe80::2"), 443, 0);
        assert!(id.starts_with("1:"));
        let rev = community_id_v1(6, ip("fe80::2"), 443, ip("fe80::1"), 5000, 0);
        assert_eq!(id, rev);
    }
}
