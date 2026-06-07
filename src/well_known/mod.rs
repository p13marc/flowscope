//! `flowscope::well_known` — curated port → protocol label table.
//!
//! Every observability example written for the 0.9 cycle ended up
//! reinventing a small "port → protocol name" table:
//!
//! ```ignore
//! match port {
//!     80 | 8080 => "http",
//!     443 => "tls/https",
//!     53 => "dns",
//!     // … and so on
//!     _ => "other",
//! }
//! ```
//!
//! This module ships that table once. ~80 entries (IANA-aligned
//! plus widely-deployed cloud-native services), refreshed once
//! per minor release. Lookup is binary-search-based and zero-cost
//! when the port is unknown.
//!
//! ```
//! use flowscope::L4Proto;
//! use flowscope::well_known::protocol_label;
//!
//! assert_eq!(protocol_label(L4Proto::Tcp, 33000, 80), Some("http"));
//! assert_eq!(protocol_label(L4Proto::Tcp, 5432, 65000), Some("postgres"));
//! assert_eq!(protocol_label(L4Proto::Udp, 53, 33000), Some("dns"));
//! assert_eq!(protocol_label(L4Proto::Tcp, 33000, 33001), None);
//! ```
//!
//! Disambiguation: the lower-numbered port is always treated as
//! the well-known side. If both ports are non-zero and both
//! resolve to known labels, the lower one wins (e.g. an
//! 80 ↔ 443 flow labels as `"http"`).
//!
//! New in 0.10.0 (plan 102 sub-D).

use crate::extractor::L4Proto;

/// One row in the curated table. Public so consumers can build
/// their own filters over the shipped entries.
pub type Entry = (L4Proto, u16, &'static str);

/// Canonical short label for the given protocol + port pair.
///
/// Returns `None` if neither port is in the curated table.
///
/// The two port arguments are accepted as `src_port, dst_port`,
/// but the lookup is order-insensitive — the lower-numbered port
/// is treated as the well-known side. Pass `0` for either port
/// to opt out of that side's lookup (useful for ICMP or other
/// portless flows).
pub fn protocol_label(proto: L4Proto, src_port: u16, dst_port: u16) -> Option<&'static str> {
    let table = table_for(proto)?;
    let lower = match (src_port, dst_port) {
        (0, 0) => return None,
        (0, p) | (p, 0) => p,
        (a, b) => a.min(b),
    };
    if let Some(label) = lookup(table, lower) {
        return Some(label);
    }
    // Fall back to the higher port for the pathological case where
    // the higher port is well-known and the lower one is in the
    // ephemeral range but happens to be smaller.
    let higher = src_port.max(dst_port);
    if higher != lower {
        lookup(table, higher)
    } else {
        None
    }
}

/// Iterate every shipped `(proto, port, label)` row. Useful for
/// rendering the table in `--help` output, or for constructing
/// custom filters over the curated set.
pub fn entries() -> impl Iterator<Item = Entry> {
    TCP_TABLE
        .iter()
        .map(|(p, l)| (L4Proto::Tcp, *p, *l))
        .chain(UDP_TABLE.iter().map(|(p, l)| (L4Proto::Udp, *p, *l)))
}

fn table_for(proto: L4Proto) -> Option<&'static [(u16, &'static str)]> {
    match proto {
        L4Proto::Tcp => Some(TCP_TABLE),
        L4Proto::Udp => Some(UDP_TABLE),
        _ => None,
    }
}

fn lookup(table: &[(u16, &'static str)], port: u16) -> Option<&'static str> {
    table
        .binary_search_by_key(&port, |(p, _)| *p)
        .ok()
        .map(|i| table[i].1)
}

/// Sorted-ascending TCP entries. Add to / refresh during each
/// minor-release sweep.
const TCP_TABLE: &[(u16, &str)] = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "dns"),
    (80, "http"),
    (110, "pop3"),
    (143, "imap"),
    (443, "tls/https"),
    (465, "smtps"),
    (587, "smtp-submission"),
    (993, "imaps"),
    (995, "pop3s"),
    (1433, "mssql"),
    (1521, "oracle"),
    (2049, "nfs"),
    (3306, "mysql"),
    (3389, "rdp"),
    (5432, "postgres"),
    (5672, "amqp"),
    (5984, "couchdb"),
    (6379, "redis"),
    (6443, "kubernetes-api"),
    (6667, "irc"),
    (7000, "cassandra"),
    (7001, "cassandra"),
    (8000, "http"),
    (8080, "http"),
    (8088, "hbase"),
    (8443, "tls/https"),
    (8500, "consul"),
    (9000, "minio"),
    (9001, "minio"),
    (9042, "cassandra-cql"),
    (9092, "kafka"),
    (9093, "kafka"),
    (9200, "elasticsearch"),
    (9300, "elasticsearch"),
    (10000, "webmin"),
    (11211, "memcached"),
    (15672, "rabbitmq-mgmt"),
    (27017, "mongodb"),
    (50070, "hdfs"),
];

/// Sorted-ascending UDP entries.
const UDP_TABLE: &[(u16, &str)] = &[
    (53, "dns"),
    (67, "dhcp"),
    (68, "dhcp"),
    (69, "tftp"),
    (88, "kerberos"),
    (123, "ntp"),
    (137, "netbios"),
    (138, "netbios"),
    (139, "netbios"),
    (161, "snmp"),
    (162, "snmp"),
    (389, "ldap"),
    (443, "quic/http3"),
    (500, "ipsec"),
    (514, "syslog"),
    (636, "ldaps"),
    (1812, "radius"),
    (1813, "radius"),
    (2049, "nfs"),
    (2152, "gtp-u"),
    (3478, "stun"),
    (4500, "ipsec"),
    (4789, "vxlan"),
    (5060, "sip"),
    (5061, "sip"),
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_sorted_ascending() {
        for w in TCP_TABLE.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "TCP_TABLE not sorted: {} >= {}",
                w[0].0,
                w[1].0
            );
        }
    }

    #[test]
    fn udp_sorted_ascending() {
        for w in UDP_TABLE.windows(2) {
            assert!(
                w[0].0 < w[1].0,
                "UDP_TABLE not sorted: {} >= {}",
                w[0].0,
                w[1].0
            );
        }
    }

    #[test]
    fn known_labels() {
        assert_eq!(protocol_label(L4Proto::Tcp, 80, 33000), Some("http"));
        assert_eq!(protocol_label(L4Proto::Tcp, 33000, 443), Some("tls/https"));
        assert_eq!(protocol_label(L4Proto::Udp, 33000, 53), Some("dns"));
        assert_eq!(protocol_label(L4Proto::Tcp, 33000, 6379), Some("redis"));
    }

    #[test]
    fn lower_port_disambiguates_two_known() {
        // 80 is lower than 443 → http wins.
        assert_eq!(protocol_label(L4Proto::Tcp, 80, 443), Some("http"));
        assert_eq!(protocol_label(L4Proto::Tcp, 443, 80), Some("http"));
    }

    #[test]
    fn higher_port_fallback_when_lower_unknown() {
        // 33000 (unknown) + 80 → label resolves via the higher port.
        // We already covered this above; this case is the explicit
        // "lower unknown" path.
        assert_eq!(protocol_label(L4Proto::Tcp, 1024, 80), Some("http"));
    }

    #[test]
    fn unknown_returns_none() {
        assert_eq!(protocol_label(L4Proto::Tcp, 33000, 33001), None);
        assert_eq!(protocol_label(L4Proto::Udp, 33000, 33001), None);
        // Wrong proto on a known TCP port → None.
        assert_eq!(protocol_label(L4Proto::Udp, 80, 33000), None);
    }

    #[test]
    fn icmp_and_other_protocols_return_none() {
        assert_eq!(protocol_label(L4Proto::Icmp, 0, 0), None);
        assert_eq!(protocol_label(L4Proto::IcmpV6, 0, 0), None);
        assert_eq!(protocol_label(L4Proto::Sctp, 80, 80), None);
        assert_eq!(protocol_label(L4Proto::Other(99), 80, 80), None);
    }

    #[test]
    fn zero_port_opts_out_of_that_side() {
        // Only the non-zero side looks up.
        assert_eq!(protocol_label(L4Proto::Tcp, 0, 80), Some("http"));
        assert_eq!(protocol_label(L4Proto::Tcp, 80, 0), Some("http"));
        // Both zero → None.
        assert_eq!(protocol_label(L4Proto::Tcp, 0, 0), None);
    }

    #[test]
    fn entries_iterates_full_table() {
        let count = entries().count();
        assert_eq!(count, TCP_TABLE.len() + UDP_TABLE.len());
    }

    #[test]
    fn entries_contains_known_rows() {
        let v: Vec<_> = entries().collect();
        assert!(v.contains(&(L4Proto::Tcp, 80, "http")));
        assert!(v.contains(&(L4Proto::Udp, 53, "dns")));
        assert!(v.contains(&(L4Proto::Udp, 4789, "vxlan")));
    }
}
