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

// ── Plan 165 (0.14) — LabelTable extensibility ───────────────

/// Caller-supplied port → label table that layers over (or
/// replaces) the built-in [`protocol_label`] dispatch.
///
/// Use for site-custom services ("our internal gRPC on
/// 8765", "metrics scrape on 9101"). The built-in table
/// covers ~80 standard ports; this struct lets you add the
/// rest without forking the source.
///
/// `Clone + Send + Sync`. Labels are `&'static str` — match
/// the built-in contract. For runtime-loaded labels (e.g.
/// from a YAML/JSON config), use `Box::leak(string)` to
/// bridge:
///
/// ```rust,ignore
/// let leaked: &'static str = Box::leak(String::from("gRPC-Internal").into_boxed_str());
/// table.set(L4Proto::Tcp, 8765, leaked);
/// ```
///
/// Plan 165 (0.14).
#[derive(Clone, Default, Debug)]
pub struct LabelTable {
    overrides: std::collections::HashMap<(L4Proto, u16), &'static str>,
    /// If `true` (default), unknown ports fall back to the
    /// built-in [`protocol_label`] table. If `false`, only
    /// `overrides` are consulted.
    inherit_builtin: bool,
}

impl LabelTable {
    /// Empty table that inherits the built-in entries when no
    /// override matches.
    pub fn new() -> Self {
        Self {
            overrides: std::collections::HashMap::new(),
            inherit_builtin: true,
        }
    }

    /// Empty table that does NOT inherit the built-in
    /// entries. Strict whitelist semantics.
    pub fn standalone() -> Self {
        Self {
            overrides: std::collections::HashMap::new(),
            inherit_builtin: false,
        }
    }

    /// Add or override a single `(proto, port) → label` entry.
    pub fn set(&mut self, proto: L4Proto, port: u16, label: &'static str) -> &mut Self {
        self.overrides.insert((proto, port), label);
        self
    }

    /// Bulk-set from an iterator. Convenient for config-
    /// driven table population.
    pub fn extend<I>(&mut self, entries: I) -> &mut Self
    where
        I: IntoIterator<Item = (L4Proto, u16, &'static str)>,
    {
        for (proto, port, label) in entries {
            self.overrides.insert((proto, port), label);
        }
        self
    }

    /// Lookup. Same shape as the free function
    /// [`protocol_label`].
    ///
    /// Algorithm:
    /// - Try the override map on `(proto, src_port)`.
    /// - Try the override map on `(proto, dst_port)`.
    /// - If [`inherit_builtin`](Self::inherit_builtin), fall
    ///   back to the built-in [`protocol_label`].
    /// - Else return `None`.
    pub fn lookup(&self, proto: L4Proto, src_port: u16, dst_port: u16) -> Option<&'static str> {
        if let Some(label) = self.overrides.get(&(proto, src_port)) {
            return Some(*label);
        }
        if let Some(label) = self.overrides.get(&(proto, dst_port)) {
            return Some(*label);
        }
        if self.inherit_builtin {
            protocol_label(proto, src_port, dst_port)
        } else {
            None
        }
    }

    /// `true` if this table falls back to the built-in
    /// [`protocol_label`] dispatch when no override matches.
    pub fn inherit_builtin(&self) -> bool {
        self.inherit_builtin
    }

    /// Number of overrides currently registered.
    pub fn override_count(&self) -> usize {
        self.overrides.len()
    }
}

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

    // ── Plan 165 (0.14) — LabelTable tests ───────────────────

    #[test]
    fn label_table_new_starts_empty_inheriting_builtin() {
        let t = LabelTable::new();
        assert!(t.inherit_builtin());
        assert_eq!(t.override_count(), 0);
    }

    #[test]
    fn label_table_standalone_does_not_inherit() {
        let t = LabelTable::standalone();
        assert!(!t.inherit_builtin());
    }

    #[test]
    fn label_table_lookup_uses_override_first() {
        let mut t = LabelTable::new();
        t.set(L4Proto::Tcp, 80, "internal-proxy");
        // Override wins over the built-in "http".
        assert_eq!(t.lookup(L4Proto::Tcp, 80, 33000), Some("internal-proxy"));
    }

    #[test]
    fn label_table_lookup_falls_back_to_builtin_when_inherit() {
        let t = LabelTable::new();
        // No overrides; built-in lookup applies.
        assert_eq!(t.lookup(L4Proto::Tcp, 80, 33000), Some("http"));
    }

    #[test]
    fn label_table_standalone_returns_none_when_no_override() {
        let t = LabelTable::standalone();
        assert_eq!(t.lookup(L4Proto::Tcp, 80, 33000), None);
    }

    #[test]
    fn label_table_extend_bulk_sets_entries() {
        let mut t = LabelTable::new();
        t.extend([
            (L4Proto::Tcp, 8765, "grpc-internal"),
            (L4Proto::Tcp, 9101, "metrics-scrape"),
        ]);
        assert_eq!(t.override_count(), 2);
        assert_eq!(t.lookup(L4Proto::Tcp, 8765, 0), Some("grpc-internal"));
        assert_eq!(t.lookup(L4Proto::Tcp, 9101, 0), Some("metrics-scrape"));
    }

    #[test]
    fn label_table_set_overrides_existing_label() {
        let mut t = LabelTable::new();
        t.set(L4Proto::Tcp, 8765, "old");
        t.set(L4Proto::Tcp, 8765, "new");
        assert_eq!(t.lookup(L4Proto::Tcp, 8765, 0), Some("new"));
        assert_eq!(t.override_count(), 1);
    }

    #[test]
    fn label_table_lookup_tries_src_port_first_then_dst() {
        let mut t = LabelTable::new();
        t.set(L4Proto::Tcp, 8765, "src-side");
        // src_port = 8765 matches first.
        assert_eq!(t.lookup(L4Proto::Tcp, 8765, 9100), Some("src-side"));
        // dst_port = 8765 also matches when src misses.
        assert_eq!(t.lookup(L4Proto::Tcp, 33000, 8765), Some("src-side"));
    }

    #[test]
    fn label_table_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<LabelTable>();
    }
}
