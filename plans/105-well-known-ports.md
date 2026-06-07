# Plan 105 — `flowscope::well_known` — port → protocol labels

## Summary

Ship a curated table mapping `(L4Proto, port)` to a
canonical short label (`"http"`, `"tls/https"`, `"dns"`,
`"redis"`, …), plus convenience accessors on `FiveTupleKey`.

The `bandwidth_by_protocol.rs` example needed this in 0.9
and hard-coded a 24-entry table inline. Ship a curated 50–80
entry version in the crate; update in patch releases.

Theme 5 follow-up.

## Status

**Ready to implement.** Targets 0.10.0.

## Prerequisites

None.

## Out of scope

- **Dynamic protocol detection from payload.** Suricata /
  Zeek do this; flowscope intentionally stays at port-based.
  Real protocol detection is the unified `Driver` route
  (plan 116) where consumers register parsers, with
  signature-based heuristic dispatch added by plan 114.
- **Negotiated port labels** (e.g. SCTP per-association
  ports). Out of scope.

---

## API

```rust
// src/well_known/mod.rs

/// Canonical short label for the given (proto, port).
/// Returns `None` for unknown ports.
///
/// Always uses the lower-numbered port to disambiguate
/// client / server pairs.
pub fn protocol_label(proto: L4Proto, src_port: u16, dst_port: u16)
    -> Option<&'static str>;

/// Iterate the full curated table for inspection or
/// custom-labelled views.
pub fn entries() -> impl Iterator<Item = (L4Proto, u16, &'static str)>;

/// Add a method to FiveTupleKey:
impl FiveTupleKey {
    /// Lower-numbered port — the "well-known" side for
    /// client/server flows.
    pub fn well_known_port(&self) -> u16;

    /// `protocol_label(self.proto, self.a.port(), self.b.port())`.
    pub fn protocol_label(&self) -> Option<&'static str>;
}
```

### Table content (initial seed)

```text
TCP:
  20, 21    ftp
  22        ssh
  23        telnet
  25, 587   smtp
  53        dns
  80, 8000, 8080  http
  110       pop3
  143       imap
  443, 8443 tls/https
  465       smtps
  587       smtp-submission
  993       imaps
  995       pop3s
  1433      mssql
  1521      oracle
  2049      nfs
  3306      mysql
  3389      rdp
  5432      postgres
  5672      amqp
  5984      couchdb
  6379      redis
  6443      kubernetes-api
  6667      irc
  7000-7001 cassandra
  8088      hbase
  8500      consul
  9000-9001 minio
  9042      cassandra-cql
  9092, 9093 kafka
  9200, 9300 elasticsearch
  10000     webmin
  11211     memcached
  15672     rabbitmq-mgmt
  27017     mongodb
  50070     hdfs

UDP:
  53        dns
  67, 68    dhcp
  69        tftp
  88        kerberos
  123       ntp
  137-139   netbios
  161, 162  snmp
  389       ldap
  443       quic / http3
  500, 4500 ipsec
  514       syslog
  636       ldaps
  1812-1813 radius
  2049      nfs
  2152      gtp-u
  3478      stun
  4789      vxlan
  5060-5061 sip
```

~80 entries total. Covered by a `phf::Map` (perfect hash) or
a sorted slice + binary search. Initial implementation: a
`[(L4Proto, u16, &'static str); N]` constant with a small
binary-search function. Pull in `phf` only if benchmarks
show the linear/binary path matters.

---

## Files

```
src/well_known/mod.rs              # public API + curated table
src/extract/five_tuple.rs           # FiveTupleKey accessors
tests/well_known.rs                # coverage
examples/bandwidth_by_protocol.rs   # MIGRATED to use protocol_label
docs/recipes.md                    # one-paragraph note
CHANGELOG.md                       # 0.10 entry
```

## Implementation steps

1. Create `src/well_known/mod.rs` with the curated table
   (constant slice) and `protocol_label()` function.
2. Add `FiveTupleKey::well_known_port()` +
   `protocol_label()` accessors.
3. Migrate `examples/bandwidth_by_protocol.rs` to use the
   shipped helper — drops 30 LoC of hand-rolled table.
4. `tests/well_known.rs`:
   - Common ports: 80 → http, 443 → tls/https, 53 →
     dns, 6379 → redis.
   - Unknown port: `Some` for known, `None` for unknown.
   - Lower-port disambiguation: port 80 + port 33000 →
     "http".
   - `entries()` iteration count matches the table size.
5. CHANGELOG entry under 0.10.0 "Added".

## Acceptance criteria

- ~80-entry curated table ships.
- Two accessors on `FiveTupleKey`.
- Example migrated.
- 4+ tests pass.
- `cargo test --all-features` clean.
- CHANGELOG entry.

## Risks

- **Table drift over time.** New port assignments happen
  periodically. Mitigation: documented refresh cadence —
  curate against the IANA registry once per minor release.

## Effort

| Surface | LoC | Hours |
|---------|-----|-------|
| `well_known/mod.rs` + table + accessors | ~250 | 4 |
| Tests | ~80 | 1 |
| Example migration | ~−25 net | 0.5 |
| Docs + CHANGELOG | ~30 | 0.5 |
| **Total** | **~335 LoC** | **~6 hours** |

## Provenance

Postmortem theme 5 — `bandwidth_by_protocol` example
hard-coded a 24-entry port table.
