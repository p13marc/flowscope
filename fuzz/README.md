# flowscope-fuzz

Cargo-fuzz harnesses for the parsers shipped under flowscope
feature gates. Issue #20.

flowscope's parsers wrap (or hand-roll) decoders that operate on
adversarial input. Upstream parser crates (`tls-parser`,
`simple-dns`, `httparse`) are themselves fuzzed, but the
flowscope wrappers — framing, state machines, dispatch — are
not exercised by their fuzz harnesses. This crate fills that
gap.

## Harnesses

| Target | Parser | Notes |
|--------|--------|-------|
| `arp` | `flowscope::arp::parse` | Pure ARP payload (28 B minimum). |
| `dns_udp` | `flowscope::dns::DnsUdpParser` | Single-datagram. |
| `dns_tcp` | `flowscope::dns::DnsTcpParser` | RFC-1035 2-byte length framing. SessionParser. |
| `http` | `flowscope::http::HttpParser` | SessionParser; covers request + response. |
| `icmp` | `flowscope::icmp::IcmpParser` | v4 + v6 dispatch. |
| `tls` | `flowscope::tls::TlsParser` | Per-message stream — ClientHello / ServerHello / Alert. |
| `tls_handshake` | `flowscope::tls::TlsHandshakeParser` | Aggregator on top of `TlsParser`. |
| `layers` | `flowscope::layers::Layers::from_frame` | Per-packet layered view; etherparse-based. |

## Running

```bash
cargo install cargo-fuzz
cd fuzz

# Quick smoke (matches the CI smoke job — ~30s per target).
cargo +nightly fuzz run dns_udp -- -max_total_time=30

# Longer hunt.
cargo +nightly fuzz run dns_udp -- -max_total_time=1800

# All targets sequentially with a 60s budget each.
for t in arp dns_udp dns_tcp http icmp tls tls_handshake layers; do
    cargo +nightly fuzz run "$t" -- -max_total_time=60
done
```

Cargo-fuzz needs the nightly toolchain (the `-Zsanitizer` flag).

## Corpora

This crate ships **no seed corpora**. libFuzzer is comfortable
starting from empty, and the parsers respond well to coverage-
guided exploration. Production use should seed from the
`tests/data/` pcap fixtures + per-parser `tests/fixtures/`
directories — extract the raw payload bytes for each parser:

```bash
mkdir -p corpus/http
# ...derive seeds from the pcap fixtures.
```

## CI integration

`.github/workflows/fuzz-smoke.yml` runs each target for a short
time-boxed window on every push / PR — designed to catch
regressions cheap, not to find new bugs. A separate scheduled
job is the right home for longer hunts.
