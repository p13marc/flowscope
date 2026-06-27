//! `flow_analysis` — enrich flows with risk + threat-intel using
//! the `analysis` composition layer (`flowscope::analysis`).
//!
//! Demonstrates the #83 wiring: feed a [`FlowAnalyzer`] the parser
//! messages you already produce (`observe_tls` / `observe_dns` /
//! `observe_http`), then `finalize` on each flow's end to get an
//! [`AnalyzedFlow`] — the 5-tuple + stats + curated L7 summary +
//! computed `FlowRisk` + threat-intel `IocMatch` hits — without
//! hand-rolling risk/IOC/L7 correlation.
//!
//! To keep the example deterministic and dependency-free it
//! synthesizes a few flows rather than reading a pcap; in a real
//! pipeline the `observe_*` calls are driven from a `Driver<E>`
//! slot drain (or a `FlowSessionDriver`) and `finalize` from the
//! flow's `Ended` event.
//!
//! Run: `cargo run --example flow_analysis --features analysis,tls,dns,emit-eve`

use std::time::Duration;

use flowscope::analysis::FlowAnalyzer;
use flowscope::detect::{IocKind, IocSet};
use flowscope::dns::{DnsFlags, DnsQuery, DnsQuestion};
use flowscope::emit::EveJsonWriter;
use flowscope::extract::FiveTupleKey;
use flowscope::tls::{TlsHandshake, TlsVersion};
use flowscope::{FlowStats, L4Proto, Timestamp};

fn key(dst_ip: &str, dport: u16) -> FiveTupleKey {
    FiveTupleKey {
        proto: L4Proto::Tcp,
        a: "10.0.0.50:51000".parse().unwrap(),
        b: format!("{dst_ip}:{dport}").parse().unwrap(),
    }
}

fn stats(pkts: u64, bytes: u64) -> FlowStats {
    let mut s = FlowStats::default();
    s.packets_initiator = pkts;
    s.bytes_initiator = bytes;
    s
}

fn main() {
    // 1. Load a tiny threat-intel feed. In production this comes
    //    from `IocSet::load_feed` over an abuse.ch / MISP export.
    let mut ioc = IocSet::with_capacity(100_000);
    ioc.insert(
        IocKind::Domain,
        "badcdn.example",
        Some(90),
        Some("intel-feed"),
    );
    ioc.insert(IocKind::Ipv4, "198.51.100.7", Some(80), Some("c2-tracker"));
    ioc.insert(
        IocKind::Ja4,
        "t13d1516h2_8daaf6152771_deadbeefcafe",
        Some(95),
        Some("malware-ja4"),
    );

    // 2. Build a bounded analyzer with the feed attached.
    let mut analyzer =
        FlowAnalyzer::<FiveTupleKey>::with_capacity(Duration::from_secs(120), 100_000)
            .with_ioc(ioc);
    let ts = Timestamp::new(1, 0);

    // ── Flow A: legacy TLS (TLS 1.0 + RC4) to a normal site ──
    let a = key("93.184.216.34", 443);
    let mut hs_a = TlsHandshake::default();
    hs_a.sni = Some("www.example.com".into());
    hs_a.version = Some(TlsVersion::Tls1_0);
    hs_a.cipher_suite = Some(0x0005); // TLS_RSA_WITH_RC4_128_SHA
    analyzer.observe_tls(&a, &hs_a, ts);

    // ── Flow B: DNS lookup of a DGA domain, to a flagged resolver IP ──
    let b = key("198.51.100.7", 53);
    let q = DnsQuery {
        transaction_id: 0x1234,
        flags: DnsFlags(0),
        questions: vec![DnsQuestion {
            name: "kq3v9z7xj2wqp1.com".into(),
            qtype: 1,
            qclass: 1,
        }],
        timestamp: ts,
    };
    analyzer.observe_dns_query(&b, &q, ts);

    // ── Flow C: TLS whose JA4 is on the malware watch-list ──
    let c = key("203.0.113.10", 8443);
    let mut hs_c = TlsHandshake::default();
    hs_c.sni = Some("cdn.badcdn.example".into()); // also a flagged domain
    hs_c.version = Some(TlsVersion::Tls1_3);
    hs_c.ja4 = Some("t13d1516h2_8daaf6152771_deadbeefcafe".into());
    analyzer.observe_tls(&c, &hs_c, ts);

    // ── Flow D: clean modern HTTPS ──
    let d = key("140.82.112.3", 443);
    let mut hs_d = TlsHandshake::default();
    hs_d.sni = Some("github.com".into());
    hs_d.version = Some(TlsVersion::Tls1_3);
    hs_d.cipher_suite = Some(0x1301); // TLS_AES_128_GCM_SHA256
    analyzer.observe_tls(&d, &hs_d, ts);

    // 3. On each flow's Ended event, finalize → enriched record.
    let flows = [
        ("A legacy-TLS", a, stats(20, 4_000)),
        ("B dga-dns   ", b, stats(2, 180)),
        ("C bad-ja4   ", c, stats(15, 9_000)),
        ("D clean     ", d, stats(40, 28_000)),
    ];

    let records: Vec<_> = flows
        .into_iter()
        .map(|(label, k, st)| (label, analyzer.finalize(&k, st)))
        .collect();

    // The analyzer evicted each flow's state on finalize.
    assert_eq!(analyzer.len(), 0);

    println!("flow          clean?  sev     score  risk / IOC");
    println!("{}", "─".repeat(72));
    for (label, rec) in &records {
        let sev = rec.severity().map(|s| s.as_str()).unwrap_or("-");
        let risks: Vec<&str> = rec.risk.as_slugs().collect();
        let mut detail = risks.join(",");
        for m in &rec.ioc_hits {
            detail.push_str(&format!(
                "  ⚑ioc:{}={}{}",
                m.kind.as_str(),
                m.value,
                m.source
                    .as_deref()
                    .map(|s| format!("({s})"))
                    .unwrap_or_default()
            ));
        }
        if detail.is_empty() {
            detail.push('-');
        }
        println!(
            "{label}  {:>5}  {sev:<6}  {:>4}   {detail}",
            if rec.is_clean() { "yes" } else { "NO" },
            rec.score(),
        );
    }

    // 4. The same records as SIEM-ready EVE JSON (one line per
    //    non-clean flow) — pipe to jq, Filebeat, Splunk, …
    println!("\n── EVE JSON (non-clean flows) ──");
    let mut eve = EveJsonWriter::new(std::io::stdout().lock());
    for (_, rec) in &records {
        if !rec.is_clean() {
            eve.write_analyzed_flow(rec).unwrap();
        }
    }
}
