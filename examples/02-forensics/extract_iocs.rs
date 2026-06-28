//! Pull every Indicator of Compromise (IoC) candidate out of
//! a pcap and emit a deduplicated list. Useful for incident
//! response and threat-intel pipelines.
//!
//! Extracts:
//!
//! ### Network identifiers
//! - **Hostnames** — SNI from TLS, Host header from HTTP, DNS
//!   query names.
//! - **IPs** — every src/dst IP from every flow, split into
//!   global (potentially-routable, "external") vs non-global
//!   (RFC 1918 / loopback / link-local / multicast, "internal")
//!   buckets via `IpAddr::is_global()`-equivalent logic.
//!
//! ### Client fingerprints
//! - **JA3 / JA4** — TLS client fingerprints.
//! - **HTTP User-Agents**.
//!
//! ### Identity claims (0.18 cycle additions)
//! - **SMTP** envelope addresses (MAIL FROM / RCPT TO) —
//!   sender / recipient enumeration.
//! - **FTP** USER credentials — cleartext credential capture.
//! - **SMB** NTLM identity tuple (domain / username /
//!   workstation) — lateral-movement actor identification.
//! - **Kerberos** client name + realm — AD enumeration.
//! - **LDAP** Bind DN — directory query actor.
//!
//! Output is grouped by category and sorted by frequency.
//!
//! ## MITRE ATT&CK
//!
//! IoC enrichment under [T1071](https://attack.mitre.org/techniques/T1071/)
//! (Application Layer Protocol — TLS / HTTP / DNS / SMB / etc.
//! are the carrier protocols for the identifiers we extract).
//!
//! ## Usage
//!
//! ```bash
//! cargo run --features \
//!     "pcap,http,tls,tls-fingerprints,dns,extractors,tracker,smtp,ftp,smb,kerberos,ldap" \
//!     --example extract_iocs -- trace.pcap
//! ```
//!
//! Closes #56.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use flowscope::dns::{DnsMessage, DnsUdpParser};
use flowscope::driver::{Driver, Event, SlotMessage};
use flowscope::extract::{FiveTuple, FiveTupleKey};
use flowscope::ftp::{FtpCommand, FtpMessage, FtpParser};
use flowscope::http::{HttpMessage, HttpParser};
use flowscope::kerberos::{KerberosMessage, KerberosTcpParser};
use flowscope::ldap::{LdapMessage, LdapParser};
use flowscope::pcap::PcapFlowSource;
use flowscope::smb::{SmbMessage, SmbParser};
use flowscope::smtp::{SmtpMessage, SmtpParser};
use flowscope::tls::{TlsHandshake, TlsHandshakeParser};

#[derive(Default)]
struct Iocs {
    hostnames: HashMap<String, (u32, &'static str)>,
    ips_global: BTreeSet<IpAddr>,
    ips_local: BTreeSet<IpAddr>,
    user_agents: HashMap<String, u32>,
    ja3s: HashMap<String, u32>,
    ja4s: HashMap<String, u32>,
    smtp_addresses: HashMap<String, u32>,
    ftp_users: HashMap<String, u32>,
    smb_identities: BTreeSet<String>,
    kerberos_clients: BTreeSet<String>,
    ldap_binds: BTreeSet<String>,
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut builder = Driver::builder(FiveTuple::bidirectional());
    let mut http_slot = builder.session_on_ports(HttpParser::default(), [80, 8080]);
    let mut tls_slot = builder.session_on_ports(TlsHandshakeParser::default(), [443, 8443]);
    let mut dns_slot = builder.datagram_on_ports(DnsUdpParser::default(), [53]);
    let mut smtp_slot = builder.session_on_ports(SmtpParser::default(), [25, 587]);
    let mut ftp_slot = builder.session_on_ports(FtpParser::default(), [21]);
    let mut smb_slot = builder.session_on_ports(SmbParser::default(), [445]);
    let mut kerberos_slot = builder.session_on_ports(KerberosTcpParser::default(), [88]);
    let mut ldap_slot = builder.session_on_ports(LdapParser::default(), [389]);
    let mut driver = builder.build();

    let mut iocs = Iocs::default();
    let mut events: Vec<Event<FiveTupleKey>> = Vec::new();
    macro_rules! drain_into {
        ($slot:ident, $msg_ty:ty, $h:expr) => {{
            let mut buf: Vec<SlotMessage<$msg_ty, FiveTupleKey>> = Vec::new();
            $slot.drain(&mut buf);
            for m in buf.drain(..) {
                $h(&mut iocs, &m.message);
            }
        }};
    }

    for view in PcapFlowSource::open(&path)?.views() {
        let view = view?;
        events.clear();
        driver.track_into(&view, &mut events);
        for ev in &events {
            if let Event::Started { key, .. } = ev {
                bucket_ip(&mut iocs, key.a.ip());
                bucket_ip(&mut iocs, key.b.ip());
            }
        }
        drain_into!(http_slot, HttpMessage, handle_http);
        drain_into!(tls_slot, TlsHandshake, handle_tls);
        drain_into!(dns_slot, DnsMessage, handle_dns);
        drain_into!(smtp_slot, SmtpMessage, handle_smtp);
        drain_into!(ftp_slot, FtpMessage, handle_ftp);
        drain_into!(smb_slot, SmbMessage, handle_smb);
        drain_into!(kerberos_slot, KerberosMessage, handle_kerberos);
        drain_into!(ldap_slot, LdapMessage, handle_ldap);
    }

    print_section_h("Hostnames", &iocs.hostnames);
    println!("\n=== IPs — external ({}) ===", iocs.ips_global.len());
    for ip in &iocs.ips_global {
        println!("  {ip}");
    }
    println!("\n=== IPs — internal ({}) ===", iocs.ips_local.len());
    for ip in &iocs.ips_local {
        println!("  {ip}");
    }
    print_section("HTTP User-Agents", &iocs.user_agents);
    print_section("JA3 fingerprints", &iocs.ja3s);
    print_section("JA4 fingerprints", &iocs.ja4s);
    print_section("SMTP addresses", &iocs.smtp_addresses);
    print_section("FTP USERs", &iocs.ftp_users);
    print_set("SMB NTLM identities", &iocs.smb_identities);
    print_set("Kerberos clients", &iocs.kerberos_clients);
    print_set("LDAP Bind DNs", &iocs.ldap_binds);
    Ok(())
}

fn bucket_ip(iocs: &mut Iocs, ip: IpAddr) {
    if is_locally_scoped(&ip) {
        iocs.ips_local.insert(ip);
    } else {
        iocs.ips_global.insert(ip);
    }
}

/// Approximation of the stable `IpAddr::is_global()` (which
/// isn't stable across all MSRVs we support) — collects every
/// non-global category we care about as "local".
fn is_locally_scoped(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_broadcast()
                || v4.is_documentation()
                || v4.is_unspecified()
                || v4.is_multicast()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                // fe80::/10 link-local
                || v6.segments()[0] & 0xffc0 == 0xfe80
                // fc00::/7 ULA
                || v6.segments()[0] & 0xfe00 == 0xfc00
        }
    }
}

fn handle_http(iocs: &mut Iocs, message: &HttpMessage) {
    if let HttpMessage::Request(req) = message {
        for (name, val) in &req.headers {
            if name.as_ref().eq_ignore_ascii_case(b"host") {
                let h = String::from_utf8_lossy(val).to_string();
                let entry = iocs.hostnames.entry(h).or_insert((0, "http"));
                entry.0 += 1;
            }
            if name.as_ref().eq_ignore_ascii_case(b"user-agent") {
                let ua = String::from_utf8_lossy(val).to_string();
                *iocs.user_agents.entry(ua).or_default() += 1;
            }
        }
    }
}

fn handle_tls(iocs: &mut Iocs, message: &TlsHandshake) {
    if let Some(sni) = message.sni.clone() {
        let entry = iocs.hostnames.entry(sni).or_insert((0, "tls"));
        entry.0 += 1;
    }
    if let Some(ja3) = message.ja3.clone() {
        *iocs.ja3s.entry(ja3).or_default() += 1;
    }
    if let Some(ja4) = message.ja4.clone() {
        *iocs.ja4s.entry(ja4).or_default() += 1;
    }
}

fn handle_dns(iocs: &mut Iocs, message: &DnsMessage) {
    let names: Vec<String> = match message {
        DnsMessage::Query(q) => q.questions.iter().map(|q| q.name.clone()).collect(),
        DnsMessage::Response(r) => r.questions.iter().map(|q| q.name.clone()).collect(),
        _ => Vec::new(),
    };
    for n in names {
        let entry = iocs.hostnames.entry(n).or_insert((0, "dns"));
        entry.0 += 1;
    }
}

fn handle_smtp(iocs: &mut Iocs, m: &SmtpMessage) {
    match m {
        SmtpMessage::MailFrom { address } => {
            *iocs.smtp_addresses.entry(address.clone()).or_default() += 1;
        }
        SmtpMessage::RcptTo { address } => {
            *iocs.smtp_addresses.entry(address.clone()).or_default() += 1;
        }
        _ => {}
    }
}

fn handle_ftp(iocs: &mut Iocs, m: &FtpMessage) {
    if let FtpMessage::Command {
        verb: FtpCommand::User,
        args,
    } = m
    {
        *iocs.ftp_users.entry(args.trim().to_string()).or_default() += 1;
    }
    if let FtpMessage::Credentials { user, .. } = m {
        *iocs.ftp_users.entry(user.clone()).or_default() += 1;
    }
}

fn handle_smb(iocs: &mut Iocs, m: &SmbMessage) {
    if let Some(auth) = m.ntlm_auth.as_ref() {
        let dom = auth.domain.as_deref().unwrap_or("");
        let user = auth.username.as_deref().unwrap_or("");
        let ws = auth.workstation.as_deref().unwrap_or("");
        iocs.smb_identities.insert(format!("{dom}\\{user}@{ws}"));
    }
}

fn handle_kerberos(iocs: &mut Iocs, m: &KerberosMessage) {
    if let Some(cname) = m.cname.as_deref() {
        iocs.kerberos_clients.insert(format!("{cname}@{}", m.realm));
    }
}

fn handle_ldap(iocs: &mut Iocs, m: &LdapMessage) {
    if let Some(bind) = m.bind_name.as_deref()
        && !bind.is_empty()
    {
        iocs.ldap_binds.insert(bind.to_string());
    }
}

fn print_section(label: &str, counts: &HashMap<String, u32>) {
    println!("\n=== {label} ({}) ===", counts.len());
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(_, c)| std::cmp::Reverse(**c));
    for (key, count) in sorted.iter().take(20) {
        println!("  {count:>4} {key}");
    }
    if counts.is_empty() {
        println!("  (none)");
    }
}

fn print_section_h(label: &str, counts: &HashMap<String, (u32, &'static str)>) {
    println!("\n=== {label} ({}) ===", counts.len());
    let mut sorted: Vec<_> = counts.iter().collect();
    sorted.sort_by_key(|(_, (c, _))| std::cmp::Reverse(*c));
    for (key, (count, src)) in sorted.iter().take(40) {
        println!("  {count:>4} {src:<6} {key}");
    }
    if counts.is_empty() {
        println!("  (none)");
    }
}

fn print_set(label: &str, set: &BTreeSet<String>) {
    println!("\n=== {label} ({}) ===", set.len());
    for v in set {
        println!("  {v}");
    }
    if set.is_empty() {
        println!("  (none)");
    }
}
