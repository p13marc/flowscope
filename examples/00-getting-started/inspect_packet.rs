//! Dump a layered view of every packet in a pcap.
//!
//! Demonstrates the Tier 3 `flowscope::layers` module: per-packet
//! zero-copy introspection with direct typed accessors AND the
//! dynamic walk (`iter` / `find` / `find_all`). Recognises VLAN,
//! ARP, IPv4/IPv6, TCP/UDP, ICMPv4/v6, and tunnel headers
//! (VXLAN / GTP-U / GRE / IP-in-IP).
//!
//! ```bash
//! cargo run --features pcap,extractors --example inspect_packet -- trace.pcap
//! ```
//!
//! Falls back to `tests/data/mixed_short.pcap` if no path is given.

use flowscope::layers::{Layer, LayerKind};
use flowscope::pcap::PcapFlowSource;
use flowscope::PacketView;

fn main() -> flowscope::Result<()> {
    let path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "tests/data/mixed_short.pcap".to_string());

    let mut packet_no = 0usize;
    for owned in PcapFlowSource::open(&path)?.views() {
        let owned = owned?;
        packet_no += 1;
        let pv = PacketView::new(&owned.frame, owned.timestamp);

        let layers = match pv.layers() {
            Ok(l) => l,
            Err(_) => {
                println!("[{packet_no}] (parse failed, {} bytes)", owned.frame.len());
                continue;
            }
        };

        let depth = layers.depth();
        let tunnel = if layers.has_tunnel() { " [tunnel]" } else { "" };
        let trunc = if layers.truncated() { " [truncated]" } else { "" };
        println!(
            "[{packet_no}] ts={}.{:09} {} bytes, {} layers{tunnel}{trunc}",
            owned.timestamp.sec, owned.timestamp.nsec,
            owned.frame.len(),
            depth,
        );

        // Dynamic walk — outer to inner.
        for layer in layers.iter() {
            describe_layer(layer);
        }
        println!();
    }

    println!("--- {packet_no} packets total");
    Ok(())
}

fn describe_layer(layer: &Layer<'_>) {
    match layer {
        Layer::Ethernet(eth) => {
            print_pair("eth", "src", &fmt_mac(eth.source()));
            print_pair("eth", "dst", &fmt_mac(eth.destination()));
            print_pair("eth", "ethertype", &format!("0x{:04x}", eth.ether_type()));
        }
        Layer::Vlan(v) => {
            print_pair("vlan", "vid", &v.vid().to_string());
            print_pair("vlan", "prio", &v.priority().to_string());
        }
        Layer::Mpls(m) => {
            print_pair("mpls", "label", &m.label().to_string());
            print_pair("mpls", "ttl", &m.ttl().to_string());
        }
        Layer::Ipv4(ip) => {
            print_pair("ipv4", "src", &ip.source().to_string());
            print_pair("ipv4", "dst", &ip.destination().to_string());
            print_pair("ipv4", "proto", &ip.protocol().to_string());
            print_pair("ipv4", "ttl", &ip.ttl().to_string());
            if ip.df() {
                print_pair("ipv4", "flags", "DF");
            }
        }
        Layer::Ipv6(ip) => {
            print_pair("ipv6", "src", &ip.source().to_string());
            print_pair("ipv6", "dst", &ip.destination().to_string());
            print_pair("ipv6", "next_header", &ip.next_header().to_string());
            print_pair("ipv6", "flow_label", &format!("0x{:05x}", ip.flow_label()));
        }
        Layer::Arp(a) => {
            print_pair("arp", "oper", &arp_oper(a.oper()));
            if let Some(sha) = a.sender_ha() {
                print_pair("arp", "sender_ha", &fmt_mac(sha));
            }
            if let Some(spa) = a.sender_pa() {
                print_pair("arp", "sender_pa", &spa.to_string());
            }
            if let Some(tpa) = a.target_pa() {
                print_pair("arp", "target_pa", &tpa.to_string());
            }
        }
        Layer::Tcp(tcp) => {
            print_pair("tcp", "src_port", &tcp.src_port().to_string());
            print_pair("tcp", "dst_port", &tcp.dst_port().to_string());
            print_pair("tcp", "seq", &tcp.seq().to_string());
            print_pair("tcp", "ack", &tcp.ack().to_string());
            print_pair("tcp", "window", &tcp.window().to_string());
            print_pair("tcp", "flags", &fmt_tcp_flags(&tcp.flags()));
            let opts: Vec<String> = tcp
                .options()
                .filter_map(|o| match o {
                    flowscope::layers::TcpOption::Mss(n) => Some(format!("MSS={n}")),
                    flowscope::layers::TcpOption::WindowScale(s) => Some(format!("WS={s}")),
                    flowscope::layers::TcpOption::SackPermitted => Some("SACK_PERM".into()),
                    flowscope::layers::TcpOption::Timestamp { tsval, .. } => {
                        Some(format!("TS={tsval}"))
                    }
                    _ => None,
                })
                .collect();
            if !opts.is_empty() {
                print_pair("tcp", "options", &opts.join(","));
            }
        }
        Layer::Udp(udp) => {
            print_pair("udp", "src_port", &udp.src_port().to_string());
            print_pair("udp", "dst_port", &udp.dst_port().to_string());
            print_pair("udp", "length", &udp.length().to_string());
        }
        Layer::Icmpv4(icmp) => {
            print_pair("icmpv4", "type", &icmp.icmp_type().to_string());
            print_pair("icmpv4", "code", &icmp.code().to_string());
        }
        Layer::Icmpv6(icmp) => {
            print_pair("icmpv6", "type", &icmp.icmp_type().to_string());
            print_pair("icmpv6", "code", &icmp.code().to_string());
        }
        Layer::Gre(g) => {
            print_pair("gre", "protocol_type", &format!("0x{:04x}", g.protocol_type()));
        }
        Layer::Vxlan(v) => {
            print_pair("vxlan", "vni", &v.vni().to_string());
        }
        Layer::GtpU(g) => {
            print_pair("gtpu", "teid", &format!("0x{:08x}", g.teid()));
            print_pair("gtpu", "msg_type", &g.msg_type().to_string());
        }
        Layer::Payload(p) => {
            println!("    payload          : {} bytes", p.len());
        }
        _ => {
            println!("    {:<17}: …", layer.kind());
        }
    }
    let _ = LayerKind::Payload; // silence unused-import warning
}

fn print_pair(layer: &str, field: &str, value: &str) {
    println!("    {layer}.{field:<14}: {value}");
}

fn fmt_mac(m: [u8; 6]) -> String {
    format!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        m[0], m[1], m[2], m[3], m[4], m[5]
    )
}

fn arp_oper(o: u16) -> String {
    match o {
        1 => "request".into(),
        2 => "reply".into(),
        n => format!("op={n}"),
    }
}

fn fmt_tcp_flags(f: &flowscope::layers::TcpFlagsView) -> String {
    let mut s = String::new();
    if f.syn { s.push('S'); }
    if f.ack { s.push('A'); }
    if f.fin { s.push('F'); }
    if f.rst { s.push('R'); }
    if f.psh { s.push('P'); }
    if f.urg { s.push('U'); }
    if f.ece { s.push('E'); }
    if f.cwr { s.push('C'); }
    if s.is_empty() { "-".into() } else { s }
}
