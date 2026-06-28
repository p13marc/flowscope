//! mDNS module — service-discovery + asset adapter coverage.

#![cfg(feature = "mdns")]

use std::net::Ipv4Addr;

use flowscope::Timestamp;
use flowscope::dns::{DnsFlags, DnsRcode, DnsRdata, DnsRecord, DnsResponse};
use flowscope::mdns::{
    MDNS_MULTICAST_V4, MDNS_MULTICAST_V6, MDNS_PORT, MdnsParser, ServiceRecord, extract_services,
    looks_like_mdns,
};

fn empty_response() -> DnsResponse {
    DnsResponse::new(
        0,
        DnsFlags(0x8400), // QR=1, AA=1 — typical mDNS response shape
        Vec::new(),
        Vec::new(),
        Vec::new(),
        Vec::new(),
        DnsRcode::NoError,
        Timestamp::default(),
        None,
    )
}

#[test]
fn constants_match_iana_assignment() {
    assert_eq!(MDNS_PORT, 5353);
    assert_eq!(MDNS_MULTICAST_V4, Ipv4Addr::new(224, 0, 0, 251));
    // ff02::fb
    assert_eq!(MDNS_MULTICAST_V6.segments()[0], 0xff02);
    assert_eq!(MDNS_MULTICAST_V6.segments()[7], 0x00fb);
}

#[test]
fn mdns_parser_uses_dns_parser_kind_slug() {
    let p = MdnsParser::default();
    use flowscope::DatagramParser;
    assert_eq!(p.parser_kind(), "mdns");
}

#[test]
fn extract_services_returns_empty_on_no_ptr() {
    let resp = empty_response();
    assert!(extract_services(&resp).is_empty());
}

#[test]
fn extract_services_decodes_multiple_records() {
    let mut resp = empty_response();
    resp.answers.push(DnsRecord::new(
        "_airplay._tcp.local",
        12,
        1,
        120,
        DnsRdata::PTR("TV._airplay._tcp.local".into()),
    ));
    resp.answers.push(DnsRecord::new(
        "_googlecast._tcp.local",
        12,
        1,
        120,
        DnsRdata::PTR("Chromecast._googlecast._tcp.local".into()),
    ));
    let services = extract_services(&resp);
    assert_eq!(services.len(), 2);
    let names: Vec<_> = services.iter().map(|s| s.service.as_str()).collect();
    assert!(names.contains(&"airplay"));
    assert!(names.contains(&"googlecast"));
}

#[test]
fn looks_like_mdns_recognizes_zero_transaction_id() {
    let resp = empty_response();
    assert!(looks_like_mdns(&resp));
}

#[test]
fn looks_like_mdns_recognizes_service_discovery_record() {
    let mut resp = empty_response();
    resp.transaction_id = 0x1234;
    resp.answers.push(DnsRecord::new(
        "_http._tcp.local",
        12,
        1,
        60,
        DnsRdata::PTR("WebUI._http._tcp.local".into()),
    ));
    assert!(looks_like_mdns(&resp));
}

#[test]
fn looks_like_mdns_rejects_unicast_dns_response() {
    let mut resp = empty_response();
    resp.transaction_id = 0x4242;
    resp.answers.push(DnsRecord::new(
        "example.com",
        1,
        1,
        300,
        DnsRdata::A(Ipv4Addr::new(93, 184, 216, 34)),
    ));
    assert!(!looks_like_mdns(&resp));
}

#[test]
fn service_record_well_known_filter() {
    // ServiceRecord is `#[non_exhaustive]`; we can't struct-
    // literal from outside the crate. Drive through the
    // parser instead.
    let mut resp = empty_response();
    resp.answers.push(DnsRecord::new(
        "_airplay._tcp.local",
        12,
        1,
        120,
        DnsRdata::PTR("TV._airplay._tcp.local".into()),
    ));
    let svc = extract_services(&resp).into_iter().next().expect("one");
    let _: &ServiceRecord = &svc;
    assert!(svc.is_well_known_device_service());
}

// ─── Asset adapter ─────────────────────────────────────────

#[cfg(feature = "asset")]
mod asset {
    use super::*;
    use flowscope::asset::{Asset, AssetCapabilities, AssetSourceSet};
    use flowscope::{Inventory, MacAddr};

    #[test]
    fn from_mdns_returns_none_on_empty_response() {
        let resp = empty_response();
        let mac = MacAddr([0xaa; 6]);
        assert!(Asset::from_mdns(&resp, mac).is_none());
    }

    #[test]
    fn from_mdns_extracts_hostname_from_a_record() {
        let mut resp = empty_response();
        resp.answers.push(DnsRecord::new(
            "printer-living-room.local",
            1,
            1,
            120,
            DnsRdata::A(Ipv4Addr::new(10, 0, 0, 42)),
        ));
        let mac = MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
        let asset = Asset::from_mdns(&resp, mac).expect("populated");
        assert_eq!(asset.mac, mac);
        assert_eq!(asset.hostname.as_deref(), Some("printer-living-room"));
        assert!(asset.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 42)));
        assert!(asset.seen_via.contains(AssetSourceSet::MDNS));
        assert!(asset.capabilities.contains(AssetCapabilities::HOST));
    }

    #[test]
    fn from_mdns_extracts_aaaa_binding() {
        let mut resp = empty_response();
        let v6 = std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0xaa, 0xbb, 0xcc, 0xdd);
        resp.answers.push(DnsRecord::new(
            "device.local",
            28,
            1,
            120,
            DnsRdata::AAAA(v6),
        ));
        let mac = MacAddr([1; 6]);
        let asset = Asset::from_mdns(&resp, mac).expect("populated");
        assert!(asset.ipv6.contains(&v6));
        assert_eq!(asset.hostname.as_deref(), Some("device"));
    }

    #[test]
    fn from_mdns_service_discovery_implies_upnp_capability() {
        let mut resp = empty_response();
        resp.answers.push(DnsRecord::new(
            "_homekit._tcp.local",
            12,
            1,
            4500,
            DnsRdata::PTR("AppleTV._homekit._tcp.local".into()),
        ));
        let mac = MacAddr([2; 6]);
        let asset = Asset::from_mdns(&resp, mac).expect("populated");
        assert!(asset.capabilities.contains(AssetCapabilities::UPNP));
        assert!(asset.capabilities.contains(AssetCapabilities::HOST));
        assert!(asset.seen_via.contains(AssetSourceSet::MDNS));
    }

    #[test]
    fn from_mdns_walks_additionals_section() {
        // Real-world mDNS responses cram A records into the
        // additionals section alongside the answer PTR.
        let mut resp = empty_response();
        resp.answers.push(DnsRecord::new(
            "_ipp._tcp.local",
            12,
            1,
            4500,
            DnsRdata::PTR("HP-Printer._ipp._tcp.local".into()),
        ));
        resp.additionals.push(DnsRecord::new(
            "HP-Printer.local",
            1,
            1,
            120,
            DnsRdata::A(Ipv4Addr::new(10, 0, 0, 100)),
        ));
        let mac = MacAddr([3; 6]);
        let asset = Asset::from_mdns(&resp, mac).expect("populated");
        assert!(asset.ipv4.contains(&Ipv4Addr::new(10, 0, 0, 100)));
        assert_eq!(asset.hostname.as_deref(), Some("HP-Printer"));
    }

    #[test]
    fn from_mdns_ignores_non_local_records() {
        let mut resp = empty_response();
        resp.answers.push(DnsRecord::new(
            "example.com",
            1,
            1,
            300,
            DnsRdata::A(Ipv4Addr::new(93, 184, 216, 34)),
        ));
        let mac = MacAddr([4; 6]);
        assert!(
            Asset::from_mdns(&resp, mac).is_none(),
            "non-.local A records should not populate an mDNS asset"
        );
    }

    #[test]
    fn inventory_absorbs_mdns_asset_and_merges() {
        let mut inv = Inventory::new(8);
        let mac = MacAddr([5; 6]);
        let mut resp = empty_response();
        resp.answers.push(DnsRecord::new(
            "tv.local",
            1,
            1,
            120,
            DnsRdata::A(Ipv4Addr::new(10, 0, 0, 50)),
        ));
        let asset = Asset::from_mdns(&resp, mac).expect("populated");
        inv.absorb(asset);
        let got = inv.get(&mac).expect("present");
        assert_eq!(got.hostname.as_deref(), Some("tv"));
        assert!(got.seen_via.contains(AssetSourceSet::MDNS));
    }
}
