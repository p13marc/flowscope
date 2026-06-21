//! RFC 6763 DNS-SD service-discovery helpers.

use crate::dns::{DnsRdata, DnsResponse};

/// One parsed RFC 6763 service record. The name follows the
/// `<instance>._<service>._<proto>.local` convention; this
/// type splits the three parts.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct ServiceRecord {
    /// User-visible instance label (e.g. `"Living Room TV"`).
    /// Often the device's friendly hostname.
    pub instance: String,
    /// Service type without the leading underscore (e.g.
    /// `"http"`, `"airplay"`, `"ipp"`).
    pub service: String,
    /// Transport protocol — `"tcp"` or `"udp"`.
    pub protocol: String,
    /// PTR target — the full DNS name pointed at.
    pub ptr_target: String,
}

impl ServiceRecord {
    /// `true` if this service-record's service type matches
    /// one of the well-known printer / display / scanner
    /// services that typically reveal a device hostname.
    /// Operationally a useful filter when populating an
    /// asset inventory.
    pub fn is_well_known_device_service(&self) -> bool {
        matches!(
            self.service.as_str(),
            "ipp"
                | "ipps"
                | "printer"
                | "scanner"
                | "airplay"
                | "googlecast"
                | "homekit"
                | "raop"
                | "smb"
                | "ssh"
                | "http"
                | "https"
                | "device-info"
                | "workstation"
        )
    }
}

/// Walk every PTR record in `resp.answers` looking for the
/// RFC 6763 `<instance>._<service>._<proto>.local` naming
/// convention. Returns one [`ServiceRecord`] per match.
///
/// PTR records whose qname doesn't match the convention
/// (e.g. plain reverse-DNS PTRs) are skipped.
pub fn extract_services(resp: &DnsResponse) -> Vec<ServiceRecord> {
    let mut out = Vec::new();
    for rr in &resp.answers {
        if let DnsRdata::PTR(target) = &rr.data {
            // The PTR record's `name` field is the service
            // type (e.g. `_http._tcp.local`); the rdata
            // `target` is the instance.
            if let Some(rec) = parse_service_name(&rr.name, target) {
                out.push(rec);
            }
        }
    }
    out
}

/// Decode `_<service>._<proto>.local` (the PTR record's name)
/// into a service + protocol. The `target` becomes the
/// instance label after stripping the type suffix.
fn parse_service_name(ptr_name: &str, target: &str) -> Option<ServiceRecord> {
    let trimmed = ptr_name.strip_suffix('.').unwrap_or(ptr_name);
    let lower = trimmed.to_ascii_lowercase();
    // Must end in ".local".
    let base = lower.strip_suffix(".local")?;
    let labels: Vec<&str> = base.split('.').collect();
    // Expect at least 2 labels (_service._proto).
    if labels.len() < 2 {
        return None;
    }
    let proto_label = labels[labels.len() - 1];
    let service_label = labels[labels.len() - 2];
    let protocol = proto_label.strip_prefix('_')?.to_string();
    let service = service_label.strip_prefix('_')?.to_string();
    if protocol != "tcp" && protocol != "udp" {
        return None;
    }
    // Instance: the part of the target *before* the service
    // type suffix. e.g. target = "Living Room TV._airplay._tcp.local"
    // → instance = "Living Room TV".
    let target_trimmed = target.strip_suffix('.').unwrap_or(target);
    let suffix = format!("._{service}._{protocol}.local");
    let instance = target_trimmed
        .strip_suffix(&suffix)
        .unwrap_or(target_trimmed)
        .to_string();

    Some(ServiceRecord {
        instance,
        service,
        protocol,
        ptr_target: target_trimmed.to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Timestamp;
    use crate::dns::{DnsFlags, DnsRcode, DnsRecord};

    fn response_with_ptr(ptr_name: &str, target: &str) -> DnsResponse {
        DnsResponse {
            transaction_id: 0,
            flags: DnsFlags(0x8400),
            questions: Vec::new(),
            answers: vec![DnsRecord {
                name: ptr_name.to_string(),
                rtype: 12, // PTR
                rclass: 1,
                ttl: 120,
                data: DnsRdata::PTR(target.to_string()),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rcode: DnsRcode::NoError,
            timestamp: Timestamp::default(),
            elapsed: None,
        }
    }

    #[test]
    fn parses_typical_airplay_record() {
        let resp = response_with_ptr(
            "_airplay._tcp.local",
            "Living Room TV._airplay._tcp.local",
        );
        let services = extract_services(&resp);
        assert_eq!(services.len(), 1);
        let s = &services[0];
        assert_eq!(s.service, "airplay");
        assert_eq!(s.protocol, "tcp");
        assert_eq!(s.instance, "Living Room TV");
        assert!(s.is_well_known_device_service());
    }

    #[test]
    fn parses_googlecast_record() {
        let resp = response_with_ptr(
            "_googlecast._tcp.local",
            "ChromecastUltra-1234._googlecast._tcp.local",
        );
        let services = extract_services(&resp);
        assert_eq!(services[0].service, "googlecast");
        assert_eq!(services[0].instance, "ChromecastUltra-1234");
    }

    #[test]
    fn parses_udp_protocol() {
        let resp = response_with_ptr("_ssdp._udp.local", "Box._ssdp._udp.local");
        let services = extract_services(&resp);
        assert_eq!(services[0].protocol, "udp");
        assert_eq!(services[0].service, "ssdp");
    }

    #[test]
    fn case_insensitive_local_suffix() {
        let resp = response_with_ptr("_airplay._tcp.LOCAL", "TV._airplay._tcp.LOCAL");
        let services = extract_services(&resp);
        assert_eq!(services.len(), 1);
    }

    #[test]
    fn rejects_non_service_ptr() {
        // Reverse DNS lookup, not a service-discovery PTR.
        let resp = response_with_ptr("1.0.0.10.in-addr.arpa", "host.example.com");
        let services = extract_services(&resp);
        assert!(services.is_empty());
    }

    #[test]
    fn rejects_non_local_tld() {
        let resp = response_with_ptr("_http._tcp.example.com", "Server._http._tcp.example.com");
        let services = extract_services(&resp);
        assert!(services.is_empty());
    }

    #[test]
    fn rejects_non_tcp_udp_protocol() {
        let resp = response_with_ptr("_http._other.local", "x._http._other.local");
        let services = extract_services(&resp);
        assert!(services.is_empty());
    }

    #[test]
    fn skips_non_ptr_records() {
        let resp = DnsResponse {
            transaction_id: 0,
            flags: DnsFlags(0x8400),
            questions: Vec::new(),
            answers: vec![DnsRecord {
                name: "_http._tcp.local".to_string(),
                rtype: 1, // A — not a PTR
                rclass: 1,
                ttl: 120,
                data: DnsRdata::A(std::net::Ipv4Addr::new(10, 0, 0, 1)),
            }],
            authorities: Vec::new(),
            additionals: Vec::new(),
            rcode: DnsRcode::NoError,
            timestamp: Timestamp::default(),
            elapsed: None,
        };
        assert!(extract_services(&resp).is_empty());
    }

    #[test]
    fn well_known_device_service_matches_curated_list() {
        for svc in &["ipp", "airplay", "googlecast", "homekit", "smb", "ssh"] {
            let s = ServiceRecord {
                instance: "x".into(),
                service: (*svc).to_string(),
                protocol: "tcp".into(),
                ptr_target: "y".into(),
            };
            assert!(s.is_well_known_device_service(), "{svc} should match");
        }
    }

    #[test]
    fn well_known_device_service_misses_random_service() {
        let s = ServiceRecord {
            instance: "x".into(),
            service: "weird-vendor-service".into(),
            protocol: "tcp".into(),
            ptr_target: "y".into(),
        };
        assert!(!s.is_well_known_device_service());
    }
}
