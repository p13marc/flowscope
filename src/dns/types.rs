use std::{
    net::{Ipv4Addr, Ipv6Addr},
    time::Duration,
};

use bytes::Bytes;
use smallvec::SmallVec;

use crate::Timestamp;

/// Parsed DNS query observed on the wire.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnsQuery {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub timestamp: Timestamp,
}

/// Parsed DNS response.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnsResponse {
    pub transaction_id: u16,
    pub flags: DnsFlags,
    pub questions: Vec<DnsQuestion>,
    pub answers: Vec<DnsRecord>,
    pub authorities: Vec<DnsRecord>,
    pub additionals: Vec<DnsRecord>,
    pub rcode: DnsRcode,
    pub timestamp: Timestamp,
    /// Time elapsed since the matching query (if seen). `None` for
    /// orphan responses (no matching query in the correlator), or
    /// when running without a correlator.
    pub elapsed: Option<Duration>,
}

#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnsQuestion {
    pub name: String,
    pub qtype: u16,
    pub qclass: u16,
}

impl DnsQuestion {
    /// Construct a DNS question.
    pub fn new(name: impl Into<String>, qtype: u16, qclass: u16) -> Self {
        Self {
            name: name.into(),
            qtype,
            qclass,
        }
    }
}

impl DnsQuery {
    /// Construct a DNS query event.
    pub fn new(
        transaction_id: u16,
        flags: DnsFlags,
        questions: Vec<DnsQuestion>,
        timestamp: Timestamp,
    ) -> Self {
        Self {
            transaction_id,
            flags,
            questions,
            timestamp,
        }
    }
}

#[allow(clippy::too_many_arguments)]
impl DnsResponse {
    /// Construct a DNS response event.
    pub fn new(
        transaction_id: u16,
        flags: DnsFlags,
        questions: Vec<DnsQuestion>,
        answers: Vec<DnsRecord>,
        authorities: Vec<DnsRecord>,
        additionals: Vec<DnsRecord>,
        rcode: DnsRcode,
        timestamp: Timestamp,
        elapsed: Option<Duration>,
    ) -> Self {
        Self {
            transaction_id,
            flags,
            questions,
            answers,
            authorities,
            additionals,
            rcode,
            timestamp,
            elapsed,
        }
    }
}

/// One DNS resource record.
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct DnsRecord {
    pub name: String,
    pub rtype: u16,
    pub rclass: u16,
    pub ttl: u32,
    pub data: DnsRdata,
}

impl DnsRecord {
    /// Construct a DNS resource record.
    pub fn new(name: impl Into<String>, rtype: u16, rclass: u16, ttl: u32, data: DnsRdata) -> Self {
        Self {
            name: name.into(),
            rtype,
            rclass,
            ttl,
            data,
        }
    }
}

/// Decoded record data for the common types we can render simply.
/// Everything else lands in [`DnsRdata::Other`].
#[derive(Debug, Clone)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "rtype", content = "data", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DnsRdata {
    A(Ipv4Addr),
    AAAA(Ipv6Addr),
    CNAME(String),
    NS(String),
    PTR(String),
    MX {
        priority: u16,
        exchange: String,
    },
    /// One `Bytes` per TXT string segment. `SmallVec` inline
    /// capacity 4 covers the modal case (1-4 strings per TXT
    /// record); 5+ strings spill to the heap.
    ///
    /// Plan 120: was `Vec<Vec<u8>>` in 0.10.
    TXT(#[cfg_attr(feature = "serde", serde(with = "serde_smallvec_bytes"))] SmallVec<[Bytes; 4]>),
    /// Unparsed: raw bytes, with the original record type code.
    /// Useful for record types we don't decode (SOA, SRV, OPT,
    /// SVCB, HTTPS, DNSKEY, RRSIG, …).
    Other {
        rtype: u16,
        /// Plan 120: was `Vec<u8>` in 0.10.
        data: Bytes,
    },
}

#[cfg(feature = "serde")]
mod serde_smallvec_bytes {
    use bytes::Bytes;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use smallvec::SmallVec;

    pub fn serialize<S>(v: &SmallVec<[Bytes; 4]>, ser: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let view: Vec<&[u8]> = v.iter().map(|b| b.as_ref()).collect();
        view.serialize(ser)
    }

    pub fn deserialize<'de, D>(de: D) -> Result<SmallVec<[Bytes; 4]>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let v: Vec<Vec<u8>> = Vec::deserialize(de)?;
        Ok(v.into_iter().map(Bytes::from).collect())
    }
}

/// DNS response code (RFC 1035 §4.1.1, RFC 6895 for extended codes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(
    feature = "serde",
    serde(tag = "kind", content = "value", rename_all = "snake_case")
)]
#[non_exhaustive]
pub enum DnsRcode {
    NoError,
    FormErr,
    ServFail,
    NXDomain,
    NotImpl,
    Refused,
    YXDomain,
    YXRRSet,
    NXRRSet,
    NotAuth,
    NotZone,
    Other(u8),
}

impl DnsRcode {
    pub fn from_raw(v: u8) -> Self {
        match v {
            0 => Self::NoError,
            1 => Self::FormErr,
            2 => Self::ServFail,
            3 => Self::NXDomain,
            4 => Self::NotImpl,
            5 => Self::Refused,
            6 => Self::YXDomain,
            7 => Self::YXRRSet,
            8 => Self::NXRRSet,
            9 => Self::NotAuth,
            10 => Self::NotZone,
            other => Self::Other(other),
        }
    }
}

/// Flag/header bits from the DNS message header word.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
pub struct DnsFlags(pub u16);

impl DnsFlags {
    pub fn is_response(&self) -> bool {
        self.0 & 0x8000 != 0
    }
    pub fn is_authoritative(&self) -> bool {
        self.0 & 0x0400 != 0
    }
    pub fn is_truncated(&self) -> bool {
        self.0 & 0x0200 != 0
    }
    pub fn is_recursion_desired(&self) -> bool {
        self.0 & 0x0100 != 0
    }
    pub fn is_recursion_available(&self) -> bool {
        self.0 & 0x0080 != 0
    }
    /// 4-bit opcode field (RFC 1035 §4.1.1).
    pub fn opcode(&self) -> u8 {
        ((self.0 >> 11) & 0x0F) as u8
    }
    /// 4-bit RCODE field.
    pub fn rcode_raw(&self) -> u8 {
        (self.0 & 0x000F) as u8
    }
}

/// Tunables for DNS query/response correlation
/// ([`crate::dns::Correlator`], [`crate::dns::DnsUdpParser::with_config`]).
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct DnsConfig {
    /// How long to wait for a response before flagging as unanswered.
    /// Default: 30 s.
    pub query_timeout: Duration,
    /// Cap on pending queries in the correlator. Beyond this, oldest
    /// pending entries are dropped. Default: 10 000.
    pub max_pending: usize,
}

impl Default for DnsConfig {
    fn default() -> Self {
        Self {
            query_timeout: Duration::from_secs(30),
            max_pending: 10_000,
        }
    }
}
