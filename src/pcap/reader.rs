//! [`CaptureReader`] — classic pcap and pcapng, with link-type
//! normalisation. Available with the light `pcap-reader` feature
//! (only `pcap-file`); the `pcap` feature adds the flow sources on
//! top.

use std::borrow::Cow;
use std::fs::File;
use std::io::{BufRead, BufReader, Read};
use std::path::Path;
use std::time::Duration;

pub use pcap_file::DataLink;
use pcap_file::pcap::PcapReader;
use pcap_file::pcapng::PcapNgReader;
use pcap_file::pcapng::blocks::enhanced_packet::EnhancedPacketOption;
use pcap_file::pcapng::blocks::interface_description::InterfaceDescriptionOption;

use crate::error::{Error, Module};

/// On-disk capture format, detected from the file's magic number.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureFormat {
    /// Classic libpcap (any byte order, µs or ns resolution).
    Pcap,
    /// pcapng (Wireshark / dumpcap default).
    PcapNg,
}

/// Direction of a captured packet relative to the capturing host,
/// when the capture records it (pcapng EPB flags, Linux cooked
/// capture packet type). New in 0.25.0.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum CaptureDirection {
    /// Received by the host.
    Inbound,
    /// Sent by the host.
    Outbound,
}

/// One packet read from a capture file.
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct CapturedPacket {
    /// Capture timestamp since the Unix epoch. For pcapng, the
    /// interface's `if_tsresol` / `if_tsoffset` are applied.
    pub timestamp: Duration,
    /// Captured bytes (possibly truncated to the snap length), in
    /// the interface's link-layer format ([`Self::datalink`]); see
    /// [`Self::into_ethernet`].
    pub data: Vec<u8>,
    /// Length of the packet on the wire.
    pub original_len: u32,
    /// Link type of the interface the packet was captured on.
    pub datalink: DataLink,
    /// Direction, when the capture recorded it. New in 0.25.0.
    pub direction: Option<CaptureDirection>,
}

impl CapturedPacket {
    /// The packet as an Ethernet frame — what flowscope's extractors
    /// read. Ethernet frames are returned as-is; Linux cooked
    /// captures (`tcpdump -i any`: `LINUX_SLL`, `LINUX_SLL2`), raw IP
    /// (`RAW`, `IPV4`, `IPV6`) and BSD loopback (`NULL`, `LOOP`) get a
    /// synthetic Ethernet header (zero MACs, except the cooked
    /// source address). Other link types are returned as
    /// `Err(datalink)`. New in 0.25.0.
    pub fn into_ethernet(self) -> Result<Vec<u8>, DataLink> {
        match to_ethernet(self.datalink, &self.data) {
            Some(Cow::Borrowed(_)) => Ok(self.data),
            Some(Cow::Owned(frame)) => Ok(frame),
            None => Err(self.datalink),
        }
    }
}

const ETH_IPV4: u16 = 0x0800;
const ETH_IPV6: u16 = 0x86dd;

fn ethertype_of_ip(ip: &[u8]) -> Option<u16> {
    match ip.first()? >> 4 {
        4 => Some(ETH_IPV4),
        6 => Some(ETH_IPV6),
        _ => None,
    }
}

fn synth(src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&[0; 6]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// See [`CapturedPacket::into_ethernet`].
fn to_ethernet(datalink: DataLink, data: &[u8]) -> Option<Cow<'_, [u8]>> {
    match datalink {
        DataLink::ETHERNET => Some(Cow::Borrowed(data)),
        DataLink::LINUX_SLL => {
            // type(2) arphrd(2) addr_len(2) addr(8) protocol(2)
            let hdr = data.get(..16)?;
            let mut src = [0u8; 6];
            let alen = usize::from(u16::from_be_bytes([hdr[4], hdr[5]])).min(6);
            src[..alen].copy_from_slice(&hdr[6..6 + alen]);
            let proto = u16::from_be_bytes([hdr[14], hdr[15]]);
            Some(Cow::Owned(synth(src, proto, &data[16..])))
        }
        DataLink::LINUX_SLL2 => {
            // protocol(2) reserved(2) ifindex(4) arphrd(2) type(1)
            // addr_len(1) addr(8)
            let hdr = data.get(..20)?;
            let mut src = [0u8; 6];
            let alen = usize::from(hdr[11]).min(6);
            src[..alen].copy_from_slice(&hdr[12..12 + alen]);
            let proto = u16::from_be_bytes([hdr[0], hdr[1]]);
            Some(Cow::Owned(synth(src, proto, &data[20..])))
        }
        DataLink::RAW | DataLink::IPV4 | DataLink::IPV6 => {
            Some(Cow::Owned(synth([0; 6], ethertype_of_ip(data)?, data)))
        }
        DataLink::NULL | DataLink::LOOP => {
            // 4-byte address family (byte order varies); the IP
            // version nibble is authoritative.
            let ip = data.get(4..)?;
            Some(Cow::Owned(synth([0; 6], ethertype_of_ip(ip)?, ip)))
        }
        _ => None,
    }
}

/// Direction recorded by a Linux cooked header's packet type.
fn cooked_direction(datalink: DataLink, data: &[u8]) -> Option<CaptureDirection> {
    let packet_type = match datalink {
        DataLink::LINUX_SLL => u16::from_be_bytes([*data.first()?, *data.get(1)?]),
        DataLink::LINUX_SLL2 => u16::from(*data.get(10)?),
        _ => return None,
    };
    match packet_type {
        4 => Some(CaptureDirection::Outbound),
        0..=3 => Some(CaptureDirection::Inbound),
        _ => None,
    }
}

/// Per-interface state of a pcapng section.
#[derive(Debug, Clone, Copy)]
struct PcapNgInterface {
    datalink: DataLink,
    /// Timestamp units per second.
    units_per_sec: u64,
    /// `if_tsoffset`, seconds added to every timestamp.
    offset_secs: i64,
}

impl PcapNgInterface {
    /// Ticks → time since the epoch. Saturating: a hostile
    /// `if_tsoffset` or tick count cannot overflow.
    fn timestamp(&self, raw: u64) -> Duration {
        let units = self.units_per_sec.max(1);
        let secs = i128::from(raw / units) + i128::from(self.offset_secs);
        let secs = secs.clamp(0, i128::from(u64::MAX)) as u64;
        let frac = u128::from(raw % units);
        let nanos = (frac * 1_000_000_000 / u128::from(units)) as u32;
        Duration::new(secs, nanos)
    }
}

enum ReaderInner<R: Read> {
    Pcap(PcapReader<R>),
    PcapNg {
        reader: PcapNgReader<R>,
        interfaces: Vec<PcapNgInterface>,
    },
}

/// Reads classic pcap **and** pcapng, detecting the format from the
/// magic number.
///
/// pcapng timestamps honour each interface's `if_tsresol` (default
/// microseconds) and `if_tsoffset`; Enhanced and Simple Packet
/// Blocks are returned, every other block is skipped. The packet
/// direction comes from the EPB flags or a Linux cooked header.
pub struct CaptureReader<R: Read> {
    inner: ReaderInner<R>,
}

impl CaptureReader<BufReader<File>> {
    /// Open a capture file.
    pub fn open(path: impl AsRef<Path>) -> crate::Result<Self> {
        let file = File::open(path).map_err(|e| Error::io(Module::Pcap, e))?;
        Self::new(BufReader::new(file))
    }
}

impl<R: BufRead> CaptureReader<R> {
    /// Wrap a buffered reader positioned at the start of a capture.
    pub fn new(mut reader: R) -> crate::Result<Self> {
        let magic = {
            let buf = reader.fill_buf().map_err(|e| Error::io(Module::Pcap, e))?;
            let mut m = [0u8; 4];
            let n = buf.len().min(4);
            m[..n].copy_from_slice(&buf[..n]);
            (n == 4).then_some(u32::from_le_bytes(m))
        };
        let inner = match magic {
            Some(0x0a0d_0d0a) => ReaderInner::PcapNg {
                reader: PcapNgReader::new(reader)
                    .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcapng header", e))?,
                interfaces: Vec::new(),
            },
            _ => ReaderInner::Pcap(
                PcapReader::new(reader)
                    .map_err(|e| Error::parse_with(Module::Pcap, "invalid pcap header", e))?,
            ),
        };
        Ok(Self { inner })
    }
}

impl<R: Read> CaptureReader<R> {
    /// The detected format.
    pub fn format(&self) -> CaptureFormat {
        match self.inner {
            ReaderInner::Pcap(_) => CaptureFormat::Pcap,
            ReaderInner::PcapNg { .. } => CaptureFormat::PcapNg,
        }
    }

    /// Next packet, `None` at end of file.
    pub fn next_packet(&mut self) -> Option<crate::Result<CapturedPacket>> {
        match &mut self.inner {
            ReaderInner::Pcap(reader) => {
                let datalink = reader.header().datalink;
                Some(
                    reader
                        .next_packet()?
                        .map(|p| {
                            let data = p.data.into_owned();
                            CapturedPacket {
                                timestamp: p.timestamp,
                                original_len: p.orig_len,
                                direction: cooked_direction(datalink, &data),
                                data,
                                datalink,
                            }
                        })
                        .map_err(|e| Error::parse_with(Module::Pcap, "malformed pcap record", e)),
                )
            }
            ReaderInner::PcapNg { reader, interfaces } => {
                use pcap_file::pcapng::Block;
                loop {
                    let block = match reader.next_block()? {
                        Ok(b) => b,
                        Err(e) => {
                            return Some(Err(Error::parse_with(
                                Module::Pcap,
                                "malformed pcapng block",
                                e,
                            )));
                        }
                    };
                    match block {
                        Block::SectionHeader(_) => interfaces.clear(),
                        Block::InterfaceDescription(idb) => {
                            let mut iface = PcapNgInterface {
                                datalink: idb.linktype,
                                units_per_sec: 1_000_000,
                                offset_secs: 0,
                            };
                            for opt in &idb.options {
                                match opt {
                                    InterfaceDescriptionOption::IfTsResol(v) => {
                                        iface.units_per_sec = if v & 0x80 == 0 {
                                            10u64.checked_pow(u32::from(*v)).unwrap_or(u64::MAX)
                                        } else {
                                            1u64.checked_shl(u32::from(v & 0x7f))
                                                .unwrap_or(u64::MAX)
                                        };
                                    }
                                    InterfaceDescriptionOption::IfTsOffset(o) => {
                                        iface.offset_secs = *o as i64;
                                    }
                                    _ => {}
                                }
                            }
                            interfaces.push(iface);
                        }
                        Block::EnhancedPacket(epb) => {
                            // pcap-file hands back the raw 64-bit tick
                            // count as nanoseconds; rescale it with the
                            // interface's resolution.
                            let iface = interfaces
                                .get(epb.interface_id as usize)
                                .copied()
                                .unwrap_or(PcapNgInterface {
                                    datalink: DataLink::ETHERNET,
                                    units_per_sec: 1_000_000,
                                    offset_secs: 0,
                                });
                            let raw = u64::try_from(epb.timestamp.as_nanos()).unwrap_or(u64::MAX);
                            // EPB flags bits 0-1: 01 inbound, 10 outbound.
                            let flagged = epb.options.iter().find_map(|o| match o {
                                EnhancedPacketOption::Flags(f) => match f & 0b11 {
                                    1 => Some(CaptureDirection::Inbound),
                                    2 => Some(CaptureDirection::Outbound),
                                    _ => None,
                                },
                                _ => None,
                            });
                            let data = epb.data.into_owned();
                            let direction =
                                flagged.or_else(|| cooked_direction(iface.datalink, &data));
                            return Some(Ok(CapturedPacket {
                                timestamp: iface.timestamp(raw),
                                original_len: epb.original_len,
                                data,
                                datalink: iface.datalink,
                                direction,
                            }));
                        }
                        Block::SimplePacket(spb) => {
                            let datalink = interfaces
                                .first()
                                .map_or(DataLink::ETHERNET, |i| i.datalink);
                            let data = spb.data.into_owned();
                            return Some(Ok(CapturedPacket {
                                timestamp: Duration::ZERO,
                                original_len: spb.original_len,
                                direction: cooked_direction(datalink, &data),
                                data,
                                datalink,
                            }));
                        }
                        _ => {}
                    }
                }
            }
        }
    }
}

impl<R: Read> Iterator for CaptureReader<R> {
    type Item = crate::Result<CapturedPacket>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_packet()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn packet(datalink: DataLink, data: Vec<u8>) -> CapturedPacket {
        CapturedPacket {
            timestamp: Duration::ZERO,
            original_len: data.len() as u32,
            direction: cooked_direction(datalink, &data),
            data,
            datalink,
        }
    }

    const IPV4: [u8; 20] = [
        0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2,
    ];

    #[test]
    fn linux_sll_becomes_ethernet_with_direction() {
        let mut d = vec![0, 4, 0, 1, 0, 6, 1, 2, 3, 4, 5, 6, 0, 0, 0x08, 0x00];
        d.extend_from_slice(&IPV4);
        let p = packet(DataLink::LINUX_SLL, d);
        assert_eq!(p.direction, Some(CaptureDirection::Outbound));
        let f = p.into_ethernet().unwrap();
        assert_eq!(&f[6..12], &[1, 2, 3, 4, 5, 6]);
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(&f[14..], &IPV4);
    }

    #[test]
    fn linux_sll2_becomes_ethernet() {
        let mut d = vec![
            0x08, 0x00, 0, 0, 0, 0, 0, 2, 0, 1, 0, 6, 9, 9, 9, 9, 9, 9, 0, 0,
        ];
        d.extend_from_slice(&IPV4);
        let p = packet(DataLink::LINUX_SLL2, d);
        assert_eq!(p.direction, Some(CaptureDirection::Inbound));
        let f = p.into_ethernet().unwrap();
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        assert_eq!(&f[14..], &IPV4);
    }

    #[test]
    fn raw_and_null_become_ethernet() {
        let f = packet(DataLink::RAW, IPV4.to_vec())
            .into_ethernet()
            .unwrap();
        assert_eq!(&f[12..14], &[0x08, 0x00]);
        let mut d = vec![2, 0, 0, 0];
        d.extend_from_slice(&IPV4);
        let f = packet(DataLink::NULL, d).into_ethernet().unwrap();
        assert_eq!(&f[14..], &IPV4);
    }

    #[test]
    fn unsupported_link_types_are_reported() {
        let p = packet(DataLink::IEEE802_11, vec![0; 30]);
        assert_eq!(p.into_ethernet(), Err(DataLink::IEEE802_11));
    }

    #[test]
    fn hostile_timestamp_offset_saturates() {
        let iface = PcapNgInterface {
            datalink: DataLink::ETHERNET,
            units_per_sec: 1,
            offset_secs: i64::MAX,
        };
        assert_eq!(iface.timestamp(u64::MAX).as_secs(), u64::MAX);
        let iface = PcapNgInterface {
            offset_secs: i64::MIN,
            ..iface
        };
        assert_eq!(iface.timestamp(5).as_secs(), 0);
    }
}
