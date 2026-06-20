//! TCP/IP passive fingerprint extraction.

use bitflags::bitflags;

use crate::layers::{Layers, TcpOption, TcpSlice};

/// Whether the fingerprint came from a SYN (client) or a
/// SYN-ACK (server). p0f-3 splits its DB by direction because
/// stacks emit slightly different defaults each way.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[cfg_attr(feature = "serde", serde(tag = "kind", rename_all = "snake_case"))]
#[non_exhaustive]
pub enum TcpDirection {
    /// SYN (no ACK) — client offering.
    Syn,
    /// SYN+ACK — server responding.
    SynAck,
}

impl TcpDirection {
    /// p0f-3 direction marker (`request` / `response`).
    pub fn as_str(self) -> &'static str {
        match self {
            TcpDirection::Syn => "request",
            TcpDirection::SynAck => "response",
        }
    }
}

bitflags! {
    /// p0f-3 quirk bits. Each bit fires when its named TCP/IP
    /// header deviation is present.
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct Quirks: u32 {  // NOTE: serde impl below — bitflags can't auto-derive.
        /// IPv4 Don't-Fragment bit set.
        const DF                  = 1 << 0;
        /// Non-zero IPv4 identification with DF=1 — atypical.
        const ID_NONZERO_WITH_DF  = 1 << 1;
        /// Zero IPv4 identification with DF=0 — atypical.
        const ID_ZERO_NO_DF       = 1 << 2;
        /// ECE / CWR / ECN flags set in the SYN.
        const ECN                 = 1 << 3;
        /// Reserved bits / NS flag set.
        const RESERVED_FLAGS      = 1 << 4;
        /// Initial sequence number is zero.
        const SEQ_ZERO            = 1 << 5;
        /// Non-zero ACK number on a pure SYN.
        const ACK_NONZERO_ON_SYN  = 1 << 6;
        /// Non-zero urgent pointer without URG flag set.
        const URG_PTR_NONZERO     = 1 << 7;
        /// URG flag set on a SYN — uncommon.
        const URG_FLAG_ON_SYN     = 1 << 8;
        /// PSH flag set on a SYN — uncommon.
        const PSH_FLAG_ON_SYN     = 1 << 9;
        /// Trailing option padding contained a non-NOP byte.
        const OPT_TRAILING_NONZERO = 1 << 10;
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for Quirks {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u32(self.bits())
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for Quirks {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let bits = <u32 as serde::Deserialize>::deserialize(deserializer)?;
        Ok(Quirks::from_bits_truncate(bits))
    }
}

/// One passive TCP/IP fingerprint capture.
///
/// Pre-formatted accessors stay in plain types so consumers can
/// match / index without parsing the p0f signature string.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize, serde::Deserialize))]
#[non_exhaustive]
pub struct TcpFingerprint {
    /// Whether this is the client's SYN or the server's SYN+ACK.
    pub direction: TcpDirection,
    /// IP version (4 or 6).
    pub ip_version: u8,
    /// Observed TTL / hop-limit on the wire.
    pub observed_ttl: u8,
    /// p0f-3 guessed initial TTL — observed_ttl rounded up to
    /// the next of {32, 64, 128, 255}. The number of hops the
    /// packet traversed is `guessed - observed`.
    pub guessed_initial_ttl: u8,
    /// Length of TCP options in bytes (post fixed 20-byte
    /// header). 0 when no options.
    pub options_length: u8,
    /// IPv4 Don't-Fragment bit (`false` for IPv6 — DF doesn't
    /// exist there).
    pub df: bool,
    /// TCP advertised window size.
    pub window_size: u16,
    /// MSS from option 2 if present.
    pub mss: Option<u16>,
    /// Window-scale shift from option 3 if present.
    pub window_scale: Option<u8>,
    /// SACK-Permitted (option 4) was sent.
    pub sack_permitted: bool,
    /// TCP timestamps (option 8) were sent.
    pub timestamps: bool,
    /// Compact p0f-3 option layout — comma-separated tokens
    /// preserving wire order. Tokens: `mss`, `nop`, `ws`,
    /// `sok`, `sack`, `ts`, `eol+N` (N pad bytes after EOL),
    /// `?KIND` for unknown kinds.
    pub option_layout: String,
    /// Quirk bits — see [`Quirks`].
    pub quirks: Quirks,
}

impl TcpFingerprint {
    /// Format as a p0f-3 signature string:
    /// `ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass`.
    ///
    /// - `ver` = 4 or 6.
    /// - `ittl` = guessed initial TTL.
    /// - `olen` = options length in bytes.
    /// - `mss` = MSS, or `*` when absent.
    /// - `wsize` = literal window when scale present, else `*`.
    /// - `scale` = window-scale shift, or `*` when absent.
    /// - `olayout` = comma-separated option-token list.
    /// - `quirks` = comma-separated quirk slugs.
    /// - `pclass` = `0` (SYN has no payload by definition).
    pub fn to_p0f_signature(&self) -> String {
        let mss = self
            .mss
            .map(|m| m.to_string())
            .unwrap_or_else(|| "*".into());
        let ws = self
            .window_scale
            .map(|w| w.to_string())
            .unwrap_or_else(|| "*".into());
        let mut quirks: Vec<&'static str> = Vec::new();
        if self.quirks.contains(Quirks::DF) {
            quirks.push("df");
        }
        if self.quirks.contains(Quirks::ID_NONZERO_WITH_DF) {
            quirks.push("id+");
        }
        if self.quirks.contains(Quirks::ID_ZERO_NO_DF) {
            quirks.push("id-");
        }
        if self.quirks.contains(Quirks::ECN) {
            quirks.push("ecn");
        }
        if self.quirks.contains(Quirks::RESERVED_FLAGS) {
            quirks.push("0+");
        }
        if self.quirks.contains(Quirks::SEQ_ZERO) {
            quirks.push("seq-");
        }
        if self.quirks.contains(Quirks::ACK_NONZERO_ON_SYN) {
            quirks.push("ack+");
        }
        if self.quirks.contains(Quirks::URG_PTR_NONZERO) {
            quirks.push("uptr+");
        }
        if self.quirks.contains(Quirks::URG_FLAG_ON_SYN) {
            quirks.push("urgf+");
        }
        if self.quirks.contains(Quirks::PSH_FLAG_ON_SYN) {
            quirks.push("pushf+");
        }
        if self.quirks.contains(Quirks::OPT_TRAILING_NONZERO) {
            quirks.push("opt+");
        }
        format!(
            "{}:{}:{}:{}:{},{}:{}:{}:0",
            self.ip_version,
            self.guessed_initial_ttl,
            self.options_length,
            mss,
            self.window_size,
            ws,
            self.option_layout,
            quirks.join(","),
        )
    }
}

/// Round `observed` up to the next of {32, 64, 128, 255} — the
/// p0f-3 "guessed initial TTL" heuristic. 32 is unusual and
/// covers some embedded stacks; 64 is Linux / macOS / BSD;
/// 128 is Windows; 255 is Solaris / Cisco IOS / routers.
pub fn guess_initial_ttl(observed: u8) -> u8 {
    match observed {
        0..=32 => 32,
        33..=64 => 64,
        65..=128 => 128,
        _ => 255,
    }
}

/// Try to extract a passive TCP/IP fingerprint from a parsed
/// per-packet view.
///
/// Returns `None` unless the packet contains:
/// - An IPv4 or IPv6 header, *and*
/// - A TCP header with either `SYN` set (with or without ACK),
///   *and*
/// - No other flags that would make it a non-SYN handshake
///   packet (RST / FIN).
pub fn fingerprint_from_layers(layers: &Layers) -> Option<TcpFingerprint> {
    let tcp = *layers.tcp()?;
    let flags = tcp.flags();
    if !flags.syn || flags.rst || flags.fin {
        return None;
    }
    let direction = if flags.ack {
        TcpDirection::SynAck
    } else {
        TcpDirection::Syn
    };

    let (ip_version, observed_ttl, df, ip_id_nonzero) = if let Some(v4) = layers.ipv4() {
        (4u8, v4.ttl(), v4.df(), v4.identification() != 0)
    } else {
        let v6 = layers.ipv6()?;
        (6u8, v6.hop_limit(), false, false)
    };

    let mut quirks = Quirks::empty();

    // IP-layer quirks.
    if df {
        quirks.insert(Quirks::DF);
    }
    if ip_version == 4 {
        if df && ip_id_nonzero {
            quirks.insert(Quirks::ID_NONZERO_WITH_DF);
        }
        if !df && !ip_id_nonzero {
            quirks.insert(Quirks::ID_ZERO_NO_DF);
        }
    }

    // TCP-layer quirks.
    if flags.ece || flags.cwr {
        quirks.insert(Quirks::ECN);
    }
    if flags.ns {
        quirks.insert(Quirks::RESERVED_FLAGS);
    }
    if tcp.seq() == 0 {
        quirks.insert(Quirks::SEQ_ZERO);
    }
    if direction == TcpDirection::Syn && tcp.ack() != 0 {
        quirks.insert(Quirks::ACK_NONZERO_ON_SYN);
    }
    if tcp.urgent_pointer() != 0 && !flags.urg {
        quirks.insert(Quirks::URG_PTR_NONZERO);
    }
    if flags.urg {
        quirks.insert(Quirks::URG_FLAG_ON_SYN);
    }
    if flags.psh {
        quirks.insert(Quirks::PSH_FLAG_ON_SYN);
    }

    let (option_layout, mss, window_scale, sack_permitted, timestamps, options_length, opt_quirks) =
        walk_options(tcp);
    quirks |= opt_quirks;

    Some(TcpFingerprint {
        direction,
        ip_version,
        observed_ttl,
        guessed_initial_ttl: guess_initial_ttl(observed_ttl),
        options_length,
        df,
        window_size: tcp.window(),
        mss,
        window_scale,
        sack_permitted,
        timestamps,
        option_layout,
        quirks,
    })
}

fn walk_options(tcp: TcpSlice<'_>) -> (String, Option<u16>, Option<u8>, bool, bool, u8, Quirks) {
    let mut layout = String::new();
    let mut mss = None;
    let mut window_scale = None;
    let mut sack_permitted = false;
    let mut timestamps = false;
    let mut quirks = Quirks::empty();
    let mut hit_eol = false;
    let mut nonzero_after_eol = false;
    let mut options_length = 0u32;

    let push = |layout: &mut String, token: &str| {
        if !layout.is_empty() {
            layout.push(',');
        }
        layout.push_str(token);
    };

    let header = tcp.header();
    if header.len() > 20 {
        options_length = (header.len() - 20) as u32;
    }

    for opt in tcp.options() {
        match opt {
            TcpOption::EndOfList => {
                push(&mut layout, "eol");
                hit_eol = true;
            }
            TcpOption::Nop => {
                push(&mut layout, "nop");
            }
            TcpOption::Mss(m) => {
                push(&mut layout, "mss");
                mss = Some(m);
            }
            TcpOption::WindowScale(w) => {
                push(&mut layout, "ws");
                window_scale = Some(w);
            }
            TcpOption::SackPermitted => {
                push(&mut layout, "sok");
                sack_permitted = true;
            }
            TcpOption::Sack(_) => {
                push(&mut layout, "sack");
            }
            TcpOption::Timestamp { .. } => {
                push(&mut layout, "ts");
                timestamps = true;
            }
            TcpOption::Unknown { kind, .. } => {
                push(&mut layout, &format!("?{kind}"));
            }
        }
        if hit_eol {
            // p0f-3 records the bytes after EOL — if any are
            // non-zero, set the `opt+` quirk.
            // The TcpOption iterator only yields parsed options;
            // we don't see raw bytes past EOL. Caller-side
            // inspection is the only way — scan the header tail
            // for non-zero bytes after the EOL byte.
            nonzero_after_eol |= header_tail_nonzero(header);
            break;
        }
    }

    if nonzero_after_eol {
        quirks.insert(Quirks::OPT_TRAILING_NONZERO);
    }

    (
        layout,
        mss,
        window_scale,
        sack_permitted,
        timestamps,
        options_length.min(u8::MAX as u32) as u8,
        quirks,
    )
}

/// Heuristic: after the EOL byte in the TCP options region,
/// any non-zero byte before the end of the header sets the
/// `opt+` quirk.
fn header_tail_nonzero(header: &[u8]) -> bool {
    // Find the EOL byte (kind=0) in the options region (bytes
    // 20..header_len). Anything non-zero past that — pad bytes
    // are supposed to be zero per RFC 793.
    if header.len() <= 20 {
        return false;
    }
    let opts = &header[20..];
    if let Some(eol_pos) = opts.iter().position(|&b| b == 0) {
        opts[eol_pos + 1..].iter().any(|&b| b != 0)
    } else {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn guess_initial_ttl_bins() {
        assert_eq!(guess_initial_ttl(1), 32);
        assert_eq!(guess_initial_ttl(32), 32);
        assert_eq!(guess_initial_ttl(33), 64);
        assert_eq!(guess_initial_ttl(64), 64);
        assert_eq!(guess_initial_ttl(65), 128);
        assert_eq!(guess_initial_ttl(128), 128);
        assert_eq!(guess_initial_ttl(129), 255);
        assert_eq!(guess_initial_ttl(255), 255);
    }

    fn build_syn_ipv4(ttl: u8, df: bool, win: u16, options: &[u8]) -> Vec<u8> {
        let tcp_header_len = 20 + options.len();
        let total_len = 20 + tcp_header_len;
        let mut p = Vec::with_capacity(total_len);
        // IPv4 header: 20 bytes, version=4, IHL=5.
        p.push(0x45);
        p.push(0x00);
        p.extend_from_slice(&(total_len as u16).to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // identification
        let flags_frag = if df { 0x4000u16 } else { 0u16 };
        p.extend_from_slice(&flags_frag.to_be_bytes());
        p.push(ttl);
        p.push(6); // TCP
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p.extend_from_slice(&[192, 0, 2, 1]); // src
        p.extend_from_slice(&[192, 0, 2, 2]); // dst
        // TCP header.
        p.extend_from_slice(&12345u16.to_be_bytes()); // sport
        p.extend_from_slice(&80u16.to_be_bytes()); // dport
        p.extend_from_slice(&0u32.to_be_bytes()); // seq
        p.extend_from_slice(&0u32.to_be_bytes()); // ack
        let doff = (tcp_header_len / 4) as u8;
        p.push(doff << 4); // data offset + reserved
        p.push(0x02); // SYN flag
        p.extend_from_slice(&win.to_be_bytes());
        p.extend_from_slice(&[0x00, 0x00]); // checksum
        p.extend_from_slice(&[0x00, 0x00]); // urg ptr
        p.extend_from_slice(options);
        p
    }

    fn linux_syn_options() -> Vec<u8> {
        // mss, sack-perm, ts, nop, ws — a typical Linux SYN.
        // Pad to 4-byte boundary.
        // mss=1460 (4B) + sok (2B) + ts (10B) + nop (1B) + ws=7 (3B) = 20B.
        let mut o = Vec::new();
        o.extend_from_slice(&[2, 4, 0x05, 0xb4]); // MSS 1460
        o.extend_from_slice(&[4, 2]); // SACK permitted
        o.extend_from_slice(&[8, 10, 0, 0, 0, 1, 0, 0, 0, 0]); // TS
        o.push(1); // NOP
        o.extend_from_slice(&[3, 3, 7]); // WS = 7
        o
    }

    #[test]
    fn extracts_typical_linux_syn() {
        let pkt = build_syn_ipv4(64, true, 29200, &linux_syn_options());
        let layers = Layers::parse_ip(&pkt).unwrap();
        let fp = fingerprint_from_layers(&layers).unwrap();
        assert_eq!(fp.direction, TcpDirection::Syn);
        assert_eq!(fp.ip_version, 4);
        assert_eq!(fp.observed_ttl, 64);
        assert_eq!(fp.guessed_initial_ttl, 64);
        assert!(fp.df);
        assert!(fp.quirks.contains(Quirks::DF));
        assert_eq!(fp.mss, Some(1460));
        assert_eq!(fp.window_scale, Some(7));
        assert!(fp.sack_permitted);
        assert!(fp.timestamps);
        assert_eq!(fp.window_size, 29200);
        assert_eq!(fp.option_layout, "mss,sok,ts,nop,ws");
        assert_eq!(fp.options_length, 20);
        // Trailing zero padding — no opt+.
        assert!(!fp.quirks.contains(Quirks::OPT_TRAILING_NONZERO));
    }

    #[test]
    fn p0f_signature_format() {
        let pkt = build_syn_ipv4(128, true, 8192, &[2, 4, 0x05, 0xb4]);
        let layers = Layers::parse_ip(&pkt).unwrap();
        let fp = fingerprint_from_layers(&layers).unwrap();
        // ver:ittl:olen:mss:wsize,scale:olayout:quirks:pclass
        // version=4, ittl=128, olen=4 (just MSS), mss=1460,
        // wsize=8192, scale=*, olayout=mss. Quirks: df (DF=1) +
        // seq- (our test builder uses seq=0).
        let sig = fp.to_p0f_signature();
        assert_eq!(sig, "4:128:4:1460:8192,*:mss:df,seq-:0");
    }

    #[test]
    fn syn_ack_detected_when_ack_flag_set() {
        let mut pkt = build_syn_ipv4(64, true, 1024, &[]);
        // Flip the TCP flag byte from 0x02 (SYN) to 0x12 (SYN+ACK).
        // IP header is 20 bytes; TCP flags lo is at offset 20+13.
        pkt[33] = 0x12;
        let layers = Layers::parse_ip(&pkt).unwrap();
        let fp = fingerprint_from_layers(&layers).unwrap();
        assert_eq!(fp.direction, TcpDirection::SynAck);
    }

    #[test]
    fn returns_none_for_non_syn() {
        let mut pkt = build_syn_ipv4(64, true, 1024, &[]);
        // Clear the SYN flag — pure ACK.
        pkt[33] = 0x10;
        let layers = Layers::parse_ip(&pkt).unwrap();
        assert!(fingerprint_from_layers(&layers).is_none());
    }

    #[test]
    fn returns_none_for_syn_with_rst() {
        let mut pkt = build_syn_ipv4(64, true, 1024, &[]);
        // SYN + RST — bad packet, not a fingerprint candidate.
        pkt[33] = 0x06;
        let layers = Layers::parse_ip(&pkt).unwrap();
        assert!(fingerprint_from_layers(&layers).is_none());
    }

    #[test]
    fn windows_style_high_ttl_classified_to_128() {
        let pkt = build_syn_ipv4(120, true, 8192, &[2, 4, 0x05, 0xb4]);
        let layers = Layers::parse_ip(&pkt).unwrap();
        let fp = fingerprint_from_layers(&layers).unwrap();
        assert_eq!(fp.guessed_initial_ttl, 128);
    }

    #[test]
    fn router_style_ttl_255_classified_to_255() {
        let pkt = build_syn_ipv4(254, true, 8192, &[]);
        let layers = Layers::parse_ip(&pkt).unwrap();
        let fp = fingerprint_from_layers(&layers).unwrap();
        assert_eq!(fp.guessed_initial_ttl, 255);
    }
}
