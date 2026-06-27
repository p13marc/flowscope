// SPDX-License-Identifier: LicenseRef-FoxIO-1.1
//
// JA4T / JA4TS are part of the JA4+ suite, (c) FoxIO, LLC, licensed under the
// FoxIO License 1.1 (see LICENSE-FoxIO-1.1 and NOTICE at the crate root) — NOT
// under flowscope's MIT/Apache-2.0 terms. JA4+ methods are patent pending.
// "JA4+" is a trademark of FoxIO, LLC. This file compiles only under the opt-in
// `ja4plus` feature; commercial use requires a FoxIO OEM license.

//! JA4T / JA4TS passive TCP fingerprint (FoxIO).
//!
//! A fingerprint of a host's TCP stack from a single SYN (JA4T, client) or
//! SYN-ACK (JA4TS, server). The license-clean p0f-style
//! [`TcpFingerprint`](super::TcpFingerprint) is the alternative for users who
//! can't accept the FoxIO terms; this is the JA4+-format variant for cross-tool
//! parity with Zeek / Suricata / Wireshark JA4T output.
//!
//! Format (FoxIO): `{window_size}_{option_kinds}_{mss}_{window_scale}`
//!
//! - `window_size` — the SYN/SYN-ACK advertised window, decimal.
//! - `option_kinds` — every TCP option kind in wire order, hyphen-joined
//!   (`2-1-3-1-1-4`), stopping at the End-of-Options marker (kind 0, not
//!   included). NOPs (kind 1) **are** included. `00` if there are no options.
//! - `mss` — the MSS option (kind 2) value, or `00` if absent.
//! - `window_scale` — the window-scale option (kind 3) shift, or `00` if absent.
//!
//! Reference: FoxIO `zeek/ja4t/main.zeek`. Golden vectors below are taken from
//! FoxIO's own Zeek test baselines.

use crate::layers::{TcpOption, TcpSlice};

/// Decomposed JA4T pieces, before assembly into the underscore-joined string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Ja4tParts {
    /// Advertised TCP window size.
    pub window: u16,
    /// TCP option kinds in wire order (End-of-Options excluded).
    pub option_kinds: Vec<u8>,
    /// MSS option value, `0` if absent.
    pub mss: u16,
    /// Window-scale shift, `0` if absent.
    pub window_scale: u8,
}

impl std::fmt::Display for Ja4tParts {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // option list, hyphen-joined, or "00" when empty
        let opts = if self.option_kinds.is_empty() {
            "00".to_string()
        } else {
            self.option_kinds
                .iter()
                .map(|k| k.to_string())
                .collect::<Vec<_>>()
                .join("-")
        };
        // MSS: zero-padded to 2 (so absent → "00", 1460 → "1460").
        // window scale: "00" when absent (0), else decimal.
        let ws = if self.window_scale == 0 {
            "00".to_string()
        } else {
            self.window_scale.to_string()
        };
        write!(f, "{}_{}_{:02}_{}", self.window, opts, self.mss, ws)
    }
}

/// Build a [`Ja4tParts`] from explicit fields (the SYN window, the ordered
/// option-kind list, the MSS, and the window-scale shift). Use this when you
/// have already parsed the SYN/SYN-ACK; [`ja4t_from_tcp`] does the parsing for
/// you from a [`TcpSlice`].
pub fn ja4t_from_parts(window: u16, option_kinds: &[u8], mss: u16, window_scale: u8) -> Ja4tParts {
    Ja4tParts {
        window,
        option_kinds: option_kinds.to_vec(),
        mss,
        window_scale,
    }
}

/// The numeric TCP option kind for a parsed [`TcpOption`], or `None` for the
/// End-of-Options marker (the signal to stop collecting, matching the FoxIO
/// reference which breaks on kind 0 without recording it).
fn option_kind(opt: &TcpOption<'_>) -> Option<u8> {
    Some(match opt {
        TcpOption::EndOfList => return None,
        TcpOption::Nop => 1,
        TcpOption::Mss(_) => 2,
        TcpOption::WindowScale(_) => 3,
        TcpOption::SackPermitted => 4,
        TcpOption::Sack(_) => 5,
        TcpOption::Timestamp { .. } => 8,
        TcpOption::Unknown { kind, .. } => *kind,
    })
}

/// Parse JA4T parts directly from a TCP header [`TcpSlice`] (typically the SYN
/// for JA4T or the SYN-ACK for JA4TS). The same formatter applies to both — the
/// distinction is purely which packet you pass.
pub fn ja4t_from_tcp(tcp: &TcpSlice<'_>) -> Ja4tParts {
    let mut kinds = Vec::new();
    let mut mss = 0u16;
    let mut window_scale = 0u8;
    for opt in tcp.options() {
        match opt {
            TcpOption::Mss(v) => mss = v,
            TcpOption::WindowScale(v) => window_scale = v,
            _ => {}
        }
        match option_kind(&opt) {
            Some(k) => kinds.push(k),
            None => break, // End-of-Options
        }
    }
    Ja4tParts {
        window: tcp.window(),
        option_kinds: kinds,
        mss,
        window_scale,
    }
}

/// Compute the JA4T (or JA4TS) string directly from a [`TcpSlice`].
pub fn ja4t(tcp: &TcpSlice<'_>) -> String {
    ja4t_from_tcp(tcp).to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    // Golden vectors from FoxIO's Zeek test baselines
    // (zeek/tests/Traces/Scripts.ja4-conn*/conn.log).

    #[test]
    fn golden_windows_syn() {
        // ja4t = 64240_2-1-3-1-1-4_1460_8
        let p = ja4t_from_parts(64240, &[2, 1, 3, 1, 1, 4], 1460, 8);
        assert_eq!(p.to_string(), "64240_2-1-3-1-1-4_1460_8");
    }

    #[test]
    fn golden_linux_syn_with_timestamps() {
        // ja4t = 65535_2-1-3-1-1-8-4_1440_6
        let p = ja4t_from_parts(65535, &[2, 1, 3, 1, 1, 8, 4], 1440, 6);
        assert_eq!(p.to_string(), "65535_2-1-3-1-1-8-4_1440_6");
    }

    #[test]
    fn golden_no_options() {
        // ja4t = 65535_00_00_00 (IPv6 flow, no TCP options observed)
        let p = ja4t_from_parts(65535, &[], 0, 0);
        assert_eq!(p.to_string(), "65535_00_00_00");
    }

    #[test]
    fn golden_synack_ja4ts() {
        // ja4ts = 64240_2-1-1-4-1-3_1460_7 — same formatter, SYN-ACK packet.
        let p = ja4t_from_parts(64240, &[2, 1, 1, 4, 1, 3], 1460, 7);
        assert_eq!(p.to_string(), "64240_2-1-1-4-1-3_1460_7");
        // and the QUIC-conn JA4TS: 64704_2-4-8-1-3_1360_13
        let p2 = ja4t_from_parts(64704, &[2, 4, 8, 1, 3], 1360, 13);
        assert_eq!(p2.to_string(), "64704_2-4-8-1-3_1360_13");
    }

    #[test]
    fn option_kind_mapping() {
        assert_eq!(option_kind(&TcpOption::Nop), Some(1));
        assert_eq!(option_kind(&TcpOption::Mss(1460)), Some(2));
        assert_eq!(option_kind(&TcpOption::WindowScale(8)), Some(3));
        assert_eq!(option_kind(&TcpOption::SackPermitted), Some(4));
        assert_eq!(option_kind(&TcpOption::Sack(&[])), Some(5));
        assert_eq!(
            option_kind(&TcpOption::Timestamp { tsval: 0, tsecr: 0 }),
            Some(8)
        );
        assert_eq!(
            option_kind(&TcpOption::Unknown {
                kind: 34,
                data: &[]
            }),
            Some(34)
        );
        assert_eq!(option_kind(&TcpOption::EndOfList), None); // stops collection
    }

    #[test]
    fn from_tcp_parses_a_real_syn() {
        // Hand-build a TCP header with options: MSS=1460, SACK-perm, TS,
        // NOP, WindowScale=7 — a typical Linux SYN. Then parse via the
        // layers TcpSlice and check the JA4T.
        // Base 20-byte header: src 1234, dst 80, seq/ack 0, data-offset
        // accounts for 20 options bytes (header len = 40 → offset 10).
        let mut hdr = vec![
            0x04, 0xd2, // src port 1234
            0x00, 0x50, // dst port 80
            0, 0, 0, 0, // seq
            0, 0, 0, 0, // ack
            0xa0, 0x02, // data offset 10 (40 bytes), flags SYN
            0xfa, 0xf0, // window 64240
            0, 0, // checksum
            0, 0, // urgent
        ];
        // Options (20 bytes): MSS 1460, SACK-perm, Timestamps(10), NOP, WScale 7
        hdr.extend_from_slice(&[
            2, 4, 0x05, 0xb4, // MSS 1460
            4, 2, // SACK permitted
            8, 10, 0, 0, 0, 0, 0, 0, 0, 0, // Timestamps (kind 8, len 10)
            1, // NOP
            3, 3, 7, // Window scale 7
        ]);
        // Header is 40 bytes (20 base + 20 options).
        let tcp = crate::layers::TcpSlice::new(&hdr, 40);
        let p = ja4t_from_tcp(&tcp);
        assert_eq!(p.window, 64240);
        assert_eq!(p.mss, 1460);
        assert_eq!(p.window_scale, 7);
        assert_eq!(p.option_kinds, vec![2, 4, 8, 1, 3]);
        assert_eq!(p.to_string(), "64240_2-4-8-1-3_1460_7");
    }
}
