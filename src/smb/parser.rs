//! SMB wire decoder.

use super::types::{DceRpcInterfaceUuid, NtlmAuth, SmbCommand, SmbDialect, SmbMessage};

pub const PARSER_KIND_STR: &str = "smb";

pub fn parser_kind() -> &'static str {
    PARSER_KIND_STR
}

/// Decode one SMB message from the front of `payload`
/// (the bytes *after* the NetBIOS Session Service
/// 4-byte length header). Returns `None` if the buffer
/// doesn't start with a known SMB protocol marker or is
/// too short for the header.
pub fn parse(payload: &[u8]) -> Option<SmbMessage> {
    let header = payload.get(..4)?;
    let dialect = match header {
        [0xFF, b'S', b'M', b'B'] => SmbDialect::V1,
        [0xFE, b'S', b'M', b'B'] => SmbDialect::V2,
        [0xFD, b'S', b'M', b'B'] => SmbDialect::EncryptedTransform,
        [0xFC, b'S', b'M', b'B'] => SmbDialect::CompressedTransform,
        _ => return None,
    };
    match dialect {
        SmbDialect::V1 => parse_smb1(payload),
        SmbDialect::V2 => parse_smb2(payload),
        SmbDialect::EncryptedTransform | SmbDialect::CompressedTransform => {
            Some(SmbMessage::new(dialect, SmbCommand::NotApplicable))
        }
    }
}

/// Parse the bare SMB1 header — we only need to recognise
/// it so we can surface the downgrade signal.
fn parse_smb1(payload: &[u8]) -> Option<SmbMessage> {
    // SMB1 header is 32 bytes: protocol(4) + command(1) +
    // status(4) + flags(1) + flags2(2) + pidhigh(2) +
    // sec(8) + reserved(2) + tid(2) + pidlow(2) + uid(2) +
    // mid(2).
    let cmd = *payload.get(4)?;
    Some(SmbMessage::new(SmbDialect::V1, SmbCommand::OtherSmb1(cmd)))
}

/// Parse the 64-byte SMB2 header + optionally walk the
/// payload for TREE_CONNECT path.
fn parse_smb2(payload: &[u8]) -> Option<SmbMessage> {
    if payload.len() < 64 {
        return None;
    }
    let command_lo = *payload.get(12)?;
    let command_hi = *payload.get(13)?;
    let command_raw = u16::from_le_bytes([command_lo, command_hi]);
    let command = SmbCommand::from_smb2(command_raw);

    // Offsets per MS-SMB2 §2.2.1.2 (SMB2 Packet Header -
    // Sync form). We treat the async form's AsyncId
    // as not-applicable; the Flags bit decides.
    let flags = u32::from_le_bytes([payload[16], payload[17], payload[18], payload[19]]);
    let is_async = (flags & 0x0000_0002) != 0;
    let message_id = u64::from_le_bytes([
        payload[24],
        payload[25],
        payload[26],
        payload[27],
        payload[28],
        payload[29],
        payload[30],
        payload[31],
    ]);
    let (tree_id, session_id) = if is_async {
        // Async header: no TreeId; SessionId still at offset 40.
        let sid = u64::from_le_bytes([
            payload[40],
            payload[41],
            payload[42],
            payload[43],
            payload[44],
            payload[45],
            payload[46],
            payload[47],
        ]);
        (None, Some(sid))
    } else {
        let tid = u32::from_le_bytes([payload[36], payload[37], payload[38], payload[39]]);
        let sid = u64::from_le_bytes([
            payload[40],
            payload[41],
            payload[42],
            payload[43],
            payload[44],
            payload[45],
            payload[46],
            payload[47],
        ]);
        (Some(tid), Some(sid))
    };

    let mut msg = SmbMessage::new(SmbDialect::V2, command);
    msg.message_id = Some(message_id);
    msg.tree_id = tree_id;
    msg.session_id = session_id;

    // Optional: TREE_CONNECT request body decode (§2.2.9):
    // StructureSize(2) + Flags(2) + PathOffset(2) +
    // PathLength(2) + Buffer (variable, UTF-16LE).
    if matches!(command, SmbCommand::TreeConnect) {
        let body = &payload[64..];
        if body.len() >= 8 {
            let _structure_size = u16::from_le_bytes([body[0], body[1]]);
            let _flags = u16::from_le_bytes([body[2], body[3]]);
            let path_offset = u16::from_le_bytes([body[4], body[5]]) as usize;
            let path_len = u16::from_le_bytes([body[6], body[7]]) as usize;
            // path_offset is from the START of the SMB2
            // header, not from the start of the body.
            if path_offset >= 64
                && path_offset + path_len <= payload.len()
                && path_len > 0
                && path_len.is_multiple_of(2)
            {
                let path_bytes = &payload[path_offset..path_offset + path_len];
                if let Some(path) = utf16le_to_string(path_bytes) {
                    msg.tree_connect_is_admin_share = is_admin_share(&path);
                    msg.tree_connect_path = Some(path);
                }
            }
        }
    }

    // M2: SMB2 CREATE request body (§2.2.13).
    // StructureSize(2)=57 + SecurityFlags(1) +
    // RequestedOplockLevel(1) + ImpersonationLevel(4) +
    // SmbCreateFlags(8) + Reserved(8) + DesiredAccess(4) +
    // FileAttributes(4) + ShareAccess(4) +
    // CreateDisposition(4) + CreateOptions(4) +
    // NameOffset(2) + NameLength(2) +
    // CreateContextsOffset(4) + CreateContextsLength(4)
    // + Buffer.
    if matches!(command, SmbCommand::Create) {
        let body = &payload[64..];
        if body.len() >= 56 {
            let name_offset = u16::from_le_bytes([body[44], body[45]]) as usize;
            let name_length = u16::from_le_bytes([body[46], body[47]]) as usize;
            if name_offset >= 64
                && name_offset + name_length <= payload.len()
                && name_length.is_multiple_of(2)
            {
                let name_bytes = &payload[name_offset..name_offset + name_length];
                if let Some(name) = utf16le_to_string(name_bytes) {
                    msg.create_is_admin_named_pipe = is_admin_named_pipe(&name);
                    msg.create_path = Some(name);
                }
            }
        }
    }

    // M2: SMB2 READ request body (§2.2.19).
    // StructureSize(2)=49 + Padding(1) + Flags(1) +
    // Length(4) + Offset(8) + ... (rest not needed).
    if matches!(command, SmbCommand::Read) {
        let body = &payload[64..];
        if body.len() >= 16 {
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let offset = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            msg.read_length = Some(length);
            msg.read_offset = Some(offset);
        }
    }

    // M2: SMB2 WRITE request body (§2.2.21).
    // StructureSize(2)=49 + DataOffset(2) + Length(4) +
    // Offset(8) + ... + WriteData.
    if matches!(command, SmbCommand::Write) {
        let body = &payload[64..];
        if body.len() >= 16 {
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let offset = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            msg.write_length = Some(length);
            msg.write_offset = Some(offset);

            // M3: scan the WRITE data for a DCE-RPC v5 PDU.
            // DataOffset (body[2..4]) is from the start of
            // the SMB2 header; the payload is `length`
            // bytes starting there.
            let data_offset = u16::from_le_bytes([body[2], body[3]]) as usize;
            let len_usize = length as usize;
            if data_offset >= 64 && data_offset + len_usize <= payload.len() {
                let data = &payload[data_offset..data_offset + len_usize];
                if let Some(uuids) = decode_dcerpc_bind(data) {
                    msg.dcerpc_bind_uuids = uuids;
                }
            }
        }
    }

    // M3: SMB2 SESSION_SETUP request body (§2.2.5) —
    // walk the security buffer for an NTLMSSP blob.
    // StructureSize(2)=25 + Flags(1) + SecurityMode(1) +
    // Capabilities(4) + Channel(4) + SecurityBufferOffset(2) +
    // SecurityBufferLength(2) + PreviousSessionId(8) + Buffer.
    if matches!(command, SmbCommand::SessionSetup) {
        let body = &payload[64..];
        if body.len() >= 24 {
            let sec_off = u16::from_le_bytes([body[12], body[13]]) as usize;
            let sec_len = u16::from_le_bytes([body[14], body[15]]) as usize;
            if sec_off >= 64 && sec_off + sec_len <= payload.len() {
                let sec_buf = &payload[sec_off..sec_off + sec_len];
                if let Some(auth) = scan_ntlm_authenticate(sec_buf) {
                    msg.ntlm_auth = Some(auth);
                }
            }
        }
    }

    Some(msg)
}

/// Scan a SESSION_SETUP security buffer for an NTLMSSP
/// AUTHENTICATE (Type 3) message. The buffer is usually
/// SPNEGO-wrapped (ASN.1 GSS-API mechToken); we bypass
/// the wrapper by searching for the `NTLMSSP\0` magic and
/// decoding from there. This matches Wireshark's approach
/// and is robust against SPNEGO version drift.
fn scan_ntlm_authenticate(buf: &[u8]) -> Option<NtlmAuth> {
    const MAGIC: &[u8; 8] = b"NTLMSSP\0";
    let start =
        (0..buf.len().saturating_sub(MAGIC.len())).find(|&i| &buf[i..i + MAGIC.len()] == MAGIC)?;
    let msg = &buf[start..];
    if msg.len() < 12 {
        return None;
    }
    let message_type = u32::from_le_bytes([msg[8], msg[9], msg[10], msg[11]]);
    if message_type != 3 {
        return None;
    }
    // Type 3 AUTHENTICATE layout per MS-NLMP §2.2.1.3:
    //   12..20  LmChallengeResponseFields (SecurityBuffer)
    //   20..28  NtChallengeResponseFields
    //   28..36  DomainNameFields
    //   36..44  UserNameFields
    //   44..52  WorkstationFields
    //   52..60  EncryptedRandomSessionKeyFields
    //   60..64  NegotiateFlags
    //   ...
    if msg.len() < 64 {
        return None;
    }
    let flags = u32::from_le_bytes([msg[60], msg[61], msg[62], msg[63]]);
    let unicode = (flags & 0x0000_0001) != 0; // NEGOTIATE_UNICODE
    let domain = read_security_buffer_string(msg, 28, unicode);
    let username = read_security_buffer_string(msg, 36, unicode);
    let workstation = read_security_buffer_string(msg, 44, unicode);
    Some(NtlmAuth {
        domain,
        username,
        workstation,
    })
}

/// Decode a SecurityBuffer (u16 length + u16 max + u32
/// offset) and return its payload as a string. `unicode`
/// selects UTF-16LE vs Windows-1252-ish; we map non-ASCII
/// OEM bytes through `String::from_utf8_lossy` for safety.
fn read_security_buffer_string(msg: &[u8], field_off: usize, unicode: bool) -> Option<String> {
    let entry = msg.get(field_off..field_off + 8)?;
    let len = u16::from_le_bytes([entry[0], entry[1]]) as usize;
    let offset = u32::from_le_bytes([entry[4], entry[5], entry[6], entry[7]]) as usize;
    if len == 0 {
        return None;
    }
    let bytes = msg.get(offset..offset + len)?;
    if unicode {
        if !bytes.len().is_multiple_of(2) {
            return None;
        }
        let units: Vec<u16> = bytes
            .chunks_exact(2)
            .map(|c| u16::from_le_bytes([c[0], c[1]]))
            .collect();
        String::from_utf16(&units).ok()
    } else {
        Some(String::from_utf8_lossy(bytes).into_owned())
    }
}

/// Check whether `data` is a DCE-RPC v5 connection-oriented
/// BIND PDU and, if so, extract the offered abstract-syntax
/// UUIDs from each context-element. Returns `None` when
/// the PDU isn't a BIND.
///
/// PDU layout (MS-RPCE §2.2.2.3):
///   0..16   Common header (rpc_vers=5, ptype=0x0B for BIND)
///   16..18  max_xmit_frag
///   18..20  max_recv_frag
///   20..24  assoc_group_id
///   24      n_context_elem
///   25..28  reserved
///   28..    p_cont_elem[n_context_elem]
/// Each p_cont_elem: p_cont_id(2) + n_transfer_syn(1) +
///   reserved(1) + abstract_syntax(20) +
///   transfer_syntaxes[n_transfer_syn * 20]
/// abstract_syntax = if_uuid(16) + if_version(4).
fn decode_dcerpc_bind(data: &[u8]) -> Option<Vec<DceRpcInterfaceUuid>> {
    if data.len() < 28 {
        return None;
    }
    if data[0] != 0x05 || data[2] != 0x0B {
        return None;
    }
    let n_ctx = data[24] as usize;
    let mut cursor = 28;
    let mut uuids = Vec::with_capacity(n_ctx);
    for _ in 0..n_ctx {
        if cursor + 24 > data.len() {
            break;
        }
        let n_transfer = data[cursor + 2] as usize;
        let mut bytes = [0u8; 16];
        bytes.copy_from_slice(&data[cursor + 4..cursor + 20]);
        uuids.push(DceRpcInterfaceUuid::from_bytes(bytes));
        cursor = cursor
            .saturating_add(24)
            .saturating_add(n_transfer.saturating_mul(20));
    }
    Some(uuids)
}

/// Decode UTF-16LE bytes to a Rust `String`. Returns
/// `None` if the byte length isn't even.
fn utf16le_to_string(bytes: &[u8]) -> Option<String> {
    if !bytes.len().is_multiple_of(2) {
        return None;
    }
    let units: Vec<u16> = bytes
        .chunks_exact(2)
        .map(|c| u16::from_le_bytes([c[0], c[1]]))
        .collect();
    String::from_utf16(&units).ok()
}

/// `true` when the path's trailing component is one of the
/// classic admin shares. Path looks like `\\server\C$`.
fn is_admin_share(path: &str) -> bool {
    let trailing = path.rsplit('\\').next().unwrap_or("");
    matches!(
        trailing.to_ascii_uppercase().as_str(),
        "C$" | "ADMIN$" | "IPC$" | "NETLOGON" | "SYSVOL" | "D$" | "E$" | "F$"
    )
}

/// `true` when the CREATE name targets a well-known
/// named-pipe endpoint historically abused for lateral
/// movement, credential dumping, or remote service
/// creation. Pipe names appear bare (e.g. `svcctl`) when
/// the parent tree is IPC$ — the SMB2 CREATE path is
/// relative to the tree root.
///
/// Sources: Zeek `dpd_smb_pipe`, MITRE T1021.002 (SMB
/// admin shares), T1003 (OS credential dumping), T1569
/// (system services), T1574.002 (DLL side-loading via
/// admin pipes), PrintNightmare (CVE-2021-34527).
fn is_admin_named_pipe(name: &str) -> bool {
    // Strip optional leading backslash (some clients
    // include it, some don't).
    let bare = name.trim_start_matches('\\');
    matches!(
        bare.to_ascii_lowercase().as_str(),
        "svcctl"      // service control — PsExec, service creation
            | "winreg" // remote registry
            | "lsarpc" // LSA — secrets / cred dump
            | "samr"   // SAMR — user enum, cred dump
            | "netlogon" // domain auth pipe
            | "spoolss" // printer — PrintNightmare
            | "atsvc"  // task scheduler
            | "eventlog"
            | "ntsvcs" // plug-and-play / service control
            | "wkssvc" // workstation
            | "srvsvc" // server — share enumeration
            | "drsuapi" // directory replication — DCSync
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_garbage() {
        assert!(parse(&[]).is_none());
        assert!(parse(&[0xAA, 0xBB, 0xCC, 0xDD]).is_none());
    }

    #[test]
    fn dialect_smb1_recognised() {
        let mut frame = [0u8; 32];
        frame[0..4].copy_from_slice(&[0xFF, b'S', b'M', b'B']);
        frame[4] = 0x72; // SMB_COM_NEGOTIATE
        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.dialect, SmbDialect::V1);
        assert_eq!(msg.command, SmbCommand::OtherSmb1(0x72));
    }

    #[test]
    fn dialect_smb2_negotiate_recognised() {
        let mut frame = [0u8; 64];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // command at offset 12-13, le bytes 0x00 0x00 = Negotiate
        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.dialect, SmbDialect::V2);
        assert_eq!(msg.command, SmbCommand::Negotiate);
    }

    #[test]
    fn dialect_encrypted_transform_marks_opaque() {
        let mut frame = [0u8; 52];
        frame[0..4].copy_from_slice(&[0xFD, b'S', b'M', b'B']);
        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.dialect, SmbDialect::EncryptedTransform);
        assert!(msg.encrypted);
        assert!(msg.dialect.is_opaque());
        assert_eq!(msg.command, SmbCommand::NotApplicable);
    }

    #[test]
    fn tree_connect_decodes_admin_share_path() {
        // Construct a minimal SMB2 TREE_CONNECT request:
        // 64-byte header + 8-byte body header + path bytes.
        let path = "\\\\srv\\C$";
        let path_utf16: Vec<u8> = path.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let path_offset = 64 + 8;
        let path_len = path_utf16.len();
        let mut frame = vec![0u8; path_offset + path_len];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // command = 0x0003 (TREE_CONNECT)
        frame[12] = 0x03;
        frame[13] = 0x00;
        // TREE_CONNECT body: StructureSize(2)=9, Flags(2),
        // PathOffset(2), PathLength(2).
        frame[64] = 9;
        frame[65] = 0;
        // Flags (2 bytes) at 66..68 stays zero.
        let off_bytes = (path_offset as u16).to_le_bytes();
        let len_bytes = (path_len as u16).to_le_bytes();
        frame[68] = off_bytes[0];
        frame[69] = off_bytes[1];
        frame[70] = len_bytes[0];
        frame[71] = len_bytes[1];
        frame[path_offset..path_offset + path_len].copy_from_slice(&path_utf16);

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.command, SmbCommand::TreeConnect);
        assert_eq!(msg.tree_connect_path.as_deref(), Some(path));
        assert!(msg.tree_connect_is_admin_share);
    }

    #[test]
    fn is_admin_share_classifies_correctly() {
        assert!(is_admin_share("\\\\srv\\C$"));
        assert!(is_admin_share("\\\\srv\\ADMIN$"));
        assert!(is_admin_share("\\\\srv\\IPC$"));
        assert!(is_admin_share("\\\\srv\\netlogon"));
        assert!(is_admin_share("\\\\srv\\SYSVOL"));
        assert!(!is_admin_share("\\\\srv\\Users"));
        assert!(!is_admin_share("\\\\srv\\Share1"));
    }

    #[test]
    fn smb2_async_header_skips_tree_id() {
        let mut frame = [0u8; 64];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // Flags: SMB2_FLAGS_ASYNC_COMMAND = 0x00000002 at offset 16-19.
        frame[16] = 0x02;
        let msg = parse(&frame).expect("parse");
        assert!(msg.tree_id.is_none());
        assert!(msg.session_id.is_some());
    }

    #[test]
    fn command_slugs_stable() {
        assert_eq!(SmbCommand::TreeConnect.as_str(), "tree_connect");
        assert_eq!(SmbCommand::Create.as_str(), "create");
        assert_eq!(SmbCommand::Other(0x99).as_str(), "other");
        assert_eq!(SmbCommand::OtherSmb1(0x72).as_str(), "smb1");
    }

    /// SMB2 CREATE request: surface filename + flag
    /// well-known admin pipe (svcctl → PsExec / service
    /// creation signal, MITRE T1569.002 / T1021.002).
    #[test]
    fn create_decodes_named_pipe_path() {
        let name = "svcctl";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_offset = 64 + 56;
        let name_length = name_utf16.len();
        let mut frame = vec![0u8; name_offset + name_length];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        // command = 0x0005 (CREATE)
        frame[12] = 0x05;
        frame[13] = 0x00;
        // CREATE body header: StructureSize=57.
        frame[64] = 57;
        frame[65] = 0;
        // NameOffset (body[44..46]) and NameLength
        // (body[46..48]).
        let off_bytes = (name_offset as u16).to_le_bytes();
        let len_bytes = (name_length as u16).to_le_bytes();
        frame[64 + 44] = off_bytes[0];
        frame[64 + 45] = off_bytes[1];
        frame[64 + 46] = len_bytes[0];
        frame[64 + 47] = len_bytes[1];
        frame[name_offset..name_offset + name_length].copy_from_slice(&name_utf16);

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.command, SmbCommand::Create);
        assert_eq!(msg.create_path.as_deref(), Some("svcctl"));
        assert!(
            msg.create_is_admin_named_pipe,
            "svcctl must classify as admin named pipe"
        );
    }

    #[test]
    fn create_path_on_file_share_not_admin_pipe() {
        let name = "Users\\bob\\Documents\\report.docx";
        let name_utf16: Vec<u8> = name.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let name_offset = 64 + 56;
        let name_length = name_utf16.len();
        let mut frame = vec![0u8; name_offset + name_length];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x05; // CREATE
        frame[64] = 57; // StructureSize
        let off_bytes = (name_offset as u16).to_le_bytes();
        let len_bytes = (name_length as u16).to_le_bytes();
        frame[64 + 44] = off_bytes[0];
        frame[64 + 45] = off_bytes[1];
        frame[64 + 46] = len_bytes[0];
        frame[64 + 47] = len_bytes[1];
        frame[name_offset..name_offset + name_length].copy_from_slice(&name_utf16);

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.create_path.as_deref(), Some(name));
        assert!(!msg.create_is_admin_named_pipe);
    }

    #[test]
    fn is_admin_named_pipe_classifies_correctly() {
        assert!(is_admin_named_pipe("svcctl"));
        assert!(is_admin_named_pipe("\\svcctl"));
        assert!(is_admin_named_pipe("SVCCTL"));
        assert!(is_admin_named_pipe("lsarpc"));
        assert!(is_admin_named_pipe("samr"));
        assert!(is_admin_named_pipe("spoolss"));
        assert!(is_admin_named_pipe("drsuapi"));
        assert!(!is_admin_named_pipe("notepad.exe"));
        assert!(!is_admin_named_pipe("Documents\\report.docx"));
    }

    /// SMB2 READ request: surface offset + length.
    /// Large `length` on a single file is the data-exfil
    /// signal.
    #[test]
    fn read_surfaces_offset_and_length() {
        let mut frame = vec![0u8; 64 + 16];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x08; // READ
        // body[4..8] = Length = 0x0010_0000 (1 MiB).
        frame[64 + 4] = 0x00;
        frame[64 + 5] = 0x00;
        frame[64 + 6] = 0x10;
        frame[64 + 7] = 0x00;
        // body[8..16] = Offset = 0x12345678.
        frame[64 + 8] = 0x78;
        frame[64 + 9] = 0x56;
        frame[64 + 10] = 0x34;
        frame[64 + 11] = 0x12;

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.command, SmbCommand::Read);
        assert_eq!(msg.read_length, Some(0x0010_0000));
        assert_eq!(msg.read_offset, Some(0x1234_5678));
    }

    /// M3: SMB2 SESSION_SETUP carrying a synthetic NTLM
    /// Type 3 AUTHENTICATE blob — decode `domain` /
    /// `username` / `workstation`.
    #[test]
    fn session_setup_extracts_ntlm_identity() {
        // Build the NTLMSSP blob first.
        let domain = "CONTOSO";
        let user = "alice";
        let workstation = "WS01";
        let domain_u: Vec<u8> = domain
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let user_u: Vec<u8> = user.encode_utf16().flat_map(|u| u.to_le_bytes()).collect();
        let ws_u: Vec<u8> = workstation
            .encode_utf16()
            .flat_map(|u| u.to_le_bytes())
            .collect();
        let mut blob = Vec::new();
        blob.extend_from_slice(b"NTLMSSP\0");
        blob.extend_from_slice(&3u32.to_le_bytes()); // MessageType = 3
        // SecurityBuffer rows occupy bytes 12..60 (six rows of 8).
        // We fill only Domain/User/Workstation; the rest stay zero.
        let header_len: u32 = 64;
        let domain_off = header_len;
        let user_off = domain_off + domain_u.len() as u32;
        let ws_off = user_off + user_u.len() as u32;
        // LM (12..20) — empty.
        blob.extend_from_slice(&0u16.to_le_bytes()); // length
        blob.extend_from_slice(&0u16.to_le_bytes()); // max
        blob.extend_from_slice(&0u32.to_le_bytes()); // offset
        // NT (20..28) — empty.
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        // Domain (28..36).
        blob.extend_from_slice(&(domain_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&(domain_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&domain_off.to_le_bytes());
        // User (36..44).
        blob.extend_from_slice(&(user_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&(user_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&user_off.to_le_bytes());
        // Workstation (44..52).
        blob.extend_from_slice(&(ws_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&(ws_u.len() as u16).to_le_bytes());
        blob.extend_from_slice(&ws_off.to_le_bytes());
        // EncryptedRandomSessionKey (52..60) — empty.
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u16.to_le_bytes());
        blob.extend_from_slice(&0u32.to_le_bytes());
        // NegotiateFlags (60..64) — only NEGOTIATE_UNICODE set.
        blob.extend_from_slice(&0x0000_0001u32.to_le_bytes());
        // Payload at offset 64.
        blob.extend_from_slice(&domain_u);
        blob.extend_from_slice(&user_u);
        blob.extend_from_slice(&ws_u);

        // Build the surrounding SMB2 SESSION_SETUP frame.
        let sec_offset_in_payload = 64 + 24; // body header is 24 bytes.
        let blob_len = blob.len();
        let mut frame = vec![0u8; sec_offset_in_payload + blob_len];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x01; // SESSION_SETUP
        // body[0..2] StructureSize = 25.
        frame[64] = 25;
        frame[65] = 0;
        // body[12..14] SecurityBufferOffset (relative to SMB2 header).
        let off_bytes = (sec_offset_in_payload as u16).to_le_bytes();
        let len_bytes = (blob_len as u16).to_le_bytes();
        frame[64 + 12] = off_bytes[0];
        frame[64 + 13] = off_bytes[1];
        frame[64 + 14] = len_bytes[0];
        frame[64 + 15] = len_bytes[1];
        frame[sec_offset_in_payload..sec_offset_in_payload + blob_len].copy_from_slice(&blob);

        let msg = parse(&frame).expect("parse");
        let auth = msg.ntlm_auth.expect("ntlm");
        assert_eq!(auth.domain.as_deref(), Some("CONTOSO"));
        assert_eq!(auth.username.as_deref(), Some("alice"));
        assert_eq!(auth.workstation.as_deref(), Some("WS01"));
    }

    /// M3: SMB2 SESSION_SETUP carrying a non-NTLM
    /// (e.g. raw Kerberos) blob — no NtlmAuth surfaced.
    #[test]
    fn session_setup_kerberos_yields_no_ntlm_auth() {
        let mut frame = vec![0u8; 64 + 24 + 16];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x01;
        frame[64] = 25;
        let off_bytes = (64u16 + 24).to_le_bytes();
        frame[64 + 12] = off_bytes[0];
        frame[64 + 13] = off_bytes[1];
        frame[64 + 14] = 16;
        frame[64 + 15] = 0;
        // 16 bytes of opaque payload — no NTLMSSP magic.
        for b in frame.iter_mut().skip(64 + 24).take(16) {
            *b = 0x42;
        }
        let msg = parse(&frame).expect("parse");
        assert!(msg.ntlm_auth.is_none());
    }

    /// M3: SMB2 WRITE carrying a synthetic DCE-RPC BIND PDU
    /// with one context offering the `svcctl` interface
    /// (UUID 367abb81-9844-35f1-ad32-98f038001003). Verifies
    /// `dcerpc_bind_uuids` surfaces it.
    #[test]
    fn write_surfaces_dcerpc_bind_uuids() {
        // svcctl UUID, little-endian per MS-DTYP.
        let uuid_le: [u8; 16] = [
            0x81, 0xbb, 0x7a, 0x36, // 367abb81 (LE)
            0x44, 0x98, // 9844
            0xf1, 0x35, // 35f1
            0xad, 0x32, // ad32
            0x98, 0xf0, 0x38, 0x00, 0x10, 0x03,
        ];
        let mut pdu = vec![
            5,    // rpc_vers
            0,    // rpc_vers_minor
            0x0B, // ptype = BIND
            0,    // pfc_flags
        ];
        pdu.extend_from_slice(&[0x10, 0, 0, 0]); // packed_drep
        pdu.extend_from_slice(&[0, 0]); // frag_length
        pdu.extend_from_slice(&[0, 0]); // auth_length
        pdu.extend_from_slice(&[0, 0, 0, 0]); // call_id
        // BIND header.
        pdu.extend_from_slice(&[0, 0]); // max_xmit_frag
        pdu.extend_from_slice(&[0, 0]); // max_recv_frag
        pdu.extend_from_slice(&[0, 0, 0, 0]); // assoc_group_id
        pdu.push(1); // n_context_elem = 1
        pdu.extend_from_slice(&[0, 0, 0]); // reserved
        // p_cont_elem.
        pdu.extend_from_slice(&[0, 0]); // p_cont_id
        pdu.push(0); // n_transfer_syn
        pdu.push(0); // reserved
        pdu.extend_from_slice(&uuid_le);
        pdu.extend_from_slice(&[0, 0, 0, 0]); // if_version

        let data_offset_in_payload = 64 + 16; // arbitrary; > body header
        let mut frame = vec![0u8; data_offset_in_payload + pdu.len()];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x09; // WRITE
        // body[2..4] = DataOffset.
        let off_bytes = (data_offset_in_payload as u16).to_le_bytes();
        frame[64 + 2] = off_bytes[0];
        frame[64 + 3] = off_bytes[1];
        // body[4..8] = Length.
        let len_bytes = (pdu.len() as u32).to_le_bytes();
        frame[64 + 4] = len_bytes[0];
        frame[64 + 5] = len_bytes[1];
        frame[64 + 6] = len_bytes[2];
        frame[64 + 7] = len_bytes[3];
        // body[8..16] = Offset, zero.
        frame[data_offset_in_payload..data_offset_in_payload + pdu.len()].copy_from_slice(&pdu);

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.command, SmbCommand::Write);
        assert_eq!(msg.dcerpc_bind_uuids.len(), 1);
        let uuid = &msg.dcerpc_bind_uuids[0];
        assert_eq!(uuid.to_string(), "367abb81-9844-35f1-ad32-98f038001003");
        assert_eq!(uuid.well_known_name(), Some("svcctl"));
    }

    #[test]
    fn write_without_dcerpc_yields_empty_uuid_list() {
        let mut frame = vec![0u8; 64 + 16 + 8];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x09;
        let off_bytes = (64u16 + 16).to_le_bytes();
        frame[64 + 2] = off_bytes[0];
        frame[64 + 3] = off_bytes[1];
        frame[64 + 4] = 8;
        let msg = parse(&frame).expect("parse");
        assert!(msg.dcerpc_bind_uuids.is_empty());
    }

    /// SMB2 WRITE request: surface offset + length.
    /// Mass writes concentrated in a short window is the
    /// ransomware signal.
    #[test]
    fn write_surfaces_offset_and_length() {
        let mut frame = vec![0u8; 64 + 16];
        frame[0..4].copy_from_slice(&[0xFE, b'S', b'M', b'B']);
        frame[12] = 0x09; // WRITE
        frame[64 + 4] = 0x00;
        frame[64 + 5] = 0x10;
        frame[64 + 6] = 0x00;
        frame[64 + 7] = 0x00;
        frame[64 + 8] = 0xAA;
        frame[64 + 9] = 0xBB;
        frame[64 + 10] = 0xCC;
        frame[64 + 11] = 0xDD;

        let msg = parse(&frame).expect("parse");
        assert_eq!(msg.command, SmbCommand::Write);
        assert_eq!(msg.write_length, Some(0x0000_1000));
        assert_eq!(msg.write_offset, Some(0xDDCC_BBAA));
    }
}
