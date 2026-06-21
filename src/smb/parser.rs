//! SMB wire decoder.

use super::types::{SmbCommand, SmbDialect, SmbMessage};

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
    // Offset(8) + ... (rest not needed).
    if matches!(command, SmbCommand::Write) {
        let body = &payload[64..];
        if body.len() >= 16 {
            let length = u32::from_le_bytes([body[4], body[5], body[6], body[7]]);
            let offset = u64::from_le_bytes([
                body[8], body[9], body[10], body[11], body[12], body[13], body[14], body[15],
            ]);
            msg.write_length = Some(length);
            msg.write_offset = Some(offset);
        }
    }

    Some(msg)
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
