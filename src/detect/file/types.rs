//! `FileHashEvent` + `FileType` — emitted by sink finalization.

/// Best-effort MIME / file-type classification from the first
/// ~64 bytes of the hashed payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum FileType {
    Unknown,
    /// PE / PE32+ — Windows `.exe` / `.dll`.
    Pe,
    /// ELF — Linux / BSD binaries.
    Elf,
    /// Mach-O — macOS / iOS binaries.
    MachO,
    Pdf,
    Png,
    Jpeg,
    Gif,
    Webp,
    /// ZIP container — also covers `.docx` / `.xlsx` / `.pptx`
    /// / `.jar` / `.apk` / etc.
    Zip,
    Gzip,
    Bzip2,
    Xz,
    /// ISO Base Media File Format — `.mp4` / `.m4a` / `.mov`.
    Mp4,
    Mp3,
    /// SQLite 3 database.
    Sqlite3,
}

#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct FileHashEvent {
    /// Hash algorithm name (e.g. `"sha256"`, `"md5"`).
    pub algorithm: &'static str,
    /// Hash digest, lowercase hex.
    pub hash_hex: String,
    /// Total bytes hashed.
    pub bytes: u64,
    /// Best-effort MIME classification from the first ~64 B.
    pub file_type: FileType,
}

/// Classify the first ~64 bytes of a payload by magic-byte
/// inspection. Returns `FileType::Unknown` for any input
/// shorter than the smallest detector or not matching any
/// known signature.
pub(super) fn classify(probe: &[u8]) -> FileType {
    if probe.len() >= 4 {
        // PNG: 89 50 4E 47 0D 0A 1A 0A
        if probe.starts_with(b"\x89PNG\r\n\x1a\n") {
            return FileType::Png;
        }
        // GIF: GIF87a / GIF89a
        if probe.starts_with(b"GIF87a") || probe.starts_with(b"GIF89a") {
            return FileType::Gif;
        }
        // JPEG: FF D8 FF
        if probe.starts_with(b"\xFF\xD8\xFF") {
            return FileType::Jpeg;
        }
        // WEBP: RIFF????WEBP
        if probe.len() >= 12 && probe.starts_with(b"RIFF") && &probe[8..12] == b"WEBP" {
            return FileType::Webp;
        }
        // ZIP: PK\x03\x04 or PK\x05\x06 (empty) or PK\x07\x08
        if probe.starts_with(b"PK\x03\x04")
            || probe.starts_with(b"PK\x05\x06")
            || probe.starts_with(b"PK\x07\x08")
        {
            return FileType::Zip;
        }
        // GZIP: 1F 8B
        if probe.starts_with(b"\x1F\x8B") {
            return FileType::Gzip;
        }
        // PDF: %PDF
        if probe.starts_with(b"%PDF") {
            return FileType::Pdf;
        }
        // ELF: 7F 45 4C 46
        if probe.starts_with(b"\x7FELF") {
            return FileType::Elf;
        }
        // PE: MZ at offset 0 (DOS stub); full PE check requires
        // following the e_lfanew offset, but MZ alone is the
        // standard heuristic.
        if probe.starts_with(b"MZ") {
            return FileType::Pe;
        }
        // Mach-O: FE ED FA CE / CE FA ED FE / FE ED FA CF / CF FA ED FE
        if probe.starts_with(b"\xFE\xED\xFA\xCE")
            || probe.starts_with(b"\xCE\xFA\xED\xFE")
            || probe.starts_with(b"\xFE\xED\xFA\xCF")
            || probe.starts_with(b"\xCF\xFA\xED\xFE")
        {
            return FileType::MachO;
        }
        // bzip2: BZh
        if probe.starts_with(b"BZh") {
            return FileType::Bzip2;
        }
        // xz: FD 37 7A 58 5A 00
        if probe.starts_with(b"\xFD7zXZ\x00") {
            return FileType::Xz;
        }
        // ID3 / MPEG-Layer-3: ID3 prefix OR sync bytes FF FB
        if probe.starts_with(b"ID3")
            || probe.starts_with(b"\xFF\xFB")
            || probe.starts_with(b"\xFF\xF3")
        {
            return FileType::Mp3;
        }
        // SQLite: "SQLite format 3\0"
        if probe.starts_with(b"SQLite format 3\0") {
            return FileType::Sqlite3;
        }
    }
    if probe.len() >= 12 {
        // MP4 / ISO BMF: bytes 4..8 == "ftyp"
        if &probe[4..8] == b"ftyp" {
            return FileType::Mp4;
        }
    }
    FileType::Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_png() {
        let payload = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0D";
        assert_eq!(classify(payload), FileType::Png);
    }

    #[test]
    fn classifies_pdf() {
        let payload = b"%PDF-1.7\n...";
        assert_eq!(classify(payload), FileType::Pdf);
    }

    #[test]
    fn classifies_zip() {
        let payload = b"PK\x03\x04\x14\x00\x00\x00\x08\x00";
        assert_eq!(classify(payload), FileType::Zip);
    }

    #[test]
    fn classifies_elf() {
        let payload = b"\x7FELF\x02\x01\x01\x00";
        assert_eq!(classify(payload), FileType::Elf);
    }

    #[test]
    fn classifies_pe() {
        let payload = b"MZ\x90\x00\x03\x00\x00\x00";
        assert_eq!(classify(payload), FileType::Pe);
    }

    #[test]
    fn classifies_macho_64bit_le() {
        let payload = b"\xCF\xFA\xED\xFE\x07\x00\x00\x01";
        assert_eq!(classify(payload), FileType::MachO);
    }

    #[test]
    fn classifies_mp4_via_ftyp() {
        // 4B size + "ftyp" + brand
        let payload = b"\x00\x00\x00\x20ftypisom\x00\x00\x02\x00";
        assert_eq!(classify(payload), FileType::Mp4);
    }

    #[test]
    fn classifies_gzip() {
        let payload = b"\x1F\x8B\x08\x00\x00\x00\x00\x00";
        assert_eq!(classify(payload), FileType::Gzip);
    }

    #[test]
    fn returns_unknown_for_random_bytes() {
        let payload = b"this is just some random text data";
        assert_eq!(classify(payload), FileType::Unknown);
    }

    #[test]
    fn short_input_returns_unknown() {
        let payload = b"x";
        assert_eq!(classify(payload), FileType::Unknown);
    }
}
