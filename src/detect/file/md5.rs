//! `Md5Sink` — streaming MD5 over a payload window.
//!
//! MD5 is not cryptographically secure but remains the de-facto
//! interop hash for legacy DFIR / IR pipelines (VirusTotal,
//! ClamAV signature DB, Suricata `file_md5`). Pair with
//! [`super::Sha256Sink`] for downstream consumers that prefer
//! SHA-256.

use md5::{Digest, Md5};

use super::{
    types::{classify, FileHashEvent, FileType},
    FileHashSink,
};

/// Streaming MD5 sink.
pub struct Md5Sink {
    hasher: Md5,
    bytes: u64,
    mime_probe: [u8; 64],
    mime_probe_len: usize,
}

impl Md5Sink {
    pub fn new() -> Self {
        Self {
            hasher: Md5::new(),
            bytes: 0,
            mime_probe: [0; 64],
            mime_probe_len: 0,
        }
    }
}

impl Default for Md5Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHashSink for Md5Sink {
    fn algorithm(&self) -> &'static str {
        "md5"
    }

    fn update(&mut self, bytes: &[u8]) {
        if self.mime_probe_len < self.mime_probe.len() {
            let room = self.mime_probe.len() - self.mime_probe_len;
            let take = room.min(bytes.len());
            self.mime_probe[self.mime_probe_len..self.mime_probe_len + take]
                .copy_from_slice(&bytes[..take]);
            self.mime_probe_len += take;
        }
        self.hasher.update(bytes);
        self.bytes += bytes.len() as u64;
    }

    fn finish(&mut self) -> FileHashEvent {
        let hasher = std::mem::replace(&mut self.hasher, Md5::new());
        let digest = hasher.finalize();
        let file_type: FileType = if self.mime_probe_len == 0 {
            FileType::Unknown
        } else {
            classify(&self.mime_probe[..self.mime_probe_len])
        };
        let evt = FileHashEvent {
            algorithm: "md5",
            hash_hex: hex::encode(digest),
            bytes: self.bytes,
            file_type,
        };
        self.bytes = 0;
        self.mime_probe_len = 0;
        evt
    }

    fn bytes_hashed(&self) -> u64 {
        self.bytes
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_input_yields_canonical_hex() {
        let mut s = Md5Sink::new();
        s.update(b"hello");
        let evt = s.finish();
        assert_eq!(evt.hash_hex, "5d41402abc4b2a76b9719d911017c592");
        assert_eq!(evt.bytes, 5);
        assert_eq!(evt.algorithm, "md5");
    }

    #[test]
    fn streaming_matches_single_call() {
        let mut s_streaming = Md5Sink::new();
        let mut s_single = Md5Sink::new();
        let payload = b"some test payload for streaming consistency";
        for chunk in payload.chunks(5) {
            s_streaming.update(chunk);
        }
        s_single.update(payload);
        assert_eq!(s_streaming.finish().hash_hex, s_single.finish().hash_hex);
    }

    #[test]
    fn classifies_jpeg_payload() {
        let mut s = Md5Sink::new();
        s.update(b"\xFF\xD8\xFF\xE0\x00\x10JFIF");
        let evt = s.finish();
        assert_eq!(evt.file_type, FileType::Jpeg);
    }
}
