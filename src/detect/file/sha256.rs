//! `Sha256Sink` — streaming SHA-256 over a payload window.

use sha2::{Digest, Sha256};

use super::{
    types::{classify, FileHashEvent, FileType},
    FileHashSink,
};

/// Streaming SHA-256 sink.
///
/// Feed bytes via [`Self::update`]; finalize via
/// [`Self::finish`] which returns the hex digest, byte count,
/// and best-effort MIME classification. After `finish()` the
/// sink resets and is ready for the next payload window.
pub struct Sha256Sink {
    hasher: Sha256,
    bytes: u64,
    mime_probe: [u8; 64],
    mime_probe_len: usize,
}

impl Sha256Sink {
    pub fn new() -> Self {
        Self {
            hasher: Sha256::new(),
            bytes: 0,
            mime_probe: [0; 64],
            mime_probe_len: 0,
        }
    }
}

impl Default for Sha256Sink {
    fn default() -> Self {
        Self::new()
    }
}

impl FileHashSink for Sha256Sink {
    fn algorithm(&self) -> &'static str {
        "sha256"
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
        let hasher = std::mem::replace(&mut self.hasher, Sha256::new());
        let digest = hasher.finalize();
        let file_type: FileType = if self.mime_probe_len == 0 {
            FileType::Unknown
        } else {
            classify(&self.mime_probe[..self.mime_probe_len])
        };
        let evt = FileHashEvent {
            algorithm: "sha256",
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
        let mut s = Sha256Sink::new();
        s.update(b"hello");
        let evt = s.finish();
        assert_eq!(
            evt.hash_hex,
            "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
        );
        assert_eq!(evt.bytes, 5);
        assert_eq!(evt.algorithm, "sha256");
    }

    #[test]
    fn classifies_png_payload() {
        let mut s = Sha256Sink::new();
        s.update(b"\x89PNG\r\n\x1a\n");
        s.update(b"\x00\x00\x00\x0D");
        let evt = s.finish();
        assert_eq!(evt.file_type, FileType::Png);
    }

    #[test]
    fn unknown_file_type_for_short_random() {
        let mut s = Sha256Sink::new();
        s.update(b"x");
        let evt = s.finish();
        assert_eq!(evt.file_type, FileType::Unknown);
    }

    #[test]
    fn finish_resets_for_next_window() {
        let mut s = Sha256Sink::new();
        s.update(b"first");
        let e1 = s.finish();
        assert_eq!(s.bytes_hashed(), 0);
        s.update(b"second");
        let e2 = s.finish();
        assert_ne!(e1.hash_hex, e2.hash_hex);
        assert_eq!(e2.bytes, 6);
    }

    #[test]
    fn streaming_matches_single_call() {
        let mut s_streaming = Sha256Sink::new();
        let mut s_single = Sha256Sink::new();
        let payload = b"hello, world! this is a longer test payload";
        for chunk in payload.chunks(7) {
            s_streaming.update(chunk);
        }
        s_single.update(payload);
        assert_eq!(s_streaming.finish().hash_hex, s_single.finish().hash_hex);
    }
}
