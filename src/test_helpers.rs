//! Parser stubs intended for downstream test crates that need a
//! `SessionParser` / `DatagramParser` impl but don't care about
//! the produced messages.
//!
//! Gated behind the `test-helpers` Cargo feature (alongside
//! `extract::parse::test_frames`). Not for production use.
//!
//! Future trait-shape evolution (new defaulted methods, signature
//! tweaks) absorbs into these stubs once instead of forcing every
//! downstream test crate to update its own copy.

use crate::{DatagramParser, FlowSide, SessionParser, Timestamp};

/// A `SessionParser` that produces no messages. Use when test code
/// needs to exercise the driver / stream wiring without caring
/// about parsed output.
#[derive(Debug, Default, Clone)]
pub struct NoopSessionParser;

impl SessionParser for NoopSessionParser {
    type Message = ();
    fn feed_initiator(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
    fn feed_responder(&mut self, _bytes: &[u8], _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
}

/// A `DatagramParser` that produces no messages. Mirror of
/// [`NoopSessionParser`].
#[derive(Debug, Default, Clone)]
pub struct NoopDatagramParser;

impl DatagramParser for NoopDatagramParser {
    type Message = ();
    fn parse(&mut self, _payload: &[u8], _side: FlowSide, _ts: Timestamp) -> Vec<()> {
        Vec::new()
    }
}

/// A `SessionParser` that echoes each fed chunk as a side-tagged
/// `Vec<u8>` message. Use when test code wants to inspect the
/// reassembled byte stream.
#[derive(Debug, Default, Clone)]
pub struct EchoSessionParser;

impl SessionParser for EchoSessionParser {
    type Message = (FlowSide, Vec<u8>);
    fn feed_initiator(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        vec![(FlowSide::Initiator, bytes.to_vec())]
    }
    fn feed_responder(&mut self, bytes: &[u8], _ts: Timestamp) -> Vec<Self::Message> {
        vec![(FlowSide::Responder, bytes.to_vec())]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn noop_session_compiles() {
        let mut p = NoopSessionParser;
        assert!(p.feed_initiator(b"hi", Timestamp::default()).is_empty());
        assert!(p.feed_responder(b"hi", Timestamp::default()).is_empty());
    }

    #[test]
    fn noop_datagram_compiles() {
        let mut p = NoopDatagramParser;
        assert!(
            p.parse(b"hi", FlowSide::Initiator, Timestamp::default())
                .is_empty()
        );
    }

    #[test]
    fn echo_session_emits_chunks() {
        let mut p = EchoSessionParser;
        let m = p.feed_initiator(b"hello", Timestamp::default());
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].0, FlowSide::Initiator);
        assert_eq!(m[0].1, b"hello");
    }
}
