//! Issue #111 — unified offline lifecycle + message stream.
//!
//! `session_pulses` / `datagram_pulses` interleave flow lifecycle and
//! typed parser messages into one ordered iterator, so a single loop
//! sees `Started → Message* → Ended` with nothing left buffered (the
//! `run_pcap` + separate-slot-drain trailing-drain footgun is gone).

use std::collections::HashMap;

use flowscope::extract::FiveTupleKey;
use flowscope::pcap::{
    Pulse, datagram_messages, datagram_pulses, session_messages, session_pulses,
};
use flowscope::{DatagramParser, FlowSide, SessionParser, Timestamp};

const HTTP_SESSION_PATH: &str = "tests/data/http_session.pcap";
const DNS_QUERIES_PATH: &str = "tests/data/dns_queries.pcap";

/// Emits the byte count of every chunk fed on either side.
#[derive(Default, Clone)]
struct ByteCounter;
impl SessionParser for ByteCounter {
    type Message = usize;
    fn feed_initiator(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
    fn feed_responder(&mut self, b: &[u8], _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(b.len());
    }
}

/// Emits the byte count of every UDP payload.
#[derive(Default, Clone)]
struct DgramSizer;
impl DatagramParser for DgramSizer {
    type Message = usize;
    fn parse(&mut self, payload: &[u8], _side: FlowSide, _ts: Timestamp, out: &mut Vec<usize>) {
        out.push(payload.len());
    }
}

/// For each flow key: the index of its first `Started`, its last
/// `Message`, and its `Ended` in the pulse stream. Asserts the
/// ordering contract — `Started` precedes every message, and every
/// message precedes `Ended` (so the close-flush batch is never
/// stranded after the flow's terminal event).
fn assert_ordering<M>(pulses: &[Pulse<FiveTupleKey, M>]) {
    let mut started: HashMap<FiveTupleKey, usize> = HashMap::new();
    let mut last_msg: HashMap<FiveTupleKey, usize> = HashMap::new();
    let mut ended: HashMap<FiveTupleKey, usize> = HashMap::new();

    for (i, p) in pulses.iter().enumerate() {
        match p {
            Pulse::Started { key, .. } => {
                started.entry(*key).or_insert(i);
            }
            Pulse::Message(m) => {
                last_msg.insert(m.key, i);
            }
            Pulse::Ended { key, .. } => {
                ended.insert(*key, i);
            }
            _ => {}
        }
    }

    for (key, &msg_idx) in &last_msg {
        let s = started.get(key).copied();
        assert!(
            s.is_some_and(|s| s < msg_idx),
            "message on {key:?} arrived before its Started",
        );
        if let Some(&e) = ended.get(key) {
            assert!(
                msg_idx < e,
                "message on {key:?} arrived after its Ended (trailing-drain footgun)",
            );
        }
    }
}

#[test]
fn session_pulses_interleaves_lifecycle_and_messages() {
    let pulses: Vec<_> = session_pulses::<ByteCounter>(HTTP_SESSION_PATH)
        .expect("open pcap")
        .collect();

    let n_started = pulses
        .iter()
        .filter(|p| matches!(p, Pulse::Started { .. }))
        .count();
    let n_msg = pulses
        .iter()
        .filter(|p| matches!(p, Pulse::Message(_)))
        .count();
    let n_ended = pulses
        .iter()
        .filter(|p| matches!(p, Pulse::Ended { .. }))
        .count();

    assert!(n_started >= 1, "at least one flow started");
    assert!(n_msg >= 1, "the session carried payload");
    assert!(n_ended >= 1, "the flow ended (flushed at end-of-pcap)");

    // The unified stream surfaces exactly the same messages as the
    // message-only helper.
    let msg_only = session_messages::<ByteCounter>(HTTP_SESSION_PATH)
        .expect("open pcap")
        .count();
    assert_eq!(
        n_msg, msg_only,
        "pulse Message count == session_messages count"
    );

    assert_ordering(&pulses);
}

#[test]
fn datagram_pulses_interleaves_lifecycle_and_messages() {
    let pulses: Vec<_> = datagram_pulses::<DgramSizer>(DNS_QUERIES_PATH)
        .expect("open pcap")
        .collect();

    let n_msg = pulses
        .iter()
        .filter(|p| matches!(p, Pulse::Message(_)))
        .count();
    assert!(
        pulses.iter().any(|p| matches!(p, Pulse::Started { .. })),
        "at least one datagram flow started",
    );
    assert!(n_msg >= 1, "DNS datagrams produced messages");

    let msg_only = datagram_messages::<DgramSizer>(DNS_QUERIES_PATH)
        .expect("open pcap")
        .count();
    assert_eq!(
        n_msg, msg_only,
        "pulse Message count == datagram_messages count"
    );

    assert_ordering(&pulses);
}
