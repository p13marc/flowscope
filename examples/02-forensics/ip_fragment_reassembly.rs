//! Reassemble fragmented IP datagrams and flag overlap-based
//! evasion (issue #138).
//!
//! A payload split across IP fragments bypasses any L4/L7 parser
//! that only sees the first fragment — the classic Ptacek–Newsham
//! insertion/evasion. `IpFragmentReassembler` stitches the
//! original datagram back together so it can be re-fed to the
//! parser, and — per RFC 5722 — **drops the whole datagram** on
//! overlapping fragments (the teardrop / evasion signature),
//! counting it as an IOC.
//!
//! This example is self-contained (no pcap needed).
//!
//! Usage:
//!     cargo run --example ip_fragment_reassembly

use flowscope::Timestamp;
use flowscope::ip_fragment::{FragmentKey, IpFragmentReassembler};

fn key(id: u32) -> FragmentKey {
    FragmentKey {
        src: "10.0.0.5".parse().unwrap(),
        dst: "10.0.0.9".parse().unwrap(),
        protocol: 6, // TCP
        id,
    }
}

fn main() {
    let mut r = IpFragmentReassembler::new();
    let now = Timestamp::new(0, 0);

    // --- Benign: an HTTP request split across three fragments ---
    // (offsets are byte offsets; IPv4 carries them in 8-byte units,
    // so real fragment payloads are multiples of 8.)
    println!("Reassembling a 3-fragment datagram (id=100):");
    assert!(r.push(key(100), 0, true, b"GET /admin ", now).is_none());
    assert!(r.push(key(100), 11, true, b"HTTP/1.1\r\n", now).is_none());
    let datagram = r
        .push(key(100), 21, false, b"Host: x\r\n\r\n", now)
        .expect("final fragment completes the datagram");
    println!(
        "  reassembled {} bytes: {:?}\n",
        datagram.len(),
        String::from_utf8_lossy(&datagram),
    );

    // --- Malicious: overlapping fragments (teardrop-style) ---
    println!("Feeding overlapping fragments (id=200):");
    r.push(key(200), 0, true, b"AAAAAAAA", now);
    // This fragment overlaps [4, 8) of the first — no legitimate use.
    let out = r.push(key(200), 4, false, b"XXXXXXXX", now);
    println!("  reassembly result: {out:?} (dropped, as expected)");

    println!("\n── summary ──");
    println!("datagrams reassembled : {}", r.reassembled());
    println!("overlap drops (IOC)   : {}", r.overlaps());
    println!("timed out             : {}", r.timed_out());

    assert_eq!(r.reassembled(), 1);
    assert_eq!(r.overlaps(), 1);
}
