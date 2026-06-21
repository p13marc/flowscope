//! Generate the length-prefixed binary protocol pcap fixture.
//!
//! Run with:
//!
//!     cargo run --example gen_length_prefixed_pcap \
//!         --features test-helpers -- tests/fixtures/length_prefixed/sample.pcap
//!
//! Output is deterministic — re-running produces a byte-identical
//! file unless the wire format below is changed.

use std::{
    env,
    fs::{File, create_dir_all},
    io::BufWriter,
    path::PathBuf,
    time::Duration,
};

use flowscope::extract::parse::test_frames::ipv4_tcp;
use pcap_file::{
    DataLink,
    pcap::{PcapHeader, PcapPacket, PcapWriter},
};

const MAC: [u8; 6] = [0; 6];
const IP_A: [u8; 4] = [10, 0, 0, 1];
const IP_B: [u8; 4] = [10, 0, 0, 2];
const PORT_A: u16 = 4321;
const PORT_B: u16 = 5678;

const MARKER_2: &[u8] = b"PFX2,";
const MARKER_4: &[u8] = b"PFX4,";

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path: PathBuf = env::args()
        .nth(1)
        .map(Into::into)
        .unwrap_or_else(|| PathBuf::from("tests/fixtures/length_prefixed/sample.pcap"));

    if let Some(parent) = path.parent() {
        create_dir_all(parent)?;
    }

    let mut pw = pcap_writer(BufWriter::new(File::create(&path)?))?;

    let mut now = Duration::from_secs(0);
    let mut tick = || {
        now += Duration::from_millis(10);
        now
    };

    // 3WHS.
    let syn = ipv4_tcp(MAC, MAC, IP_A, IP_B, PORT_A, PORT_B, 1000, 0, 0x02, b"");
    write(&mut pw, tick(), &syn)?;
    let synack = ipv4_tcp(MAC, MAC, IP_B, IP_A, PORT_B, PORT_A, 5000, 1001, 0x12, b"");
    write(&mut pw, tick(), &synack)?;
    let ack = ipv4_tcp(MAC, MAC, IP_A, IP_B, PORT_A, PORT_B, 1001, 5001, 0x10, b"");
    write(&mut pw, tick(), &ack)?;

    // Initiator side: five PFX2, frames concatenated into one TCP segment.
    let mut init_payload = Vec::new();
    for i in 0u16..5 {
        let body = format!("init-{}", i);
        init_payload.extend_from_slice(MARKER_2);
        init_payload.extend_from_slice(&(body.len() as u16).to_be_bytes());
        init_payload.extend_from_slice(body.as_bytes());
    }
    let init_data = ipv4_tcp(
        MAC,
        MAC,
        IP_A,
        IP_B,
        PORT_A,
        PORT_B,
        1001,
        5001,
        0x18,
        &init_payload,
    );
    write(&mut pw, tick(), &init_data)?;

    // Responder side: four PFX2, frames + one PFX4, frame, all on
    // the same TCP segment.
    let mut resp_payload = Vec::new();
    for i in 0u16..4 {
        let body = format!("resp-{}", i);
        resp_payload.extend_from_slice(MARKER_2);
        resp_payload.extend_from_slice(&(body.len() as u16).to_be_bytes());
        resp_payload.extend_from_slice(body.as_bytes());
    }
    // One PFX4, with a longer body to demonstrate the variable-length-marker case.
    let big = vec![b'X'; 700];
    resp_payload.extend_from_slice(MARKER_4);
    resp_payload.extend_from_slice(&(big.len() as u32).to_be_bytes());
    resp_payload.extend_from_slice(&big);
    let resp_data = ipv4_tcp(
        MAC,
        MAC,
        IP_B,
        IP_A,
        PORT_B,
        PORT_A,
        5001,
        1001 + init_payload.len() as u32,
        0x18,
        &resp_payload,
    );
    write(&mut pw, tick(), &resp_data)?;

    // FIN/FIN/ACK to close the flow cleanly.
    let fin_init = ipv4_tcp(
        MAC,
        MAC,
        IP_A,
        IP_B,
        PORT_A,
        PORT_B,
        1001 + init_payload.len() as u32,
        5001 + resp_payload.len() as u32,
        0x11,
        b"",
    );
    write(&mut pw, tick(), &fin_init)?;
    let fin_resp = ipv4_tcp(
        MAC,
        MAC,
        IP_B,
        IP_A,
        PORT_B,
        PORT_A,
        5001 + resp_payload.len() as u32,
        1002 + init_payload.len() as u32,
        0x11,
        b"",
    );
    write(&mut pw, tick(), &fin_resp)?;
    let last_ack = ipv4_tcp(
        MAC,
        MAC,
        IP_A,
        IP_B,
        PORT_A,
        PORT_B,
        1002 + init_payload.len() as u32,
        5002 + resp_payload.len() as u32,
        0x10,
        b"",
    );
    write(&mut pw, tick(), &last_ack)?;

    eprintln!("✓ wrote {}", path.display());
    Ok(())
}

fn pcap_writer<W: std::io::Write>(w: W) -> Result<PcapWriter<W>, Box<dyn std::error::Error>> {
    let header = PcapHeader {
        version_major: 2,
        version_minor: 4,
        ts_correction: 0,
        ts_accuracy: 0,
        snaplen: 65535,
        datalink: DataLink::ETHERNET,
        ts_resolution: pcap_file::TsResolution::MicroSecond,
        endianness: pcap_file::Endianness::native(),
    };
    Ok(PcapWriter::with_header(w, header)?)
}

fn write(
    pw: &mut PcapWriter<impl std::io::Write>,
    ts: Duration,
    data: &[u8],
) -> Result<(), Box<dyn std::error::Error>> {
    pw.write_packet(&PcapPacket {
        timestamp: ts,
        orig_len: data.len() as u32,
        data: data.into(),
    })?;
    Ok(())
}
