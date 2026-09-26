//! Synthetic captures. Frames are Ethernet / IPv4 / TCP|UDP with zero
//! checksums (flowscope does not validate them).

/// One captured frame.
pub struct Packet {
    pub frame: Vec<u8>,
    pub sec: u32,
    pub nsec: u32,
}

/// A scenario's traffic.
#[derive(Default)]
pub struct Capture {
    pub packets: Vec<Packet>,
    /// Index of the packet before which retained memory is sampled.
    pub measure_at: Option<usize>,
}

const SYN: u8 = 0x02;
const ACK: u8 = 0x10;
const PSH_ACK: u8 = 0x18;
const FIN_ACK: u8 = 0x11;

fn eth_ipv4(proto: u8, src: [u8; 4], dst: [u8; 4], l4: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(34 + l4.len());
    f.extend_from_slice(&[0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 1, 0x08, 0x00]);
    let total = (20 + l4.len()) as u16;
    f.extend_from_slice(&[0x45, 0]);
    f.extend_from_slice(&total.to_be_bytes());
    f.extend_from_slice(&[0, 0, 0x40, 0, 64, proto, 0, 0]);
    f.extend_from_slice(&src);
    f.extend_from_slice(&dst);
    f.extend_from_slice(l4);
    f
}

#[allow(clippy::too_many_arguments)]
fn tcp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut t = Vec::with_capacity(20 + payload.len());
    t.extend_from_slice(&sp.to_be_bytes());
    t.extend_from_slice(&dp.to_be_bytes());
    t.extend_from_slice(&seq.to_be_bytes());
    t.extend_from_slice(&ack.to_be_bytes());
    t.extend_from_slice(&[0x50, flags, 0xff, 0xff, 0, 0, 0, 0]);
    t.extend_from_slice(payload);
    eth_ipv4(6, src, dst, &t)
}

fn udp(src: [u8; 4], dst: [u8; 4], sp: u16, dp: u16, payload: &[u8]) -> Vec<u8> {
    let mut u = Vec::with_capacity(8 + payload.len());
    u.extend_from_slice(&sp.to_be_bytes());
    u.extend_from_slice(&dp.to_be_bytes());
    u.extend_from_slice(&((8 + payload.len()) as u16).to_be_bytes());
    u.extend_from_slice(&[0, 0]);
    u.extend_from_slice(payload);
    eth_ipv4(17, src, dst, &u)
}

/// A TCP connection being written into a capture.
struct Conn {
    c: [u8; 4],
    s: [u8; 4],
    cp: u16,
    sp: u16,
    cseq: u32,
    sseq: u32,
}

struct Clock(u64);
impl Clock {
    fn tick(&mut self) -> (u32, u32) {
        self.tick_by(10_000) // 10 µs per packet
    }
    fn tick_by(&mut self, ns: u64) -> (u32, u32) {
        self.0 += ns;
        ((self.0 / 1_000_000_000) as u32 + 1_000, (self.0 % 1_000_000_000) as u32)
    }
}

impl Conn {
    fn new(i: u32, sp: u16) -> Conn {
        Conn {
            c: [10, 1, (i >> 8) as u8, i as u8],
            s: [10, 2, 0, 1],
            cp: 10_000 + (i % 50_000) as u16,
            sp,
            cseq: 1_000 + i.wrapping_mul(7919),
            sseq: 50_000 + i.wrapping_mul(104_729),
        }
    }
    fn push(&self, cap: &mut Capture, clk: &mut Clock, frame: Vec<u8>) {
        let (sec, nsec) = clk.tick();
        cap.packets.push(Packet { frame, sec, nsec });
    }
    fn handshake(&mut self, cap: &mut Capture, clk: &mut Clock) {
        let f = tcp(self.c, self.s, self.cp, self.sp, self.cseq, 0, SYN, b"");
        self.push(cap, clk, f);
        let f = tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq + 1, SYN | ACK, b"");
        self.push(cap, clk, f);
        self.cseq += 1;
        self.sseq += 1;
        let f = tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, ACK, b"");
        self.push(cap, clk, f);
    }
    /// Client data; `lost` = consume sequence space without capturing it.
    fn client(&mut self, cap: &mut Capture, clk: &mut Clock, data: &[u8], lost: bool) {
        if !lost {
            let f = tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, PSH_ACK, data);
            self.push(cap, clk, f);
        }
        self.cseq = self.cseq.wrapping_add(data.len() as u32);
    }
    fn server(&mut self, cap: &mut Capture, clk: &mut Clock, data: &[u8]) {
        let f = tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, PSH_ACK, data);
        self.push(cap, clk, f);
        self.sseq = self.sseq.wrapping_add(data.len() as u32);
    }
    fn close(&mut self, cap: &mut Capture, clk: &mut Clock) {
        let f = tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, FIN_ACK, b"");
        self.push(cap, clk, f);
        self.cseq += 1;
        let f = tcp(self.s, self.c, self.sp, self.cp, self.sseq, self.cseq, FIN_ACK, b"");
        self.push(cap, clk, f);
        self.sseq += 1;
        let f = tcp(self.c, self.s, self.cp, self.sp, self.cseq, self.sseq, ACK, b"");
        self.push(cap, clk, f);
    }
}

const REQ: &[u8] = b"GET /index.html HTTP/1.1 host example.org accept */* user-agent compat\n";
const OTHER: &[u8] = b"XYZ binary-ish protocol request payload that is not http at all ....\n";
const RESP: &[u8] = b"HTTP/1.1 200 OK content-length 0 server compat date today etag abcdef\n";

/// `flows` sequential connections, `exchanges` request/response pairs
/// each. `lose` = index of the one initiator segment per flow that is
/// never captured.
pub fn line_flows(flows: u32, exchanges: usize, port: u16, lose: Option<usize>) -> Capture {
    let mut cap = Capture::default();
    let mut clk = Clock(0);
    for i in 0..flows {
        let mut c = Conn::new(i, port);
        c.handshake(&mut cap, &mut clk);
        for x in 0..exchanges {
            c.client(&mut cap, &mut clk, REQ, lose == Some(x));
            c.server(&mut cap, &mut clk, RESP);
        }
        c.close(&mut cap, &mut clk);
    }
    cap
}

/// Half the flows start with `GET`, half do not; port 8080.
pub fn heuristic_flows(flows: u32, exchanges: usize) -> Capture {
    let mut cap = Capture::default();
    let mut clk = Clock(0);
    for i in 0..flows {
        let mut c = Conn::new(i, 8080);
        c.handshake(&mut cap, &mut clk);
        let req = if i % 2 == 0 { REQ } else { OTHER };
        for _ in 0..exchanges {
            c.client(&mut cap, &mut clk, req, false);
            c.server(&mut cap, &mut clk, RESP);
        }
        c.close(&mut cap, &mut clk);
    }
    cap
}

/// `n` UDP query/response pairs on distinct flows.
pub fn dns_pairs(n: u32) -> Capture {
    let mut cap = Capture::default();
    let mut clk = Clock(0);
    let q = [0x12u8, 0x34, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 3, b'w', b'w', b'w', 0, 0, 1, 0, 1];
    for i in 0..n {
        let c = [10, 1, (i >> 8) as u8, i as u8];
        let s = [10, 2, 0, 53];
        let cp = 20_000 + (i % 40_000) as u16;
        let (sec, nsec) = clk.tick();
        cap.packets.push(Packet { frame: udp(c, s, cp, 53, &q), sec, nsec });
        let (sec, nsec) = clk.tick();
        cap.packets.push(Packet { frame: udp(s, c, 53, cp, &q), sec, nsec });
    }
    cap
}

/// `n` concurrent flows: all handshakes, one exchange each (retained
/// memory is sampled here, every flow open and idle), then all closes.
pub fn many_open_flows(n: u32) -> Capture {
    let mut cap = Capture::default();
    let mut clk = Clock(0);
    let mut conns: Vec<Conn> = (0..n).map(|i| Conn::new(i, 80)).collect();
    for c in conns.iter_mut() {
        c.handshake(&mut cap, &mut clk);
    }
    for c in conns.iter_mut() {
        c.client(&mut cap, &mut clk, REQ, false);
        c.server(&mut cap, &mut clk, RESP);
    }
    cap.measure_at = Some(cap.packets.len());
    for c in conns.iter_mut() {
        c.close(&mut cap, &mut clk);
    }
    cap
}

/// One flow: the initiator's first byte never arrives, then `bytes`
/// one-byte segments arrive in reverse order above it.
pub fn reverse_ooo(bytes: usize) -> Capture {
    one_byte_ooo(bytes, true)
}

/// Like [`reverse_ooo`], ascending order.
pub fn ascending_ooo(bytes: usize) -> Capture {
    one_byte_ooo(bytes, false)
}

fn one_byte_ooo(bytes: usize, reverse: bool) -> Capture {
    let mut cap = Capture::default();
    // 1 µs per packet: the whole run stays inside the 1 s OOO deadline.
    let mut clk = Clock(0);
    let mut c = Conn::new(1, 80);
    c.handshake(&mut cap, &mut clk);
    let base = c.cseq;
    // One in-order byte anchors the stream origin; offset 1 never arrives.
    let f = tcp(c.c, c.s, c.cp, c.sp, base, c.sseq, PSH_ACK, b"x");
    c.push(&mut cap, &mut clk, f);
    let top = bytes as u32 + 1;
    let offs: Vec<u32> = if reverse { (2..=top).rev().collect() } else { (2..=top).collect() };
    for off in offs {
        let f = tcp(c.c, c.s, c.cp, c.sp, base.wrapping_add(off), c.sseq, PSH_ACK, b"x");
        let (sec, nsec) = clk.tick_by(1_000);
        cap.packets.push(Packet { frame: f, sec, nsec });
    }
    cap
}
