# Migration: 0.16 → 0.17

The **multi-source / RX-metadata / ARP / fingerprint** cycle.
Mostly additive; **two pre-1.0 breaking changes** flagged below
and discussed first.

## §1 BREAKING — `PacketView` and `OwnedPacketView` are `#[non_exhaustive]`

(Issue [#2](https://github.com/p13marc/flowscope/issues/2)).

**Symptom**: code that constructed `PacketView` via struct
literal no longer compiles:

```rust,ignore
// before (0.16 and earlier)
let view = PacketView { frame: &bytes, timestamp: ts };
```

**Fix**: use the constructor (shipped since 0.2) + the new
`.with_rx_metadata(...)` builder.

```rust,ignore
use flowscope::{PacketView, RxMetadata};

// Default — empty rx_metadata.
let view = PacketView::new(&bytes, ts);

// With hardware metadata (typically populated by netring 0.22+
// from the AF_XDP metadata area):
let view = PacketView::new(&bytes, ts).with_rx_metadata(rx);
```

Same shape for `OwnedPacketView::new(...)`.

This breakage unlocks every future `PacketView` field addition
being purely additive. The flowscope dep policy stays *one
breakage now, none later*.

## §2 BREAKING — `MacPairKey::a` / `.b` are `MacAddr`, not `[u8; 6]`

(Issue [#1](https://github.com/p13marc/flowscope/issues/1)).

**Symptom**: code comparing `pair.a` to a raw `[u8; 6]` no
longer compiles.

**Fix**: convert via `MacAddr::from` / `into`:

```rust,ignore
use flowscope::MacAddr;

let key = pair.a;
// before (0.16):
//     if key == [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff] { ... }
// after (0.17):
if key == MacAddr([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]) { ... }

// Or via parse / display:
let target: MacAddr = "aa:bb:cc:dd:ee:ff".parse().unwrap();

// Raw bytes still accessible:
let raw: [u8; 6] = key.into();
let same: &[u8; 6] = key.as_bytes();
```

Plus new predicates: `is_broadcast` / `is_multicast` /
`is_unicast` / `is_locally_administered` / `is_zero` — replace
hand-rolled checks against `[0xff; 6]` etc.

## §3 New — `flowscope::extract::Tagged<E, T>` combinator

(Issue [#5](https://github.com/p13marc/flowscope/issues/5)).

Prefix any extractor's key with a caller-supplied per-packet
tag. Lets multi-source captures (taps, multi-NIC bonds) pick
"per-source attribution" vs "tap-merge" at extractor
registration time. No tracker change required.

```rust,ignore
use flowscope::extract::{FiveTuple, Tagged};

// Per-source attribution — `(source_idx, 5-tuple)` is the key:
let per_source = Tagged::new(
    FiveTuple::bidirectional(),
    |view| view.rx_metadata.source_idx,
);

// Source-merged (tap) — bare 5-tuple, no tag:
let merged = FiveTuple::bidirectional();
```

Function pointers, closures, and custom `Tagger` impls all work.

## §4 New — `flowscope::RxMetadata` on `PacketView`

(Issue [#2](https://github.com/p13marc/flowscope/issues/2)).

```rust,ignore
use flowscope::{
    ChecksumStatus, RssHashType, RxHash, RxMetadata, VlanProto, VlanTag,
};

let rx = RxMetadata {
    hw_timestamp: Some(timestamp),
    rx_hash: Some(RxHash::new(0xdead_beef, RssHashType::L4TcpIpv4)),
    vlan: Some(VlanTag::new(0x0064, VlanProto::Dot1Q)),
    checksum: ChecksumStatus::Unnecessary,
    source_idx: 1,
};
let view = PacketView::new(&bytes, ts).with_rx_metadata(rx);
```

Every field is independently optional / defaulted, so pcap /
synthetic sources need no changes (default is all-absent).

`VlanTag` carries `.vid()` / `.pcp()` / `.dei()` accessors;
`RssHashType` mirrors Linux's `XDP_RSS_TYPE_*` enumeration 1:1.

## §5 New — `arp` feature

(Issue [#1](https://github.com/p13marc/flowscope/issues/1)).

```toml
flowscope = { version = "0.17", features = ["arp"] }
```

```rust,ignore
use flowscope::{arp, ArpMessage, ArpOp};

// Parse an ARP payload (no Ethernet header — caller stripped):
let msg: ArpMessage = arp::parse(&payload).expect("valid arp");

// Or a whole Ethernet frame (strips one 802.1Q VLAN tag):
let msg: ArpMessage = arp::parse_frame(&frame).expect("valid arp");

assert_eq!(msg.oper, ArpOp::Reply);
if msg.is_likely_spoof() {
    eprintln!("ARP spoof: {} claims {} (sender: {})",
        msg.sender_ip, msg.target_ip, msg.sender);
}
```

ARP has no 5-tuple flow, so the parser is a **stateless free
function** rather than a `DatagramParser`. Consumers gate on
EtherType `0x0806` (or use the existing
`flowscope::layers::ArpSlice`) and call `arp::parse` /
`arp::parse_frame`.

## §6 New — `correlate::NeighborTable<L3, L4>`

Always-on (no feature gate). Generic-from-day-one so IPv6 NDP
support layers in without rename.

```rust,ignore
use flowscope::correlate::{NeighborEvent, NeighborTable};
use std::net::Ipv4Addr;
use std::time::Duration;

// `ArpTable = NeighborTable<Ipv4Addr, MacAddr>` is a type alias
// behind the `arp` feature.
let mut table = NeighborTable::<Ipv4Addr, flowscope::MacAddr>::new_unbounded(
    Duration::from_secs(300),
);

match table.observe(msg.sender_ip, msg.sender, now) {
    NeighborEvent::NewBinding { .. } => println!("first sighting"),
    NeighborEvent::Refresh => {}
    NeighborEvent::Changed { prior, new } => {
        eprintln!("rebind: {prior} → {new}");
    }
}
```

## §7 New — `fingerprint` feature

(Issue [#4](https://github.com/p13marc/flowscope/issues/4)).

```toml
flowscope = { version = "0.17", features = ["fingerprint"] }
```

```rust,ignore
use flowscope::detect::{FingerprintBuilder, FlowFingerprint};

let mut fp = FingerprintBuilder::new();
// Per-packet hook — alloc-free; first 32 samples retained.
fp.observe(payload_len, is_initiator, ts_micros);
fp.observe(payload_len, is_initiator, ts_micros);
// ...

// Finalise at flow end:
let final_fp: FlowFingerprint = fp.finish();

// Two consumer surfaces:
let h: u64 = final_fp.fnv1a();              // IOC equality
let features: [f64; 8] = final_fp.as_features(); // ML pipeline
```

Cites Cisco Joy / Mercury SPLT methodology, FoxIO JA4L,
Anderson & McGrew (ACM AISec 2016). Privacy footnote in
module rustdoc.

## §8 Smaller adds

- `MacAddr` newtype at the crate root (see §2).
- `MacAddr::from_str` parses `aa:bb:cc:dd:ee:ff` /
  `aa-bb-cc-dd-ee-ff` (upper- or lower-case) into a `MacAddr`.
- `RxHash::new` + `VlanTag::new` constructors (struct-literal
  blocked by `#[non_exhaustive]`).
- Prelude expanded with: `MacAddr`, `ChecksumStatus`,
  `RxHash`, `RxMetadata`, `RssHashType`, `VlanProto`,
  `VlanTag`, `Tagged`, `TaggedKey`, `ArpMessage`, `ArpOp`
  (gated on `arp`), `NeighborBinding`, `NeighborEvent`,
  `NeighborTable` (gated on `tracker`), `FingerprintBuilder`,
  `FlowFingerprint` (gated on `fingerprint`).
- Several pre-existing types marked `#[non_exhaustive]` for
  future-additivity: `RxHash`, `VlanTag`, `NeighborBinding`,
  `NeighborEvent`, `MacPairKey`.

## §9 Issue #3 (QUIC Initial) — deferred

The fifth opt-in issue (passive QUIC Initial parser with HKDF
key derivation + AES-128-GCM decryption + ClientHello SNI/ALPN
extraction) is genuinely a multi-day cycle on its own (~5-7
days including 3 cargo-fuzz harnesses). It's deferred to a
follow-up release rather than half-shipped.
