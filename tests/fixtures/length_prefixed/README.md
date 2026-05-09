# `length_prefixed/sample.pcap`

Synthetic pcap fixture for `examples/length_prefixed_pcap.rs` and
`tests/length_prefixed_example.rs`.

## Wire format

Each on-the-wire frame is one of:

```
┌────────┬──────────┬────────────────┐
│ marker │ length   │ body           │
│ "PFXn," │ u16/u32  │ body_len bytes │
└────────┴──────────┴────────────────┘
```

- `PFX2,` → 2-byte big-endian u16 length (7-byte header total).
- `PFX4,` → 4-byte big-endian u32 length (9-byte header total).

Body is opaque payload bytes; the parser hands them back as
`Vec<u8>`.

## Contents

- IPv4 + TCP exchange between `10.0.0.1:4321` ↔ `10.0.0.2:5678`.
- Three-way handshake (SYN / SYN-ACK / ACK).
- Initiator → responder TCP segment carrying five `PFX2,` frames
  (`init-0`..`init-4`, each 6-byte body).
- Responder → initiator TCP segment carrying four `PFX2,` frames
  (`resp-0`..`resp-3`, each 6-byte body) plus one `PFX4,` frame
  with a 700-byte body to exercise the longer-marker code path.
- Clean FIN / FIN / ACK termination.

Total: 10 length-prefixed messages on the wire (5 initiator, 5 responder).

## Regenerating

The pcap is deterministic — re-running the generator produces a
byte-identical file. To regenerate after changing the wire format
or the fixture parameters:

```sh
cargo run --example generate_length_prefixed_pcap \
    --features test-helpers,pcap -- \
    tests/fixtures/length_prefixed/sample.pcap
```

The generator lives at `examples/generate_length_prefixed_pcap.rs`.
