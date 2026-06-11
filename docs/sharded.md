# Sharded capture recipe

Pattern for running N flowscope dispatchers in parallel — one
per OS thread, each with its own [`Driver<E>`] + typed
[`SlotHandle`]s. Cross-shard totals merged via
[`std::sync::atomic`] counters or channels.

**Status**: shipped in 0.13 (plan 155). Requires `Driver<E>:
Send + Sync` (plan 156).

## When to shard

| Workload | Shard? | Why |
|---|---|---|
| Multi-Gbps pcap or capture, CPU-bound parsing | **Yes** | A single dispatcher saturates one core at ~1-2 Mpps; sharding lets you go N× |
| HTTP/TLS handshake aggregation with stateful parsers | **Yes** | Per-flow parser state is naturally per-shard; no cross-shard locks |
| Low-volume, single-flow (one TCP connection) | **No** | Cross-thread dispatch overhead exceeds parser cost |
| Cross-flow correlation (e.g., port scans across all sources) | **Depends** | Per-shard PortScanDetector loses sources scanning multiple shards; consider a serial aggregator on one shard |

## Architecture

```text
    pcap file (or live capture)
        │
        ▼ (hash 5-tuple → shard ID, dispatch to that shard's channel)
  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐
  │ shard 0  │  │ shard 1  │  │ shard 2  │  │ shard 3  │
  │ Driver<E>│  │ Driver<E>│  │ Driver<E>│  │ Driver<E>│
  │ + slot   │  │ + slot   │  │ + slot   │  │ + slot   │
  └────┬─────┘  └────┬─────┘  └────┬─────┘  └────┬─────┘
       │             │             │             │
       ▼             ▼             ▼             ▼
   drain loop    drain loop    drain loop    drain loop
       │             │             │             │
       └─────────────┴── cross-shard ────┴───────┘
                       AtomicU64 totals
                          (or channel)
```

Each shard is a self-contained dispatcher: zero cross-shard
contention on the dispatch path. The only synchronisation is
the per-shard input channel (`mpsc::channel<OwnedPacketView>`)
and whatever cross-shard aggregator you choose for results.

## Minimal example

See [`examples/00-getting-started/sharded_capture.rs`](../examples/00-getting-started/sharded_capture.rs)
for a runnable end-to-end demo:

```bash
cargo run --features pcap,http \
    --example sharded_capture -- tests/data/mixed_short.pcap 4
```

The example dispatches by hashing the IPv4 source address;
production code typically uses RSS hashing (from the NIC or
from netring's per-CPU ring queues).

## CPU pinning (optional)

The shipped example doesn't depend on `core_affinity` to stay
portable, but in production you almost certainly want to pin
each shard's worker thread to a specific CPU:

```toml
# Cargo.toml
[dependencies]
core_affinity = "0.8"
```

```rust
let cores = core_affinity::get_core_ids().unwrap();
for shard_id in 0..n_shards {
    let core = cores[shard_id % cores.len()];
    thread::spawn(move || {
        core_affinity::set_for_current(core);
        shard_worker(shard_id, ...)
    });
}
```

Pinning improves cache locality (the shard's per-flow state
stays hot in L2) and avoids cross-CPU migrations during high-
throughput phases.

## Pairing with netring

For Linux capture, [`netring`](https://crates.io/crates/netring)
already provides per-CPU ring buffers via AF_PACKET. The
natural composition is:

- One netring per-CPU queue per shard.
- One flowscope `Driver<E>` per shard, fed from the netring
  queue.
- Cross-shard aggregator drains each shard's `SlotHandle` (or
  `BroadcastSlotHandle` for fan-out subscribers; see plan
  150).

netring 0.21 Phase C documentation cross-references this
recipe.

## Pitfalls

- **Hash function choice.** `hash(src_ip)` works for the demo
  but mis-shards traffic with many flows sharing one source
  (e.g., a load balancer's egress). Prefer the canonical
  5-tuple hash from `flowscope::extract::FiveTupleKey`.
- **Per-shard back-pressure.** Each shard's input channel can
  fill if a worker is slow. Use bounded channels
  (`mpsc::sync_channel(N)`) for back-pressure, or drop on
  overflow. [`SlotHandle::drain_n`] (plan 149) helps cap
  per-iteration drain volume so one busy slot doesn't
  monopolise the shard.
- **Aggregation contention.** `AtomicU64::fetch_add` is fast
  but still a cache-coherency event. For very high-frequency
  updates (per-packet), batch locally and update the global
  counter once per N packets or once per drain pass.
- **Stateful detectors (`PortScanDetector`, `BeaconDetector`)
  are per-shard.** A source scanning N shards will be visible
  on each shard's detector with `1/N` the signal. Run cross-
  shard detectors on a separate single-thread aggregator that
  consumes the per-shard `OwnedAnomaly` streams.
