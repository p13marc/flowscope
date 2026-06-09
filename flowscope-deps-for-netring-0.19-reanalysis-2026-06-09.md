# Re-analysis: flowscope dependencies for netring 0.19

**Date:** 2026-06-09
**Reviewer:** flowscope maintainer (second pass)
**Companion to:** [`flowscope-deps-for-netring-0.19-2026-06-09.md`](./flowscope-deps-for-netring-0.19-2026-06-09.md)

**Verdict in one paragraph.** The original report is broadly right about
*direction* — flowscope must ship first, netring's zero-allocation claim is
real, and item 3.1 (`track_into`) is the keystone — but two of its six items
recommend shapes I'd reject (3.2 `&mut Vec` parameter, 3.4 TypeId-keyed
push dispatch), one is under-scoped (3.3 partial-Bytes), and the report
misses four allocations on the hot path that are larger than any single
item it flags. Net of the changes I propose below, flowscope 0.11 is
**~14–18 working days**, not 9–12, and is a fundamentally cleaner break
than the original "0.10.2 + 0.11" split. I recommend collapsing the two
phases into one breaking 0.11 release and using the slack to fix the
allocations the report missed.

---

## 1. Methodology

I re-read the original report end-to-end, then ground-truthed each claim
against the actual code at HEAD (0.10.1):

- `src/driver_unified/mod.rs` (the central Driver and its track loop)
- `src/driver_unified/erased.rs` (the per-slot dispatch shape)
- `src/session.rs` (the SessionParser / DatagramParser trait shapes)
- `src/http/types.rs`, `src/dns/types.rs`, `src/tls/types.rs`,
  `src/icmp/types.rs` (parsed-message payload shapes — where the
  per-message allocations actually live)

Where the original report cited code by line number, I re-walked the
function bodies to check whether the proposed change is sufficient (it
often isn't — neighbouring lines allocate too).

Each finding below is graded:

- ✅ **Agree** — the original report has it right, ship as-is.
- 🟡 **Agree with reservations** — direction is right, shape is wrong.
- 🔴 **Disagree** — the proposed shape is the wrong solution.
- 🆕 **Missing** — the original report does not address this and it
  matters at least as much as the items it does address.

---

## 2. Where I agree with the original report (3 items)

### 2.1 ✅ Item 3.1 — `Driver::track_into(view, &mut Vec<Event>)`

Right diagnosis, right fix, correct effort estimate (~1 day). The
keystone change for the whole story. Caveat: the current `track()` body
has three downstream allocations per call that 3.1 alone doesn't
eliminate (see §4.1 below). `track_into` is necessary but not sufficient.

### 2.2 ✅ Item 3.5 — `parser_kinds::TLS_HANDSHAKE`

Five-minute fix. No notes.

### 2.3 ✅ Sequencing recommendation (Option α — flowscope first)

This is correct and I'd go further: do not start netring 0.19 against an
intermediate flowscope 0.10.2. The 2-week dependency is honest. Ship
the whole break as 0.11 once and migrate netring against a stable
target — see §6 for sequencing.

### 2.4 ✅ Dependency-direction argument

"netring 0.19 will accumulate v0.19 workarounds that v0.20 has to
delete" — yes. The report's framing here is correct and is the strongest
argument in the document. Do not split flowscope work across two
releases just to unblock netring sooner; the throwaway-work cost
dominates.

---

## 3. Where I disagree (3 items)

### 3.1 🟡 Item 3.2 — Parser scratch reuse: wrong API shape

The original report proposes:

```rust
fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: &mut Vec<Self::Message>);
```

Three problems:

**1. The signature change is *invasive* and not the cheapest path.**
Five shipped parsers, ~20 callsites in tests/examples, and any
third-party `SessionParser` impl all break. The breakage is mechanical
but spreads across every consumer regardless of whether they care
about zero-alloc.

**2. The premise is overstated.** `Vec::new()` does **not** allocate;
it's a stack-only sentinel until first `push`. The report's "1M
`Vec::new()` calls per second" is misleading — the cost is dominated
by the `push`-then-drop cycle when messages actually fire, not by
the `Vec::new()` itself. The breakage forecast in 3.2 needs to be
weighed against the *real* hot-path arithmetic: at the realistic
"10% of packets contain L7 data" figure, the parser-scratch cost is
~100k allocations/sec, which is ~5–10 µs/sec of allocator work, or
0.001% of a core. Worth eliminating eventually; not urgent enough to
justify breaking every consumer's parser if there's a cheaper path.

**3. The API loses information.** `&mut Vec<Message>` is the *largest*
output container the parser can want. The parser typically produces
0–4 messages per call (the report itself notes this); forcing a
heap-backed `Vec` for the rare 5+-message case penalises the common case.

**Better shapes:**

- **Generic accumulator `Output: Extend<Self::Message>`:**

  ```rust
  fn feed_initiator<O: Extend<Self::Message>>(
      &mut self, bytes: &[u8], ts: Timestamp, out: &mut O,
  );
  ```

  Caller picks `Vec`, `SmallVec`, `ArrayVec`, an mpsc-sender, an
  `Extend`-ing closure, whatever fits. One generic bound; no breakage
  beyond the signature; ergonomic for everyone. The drawback —
  trait-method generics are not object-safe — does not bite us
  because `Driver` already monomorphises per parser inside
  `ConcreteSlot<E, P, M, F>`; we don't ever store `Box<dyn
  SessionParser>` at runtime today and shouldn't.

- **Concrete `OutBuf<M>` newtype (if object-safety is wanted as a
  future option):**

  ```rust
  pub struct OutBuf<'a, M> { inner: &'a mut Vec<M> }
  impl<'a, M> OutBuf<'a, M> {
      pub fn push(&mut self, m: M);
      pub fn extend(&mut self, it: impl IntoIterator<Item = M>);
  }

  fn feed_initiator(&mut self, bytes: &[u8], ts: Timestamp, out: OutBuf<'_, Self::Message>);
  ```

  Object-safe, single-type method signature, hides the underlying
  container so we can swap `Vec` for an arena later without another
  break. **My pick.**

- **Return `SmallVec<[Self::Message; 4]>` (the report's rejected Option B):**

  The report dismisses this as "less clean composition with
  `track_into`." It's actually *more* aligned with the existing API
  shape — every parser already buffers its messages internally
  before returning the Vec; the change is just the return type. No
  caller-supplied scratch needed. The cost is 4 stack slots per call
  even for empty outputs (typically `4 * sizeof(Message)` = 200–400
  bytes on the stack — fine).

  This is the right call if (and only if) we want to ship 0.11 fast
  with minimal API breakage. Less ambitious than the `OutBuf`
  approach but a strict improvement over today.

**My recommendation:** ship the `OutBuf<'_, M>` shape. ~2 days effort
matches the report's estimate but produces a cleaner trait with one
named extension point we can evolve.

### 3.2 🟡 Item 3.3 — HTTP headers: don't half-ship it

The original report proposes:

> ship the smaller alternative (values to `Bytes`, names stay `String`)
> in flowscope 0.11, full `Bytes`-both in 0.12.

This is wrong on two axes:

**1. Two flavours of the same field doubles confusion** for marginal
delivery acceleration. Two consumer reading patterns
(`name.as_str()` for one, `&value[..]` for the other); two
allocation footprints; two migration documents.

**2. The marginal cost is real but not in HTTP alone.** A full Bytes
audit across the L7 types (§4.4 below) finds these still-owned-but-
parseable-zero-copy payloads:

- `dns::DnsRdata::TXT(Vec<Vec<u8>>)` — every TXT record allocates
  twice (outer Vec + inner Vec per record).
- `dns::DnsRdata::Other { data: Vec<u8> }` — every unknown RR type
  allocates.
- `tls::TlsClientHello::compression: Vec<u8>` — small but allocates
  per handshake.
- `http::HttpResponse::reason: String` — small but allocates per
  response.

The "halfway HTTP headers" change leaves all four of these alone, so
0.12 still has to ship a follow-up audit. Better to do the audit
once.

**My recommendation:** ship a single `bytes`-everywhere migration in
0.11, covering all four sites above. ~2 days total (vs. 0.5 day for
the partial). Eliminates a class of allocations rather than half of
one site's.

### 3.3 🔴 Item 3.4 — Multi-typed `Driver`: TypeId-keyed callback is the wrong abstraction

This is the largest disagreement.

The original report proposes:

```rust
pub fn on<M: Send + 'static>(&mut self, cb: impl FnMut(&M, &EventMeta) + Send + 'static);
fn dispatch_message<M: Send + 'static>(&mut self, msg: &M, meta: &EventMeta) {
    if let Some(cb) = callbacks_by_type.get_mut(&TypeId::of::<M>()) { cb(msg as &dyn Any, meta); }
}
```

I have four objections:

**Objection 1 — it inverts the iteration model.** Today flowscope is
pull-based: `for ev in driver.track(...) { ... }`. Composes with
anything (iterators, channels, batching, retries). The proposed
`on::<M>(cb)` is push-based: the parser fires the callback as a side
effect of `track`. These are fundamentally different control flows.
Some consumers actively need pull (batching DB writes, building
columnar views, async backpressure). Adding push *alongside* pull
gives flowscope two competing APIs for the same job; switching the
default to push regresses every existing consumer.

**Objection 2 — it destroys cross-protocol ordering.** With per-type
callbacks, an HTTP request and a DNS query observed in the same
sweep arrive in *callback registration order*, not in
*observation order*. For correlation analysis — "DNS query at T,
then HTTPS handshake at T+5ms to the resolved IP" — this is fatal.
The pull model preserves ordering for free.

**Objection 3 — the TypeId-keyed dispatch is unsound under
type-monomorphisation collisions.** `TypeId::of::<T>()` is only
stable per-binary, not per-build, and (importantly) different `T`
with the same shape *can* share TypeIds across `cfg`-feature
boundaries. The report's "downcast invariant" assumes no two
parser-emitted message types share a TypeId. Today's payload types
satisfy this; the moment a third-party parser ships a tuple-typed
message (which `From` blanket impls invite), the invariant breaks
silently — a debug `expect` doesn't catch it.

**Objection 4 — the design is incompatible with `track_into`.** Push
dispatch happens *inside* the parser-feed path. `track_into(view,
&mut out)` returns a Vec of events; the proposed `on::<M>` runs
callbacks before `track_into` returns. So the consumer sees either
`out` populated *and* callbacks fired (double delivery) or `out`
empty *and* callbacks fired (silent split surface). No clean way to
unify.

**The actual problem:** netring wants typed dispatch with zero per-
message allocation. The Box<dyn Any> wrapper from `Erased` is bad.
That's the constraint. The solution does not need to be push-based.

**Three alternative designs that solve the constraint cleanly:**

**Alternative A — Typed slot drain handles (my pick).**

```rust
let (mut driver, http_slot, dns_slot) = Driver::builder(FiveTuple::bidirectional())
    .session(HttpParser::default())   // returns Slot<HttpMessage>
    .session(DnsTcpParser::default())  // returns Slot<DnsMessage>
    .build();

// Driver::track_into returns ONLY flow-lifecycle events, typed `Event<K, ()>`.
// L7 messages drain from each slot's typed handle:
driver.track_into(view, &mut flow_buf);
for msg in http_slot.drain(&mut http_buf) { ... }
for msg in dns_slot.drain(&mut dns_buf) { ... }
```

Properties:
- Zero `Box` per message — slot's internal buffer is `Vec<HttpMessage>`.
- Cross-protocol ordering preserved by interleaving the drain calls
  (or, if explicit ordering matters, slot handles can expose a
  per-message `seq` field).
- No TypeId trickery; the type system enforces correctness.
- Compatible with `track_into` (which becomes "flow events only").
- Third-party parsers work: their `Slot<TheirMessage>` is just
  another typed handle.
- Trade-off: the Driver type is generic over the *list* of slot
  types. We solve that with the builder's typestate (each `.session`
  call adds one slot type to the tuple), or with a simpler runtime-
  HashMap shape keyed by `&'static str` parser-kind labels (the
  user supplies the type at drain time).

**Alternative B — Compile-time sum-type via derive macro.**

```rust
#[derive(flowscope::MessageSum)]
enum MyMessages {
    Http(HttpMessage),
    Dns(DnsMessage),
}

let mut driver = Driver::<_, MyMessages>::builder(FiveTuple::bidirectional())
    .session(HttpParser::default())     // From<HttpMessage> for MyMessages auto-derived
    .session(DnsTcpParser::default())   // ditto
    .build();
```

Properties:
- Keeps the existing `Driver<E, M>` shape.
- `lift` closures disappear (`From::from` everywhere).
- Zero `Box` — the variant tag is one `u32` discriminant.
- Cross-protocol ordering preserved (events flow through the unified
  Vec).
- Third-party-protocol story: user adds a variant to their sum,
  recompiles. That's *not* hostile; it's how Rust enums work. The
  report dismisses this too quickly.
- Trade-off: macro complexity. A two-line declarative macro suffices
  for the From impls; the discriminant fits in 4 bytes per event.

**Alternative C — Arena-allocated typed messages, references in events.**

```rust
pub struct Arena { bump: bumpalo::Bump }
pub enum Event<'a, K, M> {
    Message { key: K, message: &'a M, ... },
    FlowStarted { ... },
}

driver.track_into(view, &mut arena, &mut out);
// `out: Vec<Event<'_, K, M>>` borrows from `arena`
for ev in &out { ... }
arena.reset();
out.clear();
```

Properties:
- True zero-allocation in steady state (arena grows once, resets).
- Lifetimes on `Event` and the parser surface — invasive.
- Cross-protocol ordering preserved.
- Trade-off: lifetime burden on users; precludes `Send`-across-tasks
  shapes that netring needs.

**My recommendation:** **Alternative A** (typed slot drain handles).
It's the cleanest fit for netring's `monitor.protocol::<Http>()` model
(each `.protocol::<P>()` call literally maps to one slot drain),
preserves the pull-based iteration model, doesn't need a macro, and
the typestate-builder shape is well-trodden Rust. Effort: 6–8 days
including a benchmark suite that proves out the zero-alloc claim.

If 6–8 days is too long, **Alternative B** is a 4-day fallback that
preserves more of today's API shape at the cost of a small macro.

I'd reject the original report's TypeId-callback approach.

---

## 4. What the original report missed (4 items)

These are allocations on the same hot path the report measures, but
either larger per-call than the items the report flags or systemic
enough that 0.11 should fix them in one go.

### 4.1 🆕 The slot dispatch is N`.collect()` per packet

The report's §3.1 (`track_into`) covers the *driver-level* Vec. But
walking `src/driver_unified/erased.rs:88-99`, every slot's `track`
allocates a fresh Vec independently:

```rust
fn track(&mut self, view: PacketView<'_>, ts: Timestamp) -> Vec<Event<E::Key, M>> {
    if let Some(ports) = &self.ports
        && !view_matches_ports(view, ports)
    {
        return Vec::new();  // ← cheap (no alloc) but
    }
    let parser_kind = self.parser_kind;
    self.driver
        .track(view)                          // ← FlowSessionDriver::track also allocates
        .into_iter()
        .filter_map(|e| lift_event(e, &self.lift, ts, parser_kind))
        .collect()                             // ← allocates again
}
```

So per slot per packet today: **2 Vec allocations from `.collect()`
calls + 1 Vec allocation from the underlying `FlowSessionDriver::track`**.
With 5 registered slots that's 15 allocations per packet, dwarfing
the driver-level Vec the report focuses on.

`track_into` as proposed at the driver layer doesn't fix this — the
slot trait method `DriverSlot::track` still returns a Vec. The fix has
to thread `&mut Vec<Event>` (or `OutBuf`) all the way through
`FlowSessionDriver::track` and the slot trait method.

**Required change:** plumb `&mut Vec<Event<K, M>>` through:

```rust
pub(super) trait DriverSlot<K, M>: Send {
    fn track_into(&mut self, view: PacketView<'_>, ts: Timestamp, out: &mut Vec<Event<K, M>>);
    fn sweep_into(&mut self, now: Timestamp, out: &mut Vec<Event<K, M>>);
    fn finish_into(&mut self, out: &mut Vec<Event<K, M>>);
}
```

Inside the slot impl, the parser-feed and the `lift_event` mapping
both write into `out` directly — no `.collect()`. The Driver hands
its `out` parameter down through every slot in sequence.

This is the real ~2-day item, not the surface-level `track_into`.

### 4.2 🆕 `emit_packet_details` clones the entire frame

`src/driver_unified/mod.rs:155`:

```rust
let (tcp_for_packet, frame_for_packet): (Option<TcpInfo>, Option<Vec<u8>>) =
    if self.emit_packet_details {
        let tcp = self.extractor.extract(view).and_then(|e| e.tcp);
        (tcp, Some(view.frame.to_vec()))  // ← frame copy, 64–1500 bytes per packet
    } else {
        (None, None)
    };
```

When `emit_packet_details(true)` is set (which the original report's
§3.1 `track_into` does not affect), every packet causes a
`view.frame.to_vec()` — copying the entire Ethernet frame into a fresh
`Vec<u8>`. At 1 Mpps with 1500-byte frames that's 1.5 GB/sec of
allocator throughput.

**Required change:** `Event::FlowPacket::frame` becomes `Option<Bytes>`
sharing the underlying `Bytes` backing the original `PacketView` (which
requires `PacketView` to hold a `Bytes` rather than `&[u8]` — a fairly
big change), OR `Option<Cow<'p, [u8]>>` (cleaner, requires lifetime on
`Event`), OR the field is removed entirely and the user is expected to
keep the original `PacketView` around if they want frame bytes.

My recommendation: **remove the field**. `emit_packet_details(true)`'s
job is to populate `tcp: Option<TcpInfo>` — that's the actually-useful
bit. The frame bytes are redundant with the source `PacketView` the
caller already holds. Two days of API shrinkage saves the 1.5 GB/sec
allocation.

This was not in the original report at all and is a bigger
allocation than items 3.1/3.2/3.3 combined.

### 4.3 🆕 `Vec<Box<dyn DriverSlot>>` is a pointer chase per slot per packet

Walking `src/driver_unified/mod.rs:182`:

```rust
for slot in &mut self.slots {
    out.extend(slot.track(view, ts));
}
```

`self.slots: Vec<Box<dyn DriverSlot<E::Key, M>>>`. Each iteration:
- Loads the next Box pointer from `slots[i]` (cache hit, usually).
- Dereferences the Box (cache miss, vtable lookup) — ~50ns at L2-miss
  latency.
- Indirect vtable call into `track` — branch predictor unhappy.

With 5 slots, 5 indirect calls per packet. At 1 Mpps that's 250ns/pkt
or ~25% of a single core's per-packet budget on a Cortex-like CPU
that's nominally 1µs/pkt at 1 Mpps. Larger than any allocation item.

**Possible mitigations:**
- **Static dispatch via a typestate Driver:** when the slot list is
  fixed at build time, generate a concrete `Driver<E, S1, S2, S3>`
  with each slot's type known. The for-loop becomes 5 inlined calls.
  Compile-time complexity moderate; runtime cost zero.
- **`Vec<*const dyn DriverSlot, dyn DriverSlot>` (wide pointer
  layout):** removes the Box indirection at the cost of slot lifetime
  trickery. Probably not worth it.
- **`enum SlotKind { Http(...), Dns(...), ... }` discriminant:** with
  Alternative B from §3.3 above, the slot Vec becomes
  `Vec<SlotKind<M>>` — one indirect call per packet (the match), not
  one per slot.

This is co-design with the §3.3 alternative-A or -B decision and adds
~1 day.

### 4.4 🆕 Owned strings/Vecs across DNS / TLS / HTTP message types

The original report's §3.3 only covers HTTP headers. The full Bytes
audit (grepped `(String|Vec<u8>)` across the L7 types):

| File | Field | Cost per message |
|---|---|---|
| `http/types.rs:7` | `HttpRequest::method: String` | 1 small alloc (3–7 bytes) |
| `http/types.rs:8` | `HttpRequest::path: String` | 1 alloc (10–100 bytes) |
| `http/types.rs:12` | `HttpRequest::headers: Vec<(String, Vec<u8>)>` | 1 + 2×N allocs (N≈10) |
| `http/types.rs:25` | `HttpResponse::headers: Vec<(String, Vec<u8>)>` | same |
| `http/types.rs:23` | `HttpResponse::reason: String` | 1 small alloc |
| `dns/types.rs:70` | `DnsRdata::TXT(Vec<Vec<u8>>)` | 1 + N allocs per TXT |
| `dns/types.rs:76` | `DnsRdata::Other { data: Vec<u8> }` | 1 alloc per unknown RR |
| `tls/types.rs:22` | `TlsClientHello::compression: Vec<u8>` | 1 small alloc per handshake |

Total per HTTP message: ~24 allocations. Per DNS response with 5 TXT
records: ~7 allocations. Per TLS handshake: 1 small alloc.

The report's "values-only Bytes" half-fix saves 10 of the HTTP
allocations. A full audit-and-convert saves ~30 across HTTP + DNS +
TLS.

**Required change:** everywhere a Vec<u8> / String holds parsed-from-
the-wire content and the parser has the original Bytes in hand,
convert to `Bytes` (zero-copy slice into the source). Where the
content is fixed-vocabulary (HTTP methods, TLS version strings,
DNS opcodes), keep `&'static str` references (interning).

Effort: 2–3 days. Larger than the report estimates because it covers
more sites, but the work is mechanical and amounts to a single PR.

---

## 5. Summary — revised work items

| # | Original report | My take | Effort | Notes |
|---|---|---|---|---|
| 3.1 | Driver::track_into | ✅ Agree, ship as-is | 1 d | Necessary but not sufficient |
| 3.2 | Parser `&mut Vec` | 🟡 Disagree on shape | 2 d | Use `OutBuf<'_, M>` newtype |
| 3.3 | HTTP headers (partial) | 🟡 Disagree on scope | 2–3 d | Full Bytes audit across HTTP/DNS/TLS |
| 3.4 | TypeId-keyed callbacks | 🔴 Disagree on design | 6–8 d | Use typed slot drain handles |
| 3.5 | TLS_HANDSHAKE constant | ✅ Agree | 5 min | |
| 3.6 | slot_by_kind accessor | ✅ Agree (subsumed by 3.4) | 0 d | Falls out of typed slots |
| 4.1 | (not in original) | 🆕 Add | 2 d | Plumb `&mut Vec` through slot trait |
| 4.2 | (not in original) | 🆕 Add | 0.5 d | Remove `Event::FlowPacket::frame` |
| 4.3 | (not in original) | 🆕 Add | 1 d | Static-dispatch the slot list |
| 4.4 | (not in original) | 🆕 Add — subsumes 3.3 | (in 3.3) | One Bytes audit, all L7 types |

**Total revised flowscope-side effort:** ~14–18 working days for the
full break, vs. the original report's ~9–12 days for a partial fix.

The extra 5–6 days buys:
- ~30 allocations/message eliminated (vs. ~10).
- The 1.5 GB/sec frame-copy cliff fixed.
- Slot dispatch indirection eliminated.
- One coherent breaking change instead of two.

---

## 6. Sequencing — revised

The original report proposed two options (α: flowscope first;
β: netring first with Erased wrapper, refactor in 0.20). I propose a
third:

### Option δ — one coherent 0.11 break, benchmark-driven

```
Week 1:    Phase 0 — benchmark baseline.
           Set up criterion benches that measure exact per-packet
           allocation count (via #[global_allocator] with a counting
           wrapper) at 1 Mpps with 0 / 1 / 5 slots, with and
           without parsed L7 traffic. This is the ground truth we
           measure every subsequent phase against.
Week 2-3:  Phase 1 — track_into + parser sink + slot threading.
           Items 3.1, 3.2 (as OutBuf), 4.1, 4.3. Single coherent
           commit chain. After: every parser-emitted message lands
           in caller-supplied storage with zero allocation in steady
           state.
Week 3:    Phase 2 — Bytes audit.
           Items 3.3 ⊕ 4.4. One PR, all L7 types touched.
Week 4-5:  Phase 3 — typed slot drains.
           Item 3.4 alternative A. Includes the typestate-builder
           and the netring-redesign-compatible Slot<P::Message> API.
Week 5:    Phase 4 — small wins.
           Items 3.5, 4.2. Quick cleanups.
Week 6:    Phase 5 — bench + ship.
           Run the Phase 0 benches against the final result, publish
           the numbers in the release notes, version 0.10.1 → 0.11.0,
           publish, write the migration guide.
Week 7-11: netring 0.19 implementation against frozen flowscope 0.11.
```

**Why I propose this over the original Option α:**

1. **One break, not two.** The report's "ship 3.1/3.2/3.3 as 0.10.2,
   then 3.4 as 0.11" forces the netring author to migrate twice and
   forces every flowscope third-party consumer to migrate twice.
   Patch-then-break is a worse migration story than "one well-
   announced break at the version boundary."

2. **Benchmarks first, then code.** The whole story is perf. If
   Phase 0 reveals that allocation count is actually fine in steady
   state (because Vec capacity gets reused via amortization across
   `extend` calls), we can scale back items 3.2 / 4.1 and ship 0.11
   in 2 weeks. If Phase 0 reveals worse problems than the report
   measures, we know before committing to a particular shape.

3. **Better alignment with netring's release cycle.** The user said
   netring 0.19 is the target. Spending an extra week on flowscope
   0.11 to get it right is dwarfed by the cost of netring 0.19
   release-blocking on a flowscope bug.

---

## 7. Risks and mitigations

### Risk 1 — `OutBuf<'_, M>` newtype is a pain ergonomically.

Mitigation: provide a `From<&mut Vec<M>> for OutBuf<'_, M>` blanket
so callers can write `parser.feed_initiator(bytes, ts, &mut vec)` as
they would today; the conversion is a single pointer move.

### Risk 2 — Typed slot drains can't preserve cross-protocol ordering for some consumers.

Mitigation: emit a monotonically-increasing `seq: u64` field on every
slot-drained message; consumers that need ordering merge-sort on
`seq` across slot drains. Documented in the migration guide.

### Risk 3 — Full Bytes audit breaks anyone matching on `headers: Vec<(String, Vec<u8>)>`.

Mitigation: the breakage is intentional and the user has explicitly
authorized it. Migration recipes for the 4 common patterns
(host lookup, Content-Length parse, full iteration, exact-string-match
on values) shipped in the migration guide.

### Risk 4 — Phase 0 benchmarks reveal that the real bottleneck is somewhere we're not touching.

This is a *good* outcome — we save 2 weeks. Mitigation: budget Phase 0
as a hard deliverable with a writeup before any code lands. If the
numbers say `track()` allocation is already amortized to near-zero by
Vec capacity reuse across packets, descope items 3.2 / 4.1 in favor of
the items the numbers actually flag (more inlining? hash function?
hot-cache contention?).

### Risk 5 — Static-dispatch of the slot list (item 4.3) requires a typestate Driver, which is API-invasive.

Mitigation: the typestate Driver is *also* needed by item 3.4
alternative A. The two changes pay for one piece of complexity.

### Risk 6 — netring author objects to typed slot drains because it forces N drain calls per `track_into`.

Mitigation: a thin convenience wrapper that loops over slot drains and
emits the combined stream — implemented in *netring*, not flowscope.
Two-line helper. The point of flowscope's Slot handles is to give
netring a typed surface; the loop is netring's idiom, not flowscope's
API.

---

## 8. What the original report got *exactly* right that bears restating

To balance the disagreements above: the original report's framing of
the problem is sound and three things in particular are worth keeping
verbatim:

1. **The dependency direction is non-negotiable.** flowscope must ship
   first. Doing the work in netring as a workaround creates
   throwaway-work debt that compounds.

2. **The zero-allocation claim is load-bearing for netring's value
   prop.** Shipping it with documented allocations on the hot path
   devalues the perf headline. The report is right to insist on
   honesty here.

3. **The "shouldn't add `async fn` to SessionParser" point in §7.**
   This is correct and important. The async/sync boundary is netring's
   to manage; flowscope must stay sync.

---

## 9. Open questions for the original author

Before committing to either the original report's plan or this
revision, three answers would sharpen the decision:

1. **How much does cross-protocol ordering matter to netring's
   consumers?** If yes (correlation analyses, audit logs, security
   pipelines), the typed-slot-drain approach in §3.3-alt-A is right.
   If no (independent per-protocol metrics only), the original
   TypeId-callback approach is cheaper to implement.

2. **Does netring's `monitor.protocol::<P>()` model permit drain-style
   pull, or does it require push-style callback?** The redesign doc
   §8 references `handler` callbacks; if those are *required* push
   semantics, my Alternative A becomes Alternative C with an
   internal callback adapter.

3. **What's the actual measured allocation cost today?** None of the
   numbers in the original report (or this one) are *measured* —
   they're estimated. Phase 0 of my proposed sequencing fixes this.
   If you have netring profiles showing the actual allocator
   bottleneck, send them; they'd refine the priority order.

---

## 10. Closing

The original report is a strong piece of work — it correctly
identifies the dependency direction, correctly catches the keystone
allocation in `Driver::track`, and correctly frames the netring 0.19
zero-allocation claim as load-bearing. Three of its six items I'd
ship as-is.

What I'd change: the parser-API breakage is bigger than necessary and
not the cleanest shape (use `OutBuf<'_, M>`); the HTTP-headers fix is
half-scoped (do all L7 types in one Bytes audit); the multi-typed
driver design is wrong shape (use typed slot drain handles, not
TypeId-keyed callbacks).

What I'd add: the slot-level `.collect()` allocations the original
report misses, the `view.frame.to_vec()` cliff that's bigger than any
single item the report flags, the slot dispatch indirection cost, and
a Phase 0 benchmark gate that grounds every other decision in
measured cost.

Net: **14–18 working days, one coherent 0.11 break, benchmark-driven**
beats **9–12 working days, two phases, premise-driven**. The 5-day
delta buys the right architecture; the original report's plan
delivers the right architecture for 60% of the surface and a
workaround for the rest.

If you'd like, the next document is a concrete `flowscope/plans/118-
zero-alloc-bytes-typed-slots.md` translating this report into the
implementation-plan shape the project uses (numbered phases, file-by-
file checklists, acceptance criteria, retirement criteria). Say the
word.
