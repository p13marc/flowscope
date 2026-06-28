# Issue #71 — Tap-merge direction & capture-leg identity: deep analysis + recommendation

**Status:** design analysis / RFC for review (no code changed).
**Scope:** decide what `flowscope` should surface, beyond arrival-order
`FlowSide`, so a merged-tap consumer can tell a flow's two legs apart —
canonical orientation and/or physical capture-leg identity.
**Breaking changes:** permitted (per the request). Recommendation is
phased so the *correctness* fix lands first and cheaply.

---

## 0. TL;DR

- The real problem isn't "we're missing a nicety." It's that the **one
  direction axis flowscope surfaces on events — `FlowSide` — is
  arrival-order-relative, and tap-merge is precisely the regime where
  arrival order is unreliable** (two NICs, two independent queues, a
  race). So `FlowSide::Initiator` can mean the TX leg on one flow and
  the RX leg on the next. For "which packets are TX vs RX" it is the
  wrong tool.
- flowscope **already computes the right anchor** — the canonical,
  address-sorted `Orientation` (`Forward`/`Reverse`, `a < b`) — and
  **already keeps it cleanly separate** from the first-seen role
  (so it does *not* have the CICFlowMeter "sorted == initiator"
  conflation bug). It just **collapses `Orientation` into `FlowSide`
  and throws it away** before any event is emitted
  (`tracker.rs:506`), and never exposes it.
- The industry model (IPFIX, Zeek, Suricata, Community ID, pcapng,
  ERSPAN, packet brokers) is unanimous: **logical role**, **canonical
  orientation**, and **physical capture leg** are *three orthogonal
  axes*. flowscope surfaces only the first.
- **Recommendation:** surface the canonical `Orientation` on per-packet
  events (Phase 1 — the actual fix, ~free), fold the physical
  `source_idx` to a **per-direction** leg binding on `FlowStats`
  (Phase 2 — the IPFIX merge model, additive + tiny plumbing), and
  document the three axes (Phase 1). Treat per-packet `source_idx` on
  every event and SYN-based role detection as separately-motivated
  options, not part of the core fix.
- Issue #71's own lean ("(3) do-nothing + (1) as a nicety") understates
  it: **(1) is the fix, not a nicety**, because of the arrival-order
  fragility above.

---

## 1. The three axes (industry model)

Every mature system separates these. They are not derivable from one
another (a SPAN port carries both directions on one leg; a two-tap
inline setup splits one biflow across two legs; asymmetric routing can
split even one logical direction across legs).

| Axis | Question it answers | Granularity | Determinism | flowscope today |
|---|---|---|---|---|
| **A. Logical role** | "client or server? who initiated?" | per-direction | arrival-order / SYN | **`FlowSide` (surfaced)** |
| **B. Canonical orientation** | "the a→b half or the b→a half?" | per-direction | **deterministic (address sort)** | `Orientation` (**computed, hidden**) |
| **C. Physical capture leg** | "which NIC/tap/port observed it?" | per-packet (→ per-direction on merge) | observed | `source_idx` (**stuck at `PacketView`**) |

Standards mapping (citations in §7):

- **A** ↔ IPFIX `biflowDirection` (IE 239, RFC 5103: `initiator` /
  `reverseInitiator`), Zeek `orig`/`resp`, Suricata
  `to_server`/`to_client` + `flow.src_ip`.
- **B** ↔ Corelight **Community ID** (sort the two `(IP,port)` tuples,
  lower first) — flowscope's `a < b` canonicalisation is *exactly*
  this. (flowscope even ships a `community-id` feature.)
- **C** ↔ IPFIX `observationPointId` (IE 138) / `ingressInterface`
  (IE 10) / `ingressPhysicalInterface` (IE 252); pcapng EPB Interface
  ID; gopacket `CaptureInfo.InterfaceIndex`; AF_PACKET
  `sockaddr_ll.sll_ifindex`; PF_RING `if_index`; ERSPAN Session-ID +
  Index; Gigamon "Source ID" port-stamp trailer.

**Two facts from the survey that drive the design:**

1. **Canonical orientation ≠ initiator orientation.** Community ID sorts
   and is arrival-order-independent; "initiator" is a first-seen/SYN
   best-effort bit. Conflating them is a real, shipped bug
   (CICFlowMeter #23 derives "forward" from byte-order of the IPs while
   *documenting* it as initiator→responder). **flowscope does *not*
   make this mistake** — `Orientation` (sorted) and `FlowSide`
   (first-seen) are distinct concepts in the code. That's a strength to
   preserve and lean on.

2. **On biflow merge, the per-packet leg is folded to a per-direction
   attribute — not dropped, not kept per-packet.** IPFIX exports a
   forward `ingressInterface` and a reverse one (via the PEN 29305
   reverse-IE space). That is the precise template for flowscope's
   "keep the flow merged but still attribute the legs": record one
   `source_idx` *per canonical orientation*, on finalize.

---

## 2. What flowscope does today (with line refs)

Data flow of "which physical direction":

```
extractor                         tracker                         event
─────────                         ───────                         ─────
FiveTuple::extract                track_with_payload              FlowEvent / Event
  src>dst ? Reverse : Forward       freeze 1st orientation as        Started { side, .. }
  (five_tuple.rs:391)               initiator_orientation            Packet  { side, .. }
        │                           (tracker.rs:448, pub(crate))       ▲
        ▼                                   │                          │ side only
  Extracted{ orientation, .. }      side = side_for(orientation)      │
  (extractor.rs:59,                 (tracker.rs:506)  ───────────────►┘
   #[non_exhaustive])                       │
                                            ▼  orientation local dropped here
PacketView.rx_metadata.source_idx ─── never read by the tracker ───► ✗ (dies at the view boundary)
  (rx_metadata.rs:61)                (tracker reads only frame.len + timestamp, tracker.rs:424-425)
```

Concretely:

- **Axis B is computed then discarded.** `Orientation::{Forward,Reverse}`
  is set by the address sort (`five_tuple.rs:391-395`,
  mirrored in `ip_pair.rs:44`, `mac_pair.rs:54`), carried in
  `Extracted.orientation` (`extractor.rs:59`), frozen as
  `FlowEntry::initiator_orientation` (**`pub(crate)`**,
  `tracker.rs:54,448`), then reduced to `FlowSide` by
  `side_for` (`tracker.rs:64-70`) and **dropped** after
  `tracker.rs:506`. No `FlowEvent` / `Event` / `FlowStats` /
  accessor exposes it.
- **Axis A is the only thing on events.** `FlowEvent::Started`/`Packet`
  and `Event::Started`/`Packet` carry `side: FlowSide`
  (`event.rs:863-876`, `driver/typed.rs:135`); `Started` is even
  hardcoded `FlowSide::Initiator` (`tracker.rs:485`). `FlowStats` is
  entirely per-side (`packets_initiator/responder`, `bytes_*`, per-side
  IAT/throughput, `event.rs:288-503`).
- **Axis C never leaves the `PacketView`.** `RxMetadata.source_idx`
  (`rx_metadata.rs:58-61`) is documented as the NIC/capture-channel id
  and "pairs with `Tagged`," but the tracker never reads
  `view.rx_metadata` — only `view.frame.len()` and `view.timestamp`
  (`tracker.rs:424-425`). The only way `source_idx` influences a flow
  is via `Tagged` folding it **into the key**
  (`tagged.rs:157-169`), which **splits** the two legs into two flows —
  defeating the merge. The `tagged.rs` module doc states the binary
  choice explicitly: *merge (no tag, leg identity lost)* vs *per-source
  (Tagged, flow unification lost)*. **There is no middle ground today.**
  Issue #71 is exactly that missing middle.

`#[non_exhaustive]` status (drives breaking-vs-additive):

| Type | `#[non_exhaustive]` | Add a field? |
|---|---|---|
| `FlowEvent<K>` / `Event<K>` (enums) | yes | new **variant** = additive; field on existing struct-variant (`Packet`/`Started`) = **breaking** |
| `FlowStats`, `PacketView`, `RxMetadata`, `Extracted`, `FlowEntry`, `TaggedKey` | yes | additive |
| `FlowSide`, `Orientation` (enums) | **no** | new variant = breaking (neither needs to grow) |

---

## 3. Why "FlowSide is enough" is wrong for tap-merge

The issue says the 2-way split "is already available — no gap." That's
true for a *single* observation point, where first-seen is a stable
proxy. **It breaks in the tap-merge regime the issue is actually
about:**

1. **Arrival-order is racy across two NICs.** TX on `eth0`, RX on
   `eth1`, each with its own ring/queue/IRQ. Whichever drains first
   "wins" first-seen. So `FlowSide::Initiator` binds to the TX leg on
   some flows and the RX leg on others — **non-deterministic across the
   flow table.** A consumer that maps `Initiator → TX` is wrong on a
   fraction of flows, silently.
2. **It corrupts the *role*, not just the leg.** If the response packet
   is delivered first (loss, reorder, mid-stream capture start, NIC
   buffering skew), the *responder* is mislabeled `Initiator`. Zeek
   mitigates this with SYN-awareness **and** an explicit flip heuristic
   (the `^` history code); flowscope uses pure first-seen with no
   correction.
3. **The deterministic anchor already exists and is immune to all of
   the above.** `Orientation` (`a < b` sort) labels the same
   address-direction `Forward` on every flow, regardless of arrival
   order, NIC, or loss. That is the correct basis for a stable TX/RX
   split — and it is exactly the Community ID canonicalisation the
   industry uses for direction-independent keying.

So the gap is not cosmetic: **flowscope surfaces the fragile axis and
hides the robust one.** That is the crux of #71.

---

## 4. Options (issue's three + the design space), evaluated

**(1) Surface canonical `Orientation` on events.** ✅ *The fix.* Cheap
(already computed), deterministic, resolves §3. Maps to Community ID /
biflow Source-Destination ordering. The only cost is a breaking field
add to two hot variants (acceptable per the request; future-proofed by
marking the variants `#[non_exhaustive]`).

**(2) Carry per-packet `source_idx` through to every event.** ⚠️
*Right data, wrong default.* Ground-truth leg, but it's a hot-path field
on the highest-volume `Packet` event and is **redundant for a
correctly-wired tap** (one NIC per orientation, so a per-direction fold
captures the same information at a fraction of the cost). Keep it as an
*opt-in* for the rare per-packet-leg audit (detecting packets arriving
on the "wrong" leg), not as the merged-mode default.

**(3) Do nothing; document FlowSide as the contract.** ❌ *Insufficient
alone.* §3 shows the contract it would document is unreliable in the
target regime. Documentation is necessary but not a substitute for
surfacing axis B.

**(4) Per-direction leg fold on finalize (added option).** ✅
*The IPFIX merge model.* Record one `source_idx` per canonical
orientation (`Forward`/`Reverse`) on `FlowStats`, populated from
`view.rx_metadata.source_idx`. Additive on the type side; needs the
tracker to read the view's `source_idx` (new but ~free). Gives
leg↔NIC binding **while keeping the flow merged** — the missing middle
ground. Mirrors IPFIX forward/reverse `ingressInterface`.

**(5) Richer `Direction` value type replacing `side` (added option).**
A `Direction { role: FlowSide, orientation: Orientation }` (and maybe
`leg`) on events. ❌ *Over-couples.* The axes are independent; a
consumer often wants one without the others. Separate fields match the
standards (IPFIX uses separate IEs) and stay incremental. Rejected in
favor of separate fields.

**(6) SYN-based initiator (added option, orthogonal).** Use TCP flags
(`SYN && !ACK` ⇒ that orientation is the true initiator) to make
`FlowSide` robust under tap races — Zeek/IPFIX best-effort model.
✅ *Worth doing, but separable.* It fixes axis **A**'s determinism for
TCP; #71 is about axes **B/C**. Recommend as an independent follow-up
(opt-in config), not part of this fix.

---

## 5. Recommendation

Adopt the three-axis model explicitly and surface the two hidden axes.
Phased so the correctness fix is first and cheapest.

### Phase 1 — surface canonical orientation + document (the fix)

1. **Add `orientation: Orientation` to the per-packet events**:
   `FlowEvent::Started`, `FlowEvent::Packet`, and the typed
   `Event::Started`, `Event::Packet`. Mark these four struct-variants
   `#[non_exhaustive]` so this is the **last** breaking change to them.
   - `Started.orientation` is the initiator's canonical direction (the
     flow's anchor); `Packet.orientation` is per-packet, deterministic,
     and never flips with arrival order.
   - Keep `side` — it answers a different question (role). Carrying both
     mirrors IPFIX carrying both `biflowDirection` and direction IEs.
2. **Expose the per-flow anchor**: a public
   `FlowEntry::initiator_orientation() -> Orientation` accessor (the
   field is already there, just `pub(crate)`), and surface it on
   `FlowStats` (additive) so it's available on `Ended` / `snapshot`
   without having to have observed `Started`.
3. **Document the three axes** in `docs/concepts.md` + a `docs/` recipe
   ("tap-merge: TX vs RX"), with the mapping table from §1 and the
   explicit guidance:
   - "which leg / TX vs RX" → **`orientation`** (deterministic) — and,
     for the literal NIC, the Phase-2 per-direction `source_idx`.
   - "client vs server / who initiated" → **`side`** (with the
     tap-merge caveat from §3, until Phase 6/SYN lands).
   - Note flowscope's `Orientation` == Community ID canonicalisation.

*Phase 1 alone resolves #71's core* (a deterministic, arrival-order-
independent 2-way split) at near-zero runtime cost.

### Phase 2 — per-direction physical-leg binding (when netring#105 asks)

4. **Fold `source_idx` to a per-orientation binding on `FlowStats`**
   (additive — `FlowStats` is `#[non_exhaustive]`):
   ```text
   // sketch — names TBD
   FlowStats.source_idx_forward: Option<u32>
   FlowStats.source_idx_reverse: Option<u32>
   FlowStats::source_idx_for(Orientation) -> Option<u32>
   ```
   Populated by new plumbing in `track_with_payload`: on first sight of
   each orientation, record `view.rx_metadata.source_idx`. Optional IOC:
   if a *second, different* `source_idx` appears for an
   already-bound orientation, set a `leg_inconsistent` flag — that is
   the tap-miswire / asymmetric-routing signal the survey warns about
   ("never assume one leg per flow"). Available on `Ended` and
   `snapshot_stats`, flow stays merged. This is the IPFIX
   forward/reverse `ingressInterface` model.
   - Cost is a `u32` read+store per first-orientation-sighting;
     negligible. If we want strict zero-overhead for non-tap users, gate
     behind a `FlowTrackerConfig` flag (default off) — but always-on is
     defensible.

### Phase 3 (optional, separately motivated)

5. **Opt-in per-packet `source_idx`** on `Packet` events for full leg
   fidelity (audit "packet arrived on the wrong leg"). Gated/opt-in to
   keep the hot path lean.
6. **SYN-based initiator** (`#6` above) for robust `FlowSide` under tap
   races — independent of #71.

### Breaking-change summary

- Breaking: the `orientation` field on `FlowEvent::{Started,Packet}` and
  `Event::{Started,Packet}` (Phase 1.1). Mitigated by marking those
  variants `#[non_exhaustive]` going forward.
- Additive (non-breaking): the `FlowStats` additions (Phase 1.2,
  Phase 2.4), the `FlowEntry` accessor, all docs.
- **netring impact:** netring re-exports/consumes these events; the
  Phase-1 field add needs a matching netring update (one match-arm
  change). Note in the netring#105 / netring#107 tracking. Everything
  else is additive for netring.

---

## 6. Why this is the *best* solution (not just the smallest)

- **It fixes a latent correctness bug, not just a missing field.** The
  surfaced axis (`FlowSide`) is the fragile one in the target regime;
  the robust one (`Orientation`) is already computed and merely hidden.
- **It matches the standards exactly.** Three orthogonal axes; canonical
  orientation = Community ID sort; per-direction leg on merge =
  IPFIX forward/reverse `ingressInterface`. flowscope already avoids the
  CICFlowMeter conflation, so we're *completing* a correct model, not
  reworking it.
- **It keeps the flow merged.** Phase 2 gives leg↔NIC binding without
  the `Tagged` split — the precise middle ground the issue identifies as
  absent.
- **It is incremental and cost-aware.** The correctness fix (Phase 1) is
  ~free and small; the heavier per-packet/SYN options are deferred and
  opt-in, used only where their cost is justified.
- **It future-proofs the hot events.** Marking the touched variants
  `#[non_exhaustive]` makes this the last breaking change to them.

---

## 7. Appendix — sources

**flowscope code:** `src/extractor.rs:46-102` (`Extracted`,
`Orientation`); `src/extract/five_tuple.rs:391-402` (canonicalisation);
`src/tracker.rs:47-71` (`FlowEntry`, `initiator_orientation`,
`side_for`), `:424-506` (track path, where orientation is dropped);
`src/event.rs:7-20` (`FlowSide`), `:282-503` (`FlowStats`), `:839-942`
(`FlowEvent`); `src/driver/typed.rs:85-180` (`Event`);
`src/rx_metadata.rs:33-62` (`source_idx`); `src/view.rs:30-94`
(`PacketView`, `with_source_idx`); `src/extract/tagged.rs:1-67`
(tap-merge framing).

**Standards / industry:**
- IPFIX IE registry — https://www.iana.org/assignments/ipfix/ipfix.xhtml
  (`flowDirection` IE 61, `biflowDirection` IE 239, `ingressInterface`
  IE 10 / `ingressPhysicalInterface` IE 252, `observationPointId`
  IE 138, `interfaceName` IE 82).
- RFC 5103 (Bidirectional Flow Export / biflow, PEN 29305 reverse IEs);
  RFC 5102 (IE definitions); RFC 7011 (IPFIX protocol — Observation
  Point / Domain).
- Corelight Community ID spec (sorted-tuple canonicalisation) —
  https://github.com/corelight/community-id-spec
- Zeek `conn.log` (`orig`/`resp`, `conn_state`, `history` case, `^`
  flip) — https://docs.zeek.org/en/master/logs/conn.html
- Suricata flow keywords / EVE flow record (`to_server`/`to_client`,
  `flow.src_ip`, `pkts_toserver/toclient`) —
  https://docs.suricata.io/en/latest/output/eve/eve-json-format.html
- CICFlowMeter sorted-vs-initiator conflation —
  https://github.com/ahlashkari/CICFlowMeter/issues/23
- Per-packet leg: pcapng EPB Interface ID
  (https://pcapng.com/), gopacket `CaptureInfo.InterfaceIndex`,
  AF_PACKET `packet(7)` `sll_ifindex`, PF_RING `if_index`.
- Aggregation: ERSPAN (draft-foschiano-erspan-03, Session ID + Index +
  HW ID); Gigamon Source Port Labeling / GigaSMART trailer (Source ID).
- netfilter conntrack dual-tuple (ORIGINAL/REPLY) direction model —
  https://conntrack-tools.netfilter.org/manual.html

---

## 8. Suggested decision for the issue

Close #71 with: **adopt Phase 1 now** (surface `Orientation` on
per-packet events + expose `initiator_orientation` + document the three
axes), **schedule Phase 2** (per-direction `source_idx` on `FlowStats`)
against netring#105's concrete requirements, and **file Phase 3/6**
(opt-in per-packet leg; SYN-based initiator) as separate, independently
motivated enhancements. This turns the issue's "likely (3) + maybe (1)"
into "(1) is the fix, (4) is the merge-preserving leg binding, (3)'s
documentation is mandatory either way."
