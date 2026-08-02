# Routing TLS connections: what you can rely on

A router that picks a backend from a TLS ClientHello is reading a
signal the client controls and encryption is progressively taking
away. This page says which signals flowscope surfaces, in what order
to prefer them, and — the part that bites people — which ones look
authoritative but are not.

Written for the inline-proxy case (issue #167); the same signals are
what a passive monitor sees.

## The degradation ladder

Prefer the highest rung available. Every rung below is still a
*routing* decision, never an *authorization* decision.

| Rung | Signal | When you have it |
|---|---|---|
| 1 | **Inner SNI + ALPN** | Only if you are an ECH decryption point — you hold the ECH config private key. flowscope cannot give you this from the wire. |
| 2 | **Outer SNI + ALPN** | The normal case. `TlsClientHello::sni()` and `.alpn`. |
| 3 | **JA4 / first-byte class** | Always. Coarse, but survives when SNI is absent — `tls::ja4` (BSD-licensed, in the royalty-free core) and [`classify_first_bytes`](https://docs.rs/flowscope/latest/flowscope/classify/fn.classify_first_bytes.html). |
| 4 | **Raw passthrough** | The honest fallback. |

The ladder is a *degradation*, not a failure cascade: dropping a rung
is normal traffic, not an error, and a router that refuses
connections it cannot classify at rung 2 will refuse legitimate ones.

## ECH: degrade, never error

With Encrypted Client Hello ([RFC 9849], published March 2026; DNS
carriage in [RFC 9848], SVCB `ech` SvcParamKey **5**), an observer
without the ECH key sees only the outer `public_name`, never the real
inner SNI. flowscope reports:

| Field | Meaning |
|---|---|
| `ech_present` | The `encrypted_client_hello` extension (`0xfe0d`) was there. |
| `sni_is_outer` | The SNI you got is the cover domain, not the target. |
| `ech_state()` | GREASE-vs-real classification — a *hint*, see below. |

**`ech_present` is advisory and nothing more.** GREASE ECH (RFC 8701)
is byte-indistinguishable from real ECH by design: Chrome and Firefox
put a structurally valid, randomly populated extension on nearly every
ClientHello. Presence therefore implies nothing about whether ECH was
actually used, and on the open web most of it is GREASE. Routing or
failing differently on `ech_present` means routing on a coin flip.

The contract:

- **Never** make `ech_present` load-bearing in a routing decision.
- **Always** be able to fall back down the ladder; treat "the SNI I
  have may be a cover domain" as the normal case, not an anomaly.
- If you need the inner SNI, you must be the decryption point. There
  is no passive path to it, and that is the entire point of ECH.

`ech_state()` applies corroborating signals (a known cover domain like
`cloudflare-ech.com`, the server's `retry_configs`) to separate likely
GREASE from likely real. It is genuinely useful for telemetry. It is
still a heuristic, so do not put it in the routing path either.

## Post-quantum: the ClientHello no longer fits in one packet

Hybrid key exchange (X25519MLKEM768 and relatives, specified by
`draft-ietf-tls-ecdhe-mlkem` — IESG-approved and in the RFC Editor
queue as of mid-2026, **not yet an RFC**; ML-KEM itself is NIST FIPS
203) carries a ~1.1 KiB public value. That pushes a typical
ClientHello to roughly 1.4–2 KiB, so it routinely spans several TCP
segments — and this is the browser default, not a corner case.

**The "SNI is in the first packet" assumption is dead.** Any
peek-based router must accumulate until the handshake's `uint24`
length is satisfied before parsing extensions. `TlsParser` already
does: it buffers per direction and does not attempt a parse until the
record is complete, bounded by `TlsConfig::max_buffer` (64 KiB). Use
it rather than re-deriving the rule.

`TlsClientHello::pq_key_share` and `key_share_groups` name the
situation directly, so "the ClientHello is suspiciously large" becomes
a specific, expected observation. See `tls::is_pq_hybrid_group` and
`tls::pq_hybrid_group_name`.

## ALPN is a first-class routing signal

`TlsClientHello::alpn` is the client's offer list;
`TlsServerHello::alpn` is what was actually selected, and
`TlsHandshake` carries both (`client_alpn` / `server_alpn`). When
both exist, **prefer the server's** — it is the negotiated outcome
rather than a wish list. `AppProtocol::from_tls_handshake` already
applies that precedence.

For a terminating proxy, ALPN is how you know whether to speak HTTP/1
or HTTP/2 on the connection you accept — and what to offer upstream.

## Bind the decision (ALPACA)

First bytes and SNI say what a client *speaks*; they do not say what
it *intends to reach*. The ALPACA cross-protocol attack exploits the
gap by steering a browser into a TLS connection with a server that
expects a different application protocol.

Bind the backend choice to **both** the negotiated ALPN and the
SNI/`Host`, and refuse mismatches — an HTTP request arriving on a
connection whose ALPN said something else should be rejected, not
routed. flowscope gives you the signals; enforcing agreement between
them is the router's job.

## License note

JA3 and JA4 (the *client* TLS fingerprint) are royalty-free and live
in the default `tls-fingerprints` feature. The rest of the JA4+ family
(JA4S, JA4H, JA4X, JA4SSH, …) is FoxIO License 1.1, which is
non-commercial, and stays behind the opt-in `ja4plus` feature —
deliberately excluded from the `l7` and `full` umbrellas. A
redistributed product should keep it that way.

[RFC 9849]: https://www.rfc-editor.org/rfc/rfc9849
[RFC 9848]: https://www.rfc-editor.org/rfc/rfc9848
