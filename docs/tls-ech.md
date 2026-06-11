# ECH (Encrypted Client Hello) — passive observation

flowscope 0.12 surfaces the ECH wire signal on `TlsClientHello`
and `TlsHandshake` events. Pinned to `draft-ietf-tls-esni-22`
(the working IETF draft at Jan 2026; semver-major bumps if the
RFC publishes with breaking format changes).

## What's extractable passively

| Field on `TlsClientHello` | Meaning |
|---|---|
| `ech_present: bool` | Extension type `0xfe0d` observed in the ClientHello. |
| `ech_config_id: Option<u8>` | HPKE `config_id` byte from the outer ECHClientHello. Useful for clustering clients by ECH config rotation. |
| `sni_is_outer: bool` | `true` when `ech_present` — the SNI we parsed is the outer (cover) domain, NOT the real target. |

| Field on `TlsHandshake` | Meaning |
|---|---|
| `ech_outcome: EchOutcome` | `NotOffered` / `Accepted` / `Rejected` / `Unknown` aggregate. |
| `ech_config_id: Option<u8>` | Carried over from the ClientHello when ECH was offered. |

## What's NOT extractable passively

- **Inner SNI** is encrypted under the HPKE-derived ECH key.
  Cryptographically impossible without ECH config private keys.
- **`EncryptedExtensions` retry_configs** sit inside the TLS 1.3
  handshake-key-encrypted record. Plaintext fallback paths
  (rare; early handshake errors) populate
  `TlsServerHello::ech_retry_configs`, but the common case
  leaves it `false`.

## `EchOutcome` semantics

```text
NotOffered  — client.ech_present == false
Accepted    — client offered ECH AND server did not signal
              plaintext retry_configs. **Best-effort** — we
              can't see the encrypted EncryptedExtensions,
              so silent rejection looks like Accepted.
Rejected    — server's plaintext EncryptedExtensions carries
              retry_configs (rare; only on early errors).
Unknown     — client offered ECH; handshake did not reach
              ServerHello.
```

## Practical usage

ECH adoption climbed sharply in 2024-2025: Chrome 124 default-
on for >0.5% of users; Firefox 119 default-on for DoH users.
By 2026 a measurable percentage of TLS handshakes carry outer
SNIs.

### Treat outer SNI as a privacy hint, not a target ID

```rust,ignore
match &client_hello.sni {
    Some(s) if client_hello.sni_is_outer => {
        // Cover domain. Don't pin enrichment / threat-intel
        // lookups to this value — the real target is opaque.
        log::trace!("ECH-cover: {}", s);
    }
    Some(s) => {
        // Plain SNI (no ECH). Canonical target identifier.
        enrichment_pipeline.lookup(s);
    }
    None => {}
}
```

### Cluster by `ech_config_id`

```rust,ignore
let mut by_config: HashMap<u8, u64> = HashMap::new();
for hs in handshakes {
    if let Some(cid) = hs.ech_config_id {
        *by_config.entry(cid).or_insert(0) += 1;
    }
}
```

Useful for spotting clients that haven't rotated their ECH
config (security signal: stale public-key material).

### Pair with JA4 for client identification

`ech_config_id` rotates on the DNS HTTPS RR refresh schedule
(daily for many CDNs); JA4 is a stable client TLS fingerprint.
Use JA4 for client identification; use `ech_config_id` for
config-version analysis, not identity.

## Wire format reference

ECH ClientHello outer struct (draft-ietf-tls-esni-22 §5.1):

```text
ECHClientHello (outer form):
  1B  ECHClientHelloType (0 = outer, 1 = inner — skipped)
  1B  HPKE config_id
  2B  HPKE KDF id
  2B  HPKE AEAD id
  2B  enc.len + enc bytes
  2B  payload.len + payload bytes (encrypted)
```

The flowscope parser extracts `config_id` only; KDF / AEAD /
`enc` / payload are recorded by the wire signal but not
exposed. Consumers wanting deeper analysis fork
`src/tls/parser.rs::build_client_hello`.

## References

- [IETF draft-ietf-tls-esni-22](https://datatracker.ietf.org/doc/draft-ietf-tls-esni/22/)
- [Cloudflare ECH announcement](https://blog.cloudflare.com/announcing-encrypted-client-hello)
- [BoringSSL ECH support](https://boringssl.googlesource.com/boringssl/+/refs/heads/master/include/openssl/ssl.h)
- [rustls 0.23+ ECH implementation](https://github.com/rustls/rustls)
