# Authentication

Apple's Screen Sharing server advertises four authentication methods. Each has its own page below; common scaffolding (banner, security-types list, `SecurityResult`) is documented in the overview.

## Start Here

- [overview.md](overview.md) — handshake skeleton, method comparison table, server dispatcher map, client selection logic.

## Per-Method Pages

| Wire ID | Method | Page |
|---|---|---|
| `30` | Apple Remote Desktop (DH + AES-ECB) | [auth-30-ard.md](auth-30-ard.md) |
| `33` | RSA-SRP (bootstrap + SRP) | [auth-33-rsa-srp.md](auth-33-rsa-srp.md) |
| `35` | Kerberos (GSS-API) | [auth-35-kerberos.md](auth-35-kerberos.md) |
| `36` | Direct SRP | [auth-36-direct-srp.md](auth-36-direct-srp.md) |

## Shared Material

- [srp-math.md](srp-math.md) — RFC-5054 SRP-6a primitives used by both type 33 and type 36 (PBKDF2-HMAC-SHA512 password preprocessing, `x` / `k` / `u` / `S` / `K` / `M1` derivations, session-key extraction).

## What This Section Covers

- The four security types the native server offers (`30`, `33`, `35`, `36`).
- Byte-precise wire format for every packet in each handshake.
- Client and server function anchors for cross-referencing the source.
- Cryptographic primitives, key derivation, and session-key handoff to the post-auth security layer.

## See Also

- Post-auth transport that consumes each method's session key: [../03-transport/startup-sequence.md](../03-transport/startup-sequence.md).
- Wireshark dissector for live auth decoding: [../06-tooling/wireshark/](../06-tooling/wireshark/).
- Open items across all auth methods: [../08-tracking/open-questions.md](../08-tracking/open-questions.md).
