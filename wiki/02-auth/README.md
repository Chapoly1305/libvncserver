# Authentication

Security type `33` (Apple `RSA-SRP`) end-to-end: handshake, packet layout, password preprocessing, SRP math, and post-auth key install.

## Pages

- [auth33-reconstruction.md](auth33-reconstruction.md) — full reconstruction: handler dispatch, RSA1 envelope, two-packet exchange, ChaCha placement, runtime key install.
- [auth33-standalone-spec.md](auth33-standalone-spec.md) — the standalone client view: exact env vars and helper invocation needed to authenticate without the native viewer.
- [authentication-pipeline.md](authentication-pipeline.md) — high-level pipeline stages (banner → security-type select → RSA1 → SRP → `SecurityResult`).

## What this section covers

- Security type `33` selection and RSA1 dispatch.
- Packet-1 and packet-2 generation (now done entirely in-process).
- PBKDF2-HMAC-SHA512 password preprocessing and the empty-username SRP step.
- Post-SRP AES key install via `SHA-256(session_key)[0:16]` and the four `CCCryptorRef` objects.

## See also

- The first post-auth control packet (`0x44f EncodeEncryptionInfo`) and the AES-CBC record layer that follows: [../03-transport/message-catalog.md](../03-transport/message-catalog.md) and [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md).
- Wireshark dissector for live decode: [../06-tooling/wireshark/](../06-tooling/wireshark/).
