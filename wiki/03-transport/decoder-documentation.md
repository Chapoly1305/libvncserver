# Entrance / Auth Decode Formats

Reference page for the format-string parsers used during the Screen Sharing entrance and auth handshake. Use this when implementing or extending a decoder for the early frames of a captured session.

For the full auth-33 reconstruction, see [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md). For the on-wire frame ledger of a recorded session, see [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md).

## What The Entrance Window Carries

- `protocol_version` (`RFB 003.889`)
- `security_types` list
- selected security type
- For security type `33` (Apple `RSA-SRP`):
  - client `RSA1` packet-1 (`authtype=2`, frame `11` pattern in `apple_hp_vnc.pcapng`)
  - server SRP challenge (frame `13` pattern)
  - client `RSA1` packet-2 (frame `15` pattern)
  - server SRP final proof (frame `17` pattern)
- `security_result`
- `ClientInit`
- `ServerInit`

## SRP Format Strings

The native handshake uses Apple's `ccsrp_mech_step` format strings. The format tokens map to:

- `%c` — 1-byte version / classifier
- `%m` — length-prefixed multi-precision integer (big-endian)
- `%o` — length-prefixed octet string
- `%s` — length-prefixed UTF-8 string
- `%q` — 4-byte unsigned big-endian integer (PBKDF2 iteration count)
- `%u` — 4-byte unsigned big-endian integer

The negative variants (`%-o`, `%-m`) indicate that the field is consumed without copying out.

### Client View (`Shared Screen Viewer::sub_1000ee62d`)

- challenge parse: `%c%m%m%o%m%q%s`
- response build: `%m%o%s%o`
- final parse: `%-o%-o%s%u`

### Server View (`screensharingd::sub_10001024e`)

- challenge input: `%m%-o%s%-o`
- challenge output: `%o%o%s%u`

## Practical Notes

- The packet-2 `%o%o%s%o` body fits inside the RSA1 envelope's `aux` length. Bytes after `aux` are not consumed by the server in this auth stage (see [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md) — packet-2 segmentation).
- The packet-2 384-byte suffix outside `aux` decodes as 96 little-endian `u32` words; this is allocator residue, not protocol material.
- The server-final packet includes two 16-byte side fields whose exact semantic role is not yet pinned down — they are consumed but their post-auth use is open.
- The `ClientInit` byte is assembled from `0x01` (shared flag), `0x80` (enhanced-mode bit), `0x40` (session-select bit). See [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md) for the BN-confirmed builder.

## See Also

- For live decoding of an entire capture with key derivation, the Wireshark dissector at [../06-tooling/wireshark/](../06-tooling/wireshark/) handles auth33 and the first rekeyed CBC record family.
