# Authentication Pipeline (24G231) - Binary + Wire Reconstruction

## Scope
- Build: macOS Sequoia `24G231`
- Server binary: `screensharingd`
- Client binary: `Shared Screen Viewer`
- Capture: `apple_hp_vnc.pcapng` (streams 0 and 2)

## 1) Binary Pipeline (Function-Level)

### Server-side (`screensharingd`)
Recovered call-chain markers (from binary strings):
1. `HandleViewerAuthenticationMessages`
2. `HandleAuthTypeMessage`
3. Type 33 path:
   - `SendSRPChallenge`
   - `HandleSRPAuthenticationMessage`
   - `SendAuthenticationResultToViewer`
4. RSA1 sub-dispatch (`SendRSAResponse`):
   - `SendRSAResponseKeyRequest` (`authtype=0`)
   - `SendRSAResponsePlainAuthentication` (`authtype=1`)
   - `SendRSAResponseSRPAuthentication` (`authtype=2`)
5. SRP core engine markers:
   - `srp_server_mech_step`
   - `srp_server_mech_step1`
   - `srp_server_mech_step2`
   - `bad SRP auth2`

Binary Ninja HLIL confirmation:
- `screensharingd::sub_10001024e` (`srp_server_mech_step`) references:
  - `%m%-o%s%-o` (step2 input parser)
  - `%o%o%s%u` (step2 output builder)
- `screensharingd::sub_100018e8c` (`SendRSAResponseSRPAuthentication`) references:
  - `rejecting auth because client sent large length:%u`
  - `bad SRP auth2`

### Client-side (`Shared Screen Viewer`)
Recovered auth markers:
1. `RFBAuthenticateCore`
2. Auth method selection:
   - `AuthenticateRSA_SRP`
   - `AuthenticateRSAPlain`
   - `AuthenticateSRPNamePassword`
3. SRP client steps:
   - `srp_client_mech_step1`
   - `srp_client_mech_step2`
   - `srp_client_mech_step3`
4. Validation marker:
   - `SRP Server spoof detected. M2 incorrect`

Binary Ninja HLIL confirmation:
- `Shared Screen Viewer::sub_1000ee62d` (SRP client mech function) references:
  - `%c%m%m%o%m%q%s` (challenge parse)
  - `%m%o%s%o` (client response builder)
  - `%-o%-o%s%u` (server final parse)

## 2) Entrance Process Frame Count (Observed)

For the authentication entrance up to `ServerInit`, there are 10 payload-carrying frames:
1. Frame 5   S->C: ProtocolVersion
2. Frame 7   C->S: ProtocolVersion
3. Frame 9   S->C: Security types list
4. Frame 11  C->S: Security selection + RSA1 packet #1
5. Frame 13  S->C: SRP challenge packet
6. Frame 15  C->S: RSA1 packet #2 (SRP response payload)
7. Frame 17  S->C: SRP final server proof packet
8. Frame 19  S->C: SecurityResult
9. Frame 21  C->S: ClientInit
10. Frame 23 S->C: ServerInit

Stream 2 repeats the same structure (`121164..121184`).

## 2.1) Native Screen Sharing Bootstrap (Observed)
When the native Apple Screen Sharing viewer is used as the auth33 oracle, it performs:
1. security selection `33`,
2. RSA1 `authtype=0` key request (`u32 len=10`, total 14 bytes),
3. server type-0 key response (DER public-key payload),
4. RSA1 `authtype=2` SRP init,
5. normal SRP challenge/response flow.

This bootstrap is required for native compatibility; omitting it causes local viewer "incompatible" failures.

## 3) Per-Frame Byte/Bit Semantics

Notation:
- `u8/u16/u32/u64`: unsigned integer, big-endian on wire.
- Bit ranges in `b7..b0` order for each byte.

### Frame 5 / 7: ProtocolVersion (`12 bytes`)
- Bytes: ASCII `52 46 42 20 30 30 33 2e 38 38 39 0a`
- Text: `RFB 003.889\n`
- Bit semantics: pure ASCII bytes; no packed sub-bit fields.

### Frame 9: Security Types (`5 bytes`)
- Byte 0: `0x04` -> number of security types.
- Byte 1: `0x1e` (30)
- Byte 2: `0x21` (33)
- Byte 3: `0x24` (36)
- Byte 4: `0x23` (35)
- Bit semantics:
  - Byte0 `00000100`: count=4
  - Remaining bytes are 8-bit enum IDs.
- `screensharingd_arm64e` server-side auth ID labels for nearby values:
  - `30` -> `DH`
  - `31` -> `Guest Request for Observe`
  - `32` -> `Guest Request for Control`
  - `33` -> `RSA` / `RSA-SRP`
  - `34` -> `Kerberos`
  - `35` -> `SRP` family
  - `36` -> `SRP` family
- Limitation:
  - in the active `screensharingd_arm64e` sample, `35` and `36` are both logged as SRP-family auth protocols; the binary does not expose a clean server-only distinction beyond that.

### Frame 11: Client selection + RSA1 packet #1 (`655 bytes`)
- Byte 0: security selection `0x21` (type 33)
- Bytes 1..654 are RSA1 message:
  - `u32` length = `0x0000028a` (650)
  - `u16` packet_version = `0x0100`
  - `4 bytes` magic = `"RSA1"`
  - `u16` authtype = `0x0002`
  - `u16` aux = `0x0100` (256)
  - Body length = 640 bytes:
    - Bytes 0..255: non-zero key material (254 non-zero bytes)
    - Bytes 256..639: zero padding
- Bit semantics:
  - Length/version/authtype/aux are big-endian integer fields.
  - Body bytes are cryptographic payload; individual bit meaning is not independently semantic.

### Frame 13: Server SRP challenge (`1169 bytes`)
Header (14 bytes):
- `u32` total_len = `0x0000048d` (1165)
- `u32` step_or_msg = `0x00000002`
- `u16` x = `0x0487` (1159)
- `u32` payload_len = `0x00000483` (1155)
- Relationship observed: `x = payload_len + 4`

Payload (1155 bytes), parsed exactly with SRP format `%c%m%m%o%m%q%s`:
- `%c`  : `0x00`
- `%m`  : `N` (512-byte RFC5054 group prime)
- `%m`  : `g` (1 byte, value `0x05`)
- `%o`  : salt (32 bytes)
- `%m`  : server public `B` (512 bytes)
- `%q`  : `156250` (KDF iteration count)
- `%s`  : options string (80 chars)
  - `mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2`

Client-side preprocessing confirmed from `Shared Screen Viewer` before SRP proof generation:
- `P' = PBKDF2-HMAC-SHA512(password_utf8, salt, iterations, dkLen=128)`
- SRP username input for step-2 is the empty string.

Bit semantics:
- `%m`: `u16 length` + raw bytes
- `%o`: `u8 length` + raw bytes
- `%s`: `u16 length` + UTF-8
- `%q`: `u64` BE
- Cryptographic vectors (`N/B/salt`) are opaque entropy bytes; no per-bit semantic flags.

### Frame 15: Client RSA1 packet #2 (`1080 bytes`)
RSA1 envelope:
- `u32` total_len = `0x00000434` (1076)
- `u16` version = `0x0100`
- magic `RSA1`
- `u16` authtype = `0x0002`
- `u16` aux = `0x02aa` (682)

Body split:
- First 682 bytes (`aux` bounded blob)
- Remaining 384 bytes (separate numeric tail)

`aux` blob format:
- `u16 preamble = 0`
- `u16 inner_len = 678`
- Then `inner_len` bytes parsed exactly as `%m%o%s%o`:
  - `%m`   : 512-byte client SRP public `A`
  - `%o`   : 64-byte SRP proof `M1`
  - `%s`   : options string (same as challenge)
  - `%o`   : 16 random client bytes (`CCRandomGenerateBytes`, later used by the security layer)

Confirmed standalone math that produces an accepted packet-2:
- `x = H(salt || H(b":" || P'))`
- `k = OS2IP(H(PAD(N) || PAD(g)))`
- `u = OS2IP(H(PAD(A) || PAD(B)))`
- `S = (B - k * g^x mod N)^(a + u*x) mod N`
- `K = H(PAD(S))`
- `M1 = H(H(PAD(N)) xor H(PAD(g)), H(b""), salt, PAD(A), PAD(B), K)`
- `a` only needs to be fresh and non-zero; the standalone generator uses a 512-bit random exponent and authenticates successfully.

384-byte tail:
- Decodes cleanly as 96 little-endian `u32` words.
- Value set is constrained to `0..9`; both observed connections have identical vector bytes.
- Prefix words: `9,8,8,8,8,8,8,8,8,7,8,8,7,7,7,7,...`
- Suffix words: `...,1,0,1,1,1,1,1,0,1,0,0,0,0,0,0,0`
- Strong inference: structured capability/weight table emitted by client template, not ciphertext.
- Stronger static inference from client builder (`Shared Screen Viewer::sub_1000f54fa`):
  - buffer is `malloc`-allocated,
  - header + blob are written,
  - final 384 bytes have no explicit initialization in this path.
  - So this tail is likely residual heap content rather than negotiated protocol data.
- Server-consumption confirmation (`screensharingd::sub_100018e8c`):
  - decrypt input length is taken from RSA1 `aux` (`rbx = bswap16(*(arg2+8))`),
  - decrypt source pointer is `arg2 + 0xa`,
  - therefore bytes beyond `aux` (the 384-byte tail) are not consumed by SRP parser/decrypt in this stage.

Bit semantics:
- RSA1 fixed fields and lengths are exact.
- SRP blobs are length-prefixed vectors; internal crypto bits are opaque.
- Tail words are fixed-width BE integers; each bit is numeric value contribution, not discrete flags (unknown semantic mapping).

### Frame 17: Server SRP final proof packet (`102 bytes`)
Header (14 bytes):
- `u32 total_len = 98`
- `u32 step_or_msg = 2`
- `u16 x = 92`
- `u32 payload_len = 88`
- Again: `x = payload_len + 4`

Payload (88 bytes), parsed exactly as `%o%o%s%u` on server side (`%-o%-o%s%u` on client side):
- `%o` : 64-byte value (server proof, likely `M2`)
- `%o` : 16-byte value (session-related opaque)
- `%s` : empty string
- `%u` : 0

Bit semantics:
- Same length-prefix rules; opaque crypto bytes for the two vectors.

Client integration note:
- This packet arrives before `SecurityResult`.
- Custom auth handler must consume it explicitly; otherwise the next `u32` (`98`) is mis-read as VNC security result.

### Frame 19: SecurityResult (`4 bytes`)
- `u32` result = `0x00000000` (success)
- Bit semantics: all bits zero.

### Frame 21: ClientInit (`1 byte`)
- Value: `0xC1`.
- In classic RFB this is typically shared-flag `0/1`; here it is extended.
- Binary-confirmed server checks in `screensharingd::sub_10003625c` (`HandleViewerInitialization` path):
  - `(flags & 0x40)` gates session-select info behavior.
  - `flags < 0` (sign bit set, i.e. `0x80`) toggles an additional viewer option path.
- Binary-confirmed client construction in `Shared Screen Viewer::sub_1000f54fa`:
  - base flag is derived from `arg4` (shared-desktop bit, `0x01` when non-zero),
  - if enhanced-mode path active, client ORs `0x80`,
  - if session-select bit requested, client ORs `0x40`,
  - then transmits this single byte via `Shared Screen Viewer::sub_100113fab(..., 1)`.
- Therefore for `0xC1`:
  - `b0=1` likely classical shared-desktop flag.
  - `b6=1` confirmed as session-select related gate.
  - `b7=1` confirmed as additional extended-flag gate (exact semantic label still open).

### Frame 23: ServerInit (`63 bytes`)
- `u16 width`  = 1920
- `u16 height` = 1080
- PixelFormat (16 bytes):
  - bpp=32, depth=24, big_endian=0, true_color=1
  - rmax=gmax=bmax=255
  - shifts: r=16 g=8 b=0
  - 3 bytes pad
- `u32 name_len = 39`
- Name payload contains prefix metadata bytes followed by UTF-8 host name (`Alex’s Mac mini`), indicating protocol-specific extension in server name field.

## 4) Auth Type Values and Their Difference

Inside RSA1 envelopes (`SendRSAResponse` dispatch):
- `authtype=0`: key request path (`SendRSAResponseKeyRequest`)
- `authtype=1`: plain auth path (`SendRSAResponsePlainAuthentication`)
- `authtype=2`: SRP auth path (`SendRSAResponseSRPAuthentication`)

Observed pcap uses `authtype=2`.

## 5) What Is Fully Bit-Decoded vs Still Open

Confirmed bit-precise (field boundaries/types):
- Protocol banners, security list, RSA1 envelope fixed fields.
- SRP challenge and SRP response payload formats (`%c%m%m%o%m%q%s`, `%m%-o%s%-o`, `%o%o%s%u`).
- Length relationships (`x = payload_len + 4`) in server step packets.
- For auth33 envelope packets, `aux` matches the dynamic inner payload byte length.

Open (not yet fully semantic per-bit):
- Exact semantic meaning of the server-final 16-byte SRP side field beyond its role in post-auth security-layer initialization.
- Exact semantic label for ClientInit `b7` gate.
