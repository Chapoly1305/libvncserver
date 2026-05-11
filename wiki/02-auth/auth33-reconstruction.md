# Auth Type 33 Reconstruction (24G231)

## Scope
- Goal: reconstruct security type `33` handshake semantics from the active `24G231` sample plus packet evidence.
- Capture source: `apple_hp_vnc.pcapng`.

## Key Conclusion
- Security type `33` is the Apple `RSA-SRP` path.
- A fully working standalone packet-2 generator now exists and succeeds against the live target without using the native Screen Sharing app as a packet oracle.
- The successful standalone reconstruction uses:
  - password preprocessing `PBKDF2-HMAC-SHA512(password_utf8, salt, rounds, dkLen=128)`,
  - empty SRP username for step-2 proof generation,
  - SRP-6a style `k/u/S/K/M1` with SHA-512,
  - a fresh random 16-byte client field in the final `%o`.

## Server-Side Dispatch (Recovered from the Active 24G231 Sample)
- Function `screensharingd::sub_100015bdc` (string-tagged `SendRSAResponse`) parses the RSA envelope and dispatches by `authtype`.
- Parsed packet shape (inside length-delimited blob):
  - offset `+0x00`: packet version (`!= 0` required)
  - offset `+0x02`: magic `'RSA1'` (`0x31415352`)
  - offset `+0x06`: `authtype` (big-endian 16-bit)
  - offset `+0x08`: subtype/aux field (observed `0x0100` in capture)
- `authtype` dispatch:
  - `0` -> `screensharingd::sub_100018754` (`SendRSAResponseKeyRequest`)
  - `1` -> `screensharingd::sub_1000189d4` (`SendRSAResponsePlainAuthentication`)
  - `2` -> `screensharingd::sub_100018e8c` (`SendRSAResponseSRPAuthentication`)
  - otherwise -> unsupported path (`SendRSAResponseUnsupported`)

## Handler Behaviors (Recovered)
- `screensharingd::sub_100018754` (`KeyRequest`) sends server RSA public key:
  - Builds response with `dword[1] = 0x100` and embedded RSA public key bytes from `RSAKeyPair exportedRSAPublicKey`.
- `screensharingd::sub_10001a152` (`SendRSAResponseNewKey`) also emits RSA public key material (`rsaDataLen:%u` log).
- `screensharingd::sub_100018e8c` (`SRPAuthentication`) invokes:
  - `srp_server_mech_step`
  - RFC5054 group/session helpers
  - emits `bad SRP auth2` on invalid proof
  - negotiates `Pmda=...` options and session key derivation.

## Evidence
- Static strings in `screensharingd` include:
  - `RSA-SRP`
  - `SendSRPChallenge`
  - `HandleSRPAuthenticationMessage`
  - `SendRSAResponseSRPAuthentication`
  - `SRP-RFC5054-4096-SHA512-PBKDF2`
  - `ChaCha20-Poly1305`
  - `SALTED-SHA512-PBKDF2`
- Imported crypto symbols in `screensharingd`:
  - `_ccsrp_gp_rfc5054_4096`
  - `_ccsrp_server_generate_public_key`
  - `_ccsrp_server_compute_session`
  - `_ccsrp_server_verify_session`
  - `_chacha20_poly1305_init_64x64`

## On-Wire Sequence (Observed)
- RFB banners: `RFB 003.889`.
- Offered security types: `30, 33, 36, 35`.
- `screensharingd_arm64e` server-side auth ID labels recovered from `HandleAuthTypeMessage` / `VNCServer_LogAuthenticationResult`:
  - `30` -> `DH`
  - `31` -> `Guest Request for Observe`
  - `32` -> `Guest Request for Control`
  - `33` -> `RSA` / `RSA-SRP`
  - `34` -> `Kerberos`
  - `35` -> `SRP` family
  - `36` -> `SRP` family
- Current server-only limitation:
  - the active `screensharingd_arm64e` sample does not cleanly separate the semantic difference between `35` and `36`; both route to SRP-family labeling in the auth-result logger.
- Client selected: `33`.
- Auth exchange pattern:
  1. Client -> Server: `0x21` selection (security type 33).
  2. Client -> Server: length-prefixed RSA envelope (`RSA1`), total `654` bytes on wire (`4-byte len + 650-byte payload`, `authtype=2`).
  3. Server -> Client: length-prefixed challenge (`1169` bytes on wire), contains RFC5054 fields and `Pmda=...`.
  4. Client -> Server: second length-prefixed RSA/SRP message (`1080` bytes on wire).
  5. Server -> Client: SRP final packet (`102` bytes on wire, `u32 len=98`), then `SecurityResult = 0x00000000`.
  6. Client -> Server: `ClientInit` (`0xc1` observed in this capture), then normal `ServerInit` + framebuffer traffic.

### Native Client Bootstrap Variant (Confirmed)
- Apple Screen Sharing client performs an extra auth33 bootstrap exchange before step (2):
  1. sends `authtype=0` RSA1 request (`14` bytes on wire including length prefix),
  2. receives type-0 key challenge/body (`301` bytes body; DER RSA public key),
  3. then sends regular `authtype=2` init (`654` bytes on wire) and proceeds with SRP.
- Captured native packet-1 marker:
  - `0000000a01005253413100000000`

## ClientInit (`0xC1`) Composition (BN-Confirmed)
- In `Shared Screen Viewer::sub_1000f54fa`, the sent byte is assembled as:
  - base shared flag (`0x01` when `arg4 != 0`)
  - OR `0x80` on enhanced-mode path
  - OR `0x40` when session-select bit is requested
- This matches observed wire value `0xC1 = 0x80 | 0x40 | 0x01`.

## Auth33 Packet-2 Segmentation (Confirmed from Pcap)
- Frame `15` (`stream 0`) and frame `121174` (`stream 2`) share identical structure:
  - outer `RSA1` header `aux=0x02aa` (`682` bytes)
  - body prefix is `u16 preamble (0x0000)` + `u16 inner_len (0x02a6)`
  - bytes `body[4 : 4+inner_len]` are the bounded SRP mech blob
- remaining payload bytes are a separate `384`-byte numeric tail
- Bounded blob details:
  - starts with `%m` length `0x0200` (`A` = 512 bytes)
  - contains `Pmda=SHA-512,...` string near blob offset `584`
  - rough entropy indicates two high-entropy 256-byte regions followed by lower-entropy tail:
    - chunk1 `256B` entropy ~`7.18`
    - chunk2 `256B` entropy ~`7.13`
    - tail `164B` entropy ~`6.3`

### Packet-2 Tail Decode (New)
- The 384-byte suffix decodes as `96` little-endian `u32` words.
- Word values are constrained to `0..9`; non-zero words are `87/96`.
- Histogram (stream 0 and stream 2, identical):
  - `9:1, 8:10, 7:9, 6:9, 5:9, 4:10, 3:13, 2:11, 1:15, 0:9`
- Prefix words:
  - `9,8,8,8,8,8,8,8,8,7,8,8,7,7,7,7`
- Suffix words:
  - `1,0,1,1,1,1,1,0,1,0,0,0,0,0,0,0`
- Strong inference:
  - this is not encrypted SRP material.
  - candidate interpretation: heap-resident integer vector copied unintentionally as trailing bytes.
- Full index/value table artifact:
  - `wiki/04-runtime-evidence/archive/auth33-tail-word-mapping-2026-03-14.md`

## Standalone Packet-2 Algorithm (Confirmed Unless Noted)

### Confirmed Byte Layout
- Input challenge body parse starts at offset `+10` with format `%c%m%m%o%m%q%s`:
  - `%c`    -> `0x00`
  - `%m`    -> `N` (512-byte RFC5054-4096 modulus)
  - `%m`    -> `g` (`0x05`)
  - `%o`    -> salt (`32` bytes)
  - `%m`    -> server public `B` (`512` bytes)
  - `%q`    -> PBKDF2 iterations (`156250`)
  - `%s`    -> option string `mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2`
- Packet-2 RSA1 envelope:
  - `packet_version = 0x0100`
  - `authtype = 0x0002`
  - `aux = 0x02aa`
  - body = `u16 0x0000 || u16 0x02a6 || inner || ignored_tail`
- `inner` parses as `%m%o%s%o`:
  - `%m` -> client SRP public `A` (512 bytes, left-padded to `len(N)`)
  - `%o` -> client proof `M1` (64 bytes)
  - `%s` -> option string copied verbatim from the challenge (`mda=...`)
  - `%o` -> random 16-byte client field
- The final 384 body bytes are outside `aux` and are ignored by the server in this auth stage. Zero-fill is accepted.

### Confirmed Password Preprocessing
- Static proof from `Shared Screen Viewer` `srp_client_mech_step2`:
  - `CCKeyDerivationPBKDF(kCCPBKDF2, password, password_len, salt, salt_len, kCCPRFHmacAlgSHA512, rounds, derived, 0x80)`
- Confirmed standalone input encoding:
  - `password` bytes are UTF-8 bytes of the supplied password.
  - `salt` is the 32-byte challenge salt.
  - `rounds` is the challenge `%q` value (`156250` in the known-working case).
  - `dkLen = 128`.
- Let:
  - `P' = PBKDF2-HMAC-SHA512(password_utf8, salt, rounds, 128)`

### Confirmed SRP Math
- Hash function: SHA-512.
- Username used inside SRP step-2 proof generation: empty string.
- Padding width for `A`, `B`, `N`, `g`, `S`: `len(N)` bytes (`512` here).
- Formulas:
  - `x = H(salt || H(b\":\" || P'))`
  - `k = OS2IP(H(PAD(N) || PAD(g)))`
  - `u = OS2IP(H(PAD(A) || PAD(B)))`
  - `v = g^x mod N`
  - `S = (B - k*v mod N)^(a + u*x) mod N`
  - `K = H(PAD(S))`
  - `M1 = H(H(PAD(N)) xor H(PAD(g)), H(b\"\"), salt, PAD(A), PAD(B), K)`
- `a` can be any fresh non-zero random secret exponent; the standalone implementation uses `512` random bits and the server accepts it.

### Confirmed 16-Byte `%o` Field
- Client step-2 fills the trailing `%o` with `16` random bytes from `CCRandomGenerateBytes`.
- This value is consumed later together with the server-final 16-byte field to initialize the post-auth security layer.

### Strong-Inference / Open
- The exact bit-length distribution used by Apple's internal random `a` is still not proven at instruction level; interoperability does not depend on matching it exactly.
- The login user name (`alex`) is not passed into the SRP step-2 call path; it is almost certainly carried elsewhere in auth33 bootstrap/session state.

### Binary-Ninja Correlation (Client Builder)
- In `Shared Screen Viewer::sub_1000f54fa`:
  - send buffer is allocated with `_malloc_type_malloc(__n_2 + 0x18a, ...)`.
  - code writes:
    - fixed header,
    - 386-byte template copy (`memcpy(buf+8, &var_3e8, 0x182)`),
    - then overlays `u16 len` and `len` bytes payload (`*(buf+8)=len`, `memcpy(buf+0xa, payload, len)`).
  - no explicit write initializes the final `0x180` bytes when `len=0x2a6` (observed).
  - therefore trailing 384 bytes are strong-candidate allocator residue in this path.

### Binary-Ninja Correlation (Server Consumer)
- In `screensharingd::sub_100018e8c` (`SendRSAResponseSRPAuthentication`):
  - decrypt data length is read from RSA1 aux field (`bswap16`),
  - decrypt input starts at `arg2 + 0xa`,
  - parser path (`screensharingd::sub_10001024e`) is fed only decrypted aux-length bytes.
- Result:
  - trailing bytes beyond aux are not used by the server in this auth stage.

## Auth33 Type-0 Key Response (Confirmed)
- Saved live authtype=0 challenge parses as:
  - `u16 packet_version = 0x0001`
  - `u32 der_len = 294`
  - `DER SubjectPublicKeyInfo` (server RSA public key)
- Extracted key:
  - RSA `2048`-bit, exponent `65537`.
- Tool used:
  - `../06-tooling/scripts/auth33_extract_pubkey.py`

## Runtime Key Installation (Confirmed, 2026-03-15)
- Frida instrumentation on live `screensharingd` `24G231` recovered the post-SRP key-install path directly.
- Hook points:
  - `ccsrp_get_session_key_length` callsite at `0x100019240`
  - `CC_SHA256` callsite at `0x100019260`
  - `SetupAESKeys` helper at `0x100016fb8`
- Confirmed runtime sequence:
  1. `ccsrp_get_session_key_length` returns `64`.
  2. `CC_SHA256` hashes the `64`-byte SRP session key buffer.
  3. `SetupAESKeys` receives the first `16` bytes of that digest as the AES key.
  4. `CCCryptorCreate` succeeds four times and writes non-zero `CCCryptorRef` values to the expected out-slots.
- Sample live trace:
  - SRP session key (`64` bytes):
    - `b41b51f8386f183aa58f8f12b703f99ed2cb3885b5d2d9f3955a8407e959222c2c4e55fc1efd7bbaa7ca3b34041663b6f9a94f77fb4ed01f8eeb439efe3dc6ff`
  - SHA-256 digest:
    - `0652090f7321f8d7536ae3ec1de3c13b01993a8fde72ececcae39db218ae3648`
  - Installed AES key (`digest[0:16]`):
    - `0652090f7321f8d7536ae3ec1de3c13b`
- Observed `CCCryptorCreate` outputs from one successful run:
  - `op=0 alg=0 options=0 iv=zero` -> `0x5e8027000`
  - `op=1 alg=0 options=2 iv=NULL` -> `0x5e81f4000`
  - `op=0 alg=0 options=2 iv=NULL` -> `0x5e81f5000`
  - `op=1 alg=0 options=0 iv=zero` -> `0x5e81f6000`
- Interpretation:
  - `confirmed`: auth33 session protection keys are derived as `AES-128 = SHA256(SRP_session_key_64)[0:16]`.
  - `confirmed`: the four local `CCCryptorRef` objects are instantiated successfully with the expected zero-IV vs `NULL`-IV split.

## ChaCha Static Placement (New)
- `_chacha20_poly1305_init_64x64` has only two recovered callsites in `screensharingd`:
  - `0x1000130a0`
  - `0x1000130b0`
- Both callsites sit inside the SRP-layer option setup path rooted near `0x100012f9c`, immediately after the code validates the negotiated `conf+int=ChaCha20-Poly1305` option string.
- Strong inference:
  - this places the real ChaCha initializer in the auth/SRP security-layer setup code, not in `screensharingd::sub_100020ef8` or the later TCP send loop that currently shows CommonCrypto AES usage.
- Remaining runtime requirement:
  - live tracing is still needed to decide whether this auth-layer ChaCha setup is actually exercised in native sessions, or merely available while the observed TCP transport continues with AES cryptors.

## Two-Connection Comparison (Same Capture)
- Capture has two distinct VNC sessions to `:5900`:
  - Stream `0`: `192.168.1.180:57847 -> 192.168.1.172:5900` (start `0.000s`)
  - Stream `2`: `192.168.1.180:57862 -> 192.168.1.172:5900` (start `79.401s`)
- Both streams advertise and select security type `33`, then perform the same three-message auth-33 exchange shape:
  - C->S `655` bytes (`4-byte len + 650-byte RSA1 payload`)
  - S->C `1169` bytes (`4-byte len + 1165-byte SRP challenge payload`)
  - C->S `1080` bytes (`4-byte len + 1076-byte RSA/SRP response payload`)
- Concrete frame pairs:
  - Stream `0`: frames `11` / `13` / `15`
  - Stream `2`: frames `121170` / `121172` / `121174`
- First and second client auth blobs differ across streams (session-unique bytes), while packet structure is invariant.
- This corroborates challenge/session binding and replay resistance.

## Parsed RSA1 Header (Client Message 1)
- Frame `11` (stream `0`) starts with:
  - `00 00 02 8a` -> payload length `0x028a` (`650`)
  - `01 00` -> packet version `0x0100`
  - `52 53 41 31` -> magic `"RSA1"`
  - `00 02` -> `authtype=2` (SRP branch)
  - `01 00` -> aux/subtype `0x0100`
- Frame `121170` (stream `2`) has the same header fields with different key material bytes after offset `+0x0e`.

## Replay Experiment Results
- Tooling:
  - `applehpdebug` with auth-33 probe path in
    `../../examples/client/applehpdebug.c`.
- Tests:
  - Selecting `33` with no handler: fails as unknown auth (expected).
  - Added auth-33 probe/replay path in `applehpdebug` and sent the captured first `RSA1` packet shape.
  - Server accepted first packet and returned a `1165`-byte challenge including `Pmda=...`.
  - Replaying a previously captured second client message yielded `Unknown VNC authentication result: 6` (auth failed).
- Inference:
  - We can drive auth-33 to full challenge/response exchange, but final proof fails with replayed response.
  - Second client message is session-bound (depends on current challenge and credentials), so static replay is insufficient.

## Standalone End-to-End Path (2026-03-14 13:21:19 EDT)
- Environment:
  - target `192.168.1.172:5900`
  - user `testuser`
  - password `changeme`
  - helper `../06-tooling/scripts/screensharing_tools.py`
- Successful standalone generator mode:
  - `VNC_AUTH33_X_MODE=srp_emptyuser_colon_pbkdf2pass`
  - `VNC_AUTH33_PBKDF2_DKLEN=128`
  - `VNC_AUTH33_M1_MODE=rfc5054_emptyuser`
  - `VNC_AUTH33_K_MODE=hn_g`
  - `VNC_AUTH33_U_MODE=a_b`
  - `VNC_AUTH33_KSESSION_MODE=h_padS`
- Client evidence:
  - `auth33: sending helper-generated response (1080 bytes)`
  - `auth33: consumed intermediate server-final packet (98 bytes)`
  - `VNC authentication succeeded`
  - `Connected to VNC server, using protocol version 3.8`
- Server evidence:
  - `2026-03-14 13:21:28.183 ... screensharingd ... Authentication: SUCCEEDED :: User Name: testuser :: Viewer Address: 192.168.1.172 :: Type: RSA-SRP`

## Local Tooling Added (Standalone, No Apple Runtime Dependency)
- Script:
  - `../06-tooling/scripts/auth33_codec.py`
- Capabilities:
  - Parse/build length-prefixed `RSA1` envelopes (`version`, `authtype`, `aux`, body).
  - Parse/build recovered SRP mech buffer formats using tokens:
    - `%c`, `%m`, `%o`, `%s`, `%u`, `%q`
- Example:
  - `auth33_codec.py parse-rsa1 <hexblob>`
  - `auth33_codec.py parse-mech --fmt '%c%m%m%o%m%q%s' <hexblob>`
- Purpose:
  - Forms the foundation for writing our own auth-33 generator/debug client without invoking private Apple binaries.

## Relevant Binary Locations
- Server auth logic:
  - `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd`
- Client auth logic:
  - `/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Support/Shared Screen Viewer.app/Contents/MacOS/Shared Screen Viewer`
- Additional server-side RFB path:
  - `/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/MacOS/AppleVNCServer`

## Confidence
- `confirmed`: type `33` = RSA-SRP family and includes SRP RFC5054-4096 + SHA-512 + ChaCha20-Poly1305/KDF negotiation.
- `strong-inference`: first client packet includes ephemeral/session-bound cryptographic data.
- `strong-inference`: packet-2 384-byte tail is likely uninitialized/residual heap data for this SRP branch.
- `confirmed`: tail beyond `aux` is ignored by server in auth33 decrypt/parse stage.
- `confirmed`: standalone packet-2 generation now interoperates without the native oracle.
- `confirmed`: password preprocessing is PBKDF2-SHA512 with challenge salt/rounds and `dkLen=128`.
- `confirmed`: packet-2 trailing `%o` is 16 random bytes.
- `confirmed`: successful standalone proof uses empty SRP username and RFC5054-style `M1`.
- `confirmed`: post-SRP local AES key is `SHA256(session_key_64)[0:16]`, and `SetupAESKeys` creates four `CCCryptorRef` objects successfully.
- `open`: exact Apple-internal random exponent generation details for `a`.
