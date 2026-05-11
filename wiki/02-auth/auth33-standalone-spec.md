# Auth33 Standalone Specification (24G231)

## 1. Purpose
- Define a complete standalone implementation of Apple Screen Sharing auth type `33` packet-2 generation for the active `24G231` sample.
- Eliminate dependency on native Screen Sharing packet output as an oracle.
- Provide a setup procedure, component model, computation specification, helper usage contract, and validation criteria.

## 2. Scope
- In scope:
  - auth type `33` / `RSA-SRP`
  - packet-2 generation
  - packet grammar
  - challenge parsing
  - password preprocessing
  - SRP proof computation
  - helper integration with `applehpdebug`
  - live validation against `192.168.1.172:5900`
- Out of scope:
  - full packet-1 bootstrap reimplementation details beyond required compatibility
  - builds not matching the canonical `24G231` sample
  - post-auth display or media behavior

## 3. Status
- `confirmed`
  - standalone packet-2 generation succeeds end-to-end
  - server accepts the standalone proof as `RSA-SRP`
  - password preprocessing is `PBKDF2-HMAC-SHA512(..., dkLen=128)`
  - packet-2 trailing `%o` field is 16 fresh random bytes
  - 384-byte body suffix outside `aux` is ignored by the server in this stage
- `strong-inference`
  - Apple’s internal random exponent size policy for `a` is not required for interoperability

## 4. Inputs
- Challenge file:
  - hex text containing the full server auth33 challenge packet body
- Runtime environment:
  - `VNC_AUTH33_USER`
  - `VNC_AUTH33_PASS`
  - or fallback `VNC_USER`, `VNC_PASS`
- Challenge-derived fields:
  - `N`
  - `g`
  - `salt`
  - `B`
  - `iterations`
  - `options`

## 5. Required Components

### 5.1 Packet Codec
- File:
  - `../06-tooling/scripts/auth33_codec.py`
- Responsibilities:
  - parse/build `RSA1` envelopes
  - parse/build mech blobs for `%c`, `%m`, `%o`, `%s`, `%u`, `%q`

### 5.2 Standalone Generator
- File:
  - `../06-tooling/scripts/screensharing_tools.py`
- Responsibilities:
  - parse live challenge
  - compute `A` and `M1`
  - generate fresh 16-byte client field
  - emit packet-2 hex to stdout

### 5.3 Debug Client
- File:
  - `../../build/examples/client/applehpdebug`
- Responsibilities:
  - negotiate auth type `33`
  - invoke helper
  - send standalone packet-2
  - consume intermediate server-final packet before `SecurityResult`

### 5.4 Validation Logs
- Client log: from the 2026-03-14 13:21:19 standalone validation run (default.log)
- Server log snippet: from the 2026-03-14 13:21:19 standalone validation run (server_log_snippet.txt)

## 6. Packet Grammar

### 6.1 Challenge Packet
- Parsing starts at byte offset `+10`
- Format:
  - `%c%m%m%o%m%q%s`
- Semantics:
  - `%c` -> `0x00`
  - `%m` -> `N`
  - `%m` -> `g`
  - `%o` -> `salt`
  - `%m` -> `B`
  - `%q` -> iteration count
  - `%s` -> option string

### 6.2 Packet-2 Inner Payload
- Format:
  - `%m%o%s%o`
- Semantics:
  - `%m` -> padded client SRP public `A`
  - `%o` -> `M1`
  - `%s` -> copied option string
  - `%o` -> 16-byte client random field

### 6.3 Packet-2 RSA1 Envelope
- `packet_version = 0x0100`
- `authtype = 0x0002`
- `aux = len(u16_zero || u16_inner_len || inner)`
- Body:
  - `u16 0x0000`
  - `u16 inner_len`
  - `inner`
  - trailing ignored bytes, length `384` in the accepted standalone implementation

## 7. Computation Specification

### 7.1 Normalization
- Let `pad_len = len(N_bytes)`.
- `PAD(x)` means big-endian left-padding to `pad_len`.
- Hash function `H` is SHA-512.
- Integer conversion uses big-endian OS2IP semantics.

### 7.2 Password Preprocessing
- Input password encoding:
  - UTF-8
- Formula:
  - `P' = PBKDF2-HMAC-SHA512(password_utf8, salt, iterations, 128)`
- Confirmed parameters:
  - `salt = challenge salt`
  - `iterations = challenge %q`
  - `dkLen = 128`

### 7.3 SRP Username Convention
- SRP username input for packet-2 proof generation is the empty string.
- The login user name used for successful server-side account mapping is not part of step-2 `x/M1` computation.

### 7.4 SRP Values
- `x = H(salt || H(b":" || P'))`
- `k = OS2IP(H(PAD(N) || PAD(g)))`
- Choose fresh non-zero random secret exponent `a`
- `A = g^a mod N`
- `u = OS2IP(H(PAD(A) || PAD(B)))`
- `v = g^x mod N`
- `S = (B - k*v mod N)^(a + u*x) mod N`
- `K = H(PAD(S))`
- `M1 = H(H(PAD(N)) xor H(PAD(g)), H(b""), salt, PAD(A), PAD(B), K)`

### 7.5 Client Random Field
- Generate 16 fresh random bytes.
- Source used by Apple client:
  - `CCRandomGenerateBytes`
- Standalone requirement:
  - any cryptographically strong random source is acceptable

### 7.6 Output Assembly
1. Encode `inner = %m%o%s%o`.
2. Prefix with `u16 0x0000` and `u16 len(inner)`.
3. Set `aux` to the length of that bounded body.
4. Append trailing bytes.
5. Emit full RSA1 envelope hex.

## 8. Setup Tasks

### 8.1 Build or Verify Client
1. Ensure the binary exists:
   - `../../build/examples/client/applehpdebug`
2. If missing, run the following from the libvncserver root:
```bash
cmake -S . -B build \
  -DWITH_EXAMPLES=ON -DWITH_TESTS=OFF
cmake --build build \
  --target client_examples_applehpdebug -j8
```

### 8.2 Configure Environment
```bash
export VNC_USER='testuser'
export VNC_PASS='changeme'
export VNC_AUTH_SCHEMES='33'
export VNC_AUTH33_REPLAY='1'
export VNC_AUTH33_HELPER='../06-tooling/scripts/screensharing_tools.py'
export VNC_AUTH33_X_MODE='srp_emptyuser_colon_pbkdf2pass'
export VNC_AUTH33_PBKDF2_DKLEN='128'
export VNC_AUTH33_M1_MODE='rfc5054_emptyuser'
export VNC_AUTH33_K_MODE='hn_g'
export VNC_AUTH33_U_MODE='a_b'
export VNC_AUTH33_KSESSION_MODE='h_padS'
```

### 8.3 Run Validation
```bash
../06-tooling/scripts/screensharing_workflows.sh auth33 applehpdebug \
  192.168.1.172 5900 20
```

## 9. Helper Contract
- Invocation:
  - `helper <challenge_hex_file>`
- Input:
  - file containing challenge hex
- Output:
  - response hex to stdout
- Required behavior:
  - non-zero exit on failure
  - do not emit non-hex content to stdout

## 10. Usage Notes
- The standalone generator is deterministic with respect to:
  - challenge fields
  - password
  - selected SRP mode
- It is intentionally non-deterministic in:
  - secret exponent `a`
  - trailing 16-byte client field
- Replaying stale packet-2 data against a fresh challenge is not valid.

## 11. Validation Criteria
- Client-side success indicators:
  - `auth33: sending helper-generated response`
  - `auth33: consumed intermediate server-final packet (98 bytes)`
  - `VNC authentication succeeded`
  - `Connected to VNC server`
- Server-side success indicator:
  - `Authentication: SUCCEEDED :: User Name: testuser :: Type: RSA-SRP`

## 12. Completed Investigation Outcome
- The investigation objective for standalone packet-2 generation is complete for the canonical `24G231` sample.
- Remaining unresolved work is limited to Apple-internal implementation details that do not block interoperability.
