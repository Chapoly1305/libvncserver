# Investigation TODO (24G231)

## Purpose
- Maintain a stable list of open reverse-engineering tasks for macOS Sequoia `24G231` Screen Sharing.
- Keep each task grounded in current evidence, not memory.
- Separate `confirmed`, `strong-inference`, and `open` items so later work does not drift.

## How To Use This Page

- Use this page for unresolved work, not for the best summary of confirmed protocol facts.
- If an item becomes stable and durable, move its explanation to findings or reference pages and leave only the remaining question here.
- When a question is primarily about the standalone client implementation, prefer [client-implementation-track.md](client-implementation-track.md).

## Scope
- Build: macOS Sequoia `24G231`
- Workspace root: current repo

## Current Top Open Questions

- What is the exact DCT quantization table and coefficient encoding for `0x3f3` DCT tiles? The tile command bitstream structure (White, MatchPrevious, MatchAbove, TwoColor, DCT) is now resolved, but the DCT coefficient packing details are not yet decoded.
- What is the exact semantic role of the `EncodeEncryptionInfo` generation/counter field?
- What is the exact semantic meaning of later client `0x10` records and the remaining HP follow-up traffic after `0x3f2`?
- Which remaining post-auth message families still need full field-level schemas, especially beyond the first confirmed Apple-private burst?

## Adaptive Mode Encoding Tiers

The encoding-tier model is settled — see [../05-high-performance/encoding-tiers.md](../05-high-performance/encoding-tiers.md) for the tier table, URL-parameter mapping, and per-encoding pipeline.

## Current Background
- `confirmed`: auth33 is Apple `RSA-SRP`.
- `confirmed`: after SRP success, `screensharingd` derives an AES-128 key from `SHA-256(session_key)[0:16]`.
- `confirmed`: `SetupAESKeys` installs four CommonCrypto contexts:
  - `viewer + 0x5f0`: AES-CBC encrypt
  - `viewer + 0x5f8`: AES-ECB decrypt
  - `viewer + 0x600`: AES-ECB encrypt
  - `viewer + 0x5e8`: AES-CBC decrypt
- `confirmed`: the binary also contains a real `ChaCha20-Poly1305` initialization path in the SRP layer code.
- `open`: which transport path is active for each post-auth message family in the native TCP session.
- `confirmed` on viewer build `24G419`: native machine/VNC sessions can activate HP, with viewer-side logs showing `usingVirtualDisplay 1`, `ProMode enabled`, and `dynamic resolution enabled on server`.
- `confirmed` on viewer build `24G419`: Apple ID uses a different quick-relay / `NWDatagramConnection` / AVConference path instead of the plain machine/VNC TCP connection class.
- `confirmed` on viewer build `24G419`: Apple ID can still fail before a stable HP-style path comes up when the remote AVConference sidecar tears down.
- `confirmed` on correlated local+remote run for viewer build `24G419`: the first concrete Apple ID failure is remote `avconferenced` failing the AVConference client start with `GKVoiceChatServiceErrorDomain Code=32000 "Client ... failed to start"`, which propagates back to the viewer as `Remote participant hangup` and later `LocalHangup`.
- `confirmed` on deeper remote `avconferenced` logs: the startup failure includes CoreAudio/AUVP errors finding a usable input device and creating an aggregate audio device (`err=-10876`).
- `reference`: `../05-high-performance/viewer-track-24G419.md`

## Current Apple ID / HP Open Question
- `open`: why remote `avconferenced` fails to start the AVConference client on the Apple ID Screen Sharing path.
- `narrowed`: remote `avconferenced` is failing in audio-device startup, not in viewer auth or basic RFB bring-up.
- `open`: whether the failure is caused by the remote host having no default input device, by specific third-party audio devices, or by AVConference policy for this Screen Sharing path.
- `not open anymore`: whether the viewer popup / `Communications error` is the primary cause.
- `strong-inference`: viewer teardown is secondary cleanup after remote AVConference startup failure.
- `open`: whether Apple ID quick-relay sessions ever switch to the same UDP media branch implied by `SSUDPSender`, or whether the observed relay datagram path is distinct from that classic HP UDP branch.

## Current Post-Auth Read
- Capture:
  - `capture.pcapng`
- Main decoded stream:
  - `tcp.stream==2`
- Current message mapping:
  - frame `625`
    - `confirmed`: `ServerInit`
  - frame `631`
    - `confirmed`: `ViewerInfo`
  - frame `638`
    - `confirmed`: `HandleViewerCutTextMessage`
  - frame `641`
    - `confirmed`: `EncodeEncryptionInfo`
  - frame `645`
    - `confirmed`: first opaque post-rekey server burst

## Crypto Status
- `confirmed`: frame `641` matches the `EncodeEncryptionInfo` sender path in `screensharingd::sub_100020ef8`.
- `confirmed`: that path uses `CCCryptorUpdate(*(viewer + 0x600), ...)`.
- `confirmed`: `viewer + 0x600` is the AES-ECB encrypt context.
- `confirmed`: frame `641` therefore proves AES-ECB is used for at least one post-auth control packet.
- `confirmed`: frame `641` layout is:
  - 16-byte `0x44f` control header
  - 4-byte generation/counter from `viewer + 0x8cc`
  - 16-byte AES-ECB-encrypted block from `viewer + 0x8d2`
  - 16-byte AES-ECB-encrypted block from `viewer + 0x8e2`
- `confirmed`: single-block replay against the same-session wrap key matches both ciphertext blocks under AES-ECB.
- `confirmed`: a one-block AES-CBC replay with zero IV also matches each block by construction, so cryptographic replay alone is not the deciding factor for mode selection here.
- `confirmed`: the deciding mode evidence is the runtime `CCCryptorCreate` state for the wrap cryptor: `options=2` with `iv_ptr=NULL`, which is the CommonCrypto ECB configuration.
- `not confirmed`: that later bulk session traffic also uses ECB.
- `confirmed`: the later opaque post-auth record layer does not use the original SRP-derived AES key directly.
- `confirmed`: the matching Frida trace recovered the next transport key and IV for frame `641` directly:
  - next key:
    - `c3754936827b3c2c984f19a46625de41`
  - next IV:
    - `03767a819658423f8ffb351989369543`
- `confirmed`: later opaque packets use a length-prefixed AES-CBC record layer with the rekeyed material distributed by frame `641`.
- `not evidenced`: AES-GCM in the native TCP path.
- `present in binary but not yet tied to this session path`: ChaCha20-Poly1305.
- `confirmed`: the current `capture.pcapng` run and the earlier 2026-03-15 00:13:05 transport trace run both prove the `EncodeEncryptionInfo` rekey model and immediate AES context rebuild.

## What We Need To Determine
- Which post-auth message families use:
  - the CBC record layer
  - the ECB-wrapped fixed-size control path
  - or some other path
- The exact semantic role of the `viewer + 0x8cc` counter/generation field.
- Full message schemas and handler mapping for the Apple-specific rekeyed records (`0x451`, `0x453`, `0x455`, `0x456`, and smaller client controls).
- Whether any later post-auth TCP family performs another ECB-wrapped rekey/update beyond the first confirmed one.

## Active TODOs

### T1. Prove Frame `641` End-To-End
- Status:
  - `completed`
- Result:
  - `confirmed`: runtime `CCCryptorUpdate` output for the `0x44f` path matches the on-wire `EncodeEncryptionInfo` packet byte-for-byte
- Evidence:
  - static sender path in `screensharingd::sub_100020ef8`
  - Frida transport trace from the 2026-03-15 00:13:05 transport trace capture
  - live packet correlation from the same 2026-03-15 00:13:05 transport trace capture

### T2. Resolve Bulk Post-Auth Transport Mode
- Status:
  - `completed` for the first opaque TCP record family model; current active capture is `capture.pcapng` stream `2`
- Result:
  - `confirmed`: `screensharingd::sub_10001d19c` uses `EncryptOneMessage` (`screensharingd::sub_100054888`) with `viewer + 0x5f0` to send later post-auth encrypted records
  - `confirmed`: `screensharingd::sub_100031d8c` uses `DecryptNextMessage` + `DecryptOneMessageWithComCryption` (`screensharingd::sub_100054a74`) with `viewer + 0x5e8` to receive them
  - `confirmed`: those records are framed as:
    - `u16_be ciphertext_len`
    - `ciphertext`, where ciphertext length is a multiple of 16
  - `confirmed`: decrypted plaintext is framed as:
    - `u16_be plaintext_len`
    - `plaintext_body`
    - PKCS#7-like pad bytes up to a 16-byte boundary
    - trailing `20`-byte SHA-1 over `u32_be sequence || plaintext_without_hash`
  - `confirmed`: the initial CBC key/IV for this record family are the rekeyed values distributed by `EncodeEncryptionInfo`
- Evidence:
  - `screensharingd::sub_100054888` pads, hashes, and encrypts with `CCCryptorUpdate(arg4, ...)`
  - `screensharingd::sub_10001d19c` passes `viewer + 0x5f0` and prepends the outer `u16_be ciphertext_len`
  - `screensharingd::sub_100031d8c` reads `u16_be ciphertext_len` from the wire and calls `screensharingd::sub_100054a74(..., viewer + 0x5e8)`
  - earlier validated runs show the derived key/IV decrypt later post-auth frames into valid plaintext
- Remaining work:
  - classify every record family using the decrypted plaintext
  - determine whether any later message family still uses the ECB path

### T3. Investigate Whether ChaCha20-Poly1305 Is Ever Active In Practice
- Goal:
  - decide whether the native session ever takes the ChaCha path after auth33 negotiation
- Why:
  - the auth33 option string advertises `conf+int=ChaCha20-Poly1305`
  - the binary contains a real ChaCha init path
  - current TCP transport evidence still points at CommonCrypto AES contexts
- Current static position:
  - `strong-inference`: the only `screensharingd` callsites to `_chacha20_poly1305_init_64x64` are in the SRP-layer option setup path near `0x100012f9c`, not in the post-auth send loop or the `0x44f` rekey path
- What to do:
  - trace xrefs from `_chacha20_poly1305_init_64x64`
  - inspect the surrounding layer-init structures and activation flags
  - compare those flags against the viewer/session state used by the TCP send loop
  - add runtime hooks if needed to detect any ChaCha init/use during a real session
- Success condition:
  - either:
    - ChaCha is observed in the live session path
  - or:
    - ChaCha is shown to be negotiated but not used on this TCP transport path

### T4. Rule In Or Rule Out AES-GCM
- Status:
  - `completed` for current static scope
- Result:
  - `confirmed`: no AES-GCM evidence was found in the `screensharingd` transport path for the active sample
- Evidence:
  - import table exposes `CCCryptorCreate`, `CCCryptorUpdate`, and `chacha20_poly1305_init_64x64`, but no `CCCryptorGCM` or GCM-specific CommonCrypto entrypoints
  - string/corpus search across the `screensharingd.arm64e` binary, framework-cache selector evidence, and symbol packs found no `GCM`, `AES-GCM`, or `CCCryptorGCM` hits tied to the transport path
- Remaining caveat:
  - this closes the static `screensharingd` question, not every possible unrelated framework on the system

### T5. Decode The Exact `EncodeEncryptionInfo` Packet Layout
- Status:
  - `completed` for packet layout
- Result:
  - `confirmed`: frame `641` is a standard RFB `FramebufferUpdate` carrying one rectangle with encoding `0x44f`
  - `confirmed`: packet body layout is:
    - 4-byte `FramebufferUpdate` header (`msg=0`, `pad=0`, `num_rects=1`)
    - 12-byte rectangle header (`x=0`, `y=0`, `w=0`, `h=0`, `encoding=0x44f`)
    - 4-byte generation/counter from `viewer + 0x8cc`
    - 16-byte AES-ECB-encrypted block from `viewer + 0x8d2`
    - 16-byte AES-ECB-encrypted block from `viewer + 0x8e2`
- Evidence:
  - `screensharingd::sub_10001cd40` writes the exact `FramebufferUpdate` + rectangle header seen on the wire
  - `screensharingd::sub_100020ef8` copies the counter and the two 16-byte source blocks, encrypting the latter with `CCCryptorUpdate(*(viewer + 0x600), ...)`
  - frame `641` in `capture.pcapng` matches the reconstructed 52-byte layout
- Remaining work:
  - semantic naming of the counter/key/IV fields stays in `T5a`

### T5a. Resolve `EncodeEncryptionInfo` Semantics Completely
- Status:
  - `completed` for rekey semantics
- Result:
  - `confirmed`: `viewer + 0x8d2` is the next transport AES key and `viewer + 0x8e2` is the companion IV distributed by `EncodeEncryptionInfo`
  - `confirmed`: the packet is immediately followed by `CCCryptorCreate` calls that rebuild CBC and ECB cryptors from that material
  - `open`: the exact semantic meaning of the `viewer + 0x8cc` counter/generation field remains unresolved
- Evidence:
  - static `screensharingd::sub_100020ef8` field copies and `CCCryptorCreate` calls
  - runtime Frida transport trace proving plaintext material and rekey callsites
  - the matching current-run Frida trace recovers key `c3754936827b3c2c984f19a46625de41` and IV `03767a819658423f8ffb351989369543` for the `0x44f` packet

### T5b. Catalogue The First Rekeyed CBC Records
- Goal:
  - label the first decrypted post-auth messages after the `EncodeEncryptionInfo` rekey
- Why:
  - we now have working decryption for the first opaque record family
  - the next gain is protocol naming, not crypto guessing
- Current confirmed decodes:
  - server frame `756` contains three records:
    - encoding `0x451`
    - encoding `0x453`
    - encoding `0x455`
  - server frame `759` contains one record:
    - encoding `0x456`
    - body includes `Mac16,10` and two `unknown` strings
  - client frame `761` decrypts to a valid `SetPixelFormat`
  - client frame `765` decrypts to a valid `SetEncodings` carrying:
    - `0xffffff11`
    - `0x450`
    - `0x44c`
    - `0xffffff21`
    - `0x44d`
    - `0x451`
    - `0x453`
    - `0x455`
    - `0x456`
  - client frame `776` repeats a valid `SetPixelFormat`
  - client frames `771` and `780` each contain:
    - a standard `FramebufferUpdateRequest` for `3840 x 2160`
    - one repeated client type `0x09` `HandleAutoFrameBufferUpdateMessage`
      - version / selector `1`
      - selected-screen / target `0xffffffff`
      - region `0,0 3840x2160`
  - client frame `768` is client type `0x15` `HandleAutoPasteboardCommand`
    - selector `2`
- Current semantic mapping:
  - `0x450` -> `CursorImage`
  - `0x451` -> `AppleDisplayLayout` / display-layout update
  - `0x453` -> `VendorKeysymEncoding` / vendor-keysym update
  - `0x455` -> `KeyboardInputSource` / keyboard-layout update
  - `0x456` -> `DeviceInfo` / device-info update
- Current confirmed semantic mapping:
  - `0x451` -> `AppleDisplayLayout`
    - backed by geometry-heavy decrypted bodies, host logs `EncodeDisplayInfo` and `encode display info2 ...`, and viewer-side `handleDisplayInfo2:` / `handleDisplayInfo2b:...` consumers
  - `0x453` -> `VendorKeysymEncoding`
    - backed by server-side `HandleSetEncodingsMessage`, which treats `0x453` as `vendor keysyms supported`, the viewer-side `handleVendorKeysymEncoding:` symbol, and the decrypted four-`u32` body shape
  - `0x455` -> `KeyboardInputSource`
    - backed by server-side `HandleSetEncodingsMessage`, which treats `0x455` as `keyboard input language encoding`, plus decrypted `com.apple.keylayout.US`, host logs `SendKeyboardSourceInfoToDaemon` and `keyboardInputSourceStringSize`, and viewer-side keyboard-layout consumers
  - `0x456` -> device-info update
    - backed by host log `RFBDeviceInfoMessageEncoding ...`, decrypted `Mac16,10`, live viewer-binary paths `sessionFetchedDeviceInfo:` and `SessionStateProvider updateDeviceInfoWithConnectionIdentifier:deviceInfo:error:`, and static `EncodeDeviceInfoMessage` builder coverage for identifier/color/enclosure-color/housing-color fields
- Resolution-change note:
  - `0xffffff21` remains the standard `DesktopSize` pseudo-encoding
  - `SendResolutionChargeToViewer` emits `EncodeDesktopSize` with `0xffffff21`; it does not prove `0x453`
- What to do:
  - finish the remaining `0x451` field mapping and relate it cleanly to `DesktopSize`
  - recover the exact numeric encoding-to-handler dispatch table in the viewer
  - determine the exact user-facing meaning of auto-pasteboard selectors `1` vs `2`

### T5c. Extend The Session-Aware Wireshark Decoder
- Status:
  - `in_progress`
- Goal:
  - make the dissector reflect the confirmed transport model instead of only offering exploratory AES guesses
- Current state:
  - `confirmed`: the Lua plugin now derives the next key/IV from `EncodeEncryptionInfo` when the initial AES key is provided
  - `confirmed`: it tracks per-stream CBC state and decodes the first confirmed rekeyed record family
- Remaining work:
  - packet reassembly across split TCP segments
  - richer field-level parsing for `0x451`
  - support for later rekeys if additional `0x44f` packets appear
  - optional import of runtime-derived keys without manual preference entry

### T6. Continue The Server->Client Cleartext Setup Window
- Status:
  - `completed` for the active `capture.pcapng` stream `2` window
- Result:
  - `confirmed`: the cleartext setup window for this stream is fully accounted for by frames `625`, `631`, `638`, `641`, and `647`
  - `confirmed`: the first opaque post-rekey server burst begins at frame `645`, while frame `647` is a trailing client-side cut-text header
- Evidence:
  - payload-bearing frames in the setup window resolve to:
    - `625` -> `ServerInit`
    - `631` -> `ViewerInfo`
    - `638` -> `ViewerCutText`
    - `641` -> `EncodeEncryptionInfo`
    - `647` -> `ViewerCutText`
    - `603` -> `ViewerCutText`
  - `tshark` enumeration on `tcp.stream==7` shows no intervening payload frames after `603` before the later opaque records

## Supporting Artifacts
- Post-auth setup ledger:
  - `../04-runtime-evidence/post-auth-stream7-ledger.md`
- Auth33 reconstruction:
  - `../02-auth/auth33-reconstruction.md`
- Authentication pipeline:
  - `../02-auth/authentication-pipeline.md`
- Wireshark dissector:
  - `../06-tooling/wireshark/apple_screensharing_auth33.lua`
- Runtime transport tracer:
  - `../06-tooling/scripts/frida_screensharingd.js`
  - `../06-tooling/scripts/screensharing_workflows.sh daemon-frida transport`
- Live transport proof: the 2026-03-15 00:13:05 transport trace analysis

## Notes For Future Passes
- Do not assume the auth33 option string tells you the active record-layer cipher.
- Treat control packets and bulk framebuffer/session packets separately.
- When claiming a transport mode, prefer:
  - Binary Ninja call path
  - runtime hook evidence
  - packet correlation
  - only then plaintext plausibility
