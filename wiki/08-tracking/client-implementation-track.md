# Client Implementation Track

This page is a scoped worklog for the standalone client effort. It is not the canonical reverse-engineering summary; use [open-questions.md](open-questions.md) and [../00-overview/current-status.md](../00-overview/current-status.md) for the current investigation state, and the topical section pages (e.g. [../03-transport/startup-sequence.md](../03-transport/startup-sequence.md), [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md)) for protocol-level definitions.

## Objective
- Turn the current auth33 proof-of-concept into a functional Apple Screen Sharing client.

## Completed
- Auth33 handshake works end-to-end via the standalone generator path.
- Intermediate server-final packet handling is understood and implemented.
- Framebuffer streaming is validated.
- First-frame and periodic frame dumps are validated.
- Stream telemetry is logged with frame counts and FPS summary.
- Native auth33/ProMode cleartext prelude is now reproduced correctly for the localhost path:
  - `ViewerInfo` exact `66`-byte payload
  - `SetEncryptionMessage` exact `12`-byte command-1 payload
  - no pre-`0x44f` cleartext `318`-byte `SetDisplayConfiguration` blob on the working localhost HP path
- Post-`0x44f` standalone transport now decrypts, consumes, and sends the first Apple AES-CBC record family:
  - extra cleartext `SetEncryptionMessage` command-2 payload `1200000200010000`
  - encrypted preface `0x1d SetDisplayConfiguration`, then `0x02 SetEncodings`
  - first encrypted server burst `0x451`, `0x453`, `0x455`, `0x456` consumed as Apple-private framebuffer-update rectangle encodings
  - later client burst aligned closely enough with native ordering to sustain localhost framebuffer streaming for the full timed run

## Current Track
- `T1` Complete: auth33 connectivity and server compatibility.
- `T2` Complete: framebuffer stream acquisition and artifact capture.
- `T3` Complete: live viewer path on top of the working auth33 client.
- `T4` In Progress: pointer and keyboard input path.
- `T5` Complete: standalone packet-2 generation is the maintained auth33 path.
- `T5.1` Complete: standalone packet-1 generation is now the default maintained auth33 path on macOS.
- `T6` In Progress: determine whether Apple-specific high-performance / ProMode transport can be negotiated from this client base.

## Immediate Next Steps
- Verify pointer and keyboard event injection against the same target.
- Keep the standalone generator as the default runner path.
- Keep the in-process packet-1 generator as the default auth33 path; reserve `VNC_AUTH33_INIT_KEY_HEX` / `VNC_AUTH33_INIT_HELPER` for debugging only.
- Keep headless mode intact so the existing stream runner remains stable.
- Keep the native encrypted preface enabled by default on the auth33 HP path unless a target-specific regression appears.
- Keep libvncclient incremental polling suppressed once `0x09 AutoFrameBufferUpdate` is active on the HP path; the native viewer does not flood encrypted `0x03` requests after startup.
- Tighten post-rekey transport logging so large framebuffer payload records are not mislabeled as fresh RFB messages.
- Capture native and standalone runtime evidence side-by-side for the same server and same user action sequence.
- Snapshot `/tmp/screensharing.log` into trace folders and extract HP/UDP/pro-mode markers after each run.
- Use the existing BN-derived symbols as a fixed hypothesis set instead of reverse engineering blind.

## Two Workstreams
- `Interactive VNC`
  - send pointer events
  - send wheel events
  - send key up/down and text input
  - verify no disconnect/regression while interacting
- `High-Performance Transport`
  - identify the negotiation messages beyond auth33 + RFB init
  - determine whether libvncclient can carry the required extension messages directly
  - verify whether UDP / video path is actually active at runtime
  - compare standalone client traces against native Screen Sharing traces
  - correlate `screensharingd` / `ScreensharingAgent` logs with packet captures and client logs
  - confirm whether Apple-specific promotion gates are missing in our client or blocked by server policy

## Evidence Sources
- Runtime logs:
  - `/tmp/screensharing.log`
  - per-scenario unified log streams (`log_stream.ndjson`) from each run
- Client logs:
  - per-run standalone client logs (`client.log`)
  - per-run auth33 standalone validation logs (`default.log`)
- Static/Binary Ninja-derived artifacts:
  - `../07-reference-generated/symbols/ScreensharingAgent.md`
  - `../07-reference-generated/symbols/screensharingd.bn.md`
  - `../05-high-performance/static-guard-matrix.md`

## Adaptive Mode Encoding Analysis (2026-05-11)

- `confirmed` from `ScreenSharing.framework` (24G419): the native viewer selects
  encodings via `+[SSSession qualityEncodingsForMode:withDisplayConfiguration:]`.
  Five tiers exist: Full (mode 4), Low (mode 1), Medium (mode 2), High (default),
  High+ProMode (default + gate).
- `confirmed`: High tier = `[0x3f3, 0x3ea, zlib, zrle]`. High+ProMode adds `0x3f2`
  at the front.
- `confirmed`: mode selection is via the `quality` URL parameter on `vnc://`
  connections (`quality=low|medium|full|high`), not bandwidth/latency-adaptive.
- `confirmed` from `screensharingd::EncodeZlib` (24G231):
  - `0x3e8` (Low): 4-bit color + deflate level 9
  - `0x3e9` (Medium): 8-bit YCoCg dither + deflate level 6
  - `0x3ea` (High): 16-bit RGB 5-6-5 + deflate level 1
  - `0x3f3` (MVS): GPU per-tile adaptive via agent RPC
- The standalone client now advertises `0x3f3` and `0x3ea` (plus `0x3f2` via
  `VNC_APPLE_HP_ADD_PROMODE_ENCODING`). `0x3f3`/`0x3ea` rectangle handlers exist
  but do not decode content yet; zlib remains the primary framebuffer encoding.
- `confirmed` (2026-05-11): `0x3f3` MVS wire format resolved at the tile-type
  level. Rectangle body = tile_width (1B) + tile_height (1B) + command bitstream
  + render_data + trailer. Tile types: 0=White/Skip, 1=MatchPrevious,
  2=MatchAbove, 3=TwoColor(B&W), 4=TwoColor, DCT=complex. OpenCL kernel
  `EncodeVectorized` in ScreensharingAgent does GPU-parallel tile classification.
  DCT coefficient packing details remain open.
- `0x3e8`/`0x3e9`/`0x3ea` rectangles are zlib-compressed with pre-processing;
  they may be decodable with standard zlib inflate after reversing the
  pre-processing step (4-bit, 8-bit dither, or 16-bit color).
- Next step for T6: implement `0x3f3` wire-format decoder to use the
  multi-variant codec as the primary framebuffer encoding.
  - `wiki/01-architecture/state-machine.md`

## Current Hypotheses For T6
- The current standalone client is still using the standard TCP framebuffer path.
- Apple high-performance mode requires additional post-auth session modification messages not yet sent by `libvncclient`.
- Promotion to HP likely depends on viewer capability/config messages that align with:
  - `Set server stream config viewerID %d startingUDPPort %d`
  - `supports60FPS`
  - ProMode/session-acceleration gates
- If HP is active, runtime evidence should include one or more of:
  - `ProMode active`
  - UDP-related `screensharingd` or `ScreensharingAgent` messages
  - sustained UDP flows in packet capture after auth/session setup

## New Localhost Findings
- `confirmed`: localhost forced to security type `33` accepts the corrected native cleartext prelude (`ViewerInfo` + `SetEncryptionMessage` + `SetModeMessage`, without the stale cleartext `318`-byte `SetDisplayConfiguration` blob) and emits `EncodeEncryptionInfo (0x44f)`.
- `confirmed`: post-`0x44f` transport handoff in the standalone client had a real buffering bug:
  - `libvncclient` can already have encrypted post-rekey bytes buffered when `0x44f` is handled
  - zeroing `client->buffered` / bypassing `client->bufoutptr` at CBC enable time drops or desynchronizes those bytes
  - localhost traces proved this with a coalesced `0x44f` + first encrypted server record in one TCP chunk
- `confirmed`: the previous standalone `ViewerInfo` / `SetDisplayConfiguration` replay bug was partly self-inflicted:
  - `ViewerInfo` had been sent as `68` bytes instead of the native `66`
  - `SetDisplayConfiguration` had incorrectly included the separate `SetEncodings` payload
- `confirmed`: after `0x44f`, the localhost path uses the same Apple AES-CBC record layer model as the native trace.
- `confirmed`: sequence handling for the current standalone localhost encrypted exchange is:
  - first decrypted server record uses receive sequence `0`
  - when the encrypted preface is disabled, the first encrypted client record uses send sequence `0`
- `confirmed`: saved native `2026-03-15` pcap evidence shows the auth33 viewer does consume encrypted client send sequences before `0x0d`:
  - frame `177` carries `EncodeEncryptionInfo` with generation/counter `1`
  - frame `179` is the extra cleartext `1200000200010000`
  - frame `181` is a `338`-byte client->server encrypted record whose size matches encrypted `0x1d SetDisplayConfiguration`
  - frame `185` is an `82`-byte client->server encrypted record whose size matches encrypted `0x02 SetEncodings`
  - the native `0x0d` plaintext checksum proves that later record uses send sequence `2`
- `strong-inference`: the current standalone localhost failure after sending `0x0d` with send sequence `0` is at least partly explained by the missing native encrypted preface, not just by malformed `0x0d` transport wrapping.
- `confirmed`: the auth33 packet-1 RSA plaintext is now recovered from the native viewer instead of guessed:
  - viewer-side `SecKeyEncrypt(..., padding=PKCS1)` runs immediately before the `654`-byte type-2 RSA1 init write
  - Binary Ninja on `ScreenSharing.framework::_srp_client_mech_step` plus the runtime trace now decode that plaintext as `u32_be payloadLen || %s(\"\") || %s(username) || %s(\"\") || %o(empty)`
  - for `alex`, the plaintext bytes are `0000000b00000004616c6578000000`
  - the matching wire packet still uses `aux=0x0100`; first `256` body bytes are ciphertext and the remaining `384` body bytes are zero
- `confirmed`: generating packet-1 ciphertext from the type-0 DER public key reply with PKCS#1 RSA now works against the live host:
  - a temporary helper using `openssl pkeyutl -encrypt -pubin -keyform DER -pkeyopt rsa_padding_mode:pkcs1` authenticates successfully
  - the standalone client now performs that same step in-process with `SecKeyCreateEncryptedData`
  - forced-auth33 localhost runs succeed without any compiled packet-1 ciphertext blob and without `VNC_AUTH33_INIT_HELPER`
- `confirmed`: the first localhost post-rekey server record currently observed by the standalone client is message `0x14` with body:
  - `140000040001000c`
  - or on a quiet run `1400000400010004`
- `confirmed`: native ordering matters after rekey. On localhost, waiting for two encrypted server `0x14` records before sending the first encrypted client record changes the failure point.
- `confirmed`: once the client wait order is aligned with the native trace, localhost now closes immediately after the encrypted `0x0d` hello, before any standalone `SetPixelFormat` or `SetEncodings` are sent.
- `confirmed`: `screensharingd` logs that close under `HandleSetPixelFormatMessage`, even on runs where the standalone client only sent encrypted `0x0d`.
- `confirmed`: static analysis of `screensharingd::sub_1000352ac` on `24G231` now identifies client message `0x0d` as `HandleSetDisplayMessage`.
- `confirmed`: `HandleSetDisplayMessage` requires an `8`-byte message and parses the native localhost body `0d01000000000000` as:
  - byte `1`: `combineAllDisplaysFlag`
  - bytes `4..7`: big-endian selected-display id, used when `combineAllDisplaysFlag == 0`
- `confirmed`: when `combineAllDisplaysFlag == 1`, the handler treats the request as "combine all displays" / return to the default display aggregate and ignores the display-id field.
- `confirmed`: if the viewer is already on the default aggregate (`viewer+0x624 == -1`), the native `0x0d01000000000000` path is a no-op success path in `HandleSetDisplayMessage`.
- `confirmed`: the handler has explicit state gates unrelated to auth:
  - global `gOnlySendMainDisplayFlag`
  - viewer-local flag at `viewer+0xdff`
  - current selected display state at `viewer+0x624`
- `strong-inference`: because the native localhost `0x0d` payload is a benign display-selection no-op when the selected-display sentinel is already unset, the immediate localhost disconnect after sending it is more consistent with transport/decrypt framing failure than with wrong `0x0d` plaintext semantics.
- `confirmed`: clearing the copied `0xd174` current display mode index from `SetDisplayConfiguration` changes localhost behavior:
  - the previous host log `53620 is not a valid current display mode index` disappears
  - the new host log becomes `displayInfo goes beyond end of message`
  - the session now reaches `device is virtual display` / `vfb = 1` before the first encrypted-client reject
- `confirmed`: Binary Ninja + host log correlation on `24G419` now pin down the actual `SetDisplayConfiguration` layout:
  - message header is `12` bytes:
    - `+0x02` message size
    - `+0x04` message version
    - `+0x06` display count
    - `+0x08` message flags
  - each display descriptor starts at message offset `+0x0c` and expects:
    - `+0x00` displayInfoSize
    - `+0x92` currentModeIndex
    - `+0x94` preferredModeIndex
    - `+0x96` unknown `u32`
    - `+0x9a` modeCount
    - `+0x9c` `mode[modeCount]` with `0x1c`-byte entries
- `confirmed`: the replayed blob had the mode table starting `6` bytes too early at descriptor offset `0x96`.
  - the first mode width / height were being misparsed as the missing `u32` and `modeCount` fields
  - that is why localhost logged `display mode count 2160`
- `confirmed`: rewriting the standalone blob to shift the mode table to `0x9c` and populate the missing `current/preferred/u32/modeCount` fields makes the host accept the structure:
  - host logs now show `message size 304 messageVersion 1`
  - `full message size 308`
  - `message flags 0x0`
  - `displayInfoSize 296`
  - `display mode count 5`
  - `displayInfo goes beyond end of message` no longer appears
- `confirmed`: the saved native `2026-03-15` Frida plaintext for encrypted `0x1d` matches the corrected standalone front header:
  - native pre-encryption bytes begin `0134 1d 000130 0001 0001 00000000 ...`
  - this confirms wrapper body length `308`, message size `304`, version `1`, display count `1`, and flags `0`
  - the front header/layout bug is no longer the active mismatch
- `strong-inference`: the remaining localhost failure picture is now:
  - the remaining mismatch is later inside encrypted `0x1d` itself and/or in the immediate post-`0x0d` encrypted client burst
  - if encrypted `0x1d` is fully corrected, the next likely boundary is that immediate post-`0x0d` client burst
- `confirmed`: a saved native ProMode viewer trace on `24G419` now gives the concrete first post-rekey client order:
  - encrypted preface at CBC enable: `0x1d SetDisplayConfiguration`, then `0x02 SetEncodings`
  - first post-server-burst client record: `0x0d SetDisplayMessage`
  - immediate follow-ups: `0x00 SetPixelFormat`, `0x02 SetEncodings`, `0x15 AutoPasteboard selector=1`, `0x08` scale-factor-like message, `0x00`, `0x03`, `0x09`, `0x00`, `0x03`, `0x09`
- `confirmed`: the same saved native pcap resolves the first-sequence question:
  - native `0x0d` plaintext `00080d0100000000000010c20cacfbf48706757cd1758527102de1848616b32d`
  - the trailing SHA1 matches `SHA1(be32(2) || plain[0:12])`
  - therefore native `0x0d` is sent with sequence `2`
- `open`: the exact full plaintext tail of native encrypted preface record `0x1d` still needs same-session decryption or a full-buffer Frida capture.
- `confirmed`: the native `0x15` selector in that first post-rekey burst is `1`, not the standalone client's earlier replayed selector `2`.
- `strong-inference`: native `0x08` is a scale-factor control:
  - body `08003fea759203cae759`
  - BE double-like value `0.8268518518518518`
  - later native update regions `3175x1786` align with a rounded scaled view of `3840x2160`
- `strong-inference`: repeated later client `0x10` records are more likely keyboard/input-source state messages than generic display-mode controls:
  - native shape is stable: `0x10 0x03 <16 opaque bytes>`
  - runtime timestamps cluster with viewer logs `received keyboard input source info` and secure-input state changes
- `confirmed`: the bytes between the CBC body and trailing SHA1 are generic CBC slack, not a message-semantic field.
  - Binary Ninja on `ScreenSharing.framework::_EncryptOneMessage` shows the transport helper writes `u16_be(bodyLen)`, copies the body, hashes `seq_be || plain[0:plainLen-20]`, appends the SHA1, and does not branch on message type to choose filler bytes.
  - `_WriteSocketData` and `_UDPSend_ScreenSharing` reuse cached output buffers and do not clear the filler region before each call into `_EncryptOneMessage`.
  - native traces now show the same message body with different filler bytes across runs, including `0x0d SetDisplayMessage` and native `SetPixelFormat`, which rules out replay-era per-message filler constants.
- `confirmed`: the first post-rekey server burst after the encrypted preface is delivered as standard `FramebufferUpdate` messages carrying Apple-private rectangle encodings `0x451`, `0x453`, `0x455`, and `0x456`.
  - the standalone client must consume those through `handleEncoding`; treating them as unknown rect encodings aborts the session before streaming begins
- `confirmed`: Apple cursor-image decode is no longer blocked on the high-level `0x450` wrapper shape.
  - Binary Ninja decompilation of `EncodeCursorImageWithAlpha` shows the uncompressed payload is `w*h*4` color bytes plus a separate `w*h` alpha plane
  - captured standalone payload `/tmp/applehp_cursor_payload.bin` starts with `78 da` and inflates to the full expected `w*h*5` bytes, but never reaches zlib `eof`
  - consequence: the payload is a truncated zlib-header stream, not a complete standalone zlib blob
  - the standalone client now accepts full-output incremental inflate and logs `live-view: stored cursor cache=1000 hot=4,4 size=17x23`
- `confirmed`: an opt-in standalone `SetEncodings` probe that adds `0x3f2` now triggers the next HP/media-init branch on localhost.
  - host logs show:
    - `ProMode also enabled on viewer`
    - `set flag to init video stream`
    - `sent RFBMediaStreamMessage1Encoding`
    - `virtualDisplayCount 0`
    - `base UDP 5900 stream count 1 videoStream1HDR 0  videoStream2HDR 0`
  - the first new server response is a `FramebufferUpdate` rectangle with encoding `0x3f2`
  - Binary Ninja for `EncodeRFBMediaStreamMessage1` matches the observed `0x3f2` payload shape and size
  - the standalone client now parses `0x3f2` as `RFBMediaStream` version `1` and no longer aborts on that rectangle
  - after consuming `0x3f2`, the session continues streaming legacy `0x6 zlib` framebuffer rects and still ends with `session not accelerated 1`
  - current interpretation:
    - `confirmed`: `0x3f2` is the first real HP/media-init gate beyond plain rekeyed Apple metadata
    - `strong-inference`: the remaining gating surface is now viewer capability / virtual-display support, not whether `SetEncodings` can trigger media init at all
  - `confirmed`: Binary Ninja decompilation of `EncodeRFBMediaStreamMessage1` now resolves the observed payload more tightly:
    - base UDP port `5900`
    - stream count `1`
    - next advertised port `5901`
    - remaining control fields zero in the current localhost sample
  - `strong-inference`: `0x3f2` is a media-init announcement, not the media stream itself; the successful saved native pcap does not show matching UDP traffic on those ports
  - new native-viewer persistence evidence now narrows that gating surface further:
    - `~/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist` stores `supportsProMode = true` for the `Alexs-Mac-mini.local` session
    - the same saved connection encodes `displayConfiguration.displayType.virtualDisplays.numberOfDisplays = 0`
    - strong-inference: the current localhost ProMode-forcing Frida hook still leaves the native viewer on a different request shape than the earlier successful native virtual-display capture
- `confirmed`: the successful native `usingVirtualDisplay 1` capture stores the decisive request sequence in its Frida trace, not in markdown.
  - The viewer transport trace from the 2026-03-15 21:46:39 native ProMode capture carries:
    - initial auth33 wrap key `c564da853b2a177e55681e0f370ad7b1`
    - post-`0x44f` CBC key `7027fde5a3871ea382ebaed6eac97df8`
    - post-`0x44f` CBC IV `e4a9cde3ef19e30d45a546c501df5fe5`
  - the same trace proves the successful native request sequence:
    - cleartext `ViewerInfo`
    - cleartext `0x12 SetEncryptionMessage(command=1, methodCount=1, method=1)` `120000010001000100000001`
    - cleartext `0x0a SetModeMessage(mode=1)` `0a000001`
    - cleartext `0x12 SetEncryptionMessage short form (command=2, value=1)` `1200000200010000`
    - encrypted `0x1d SetDisplayConfiguration`
    - encrypted `0x02 SetEncodings`
    - encrypted `0x0d`, `0x00`, `0x02`, `0x15`, `0x08`
  - the encrypted `0x02 SetEncodings` bodies in that successful native run do not contain `0x3f2`
  - consequence: `0x3f2` is proven real on localhost, but not required to match the earlier successful native virtual-display startup
- `confirmed`: the standalone client now follows that native startup more closely by default.
  - cleartext prelude is now sent as separate `SetEncryptionMessage` and `SetModeMessage` messages
  - encrypted post-rekey `0x1d` / `0x02` preface is now the default path, with opt-out `VNC_APPLE_HP_NO_POSTREKEY_PREFACE=1`
  - a fresh forced-auth33 localhost run with the default path still streams successfully for the full timed run
- `confirmed`: the exact native encrypted `0x1d SetDisplayConfiguration` body is now recovered and in use.
  - decrypting the successful native `usingVirtualDisplay 1` pcap yields the full `308`-byte `0x1d` body, not just the front header
  - replacing the standalone replayed tail with that exact native body removes the last localhost `SetDisplayConfiguration` rejection
  - fresh host logs now show:
    - `initVirtualDisplay called`
    - `gVirtualDisplay1 0x... displayID ...`
  - the earlier `Invalid size in millimeters` / null-virtual-display failure is gone on the working localhost path
- `confirmed`: once the native `0x1d` body is used, the remaining standalone blocker shifts from request acceptance to framebuffer sizing.
  - the first accepted `0x451 AppleDisplayLayout` advertises `ui=3840x2160`
  - later `0x451` shrinks that to `ui=3175x1786`
  - the standalone client now grows its local framebuffer on `AppleDisplayLayout` before large rectangles arrive
  - result: the localhost auth33 HP path survives the `3840x2160 -> 3175x1786` transition and repaints the final `3175x1786` region instead of aborting with `Rect too large`
- `confirmed`: the current standalone input path works when it treats `0x451 AppleDisplayLayout` `display=` as the logical desktop UI space and does not infer pointer scale from the transient `backing=` size.
  - observed working layout sequence on localhost:
    - `display=1920x1080 backing=3840x2160`
    - later `display=1920x1080 backing=3175x1786`
  - the streamed backing size is therefore not a stable proxy for the remote pointer/input coordinate space
  - the current working standalone rule is:
    - local viewport `dst` coordinates -> logical `1920x1080`
    - cursor preview uses local output coordinates directly
    - transmitted pointer events are currently hard-coded to `logical * 2`
  - consequence: keep the `x2` send rule as the active workaround until a distinct remote input/native coordinate field is identified
- `confirmed`: the 5-entry display-mode table in `SetDisplayConfiguration` is sent by the standalone client to the server; it is not a server-advertised table currently used for pointer scaling.
  - `examples/client/applehp_protocol.h` defines `APPLE_HP_DISPLAY_CONFIG_MODE_COUNT = 5`
  - `apple_hp_make_native_display_configuration()` serializes those five mode entries into the outbound `0x1d SetDisplayConfiguration`
  - consequence: that table can explain what the client advertises, but it does not by itself tell us which coordinate space the server expects for pointer injection
- `confirmed`: the standalone `ViewerInfo` blob is not currently the active startup mismatch.
  - the standalone client still sends the exact native `66`-byte `ViewerInfo` payload from the successful `usingVirtualDisplay 1` trace
  - Binary Ninja on `ScreenSharing.framework::_RFBViewerInformation` now shows the actual `66`-byte wire layout is `u16 viewerInfoVersion`, `u32 viewerApp`, four viewer/system version words, and `viewerCommandBitmap[32]`
  - the `32`-byte tail is now confirmed to be a `256`-bit command-support bitmap; native set bits are `0, 2, 3, 20, 30, 31, 32, 35, 81`
  - Binary Ninja now ties encrypted server `0x14` to `SendMiscStatusMessageToViewer`, gated by that command-support bitmap
- `confirmed`: the cleartext prelude messages are now structurally and semantically resolved.
  - `0x0a` is `SetModeMessage` with mode values `0=observe`, `1=control`, `2=stronger control path used for native controlType 2/3`
  - `0x12` is `SetEncryptionMessage`
  - command `1` is the native prelude form that enables encrypted receive handling with method `1`
  - command `2` is a distinct native `8`-byte short form (`1200000200010000`), not the first `8` bytes of the command-`1` structure
  - that short form is the second-stage message the native viewer sends during the post-rekey keyboard-input-source (`0x455`) follow-up path
- `confirmed`: the standalone localhost auth33 HP path now streams frames for the full timed run when three fixes are combined:
  - suppress the old cleartext pre-`0x44f` `SetDisplayConfiguration`
  - handle Apple rectangle encodings `0x451` / `0x453` / `0x455` / `0x456`
  - tolerate `EAGAIN` / `EWOULDBLOCK` in the raw CBC socket helpers
- `confirmed`: libvncclient's default incremental polling was a real non-native HP-path divergence.
  - before suppression, the working HP path could emit hundreds of encrypted `0x03 FramebufferUpdateRequest` records after startup
  - after suppressing that polling once `0x09 AutoFrameBufferUpdate` is active, an `8s` forced-auth33 localhost run emits only `9` encrypted `0x03` requests
  - the session still streams successfully after that change
- `confirmed`: the first localhost `true vfb` / acceleration decision happens before `ViewerInfo`.
  - fresh host logs show `sent server initialization2`, then `set system mode success`, then `monitor screen changes true vfb %d`, and only after that `HandleViewerInfoMessage`
  - Binary Ninja confirms that order in `screensharingd::HandleViewerInitialization`: the first `SSAgent_SetSystemMode_rpc` happens before the client `ViewerInfo` path is handled
  - consequence: `ViewerInfo` alone cannot be the initial localhost HP/virtual-display gate
- `confirmed`: `screensharingd::sub_10006c334` is the wrapper for `SSAgent_MonitorScreenChanges_rpc`, and the corresponding agent logs are now captured.
  - `ScreensharingAgent` logs the same transition as `Monitor screen changes <port> want changes <n> current <n> ... capture screen <n> current <n>`
  - the daemon's `monitor screen changes true vfb %d` line is therefore agent-supplied state, not a client-side post-rekey transport artifact
  - after switching to the exact native `0x1d` body, localhost runs now do emit `initVirtualDisplay called` and `gVirtualDisplay1 ...`
- `confirmed`: the later `session not accelerated 1` close log is sourced from the same `MonitorScreenChanges` result, not from a separate late failure flag.
  - raw disassembly shows `SendFrameBuffer` writes `viewer+0xdb2 = 1` when `SSAgent_MonitorScreenChanges_rpc(..., &vfb)` returns non-zero `vfb`
  - `CloseThisConnection` later logs `session not accelerated %d` from that same `viewer+0xdb2` byte
  - consequence: on the now-working localhost virtual-display path, `session not accelerated 1` is currently aligned with `vfb 1`, so it should not be treated as proof that HP startup still failed
- `confirmed`: `ClientInit` flags remain the earliest client-controlled input on this path, but no stable acceleration fix is confirmed from flag sweeps yet.
  - `0x01` is invalid on auth33 localhost: the server closes before sending the SRP challenge
  - `0x41`, `0x81`, and `0xC1` all authenticate and reach the HP transport path
  - one localhost `0x81` run briefly produced `monitor screen changes true vfb 0` and `session not accelerated 0`, but repeat fresh-daemon runs reverted to `true vfb 1` / `session not accelerated 1`
  - consequence: treat `0x81` as an interesting probe, not a fix
- `confirmed`: CBC transport records stop lining up cleanly with RFB message boundaries once large framebuffer payloads start.
  - early control records are message-shaped
  - later large records can carry arbitrary continuation bytes for framebuffer rectangle payloads, so transport-record logs after that point are not reliable message-type evidence by themselves

- `confirmed`: the standalone client now has explicit probe knobs for the `0x1d SetDisplayConfiguration` header fields already localized in Binary Ninja.
  - `VNC_APPLE_HP_DISPLAY_COUNT`
  - `VNC_APPLE_HP_DISPLAY_MSG_FLAGS`
  - `VNC_APPLE_HP_DISPLAY_UNKNOWN_U32`
  - these do not prove the correct native mapping yet, but they remove the need for repeated manual blob edits while probing the virtual-display request semantics

## Exit Criteria
- A single client binary can authenticate with auth33 and show a live desktop.
- The same binary still supports non-interactive trace capture for debugging.
- Interactive control works without destabilizing the session.
- High-performance transport is either enabled with evidence or ruled out with evidence.
