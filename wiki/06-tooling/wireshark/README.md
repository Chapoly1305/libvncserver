# Wireshark Auth33 Plugin

## Scope
- Build target: macOS Sequoia `24G84`
- Status:
  - `confirmed`: auth33 handshake field decoding
  - `confirmed`: session-aware decode of `EncodeEncryptionInfo` and the first rekeyed AES-CBC TCP record family when given the initial SRP-derived AES key
  - `open`: automatic session-key derivation, full packet reassembly, and complete message-family labeling

## Files
- Plugin:
  - `apple_screensharing_auth33.lua`

## Install
Copy or symlink the Lua file into a Wireshark personal plugins directory, or load it directly with `tshark`:

```bash
tshark -X lua_script:apple_screensharing_auth33.lua -r capture.pcapng
```

## Preferences
Set these in Wireshark under the plugin preferences:

- `session_key_hex`
  - 16-byte initial AES key in hex, derived from `SHA-256(session_key)[0:16]`
  - example: `437faae967f8e033443e49255517579e`
- `client_mode`
  - `auto`, `none`, `aes-128-ecb`, `aes-128-cbc-zero-iv`
- `server_mode`
  - `auto`, `none`, `aes-128-ecb`, `aes-128-cbc-zero-iv`
- `client_offset`
  - bytes to skip before decrypting client-to-server post-auth payload
- `server_offset`
  - bytes to skip before decrypting server-to-client post-auth payload

## What It Decodes
- RFB `003.889` protocol banners
- Security type list
- Security type `33` selection
- RSA1 packet headers
- SRP challenge packet:
  - length fields
  - `N`, `g`, salt, `B`, iterations, options string
- SRP final packet header
- SecurityResult
- ClientInit with bit-level flags:
  - shared desktop bit
  - bit `6`
  - bit `7`
- ServerInit:
  - width
  - height
  - name length
  - server name bytes
- Cleartext post-auth message labels:
  - `ViewerInfo` (`0x21`)
  - `SetEncryptionMessage` (`0x12`)
  - `SetDisplayConfiguration` (`0x1d`)
 - `EncodeEncryptionInfo` (`0x44f`):
   - RFB `FramebufferUpdate` wrapper
   - counter / generation field
   - two ECB-wrapped 16-byte blocks
   - derived next key and IV when `session_key_hex` is provided
 - Rekeyed AES-CBC record layer:
   - per-stream CBC state
   - separate client and server chaining IVs
   - concatenated `u16_be ciphertext_len + ciphertext` records inside one TCP segment
   - plaintext body preview plus record metadata
- First decoded rekeyed records:
   - server `FramebufferUpdate` records with encodings such as `0x451`, `0x453`, `0x455`, `0x456`
   - current confirmed semantic labels for those encodings:
     - `0x451` -> `AppleDisplayLayout`
     - `0x453` -> `VendorKeysymEncoding`
     - `0x455` -> `KeyboardInputSource`
     - `0x456` -> `DeviceInfo`
   - current subfield annotations:
     - `0x451`: payload length, version, scaled/ui dimensions, selected-screen sentinel, flags, and a pixel-format-tail note
     - `0x453`: payload length, version, four `u32` vendor-keysym values
     - `0x455`: payload length, version, flags, string length, and input-source string
     - `0x456`: payload length, version, block count, flags, three string lengths, three strings, and trailing housing-color integer
   - client `SetPixelFormat`
   - client `SetEncodings`
   - client `FramebufferUpdateRequest`
   - client `0x09` -> `AutoFrameBufferUpdate`
     - selector/version, selected-screen sentinel/target, and requested region
   - client `0x15` -> `AutoPasteboardCommand`
     - selector value from the fixed 8-byte body

## Post-Auth Decryption
The plugin uses a provided initial AES key to drive two different post-auth paths:

- It tracks auth/setup state per `tcp.stream`.
- On `EncodeEncryptionInfo`, it decrypts the two 16-byte blocks with the current ECB wrap key and rotates stream state to the newly derived key and IV.
- After rekey, it decodes the known TCP record layer as:
  - `u16_be ciphertext_len`
  - `ciphertext`
- For each decrypted record it exposes:
  - inner plaintext length
  - plaintext body length
  - padding length
  - trailing SHA-1 bytes
  - plaintext hex preview
  - plaintext ASCII preview
  - guessed message type
- If no rekeyed CBC state is available yet, the older exploratory decrypt candidates remain available:
  - `AES-128-ECB`
  - `AES-128-CBC` with zero IV

## Caveats
- This registers on `tcp.port 5900` and chains into the built-in `vnc` dissector first.
- Packet reassembly is not implemented in this first version.
- The decoder still depends on a user-supplied initial session AES key; it does not derive that key from the auth exchange itself.
- The CBC decoder currently covers the first confirmed record family, not every later Apple-specific message path.
- Message semantics for `0x451`, `0x453`, `0x455`, and `0x456` are now confirmed at the message-name level. `0x453`, `0x455`, and `0x456` have practical field layouts; `0x451` (`AppleDisplayLayout` in our client/dissector labels, native viewer methods still say `handleDisplayInfo2:`) is still only partially mapped.
- Cleartext client `0x12` is now confirmed as `SetEncryptionMessage`, not `ViewerCutText`. The native `12`-byte form with command `1` enables encrypted receive handling with method `1`; the native `8`-byte short form with command `2` is the second-stage follow-up the viewer sends around `0x455 KeyboardInputSource`.
- Client extension types `0x09` and `0x15` are now identified as `HandleAutoFrameBufferUpdateMessage` and `HandleAutoPasteboardCommand`; only the exact UI meaning of auto-pasteboard selector values remains open.
- Static server evidence now shows `SendResolutionChargeToViewer` emits standard `DesktopSize` (`0xffffff21`), so Apple-private `0x453` should not be read as the resolution-change message.
- AES candidate decryption shells out to `openssl`, so large captures can be slow once a session key is configured.
