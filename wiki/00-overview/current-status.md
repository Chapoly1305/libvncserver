# Current Status

One-screen snapshot of the maintained spec state. Each line is a pointer — follow the linked page for definitions, evidence, and field-level detail.

## What Is Settled

- **Auth33 (Apple `RSA-SRP`)** works end-to-end in a standalone client — PBKDF2-HMAC-SHA512 password preprocessing, empty-username SRP step, in-process RSA packet-1 generation. See [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md). Direct SRP (type 36) and Kerberos (type 35) also work — see [../02-auth/overview.md](../02-auth/overview.md) for the four-method picture.
- **Post-auth rekey** at the `0x44f EncodeEncryptionInfo` rectangle: AES-CBC record layer with the next key/IV distributed by that packet. See [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md) (runtime key install) and [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md) (frame ledger).
- **Native-compatible startup sequence** from `ViewerInfo` through the first post-rekey control burst is reproduced closely enough to stream framebuffer updates on localhost. See [../03-transport/startup-sequence.md](../03-transport/startup-sequence.md).
- **Apple-private rectangle encodings** `0x450 CursorImage`, `0x451 AppleDisplayLayout`, `0x453 VendorKeysymEncoding`, `0x455 KeyboardInputSource`, `0x456 DeviceInfo`, and `0x3f2 RFBMediaStreamMessage1` are mapped well enough for a working consumer. See [../03-transport/message-catalog.md](../03-transport/message-catalog.md).
- **Encoding-tier model**: five tiers selected by `+[SSSession qualityEncodingsForMode:withDisplayConfiguration:]` and chosen by the `quality=` URL parameter. See [../05-high-performance/encoding-tiers.md](../05-high-performance/encoding-tiers.md).
- **Three-gate acceleration model** (`vfb` from `MonitorScreenChanges`, ProMode from `0x3f2` advertisement, `virtualDisplayCount` from `SetDisplayConfiguration`) is structurally resolved. See [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md).
- **`0x3f3` multi-variant codec wire format** is now partially decoded: tile types (`White`, `MatchPrevious`, `MatchAbove`, `TwoColor`, `DCT`), command-bitstream layout, and YCoCg color quantization. See [../05-high-performance/encoding-tiers.md](../05-high-performance/encoding-tiers.md).
- **Binary baseline**: `24G231` `arm64e` slice with the approved function-offset ledger. See [../06-tooling/binary-baseline.md](../06-tooling/binary-baseline.md).

## What Is Open

The full open list lives in [../08-tracking/open-questions.md](../08-tracking/open-questions.md). Today's highest-priority items:

- Exact bit-packing of the `0x3f3` command stream and DCT coefficient encoding (tile types known; encoder-side byte layout still being walked).
- Exact wire format of `0x3ea` (high quality codec) rectangles.
- Exact field schema for later `AppleDisplayLayout` follow-ups (native viewer uses `DisplayInfo2`).
- Semantics of the `EncodeEncryptionInfo` generation/counter field at `viewer + 0x8cc`.
- Exact agent-side condition that decides `vfb=1` and `virtualDisplayCount=0` on the localhost path.
- Whether `0x3f2` follow-up state ever produces a sustained AVC/HEVC media stream over the dedicated UDP plane.

## Best Reading Order

1. [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md)
2. [../03-transport/startup-sequence.md](../03-transport/startup-sequence.md)
3. [../03-transport/message-catalog.md](../03-transport/message-catalog.md)
4. [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md)
5. [../05-high-performance/encoding-tiers.md](../05-high-performance/encoding-tiers.md)
6. [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md)
7. [../06-tooling/binary-baseline.md](../06-tooling/binary-baseline.md)
8. [../08-tracking/open-questions.md](../08-tracking/open-questions.md)
