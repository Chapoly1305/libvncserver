# Transport

Post-auth transport: the AES-CBC record layer, the native-compatible startup sequence, and the message catalog (RFB plus Apple-private encodings).

## Pages

- [startup-sequence.md](startup-sequence.md) — the maintained order of operations from `ViewerInfo` through the first post-rekey control burst, plus the `SetDisplayConfiguration` body layout and dynamic-resize behavior.
- [message-catalog.md](message-catalog.md) — every named message family with its meaning and evidence.
- [decoder-documentation.md](decoder-documentation.md) — the auth-entrance decoder script (`decode_auth_entrance.py`).

## What this section covers

- The cleartext prelude (`ViewerInfo`, `SetEncryptionMessage`, `SetModeMessage`, short `0x12` follow-up).
- The `0x44f EncodeEncryptionInfo` rekey boundary and what follows it.
- The first resolved Apple-private rectangles (`0x450` `CursorImage`, `0x451` `AppleDisplayLayout`, `0x453` `VendorKeysymEncoding`, `0x455` `KeyboardInputSource`, `0x456` `DeviceInfo`, `0x3f2` `RFBMediaStreamMessage1`).
- The first encrypted client burst: `SetDisplayConfiguration`, `SetEncodings`, `SetDisplayMessage`, `SetPixelFormat`, `AutoPasteboard`, the `0x08` scale-factor control, and update cycles.

## See also

- Auth completion and rekey crypto: [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md).
- Capture-backed frame ledger: [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md).
- HP encoding tiers advertised via `SetEncodings`: [../05-high-performance/encoding-tiers.md](../05-high-performance/encoding-tiers.md).
