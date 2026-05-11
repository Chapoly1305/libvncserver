# Startup Sequence (24G231)

Specification for the native-compatible startup sequence from RFB version exchange to the first post-rekey control burst. Use this page as the protocol order-of-operations reference. Field-level message details belong in [message-catalog.md](message-catalog.md); the rekey crypto sits in [../02-auth/auth33-reconstruction.md](../02-auth/auth33-reconstruction.md).

## Cleartext Prelude

The maintained native-compatible prelude is, in order:

1. `ViewerInfo`
2. `0x12 SetEncryptionMessage(command=1, method=1)` — wire form `120000010001000100000001`
3. `0x0a SetModeMessage(mode=1)` for the normal control path — wire form `0a000001`
4. short `0x12` command-2 follow-up — wire form `1200000200010000`

The cleartext window ends at the server's `0x44f EncodeEncryptionInfo` rectangle, which carries the next transport key and IV (see [../02-auth/auth33-reconstruction.md](../02-auth/auth33-reconstruction.md) for the runtime key install). After this point traffic is on the Apple AES-CBC record layer.

## Encrypted Preface

The first two encrypted client records after CBC enable are:

1. `0x1d SetDisplayConfiguration`
2. `0x02 SetEncodings`

Sending these in this order, with the correct `SetDisplayConfiguration` body, reaches the useful virtual-display branch. Sending the old `318`-byte replay tail produces stale `HandleSetPixelFormatMessage` field decodes on localhost and must be suppressed.

## First Post-Rekey Server Burst

The server replies with a metadata burst of Apple-private rectangles, currently:

- `0x451 AppleDisplayLayout`
- `0x453 VendorKeysymEncoding`
- `0x455 KeyboardInputSource`
- `0x456 DeviceInfo`

A `0x450 CursorImage` rectangle follows. `libvncclient` consumers must treat these as `FramebufferUpdate` rectangle encodings, not standalone server messages, or the connection aborts on `Unknown rect encoding`.

## First Post-Rekey Client Burst

After the server metadata burst the native viewer sends:

1. `0x0d SetDisplayMessage` — native body `0x0d01000000000000` means "combine all displays" and is treated as a no-op when no explicit display is already selected
2. `0x00 SetPixelFormat`
3. `0x02 SetEncodings`
4. `0x15 AutoPasteboard selector=1`
5. `0x08` scale-factor-like control — observed body `08003fea759203cae759` decodes as the BE double `0.8268518518518518`, matching the later `3175x1786` update region derived from a scaled `3840x2160`
6. update cycles (`0x09 AutoFrameBufferUpdate` followed by `FramebufferUpdateRequest` polling)

The native viewer does not flood `0x03 FramebufferUpdateRequest` records after `0x09 AutoFrameBufferUpdate` becomes active. A correct standalone client should send roughly an order of magnitude fewer polling requests than a naïve libvncclient loop.

## SetDisplayConfiguration Body Layout

`screensharingd` on `24G419` expects a 12-byte `0x1d` header:

- `+0x02` message size
- `+0x04` message version
- `+0x06` display count
- `+0x08` message flags

Each display descriptor begins at message offset `+0x0c` with:

- `+0x00` `displayInfoSize`
- `+0x92` `currentModeIndex`
- `+0x94` `preferredModeIndex`
- `+0x96` reserved `u32`
- `+0x9a` `modeCount`
- `+0x9c` `mode[modeCount]` with `0x1c`-byte entries

The replayed body in early standalone work had the mode table starting at descriptor offset `0x96`; shifting it to `0x9c` and populating the missing fields turns the host log from `displayInfo goes beyond end of message` into `display mode count 5`.

Native pre-encryption bytes for the corrected front header begin `0134 1d 000130 0001 0001 00000000 ...` which maps to wrapper body length `308`, message type `0x1d`, message size `304`, version `1`, display count `1`, flags `0`. Using the exact native `308`-byte body removes the last localhost `SetDisplayConfiguration` blocker — fresh host logs show `initVirtualDisplay called` followed by `gVirtualDisplay1 0x... displayID ...` instead of `Invalid size in millimeters`.

## Dynamic Layout Resize

After the virtual-display branch is accepted, `0x451 AppleDisplayLayout` updates can change the effective framebuffer dimensions mid-session. Observed sequence on a successful localhost run:

- first `AppleDisplayLayout` advertises `ui=3840x2160`
- later `AppleDisplayLayout` advertises `ui=3175x1786`

The standalone client must grow its local framebuffer on each `AppleDisplayLayout` before the next large rectangle arrives, otherwise the run aborts with `Rect too large`. With that in place, forced-auth33 localhost runs survive the `3840x2160 -> 3175x1786` change and repaint the final `3175x1786` region.

## ViewerInfo Wire Layout

Binary Ninja on `ScreenSharing.framework::_RFBViewerInformation`:

- `u16 viewerInfoVersion`
- `u32 viewerApp`
- `u32 viewerAppMajor`
- `u32 viewerAppMinor`
- `u32 viewerAppBugFix`
- `u32 systemMajor`
- `u32 systemMinor`
- `u32 systemBugFix`
- `viewerCommandBitmap[32]`

The `32`-byte tail is a `256`-bit viewer-command support bitmap, not a generic feature blob. Native advertised command IDs are `0, 2, 3, 20, 30, 31, 32, 35, 81`. Encrypted server `0x14` is `SendMiscStatusMessageToViewer`, a viewer-feature-gated misc-status channel gated on bit `0x14` in this bitmap.

## Adjacent References

- Auth completion and rekey crypto: [../02-auth/auth33-reconstruction.md](../02-auth/auth33-reconstruction.md)
- Message families and Apple-private encodings: [message-catalog.md](message-catalog.md)
- Frame-level capture ledger: [../04-runtime-evidence/post-auth-stream7-ledger.md](../04-runtime-evidence/post-auth-stream7-ledger.md)
- HP gating after the encoding-tier negotiation: [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md)
