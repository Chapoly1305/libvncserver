# Acceleration Gates (24G231 / 24G419)

Specification for the three independent gates that decide whether a session reaches the accelerated virtual-display branch. The gates can be set independently: ProMode can be "enabled" (Gate 2) while `virtualDisplayCount=0` (Gate 3) and `vfb=1` (Gate 1).

The static gating surface (server-advertised support, viewer intent, UDP health, multi-viewer release path) is catalogued in [static-guard-matrix.md](static-guard-matrix.md). This page covers the runtime decision points that hold the matrix together.

## Gate 1 — Virtual Framebuffer (`vfb`)

- Source: `ScreensharingAgent::MonitorScreenChanges` calls `CGMainDisplayID()` then `kCGDisplayIsVirtualDevice`.
- Physical display → `vfb=0`. Virtual / headless display → `vfb=1`.
- The value is written to `viewer+0xdb2`.
- `CloseThisConnection` later emits `session not accelerated %d` from that byte, so the close-time log tracks `vfb 1` rather than proving the request failed.
- Agent-side log line: `Monitor screen changes <port> want changes <n> current <n> mypid <pid> capture screen <n> current <n>`.
- The daemon's `monitor screen changes true vfb %d` value is agent-supplied state, not a client-side CBC decode artifact.

## Gate 2 — ProMode Activation

- Triggered when the client advertises `0x3f2` in `SetEncodings`.
- Server logs `ProMode also enabled on viewer`, then `set flag to init video stream`, then `sent RFBMediaStreamMessage1Encoding`.
- Server emits a `FramebufferUpdate` rectangle with encoding `0x3f2`, whose payload shape matches `EncodeRFBMediaStreamMessage1`.
- The current localhost payload announces base UDP port `5900`, stream count `1`, and next port `5901`.
- The successful saved native pcap does not show UDP media traffic on those ports. Treat `0x3f2` as a media-init announcement, not proof of active UDP video.

## Gate 3 — Virtual Display Count

- Read from `viewer+0x10a2` by `InitializeUDPVideoStream`.
- Set during `SSAgent_SetDisplayConfiguration_rpc` → `CreateVirtualDisplay` based on the `display_count` field in the client's `SetDisplayConfiguration`.
- When `>0`, additional media setup occurs and audio is muted.
- Native viewer persistence shows the connection-time intent: `~/Library/Containers/com.apple.ScreenSharing/Data/Library/Preferences/com.apple.ScreenSharing.plist` stores `supportsProMode = true` for the working `Alexs-Mac-mini.local` session while still carrying `displayConfiguration.displayType.virtualDisplays.numberOfDisplays = 0` — so this gate is influenced by saved per-host configuration in the native viewer.

## What Is Confirmed

- The binaries contain a real HP / media-control surface.
- The server tracks ProMode-related state and can emit `0x3f2 RFBMediaStreamMessage1`.
- Advertising `0x3f2` is a real media-init gate on localhost.
- The three-gate model is structurally resolved.

## What Is Not Yet Proven

- The exact bit-packing of the `0x3f3` command bitstream and the DCT coefficient encoding (tile types and high-level structure are documented in [encoding-tiers.md](encoding-tiers.md); the encoder-side byte layout is still being walked).
- The exact wire format of `0x3ea` (high quality codec) rectangles.
- A successful machine/VNC session in this repo has not yet been shown to carry visible content as a sustained AVC/HEVC media stream. The saved native HP TCP transport trace is dominated by classic `0x6 zlib` framebuffer rectangles, not `rfbEncodingH264` or obvious Annex B / AVCC / HVCC video samples. The observed native machine/VNC HP session is a low-latency TCP framebuffer path, not a hardware video-decode path. This is session-specific, not a claim that the product lacks media decode support overall — `SSFrameBufferAVCMediaView` and `_GetHEVCDecoderMaxSupportedFrameRate` show a real decode path exists.
- The exact runtime condition that causes the viewer to enter the AVC media path instead of the TCP virtual-display framebuffer path.

## Adjacent References

- Static guard catalogue: [static-guard-matrix.md](static-guard-matrix.md)
- Video pipeline narrative: [video-pipeline.md](video-pipeline.md)
- Encoding tier negotiation: [encoding-tiers.md](encoding-tiers.md)
- Open follow-up work: [../08-tracking/open-questions.md](../08-tracking/open-questions.md)
