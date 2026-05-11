# Message Catalog (24G231)

Use this page as a protocol reference, not as a worklog. It summarizes the named message families and the current evidence for what they mean.

## How To Read This Page

- message names reflect the best current mapping from static analysis and runtime evidence
- "meaning" is the current durable interpretation, not every historical hypothesis
- when a message is still only partially resolved, the linked tracking pages should carry the uncertainty, not this page

## Most Important Confirmed Families

- Auth33 / RSA-SRP handshake messages are documented in [../02-auth/auth-33-rsa-srp.md](../02-auth/auth-33-rsa-srp.md).
- `0x44f` is `EncodeEncryptionInfo`, the rekey boundary into the Apple CBC record layer.
- First post-rekey Apple-private rectangles now have stable names:
  - `0x450` `CursorImage`
  - `0x451` `AppleDisplayLayout`
  - `0x453` `VendorKeysymEncoding`
  - `0x455` `KeyboardInputSource`
  - `0x456` `DeviceInfo`
  - `0x3f2` `RFBMediaStreamMessage1`

## Server/Auth/Session Messages
- `AuthenticateAndAuthorizeTheViewer`
  - Meaning: combined authn/authz processing for inbound viewer.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

- `AuthorizeTheViewerUsingUID`
  - Meaning: local user/account-based authorization check branch.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

- `HandleViewerAuthenticationMessages`
  - Meaning: parser/dispatcher for authentication message subprotocol.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

- `HandleAuthTypeMessage` / `SendRSAResponseSRPAuthentication` / `HandleSRPAuthenticationMessage` / `SendSRPChallenge`
  - Meaning: security type `33` auth dispatcher and RSA+SRP challenge/response path on server.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/02-auth/auth-33-rsa-srp.md`.

- `SendRSAResponseKeyRequest` / `SendRSAResponsePlainAuthentication` / `SendRSAResponseNewKey` / `SendRSAResponseUnsupported`
  - Meaning: RSA envelope sub-protocol branches selected by `authtype` field (`0/1/2/other`) inside the type-33 auth packet.
  - Evidence: `wiki/02-auth/auth-33-rsa-srp.md`, `wiki/06-tooling/binary-baseline.md`.

- `RSA1` envelope header fields (`version`, `magic`, `authtype`, `aux`)
  - Meaning: stable wire header used by client auth-33 packets before SRP material.
  - Evidence: pcap frames `11`/`121170` and static parser logic in `screensharingd::sub_100015bdc` (documented in `wiki/02-auth/auth-33-rsa-srp.md`).

- `RSA-SRP` / `SRP-RFC5054-4096-SHA512-PBKDF2` / `ChaCha20-Poly1305` / `SALTED-SHA512-PBKDF2`
  - Meaning: auth-33 cryptographic profile and option set negotiated during handshake.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/02-auth/auth-33-rsa-srp.md`, `apple_hp_vnc.pcapng`.

- `HandleViewerInitialization`
  - Meaning: post-auth viewer init phase.
  - Evidence: `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

- `HandleModifySession`
  - Meaning: in-session mode/config mutation handler.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

- `HandleCodecChanged`
  - Meaning: codec transition/update event.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, `wiki/07-reference-generated/symbols/AppleVNCServer.md`.

## Observe/Control Mode Signals
- `Guest Request for Observe`
- `Guest Request for Control`
  - Meaning: explicit request classes for permissioned mode transitions.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`.

- `ViewerObserveFlags`
  - Meaning: per-viewer observe flag state.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `agent_SSAgent_SetControl_rpc`
  - Meaning: RPC from daemon side to agent/media context for control state.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

## High-Performance / Media Promotion Signals
- `SSUDPSender ... supports60FPS ...`
  - Meaning: negotiated high-frame-rate media path candidate.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `doesServerSupportProMode` / `appWantsProModeInterface` / `delegateWantsProModeInterface`
  - Meaning: pro-mode eligibility + desire gating dimensions tracked in session layer.
  - Evidence: `wiki/07-reference-generated/framework-cache-signals.md`.

- `setVideoStream1Supports60FPS:` / `setVideoStream2Supports60FPS:`
  - Meaning: per-stream capability bits for high-frame-rate path.
  - Evidence: `wiki/07-reference-generated/framework-cache-signals.md`.

- `connectionDoesNotSupportProMode`
  - Meaning: explicit fallback reason state exposed to session/view layer.
  - Evidence: `wiki/07-reference-generated/framework-cache-signals.md`.

- `Set server stream config viewerID %d startingUDPPort %d`
  - Meaning: server-side media stream config pushed for a viewer.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `GetHEVCEncoderMaxSupportedFrameRate`
  - Meaning: capability query for HEVC frame rate ceiling.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`, `wiki/07-reference-generated/symbols/screensharingd.md`.

- `Pro Mode not currently active` / `ProMode active - called release` / `ProMode not active`
  - Meaning: explicit internal state transitions for pro mode branch.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `ProMode also enabled on viewer`
  - Meaning: viewer-scoped enablement bit exists in daemon-side flow.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`.

- `Release UDP Streaming viewerID %d`
  - Meaning: downgrade/teardown of high-performance UDP media channel.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

## Multi-Viewer / Fallback Indicators
- `0x14` encrypted server message -> `SendMiscStatusMessageToViewer`
  - Meaning: viewer-capability-gated misc-status message sent over the Apple CBC record layer.
  - Evidence: `screensharingd::sub_100009360` allocates a `0x16`-byte message, sets message type `0x14`, writes an `8`-byte payload, and only sends it if the viewer-command bitmap reports support for command `0x14`.

- `2 or more viewers, send list again to the menu extra`
  - Meaning: multi-viewer branch condition is explicitly tracked.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `session not accelerated %d`
  - Meaning: acceleration (likely high-performance media) not active for session.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`.

## Transport and Reliability
- `CreateConnectedUDPSocket`, `UDP connect failed`, `streamDidRTCPTimeOut`, `streamDidRTPTimeOut`
  - Meaning: UDP stream setup/health/downgrade-related control points.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

## IDS / Service Orchestration Labels
- `com.apple.private.alloy.screensharing`
- `com.apple.private.alloy.screensharing.qr`
- `com.apple.screensharing.idslaunchnotification`
  - Meaning: service discovery/routing endpoints for invitation/session setup.
  - Evidence: `raw/plists/com.apple.private.alloy.screensharing*.plist.txt`.
