# Static Guard Matrix (24G231, High-Performance Path)

## Scope
- Static-only reconstruction of high-performance (ProMode/UDP media) eligibility and fallback guards.
- Sources: extracted symbol packs, BN artifacts, and dyld-cache string recovery.

## Guard Candidates
| Guard / Condition | Static Evidence | Likely Effect | Confidence |
|---|---|---|---|
| Server advertises ProMode support | `doesServerSupportProMode` in framework-cache selector evidence | If false, do not promote to ProMode | strong-inference |
| Client/session wants ProMode UI/path | `appWantsProModeInterface`, `delegateWantsProModeInterface` in framework-cache selector evidence | If false, remain standard mode | strong-inference |
| Connection-level incompatibility | `connectionDoesNotSupportProMode` in framework-cache selector evidence | Immediate fallback/no promotion | strong-inference |
| Stream capability includes high-FPS | `setVideoStream1Supports60FPS:`, `setVideoStream2Supports60FPS:` and `supports60FPS` args in `SSUDPSender` methods (`wiki/07-reference-generated/symbols/ScreensharingAgent.md`) | Enables high-perf profile; missing support may stay in standard | strong-inference |
| UDP media config established | `Set server stream config viewerID %d startingUDPPort %d`, `sendToRemoteAddress:...startingUDPPort...` (`wiki/07-reference-generated/symbols/ScreensharingAgent.md`) | Required for UDP media branch | strong-inference |
| UDP path health maintained | `streamDidRTCPTimeOut:`, `streamDidRTPTimeOut:`, `UDP streaming not active` (`wiki/07-reference-generated/symbols/ScreensharingAgent.md`) | Timeout/health failure causes downgrade | strong-inference |
| Multi-viewer branch active | `2 or more viewers, send list again to the menu extra` (`wiki/07-reference-generated/symbols/ScreensharingAgent.md`) | Blocks or releases ProMode in multi-viewer scenario | strong-inference |
| Session acceleration available | `session not accelerated %d` (`wiki/07-reference-generated/symbols/screensharingd.md`) | If not accelerated, no high-perf promotion | strong-inference |
| Explicit release triggers | `ProMode active - called release`, `...due to display change`, `Release UDP Streaming viewerID %d` (`wiki/07-reference-generated/symbols/ScreensharingAgent.md`) | Downgrade from ProMode to fallback path | confirmed (release path exists) |

## Ordering Hypothesis (Static)
1. Auth/session setup (`AuthenticateAndAuthorizeTheViewer`, `AuthorizeTheViewerUsingUID`).
2. Observe/control mode request (`Guest Request for Observe` / `Guest Request for Control`).
3. Media config and capability checks (`HandleModifySession`, `HandleCodecChanged`, `supports60FPS`, UDP port config).
4. ProMode gate agreement (`doesServerSupportProMode` + app/delegate intent + no connection incompatibility).
5. Runtime enforcement and demotion on health/topology changes (RTP/RTCP timeout, display change, multi-viewer).

Confidence: `strong-inference` (ordering needs runtime log correlation).

## Explaining “HP set in UI but only TCP seen in pcap”
Static evidence supports this exact possibility:
- UI intent alone is insufficient (`appWantsProModeInterface` exists separately from support/error flags).
- Connection can be marked unsupported (`connectionDoesNotSupportProMode`).
- Session can remain non-accelerated (`session not accelerated %d`).
- UDP branch can be released or never activated (`Release UDP Streaming`, `UDP streaming not active`).

Therefore, HP preference can be true while transport remains TCP-only.
