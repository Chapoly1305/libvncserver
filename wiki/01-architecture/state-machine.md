# State Machine (24G231)

## State Set
1. `Idle`
2. `ServiceActivated`
3. `AuthPending`
4. `ObservedSession`
5. `ControlRequested`
6. `ControlGranted`
7. `MediaNegotiation`
8. `HighPerformanceActive`
9. `FallbackActive`
10. `Teardown`

## Transitions
- `Idle -> ServiceActivated`
  - Trigger: launchd socket/mach activation for `com.apple.screensharing` or agent mach services.
  - Guards: service enabled and launch event fired.
  - Evidence: `raw/plists/com.apple.screensharing*.plist.txt`.

- `ServiceActivated -> AuthPending`
  - Trigger: viewer connection accepted.
  - Guards: listener socket/mach endpoint active.
  - Evidence: `Connection accepted :: Viewer Address` + auth handler strings in `wiki/07-reference-generated/symbols/screensharingd.md`.

- `AuthPending -> ObservedSession`
  - Trigger: observe flow accepted (`Guest Request for Observe`).
  - Guards: authz checks pass.
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`.

- `AuthPending -> ControlRequested`
  - Trigger: explicit control request (`Guest Request for Control`).
  - Evidence: `wiki/07-reference-generated/symbols/screensharingd.md`, control keypaths in `wiki/07-reference-generated/symbols/Shared_Screen_Viewer.bn.md`.

- `ControlRequested -> ControlGranted`
  - Trigger: authorization grant + RPC propagation.
  - Guards: user/policy permission.
  - Evidence: `AuthorizeTheViewerUsingUID`, `agent_SSAgent_SetControl_rpc`.

- `ControlGranted -> MediaNegotiation`
  - Trigger: media stream configuration for viewer.
  - Evidence: `Set server stream config viewerID ...`, `HandleCodecChanged`, `HandleModifySession`.

- `MediaNegotiation -> HighPerformanceActive`
  - Trigger candidates:
    - UDP stream setup succeeds
    - codec/framerate capability satisfied (`supports60FPS`, HEVC max framerate checks)
    - framework gate agreement (`doesServerSupportProMode` + app/delegate pro-mode intent)
    - viewer-level pro-mode enablement (`ProMode also enabled on viewer`)
    - pro mode branch becomes active
  - Evidence: `SSUDPSender` methods with `supports60FPS`, `GetHEVCEncoderMaxSupportedFrameRate`, `ProMode active` strings, framework cache selectors in `wiki/07-reference-generated/framework-cache-signals.md`.

- `MediaNegotiation -> FallbackActive`
  - Trigger candidates:
    - session acceleration unavailable (`session not accelerated`)
    - connection-level pro-mode unsupported (`connectionDoesNotSupportProMode`)
    - UDP setup/health failure (`UDP connect failed`, RTP/RTCP timeout)
    - multi-viewer condition (`2 or more viewers`)
    - explicit non-active state (`ProMode not active`)
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`, `wiki/07-reference-generated/symbols/screensharingd.md`.

- `HighPerformanceActive -> FallbackActive`
  - Trigger candidates:
    - display/session change (`ProMode active - called release due to display change`)
    - explicit release (`Release UDP Streaming viewerID`)
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `ObservedSession|ControlGranted|FallbackActive|HighPerformanceActive -> Teardown`
  - Trigger: disconnect/server termination.
  - Evidence: `DisconnectViewer`, `DisconnectViewersSilently`, `No viewers so time to exit`, `streamDidStop`.

## Guard Conditions (Current Confidence)
- Confirmed-in-static:
  - observe vs control request separation
  - auth/authz gating stage exists
  - UDP high-perf media branch exists and has release path
  - multi-viewer branch exists
- Open pending runtime proof:
  - exact guard ordering for promotion to high-performance
  - exact downgrade precedence under concurrent triggers (timeout + second viewer + policy)
  - Consolidated static matrix: `wiki/05-high-performance/static-guard-matrix.md`
