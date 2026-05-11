# Component Map (24G231)

## Scope
- Build: macOS Sequoia 15.7.1, `24G231`
- Focus: Screen Sharing high-performance path (control flow + service orchestration)

## Primary Components
- `Shared Screen Viewer`
  - Path: `/System/Library/CoreServices/RemoteManagement/ARDAgent.app/Contents/Support/Shared Screen Viewer.app/Contents/MacOS/Shared Screen Viewer`
  - Role: viewer/client UI, session/control-mode orchestration, IDS-based invitation/address resolution.
  - Evidence:
    - `IDSSession/IDSService` symbols and `SSAddressResolver` methods in `wiki/07-reference-generated/symbols/Shared_Screen_Viewer.bn.md`.
    - Control/observe support keypaths in `wiki/07-reference-generated/symbols/Shared_Screen_Viewer.bn.md`.

- `screensharingd`
  - Path: `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd`
  - Role: daemon-side session/auth/control state machine for VNC/RFB endpoint + viewer management.
  - Evidence:
    - `AuthenticateAndAuthorizeTheViewer`, `HandleViewer*`, `HandleModifySession`, `HandleCodecChanged` strings in `wiki/07-reference-generated/symbols/screensharingd.md`.
    - LaunchDaemon socket/mach service in `raw/plists/com.apple.screensharing.plist.txt`.

- `ScreensharingAgent`
  - Path: `/System/Library/CoreServices/RemoteManagement/ScreensharingAgent.bundle/Contents/MacOS/ScreensharingAgent`
  - Role: media path and UDP stream handling; appears to host pro/high-perf media session operations.
  - Evidence:
    - `SSUDPSender` API surface and `supports60FPS` stream creation methods in `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.
    - `ProMode active/not active` and `Release UDP Streaming` strings in `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.

- `AppleVNCServer`
  - Path: `/System/Library/CoreServices/RemoteManagement/AppleVNCServer.bundle/Contents/MacOS/AppleVNCServer`
  - Role: additional server/agent path used by launch agent `com.apple.screensharing.MessagesAgent`; overlaps with viewer/auth/session handling APIs.
  - Evidence:
    - Auth/viewer handling strings in `wiki/07-reference-generated/symbols/AppleVNCServer.md`.
    - `com.apple.private.screensharing.screenControl` entitlement in `raw/entitlements_AppleVNCServer.xml`.

- `ScreenSharing.framework` and `ScreenSharingUI.framework`
  - Paths rooted at `/Volumes/MacintoshHD/System/Library/PrivateFrameworks/ScreenSharing.framework`
  - Notes: top-level framework binaries are broken symlinks in this extracted image; code resides in dyld shared cache.
  - Evidence:
    - Filesystem inspection showed symlink targets missing as standalone Mach-Os.
    - dyld map entries in the shared-cache map:
      - `/System/Library/PrivateFrameworks/ScreenSharing.framework/Versions/A/ScreenSharing`
      - `/System/Library/PrivateFrameworks/ScreenSharing.framework/Versions/A/Frameworks/ScreenSharingUI.framework/Versions/A/ScreenSharingUI`
      - `/System/Library/PrivateFrameworks/ScreenSharingKit.framework/Versions/A/ScreenSharingKit`
      - `/System/Library/PrivateFrameworks/ScreenSharingServer.framework/Versions/A/ScreenSharingServer`

## Launchd / Service Chain
1. `com.apple.screensharing` LaunchDaemon
- Program: `screensharingd`
- Socket: Bonjour `rfb`, service `vnc-server`
- Mach service: `com.apple.screensharing.server`
- Config in `raw/plists/com.apple.screensharing.plist.txt`

2. `com.apple.screensharing.agent` LaunchAgent
- Program: `ScreensharingAgent`
- Mach service: `com.apple.screensharing.agent`
- Triggered by notify/watch path launch events
- Config in `raw/plists/com.apple.screensharing.agent.plist.txt`

3. `com.apple.screensharing.MessagesAgent` LaunchAgent
- Program: `AppleVNCServer`
- Mach service: `com.apple.screensharing.MessagesAgent`
- Config in `raw/plists/com.apple.screensharing.MessagesAgent.plist.txt`

4. IDS service definitions
- `com.apple.private.alloy.screensharing`
- `com.apple.private.alloy.screensharing.qr`
- Both reference `com.apple.screensharing.idslaunchnotification`
- Config in `raw/plists/com.apple.private.alloy.screensharing*.plist.txt`

## IPC/Protocol Edges (Observed Statically)
- Viewer ↔ IDS layer
  - `IDSService`, `IDSSession`, `SSAddressResolver ... IDSServiceMessageObserver`
  - Evidence: `wiki/07-reference-generated/symbols/Shared_Screen_Viewer.bn.md`.

- Viewer ↔ daemon/agent control
  - Control/observe mode toggles and permission surfaces (`supportsControlMode`, `requestControl`, `allowControl`).
  - Evidence: `wiki/07-reference-generated/symbols/Shared_Screen_Viewer.bn.md`, `wiki/07-reference-generated/symbols/screensharingd.md`.

- Daemon/agent ↔ media plane
  - `SSUDPSender` orchestration with UDP sockets, stream startup, RTCP timeout handlers, codec config updates.
  - Evidence: `wiki/07-reference-generated/symbols/ScreensharingAgent.bn.md`.
  - Callflow evidence:
    - `-[SSUDPSender createAVCVideoStreamWithRemoteAddress:...supports60FPS...]` calls media session/config helpers and XPC dictionary setup in `symbols/ScreensharingAgent.bn.focus.edges.csv`.
    - `-[SSUDPSender createNegotiatorOptionsDictionaryFromDisplay:hdr:]` calls display mode/resolution APIs in `symbols/ScreensharingAgent.bn.focus.edges.csv`.

- System policy/privilege gates
  - TCC/OpenDirectory/security entitlements present in `screensharingd`, `ScreensharingAgent`, `AppleVNCServer`.
  - Evidence: `raw/entitlements_*.xml`, `symbols/*.md` (linked frameworks include TCC, OpenDirectory symbols).
  - Callflow evidence:
    - `ODHelper nodeIsLocal:` calls `_ODSessionCreate` and `_ODSessionNodeNameIsLocal` in both `screensharingd` and `AppleVNCServer` focus edge graphs.

## Dependency Highlights
- `screensharingd` links/imports VideoToolbox and uses `VTCompressionSessionCreate`, indicating encoded video path.
- `ScreensharingAgent` includes stream/UDP sender classes and `supports60FPS` arguments, indicating high-perf media branch.
- IDS stack appears on viewer and AppleVNCServer paths for invitation/routing variants.

## Known Gaps
- `ScreenSharing.framework` and nested `ScreenSharingUI.framework` code not present as standalone binaries in extracted filesystem (dyld cache extraction pending).
- Framework-level selector evidence is now partially recovered in `wiki/07-reference-generated/framework-cache-signals.md`, reducing uncertainty on ProMode gating fields.
- Runtime logs/pcaps not yet captured in this run; dynamic guards and downgrade events are still inference-level.
