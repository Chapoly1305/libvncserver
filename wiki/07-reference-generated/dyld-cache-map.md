# dyld Cache Mapping Notes (24G84)

## Source
- `/Volumes/GlowG24G84.arm64eSystemCryptex/System/Library/dyld/dyld_shared_cache_arm64e.map`

## Relevant Entries
- `/System/Library/PrivateFrameworks/ScreenSharing.framework/Versions/A/ScreenSharing`
  - `__TEXT 0x1C20EB000 -> 0x1C229F720`
- `/System/Library/PrivateFrameworks/ScreenSharing.framework/Versions/A/Frameworks/ScreenSharingUI.framework/Versions/A/ScreenSharingUI`
  - `__TEXT 0x24F9E5000 -> 0x24F9F4080`
- `/System/Library/PrivateFrameworks/ScreenSharingKit.framework/Versions/A/ScreenSharingKit`
  - `__TEXT 0x24F9F5000 -> 0x24FB7CE4F`
- `/System/Library/PrivateFrameworks/ScreenSharingServer.framework/Versions/A/ScreenSharingServer`
  - `__TEXT 0x24FB7D000 -> 0x24FB84480`

## Interpretation
- The absence of standalone `ScreenSharing`/`ScreenSharingUI` binaries in the extracted root is consistent with dyld shared-cache packing for this build.
- Additional Screen Sharing-relevant code is likely split across:
  - `ScreenSharing.framework`
  - `ScreenSharingUI.framework`
  - `ScreenSharingKit.framework`
  - `ScreenSharingServer.framework`

## Impact on Investigation
- Static binary extraction from filesystem alone is incomplete for framework-level message mapping.
- Current 24G84 conclusions are therefore strongest for daemon/agent/viewer binaries already extracted as standalone executables.
