# Framework Cache Signals (24G84)

## Source
- dyld cache: `/Volumes/GlowG24G84.arm64eSystemCryptex/System/Library/dyld/dyld_shared_cache_arm64e`
- extracted signal set: archived `cache_strings_24G84_screensharing.txt` (24G84 dyld cache strings extract)

## High-Performance / ProMode Selectors
- `-[SSSession doesServerSupportProMode]`
- `-[SSSession appWantsProModeInterface]`
- `-[SSSession delegateWantsProModeInterface]`
- `-[SSSession dtDelegateWantsProModeInterface]`
- `-[SSSession setAppWantsProModeInterface:]`
- `-[SSSession setVideoStream1Supports60FPS:]`
- `-[SSSession setVideoStream2Supports60FPS:]`
- `-[SSSession videoStream1Supports60FPS]`
- `-[SSSession videoStream2Supports60FPS]`
- `-[SSSessionView closeOpenProModeSession]`
- `-[SSSessionView hasOpenProModeSession]`
- `-[SSSessionView openProModeSessionDisplayName]`
- `-[SSSessionView connectionDoesNotSupportProMode]`
- `-[SSSessionView setConnectionDoesNotSupportProMode:]`
- `-[SSSessionView ssSessionWantsProModeInterface:]`

## Related Constants and ivars
- `_SSHighQualityEncodingsForProMode`
- `_kPLProModeNotification`
- `_OBJC_IVAR_$_SSSession._appWantsProModeInterface`
- `_OBJC_IVAR_$_SSSession._videoStream1Supports60FPS`
- `_OBJC_IVAR_$_SSSession._videoStream2Supports60FPS`
- `_OBJC_IVAR_$_SSSessionView._connectionDoesNotSupportProMode`

## Interpretation
- Framework-level logic appears to model a negotiation matrix:
  - server supports pro mode
  - app/delegate wants pro mode
  - stream-level 60FPS capabilities (video stream 1/2)
  - explicit non-support and breakout UI states
- This strengthens the inference that high-performance mode is negotiated via multiple gates, not just a single daemon flag.

## Additional Notes
- Cache also contains paths for:
  - `ScreenSharing.framework`
  - `ScreenSharingUI.framework`
  - `ScreenSharingKit.framework`
  - `ScreenSharingServer.framework`
- This confirms Screen Sharing userland behavior is split across multiple framework images in cache for 24G84.
