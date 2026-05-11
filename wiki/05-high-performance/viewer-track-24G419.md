# Viewer HP Track (24G419)

## Objective
- Answer two viewer-side questions on macOS `24G419`:
  - why high performance / dynamic resolution is not used on the working VNC path
  - why the Apple ID / iCloud path still fails before high performance can come up

## Final Answers

### 1. Why HP is not used on the working VNC path
- The working VNC session stays on the standard framebuffer path, not the AVC media framebuffer path.
- In the viewer binary, `-[SSSessionView dynamicResolutionModeAvailable]` requires all three of:
  - `frameBufferView.isUsingAVCMediaStream`
  - `self.isUsingVirtualDisplay`
  - `frameBufferView.frameBuffer.screenConfiguration.screens.count == 1`
- The concrete framebuffer implementations prove the first gate is decisive:
  - `-[SSFrameBufferView isUsingAVCMediaStream]` returns `0`
  - `-[SSFrameBufferAVConferenceView isUsingAVCMediaStream]` returns `0`
  - `-[SSFrameBufferAVCMediaView isUsingAVCMediaStream]` returns `1`
- The working VNC trace only hit the base framebuffer path and never hit the AVC media path.
- Therefore the VNC session is treated as a standard connection, `dynamicResolutionModeAvailable` stays false, and HP is not used.

### 2. Why the Apple ID path still fails before HP is used
- The Apple ID path gets further than VNC: it authenticates and reaches `ssSessionReady:`.
- It still never reaches AVC media activation before teardown.
- The earliest reliable failure is on the AVConference sidecar path:
  - `-[SSSessionView startAudioAVConferenceCallWithRemoteDictionary:]`
  - AVConference start succeeds with `relayEnabled=1` and `didSucceed=1`
  - `-[AVConference videoConference:didStopWithCallID:error:callMetadata:]`
  - `-[SSSessionView conference:didStopWithCallID:error:]`
  - error: `GKVoiceChatServiceErrorDomain Code=32003 "Remote participant hangup."`
- Remote-host root cause is now available from `avconferenced`:
  - `VideoConference: clean up session ... error Error Domain=GKVoiceChatServiceErrorDomain Code=32000 "Client ... failed to start"`
  - `didStart when call is not running?`
  - `Ending the Call even though we haven't finished notifying the client that we have started`
  - deeper `avconferenced` startup logs point to an audio-device bring-up failure:
    - `Could not find default device for <private>`
    - `AUVP: FindUsableDevice: NO usable device found`
    - `Unable to get a usable input device (err=-10876)`
    - `couldn't create the aggregate device (err=-10876)`
- After that, the session still reaches `ssSessionReady:` and `kSSSessionStateConnected`, but it is already no longer in a healthy AVConference-backed state.
- The later viewer-visible teardown is secondary:
  - IDS ends the session with `IDSSessionEndedReasonLocalHangup (11)`
  - `handleSessionEnded:fromID:withInfo:` sees `REASON = LocalHangup`
  - `ssSession:connectDidFail:` maps failure code `2` to `Communications error`
- The viewer also logs `use avconference call 0` and `usingVirtualDisplay 0`, so the path never reaches an HP-eligible state before teardown.
- Therefore the Apple ID path fails because the AVConference relay/audio sidecar collapses first, and the later LocalHangup / Communications error path is just the viewer's cleanup/reporting of that earlier failure.

## Evidence

### Runtime Evidence
- VNC trace from the 2026-03-15 13:51:29 viewer lldb capture:
  - Shows:
    - `viewer_auth_result`
    - `viewer_session_ready`
    - repeated `viewer_is_using_avc_base`
    - no `viewer_session_ended`
    - no `viewer_connect_did_fail`
- Apple ID trace from the 2026-03-15 13:47:55 viewer lldb capture:
  - Shows:
    - `viewer_auth_result`
    - `viewer_session_ready`
    - `viewer_session_ended`
    - `viewer_connect_did_fail`
    - failure code register `x3 = 2`
- Apple ID AVConference trace from the 2026-03-15 14:37:55 viewer lldb bypass capture:
  - Shows:
    - `viewer_start_audio_avconference_call`
    - `viewer_avconference_did_stop`
    - `viewer_sessionview_conference_did_stop`
  - Correlated local log:
    - AVConference start succeeds
    - AVConference stops with `Remote participant hangup`
    - session later reaches `connected`
    - IDS later ends with `LocalHangup`
- Focused remote host trace from the 2026-03-15 14:43 remote focus capture:
  - Shows remote `avconferenced` failing the same Apple ID run with:
    - `GKVoiceChatServiceErrorDomain Code=32000 "Client ... failed to start"`
    - `didStart when call is not running?`
    - `Ending the Call even though we haven't finished notifying the client that we have started`
    - CoreAudio / AUVP failures finding a usable input device and creating the aggregate device
- Successful remote host comparison:
  - live `avconferenced` log after removing NoMachine audio devices and attaching AirPods
  - shows a stable `VCCallSession-AudioOnly` with ongoing TX/RX bitrate, IDS datagrams, and `AudioIO ... ready=1`
  - remote audio device state at the same time:
    - `Alex's AirPods Pro` = default input device
    - `Alex's AirPods Pro` = default output / system output device
    - No NoMachine virtual audio devices present

### Viewer Logic
- `-[SessionWindowController appWantsProModeInterface]` returns `1`.
- `-[SessionWindowController canUseDynamicResolutionMode]` requires:
  - `sessionView.isConnected`
  - `sessionView.isControlling`
  - `!paused`
  - `sessionView.dynamicResolutionModeAvailable`
- `-[SessionWindowController updateDynamicResolutionButtonTooltip]` checks `sessionView.isUsingAVCMediaStream` first and selects `DRUnavailableInStandardConnection` when false.
- `-[SessionWindowController addSessionViewObservers]` watches:
  - `dynamicResolutionModeAvailable`
  - `usingAVCMediaStream`
  - `isControlling`
  - `sessionPaused`

### Critical Disassembly
- `-[SSSessionView dynamicResolutionModeAvailable]`:
  - `frameBufferView.isUsingAVCMediaStream`
  - `self.isUsingVirtualDisplay`
  - `frameBufferView.frameBuffer.screenConfiguration.screens.count == 1`
- `-[SSSessionView setDynamicResolutionMode:]`:
  - only blocks when a transition is already in progress
  - otherwise tail-calls `setDynamicResolutionModeCore:`
- `-[SSSessionView ssSession:connectDidFail:]`:
  - maps failure code `2` to `Communications error`
- `-[SSSessionView handleSessionEnded:fromID:withInfo:]`:
  - unknown end-reason branch forwards into `ssSession:connectDidFail:` with code `2`
- `-[SSSessionView conference:didStopWithCallID:error:]`:
  - sits directly on the AVConference stop path observed at runtime

## Current Best Explanation
- Strong inference from the correlated traces:
  - the Apple ID path creates a relay-enabled AVConference sidecar
  - the remote host's `avconferenced` fails to start its AVConference client for that sidecar
  - the immediate cause appears to be audio startup on the remote host, specifically failure to find a usable input device / build the aggregate audio device
  - that failed start tears the sidecar down almost immediately
  - the viewer can still briefly render RFB content after the sidecar dies
  - but it never transitions into an HP-eligible AVConference / virtual-display state
  - IDS then ends the session with `LocalHangup`, and the viewer reports `Communications error`
- The successful comparison run strengthens this:
  - after removing NoMachine and making AirPods the default input/output device, the Apple ID session stays connected
  - remote `avconferenced` no longer shows the aggregate-device / usable-input failures
  - therefore the failure appears environment-dependent and strongly tied to remote audio-device configuration

## Scope Notes
- These conclusions are viewer-side only.
- They answer why HP is absent on the tested native viewer paths.
- They do not yet decode the exact `sessionEndInfo` dictionary key/value that produced the Apple ID unknown-reason branch.

## Remaining Open Item
- The remaining Apple ID question is no longer "why did the viewer report LocalHangup?"
- It is:
  - why remote `avconferenced` cannot start the AVConference client for this Screen Sharing Apple ID session
- The next step should focus on remote `avconferenced` / `rapportd` startup prerequisites, not viewer teardown mapping.
- Current leading hypothesis:
  - NoMachine virtual audio devices and/or lack of a valid default input device on the remote host were causing the AVConference startup failure.
