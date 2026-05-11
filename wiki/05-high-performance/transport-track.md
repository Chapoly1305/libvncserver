# High-Performance Transport Track

## Objective
- Determine whether the Apple Screen Sharing high-performance path can be activated from the standalone `libvncclient`-based client.
- If yes, document the required negotiation and runtime evidence.
- If no, isolate the missing gate or message sequence with evidence.

## Ground Truth
- Auth33 is standalone and working.
- Live viewing is standalone and working.
- Interactive input path is under active validation.
- No runtime oracle is required in the default path.
- High-performance session state is now proven in the native machine/VNC path.

## Static Evidence Baseline
- `wiki/07-reference-generated/symbols/ScreensharingAgent.md`
  - `SSUDPSender`
  - `AVCMediaStreamNegotiator`
  - `Set server stream config viewerID %d startingUDPPort %d`
  - `UDP streaming not active`
  - `Release UDP Streaming viewerID %d`
  - `ProMode active - called release`
- `wiki/07-reference-generated/symbols/screensharingd.bn.md`
  - `InitializeUDPVideoStream`
  - `UDPSend_ScreenSharing`
  - `session not accelerated %d`
- `wiki/05-high-performance/static-guard-matrix.md`
- `wiki/01-architecture/state-machine.md`
- refreshed headless Binary Ninja extracts (see `07-reference-generated/symbols/`)

## Current Static Read
- High-performance mode is not just a better framebuffer encoding.
- `screensharingd` / `AppleVNCServer` appear to own the control-plane transition:
  - `HandleModifySession`
  - `HandleCodecChanged`
  - `ProMode also enabled on viewer`
  - `viewer->udpVideoStreamWasInitialized %d  viewer->initUDPVideoStream %d`
- `ScreensharingAgent` appears to own the media-plane bring-up:
  - `Set server stream config viewerID %d startingUDPPort %d`
  - `sendToRemoteAddress:...startingUDPPort:...sessionID:supports60FPS:sendCursor:avcClientName:`
  - `createAVCVideoStreamWithRemoteAddress:...supports60FPS:...`
  - `Release UDP Streaming viewerID %d`
- This strongly suggests a two-stage promotion path:
  - Stage 1: Apple-specific post-auth session/codec modification on the TCP control plane
  - Stage 2: Agent-side UDP/AVC setup using negotiated session parameters

## What The Standalone Client Likely Still Lacks
- A vendor-specific post-auth session modification message path.
- A codec change / high-performance capability advertisement path.
- A way to provide or receive the values needed by UDP setup:
  - viewer ID
  - starting UDP port
  - media session ID
  - encryption keys
  - `supports60FPS`
  - `sendCursor`

## Investigation Tasks
### Task 1: Establish a clean runtime evidence loop
- Start unified log capture before each run.
- Preserve `/tmp/screensharing.log` into a scenario-specific folder after each run.
- Capture client logs, optional pcaps, and packet summaries into the same folder.

### Task 2: Compare native vs standalone runs
- Native Apple Screen Sharing client against the same server.
- Standalone `applehpdebug` client against the same server.
- Keep the same target, account, and basic interaction pattern.
- Compare:
  - log markers
  - UDP flow presence
  - acceleration / ProMode / stream-config messages

### Task 3: Identify missing viewer capability messages
- Review post-auth message flow in the standalone client.
- Search for Apple-specific session-modification or vendor-extension hooks in `libvncclient`.
- Match any missing steps against static strings:
  - stream config
  - codec changes
  - 60 FPS support
  - ProMode support / incompatibility
  - viewer UDP init flags

### Task 4: Instrument the standalone client for negotiation visibility
- Log all server-to-client and client-to-server extension points after auth.
- Record:
  - message ids
  - lengths
  - timing
  - any non-standard message types
- Confirm whether the session remains standard RFB framebuffer updates only.

### Task 5: Attempt controlled promotion experiments
- Vary only one factor at a time:
  - interactive vs observe-only usage
  - display selection / resolution
  - codec-related extension behavior if implemented
  - any discovered vendor capability messages
- Re-capture logs and network flows after each variant.

## Success Criteria
- We can point to a concrete message sequence and runtime evidence showing HP activation.

## Failure Criteria
- We can point to a concrete missing gate, unsupported message, or server-side incompatibility preventing HP activation.

## Required Artifacts Per Scenario
- `client.log`
- `screensharing.log`
- `hp_markers.txt`
- `timeline_notes.md`
- optional:
  - `packet_capture.pcapng`
  - `conversations_udp.txt`
  - `io_stat_1s.txt`

## Probe Commands
- Automated standalone probe:
  - `../06-tooling/scripts/screensharing_workflows.sh auth33 hp-probe <scenario> <host> [port] [seconds]`
- Manual runtime capture:
  - `../06-tooling/scripts/screensharing_workflows.sh capture runtime <scenario> <peer_ip_or_host>`

## Current Read
- The standalone client is likely still on the standard TCP framebuffer path.
- The most probable missing step is Apple-specific post-auth media/session negotiation rather than auth itself.
- The first implementation target should be TCP-side negotiation visibility, not UDP transport code.
- Native viewer-side conclusions for macOS `24G419` are now captured in:
  - `wiki/05-high-performance/viewer-track-24G419.md`
  - Key result: native machine/VNC sessions can reach HP with viewer-side evidence `usingVirtualDisplay 1`, `ProMode enabled`, and `dynamic resolution enabled on server` even when the observed packet capture remains TCP-dominant.
  - Key result: Apple ID / iCloud sessions use a different relay/datagram path (`quick relay`, `NWDatagramConnection`, AVConference sidecar) rather than the plain VNC/TCP connection class.
  - Key result: Apple ID also has an AVConference failure mode where the remote host's `avconferenced` fails client start (`GKVoiceChatServiceErrorDomain Code=32000 "Client ... failed to start"`), which leads to viewer-side `Remote participant hangup` and later `LocalHangup`.

## Next Implementation Targets
- Add explicit logging in the standalone client around:
  - post-auth non-standard server message ids
  - client-to-server vendor/extension messages after `ClientInit`
  - any server capability rectangles for supported messages / encodings / identity
- Compare a native Apple session and a standalone session to isolate:
  - which control-plane message causes `HandleModifySession`
  - which message or flag precedes `HandleCodecChanged`
  - whether the server ever offers data that looks like stream config or UDP setup material
