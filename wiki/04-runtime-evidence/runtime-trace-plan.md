# Runtime Trace Plan (24G231)

## Goal
Capture dynamic evidence for TC1..TC5 on `24G231`.

## Per-Scenario Folder Convention
- `TC1_observe_only/`
- `TC2_control_enabled/`
- `TC3_high_perf/`
- `TC4_second_viewer_fallback/`
- `TC5_policy_or_capability_block/`

Each folder should contain:
- `log_stream.ndjson`
- `launchctl_state.txt`
- `nettop_snapshot.txt`
- `packet_capture.pcapng`
- `timeline.csv`

## Suggested Capture Commands
- Unified logs (example):
  - `log stream --style ndjson --predicate '(process == "screensharingd" OR process == "ScreensharingAgent" OR process == "AppleVNCServer" OR subsystem CONTAINS "screensharing" OR eventMessage CONTAINS[c] "ProMode" OR eventMessage CONTAINS[c] "viewer" OR eventMessage CONTAINS[c] "UDP")'`
- Service state snapshots:
  - `launchctl print system/com.apple.screensharing`
  - `launchctl print gui/$UID/com.apple.screensharing.agent`
- Network snapshots:
  - `nettop -P -L 1 -m tcp,udp`
  - `sudo tcpdump -i any -w packet_capture.pcapng host <peer_ip>`

## Normalization
- Normalize all timestamps to UTC ISO8601 with millisecond precision.
- Build `timeline.csv` columns:
  - `ts_utc,event,process,source_file,raw_excerpt`

## If You Only Have Encrypted PCAP
- You can still infer transport/state transitions without decrypting payload.
- Use:
  - `../06-tooling/scripts/screensharing_workflows.sh pcap analyze`
- Example:
  - `../06-tooling/scripts/screensharing_workflows.sh pcap analyze <capture.pcapng> <scenario_out_dir> [peer_ip]`
- Outputs to use:
  - `handshake_timeline.csv` for setup/teardown boundaries
  - `packet_timeline.csv` for flow transition timing
  - `conversations_udp.txt` + `conversations_tcp.txt` for media/control path dominance
  - `io_stat_1s.txt` for bandwidth phase shifts
- Interpretation heuristics:
  - Handshake complete then sustained high-rate UDP flow: likely high-performance media active.
  - Additional viewer often appears as new concurrent flow set and can precede UDP reduction.
  - Transition from sustained UDP to mostly TCP/control traffic: likely downgrade/fallback.

## libvncserver Debug Client
- Source:
  - `../../examples/client/applehpdebug.c`
- Built binary:
  - `../../build/examples/client/applehpdebug`
- Wrapper:
  - `../06-tooling/scripts/screensharing_workflows.sh auth33 applehpdebug`

Example:
- `VNC_USER='user' VNC_PASS='pass' ../06-tooling/scripts/screensharing_workflows.sh auth33 applehpdebug <server-ip> 5900 180`

What it logs:
- selected auth + sub-auth (ARD/VeNCrypt/TLS/etc)
- framebuffer update cadence
- cursor-shape/cut-text events
- chosen encoding string
