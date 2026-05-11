# screensharingd SSH LLDB Runbook (24G231)

## Scope
- Build: macOS Sequoia `24G231`
- Target: `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd`
- Goal: debug from SSH to avoid local display disruption when LLDB pauses the daemon.

## Why SSH
- confirmed: pausing `screensharingd` with LLDB can stall host/viewer display behavior.
- confirmed: remote SSH control avoids losing your control channel when GUI/session is impacted.

## Preconditions
- SSH access to host is working.
- You can run `sudo` over SSH.
- Keep one local or secondary machine ready to trigger viewer connections.

## Known 24G231 Static Function Anchors
- `screensharingd::sub_100015bdc` -> auth dispatch (`SendRSAResponse`) post-prologue probe
- `screensharingd::sub_100018754` -> key request path (`authtype=0`) post-prologue probe
- `screensharingd::sub_1000189d4` -> plain auth path (`authtype=1`) post-prologue probe
- `screensharingd::sub_100018e8c` -> SRP auth path (`authtype=2`) post-prologue probe

These are `arm64e` static addresses from the thin slice and must be rebased with the runtime ASLR slide each run.
Do not use the earlier mixed-slice anchors `screensharingd::sub_10001621c`, `screensharingd::sub_100018dbc`, `screensharingd::sub_10001904c`, `screensharingd::sub_1000195e6`; the old SRP anchor was misaligned and invalid for `arm64e`.
Canonical identity and approved offsets live in [binary-baseline.md](binary-baseline.md).

## Session Layout (tmux recommended)
```bash
ssh alex@<host>
tmux new -s ssdbg
```

Use 3 panes:
1. `log` pane
2. `lldb` pane
3. `control` pane (kickstart/trigger helpers)

## Pane 1: Focused Log Stream
Use tight filtering to see trigger points without giant noise:
```bash
sudo log stream --style compact --level debug --predicate '
process == "screensharingd" AND (
eventMessage CONTAINS "accept new screen sharing connection" OR
eventMessage CONTAINS "HandleAuthTypeMessage 33" OR
eventMessage CONTAINS "SendRSAResponse" OR
eventMessage CONTAINS "SendRSAResponseSRPAuthentication" OR
eventMessage CONTAINS "Authentication: SUCCEEDED" OR
eventMessage CONTAINS "session not accelerated"
)'
```

## Pane 2: LLDB Attach Workflow
Preferred attach path for this daemon:
```bash
sudo launchctl attach -ks system/com.apple.screensharing
```

Then in LLDB:
```lldb
command source scripts/lldb/screensharingd_attach_init.lldb
breakpoint list
continue
```

Notes:
- The helper rebases the breakpoints automatically from the current slide.
- Name breakpoints like `SendRSAResponseSRPAuthentication` are unresolved on this stripped build; use address/named probes from the helper instead.
- If process exits, reattach and rerun the init file.
- If `auth_dispatch` fires, LLDB on this host may repeatedly retrap on resume. In that case:
```lldb
breakpoint disable 1
continue
```
- If `auth_srp` fires and you want auth to finish:
```lldb
breakpoint disable 4
continue
```

## Pane 3: Control Helpers
Restart daemon cleanly:
```bash
sudo launchctl kill SIGKILL system/com.apple.screensharing 2>/dev/null || true
sudo launchctl kickstart -k system/com.apple.screensharing
```

Quick state check:
```bash
launchctl print system/com.apple.screensharing | rg 'state =|runs =|last exit code'
```

## Optional: One-Liner Runtime Address Calculator
Replace `SLIDE_HEX` with value from `image list -o -f`:
```bash
SLIDE_HEX=0x0000000000b18000
python3 - <<'PY'
import os
slide = int(os.environ["SLIDE_HEX"], 16)
addrs = {
    "dispatch": 0x100015bdc,
    "keyreq":   0x100018754,
    "plain":    0x1000189d4,
    "srp":      0x100018e8c,
}
for k,v in addrs.items():
    print(f"{k}: {hex(v + slide)}")
PY
```

Then paste resulting addresses into LLDB `breakpoint set --address ...`.

## Minimal End-to-End Sequence
1. Start filtered log stream (Pane 1).
2. Attach with `launchctl attach -ks` (Pane 2).
3. Source the LLDB init file and verify breakpoints.
4. `continue`.
5. Trigger viewer connection from client machine.

## Failure Modes
- `error: Process must be launched.`  
  LLDB has no active process (target exited). Reattach.

- `unresolved` address breakpoints  
  No loaded process/module or wrong slide math. Recheck `image list -o -f`.

- Attach stops with unusable `pc=0` state  
  Observed on this host even when breakpoint subcodes are valid. Treat the breakpoint stop subcode as ground truth.

- Repeated stop at the same auth breakpoint after `continue`
  Observed on this host for both software and hardware breakpoints. Disable the just-hit breakpoint and continue.

- Repeated stop at `dyld` `lldb_image_notifier`
  Disable LLDB's internal shared-library-event breakpoint if present or rerun the init file, which suppresses this path.

## Evidence Labels
- confirmed: launchd on-demand activation and auth33 flow (`HandleAuthTypeMessage 33`, `SendRSAResponseSRPAuthentication`) observed in runtime logs.
- confirmed: corrected `arm64e` auth probes hit at `SendRSAResponse` and `SendRSAResponseSRPAuthentication`.
- confirmed: `screensharingd` exits when idle / after session teardown.
- strong-inference: LLDB attach on this `arm64e` system daemon does hit the right code, but interactive frame/register presentation and breakpoint retirement are unstable on this host; use stop subcodes and logs as the reliable evidence.
