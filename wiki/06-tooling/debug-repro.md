# LLDB arm64e Repro Matrix

This folder isolates three variables:

- `arm64e` code generation
- ordinary process attach
- `launchd`-managed attach

Artifacts:

- `lldb_arm64e_repro`: tiny `arm64e` executable with stable non-inlined functions
- `com.local.lldb-arm64e-repro.plist`: user LaunchAgent for the same executable
- `install_launchagent.sh`: install/bootstrap the agent
- `uninstall_launchagent.sh`: remove it
- `attach_plain.sh`: run the binary directly
- `attach_launchd.sh`: attach via `launchctl attach -ks`

Useful LLDB commands:

```lldb
image lookup -n pac_candidate
breakpoint set --name pac_candidate
breakpoint set --name inner_work
continue
register read pc sp x0 x1
thread backtrace
```

Matrix:

1. Direct process attach
```bash
zsh attach_plain.sh
```
Then attach from another terminal:
```bash
lldb -p <pid>
```

2. launchd-managed user agent
```bash
zsh install_launchagent.sh
launchctl print gui/$(id -u)/com.local.lldb-arm64e-repro
zsh attach_launchd.sh
```

Interpretation:

- if both cases debug cleanly, the issue is specific to `screensharingd`
- if direct attach works but launchd attach corrupts stop state, the problem is in the launchd/debugserver path
- if both fail on this tiny binary, the issue is broader `arm64e` LLDB/debugserver behavior on this host
