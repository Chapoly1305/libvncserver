# Architecture

How the Screen Sharing system is organised at the process and session level. Read this section to learn which process does what and how the session moves between observe / control / acceleration states.

## Pages

- [component-map.md](component-map.md) — process roles (`screensharingd`, `ScreensharingAgent`, `AppleVNCServer`, `Shared Screen Viewer`, supporting frameworks), launchd / launch agent chain, IPC edges.
- [state-machine.md](state-machine.md) — session states (`Idle` → `HighPerformanceActive` → `Teardown`), transitions, and the static guard candidates for each.

## See also

- HP-specific gating in [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md).
- Static guard matrix backing the state-machine transitions: [../05-high-performance/static-guard-matrix.md](../05-high-performance/static-guard-matrix.md).
