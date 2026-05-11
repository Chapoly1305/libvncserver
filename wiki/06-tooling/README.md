# Tooling

Local operator tooling: binary baselines, debug runbooks, scripts, and the Wireshark dissector.

## Pages

- [binary-baseline.md](binary-baseline.md) — the canonical `24G231` `arm64e` slice identity and the approved function-offset ledger. Quote offsets from here, not from individual pages.
- [screensharingd-lldb-runbook.md](screensharingd-lldb-runbook.md) — lldb attach / break / log recipe for `screensharingd`.
- [macmini-breakpoints.md](macmini-breakpoints.md) — breakpoint set for the Mac mini test target.
- [debug-repro.md](debug-repro.md) — how to reproduce a debug session end-to-end.

## Directories

- [scripts/](scripts/) — Python helpers (`auth33_codec.py`, `screensharing_tools.py`), Frida scripts (`frida_screensharingd.js`), workflow wrapper (`screensharing_workflows.sh`), lldb command files.
- [wireshark/](wireshark/) — the `apple_screensharing_auth33.lua` dissector and its README.

## See also

- The protocol facts these tools demonstrate live in [../02-auth/](../02-auth/) and [../03-transport/](../03-transport/).
- Captures used by the runbooks: `apple_hp_vnc.pcapng` and `capture.pcapng` at the workspace root.
