# Overview

The entry point for the wiki. This section answers "what is currently known, what isn't, and where do I read more?" — nothing else lives here.

## Pages

- [current-status.md](current-status.md) — one-screen snapshot of what's settled, what's open, and which page owns each topic.

## Where to go next

| If you want… | Go to |
|---|---|
| The full protocol document | [../apple_vnc_hp.md](../apple_vnc_hp.md) |
| Authentication mechanics | [../02-auth/](../02-auth/) |
| Post-auth message families and startup ordering | [../03-transport/](../03-transport/) |
| HP / ProMode and acceleration gates | [../05-high-performance/](../05-high-performance/) |
| Binary baseline and debug runbooks | [../06-tooling/](../06-tooling/) |
| Open questions | [../08-tracking/open-questions.md](../08-tracking/open-questions.md) |
| Status of the standalone client | [../08-tracking/applehpdebug-comparison.md](../08-tracking/applehpdebug-comparison.md) |

## Baseline

- Active runtime baseline: macOS Sequoia `24G231`.
- Viewer comparison baseline (HP path only): `24G419`.
- All function offsets must come from [../06-tooling/binary-baseline.md](../06-tooling/binary-baseline.md).
