# Binary Baseline (24G231)

## Canonical Sample

- Active build: macOS Sequoia `24G231`
- Live host binary:
  - `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd`
- Canonical repo sample:
  - the archived `arm64e`-thin `screensharingd_arm64e` baseline binary (SHA-256 below)
- Validation rule:
  - `lipo -thin arm64e` of the live host binary must match the archived sample byte-for-byte.

## Identity

| Field | Value |
|---|---|
| SHA-256 (`arm64e` thin) | `80669dd6e377be9322568a46e8962dfdb26af4a160fc25aac799ff218ee091c1` |
| Mach-O UUID | `F7046EA2-D4A9-37D0-B635-71AF41CCE493` |
| Identifier | `com.apple.screensharing.daemon` |
| CandidateCDHash sha256 | `1f284abeed4b47d1283a68ed5f35109038cb3f68` |

## Canonical Auth Anchors

These are the approved `arm64e` static addresses for the active wiki.

| Symbolic label | Static address | Notes |
|---|---|---|
| `SendRSAResponse` | `screensharingd::sub_100015bdc` | auth33 RSA1 sub-dispatch entry |
| `SendRSAResponseKeyRequest` | `screensharingd::sub_100018754` | `authtype=0` |
| `SendRSAResponsePlainAuthentication` | `screensharingd::sub_1000189d4` | `authtype=1` |
| `SendRSAResponseSRPAuthentication` | `screensharingd::sub_100018e8c` | `authtype=2` |

## Canonical HP / Post-Auth Anchors

| Symbolic label | Static address | Notes |
|---|---|---|
| `HandleSetEncodingsMessage` path | `screensharingd::sub_1000352ac` | post-auth command multiplexer |
| `SetupAESKeys` | `screensharingd::sub_100016fb8` | installs local transport cryptors |
| `EncodeEncryptionInfo` sender path | `screensharingd::sub_100020ef8` | emits `0x44f` rekey packet |
| `SetEncodings entry` | `screensharingd::sub_1000377c0` | Frida/LLDB HP trace anchor |
| `Chosen encoding` | `screensharingd::sub_10003b3ec` | selected post-auth encoding |
| `UDP init` | `screensharingd::sub_100042478` | HP media bring-up probe |

## Working Rule

- Active narrative pages should cite this page or [screensharingd-lldb-runbook.md](screensharingd-lldb-runbook.md) when quoting offsets.
- Do not cite the older mixed-slice anchors `sub_10001621c`, `sub_100018dbc`, `sub_10001904c`, or `sub_1000195e6` as active truth.
