# Apple Screen Sharing Wiki

A reverse-engineered specification of Apple's macOS Screen Sharing protocol, baselined on `24G231`. This wiki is the canonical knowledge base for the project that ships [`examples/client/applehpdebug.c`](../examples/client/applehpdebug.c).

## Start Here

If you are new to the project, read in this order:

1. [apple_vnc_hp.md](apple_vnc_hp.md) — the long-form protocol document.
2. [00-overview/current-status.md](00-overview/current-status.md) — what is settled, what is open, in one screen.
3. The topical section you need (see "Browse by Topic" below).

If you want to **modify the standalone client**, read:

- [08-tracking/applehpdebug-comparison.md](08-tracking/applehpdebug-comparison.md) — what the client already implements.
- [08-tracking/client-implementation-track.md](08-tracking/client-implementation-track.md) — current worklog.

If you want to **answer an open protocol question**, start at [08-tracking/open-questions.md](08-tracking/open-questions.md).

## Browse by Topic

| Section | What's in it |
|---|---|
| [`00-overview/`](00-overview/) | At-a-glance status snapshot. |
| [`01-architecture/`](01-architecture/) | Process roles, components, session state machine. |
| [`02-auth/`](02-auth/) | Security type `33` (Apple `RSA-SRP`), packet generation, post-auth key install. |
| [`03-transport/`](03-transport/) | Post-auth record layer, message catalog, startup sequence. |
| [`04-runtime-evidence/`](04-runtime-evidence/) | Capture-backed ledgers and archived decode dumps. |
| [`05-high-performance/`](05-high-performance/) | HP / ProMode model, encoding tiers, acceleration gates. |
| [`06-tooling/`](06-tooling/) | Binary baseline, debugging runbooks, scripts, Wireshark dissector. |
| [`07-reference-generated/`](07-reference-generated/) | Mechanically exported symbol material — reference data. |
| [`08-tracking/`](08-tracking/) | Open questions, client worklog, `applehpdebug.c` comparison. |

Flat link catalogues across the sections:

- [explanation-index.md](explanation-index.md) — design-level explanations.
- [reference-index.md](reference-index.md) — protocol / tooling / generated reference.
- [tracking-index.md](tracking-index.md) — open work and historical material.

## Conventions

- Active runtime baseline is `24G231`. Comparison viewer material is on `24G419`. Anchor offsets in [06-tooling/binary-baseline.md](06-tooling/binary-baseline.md); do not quote a function address without going through that ledger.
- Function addresses are written `binary::sub_<addr>` (e.g. `screensharingd::sub_100020ef8`) so the owning binary is explicit. Note provenance (thin `arm64e` slice, Binary Ninja database, or runtime-rebased session) when it matters.
- Every protocol claim carries a confidence label: `confirmed`, `strong-inference`, `open`, or `revision-gap`. `confirmed` requires at least two independent evidence types.
- Paths inside this wiki are relative. Workspace-internal references stay inside `libvncserver/wiki/`; nothing links to material outside the wiki tree.
- Open questions live only in [08-tracking/open-questions.md](08-tracking/open-questions.md). When a question is resolved, the answer moves to its topical section.

See [../../CLAUDE.md](../../CLAUDE.md) at the workspace root for the full set of documentation principles.
