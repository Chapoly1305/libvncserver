# `applehpdebug.c` Comparison

Comparison page for the maintained investigation narrative and the local `libvncserver/examples/client/applehpdebug.c` implementation.

## Scope

- Source under comparison: `libvncserver/examples/client/applehpdebug.c`
- Primary investigation references:
  - [open-questions.md](open-questions.md)
  - [client-implementation-track.md](client-implementation-track.md)
  - [../03-transport/startup-sequence.md](../03-transport/startup-sequence.md)
  - [../05-high-performance/acceleration-gates.md](../05-high-performance/acceleration-gates.md)
  - [../05-high-performance/video-pipeline.md](../05-high-performance/video-pipeline.md)

## What The Example Already Implements

- Auth33 end-to-end client flow using `VNC_USER` and `VNC_PASS`, including packet-1 generation and the Apple post-auth transport handoff.
- The native post-rekey startup shape described elsewhere in the wiki:
  - encrypted `0x1d SetDisplayConfiguration`
  - encrypted `0x02 SetEncodings`
  - first post-rekey `0x0d SetDisplayMessage`
- Apple-private rectangle handling for the early metadata burst, including `0x451`, `0x453`, `0x455`, `0x456`, and the `0x3f2` media-init rectangle.
- Suppression of non-native incremental polling after `0x09 AutoFrameBufferUpdate` becomes active.
- Live-view support with SDL, including framebuffer presentation, cursor handling, pointer injection, wheel input, and keyboard input.
- High-performance probes and toggles through environment variables such as:
  - `VNC_APPLE_HP`
  - `VNC_APPLE_HP_ADD_PROMODE_ENCODING`
  - `VNC_APPLE_HP_PREFER_PROMODE_ENCODING`
  - `VNC_LIVE_VIEW`

## Where The Wiki And Code Agree

- The example matches the current wiki conclusion that auth33 and the Apple CBC record layer are understood well enough for a working standalone client.
- The example also matches the current HP conclusion: the client can trigger Apple-private metadata and even the `0x3f2` media-init message, but that does not yet prove a sustained accelerated media session.
- The example's comment and logic around the first post-rekey `0x0d` message align with the tracked native ordering result: `0x0d01000000000000` is the first post-rekey display-selection body, but it is not the first encrypted client record overall.

## Where The Wiki Still Carries Information The Example Does Not Fully Close

- The wiki still treats true acceleration gating as open. The code can request ProMode-related behavior, but the repo evidence still says successful startup may remain on the TCP framebuffer branch.
- Pointer injection is implemented in the example, but the wiki still documents unresolved coordinate-space semantics. The current working rule remains a practical workaround, not a final protocol-level explanation.
- The exact conditions that make the server choose virtual-display state versus fallback state are still documented as an investigation question, not a solved invariant.
- Some native evidence remains stored in trace artifacts rather than reduced into durable reference pages, especially for same-session encrypted control traffic details.

## Documentation Guidance

- Treat `client-implementation-track.md` as the running worklog for standalone-client behavior.
- Treat this page as the shortest route for answering "does the repo example already do this?"
- When code comments and narrative notes diverge, the topical wiki section (e.g. `../03-transport/startup-sequence.md`, `../05-high-performance/acceleration-gates.md`) is the canonical source.

## Recommended Next Cleanup

- Normalize remaining stale absolute links inside deeper narrative pages.
- Extract the most important native-trace-only facts from prior runtime trace captures into stable markdown pages when they become durable conclusions.
- Keep this page updated whenever `applehpdebug.c` materially changes its startup sequence, input behavior, or HP negotiation path.
