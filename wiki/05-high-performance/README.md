# High-Performance Path

Everything about "ProMode" / accelerated / virtual-display behavior. The short story: a session can reach a low-latency virtual-display state while content still arrives over TCP framebuffer rectangles; a separate compressed-media path exists in the binaries but the conditions that activate it are not fully settled.

## Pages

- [encoding-tiers.md](encoding-tiers.md) — the five-tier quality system, the `quality=` URL parameter, and the per-encoding pixel-pipeline mapping (`0x3e8`, `0x3e9`, `0x3ea`, `0x3f2`, `0x3f3`, standard zlib).
- [acceleration-gates.md](acceleration-gates.md) — the three runtime gates (`vfb`, ProMode, `virtualDisplayCount`) and what is / isn't yet proven about the AVC media path.
- [static-guard-matrix.md](static-guard-matrix.md) — the static guard surface (server-advertised support, viewer intent, UDP health, multi-viewer release path).
- [video-pipeline.md](video-pipeline.md) — the narrative argument that the observed native HP session is a low-latency TCP framebuffer path, not a hardware video-decode path.
- [transport-track.md](transport-track.md) — transport-side promotion work and runtime observations.
- [viewer-track-24G419.md](viewer-track-24G419.md) — viewer-side findings from the `24G419` comparison build.

## See also

- The Apple-private message families the HP path uses are catalogued in [../03-transport/message-catalog.md](../03-transport/message-catalog.md).
- Session state transitions feeding into HP: [../01-architecture/state-machine.md](../01-architecture/state-machine.md).
- Open items on the HP path: [../08-tracking/open-questions.md](../08-tracking/open-questions.md).
