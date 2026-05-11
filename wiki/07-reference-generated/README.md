# Reference (Generated)

Mechanically-derived reference material — symbol exports from each binary, dyld-cache extracts, framework-cache string signals. These pages support claims elsewhere in the wiki; they are not the primary spec.

Treat the contents of this section as **reference data**: lookups, not narrative. When citing a function name or symbol from here, link to it; don't restate it elsewhere.

## Pages

- [dyld-cache-map.md](dyld-cache-map.md) — relevant entries from the dyld shared cache.
- [framework-cache-signals.md](framework-cache-signals.md) — selector strings recovered from the framework cache (ProMode gating, stream config, etc.).

## Symbol exports

Per-binary symbol catalogues. Each has both a high-level `.md` (Mach-O + import / export summary) and a Binary Ninja-derived `.bn.md` (function index) plus a focused subset (`.bn.focus.md`).

- `screensharingd`: [symbols/screensharingd.md](symbols/screensharingd.md), [symbols/screensharingd.bn.md](symbols/screensharingd.bn.md), [symbols/screensharingd.bn.focus.md](symbols/screensharingd.bn.focus.md)
- `ScreensharingAgent`: [symbols/ScreensharingAgent.md](symbols/ScreensharingAgent.md), [symbols/ScreensharingAgent.bn.md](symbols/ScreensharingAgent.bn.md), [symbols/ScreensharingAgent.bn.focus.md](symbols/ScreensharingAgent.bn.focus.md)
- `AppleVNCServer`: [symbols/AppleVNCServer.md](symbols/AppleVNCServer.md), [symbols/AppleVNCServer.bn.md](symbols/AppleVNCServer.bn.md), [symbols/AppleVNCServer.bn.focus.md](symbols/AppleVNCServer.bn.focus.md)
- `Shared Screen Viewer`: [symbols/Shared_Screen_Viewer.md](symbols/Shared_Screen_Viewer.md), [symbols/Shared_Screen_Viewer.bn.md](symbols/Shared_Screen_Viewer.bn.md), [symbols/Shared_Screen_Viewer.bn.focus.md](symbols/Shared_Screen_Viewer.bn.focus.md)
