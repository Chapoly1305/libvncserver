# Encoding Tiers And Quality Modes (24G419)

Specification for the native viewer's "adaptive" mode. The mode is **not** adaptive to bandwidth or latency — it is a static user preference that selects an encoding-tier set. The only per-tile adaptive behavior is hidden inside the `0x3f3` multi-variant codec path.

## Tier Selection

`+[SSSession qualityEncodingsForMode:withDisplayConfiguration:]` on `ScreenSharing.framework` (`24G419`) selects one of five tiers:

| Tier | Mode | Encodings Advertised |
|------|------|---------------------|
| Full | `4` | `zlib, copyrect` |
| Low | `1` | `0x3e8, zlib, zrle` |
| Medium | `2` | `0x3e9, zlib, zrle` |
| High | default | `0x3f3, 0x3ea, zlib, zrle` |
| High+ProMode | default + gate | `0x3f2, 0x3f3, 0x3ea, zlib, zrle` |

The `_RFBMaxQualityLevels` symbol returns `5`. Mode `5` (`kSSAudioHighQuality`) requires valid `numVirtualDisplays`; if no virtual displays exist, the viewer logs a warning and falls back.

## Quality Mode From The URL

The tier is set by `screenQualityMode` on `SSConnectionOptions`, parsed from the `quality` URL parameter on `vnc://` connections:

```
vnc://host?quality=low       → mode 1 → [0x3e8, zlib, zrle]
vnc://host?quality=medium    → mode 2 → [0x3e9, zlib, zrle]
vnc://host?quality=full      → mode 4 → [zlib, copyrect]
vnc://host?quality=high      → mode 5 → [0x3f3, 0x3ea, zlib, zrle]
vnc://host                   → mode 0 → same as high (default)
```

Other URL parameters observed on the viewer side: `encrypt`, `panning`, `deviceID`, `displayID`, `displayName`, `numVirtualDisplays`, `auth`, `hdr`, `control`, `showConnectionProgress`, `windowAlignment`, `disableReconnect`, `fallBackToObserve`.

## Encoder Pipeline (24G231)

The Apple-private codec encodings form a quality scale backed by `EncodeZlib` (`screensharingd::sub_100055b18`). Each preprocesses pixels differently before the same zlib backend, with different deflate levels:

| Encoding | Name | Pre-processing | Zlib Level | Dispatch |
|----------|------|----------------|------------|----------|
| `0x3e8` (`1000`) | Low Quality | 4-bit color (16-color palette per 8px block) | `9` (max) | `sub_100055b18` (`EncodeZlib`) |
| `0x3e9` (`1001`) | Medium Quality | 8-bit YCoCg-like dithering, 2px/byte | `6` | `sub_100055b18` (`EncodeZlib`) |
| `0x3ea` (`1002`) | High Quality | 16-bit RGB 5-6-5 color | `1` (min) | `sub_100055b18` (`EncodeZlib`) |
| `0x3f2` (`1010`) | RFBMediaStreamMessage1 | — | — | ProMode media-init announcement |
| `0x3f3` (`1011`) | Multi-Variant Scaled | GPU per-tile adaptive → agent RPC | — | `sub_100042478` (MVS) |
| `0x06` | Standard zlib | 32-bit pass-through | `1` | `sub_100055b18` (`EncodeZlib`) |

Compression rises as quality falls: Low pairs maximum compression with aggressive 4-bit color reduction; High preserves 16-bit color but uses minimum compression.

## Multi-Variant Path (`0x3f3`)

`0x3f3` is the only encoding that diverges from the `EncodeZlib` pipeline. It hands work to `ScreensharingAgent` via:

- `SSAgent_SendScaledScreenMVS_rpc` (`agent_SSAgent_SendScaledScreenMVS_rpc`)
- `SSAgent_SendUnscaledScreenMVS_rpc` (`agent_SSAgent_SendUnscaledScreenMVS_rpc`)
- `agent_SSAgent_EncodePartialUpdateMVS` — partial update encoding
- `agent_SSAgent_SetCacheFlagMVS` / `agent_SSAgent_ReinitializeCacheMVS` — cache management

When `0x3f3` is active, `screensharingd::AllocateMultiVariantCodecMemoryBuffer` allocates per-tile buffers. Tile size is determined by `DetermineEncodingParameters` (`screensharingd::sub_100042310`): default 15×25, with 9×12, 3×5, or 2×3 for constrained paths.

### Wire Format

The `0x3f3` rectangle body:

```
[1 byte]  tile_width
[1 byte]  tile_height
[variable] command_bitstream  — per-tile type codes, run-length encoded
[variable] render_data        — DCT coefficients, palette colors, masks
[trailer] length fields       — 0x14 byte tail
```

### Tile Types

The agent runs an OpenCL kernel (`EncodeVectorized`) that classifies each 8×8 pixel tile and outputs `commands[]` + `render_data[]`. Tile types from `screensharingd::EncodeMVS` (`sub_100042478`):

| Command | Name | Render Data |
|---------|------|-------------|
| `0` | White / Skip | None |
| `1` | MatchPrevious | None (copy from same position in previous frame) |
| `2` | MatchAbove | None (copy from tile above) |
| `3` | TwoColor (B&W) | 8-byte pixel mask + 2 colors (YCoCg, 8/6/6 bits each) |
| `4` | TwoColor | 8-byte pixel mask + 2 colors (YCoCg, 8/6/6 bits each) |
| `0x6d` | End marker | — |
| Complex | DCT | Quantized DCT coefficients in YCoCg color space |

OpenCL kernel constants from `ScreensharingAgent`:
- `kRFB_MVS_Tile_Invalid = 0xff`
- `kRFB_MVS_Tile_White` — all-white tile (kWhite = 0x01)
- `kRFB_MVS_Tile_LastMatch` — matches previous frame
- `kRFB_MVS_Tile_UpperMatch` — matches tile above
- `kRFB_MVS_Tile_BlackWhite` — black and white only
- `kRFB_MVS_Tile_TwoColor` — two unique colors
- `kRFB_MVS_Tile_DCT` — complex content, DCT-encoded

The bitstream is packed with `sub_100041bf0` (bit-writer) and `sub_100044bd8` (bit-aligner). Colors use YCoCg color space with 8/6/6-bit quantization via `sub_100044ce0` / `sub_1000453f4`. DCT quantization table is passed as a kernel parameter.

The standalone client currently advertises `0x3f3` and `0x3ea` but keeps zlib as the primary framebuffer encoder until an MVS decoder exists. The `0x3ea`/`0x3e9`/`0x3e8` decoders are simpler (zlib inflate + color conversion) and are the next implementation priority.

## Adjacent References

- HP gating beyond encoding tier: [acceleration-gates.md](acceleration-gates.md)
- Video pipeline narrative: [video-pipeline.md](video-pipeline.md)
- Open work for `0x3f3` / `0x3ea` decode: [../08-tracking/open-questions.md](../08-tracking/open-questions.md)
