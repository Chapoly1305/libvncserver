# screensharingd Mac mini Breakpoints

Target binary:

- `/System/Library/CoreServices/RemoteManagement/screensharingd.bundle/Contents/MacOS/screensharingd`

Workspace copy used for analysis: an archived `screensharingd.macmini` Mac mini binary capture.

The live Mac mini binary does not expose `HandleModifySession` or `HandleCodecChanged` as LLDB-resolvable symbols. Those names exist as strings only. Use module offsets or file addresses derived from the live binary copy.

## Verified Mapping

Binary Ninja on the live copy resolved these functions from string references:

- modify-session dispatcher context:
  - function start: `0x1000383d8`
  - offset from image base: `0x383d8`
  - string refs to `"HandleModifySession"` at:
    - `0x10003a92a`
    - `0x10003a9fb`
    - `0x10003d427`
    - `0x10003d4ec`
    - `0x10003d5c3`
- codec-changed handler context:
  - function start: `0x100021de7`
  - offset from image base: `0x21de7`
  - string ref to `"HandleCodecChanged"` at:
    - `0x100024426`
- UDP video init context:
  - function start: `0x100042d03`
  - offset from image base: `0x42d03`
  - string ref to `"InitializeUDPVideoStream"` at:
    - `0x100042d86`
- acceleration-decision context:
  - function start: `0x10000fe07`
  - offset from image base: `0xfe07`
  - string refs to `" session not accelerated %d"` at:
    - `0x10000fea1`
    - `0x10000feb5`
    - `0x10000fee0`
- UDP stream state context:
  - function start: `0x1000033cb`
  - offset from image base: `0x33cb`
  - string refs to `"viewer->udpVideoStreamWasInitialized %d  viewer->initUDPVideoStream %d"` at:
    - `0x100003643`
    - `0x10000366b`
    - `0x100003699`

Base image address in Binary Ninja:

- `0x100000000`

## Practical LLDB Use

For an attached process, first get the module load base:

```lldb
image list -o -f screensharingd
```

Then compute:

```text
actual_load_address = module_load_base + offset
```

Example offsets:

- `0x383d8` modify-session dispatcher
- `0x21de7` codec-changed context
- `0x42d03` UDP video init context
- `0xfe07` acceleration-decision context
- `0x33cb` UDP stream state context

## Recommended Break Order

Use these first:

```lldb
b -a <base+0xfe07>
b -a <base+0x383d8>
b -a <base+0x21de7>
b -a <base+0x42d03>
b -a <base+0x33cb>
```

If you want more selective stops inside the larger modify-session dispatcher, use the string-ref sites:

```lldb
b -a <base+0x3a92a>
b -a <base+0x3a9fb>
b -a <base+0x3d427>
b -a <base+0x3d4ec>
b -a <base+0x3d5c3>
```

## Suggested Workflow

1. Attach to `screensharingd` after a client connects.
2. Run `image list -o -f screensharingd`.
3. Set the offset-based breakpoints above.
4. Continue and trigger:
   - a normal standalone session
   - then a native Screen Sharing session
5. Compare which of these contexts fire in each run.

## Expected Value

- `0xfe07` tells you whether the daemon is deciding the session is not accelerated.
- `0x383d8` should catch the control-plane message dispatcher that includes modify-session handling.
- `0x21de7` should catch codec-change handling if HP promotion happens.
- `0x42d03` and `0x33cb` should only become interesting once UDP video bring-up starts.
