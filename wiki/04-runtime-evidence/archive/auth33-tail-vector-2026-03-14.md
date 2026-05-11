# Auth33 Packet-2 Tail Vector (24G84)

## Source
- Capture: `apple_hp_vnc.pcapng`
- Frames: `15` and `121174`

## Extraction
- RSA1 packet-2 has `aux=0x02aa`.
- Tail bytes are `body[aux:]`, length `384` bytes.

## Decode
- Parsed as `96` little-endian `u32` words.
- Streams 0 and 2 tails are byte-identical.
- Histogram:
  - `9:1, 8:10, 7:9, 6:9, 5:9, 4:10, 3:13, 2:11, 1:15, 0:9`
- Prefix words:
  - `9,8,8,8,8,8,8,8,8,7,8,8,7,7,7,7`
- Suffix words:
  - `1,0,1,1,1,1,1,0,1,0,0,0,0,0,0,0`

## Interpretation
- This vector is structured metadata emitted by client-side packet template logic.
- It is not random ciphertext and is not challenge-variant in the two observed sessions.
