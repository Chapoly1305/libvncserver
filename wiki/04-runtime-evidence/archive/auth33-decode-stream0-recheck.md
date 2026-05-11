# Entrance/Auth Decode

## Frame 5 (protocol_version)
- Time: `0.136414000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `12`
```json
{
  "text": "RFB 003.889"
}
```

## Frame 7 (protocol_version)
- Time: `0.136825000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `12`
```json
{
  "text": "RFB 003.889"
}
```

## Frame 9 (security_types)
- Time: `0.605188000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `5`
```json
{
  "count": 4,
  "types": [
    30,
    33,
    36,
    35
  ]
}
```

## Frame 11 (rsa1_client_packet1)
- Time: `0.738953000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `655`
```json
{
  "len_prefix": 650,
  "packet_version": 256,
  "magic": "RSA1",
  "authtype": 2,
  "aux": 256,
  "body_len": 640,
  "security_selection": 33,
  "body_non_zero_bytes": 254
}
```

## Frame 13 (srp_server_challenge_packet)
- Time: `0.774777000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1169`
```json
{
  "total_len": 1165,
  "step_u32": 2,
  "x_u16": 1159,
  "inner_len": 1155,
  "x_minus_inner": 4,
  "body_len": 1155,
  "srp_server_challenge": {
    "c": 0,
    "N_len": 512,
    "g_hex": "05",
    "salt_len": 32,
    "salt_hex": "847b98715c122b9e16221d4e48f4a3442eee69743856515f94e488ecc765a7d8",
    "B_len": 512,
    "kdf_iterations": 156250,
    "options": "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2"
  }
}
```

## Frame 15 (rsa1_client_packet)
- Time: `0.926852000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `1080`
```json
{
  "len_prefix": 1076,
  "packet_version": 256,
  "magic": "RSA1",
  "authtype": 2,
  "aux": 682,
  "body_len": 1066,
  "body_prefix_u16": 0,
  "inner_len": 678,
  "aux_minus_4": 678,
  "srp_client_step2": {
    "A_len": 512,
    "M1_len": 64,
    "options": "mda=SHA-512,replay_detection,conf+int=ChaCha20-Poly1305,kdf=SALTED-SHA512-PBKDF2",
    "field4_len": 16,
    "field4_hex": "19913da5559b362af324ff4fb0332595"
  },
  "trailing_tail_len": 384,
  "trailing_tail_prefix_hex": "0900000008000000080000000800000008000000080000000800000008000000",
  "trailing_tail_u32_le_count": 96,
  "trailing_tail_u32_le_first32": [
    9,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    8,
    7,
    8,
    8,
    7,
    7,
    7,
    7,
    7,
    6,
    7,
    6,
    7,
    6,
    7,
    6,
    6,
    5,
    6,
    6,
    5,
    5,
    6,
    6
  ],
  "trailing_tail_u32_le_last16": [
    1,
    0,
    1,
    1,
    1,
    1,
    1,
    0,
    1,
    0,
    0,
    0,
    0,
    0,
    0,
    0
  ],
  "trailing_tail_u32_le_histogram": {
    "9": 1,
    "8": 10,
    "7": 9,
    "6": 9,
    "5": 9,
    "4": 10,
    "3": 13,
    "2": 11,
    "1": 15,
    "0": 9
  }
}
```

## Frame 17 (srp_server_final_packet)
- Time: `0.944863000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `102`
```json
{
  "total_len": 98,
  "step_u32": 2,
  "x_u16": 92,
  "inner_len": 88,
  "x_minus_inner": 4,
  "body_len": 88,
  "srp_server_final": {
    "field1_len": 64,
    "field2_len": 16,
    "string_len": 0,
    "u32": 0
  }
}
```

## Frame 19 (security_result)
- Time: `0.950764000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `4`
```json
{
  "result_u32": 0
}
```

## Frame 21 (client_init)
- Time: `0.950920000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `1`
```json
{
  "byte": 193,
  "bits_b7_b0": "11000001"
}
```

## Frame 23 (server_init)
- Time: `1.731437000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `63`
```json
{
  "width": 1920,
  "height": 1080,
  "pixel_format": {
    "bits_per_pixel": 32,
    "depth": 24,
    "big_endian_flag": 0,
    "true_color_flag": 1,
    "red_max": 255,
    "green_max": 255,
    "blue_max": 255,
    "red_shift": 16,
    "green_shift": 8,
    "blue_shift": 0
  },
  "name_len": 39,
  "name_utf8_lossy": "\u0000\u0000\u0000\u0000\u0000R\ufffd\ufffd\ufffd/\ufffd\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000\u0000<server-hostname>",
  "name_hex": "000000000052bff6e72fe00000000000000000000000416c6578e2809973204d6163206d696e69"
}
```

## Frame 25 (unknown)
- Time: `1.732253000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `66`
```json
{}
```

## Frame 27 (unknown)
- Time: `1.746945000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `16`
```json
{}
```

## Frame 29 (unknown)
- Time: `1.801173000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `308`
```json
{}
```

## Frame 30 (unknown)
- Time: `1.851339000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `52`
```json
{}
```

## Frame 31 (unknown)
- Time: `1.851430000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `48`
```json
{}
```

## Frame 34 (unknown)
- Time: `1.855708000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `8`
```json
{}
```

## Frame 36 (unknown)
- Time: `2.547876000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `310`
```json
{}
```

## Frame 38 (unknown)
- Time: `2.549289000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 39 (unknown)
- Time: `2.553585000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `98`
```json
{}
```

## Frame 40 (unknown)
- Time: `2.553755000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `50`
```json
{}
```

## Frame 43 (unknown)
- Time: `2.571394000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `82`
```json
{}
```

## Frame 45 (unknown)
- Time: `2.576735000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 46 (unknown)
- Time: `2.580980000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `130`
```json
{}
```

## Frame 48 (unknown)
- Time: `2.582482000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `180`
```json
{}
```

## Frame 50 (unknown)
- Time: `2.593490000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 52 (unknown)
- Time: `2.626590000`
- Path: `<viewer-ip>:57847 -> <server-ip>:5900`
- TCP len: `184`
```json
{}
```

## Frame 54 (unknown)
- Time: `3.575646000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 55 (unknown)
- Time: `3.575651000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 56 (unknown)
- Time: `3.575653000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 57 (unknown)
- Time: `3.575656000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 58 (unknown)
- Time: `3.575659000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 59 (unknown)
- Time: `3.575662000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 60 (unknown)
- Time: `3.575664000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 61 (unknown)
- Time: `3.575667000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 62 (unknown)
- Time: `3.575670000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 63 (unknown)
- Time: `3.575672000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 64 (unknown)
- Time: `3.575675000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 65 (unknown)
- Time: `3.575677000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 66 (unknown)
- Time: `3.575680000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 71 (unknown)
- Time: `3.584999000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 72 (unknown)
- Time: `3.585003000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 73 (unknown)
- Time: `3.585007000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 74 (unknown)
- Time: `3.585010000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 75 (unknown)
- Time: `3.585012000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 76 (unknown)
- Time: `3.585015000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 77 (unknown)
- Time: `3.585018000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 78 (unknown)
- Time: `3.585021000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 79 (unknown)
- Time: `3.585023000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 80 (unknown)
- Time: `3.585026000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 81 (unknown)
- Time: `3.585028000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `946`
```json
{}
```

## Frame 84 (unknown)
- Time: `3.618528000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 85 (unknown)
- Time: `3.618532000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 86 (unknown)
- Time: `3.618538000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 87 (unknown)
- Time: `3.618541000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 88 (unknown)
- Time: `3.618544000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 89 (unknown)
- Time: `3.618548000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 90 (unknown)
- Time: `3.618551000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 91 (unknown)
- Time: `3.618554000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 92 (unknown)
- Time: `3.618557000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```

## Frame 93 (unknown)
- Time: `3.618563000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57847`
- TCP len: `1448`
```json
{}
```
