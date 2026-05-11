# Entrance/Auth Decode

## Frame 121164 (protocol_version)
- Time: `79.710129000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `12`
```json
{
  "text": "RFB 003.889"
}
```

## Frame 121166 (protocol_version)
- Time: `79.710623000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `12`
```json
{
  "text": "RFB 003.889"
}
```

## Frame 121168 (security_types)
- Time: `80.094488000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
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

## Frame 121170 (rsa1_client_packet1)
- Time: `80.126273000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
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
  "body_non_zero_bytes": 256
}
```

## Frame 121172 (srp_server_challenge_packet)
- Time: `80.172377000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
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

## Frame 121174 (rsa1_client_packet)
- Time: `80.348279000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
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
    "field4_hex": "3bcf1754052e0fc62cb5dc0c4d29bc42"
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

## Frame 121175 (rsa1_client_packet)
- Time: `80.510410000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
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
    "field4_hex": "3bcf1754052e0fc62cb5dc0c4d29bc42"
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

## Frame 121178 (srp_server_final_packet)
- Time: `80.544563000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
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

## Frame 121180 (security_result)
- Time: `80.551106000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `4`
```json
{
  "result_u32": 0
}
```

## Frame 121182 (client_init)
- Time: `80.551325000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `1`
```json
{
  "byte": 193,
  "bits_b7_b0": "11000001"
}
```

## Frame 121184 (server_init)
- Time: `80.582780000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
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

## Frame 121186 (unknown)
- Time: `80.584268000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `66`
```json
{}
```

## Frame 121188 (unknown)
- Time: `80.590311000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `16`
```json
{}
```

## Frame 121190 (unknown)
- Time: `80.598202000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `52`
```json
{}
```

## Frame 121192 (unknown)
- Time: `80.598386000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `8`
```json
{}
```

## Frame 121194 (unknown)
- Time: `80.610120000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `338`
```json
{}
```

## Frame 121196 (unknown)
- Time: `80.620167000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `82`
```json
{}
```

## Frame 121198 (unknown)
- Time: `82.219351000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `310`
```json
{}
```

## Frame 121200 (unknown)
- Time: `82.221225000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 121201 (unknown)
- Time: `82.243123000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `98`
```json
{}
```

## Frame 121203 (unknown)
- Time: `82.243278000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `166`
```json
{}
```

## Frame 121205 (unknown)
- Time: `82.249860000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `196`
```json
{}
```

## Frame 121207 (unknown)
- Time: `82.255751000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `114`
```json
{}
```

## Frame 121209 (unknown)
- Time: `82.256406000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 121211 (unknown)
- Time: `82.262142000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `50`
```json
{}
```

## Frame 121213 (unknown)
- Time: `82.268034000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `50`
```json
{}
```

## Frame 121215 (unknown)
- Time: `82.285285000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `34`
```json
{}
```

## Frame 121217 (unknown)
- Time: `82.291804000`
- Path: `<viewer-ip>:57862 -> <server-ip>:5900`
- TCP len: `50`
```json
{}
```

## Frame 121219 (unknown)
- Time: `82.938929000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `1448`
```json
{}
```

## Frame 121220 (unknown)
- Time: `82.938933000`
- Path: `<server-ip>:5900 -> <viewer-ip>:57862`
- TCP len: `1448`
```json
{}
```
