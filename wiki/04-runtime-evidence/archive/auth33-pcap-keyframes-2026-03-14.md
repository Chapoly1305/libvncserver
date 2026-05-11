# Auth33 Pcap Keyframes (2026-03-14)

Capture: apple_hp_vnc.pcapng

## Conversation Summary
================================================================================
TCP Conversations
Filter:<No Filter>
                                                           |       <-      | |       ->      | |     Total     |    Relative    |   Duration   |
                                                           | Frames  Bytes | | Frames  Bytes | | Frames  Bytes |      Start     |              |
<viewer-ip>:57847        <-> <server-ip>:5900          116702 171 MB       4412 353 kB     121114 172 MB        0.000000000        71.6026
<viewer-ip>:57862        <-> <server-ip>:5900            7350 10 MB         520 40 kB        7870 10 MB        79.400850000        12.1209
<server-ip>:51974        <-> <viewer-ip>:7000               7 2399 bytes       6 449 bytes      13 2848 bytes    40.606364000         0.0459
================================================================================

## Stream 0 and Stream 2 auth33 handshake frames
frame.number	frame.time_relative	tcp.stream	ip.src	tcp.srcport	ip.dst	tcp.dstport	tcp.len	vnc.num_security_types	vnc.security_type	vnc.client_security_type
9	0.605188000	0	<server-ip>	5900	<viewer-ip>	57847	5	4	30,33,36,35	
11	0.738953000	0	<viewer-ip>	57847	<server-ip>	5900	655			33
13	0.774777000	0	<server-ip>	5900	<viewer-ip>	57847	1169			0
15	0.926852000	0	<viewer-ip>	57847	<server-ip>	5900	1080			0
121168	80.094488000	2	<server-ip>	5900	<viewer-ip>	57862	5	4	30,33,36,35	
121170	80.126273000	2	<viewer-ip>	57862	<server-ip>	5900	655			33
121172	80.172377000	2	<server-ip>	5900	<viewer-ip>	57862	1169			0
121174	80.348279000	2	<viewer-ip>	57862	<server-ip>	5900	1080			0

## Frame 11 (stream 0, client RSA1 init)
0040  e7 8b 21 00 00 02 8a 01 00 52 53 41 31 00 02 01   ..!......RSA1...
0050  00 d0 9b 1f 7d 97 8b fc ec 8d 31 b1 f6 5a 3b 41   ....}.....1..Z;A
0060  91 09 39 f7 ee b2 d9 52 6f 4b 98 36 90 13 85 47   ..9....RoK.6...G
0070  d8 6c 89 4f de c1 55 d9 c0 ef 7b f8 42 d8 e3 6d   .l.O..U...{.B..m
0080  93 c5 d6 a3 4a bd fe 25 9a 25 1a 39 28 59 26 62   ....J..%.%.9(Y&b
0090  46 91 58 39 71 1a 51 3e b3 2c 75 56 19 58 38 c9   F.X9q.Q>.,uV.X8.
00a0  46 8e bb ee 64 6f e5 58 7f f4 66 54 a7 ec c2 bc   F...do.X..fT....
00b0  dd f8 7c 9f cd 7a d6 af 26 1e f1 b9 66 02 99 3b   ..|..z..&...f..;
00c0  25 84 17 cf 76 a2 bc 50 d8 80 f1 3c 51 fd a6 9c   %...v..P...<Q...
00d0  ca 4a 5d 2d 7e d8 2f b0 ea 07 94 9f 87 05 42 8e   .J]-~./.......B.
00e0  8a ad 24 92 6b 43 82 cc 91 14 81 db e5 c0 71 31   ..$.kC........q1
00f0  2a 07 6f 05 3c 50 56 35 43 d0 75 78 0e 55 1e 2e   *.o.<PV5C.ux.U..
0100  57 60 4f b5 4c 69 fd 0b 6d b7 8f 04 bf 30 4c 66   W`O.Li..m....0Lf
0110  60 53 2e 58 01 ca 33 83 58 89 53 d2 1b a4 10 71   `S.X..3.X.S....q

## Frame 121170 (stream 2, client RSA1 init)
0040  08 f1 21 00 00 02 8a 01 00 52 53 41 31 00 02 01   ..!......RSA1...
0050  00 c1 d6 13 ea 3a 98 d0 6d 90 c0 b7 86 13 78 0a   .....:..m.....x.
0060  19 9c af 7d 02 eb 0c fe 24 f2 c7 8a 34 13 54 57   ...}....$...4.TW
0070  d6 e0 b2 cd b0 9a 6e 39 3e 78 86 11 25 87 5d 45   ......n9>x..%.]E
0080  35 10 d8 cb 87 a4 08 69 e0 bc d2 a8 5e 30 56 82   5......i....^0V.
0090  3c 43 e2 0c 0d aa 04 f3 82 37 9c 67 eb 9c 15 2f   <C.......7.g.../
00a0  45 ae 85 19 b5 89 64 c6 9c e2 3d 67 6a 11 1d bb   E.....d...=gj...
00b0  a0 fc 23 54 70 9c 54 26 17 03 a0 0c 42 60 0a 69   ..#Tp.T&....B`.i
00c0  45 95 bc bf 2c a9 9a 5d 7c 04 10 26 c7 67 d5 bc   E...,..]|..&.g..
00d0  7f d7 69 d0 1f e6 48 65 4c 1e e1 0a 8a 78 73 e8   ..i...HeL....xs.
00e0  f8 ac cb 6c b3 75 7c 4c 47 5b cf 25 ed c6 bf b2   ...l.u|LG[.%....
00f0  51 d2 62 c1 3d 78 dd 81 e9 45 85 ff 62 cd 58 5e   Q.b.=x...E..b.X^
0100  68 f6 fa 77 23 42 d6 b3 f2 24 e8 46 82 63 f4 a2   h..w#B...$.F.c..
0110  61 ec ea 76 c1 44 29 0d 99 28 06 7d 2f 9e 9c ce   a..v.D)..(.}/...
