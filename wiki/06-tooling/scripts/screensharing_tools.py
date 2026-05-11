#!/usr/bin/env python3
from __future__ import annotations

import argparse
import base64
import binascii
import csv
import hashlib
import json
import os
import select
import secrets
import selectors
import socket
import struct
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
ROOT = SCRIPT_DIR.parent
RUNTIME_TRACES = ROOT / "runtime_traces"
RSA1_MAGIC = b"RSA1"


def clean_hex(s: str) -> bytes:
    s = "".join(ch for ch in s if ch not in " \n\r\t:_-")
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2:
        raise ValueError("hex length must be even")
    return bytes.fromhex(s)


def fmt_hex(data: bytes, limit: int = 64) -> str:
    h = data.hex()
    if len(h) <= limit * 2:
        return h
    return f"{h[: limit * 2]}... ({len(data)} bytes)"


def tshark_bin() -> str:
    candidates = [
        os.environ.get("TSHARK_BIN"),
        "/Applications/Wireshark.app/Contents/MacOS/tshark",
        subprocess.run(
            ["bash", "-lc", "command -v tshark || true"],
            check=False,
            capture_output=True,
            text=True,
        ).stdout.strip(),
    ]
    for candidate in candidates:
        if candidate and Path(candidate).exists():
            return candidate
    raise SystemExit("missing tshark binary; set TSHARK_BIN or install Wireshark")


@dataclass
class RSA1Envelope:
    packet_version: int
    authtype: int
    aux: int
    body: bytes

    def encode(self) -> bytes:
        payload = struct.pack(">H4sHH", self.packet_version, RSA1_MAGIC, self.authtype, self.aux)
        payload += self.body
        return struct.pack(">I", len(payload)) + payload

    @staticmethod
    def decode(blob: bytes) -> "RSA1Envelope":
        if len(blob) < 14:
            raise ValueError("blob too short")
        (n,) = struct.unpack_from(">I", blob, 0)
        if n != len(blob) - 4:
            raise ValueError(f"length mismatch: prefix={n} actual={len(blob) - 4}")
        packet_version, magic, authtype, aux = struct.unpack_from(">H4sHH", blob, 4)
        if magic != RSA1_MAGIC:
            raise ValueError(f"unexpected magic: {magic!r}")
        return RSA1Envelope(packet_version, authtype, aux, blob[14:])


def parse_fmt_tokens(fmt: str) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(fmt):
        if fmt[i] != "%":
            i += 1
            continue
        i += 1
        while i < len(fmt) and fmt[i] == "-":
            i += 1
        if i >= len(fmt):
            raise ValueError(f"dangling % in format: {fmt!r}")
        token = fmt[i]
        if token not in "cmosuq":
            raise ValueError(f"unsupported token %{token} in format: {fmt!r}")
        out.append(token)
        i += 1
    return out


def parse_mech_blob(fmt: str, blob: bytes) -> dict[str, Any]:
    tokens = parse_fmt_tokens(fmt)
    offset = 0
    values: list[Any] = []
    for token in tokens:
        if token == "c":
            values.append(blob[offset])
            offset += 1
        elif token == "m":
            (length,) = struct.unpack_from(">H", blob, offset)
            offset += 2
            values.append(blob[offset : offset + length])
            offset += length
        elif token == "o":
            length = blob[offset]
            offset += 1
            values.append(blob[offset : offset + length])
            offset += length
        elif token == "s":
            (length,) = struct.unpack_from(">H", blob, offset)
            offset += 2
            values.append(blob[offset : offset + length].decode("utf-8", errors="replace"))
            offset += length
        elif token == "u":
            (value,) = struct.unpack_from(">I", blob, offset)
            values.append(value)
            offset += 4
        elif token == "q":
            (value,) = struct.unpack_from(">Q", blob, offset)
            values.append(value)
            offset += 8
    return {"fmt": fmt, "size": len(blob), "consumed": offset, "values": values, "remaining": blob[offset:]}


def build_mech_blob(fmt: str, values: list[Any]) -> bytes:
    tokens = parse_fmt_tokens(fmt)
    if len(tokens) != len(values):
        raise ValueError(f"value count mismatch: need {len(tokens)}, got {len(values)}")
    out = bytearray()
    for token, value in zip(tokens, values):
        if token == "c":
            out += struct.pack("B", int(value) & 0xFF)
        elif token in {"m", "o"}:
            data = clean_hex(value) if isinstance(value, str) else bytes(value)
            if token == "m":
                out += struct.pack(">H", len(data))
            else:
                out += struct.pack("B", len(data))
            out += data
        elif token == "s":
            data = str(value).encode("utf-8")
            out += struct.pack(">H", len(data))
            out += data
        elif token == "u":
            out += struct.pack(">I", int(value) & 0xFFFFFFFF)
        elif token == "q":
            out += struct.pack(">Q", int(value) & 0xFFFFFFFFFFFFFFFF)
    return bytes(out)


def parse_challenge(chal: bytes):
    parsed = parse_mech_blob("%c%m%m%o%m%q%s", chal[10:])
    vals = parsed["values"]
    n_bytes = bytes(vals[1])
    g_bytes = bytes(vals[2])
    b_bytes = bytes(vals[4])
    return (
        vals[0],
        int.from_bytes(n_bytes, "big"),
        int.from_bytes(g_bytes, "big"),
        bytes(vals[3]),
        int.from_bytes(b_bytes, "big"),
        int(vals[5]),
        str(vals[6]),
        len(n_bytes),
    )


def H(*parts: bytes) -> bytes:
    h = hashlib.sha512()
    for part in parts:
        h.update(part)
    return h.digest()


def int_to_pad(n: int, width: int) -> bytes:
    b = n.to_bytes((n.bit_length() + 7) // 8 or 1, "big")
    if len(b) > width:
        return b[-width:]
    return b.rjust(width, b"\x00")


def derive_x(user: str, password: str, salt: bytes, iters: int) -> int:
    mode = os.getenv("VNC_AUTH33_X_MODE", "srp_emptyuser_colon_pbkdf2pass")
    dklen = int(os.getenv("VNC_AUTH33_PBKDF2_DKLEN", "128"))
    ui = f"{user}:{password}".encode()
    pw = password.encode()
    pbkdf2_pass = hashlib.pbkdf2_hmac("sha512", pw, salt, max(iters, 1), dklen=dklen)
    if mode == "pbkdf2_pass":
        xb = pbkdf2_pass
    elif mode == "pbkdf2_user_colon_pass":
        xb = hashlib.pbkdf2_hmac("sha512", ui, salt, max(iters, 1), dklen=dklen)
    elif mode == "h_s_h_user_colon_pass":
        xb = H(salt, H(ui))
    elif mode == "h_user_colon_pass":
        xb = H(ui)
    elif mode == "srp_nouser_pbkdf2pass":
        xb = H(salt, H(pbkdf2_pass))
    elif mode == "srp_user_colon_pbkdf2pass":
        xb = H(salt, H(user.encode() + b":" + pbkdf2_pass))
    else:
        xb = H(salt, H(b":" + pbkdf2_pass))
    return int.from_bytes(xb, "big")


def derive_k(n_pad: bytes, g_pad: bytes) -> int:
    mode = os.getenv("VNC_AUTH33_K_MODE", "hn_g")
    if mode == "hn":
        return int.from_bytes(H(n_pad), "big")
    if mode == "3":
        return 3
    return int.from_bytes(H(n_pad, g_pad), "big")


def derive_u(a_pad: bytes, b_pad: bytes) -> int:
    mode = os.getenv("VNC_AUTH33_U_MODE", "a_b")
    if mode == "b_a":
        return int.from_bytes(H(b_pad, a_pad), "big")
    return int.from_bytes(H(a_pad, b_pad), "big")


def derive_ksession(S: int, pad_len: int) -> bytes:
    mode = os.getenv("VNC_AUTH33_KSESSION_MODE", "h_padS")
    sp = int_to_pad(S, pad_len)
    if mode == "padS":
        return sp
    if mode == "h_rawS":
        sraw = S.to_bytes((S.bit_length() + 7) // 8 or 1, "big")
        return H(sraw)
    if mode == "h_h_padS":
        return H(H(sp))
    return H(sp)


def derive_m1(user: str, n_pad: bytes, g_pad: bytes, salt: bytes, a_pad: bytes, b_pad: bytes, key: bytes) -> bytes:
    mode = os.getenv("VNC_AUTH33_M1_MODE", "rfc5054_emptyuser")
    xor = bytes(a ^ b for a, b in zip(H(n_pad), H(g_pad)))
    if mode == "concat":
        return H(H(n_pad), H(g_pad), H(user.encode()), salt, a_pad, b_pad, key)
    if mode == "abk":
        return H(a_pad, b_pad, key)
    if mode == "rfc5054_user":
        return H(xor, H(user.encode()), salt, a_pad, b_pad, key)
    if mode == "rfc5054_nouser":
        return H(xor, salt, a_pad, b_pad, key)
    return H(xor, H(b""), salt, a_pad, b_pad, key)


def srp_candidate(user: str, password: str, N: int, g: int, salt: bytes, B: int, iters: int, pad_len: int):
    x = derive_x(user, password, salt, iters)
    a = secrets.randbits(max(int(os.getenv("VNC_AUTH33_A_BITS", "512")), 64))
    A = pow(g, a, N)
    n_pad = int_to_pad(N, pad_len)
    g_pad = int_to_pad(g, pad_len)
    a_pad = int_to_pad(A, pad_len)
    b_pad = int_to_pad(B, pad_len)
    k = derive_k(n_pad, g_pad)
    u = derive_u(a_pad, b_pad)
    v = pow(g, x, N)
    S = pow((B - (k * v) % N) % N, a + u * x, N)
    key = derive_ksession(S, pad_len)
    m1 = derive_m1(user, n_pad, g_pad, salt, a_pad, b_pad, key)
    return a_pad, m1, key


def build_packet2_candidate(a_bytes: bytes, m1: bytes, option_string: str) -> bytes:
    inner = build_mech_blob("%m%o%s%o", [a_bytes, m1, option_string, secrets.token_bytes(16)])
    wrapped = struct.pack(">HH", 0, len(inner)) + inner
    tail = b"\x00" * int(os.getenv("VNC_AUTH33_TAIL_LEN", "384"))
    env = RSA1Envelope(packet_version=0x0100, authtype=0x0002, aux=len(wrapped), body=wrapped + tail)
    return env.encode()


def write_session_wrap_key(session_key_64: bytes) -> None:
    path = os.getenv("VNC_AUTH33_SESSION_KEY_FILE")
    if path:
        Path(path).write_text(hashlib.sha256(session_key_64).digest()[:16].hex())


def cmd_auth33_codec(args: argparse.Namespace) -> int:
    if args.action == "parse-rsa1":
        env = RSA1Envelope.decode(clean_hex(args.hex_blob))
        print(
            json.dumps(
                {
                    "packet_version": env.packet_version,
                    "authtype": env.authtype,
                    "aux": env.aux,
                    "body_len": len(env.body),
                    "body_hex_prefix": fmt_hex(env.body),
                },
                indent=2,
            )
        )
        return 0
    if args.action == "build-rsa1":
        print(
            RSA1Envelope(
                args.packet_version,
                args.authtype,
                args.aux,
                clean_hex(args.body_hex) if args.body_hex else b"",
            ).encode().hex()
        )
        return 0
    if args.action == "parse-mech":
        parsed = parse_mech_blob(args.fmt, clean_hex(args.hex_blob))
        parsed["values"] = [
            {"hex": value.hex(), "len": len(value)} if isinstance(value, bytes) else value
            for value in parsed["values"]
        ]
        parsed["remaining"] = {"hex": parsed["remaining"].hex(), "len": len(parsed["remaining"])}
        print(json.dumps(parsed, indent=2))
        return 0
    print(build_mech_blob(args.fmt, json.loads(args.values_json)).hex())
    return 0


def load_blob(path: str) -> bytes:
    data = Path(path).read_bytes()
    if all((32 <= b <= 126) or b in (9, 10, 13) for b in data):
        return clean_hex(data.decode("utf-8", errors="ignore"))
    return data


def to_pem_spki(der: bytes) -> str:
    b64 = base64.encodebytes(der).decode("ascii").replace("\n", "")
    lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(lines) + "\n-----END PUBLIC KEY-----\n"


def cmd_extract_pubkey(args: argparse.Namespace) -> int:
    blob = load_blob(args.challenge)
    version = int.from_bytes(blob[0:2], "big")
    der_len = int.from_bytes(blob[2:6], "big")
    der = blob[6 : 6 + der_len]
    print(f"packet_version=0x{version:04x}")
    print(f"der_len={der_len}")
    print(f"trailing={len(blob) - (6 + der_len)}")
    if args.out_der:
        Path(args.out_der).write_bytes(der)
    if args.out_pem:
        Path(args.out_pem).write_text(to_pem_spki(der))
    if not args.out_der and not args.out_pem:
        sys.stdout.write(to_pem_spki(der))
    return 0


def cmd_generate_candidate(args: argparse.Namespace) -> int:
    chal = clean_hex(Path(args.challenge_hex_file).read_text())
    user = os.getenv("VNC_AUTH33_USER") or os.getenv("VNC_USER") or ""
    password = os.getenv("VNC_AUTH33_PASS") or os.getenv("VNC_PASS") or ""
    if not user or not password:
        raise SystemExit("missing VNC_AUTH33_USER/VNC_AUTH33_PASS or VNC_USER/VNC_PASS")
    cflag, N, g, salt, B, iters, option_string, pad_len = parse_challenge(chal)
    a_bytes, m1, session_key = srp_candidate(user, password, N, g, salt, B, iters, pad_len)
    out = build_packet2_candidate(a_bytes, m1, option_string)
    write_session_wrap_key(session_key)
    print(
        f"challenge: cflag={cflag} N={pad_len}B g={g} salt={len(salt)}B iters={iters} opt={option_string!r}",
        file=sys.stderr,
    )
    print(out.hex())
    return 0


def build_plaintext(username: str) -> bytes:
    user = username.encode("utf-8")
    total_len = len(user) + 7
    return struct.pack(">II", total_len, len(user)) + user + b"\x00\x00\x00"


def cmd_init_encrypt(args: argparse.Namespace) -> int:
    type0_reply = clean_hex(Path(args.type0_reply_hex_file).read_text())
    packet_version = struct.unpack(">H", type0_reply[0:2])[0]
    der_len = struct.unpack(">H", type0_reply[4:6])[0]
    der = type0_reply[6 : 6 + der_len]
    if packet_version != 1:
        raise SystemExit(f"unexpected packet version: {packet_version}")
    username = os.environ.get("VNC_AUTH33_USER", "")
    if not username:
        raise SystemExit("missing VNC_AUTH33_USER")
    with tempfile.TemporaryDirectory() as tmpdir:
        der_path = Path(tmpdir) / "key.der"
        plain_path = Path(tmpdir) / "plain.bin"
        cipher_path = Path(tmpdir) / "cipher.bin"
        der_path.write_bytes(der)
        plain_path.write_bytes(build_plaintext(username))
        subprocess.run(
            [
                "openssl",
                "pkeyutl",
                "-encrypt",
                "-pubin",
                "-keyform",
                "DER",
                "-inkey",
                str(der_path),
                "-pkeyopt",
                "rsa_padding_mode:pkcs1",
                "-in",
                str(plain_path),
                "-out",
                str(cipher_path),
            ],
            check=True,
        )
        sys.stdout.write(cipher_path.read_bytes().hex())
    return 0


def cmd_mutate_tail(args: argparse.Namespace) -> int:
    pkt = load_blob(args.packet)
    mode = args.mode
    body = bytearray(pkt)
    aux = struct.unpack_from(">H", body, 12)[0]
    tail_off = 14 + aux
    tail = body[tail_off:]
    if mode == "zero":
        body[tail_off:] = b"\x00" * len(tail)
    elif mode == "ones":
        body[tail_off:] = b"\xff" * len(tail)
    elif mode == "flip_first" and len(tail) >= 4:
        value = struct.unpack_from("<I", tail, 0)[0] ^ 0xFFFFFFFF
        struct.pack_into("<I", body, tail_off, value)
    print(bytes(body).hex())
    return 0


@dataclass
class Frame:
    number: int
    rel_time: str
    src: str
    sport: int
    dst: str
    dport: int
    tcp_len: int
    payload: bytes


def run_tshark_stream(pcap: str, stream: int, limit: int) -> list[Frame]:
    cmd = [
        tshark_bin(),
        "-r",
        pcap,
        "-Y",
        f"tcp.stream=={stream} && tcp.len>0",
        "-T",
        "fields",
        "-e",
        "frame.number",
        "-e",
        "frame.time_relative",
        "-e",
        "ip.src",
        "-e",
        "tcp.srcport",
        "-e",
        "ip.dst",
        "-e",
        "tcp.dstport",
        "-e",
        "tcp.len",
        "-e",
        "tcp.payload",
    ]
    out = subprocess.check_output(cmd, text=True)
    frames: list[Frame] = []
    for line in out.splitlines():
        parts = line.split("\t")
        if len(parts) != 8 or not parts[7]:
            continue
        frames.append(
            Frame(
                number=int(parts[0]),
                rel_time=parts[1],
                src=parts[2],
                sport=int(parts[3]),
                dst=parts[4],
                dport=int(parts[5]),
                tcp_len=int(parts[6]),
                payload=bytes.fromhex(parts[7]),
            )
        )
        if len(frames) >= limit:
            break
    return frames


def list_tcp_streams(pcap: str) -> list[int]:
    cmd = [
        tshark_bin(),
        "-r",
        pcap,
        "-Y",
        "tcp.len>0",
        "-T",
        "fields",
        "-e",
        "tcp.stream",
    ]
    out = subprocess.check_output(cmd, text=True)
    streams = {int(line.strip()) for line in out.splitlines() if line.strip().isdigit()}
    return sorted(streams)


def parse_serverinit(payload: bytes) -> dict[str, Any]:
    width, height = struct.unpack_from(">HH", payload, 0)
    pf = payload[4:20]
    name_len = struct.unpack_from(">I", payload, 20)[0]
    name_bytes = payload[24 : 24 + name_len]
    return {
        "width": width,
        "height": height,
        "pixel_format": {
            "bits_per_pixel": pf[0],
            "depth": pf[1],
            "big_endian_flag": pf[2],
            "true_color_flag": pf[3],
            "red_max": struct.unpack_from(">H", pf, 4)[0],
            "green_max": struct.unpack_from(">H", pf, 6)[0],
            "blue_max": struct.unpack_from(">H", pf, 8)[0],
            "red_shift": pf[10],
            "green_shift": pf[11],
            "blue_shift": pf[12],
        },
        "name_len": name_len,
        "name_utf8_lossy": name_bytes.decode("utf-8", errors="replace"),
    }


def decode_rsa1(payload: bytes, has_selection_byte: bool) -> dict[str, Any]:
    blob = payload[1:] if has_selection_byte else payload
    env = RSA1Envelope.decode(blob)
    result: dict[str, Any] = {
        "packet_version": env.packet_version,
        "authtype": env.authtype,
        "aux": env.aux,
        "body_len": len(env.body),
    }
    if has_selection_byte:
        result["security_selection"] = payload[0]
    if env.authtype == 2 and env.aux == 0x02AA and len(env.body) >= 4:
        inner_len = struct.unpack_from(">H", env.body, 2)[0]
        parsed = parse_mech_blob("%m%o%s%o", env.body[4 : 4 + inner_len])
        vals = parsed["values"]
        result["srp_client_step2"] = {
            "A_len": len(vals[0]),
            "M1_len": len(vals[1]),
            "options": vals[2],
            "field4_len": len(vals[3]),
        }
    return result


def decode_srp_server_step(payload: bytes) -> dict[str, Any]:
    body = payload[14:]
    out: dict[str, Any] = {}
    try:
        vals = parse_mech_blob("%c%m%m%o%m%q%s", body)["values"]
        out["srp_server_challenge"] = {
            "c": vals[0],
            "N_len": len(vals[1]),
            "g_hex": bytes(vals[2]).hex(),
            "salt_len": len(vals[3]),
            "B_len": len(vals[4]),
            "kdf_iterations": vals[5],
            "options": vals[6],
        }
    except Exception:
        pass
    return out


def classify_and_decode(frames: list[Frame]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for fr in frames:
        p = fr.payload
        row: dict[str, Any] = {
            "frame": fr.number,
            "time_rel": fr.rel_time,
            "src": f"{fr.src}:{fr.sport}",
            "dst": f"{fr.dst}:{fr.dport}",
            "tcp_len": fr.tcp_len,
            "payload_hex_prefix": p[:40].hex(),
            "type": "unknown",
        }
        if p.startswith(b"RFB "):
            row["type"] = "protocol_version"
            row["decoded"] = {"text": p.decode("ascii", errors="replace").rstrip("\n")}
        elif len(p) >= 2 and p[0] + 1 == len(p):
            row["type"] = "security_types"
            row["decoded"] = {"count": p[0], "types": list(p[1:])}
        elif len(p) >= 15 and p[0] == 0x21 and p[7:11] == b"RSA1":
            row["type"] = "rsa1_client_packet1"
            row["decoded"] = decode_rsa1(p, True)
        elif len(p) >= 14 and p[6:10] == b"RSA1":
            row["type"] = "rsa1_client_packet"
            row["decoded"] = decode_rsa1(p, False)
        elif len(p) == 4:
            row["type"] = "security_result"
            row["decoded"] = {"result_u32": int.from_bytes(p, "big")}
        elif len(p) == 1:
            row["type"] = "client_init"
            row["decoded"] = {"byte": p[0]}
        elif len(p) >= 24 and p[0] == 0x07:
            row["type"] = "server_init"
            row["decoded"] = parse_serverinit(p)
        elif len(p) >= 14 and p[:4] == struct.pack(">I", len(p) - 4):
            step = decode_srp_server_step(p)
            if step:
                row["type"] = "srp_server_challenge_packet"
                row["decoded"] = step
        out.append(row)
    return out


def render_markdown(decoded: list[dict[str, Any]]) -> str:
    lines = ["# Entrance/Auth Decode", ""]
    for row in decoded:
        lines.append(f"## Frame {row['frame']} ({row['type']})")
        lines.append(f"- Time: `{row['time_rel']}`")
        lines.append(f"- Path: `{row['src']} -> {row['dst']}`")
        lines.append("```json")
        lines.append(json.dumps(row.get("decoded", {}), indent=2))
        lines.append("```")
        lines.append("")
    return "\n".join(lines)


def summarize_rfb_stream(frames: list[Frame]) -> dict[str, Any] | None:
    summary: dict[str, Any] = {}
    security_idx: int | None = None
    seen_protocol = False
    protocol_server: tuple[str, int] | None = None
    protocol_client: tuple[str, int] | None = None
    for idx, frame in enumerate(frames):
        payload = frame.payload
        if payload.startswith(b"RFB "):
            seen_protocol = True
            summary["protocol_version"] = payload.decode("ascii", errors="replace").rstrip("\n")
            if protocol_server is None:
                protocol_server = (frame.src, frame.sport)
            else:
                protocol_client = (frame.src, frame.sport)
        elif len(payload) >= 2 and payload[0] + 1 == len(payload):
            if not seen_protocol:
                continue
            if protocol_server is not None and (frame.src, frame.sport) != protocol_server:
                continue
            summary["security_types"] = list(payload[1:])
            summary["security_types_count"] = payload[0]
            summary["security_types_frame"] = frame.number
            summary["security_types_src"] = f"{frame.src}:{frame.sport}"
            security_idx = idx
            break
    if "security_types" not in summary:
        return None

    selection: dict[str, Any] | None = None
    for frame in frames[(security_idx or 0) + 1 :]:
        if protocol_client is not None and (frame.src, frame.sport) != protocol_client:
            continue
        if not frame.payload:
            continue
        if frame.payload[0] not in summary["security_types"]:
            continue
        selection = {
            "frame": frame.number,
            "src": f"{frame.src}:{frame.sport}",
            "selected_type": frame.payload[0],
            "payload_len": len(frame.payload),
            "payload_hex": frame.payload.hex(),
        }
        break
    if selection:
        summary["selection"] = selection
    return summary


def render_rfb_security_types_markdown(rows: list[dict[str, Any]]) -> str:
    lines = ["# RFB Security Types", ""]
    if not rows:
        lines.append("No RFB security-type advertisements were detected.")
        lines.append("")
        return "\n".join(lines)
    for row in rows:
        lines.append(f"## tcp.stream {row['tcp_stream']}")
        lines.append(f"- Protocol version: `{row.get('protocol_version', 'unknown')}`")
        lines.append(f"- Server security types: `{row['security_types']}`")
        lines.append(f"- Advertised count byte: `{row['security_types_count']}`")
        lines.append(f"- Security-types frame: `{row['security_types_frame']}`")
        if "selection" in row:
            lines.append(f"- Client selected type: `{row['selection']['selected_type']}`")
            lines.append(f"- Client selection payload: `{row['selection']['payload_hex']}`")
            lines.append(f"- Client selection frame: `{row['selection']['frame']}`")
        lines.append("")
    return "\n".join(lines)


def cmd_decode_auth_entrance(args: argparse.Namespace) -> int:
    decoded = classify_and_decode(run_tshark_stream(args.pcap, args.stream, args.limit))
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(decoded, indent=2))
    if args.out_md:
        Path(args.out_md).write_text(render_markdown(decoded))
    for row in decoded:
        print(f"{row['frame']:>7}  {row['time_rel']:>10}  {row['type']}")
    return 0


def cmd_extract_rfb_security_types(args: argparse.Namespace) -> int:
    summaries: list[dict[str, Any]] = []
    for stream in list_tcp_streams(args.pcap):
        frames = run_tshark_stream(args.pcap, stream, args.limit)
        summary = summarize_rfb_stream(frames)
        if not summary:
            continue
        summary["tcp_stream"] = stream
        summaries.append(summary)
    if args.out_json:
        Path(args.out_json).write_text(json.dumps(summaries, indent=2))
    if args.out_md:
        Path(args.out_md).write_text(render_rfb_security_types_markdown(summaries))
    for row in summaries:
        selection = row.get("selection", {}).get("selected_type")
        selection_txt = f" selected={selection}" if selection is not None else ""
        print(f"tcp.stream {row['tcp_stream']}: offered={row['security_types']}{selection_txt}")
    return 0


def parse_hex_16(name: str, value: str) -> bytes:
    try:
        data = bytes.fromhex(value)
    except ValueError as exc:
        raise SystemExit(f"{name}: invalid hex: {exc}") from exc
    if len(data) != 16:
        raise SystemExit(f"{name}: expected 16 bytes, got {len(data)}")
    return data


def cmd_verify_transport_ecb(args: argparse.Namespace) -> int:
    try:
        from Crypto.Cipher import AES
    except ImportError as exc:
        raise SystemExit(f"missing pycryptodome: {exc}") from exc

    wrap_key = parse_hex_16("wrap-key", args.wrap_key)
    pt1 = parse_hex_16("pt1", args.pt1)
    ct1 = parse_hex_16("ct1", args.ct1)
    pt2 = parse_hex_16("pt2", args.pt2)
    ct2 = parse_hex_16("ct2", args.ct2)

    ecb1 = AES.new(wrap_key, AES.MODE_ECB).encrypt(pt1)
    ecb2 = AES.new(wrap_key, AES.MODE_ECB).encrypt(pt2)
    print(f"AES-128-ECB block1: {'MATCH' if ecb1 == ct1 else 'mismatch'}")
    print(f"AES-128-ECB block2: {'MATCH' if ecb2 == ct2 else 'mismatch'}")
    return 0 if ecb1 == ct1 and ecb2 == ct2 else 1


def recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise EOFError(f"short read: wanted {n}, got {len(buf)}")
        buf.extend(chunk)
    return bytes(buf)


def recv_with_idle(sock: socket.socket, first_len: int = 1, idle_timeout: float = 0.2, max_total: int = 4096) -> bytes:
    data = bytearray(recv_exact(sock, first_len))
    sock.setblocking(False)
    try:
        while len(data) < max_total:
            ready, _, _ = select.select([sock], [], [], idle_timeout)
            if not ready:
                break
            chunk = sock.recv(max_total - len(data))
            if not chunk:
                break
            data.extend(chunk)
    finally:
        sock.setblocking(True)
    return bytes(data)


def parse_auth_types_csv(text: str) -> list[int]:
    values: list[int] = []
    for item in text.split(","):
        item = item.strip()
        if not item:
            continue
        value = int(item, 0)
        if not 0 <= value <= 255:
            raise SystemExit(f"invalid auth type byte: {value}")
        values.append(value)
    if not values:
        raise SystemExit("empty auth type list")
    return values


def hex_preview(data: bytes, limit: int = 64) -> str:
    sample = data[:limit]
    out = binascii.hexlify(sample).decode("ascii")
    if len(data) > limit:
        out += "..."
    return out


class DirectionBuffer:
    def __init__(self, name: str, log_fh) -> None:
        self.name = name
        self.buf = bytearray()
        self.log_fh = log_fh

    def feed(self, data: bytes) -> None:
        if not data:
            return
        self.buf.extend(data)
        self.log_event("chunk", data)
        self._drain_messages()

    def log_event(self, kind: str, data: bytes, extra: dict[str, Any] | None = None) -> None:
        payload = {
            "ts": time.time(),
            "dir": self.name,
            "kind": kind,
            "len": len(data),
            "hex": binascii.hexlify(data).decode("ascii"),
            "preview": hex_preview(data),
        }
        if extra:
            payload.update(extra)
        self.log_fh.write(json.dumps(payload) + "\n")
        self.log_fh.flush()

    def _message_length(self, msg_type: int, buf: bytearray) -> int | None:
        if msg_type == 0:
            return 20
        if msg_type == 2:
            if len(buf) < 4:
                return None
            return 4 + int.from_bytes(buf[2:4], "big") * 4
        if msg_type == 3:
            return 10
        if msg_type == 4:
            return 8
        if msg_type == 5:
            return 6
        if msg_type in {0x12, 0x1D, 0x21}:
            if len(buf) < 4:
                return None
            return 4 + int.from_bytes(buf[2:4], "big")
        if msg_type == 6:
            if len(buf) < 8:
                return None
            return 8 + int.from_bytes(buf[4:8], "big")
        if msg_type == 0x09:
            return 10
        if msg_type == 0x15:
            return 4
        return None

    def _drain_messages(self) -> None:
        while self.buf:
            need = self._message_length(self.buf[0], self.buf)
            if need is None or len(self.buf) < need:
                return
            msg = bytes(self.buf[:need])
            del self.buf[:need]
            self.log_event("message", msg, {"msg_type": msg[0]})


def relay_phase(client: socket.socket, upstream: socket.socket, *, log_fh) -> None:
    selector = selectors.DefaultSelector()
    selector.register(client, selectors.EVENT_READ, data="c2s")
    selector.register(upstream, selectors.EVENT_READ, data="s2c")
    c_parser = DirectionBuffer("c2s", log_fh)
    s_parser = DirectionBuffer("s2c", log_fh)
    try:
        while True:
            for key, _ in selector.select(timeout=0.5):
                data = key.fileobj.recv(65536)
                if not data:
                    return
                if key.data == "c2s":
                    upstream.sendall(data)
                    c_parser.feed(data)
                else:
                    client.sendall(data)
                    s_parser.feed(data)
    finally:
        selector.close()


def cmd_proxy(args: argparse.Namespace) -> int:
    log_path = Path(args.log)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
        server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server.bind((args.listen_host, args.listen_port))
        server.listen(1)
        print(f"listening on {args.listen_host}:{args.listen_port}", flush=True)
        client, client_addr = server.accept()
        with client, socket.create_connection((args.upstream_host, args.upstream_port)) as upstream, log_path.open("w") as log_fh:
            client.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            log_fh.write(json.dumps({"ts": time.time(), "kind": "accept", "client_addr": client_addr}) + "\n")
            server_banner = recv_exact(upstream, 12)
            client.sendall(server_banner)
            client_banner = recv_exact(client, 12)
            upstream.sendall(client_banner)
            count = recv_exact(upstream, 1)[0]
            offered = recv_exact(upstream, count)
            advertised = list(offered) if not args.advertise_types else parse_auth_types_csv(args.advertise_types)
            client.sendall(bytes([len(advertised)]) + bytes(advertised))
            try:
                selection_blob = recv_with_idle(client, idle_timeout=args.selection_idle_timeout_ms / 1000.0)
            except EOFError:
                log_fh.write(
                    json.dumps(
                        {
                            "ts": time.time(),
                            "kind": "security_types",
                            "upstream_offered": list(offered),
                            "advertised_to_client": advertised,
                            "client_selection_blob_hex": "",
                            "client_selected_type": None,
                            "forwarded_to_upstream": None,
                            "client_closed_before_selection": True,
                        }
                    )
                    + "\n"
                )
                return 0
            selected_type = selection_blob[0]
            if args.force_selection is not None:
                upstream.sendall(bytes([args.force_selection]))
            elif selected_type in offered:
                upstream.sendall(selection_blob)
            log_fh.write(
                json.dumps(
                    {
                        "ts": time.time(),
                        "kind": "security_types",
                        "upstream_offered": list(offered),
                        "advertised_to_client": advertised,
                        "client_selection_blob_hex": selection_blob.hex(),
                        "client_selected_type": selected_type,
                        "forwarded_to_upstream": args.force_selection if args.force_selection is not None else (selected_type if selected_type in offered else None),
                    }
                )
                + "\n"
            )
            if selected_type not in offered and args.force_selection is None:
                return 0
            relay_phase(client, upstream, log_fh=log_fh)
    return 0


def load_keywords(path: Path | None, defaults: list[str]) -> list[str]:
    if not path:
        return defaults
    return [line.strip() for line in path.read_text().splitlines() if line.strip() and not line.startswith("#")]


def cmd_bn_extract(args: argparse.Namespace) -> int:
    try:
        import binaryninja as bn
    except ImportError as exc:
        raise SystemExit(f"binaryninja unavailable: {exc}") from exc
    keywords = load_keywords(Path(args.keywords_file) if args.keywords_file else None, ["high", "performance", "promode", "viewer", "udp", "tcp"])
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bv = bn.load(str(Path(args.binary).resolve()), update_analysis=True)
    if bv is None:
        raise SystemExit(f"could not load {args.binary}")
    bv.update_analysis_and_wait()
    rows = []
    for fn in bv.functions:
        name = fn.symbol.full_name if fn.symbol else f"sub_{fn.start:x}"
        low = name.lower()
        if any(k.lower() in low for k in keywords):
            rows.append({"function": name, "address": hex(fn.start)})
    csv_path = out_dir / f"{Path(args.binary).name.replace(' ', '_')}.bn.extract.csv"
    with csv_path.open("w", newline="") as fh:
        writer = csv.DictWriter(fh, fieldnames=["function", "address"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"Wrote {csv_path}")
    return 0


def cmd_bn_focus(args: argparse.Namespace) -> int:
    try:
        import binaryninja as bn
    except ImportError as exc:
        raise SystemExit(f"binaryninja unavailable: {exc}") from exc
    keywords = load_keywords(Path(args.keywords_file) if args.keywords_file else None, ["viewer", "session", "stream", "udp", "tcp", "promode"])
    out_dir = Path(args.out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    bv = bn.load(str(Path(args.binary).resolve()), update_analysis=True)
    if bv is None:
        raise SystemExit(f"could not load {args.binary}")
    bv.update_analysis_and_wait()
    focus = []
    for fn in bv.functions:
        name = fn.symbol.full_name if fn.symbol else f"sub_{fn.start:x}"
        if any(k in name.lower() for k in [kw.lower() for kw in keywords]):
            focus.append(name)
    out_path = out_dir / f"{Path(args.binary).name.replace(' ', '_')}.bn.focus.json"
    out_path.write_text(json.dumps({"binary": args.binary, "focus": focus[: args.max_focus]}, indent=2))
    print(f"Wrote {out_path}")
    return 0


def cmd_bn_batch(args: argparse.Namespace) -> int:
    targets = [line.strip() for line in Path(args.targets_file).read_text().splitlines() if line.strip() and not line.startswith("#")]
    for target in targets:
        subprocess.run(
            [
                sys.executable,
                str(SCRIPT_DIR / "screensharing_tools.py"),
                "bn-extract",
                "--binary",
                target,
                "--out-dir",
                args.output_dir,
                *([] if not args.keywords_file else ["--keywords-file", args.keywords_file]),
            ],
            check=True,
        )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Consolidated Screen Sharing research helpers")
    sub = parser.add_subparsers(dest="cmd", required=True)

    codec = sub.add_parser("auth33-codec", help="RSA1 and SRP mech blob helpers")
    codec_sub = codec.add_subparsers(dest="action", required=True)
    c1 = codec_sub.add_parser("parse-rsa1")
    c1.add_argument("hex_blob")
    c1.set_defaults(func=cmd_auth33_codec)
    c2 = codec_sub.add_parser("build-rsa1")
    c2.add_argument("--packet-version", type=lambda x: int(x, 0), default=0x0100)
    c2.add_argument("--authtype", type=lambda x: int(x, 0), default=0x0002)
    c2.add_argument("--aux", type=lambda x: int(x, 0), default=0x0100)
    c2.add_argument("--body-hex", default="")
    c2.set_defaults(func=cmd_auth33_codec)
    c3 = codec_sub.add_parser("parse-mech")
    c3.add_argument("--fmt", required=True)
    c3.add_argument("hex_blob")
    c3.set_defaults(func=cmd_auth33_codec)
    c4 = codec_sub.add_parser("build-mech")
    c4.add_argument("--fmt", required=True)
    c4.add_argument("values_json")
    c4.set_defaults(func=cmd_auth33_codec)

    extract = sub.add_parser("auth33-extract-pubkey")
    extract.add_argument("challenge")
    extract.add_argument("--out-der")
    extract.add_argument("--out-pem")
    extract.set_defaults(func=cmd_extract_pubkey)

    candidate = sub.add_parser("auth33-generate-candidate")
    candidate.add_argument("challenge_hex_file")
    candidate.set_defaults(func=cmd_generate_candidate)

    init_encrypt = sub.add_parser("auth33-init-encrypt")
    init_encrypt.add_argument("type0_reply_hex_file")
    init_encrypt.set_defaults(func=cmd_init_encrypt)

    mutate = sub.add_parser("auth33-mutate-tail")
    mutate.add_argument("packet")
    mutate.add_argument("--mode", choices=["baseline", "zero", "flip_first", "ones"], default="flip_first")
    mutate.set_defaults(func=cmd_mutate_tail)

    decode = sub.add_parser("decode-auth-entrance")
    decode.add_argument("--pcap", required=True)
    decode.add_argument("--stream", type=int, default=0)
    decode.add_argument("--limit", type=int, default=40)
    decode.add_argument("--out-json")
    decode.add_argument("--out-md")
    decode.set_defaults(func=cmd_decode_auth_entrance)

    rfb_types = sub.add_parser("extract-rfb-security-types")
    rfb_types.add_argument("--pcap", required=True)
    rfb_types.add_argument("--limit", type=int, default=20)
    rfb_types.add_argument("--out-json")
    rfb_types.add_argument("--out-md")
    rfb_types.set_defaults(func=cmd_extract_rfb_security_types)

    verify = sub.add_parser("verify-transport-ecb")
    verify.add_argument("--wrap-key", required=True)
    verify.add_argument("--pt1", default="a6ebf1420ebebc10c1aec82e22d7c15b")
    verify.add_argument("--ct1", default="910fea2564450b57fb3123ad3af0fe09")
    verify.add_argument("--pt2", default="92dd09fa1b27d7dc19c14f95ee003b2b")
    verify.add_argument("--ct2", default="d88bce9130cdfb8ec90dd9e0b6bf3982")
    verify.set_defaults(func=cmd_verify_transport_ecb)

    proxy = sub.add_parser("proxy")
    proxy.add_argument("--listen-host", default="127.0.0.1")
    proxy.add_argument("--listen-port", type=int, default=5901)
    proxy.add_argument("--upstream-host", default="127.0.0.1")
    proxy.add_argument("--upstream-port", type=int, default=5900)
    proxy.add_argument("--advertise-types", help="Comma-separated auth type bytes to advertise to the client")
    proxy.add_argument("--force-selection", type=lambda x: int(x, 0), help="Force a specific selection byte upstream instead of forwarding the client's blob")
    proxy.add_argument("--selection-idle-timeout-ms", type=int, default=200)
    proxy.add_argument("--log", required=True)
    proxy.set_defaults(func=cmd_proxy)

    bn_extract = sub.add_parser("bn-extract")
    bn_extract.add_argument("--binary", required=True)
    bn_extract.add_argument("--out-dir", required=True)
    bn_extract.add_argument("--keywords-file")
    bn_extract.set_defaults(func=cmd_bn_extract)

    bn_focus = sub.add_parser("bn-focus")
    bn_focus.add_argument("--binary", required=True)
    bn_focus.add_argument("--out-dir", required=True)
    bn_focus.add_argument("--keywords-file")
    bn_focus.add_argument("--max-focus", type=int, default=400)
    bn_focus.set_defaults(func=cmd_bn_focus)

    bn_batch = sub.add_parser("bn-batch")
    bn_batch.add_argument("targets_file")
    bn_batch.add_argument("output_dir")
    bn_batch.add_argument("keywords_file", nargs="?")
    bn_batch.set_defaults(func=cmd_bn_batch)

    return parser


def main() -> int:
    if len(sys.argv) == 2 and Path(sys.argv[1]).exists():
        sys.argv.insert(1, "auth33-generate-candidate")
    parser = build_parser()
    args = parser.parse_args()
    try:
        return int(args.func(args))
    except BrokenPipeError:
        return 0
    except (ValueError, struct.error, binascii.Error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
