#!/usr/bin/env python3
"""Real TCP benchmark for RIA-QKD."""

from __future__ import annotations

import argparse
import datetime
import hashlib
import json
import math
import os
import platform
import socket
import statistics
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import oqs

from common.crypto_primitives import HKDFWrapper, HMACWrapper, generate_nonce, hash_transcript


KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"
N_WARMUP = 20
PROTO_ID = b"RIA-QKD-v2"
SERVER_ID = b"RIA-QKD-GW"


def read_bytes(path: str) -> bytes:
    return Path(path).read_bytes()


def load_anchor(path: str) -> bytes:
    return read_bytes(path) if path else hashlib.sha256(PROTO_ID + b"-enrolled-ak").digest()


def send_msg(sock, data):
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_msg(sock):
    raw = b""
    while len(raw) < 4:
        chunk = sock.recv(4 - len(raw))
        if not chunk:
            raise ConnectionError("disconnected")
        raw += chunk
    n = struct.unpack(">I", raw)[0]
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            raise ConnectionError("disconnected")
        data += chunk
    return data


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, math.ceil(p * len(sorted_values)) - 1))
    return sorted_values[idx]


def runtime_metadata(role: str):
    try:
        import oqs
        liboqs_version = oqs.oqs_python_version()
    except Exception:
        liboqs_version = "unavailable"
    return {
        "role": role,
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "liboqs_version": liboqs_version,
        "argv": list(sys.argv),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def run_server(port, n_total, client_static_pk_path: str, server_sig_pk_out: str = "", anchor_path: str = "", output_path: str = ""):
    with oqs.Signature(SIG_ALG) as signer:
        srv_pk = signer.generate_keypair()
        srv_sk_bytes = signer.export_secret_key()
    if server_sig_pk_out:
        Path(server_sig_pk_out).write_bytes(srv_pk)
    cli_static_pk = read_bytes(client_static_pk_path)
    anchor = load_anchor(anchor_path)
    print(f"[Server] Listening on 0.0.0.0:{port}, expecting {n_total} handshakes")
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"[Server] Client connected from {addr}")
    completed = 0
    t_start = time.perf_counter()
    while completed < n_total:
        m1 = recv_msg(conn)
        cli_id_len = struct.unpack(">H", m1[:2])[0]
        cli_id = m1[2:2 + cli_id_len]
        epoch = m1[2 + cli_id_len:2 + cli_id_len + 4]
        r_c = m1[2 + cli_id_len + 4:2 + cli_id_len + 4 + 32]
        cli_eph_pk_len = struct.unpack(">H", m1[2 + cli_id_len + 4 + 32:2 + cli_id_len + 4 + 34])[0]
        off = 2 + cli_id_len + 4 + 34
        cli_eph_pk = m1[off:off + cli_eph_pk_len]
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ct1, ss1 = kem.encap_secret(cli_static_pk)
            ct2, ss2 = kem.encap_secret(cli_eph_pk)
            srv_eph_pk_bytes = kem.generate_keypair()
            srv_eph_sk_bytes = kem.export_secret_key()
        transcript = hash_transcript(b"RIA-QKD-V1-Server", SERVER_ID + cli_id + epoch + r_c + cli_eph_pk + srv_eph_pk_bytes + ct1 + ct2)
        with oqs.Signature(SIG_ALG, srv_sk_bytes) as signer:
            sig = signer.sign(transcript)
        m2 = struct.pack(">H", len(srv_eph_pk_bytes)) + srv_eph_pk_bytes + struct.pack(">H", len(ct1)) + ct1 + struct.pack(">H", len(ct2)) + ct2 + struct.pack(">H", len(sig)) + sig
        send_msg(conn, m2)
        m3 = recv_msg(conn)
        if m3 == b"FAIL":
            continue
        ct3_len = struct.unpack(">H", m3[:2])[0]
        ct3 = m3[2:2 + ct3_len]
        t_c = m3[2 + ct3_len:]
        with oqs.KeyEncapsulation(KEM_ALG, srv_eph_sk_bytes) as kem:
            ss3 = kem.decap_secret(ct3)
        tr = hash_transcript(m1 + m2 + ct3)
        prk = HKDFWrapper.extract(anchor, ss1 + ss2 + ss3)
        k_fin = HKDFWrapper.expand(prk, b"finished" + tr)
        if not HMACWrapper.verify(k_fin, tr + b"CL_FIN", t_c):
            send_msg(conn, b"FAIL")
            continue
        tr2 = hash_transcript(tr + m3)
        send_msg(conn, HMACWrapper.compute(k_fin, tr2 + b"SV_FIN"))
        completed += 1
    wall_time = time.perf_counter() - t_start
    result = {
        "protocol": "RIA-QKD",
        "role": "server",
        "expected_handshakes": n_total,
        "completed": completed,
        "wall_time_s": round(wall_time, 3),
        "throughput_hs": round(completed / wall_time, 2) if wall_time else 0.0,
        "metadata": runtime_metadata("server"),
    }
    conn.close()
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


def run_client(server_ip, port, n, client_static_sk_path: str, server_sig_pk_path: str, anchor_path: str = "", label: str = "default", output_path: str | None = None):
    client_static_sk = read_bytes(client_static_sk_path)
    server_sig_pk = read_bytes(server_sig_pk_path)
    anchor = load_anchor(anchor_path)
    s = socket.create_connection((server_ip, port))
    cid = label.encode("utf-8")
    latencies = []
    errors = 0
    for i in range(n + N_WARMUP):
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            pk_eph = kem.generate_keypair()
            sk_eph = kem.export_secret_key()
        rc = generate_nonce(32)
        m1 = struct.pack(">H", len(cid)) + cid + b"\x00\x00\x00\x01" + rc + struct.pack(">H", len(pk_eph)) + pk_eph
        start = time.perf_counter_ns()
        send_msg(s, m1)
        m2 = recv_msg(s)
        off = 0
        srv_eph_pk_len = struct.unpack(">H", m2[off:off + 2])[0]
        off += 2
        srv_eph_pk = m2[off:off + srv_eph_pk_len]
        off += srv_eph_pk_len
        ct1_len = struct.unpack(">H", m2[off:off + 2])[0]
        off += 2
        ct1 = m2[off:off + ct1_len]
        off += ct1_len
        ct2_len = struct.unpack(">H", m2[off:off + 2])[0]
        off += 2
        ct2 = m2[off:off + ct2_len]
        off += ct2_len
        sig_len = struct.unpack(">H", m2[off:off + 2])[0]
        off += 2
        sig = m2[off:off + sig_len]
        transcript = hash_transcript(b"RIA-QKD-V1-Server", SERVER_ID + cid + b"\x00\x00\x00\x01" + rc + pk_eph + srv_eph_pk + ct1 + ct2)
        if not oqs.Signature(SIG_ALG).verify(transcript, sig, server_sig_pk):
            send_msg(s, b"FAIL")
            errors += 1
            continue
        with oqs.KeyEncapsulation(KEM_ALG, client_static_sk) as kem:
            ss1 = kem.decap_secret(ct1)
        with oqs.KeyEncapsulation(KEM_ALG, sk_eph) as kem:
            ss2 = kem.decap_secret(ct2)
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ct3, ss3 = kem.encap_secret(srv_eph_pk)
        tr = hash_transcript(m1 + m2 + ct3)
        prk = HKDFWrapper.extract(anchor, ss1 + ss2 + ss3)
        k_fin = HKDFWrapper.expand(prk, b"finished" + tr)
        t_c = HMACWrapper.compute(k_fin, tr + b"CL_FIN")
        send_msg(s, struct.pack(">H", len(ct3)) + ct3 + t_c)
        m4 = recv_msg(s)
        if m4 == b"FAIL":
            errors += 1
            continue
        tr2 = hash_transcript(tr + struct.pack(">H", len(ct3)) + ct3 + t_c)
        if not HMACWrapper.verify(k_fin, tr2 + b"SV_FIN", m4):
            errors += 1
            continue
        if i >= N_WARMUP:
            latencies.append((time.perf_counter_ns() - start) / 1e6)
    latencies.sort()
    result = {
        "protocol": "RIA-QKD",
        "n_warmup": N_WARMUP,
        "n_measured": len(latencies),
        "n_errors": errors,
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "samples": [round(value, 6) for value in latencies],
        },
        "throughput_hs": round(1000.0 / statistics.mean(latencies), 2),
        "metadata": runtime_metadata("client"),
    }
    out = Path(output_path or "out/network_bench_1000.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["server", "client"], required=True)
    ap.add_argument("--server-ip", default="")
    ap.add_argument("--port", type=int, default=9999)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--label", default="default")
    ap.add_argument("--output", default="")
    ap.add_argument("--client-static-pk", default="", help="server mode: path to enrolled client static KEM public key")
    ap.add_argument("--client-static-sk", default="", help="client mode: path to client static KEM secret key")
    ap.add_argument("--server-sig-pk", default="", help="client mode: path to server signature public key")
    ap.add_argument("--server-sig-pk-out", default="", help="server mode: where to write server signature public key")
    ap.add_argument("--anchor", default="", help="path to 32-byte anchor")
    args = ap.parse_args()
    if args.mode == "server":
        if not args.client_static_pk:
            raise SystemExit("--client-static-pk is required in server mode")
        run_server(args.port, args.n + N_WARMUP, args.client_static_pk, server_sig_pk_out=args.server_sig_pk_out, anchor_path=args.anchor, output_path=args.output)
    else:
        if not args.server_ip:
            raise SystemExit("--server-ip is required in client mode")
        if not args.client_static_sk:
            raise SystemExit("--client-static-sk is required in client mode")
        if not args.server_sig_pk:
            raise SystemExit("--server-sig-pk is required in client mode")
        run_client(args.server_ip, args.port, args.n, args.client_static_sk, args.server_sig_pk, anchor_path=args.anchor, label=args.label, output_path=args.output or None)
