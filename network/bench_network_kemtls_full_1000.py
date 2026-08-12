#!/usr/bin/env python3
"""KEMTLS-style server-auth-only contextual reference benchmark.

This intentionally lightweight reference has no client static KEM credential.
It is useful for latency context only, not as a mutual-authentication baseline.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import hmac
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

try:
    import oqs
except ImportError:
    print("ERROR: liboqs-python not available. Install with: pip install liboqs-python")
    sys.exit(1)


KEM_ALG = "ML-KEM-512"
PROTO_ID = b"KEMTLS-full-v1"
N_WARMUP = 20


def runtime_metadata(role: str):
    return {
        "role": role,
        "hostname": socket.gethostname(),
        "python": platform.python_version(),
        "argv": list(sys.argv),
        "timestamp_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
    }


def hkdf_extract(salt, ikm):
    return hmac.new(salt, ikm, hashlib.sha256).digest()


def hkdf_expand(prk, info, length=32):
    t = b""
    okm = b""
    i = 1
    while len(okm) < length:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest()
        okm += t
        i += 1
    return okm[:length]


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


def credential_fingerprint(credential_blob):
    return hashlib.sha256(credential_blob).hexdigest()


def encode_server_credential(server_pk):
    subject = b"CN=KEMTLS-Gateway-001"
    issuer = b"CN=Local-Test-CA"
    alg = KEM_ALG.encode()
    return (
        PROTO_ID
        + struct.pack(">H", len(subject)) + subject
        + struct.pack(">H", len(issuer)) + issuer
        + struct.pack(">H", len(alg)) + alg
        + struct.pack(">H", len(server_pk)) + server_pk
    )


def decode_server_credential(credential_blob):
    off = 0
    proto = credential_blob[off:off + len(PROTO_ID)]
    off += len(PROTO_ID)
    if proto != PROTO_ID:
        raise ValueError("unexpected protocol identifier in credential")

    subject_len = struct.unpack(">H", credential_blob[off:off + 2])[0]
    off += 2
    subject = credential_blob[off:off + subject_len]
    off += subject_len

    issuer_len = struct.unpack(">H", credential_blob[off:off + 2])[0]
    off += 2
    issuer = credential_blob[off:off + issuer_len]
    off += issuer_len

    alg_len = struct.unpack(">H", credential_blob[off:off + 2])[0]
    off += 2
    alg = credential_blob[off:off + alg_len]
    off += alg_len

    pk_len = struct.unpack(">H", credential_blob[off:off + 2])[0]
    off += 2
    server_pk = credential_blob[off:off + pk_len]

    return {
        "subject": subject.decode(),
        "issuer": issuer.decode(),
        "alg": alg.decode(),
        "server_pk": server_pk,
    }


def write_trust_store(path, credential_blob):
    payload = {
        "protocol": PROTO_ID.decode(),
        "credential_sha256": credential_fingerprint(credential_blob),
        "credential_b64": base64.b64encode(credential_blob).decode(),
    }
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload, indent=2))


def load_trust_store(path):
    with open(path, "r") as f:
        data = json.load(f)
    blob = base64.b64decode(data["credential_b64"])
    return {
        "credential_sha256": data["credential_sha256"],
        "credential_blob": blob,
    }


def run_server(port, n_total, trust_store_out: str = "", output_path: str = ""):
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        srv_pk = kem.generate_keypair()
        srv_sk = kem.export_secret_key()

    credential_blob = encode_server_credential(srv_pk)
    if trust_store_out:
        write_trust_store(trust_store_out, credential_blob)

    print(f"[Server] Listening on 0.0.0.0:{port}, expecting {n_total} handshakes")
    print(f"[Server] Credential SHA256: {credential_fingerprint(credential_blob)}")

    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(1)
    conn, addr = srv.accept()
    print(f"[Server] Client connected from {addr}")

    completed = 0
    t_start = time.perf_counter()

    while completed < n_total:
        try:
            m1 = recv_msg(conn)
            cli_id_len = struct.unpack(">H", m1[:2])[0]
            cli_id = m1[2:2 + cli_id_len]
            off = 2 + cli_id_len
            r_c = m1[off:off + 32]
            off += 32
            cli_eph_pk_len = struct.unpack(">H", m1[off:off + 2])[0]
            off += 2
            cli_eph_pk = m1[off:off + cli_eph_pk_len]

            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ct_e, ss_e = kem.encap_secret(cli_eph_pk)

            r_s = os.urandom(32)
            m2 = (
                struct.pack(">H", len(credential_blob)) + credential_blob +
                r_s +
                struct.pack(">H", len(ct_e)) + ct_e
            )
            send_msg(conn, m2)

            transcript = hashlib.sha256(PROTO_ID + m1 + m2).digest()
            m3 = recv_msg(conn)
            ct_auth_len = struct.unpack(">H", m3[:2])[0]
            ct_auth = m3[2:2 + ct_auth_len]
            t_c = m3[2 + ct_auth_len:]

            with oqs.KeyEncapsulation(KEM_ALG, srv_sk) as kem:
                ss_auth = kem.decap_secret(ct_auth)

            prk = hkdf_extract(b"KEMTLS-full-v1-salt", ss_e + ss_auth)
            ms = hkdf_expand(prk, b"KEMTLS-full-v1-session" + transcript)
            expected_t_c = hmac.new(ms, b"CL_FIN", hashlib.sha256).digest()
            if not hmac.compare_digest(t_c, expected_t_c):
                send_msg(conn, b"FAIL")
                continue

            t_s = hmac.new(ms, b"SV_FIN", hashlib.sha256).digest()
            send_msg(conn, t_s)
            completed += 1
        except Exception as e:
            print(f"[Server] Error at handshake {completed}: {e}")
            break

    elapsed = time.perf_counter() - t_start
    result = {
        "protocol": "KEMTLS-style-server-auth-only",
        "role": "server",
        "expected_handshakes": n_total,
        "completed": completed,
        "wall_time_s": round(elapsed, 3),
        "throughput_hs": round(completed / elapsed, 2) if elapsed else 0.0,
        "metadata": runtime_metadata("server"),
    }
    if output_path:
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n")
    print(f"[Server] {completed}/{n_total} handshakes in {elapsed:.2f}s = {completed/elapsed:.1f} hs/s")
    print(json.dumps(result, indent=2))
    conn.close()
    srv.close()


def run_client(server_ip, port, n_total, trust_store_path, label="default", output_path=None):
    trust = load_trust_store(trust_store_path)
    expected_fp = trust["credential_sha256"]
    expected_credential_blob = trust["credential_blob"]

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((server_ip, port))
    print(f"[Client] Connecting to {server_ip}:{port}, {n_total} handshakes ({N_WARMUP} warmup)")

    latencies_ns = []
    errors = 0
    payload_sizes = None

    for i in range(N_WARMUP + n_total):
        is_warmup = i < N_WARMUP
        try:
            with oqs.KeyEncapsulation(KEM_ALG) as kem_eph:
                cli_eph_pk = kem_eph.generate_keypair()
                cli_eph_sk = kem_eph.export_secret_key()

            cli_id = b"KEMTLS-Full-Client-001"
            r_c = os.urandom(32)
            m1 = (
                struct.pack(">H", len(cli_id)) + cli_id +
                r_c +
                struct.pack(">H", len(cli_eph_pk)) + cli_eph_pk
            )

            t0 = time.perf_counter_ns()
            send_msg(sock, m1)

            m2 = recv_msg(sock)
            off = 0
            cred_len = struct.unpack(">H", m2[off:off + 2])[0]
            off += 2
            credential_blob = m2[off:off + cred_len]
            off += cred_len
            r_s = m2[off:off + 32]
            off += 32
            ct_e_len = struct.unpack(">H", m2[off:off + 2])[0]
            off += 2
            ct_e = m2[off:off + ct_e_len]

            fp = credential_fingerprint(credential_blob)
            if fp != expected_fp or credential_blob != expected_credential_blob:
                raise ValueError("server credential fingerprint mismatch")

            cred = decode_server_credential(credential_blob)
            if cred["alg"] != KEM_ALG:
                raise ValueError("unexpected KEM algorithm in server credential")

            transcript = hashlib.sha256(PROTO_ID + m1 + m2).digest()

            with oqs.KeyEncapsulation(KEM_ALG, cli_eph_sk) as kem:
                ss_e = kem.decap_secret(ct_e)

            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ct_auth, ss_auth = kem.encap_secret(cred["server_pk"])

            prk = hkdf_extract(b"KEMTLS-full-v1-salt", ss_e + ss_auth)
            ms = hkdf_expand(prk, b"KEMTLS-full-v1-session" + transcript)
            t_c = hmac.new(ms, b"CL_FIN", hashlib.sha256).digest()
            m3 = struct.pack(">H", len(ct_auth)) + ct_auth + t_c
            send_msg(sock, m3)

            m4 = recv_msg(sock)
            t1 = time.perf_counter_ns()
            expected_t_s = hmac.new(ms, b"SV_FIN", hashlib.sha256).digest()
            if not hmac.compare_digest(m4, expected_t_s):
                errors += 1
                continue

            if payload_sizes is None:
                payload_sizes = {
                    "client_hello_bytes": len(m1),
                    "server_credential_bytes": len(credential_blob),
                    "server_hello_bytes": len(m2),
                    "client_auth_payload_bytes": len(m3),
                    "server_finished_bytes": len(m4),
                    "total_application_bytes": len(m1) + len(m2) + len(m3) + len(m4),
                }

            if not is_warmup:
                latencies_ns.append(t1 - t0)
        except Exception as e:
            print(f"[Client] Error at iteration {i}: {e}")
            errors += 1

    sock.close()

    if not latencies_ns:
        print("[Client] No successful measurements")
        return

    n = len(latencies_ns)
    mean_ms = statistics.mean(latencies_ns) / 1e6
    std_ms = statistics.stdev(latencies_ns) / 1e6 if n > 1 else 0
    ci95_ms = 1.96 * std_ms / math.sqrt(n)
    min_ms = min(latencies_ns) / 1e6
    max_ms = max(latencies_ns) / 1e6
    sorted_latencies = sorted(latencies_ns)
    median_ms = statistics.median(latencies_ns) / 1e6
    p95_ms = percentile(sorted_latencies, 0.95) / 1e6
    p99_ms = percentile(sorted_latencies, 0.99) / 1e6

    result = {
        "protocol": "KEMTLS-style-server-auth-only",
        "label": label,
        "n_warmup": N_WARMUP,
        "n_measured": n,
        "n_errors": errors,
        "server": server_ip,
        "port": port,
        "trust_model": "pinned-hash credential store",
        "latency_ms": {
            "mean": round(mean_ms, 3),
            "stddev": round(std_ms, 3),
            "ci95": round(ci95_ms, 3),
            "min": round(min_ms, 3),
            "max": round(max_ms, 3),
            "median": round(median_ms, 3),
            "p95": round(p95_ms, 3),
            "p99": round(p99_ms, 3),
            "samples": [round(value / 1e6, 6) for value in sorted_latencies],
        },
        "throughput_hs": round(1000.0 / mean_ms, 2),
        "payload_bytes": payload_sizes,
        "metadata": runtime_metadata("client"),
    }
    print(json.dumps(result, indent=2))

    out = Path(output_path or "out/network_kemtls_full_1000.json")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(f"[Client] Results saved to {out}")


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--mode", choices=["server", "client"], required=True)
    ap.add_argument("--server-ip", default="")
    ap.add_argument("--port", type=int, default=9994)
    ap.add_argument("--n", type=int, default=1000)
    ap.add_argument("--label", default="default")
    ap.add_argument("--output", default="")
    ap.add_argument("--trust-store", default="")
    ap.add_argument("--trust-store-out", default="")
    ap.add_argument("--server-output", default="out/network_kemtls_full_1000_server.json")
    args = ap.parse_args()

    if args.mode == "server":
        run_server(args.port, args.n + N_WARMUP, args.trust_store_out, args.server_output)
    else:
        if not args.server_ip:
            raise SystemExit("--server-ip is required in client mode")
        if not args.trust_store:
            raise SystemExit("--trust-store is required in client mode")
        run_client(args.server_ip, args.port, args.n, args.trust_store, label=args.label, output_path=args.output or None)
