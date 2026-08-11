#!/usr/bin/env python3
"""Concurrent RIA-QKD network benchmark."""

from __future__ import annotations

import argparse
import hashlib
import hmac
import json
import math
import multiprocessing as mp
import os
import socket
import statistics
import struct
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import oqs

from bench_network_1000 import KEM_ALG, SIG_ALG, recv_msg, runtime_metadata, send_msg


EPOCH = b"\x00\x00\x00\x01"
SERVER_ID = b"RIA-QKD-GW"
ROOT = Path(__file__).resolve().parent
N_WARMUP = 5


def percentile(sorted_values, p):
    if not sorted_values:
        return 0.0
    idx = max(0, min(len(sorted_values) - 1, math.ceil(p * len(sorted_values)) - 1))
    return sorted_values[idx]


class ServerContext:
    def __init__(self):
        with oqs.Signature(SIG_ALG) as signer:
            self.srv_pk = signer.generate_keypair()
            self.srv_sk = signer.export_secret_key()
        self.enrolled = {}


def parse_enrollment(m: bytes):
    if not m.startswith(b"ENR"):
        raise ValueError("expected enrollment")
    off = 3
    cid_len = struct.unpack(">H", m[off:off + 2])[0]
    off += 2
    cid = m[off:off + cid_len]
    off += cid_len
    pk_len = struct.unpack(">H", m[off:off + 2])[0]
    off += 2
    pk = m[off:off + pk_len]
    return cid, pk


def server_worker(conn: socket.socket, hs_per_client: int, ctx: ServerContext, result_list: list[float], provisioning_dir: str):
    enr = recv_msg(conn)
    cid, pk_static = parse_enrollment(enr)
    ctx.enrolled[cid] = pk_static
    anchor_path = Path(provisioning_dir) / f"{cid.decode('utf-8')}_anchor.bin"
    if not anchor_path.is_file():
        raise FileNotFoundError(f"missing provisioned anchor: {anchor_path}")
    anchor = anchor_path.read_bytes()
    send_msg(conn, ctx.srv_pk)
    completed = 0
    while completed < hs_per_client:
        start = time.perf_counter_ns()
        try:
            m1 = recv_msg(conn)
            cli_id_len = struct.unpack(">H", m1[:2])[0]
            cli_id = m1[2:2 + cli_id_len]
            epoch = m1[2 + cli_id_len:2 + cli_id_len + 4]
            r_c = m1[2 + cli_id_len + 4:2 + cli_id_len + 4 + 32]
            cli_eph_pk_len = struct.unpack(">H", m1[2 + cli_id_len + 4 + 32:2 + cli_id_len + 4 + 34])[0]
            off = 2 + cli_id_len + 4 + 34
            cli_eph_pk = m1[off:off + cli_eph_pk_len]
            cli_static_pk = ctx.enrolled.get(cli_id)
            if cli_static_pk is None:
                send_msg(conn, b"FAIL")
                continue
            with oqs.KeyEncapsulation(KEM_ALG) as kem:
                ct1, ss1 = kem.encap_secret(cli_static_pk)
                ct2, ss2 = kem.encap_secret(cli_eph_pk)
                srv_eph_pk = kem.generate_keypair()
                srv_eph_sk = kem.export_secret_key()
            transcript = hashlib.sha256(b"RIA-QKD-V1-Server" + SERVER_ID + cli_id + epoch + r_c + srv_eph_pk + ct1 + ct2).digest()
            with oqs.Signature(SIG_ALG, ctx.srv_sk) as signer:
                sig = signer.sign(transcript)
            m2 = struct.pack(">H", len(srv_eph_pk)) + srv_eph_pk + struct.pack(">H", len(ct1)) + ct1 + struct.pack(">H", len(ct2)) + ct2 + struct.pack(">H", len(sig)) + sig
            send_msg(conn, m2)
            m3 = recv_msg(conn)
            ct3_len = struct.unpack(">H", m3[:2])[0]
            ct3 = m3[2:2 + ct3_len]
            t_c = m3[2 + ct3_len:]
            with oqs.KeyEncapsulation(KEM_ALG, srv_eph_sk) as kem:
                ss3 = kem.decap_secret(ct3)
            tr = hashlib.sha256(m1 + m2 + ct3).digest()
            prk = hmac.new(anchor, ss1 + ss2 + ss3, hashlib.sha256).digest()
            k_fin = hmac.new(prk, b"finished" + tr + b"\x01", hashlib.sha256).digest()
            expected = hmac.new(k_fin, tr + b"CL_FIN", hashlib.sha256).digest()
            if not hmac.compare_digest(t_c, expected):
                send_msg(conn, b"FAIL")
                continue
            tr2 = hashlib.sha256(tr + m3).digest()
            send_msg(conn, hmac.new(k_fin, tr2 + b"SV_FIN", hashlib.sha256).digest())
            completed += 1
            result_list.append((time.perf_counter_ns() - start) / 1e6)
        except Exception:
            break
    conn.close()


def run_server(port: int, clients: int, hs_per_client: int, provisioning_dir: str, output_path: str):
    ctx = ServerContext()
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("0.0.0.0", port))
    srv.listen(clients)
    wall_start = time.perf_counter()
    manager = mp.Manager()
    result_list = manager.list()
    procs = []
    for _ in range(clients):
        conn, _ = srv.accept()
        proc = mp.Process(target=server_worker, args=(conn, hs_per_client + N_WARMUP, ctx, result_list, provisioning_dir))
        proc.start()
        procs.append(proc)
    for proc in procs:
        proc.join()
    wall = time.perf_counter() - wall_start
    latencies = sorted(list(result_list))
    if not latencies:
        result = {"protocol": "RIA-QKD", "role": "server", "n_errors": clients * hs_per_client, "throughput_hs": 0.0, "metadata": runtime_metadata("server")}
        out = Path(output_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(result, indent=2) + "\n")
        print(json.dumps(result, indent=2))
        return
    result = {
        "protocol": "RIA-QKD",
        "clients": clients,
        "hs_per_client": hs_per_client,
        "n_warmup": N_WARMUP,
        "n_measured": len(latencies),
        "n_errors": 0,
        "latency_ms": {
            "mean": round(statistics.mean(latencies), 3),
            "median": round(statistics.median(latencies), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "samples": [round(value, 6) for value in latencies],
        },
        "throughput_hs": round(len(latencies) / wall, 2),
        "role": "server",
        "metadata": runtime_metadata("server"),
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


def client_worker(server_ip: str, port: int, hs_per_client: int, client_index: int, provisioning_dir: str, q: mp.Queue):
    client_id = f"client-{client_index}".encode()
    material_dir = Path(provisioning_dir)
    client_static_sk = (material_dir / f"client-{client_index}_static_sk.bin").read_bytes()
    client_static_pk = (material_dir / f"client-{client_index}_static_pk.bin").read_bytes()
    anchor = (material_dir / f"client-{client_index}_anchor.bin").read_bytes()
    s = socket.create_connection((server_ip, port))
    enr = b"ENR" + struct.pack(">H", len(client_id)) + client_id + struct.pack(">H", len(client_static_pk)) + client_static_pk
    send_msg(s, enr)
    server_sig_pk = recv_msg(s)
    latencies = []
    errors = 0
    for i in range(hs_per_client + N_WARMUP):
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            pk_eph = kem.generate_keypair()
            sk_eph = kem.export_secret_key()
        rc = os.urandom(32)
        m1 = struct.pack(">H", len(client_id)) + client_id + EPOCH + rc + struct.pack(">H", len(pk_eph)) + pk_eph
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
        transcript = hashlib.sha256(b"RIA-QKD-V1-Server" + SERVER_ID + client_id + EPOCH + rc + srv_eph_pk + ct1 + ct2).digest()
        if not oqs.Signature(SIG_ALG).verify(transcript, sig, server_sig_pk):
            errors += 1
            continue
        with oqs.KeyEncapsulation(KEM_ALG, client_static_sk) as kem:
            ss1 = kem.decap_secret(ct1)
        with oqs.KeyEncapsulation(KEM_ALG, sk_eph) as kem:
            ss2 = kem.decap_secret(ct2)
        with oqs.KeyEncapsulation(KEM_ALG) as kem:
            ct3, ss3 = kem.encap_secret(srv_eph_pk)
        tr = hashlib.sha256(m1 + m2 + ct3).digest()
        prk = hmac.new(anchor, ss1 + ss2 + ss3, hashlib.sha256).digest()
        k_fin = hmac.new(prk, b"finished" + tr + b"\x01", hashlib.sha256).digest()
        t_c = hmac.new(k_fin, tr + b"CL_FIN", hashlib.sha256).digest()
        send_msg(s, struct.pack(">H", len(ct3)) + ct3 + t_c)
        m4 = recv_msg(s)
        tr2 = hashlib.sha256(tr + struct.pack(">H", len(ct3)) + ct3 + t_c).digest()
        expected_t_s = hmac.new(k_fin, tr2 + b"SV_FIN", hashlib.sha256).digest()
        if not hmac.compare_digest(m4, expected_t_s):
            errors += 1
            continue
        if i >= N_WARMUP:
            latencies.append((time.perf_counter_ns() - start) / 1e6)
    q.put({"latencies_ms": latencies, "errors": errors})


def run_client(server_ip: str, port: int, clients: int, hs_per_client: int, provisioning_dir: str, output_path: str):
    manager = mp.Manager()
    q = manager.Queue()
    procs = []
    start = time.perf_counter_ns()
    for i in range(clients):
        p = mp.Process(target=client_worker, args=(server_ip, port, hs_per_client, i, provisioning_dir, q))
        p.start()
        procs.append(p)
    results = [q.get() for _ in range(clients)]
    for p in procs:
        p.join()
    wall = (time.perf_counter_ns() - start) / 1e9
    latencies = []
    errors = 0
    for item in results:
        latencies.extend(item["latencies_ms"])
        errors += item["errors"]
    latencies.sort()
    result = {
        "protocol": "RIA-QKD",
        "clients": clients,
        "hs_per_client": hs_per_client,
        "n_warmup": N_WARMUP,
        "n_measured": len(latencies),
        "n_errors": errors,
        "latency_ms": {"mean": round(statistics.mean(latencies), 3), "median": round(statistics.median(latencies), 3), "p95": round(percentile(latencies, 0.95), 3), "p99": round(percentile(latencies, 0.99), 3), "samples": [round(value, 6) for value in latencies]},
        "wall_time_s": round(wall, 3),
        "throughput_hs": round(len(latencies) / wall, 2),
        "role": "client",
        "metadata": runtime_metadata("client"),
    }
    out = Path(output_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


def main():
    parser = argparse.ArgumentParser(description="RIA-QKD real network concurrency benchmark")
    parser.add_argument("--mode", choices=["server", "client"], required=True)
    parser.add_argument("--server-ip", default="")
    parser.add_argument("--port", type=int, default=9998)
    parser.add_argument("--clients", type=int, required=True)
    parser.add_argument("--hs-per-client", type=int, default=50)
    parser.add_argument("--provisioning-dir", required=True)
    parser.add_argument("--output", default=str(ROOT / "out" / "network_concurrency.json"))
    parser.add_argument("--server-output", default=str(ROOT / "out" / "network_concurrency_server.json"))
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.port, args.clients, args.hs_per_client, args.provisioning_dir, args.server_output)
    else:
        if not args.server_ip:
            raise SystemExit("--server-ip is required in client mode")
        run_client(args.server_ip, args.port, args.clients, args.hs_per_client, args.provisioning_dir, args.output)


if __name__ == "__main__":
    main()
