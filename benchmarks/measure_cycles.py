#!/usr/bin/env python3
"""Optional cycle-count style benchmark for the artifact."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_primitives import MLDSAWrapper, MLKEMWrapper, generate_nonce
from common.protocol import RIAQKDClient, RIAQKDServer


def bench_ria_qkd_client(iterations: int = 50):
    total = 0.0
    for i in range(iterations):
        master_key = generate_nonce(32)
        server = RIAQKDServer(master_key)
        client = RIAQKDClient(f"client_{i}")
        server.enroll_client(f"client_{i}", client.pk_static)
        start = time.perf_counter()
        m1 = client.start_handshake()
        m2 = server.process_client_hello(m1)
        m3 = client.process_server_hello(m2, server.pk_sig)
        _ = m3
        total += time.perf_counter() - start
    avg_ms = total / iterations * 1000
    return {"protocol": "RIA-QKD", "avg_time_ms": avg_ms, "estimated_cycles_millions": avg_ms * 2.7}


def bench_mtls_pqc_client(iterations: int = 50):
    kem = MLKEMWrapper("ML-KEM-512")
    sig = MLDSAWrapper("ML-DSA-44")
    total = 0.0
    for _ in range(iterations):
        pk_eph, sk_eph = kem.keygen()
        pk_sig, sk_sig = sig.keygen()
        start = time.perf_counter()
        ss, ct = kem.encapsulate(pk_eph)
        _ = kem.decapsulate(sk_eph, ct)
        server_message = generate_nonce(32)
        server_sig = sig.sign(sk_sig, server_message)
        sig.verify(pk_sig, server_message, server_sig)
        client_sig = sig.sign(sk_sig, generate_nonce(32))
        _ = client_sig
        total += time.perf_counter() - start
    avg_ms = total / iterations * 1000
    return {"protocol": "mTLS-PQC", "avg_time_ms": avg_ms, "estimated_cycles_millions": avg_ms * 2.7}


def main():
    results = {
        "mtls_pqc": bench_mtls_pqc_client(),
        "ria_qkd": bench_ria_qkd_client(),
    }
    out = Path("out")
    out.mkdir(exist_ok=True)
    (out / "cycle_count_results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
