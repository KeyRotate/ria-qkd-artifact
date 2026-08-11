#!/usr/bin/env python3
"""More explicit client-side cycle-style benchmark."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_primitives import generate_nonce, MLKEMWrapper, MLDSAWrapper, HKDFWrapper, HMACWrapper, hash_transcript


def bench_ria_qkd_client(iterations: int = 100):
    kem = MLKEMWrapper("ML-KEM-512")
    sig = MLDSAWrapper("ML-DSA-44")
    pk_server_sig, sk_server_sig = sig.keygen()
    pk_server_eph, sk_server_eph = kem.keygen()
    total = 0.0
    for _ in range(iterations):
        pk_client, sk_client = kem.keygen()
        K1, ct_static = kem.encapsulate(pk_client)
        start = time.perf_counter()
        pk_client_eph, sk_client_eph = kem.keygen()
        transcript = generate_nonce(64)
        server_signature = sig.sign(sk_server_sig, transcript)
        sig.verify(pk_server_sig, transcript, server_signature)
        K1_client = kem.decapsulate(sk_client, ct_static)
        _, ct_ephemeral = kem.encapsulate(pk_client_eph)
        K2_client = kem.decapsulate(sk_client_eph, ct_ephemeral)
        K3, ct_client = kem.encapsulate(pk_server_eph)
        transcript_hash = hash_transcript(transcript, ct_client)
        prk_sess = HKDFWrapper.extract(generate_nonce(32), K1_client + K2_client + K3)
        finished_key = HKDFWrapper.expand(prk_sess, b"finished" + transcript_hash, 32)
        _ = HMACWrapper.compute(finished_key, b"CL_FIN")
        total += time.perf_counter() - start
    avg_ms = total / iterations * 1000
    return {"avg_time_ms": avg_ms, "estimated_cycles_millions": avg_ms * 2.7}


def main():
    result = bench_ria_qkd_client()
    out = Path("out")
    out.mkdir(exist_ok=True)
    (out / "cycle_count_accurate_results.json").write_text(json.dumps(result, indent=2))
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
