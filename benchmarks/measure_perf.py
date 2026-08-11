#!/usr/bin/env python3
"""Per-operation timing for ML-KEM-512 and ML-DSA-44 (liboqs)."""

from __future__ import annotations

import argparse
import json
import platform
import socket
import time
from pathlib import Path

import oqs


def bench_kem(iterations: int) -> dict:
    alg = "ML-KEM-512"
    keygen_ms = encap_ms = decap_ms = 0.0
    for _ in range(iterations):
        t0 = time.perf_counter()
        with oqs.KeyEncapsulation(alg) as kem:
            pk = kem.generate_keypair()
            sk = kem.export_secret_key()
            keygen_ms += time.perf_counter() - t0
            t0 = time.perf_counter()
            ct, ss = kem.encap_secret(pk)
            encap_ms += time.perf_counter() - t0
            t0 = time.perf_counter()
            ss2 = kem.decap_secret(ct)
            decap_ms += time.perf_counter() - t0
    return {
        "algorithm": alg,
        "iterations": iterations,
        "keygen_ms": round(keygen_ms / iterations * 1000, 4),
        "encap_ms": round(encap_ms / iterations * 1000, 4),
        "decap_ms": round(decap_ms / iterations * 1000, 4),
    }


def bench_sig(iterations: int) -> dict:
    alg = "ML-DSA-44"
    keygen_ms = sign_ms = verify_ms = 0.0
    msg = b"benchmark-message"
    for _ in range(iterations):
        t0 = time.perf_counter()
        with oqs.Signature(alg) as sig:
            pk = sig.generate_keypair()
            sk = sig.export_secret_key()
            keygen_ms += time.perf_counter() - t0
            t0 = time.perf_counter()
            sm = sig.sign(msg)
            sign_ms += time.perf_counter() - t0
            t0 = time.perf_counter()
            valid = sig.verify(msg, sm, pk)
            verify_ms += time.perf_counter() - t0
            assert valid
    return {
        "algorithm": alg,
        "iterations": iterations,
        "keygen_ms": round(keygen_ms / iterations * 1000, 4),
        "sign_ms": round(sign_ms / iterations * 1000, 4),
        "verify_ms": round(verify_ms / iterations * 1000, 4),
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--iterations", type=int, default=100)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    result = {
        "platform": {
            "hostname": socket.gethostname(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "processor": platform.processor(),
            "liboqs": oqs.oqs_version(),
        },
        "kem": bench_kem(args.iterations),
        "sig": bench_sig(args.iterations),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
