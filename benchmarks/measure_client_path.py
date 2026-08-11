#!/usr/bin/env python3
"""Client-side-only path timing: mTLS-PQC vs RIA-QKD (liboqs)."""

from __future__ import annotations

import argparse
import json
import platform
import socket
import time
from pathlib import Path

import oqs

KEM_ALG = "ML-KEM-512"
SIG_ALG = "ML-DSA-44"


def mtls_client_path(iterations: int) -> float:
    """mTLS-PQC client cost: verify server cert signature, sign client auth,
    decapsulate the key-exchange ciphertext."""
    total = 0.0
    with oqs.Signature(SIG_ALG) as server_sig:
        srv_pk = server_sig.generate_keypair()
        srv_sk = server_sig.export_secret_key()
        cert_msg = b"server-certificate"
        cert_sig = server_sig.sign(cert_msg)
    with oqs.Signature(SIG_ALG) as client_sig:
        cli_pk = client_sig.generate_keypair()
        cli_sk = client_sig.export_secret_key()
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        eph_pk = kem.generate_keypair()
        eph_sk = kem.export_secret_key()
        _, ct = kem.encap_secret(eph_pk)
    verifier = oqs.Signature(SIG_ALG)
    client_signer = oqs.Signature(SIG_ALG, cli_sk)
    kdec = oqs.KeyEncapsulation(KEM_ALG, eph_sk)
    try:
        for _ in range(iterations):
            t0 = time.perf_counter()
            assert verifier.verify(cert_msg, cert_sig, srv_pk)
            client_signer.sign(b"client-auth")
            kdec.decap_secret(ct)
            total += time.perf_counter() - t0
    finally:
        verifier.free()
        client_signer.free()
        kdec.free()
    return total / iterations


def ria_client_path(iterations: int) -> float:
    """RIA-QKD client cost: verify server signature, decap static + ephemeral
    ciphertexts, encapsulate to the server ephemeral key."""
    total = 0.0
    with oqs.Signature(SIG_ALG) as sig:
        srv_pk = sig.generate_keypair()
        srv_sk = sig.export_secret_key()
        hs_msg = b"server-hello"
        hs_sig = sig.sign(hs_msg)
    with oqs.KeyEncapsulation(KEM_ALG) as kem:
        static_pk = kem.generate_keypair()
        static_sk = kem.export_secret_key()
        eph_pk = kem.generate_keypair()
        eph_sk = kem.export_secret_key()
        srv_eph_pk = kem.generate_keypair()
        srv_eph_sk = kem.export_secret_key()
        _, ct_static = kem.encap_secret(static_pk)
        _, ct_eph = kem.encap_secret(eph_pk)
    verifier = oqs.Signature(SIG_ALG)
    kdec_static = oqs.KeyEncapsulation(KEM_ALG, static_sk)
    kdec_eph = oqs.KeyEncapsulation(KEM_ALG, eph_sk)
    kenc = oqs.KeyEncapsulation(KEM_ALG)
    try:
        for _ in range(iterations):
            t0 = time.perf_counter()
            verifier.verify(hs_msg, hs_sig, srv_pk)
            kdec_static.decap_secret(ct_static)
            kdec_eph.decap_secret(ct_eph)
            kenc.encap_secret(srv_eph_pk)
            total += time.perf_counter() - t0
    finally:
        verifier.free()
        kdec_static.free()
        kdec_eph.free()
        kenc.free()
    return total / iterations


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
        "iterations": args.iterations,
        "mtls_pqc_client_path_ms": round(mtls_client_path(args.iterations) * 1000, 4),
        "ria_qkd_client_path_ms": round(ria_client_path(args.iterations) * 1000, 4),
    }
    out = Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
