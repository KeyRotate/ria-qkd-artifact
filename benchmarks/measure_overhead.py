#!/usr/bin/env python3
"""Measure handshake byte overhead for the paper artifact."""

from __future__ import annotations

import json
from pathlib import Path
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from common.crypto_primitives import generate_nonce, MLKEMWrapper, MLDSAWrapper
from common.protocol import RIAQKDClient, RIAQKDServer, derive_application_key


def measure_ria_qkd():
    master_key = generate_nonce(32)
    client_id = "test_client"
    application_key = derive_application_key(master_key, client_id)
    client = RIAQKDClient(client_id, application_key=application_key)
    server = RIAQKDServer(master_key)
    server.enroll_client(client_id, client.pk_static)

    msg1 = client.start_handshake()
    msg2 = server.process_client_hello(msg1)
    msg3 = client.process_server_hello(msg2, server.pk_sig)
    msg4 = server.process_client_finished(msg3)
    if msg4 is None or not client.process_server_finished(msg4):
        raise RuntimeError("RIA-QKD handshake failed")

    kem = MLKEMWrapper("ML-KEM-512")
    sig = MLDSAWrapper("ML-DSA-44")
    results = {
        "protocol": "RIA-QKD",
        "client_hello": msg1.size(),
        "server_hello": msg2.size(),
        "client_finished": msg3.size(),
        "server_finished": msg4.size(),
        "total_handshake": msg1.size() + msg2.size() + msg3.size() + msg4.size(),
        "client_auth_payload": msg3.size(),
        "server_hello_breakdown": {
            "server_pk_ephemeral": kem.public_key_size,
            "ct_static": kem.ciphertext_size,
            "ct_ephemeral": kem.ciphertext_size,
            "signature": sig.signature_size,
            "overhead": msg2.size() - (kem.public_key_size + 2 * kem.ciphertext_size + sig.signature_size),
        },
    }
    return results


def estimate_mtls_pqc():
    kem = MLKEMWrapper("ML-KEM-512")
    sig = MLDSAWrapper("ML-DSA-44")
    client_hello = 32 + 100 + kem.public_key_size
    server_certificate = 2000
    server_hello = 32 + kem.ciphertext_size + server_certificate + sig.signature_size
    client_certificate = 1500
    client_auth = client_certificate + sig.signature_size
    return {
        "protocol": "mTLS-PQC",
        "client_hello": client_hello,
        "server_hello": server_hello,
        "client_finished": 0,
        "server_finished": 0,
        "total_handshake": client_hello + server_hello + client_auth,
        "client_auth_payload": client_auth,
    }


def estimate_kemtls():
    kem = MLKEMWrapper("ML-KEM-512")
    client_hello = 32 + 100 + kem.public_key_size
    server_hello = 32 + kem.ciphertext_size + 500
    client_auth = kem.ciphertext_size
    return {
        "protocol": "KEMTLS",
        "client_hello": client_hello,
        "server_hello": server_hello,
        "client_finished": 0,
        "server_finished": 0,
        "total_handshake": client_hello + server_hello + client_auth,
        "client_auth_payload": client_auth,
    }


def main():
    ria = measure_ria_qkd()
    mtls = estimate_mtls_pqc()
    kemtls = estimate_kemtls()
    reduction_client_auth = (1 - ria["client_auth_payload"] / mtls["client_auth_payload"]) * 100
    reduction_total = (1 - ria["total_handshake"] / mtls["total_handshake"]) * 100
    results = {
        "ria_qkd": ria,
        "mtls_pqc": mtls,
        "kemtls": kemtls,
        "reductions": {
            "client_auth_vs_mtls": reduction_client_auth,
            "total_vs_mtls": reduction_total,
        },
    }
    out = Path("out")
    out.mkdir(exist_ok=True)
    (out / "communication_overhead_results.json").write_text(json.dumps(results, indent=2))
    print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
