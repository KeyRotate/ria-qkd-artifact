#!/usr/bin/env python3
"""Generate out-of-band provisioning materials for the artifact."""

from __future__ import annotations

import argparse
import os
from pathlib import Path

import oqs


def main() -> None:
    parser = argparse.ArgumentParser(description="Generate provisioning materials")
    parser.add_argument("--outdir", required=True)
    parser.add_argument("--client-id", default="artifact-client")
    parser.add_argument("--count", type=int, default=1, help="generate per-client materials for a concurrency run")
    parser.add_argument("--kem", default="ML-KEM-512")
    parser.add_argument("--sig", default="ML-DSA-44")
    args = parser.parse_args()

    outdir = Path(args.outdir)
    outdir.mkdir(parents=True, exist_ok=True)

    if args.count < 1:
        raise SystemExit("--count must be positive")

    if args.count == 1:
        kem = oqs.KeyEncapsulation(args.kem)
        client_pk = kem.generate_keypair()
        client_sk = kem.export_secret_key()
        (outdir / "client_static_pk.bin").write_bytes(client_pk)
        (outdir / "client_static_sk.bin").write_bytes(client_sk)

        sig = oqs.Signature(args.sig)
        server_pk = sig.generate_keypair()
        server_sk = sig.export_secret_key()
        (outdir / "server_sig_pk.bin").write_bytes(server_pk)
        (outdir / "server_sig_sk.bin").write_bytes(server_sk)

        (outdir / "anchor.bin").write_bytes(os.urandom(32))
        (outdir / "client_id.txt").write_text(args.client_id + "\n")
    else:
        for index in range(args.count):
            kem = oqs.KeyEncapsulation(args.kem)
            client_pk = kem.generate_keypair()
            client_sk = kem.export_secret_key()
            prefix = f"client-{index}"
            (outdir / f"{prefix}_static_pk.bin").write_bytes(client_pk)
            (outdir / f"{prefix}_static_sk.bin").write_bytes(client_sk)
            (outdir / f"{prefix}_anchor.bin").write_bytes(os.urandom(32))
    print(f"Provisioning materials written to {outdir}")


if __name__ == "__main__":
    main()
