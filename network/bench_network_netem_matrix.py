#!/usr/bin/env python3
"""Optional helper to run the RTT/loss matrix on two hosts."""

from __future__ import annotations

import argparse
import atexit
import json
import shlex
import signal
import subprocess
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parent
BENCH = ROOT / "bench_network_1000.py"
RESULTS_DIR = ROOT / "out"


def run(cmd: str, check: bool = True):
    return subprocess.run(cmd, shell=True, check=check, text=True, capture_output=True)


def ssh(pi_host: str, cmd: str, check: bool = True):
    return run(f"ssh {shlex.quote(pi_host)} {shlex.quote(cmd)}", check=check)


def restore_default_qdisc(host_dev: str, pi_host: str, pi_dev: str):
    run(f"sudo tc qdisc replace dev {shlex.quote(host_dev)} root fq_codel", check=False)
    ssh(pi_host, f"sudo tc qdisc replace dev {shlex.quote(pi_dev)} root fq_codel", check=False)


def apply_qdisc(dev: str, spec: str | None):
    if spec:
        run(f"sudo tc qdisc replace dev {shlex.quote(dev)} root netem {spec}")
    else:
        run(f"sudo tc qdisc del dev {shlex.quote(dev)} root", check=False)


def apply_pi_qdisc(pi_host: str, pi_dev: str, spec: str | None):
    if spec:
        ssh(pi_host, f"sudo tc qdisc replace dev {shlex.quote(pi_dev)} root netem {spec}")
    else:
        ssh(pi_host, f"sudo tc qdisc del dev {shlex.quote(pi_dev)} root", check=False)


def install_cleanup_handlers(host_dev: str, pi_host: str, pi_dev: str):
    def _cleanup(*_args):
        restore_default_qdisc(host_dev, pi_host, pi_dev)
    atexit.register(_cleanup)
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: (_cleanup(), sys.exit(1)))


def main():
    parser = argparse.ArgumentParser(description="Run RTT/loss matrix on two hosts")
    parser.add_argument("--server-ip", required=True)
    parser.add_argument("--pi-host", required=True)
    parser.add_argument("--pi-user", default="")
    parser.add_argument("--host-dev", required=True)
    parser.add_argument("--pi-dev", required=True)
    parser.add_argument("--server-port", type=int, default=9999)
    parser.add_argument("--n", type=int, default=500)
    parser.add_argument("--labels", default="baseline,rtt50ms,loss1p0")
    parser.add_argument("--pi-root", default="~/ria_qkd_artifact")
    args = parser.parse_args()
    install_cleanup_handlers(args.host_dev, args.pi_host, args.pi_dev)
    RESULTS_DIR.mkdir(exist_ok=True)
    selected = {x.strip() for x in args.labels.split(",") if x.strip()}
    restore_default_qdisc(args.host_dev, args.pi_host, args.pi_dev)
    print("This helper expects you to pre-provision the client static key, server signature key, and anchor.")
    print("Use the commands in README.md for the manual path.")
    print(json.dumps({"selected": sorted(selected)}, indent=2))


if __name__ == "__main__":
    main()
