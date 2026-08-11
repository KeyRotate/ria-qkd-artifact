#!/usr/bin/env python3
"""Aggregate archived client-side network benchmark JSON files."""

from __future__ import annotations

import argparse
import json
import statistics
from pathlib import Path


def percentile(values: list[float], p: float) -> float:
    values = sorted(values)
    if not values:
        return 0.0
    index = max(0, min(len(values) - 1, int((p * len(values) + 0.9999999999)) - 1))
    return values[index]


def summarize(paths: list[Path]) -> dict:
    runs = []
    samples = []
    for path in sorted(paths):
        data = json.loads(path.read_text())
        latency = data["latency_ms"]
        run_samples = latency["samples"]
        samples.extend(run_samples)
        runs.append({
            "file": str(path),
            "n_measured": data["n_measured"],
            "n_errors": data["n_errors"],
            "mean_ms": latency["mean"],
            "median_ms": latency["median"],
            "p95_ms": latency["p95"],
            "p99_ms": latency["p99"],
            "throughput_hs": data["throughput_hs"],
        })

    means = [run["mean_ms"] for run in runs]
    p95s = [run["p95_ms"] for run in runs]
    p99s = [run["p99_ms"] for run in runs]
    return {
        "n_runs": len(runs),
        "n_measured_total": len(samples),
        "n_errors_total": sum(run["n_errors"] for run in runs),
        "aggregate_samples": {
            "mean_ms": round(statistics.mean(samples), 3),
            "median_ms": round(statistics.median(samples), 3),
            "p95_ms": round(percentile(samples, 0.95), 3),
            "p99_ms": round(percentile(samples, 0.99), 3),
        },
        "run_mean_ms": {
            "mean": round(statistics.mean(means), 3),
            "min": round(min(means), 3),
            "max": round(max(means), 3),
        },
        "run_p95_ms": {"min": round(min(p95s), 3), "max": round(max(p95s), 3)},
        "run_p99_ms": {"min": round(min(p99s), 3), "max": round(max(p99s), 3)},
        "run_throughput_hs": {
            "mean": round(statistics.mean(run["throughput_hs"] for run in runs), 2),
            "min": round(min(run["throughput_hs"] for run in runs), 2),
            "max": round(max(run["throughput_hs"] for run in runs), 2),
        },
        "runs": runs,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()

    conditions = {
        "ria_lan": "run*_lan/*_client.json",
        "ria_rtt50": "run*_rtt50/*_client.json",
        "ria_concurrency": "run*_concurrency/*_client.json",
        "kemtls_contextual": "run*_kemtls/*_client.json",
    }
    result = {"artifact_run": args.root.name, "conditions": {}}
    for name, pattern in conditions.items():
        paths = list(args.root.glob(pattern))
        if len(paths) != 3:
            raise SystemExit(f"{name}: expected 3 client JSON files, found {len(paths)}")
        result["conditions"][name] = summarize(paths)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
