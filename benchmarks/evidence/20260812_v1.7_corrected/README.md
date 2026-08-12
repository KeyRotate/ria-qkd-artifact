# Corrected mTLS client-path baseline evidence (2026-08-12)

Three 100-iteration runs per platform of `benchmarks/measure_client_path.py`
at its corrected revision, after the post-v1.6 verification-handle fix
(documented in `../20260811_v1.6/README.md`).

The same script revision was run on both hosts; its SHA-256 is recorded in
`SHA256SUMS` (script digest `5cae3812...`). Both hosts report liboqs 0.15.0.

## Medians of three runs (client-side-only path, ms)

| Path | NUC (x86_64, 3.12.3) | Pi 2B (armv7l, 3.13.5) |
|---|---|---|
| mTLS-PQC client | 0.2333 | 18.0866 |
| RIA-QKD client | 0.1315 | 9.8937 |

Savings: about 0.10 ms on the NUC and 8.2 ms on the Pi 2B per handshake.

These corrected values supersede the client-path values in
`../20260811_v1.6/` for the manuscript's Table III and related prose; the
earlier pass is retained as provenance, with its known baseline defect
documented. The raw JSONs below are the authoritative corrected samples.
