# Performance Benchmark Evidence: artifact-v1.6

Raw per-operation and client-path timings from the v1.6 rerun, measured with
`benchmarks/measure_perf.py` (per-operation) and
`benchmarks/measure_client_path.py` (client-side-only path) on both platforms.

## Per-operation (medians of three 100-iteration runs)

| Op | NUC (ms) | Pi 2B (ms) |
|---|---|---|
| ML-KEM-512 Encap | 0.0243 | 1.5776 |
| ML-KEM-512 Decap | 0.0201 | 1.8817 |
| ML-DSA-44 Sign | 0.1056 | 12.4049 |
| ML-DSA-44 Verify | 0.0403 | 4.6304 |

Equivalent cycles use nominal CPU frequency (NUC 2.7 GHz, Pi 2B 900 MHz) and
are time-derived, not hardware-counter values. Timings vary with CPU frequency
scaling; the three runs per platform are archived to show the spread.

## Client-side-only path (medians of three 100-iteration runs)

| Path | NUC (ms) | Pi 2B (ms) |
|---|---|---|
| mTLS-PQC client | 0.2605 | 18.4164 |
| RIA-QKD client | 0.1481 | 9.9517 |

The mTLS client path is verify server signature + sign client auth + one KEM
decapsulation; the RIA-QKD client path is verify server signature + two KEM
decapsulations + one KEM encapsulation (client never signs). These are
client-side crypto costs only and exclude network/serialization overhead.

## Baseline-script fix note (post-v1.6)

`benchmarks/measure_client_path.py` was corrected after this evidence was
archived: the mTLS baseline now signs the server certificate with a dedicated
server signature handle and verifies it against the matching public key (the
earlier revision generated the client keypair on the same handle, so the
verification ran against a mismatched key and always returned False). This
fix does not change the measured timings: ML-DSA verification performs the
same full verification arithmetic regardless of the outcome (an ML-DSA
signature from a valid signing run passes the norm and hash checks and fails
only at the final key comparison), and verification cost is input-independent.
Re-runs on both platforms with the corrected script reproduce the archived
values within measurement noise (e.g., Raspberry Pi 2B client path 18.42 ->
17.68 ms mTLS, 9.95 -> 9.91 ms RIA-QKD). The archived JSONs therefore remain
the authoritative timing evidence.
