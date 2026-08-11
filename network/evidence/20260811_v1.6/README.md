# Network Evidence: artifact-v1.6

This directory contains the raw client-side latency samples and server-side
run records for the v1.6 network rerun. Each condition has three independent
runs. The client JSON files contain every post-warmup sample, summary
statistics, error counts, command-line arguments, host name, Python version,
liboqs version, and UTC start time. The server JSON files contain the
completed count, server wall-clock record, and the same metadata.

## Why a second rerun

The v1.5 evidence was produced by benchmark scripts whose wire behavior did
not exactly match the protocol analyzed in the paper: the server signature
input omitted the client ephemeral public key, and the sequential client did
not recompute and verify the server Finished tag before recording a sample.
Both defects are fixed in v1.6, and all conditions were re-run from scratch:

- `H_sig` now covers the full client hello, including `pk_C^eph`, matching
  Algorithm 1 and `common/protocol.py`.
- The sequential client verifies `t_S = HMAC(K_fin, Tr2 || "SV_FIN")` and
  records a sample only after successful verification; a `FAIL` frame from
  either side is counted as an error.
- The concurrency server records only post-warmup samples and starts its
  wall clock at the first client connection, so the server rate measures
  busy time and is comparable with the client-observed rate.
- Both hosts report `liboqs 0.15.0` (C and Python bindings) in the metadata.

## Testbed

- Server: Intel NUC, `192.168.199.24`, interface `eno1`, Python 3.12.3,
  liboqs-python 0.15.0.
- Client: Raspberry Pi 2B, `192.168.199.55`, interface `eth0`, Python 3.13.5,
  liboqs-python 0.15.0.
- Both hosts used the same SHA256-verified benchmark scripts.
- LAN runs used the normal `fq_codel` qdisc.
- RTT=50 ms runs used `netem delay 25ms` on both interfaces and were followed
  by restoration to `fq_codel`; the restored state was verified on both hosts.
- RIA-QKD sequential runs used one provisioned static ML-KEM client key and
  one provisioned 32-byte anchor. Concurrent runs used 16 distinct static
  client keys and 16 distinct anchors. No private key or anchor is archived.

## Conditions

- `run*_lan/`: RIA-QKD, 5,000 measured handshakes plus 20 warmups.
- `run*_rtt50/`: RIA-QKD, 1,000 measured handshakes plus 20 warmups.
- `run*_concurrency/`: 16 clients, 50 measured handshakes plus 5 warmups per
  client; both the client and server outputs contain 800 post-warmup samples.
- `run*_kemtls/`: contextual KEMTLS-full reference, 1,000 measured
  handshakes plus 20 warmups.

`SUMMARY.json` is generated from the raw client JSON files by
`network/summarize_network_evidence.py`. The aggregate values in the paper
are the pooled post-warmup client samples; the per-run range remains available
in `SUMMARY.json`.

The server-side wall-clock record is archived in each `server.json`. The
raw terminal stdout logs are not archived (they are gitignored); the recorded
`server.json` captures the same completed-count and wall-clock information.
