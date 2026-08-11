# Network Evidence: artifact-v1.5

This directory contains the raw client-side latency samples and server-side
run records for the v1.5 network rerun. Each condition has three independent
runs. The client JSON files contain every post-warmup sample, summary
statistics, error counts, command-line arguments, host name, Python version,
and UTC start time. The server JSON files contain the completed count and
server wall-clock record.

## Testbed

- Server: Intel NUC, `192.168.199.24`, interface `eno1`, Python 3.12.3.
- Client: Raspberry Pi 2B, `192.168.199.55`, interface `eth0`, Python 3.13.5.
- Both hosts used the same SHA256-verified benchmark scripts and
  `liboqs-python`; the installed library emitted the documented liboqs version
  warning but completed all handshakes.
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
  client; the client output contains 800 measured samples.
- `run*_kemtls/`: contextual KEMTLS-full reference, 1,000 measured
  handshakes plus 20 warmups.

`SUMMARY.json` is generated from the raw client JSON files by
`network/summarize_network_evidence.py`. The aggregate values in the paper
are the pooled post-warmup client samples; the per-run range remains available
in `SUMMARY.json`.
