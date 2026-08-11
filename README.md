# RIA-QKD IoTJ Artifact

This repository contains the code and scripts used to reproduce the main results in the paper.

## What this artifact reproduces

- Handshake byte counts
- LAN handshake latency at `N=5000`
- Netem RTT `50 ms` handshake latency
- Concurrent handshake benchmark with `16` clients
- Optional contextual reference: `KEMTLS-full`
- Optional cycle-style benchmark scripts
- Cortex-M4 (STM32F407) primitive benchmarks and end-to-end handshake evidence (`m4/`; firmware, raw PPK2 power traces, serial captures, logs, the full benchmark workspace archive, and SHA-256 manifests)

> Scope note (artifact-v1.6): this artifact validates the protocol and its
> performance as a *software* implementation. It does not exercise or validate
> a physical HSM or QKD device; the HSM-only derivation boundary and the QKD
> interface are deployment assumptions of the architecture, not properties
> established by this code.

## Requirements

- Python 3.11+
- `liboqs` and `liboqs-python`
- `tc` for netem experiments
- Two hosts for network tests: gateway/server and client

Install Python dependencies:

```bash
pip install -r requirements.txt
```

## Provisioning files

Generate the out-of-band materials once, then copy the files to the two hosts as needed:

```bash
python3 network/provision_materials.py --outdir out/provisioning
```

The directory will contain:

- `client_static_pk.bin`
- `client_static_sk.bin`
- `server_sig_pk.bin`
- `server_sig_sk.bin`
- `anchor.bin`

Place files as follows:

- Server host: `client_static_pk.bin`, `server_sig_pk.bin`, `anchor.bin`
- Client host: `client_static_sk.bin`, `server_sig_pk.bin`, `anchor.bin`
- Keep `server_sig_sk.bin` on the server host only

Start the server first, then start the client.

For the concurrent benchmark, generate independent per-client materials:

```bash
python3 network/provision_materials.py \
  --outdir out/provisioning/concurrency \
  --count 16
```

This creates `client-0` through `client-15` static key pairs and anchors.
Keep these files outside the public artifact; the benchmark only archives
the resulting measurements and the fact that distinct materials were used.

Example copy commands:

```bash
scp out/provisioning/client_static_pk.bin <SERVER_USER>@<SERVER_IP>:~/ria-qkd-artifact/out/provisioning/
scp out/provisioning/server_sig_pk.bin <SERVER_USER>@<SERVER_IP>:~/ria-qkd-artifact/out/provisioning/
scp out/provisioning/anchor.bin <SERVER_USER>@<SERVER_IP>:~/ria-qkd-artifact/out/provisioning/
scp out/provisioning/client_static_sk.bin <PI_USER>@<PI_HOST>:~/ria-qkd-artifact/out/provisioning/
scp out/provisioning/server_sig_pk.bin <PI_USER>@<PI_HOST>:~/ria-qkd-artifact/out/provisioning/
scp out/provisioning/anchor.bin <PI_USER>@<PI_HOST>:~/ria-qkd-artifact/out/provisioning/
```

## 1. Handshake bytes

```bash
python3 benchmarks/measure_overhead.py
```

Output: `out/communication_overhead_results.json`

Expected values:

- `client_hello`: `904`
- `server_hello`: `4825`
- `client_finished`: `835`
- `server_finished`: `55`
- `total_handshake`: `6619`

## 2. LAN handshake latency

Server:

```bash
python3 network/bench_network_1000.py \
  --mode server \
  --port 9999 \
  --n 5000 \
  --client-static-pk out/provisioning/client_static_pk.bin \
  --server-sig-pk-out out/provisioning/server_sig_pk.bin \
  --anchor out/provisioning/anchor.bin \
  --output out/network_bench_5000_server.json
```

Client:

```bash
python3 network/bench_network_1000.py \
  --mode client \
  --server-ip <SERVER_IP> \
  --port 9999 \
  --n 5000 \
  --client-static-sk out/provisioning/client_static_sk.bin \
  --server-sig-pk out/provisioning/server_sig_pk.bin \
  --anchor out/provisioning/anchor.bin \
  --label lan5000 \
  --output out/network_bench_5000.json
```

Output: `out/network_bench_5000.json`

Expected values:

- pooled mean latency over 3 x 5000 samples: `16.309 ms`
- pooled latency-equivalent rate: `61.32 hs/s`
- per-run mean range: `15.885--16.947 ms`

## 3. Netem RTT 50 ms

Apply on both hosts:

```bash
sudo tc qdisc replace dev <HOST_DEV> root netem delay 25ms
sudo tc qdisc replace dev <PI_DEV> root netem delay 25ms
```

Then run the same server/client commands with `--n 1000`.

Restore after the test:

```bash
sudo tc qdisc replace dev <HOST_DEV> root fq_codel
sudo tc qdisc replace dev <PI_DEV> root fq_codel
```

Expected values:

- pooled mean latency over 3 x 1000 samples: `123.022 ms`
- pooled latency-equivalent rate: `8.13 hs/s`
- per-run mean range: `122.961--123.109 ms`

## 4. Concurrent benchmark

Server:

```bash
python3 network/bench_network_concurrency.py \
  --mode server \
  --port 9998 \
  --clients 16 \
  --hs-per-client 50 \
  --provisioning-dir out/provisioning/concurrency \
  --server-output out/network_concurrency_server.json
```

Client:

```bash
python3 network/bench_network_concurrency.py \
  --mode client \
  --server-ip <SERVER_IP> \
  --port 9998 \
  --clients 16 \
  --hs-per-client 50 \
  --provisioning-dir out/provisioning/concurrency \
  --output out/network_concurrency.json
```

Expected values:

- pooled mean latency over 3 x 800 samples: `66.960 ms`
- pooled p99 latency: `88.011 ms`
- client-observed completion rate: about `176.97 hs/s`
- server wall-clock rate (measured from the first client connection; the
  window includes the clients' enrollment and warm-up phases while the
  completion count excludes warmups, so the rate is conservative): about
  `181.09 hs/s`
- Each concurrent client uses a distinct provisioned static key and anchor;
  the server and client must receive the same per-client material directory.

## Optional: KEMTLS-full contextual reference

Server:

```bash
python3 network/bench_network_kemtls_full_1000.py \
  --mode server \
  --port 9994 \
  --n 1000 \
  --trust-store-out out/provisioning/kemtls_trust_store.json \
  --server-output out/network_kemtls_full_1000_server.json
```

Copy `out/provisioning/kemtls_trust_store.json` to the client host, then run:

```bash
python3 network/bench_network_kemtls_full_1000.py \
  --mode client \
  --server-ip <SERVER_IP> \
  --port 9994 \
  --n 1000 \
  --trust-store out/provisioning/kemtls_trust_store.json \
  --output out/network_kemtls_full_1000.json
```

Expected values:

- pooled mean latency over 3 x 1000 samples: `8.080 ms`
- pooled latency-equivalent rate: `123.76 hs/s`
- the script should complete without handshake failures
- output file: `out/network_kemtls_full_1000.json`

## Optional: cycle-style benchmarks

```bash
python3 benchmarks/measure_cycles.py
python3 benchmarks/measure_cycles_accurate.py
```

## Notes

- Replace every placeholder with your own host, device, and path values.
- The code does not contain repository-specific IP addresses or `/root` paths.
- Network scripts write outputs to relative paths under `out/`.
- A liboqs/liboqs-python version warning may appear and does not block the run.
- Archived raw network evidence and the generated pooled summary are under
  `network/evidence/20260811_v1.6/`; run
  `network/summarize_network_evidence.py` after a new three-run set.
- Per-operation and client-path timings are archived under
  `benchmarks/evidence/20260811_v1.6/` (three runs per platform, `measure_perf.py`
  and `measure_client_path.py`).
