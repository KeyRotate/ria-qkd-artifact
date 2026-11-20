# RIA-QKD Artifact v2.0 (Revision R3)

Companion artifact for:
**RIA-QKD: A Risk-Isolated, Asymmetric Authenticated Key Distribution Architecture for Hybrid QKD-PQC IoT Networks**
IEEE Internet of Things Journal, Manuscript IoT-66423-2026.R2 (Revision R3).

This bundle contains everything needed to reproduce the R3 empirical results reported in
Tables II, III, V, VI, VII and Figures 4 and 5: the pure-C benchmark sources, the raw JSON
measurements, the NIST SP 800-230 implementation and verified test vectors, and the
decoy-state BB84 simulator.

## Platforms
- **Gateway proxy (NUC):** Intel NUC8i7BEH, Core i7-8559U (x86-64, AVX2), Ubuntu 24.04,
  OpenSSL 3.0.13. Benchmarks pinned to one core (`taskset -c 0`), governor `performance`,
  Intel Turbo Boost disabled (`no_turbo=1`) so the reference TSC is fixed at 2.70 GHz;
  cycles read with `rdtscp`, wall time with `CLOCK_MONOTONIC_RAW`.
- **Edge proxy (RPi 2B):** Raspberry Pi 2B, ARMv7 Cortex-A7 @ 900 MHz, Raspberry Pi OS,
  OpenSSL 3.5.5. Governor `performance`, single-core pinning.
- **Crypto library:** Open Quantum Safe `liboqs 0.15.0`, built in two x86-64 variants
  (AVX2 runtime-dispatch and portable clean C) plus an ARMv7 build. HQC enabled
  (`-DOQS_ENABLE_KEM_HQC=ON`). See `build/build.sh`.

## Contents
- `benchmarks/bench_table_v.c` — primitive KEM/signature benchmarks (Table V), adaptive
  warmup/iteration counts, median/IQR/cycle reporting, Falcon unpadded-length sampling.
- `benchmarks/bench_table_vi.c` — full client-path benchmarks for the 8 compared schemes
  (Table VI / Figure 4), decomposed into Verify/KeyGen/Encap/Decap/Sign/KDF-Hash-MAC.
- `benchmarks/test_hqc.c` — quick HQC/FrodoKEM/McEliece sanity benchmark.
- `benchmarks/wire_accounting.py` — exact wire-byte formulas; asserts the RIA serializer
  sizes (904+4825+835+55 = 6619 B) and emits `results/master_stage1_summary.json`.
- `benchmarks/bb84_qkd_model.py` — three-intensity decoy-state BB84: asymptotic GLLP and
  finite-key (Lim et al. Chernoff bounds) rates; DWDM parallel-channel (M=1..32),
  block-size (N=1e6..1e10) and repetition-rate scaling. Emits `results/bb84_extended.json`.
- `sp800_230/` — FIPS 205 `slh_dsa_c` reference code extended with the six NIST SP 800-230
  (IPD, Apr 2026) limited-signature parameter sets. `SP800_230.patch` is the exact diff
  against the liboqs 0.15.0 baseline. `gen_vectors.c` generates/verifies real signature
  test vectors (`vectors/*.bin`) and benchmarks verification; `res_*.json` record the
  measured keygen/sign times. `verify_cross.c` cross-checks SLH-DSA-SHA2-128s against liboqs.
- `results/` — raw measurements: `nuc_table_v_avx2.json`, `nuc_table_v_clean.json`,
  `rpi_table_v.json`, `nuc_table_vi.json`, `rpi_table_vi.json`,
  `nuc_sp800_230_verify.jsonl`, `rpi_sp800_230_verify.jsonl`,
  `bb84_extended.json`, `master_stage1_summary.json`.
- `build/build.sh` — liboqs build + benchmark compile + run commands.

## Key measured facts (medians)
- Falcon-padded-512 verify vs ML-DSA-44 verify: RPi 2B 1.10 ms vs 4.42 ms (4.02x faster);
  x86-64 clean C 64.6 us vs 141.0 us (2.18x faster); x86-64 AVX2 59.7 us vs 34.9 us
  (ML-DSA faster on this backend due to hand-written AVX2 NTT + shake256x4).
- Falcon-padded-512 signature = 666 B (fixed); unpadded Falcon-512 empirical 649–662 B
  (mean 655.1 B), max buffer 752 B. RIA wire with Falcon-padded-512 = 4865 B (-26.5%).
- Full client path (median): RIA-QKD L1 = 109.4 us (NUC) / 11.01 ms (RPi);
  mTLS-PQC = 178.5 us / 17.79 ms. Median reduction 38.7% (NUC) / 38.1% (RPi).
- SP 800-230 SLH-DSA-SHA2-128-24: 32-B PK, 3856-B signature; sign 520.7 s (NUC),
  verify 97.1 us (NUC) / 1.02 ms (RPi). Offline trust-anchor use; 2^24 signature cap.
- BB84 50 km / 2% optical error: asymptotic 133.79 kbps (191,346 pulses/256-bit key);
  finite-key (N=1e9, eps_QKD<=1e-10) 71.05 kbps (360,332 pulses). DWDM M=32 raises QBER
  to ~7% and collapses distillation.

## Reproduce
```
bash build/build.sh          # builds liboqs (avx2/clean), compiles & runs benchmarks
python3 benchmarks/bb84_qkd_model.py
python3 benchmarks/wire_accounting.py
```
Note: HQC in liboqs 0.15.0 uses the upstream PQClean `hqc_clean` backend compiled at `-O0`
by upstream CMake; reported HQC latencies reflect that build (documented in Table V note).

## Provenance / scope
These are software-path measurements; they do not validate a physical HSM, QKD device, or
field-deployed utility controller. The Cortex-M4 energy evidence (Sec. V-D) is from the
earlier archived session (see artifact v1.8.1) and is unchanged in R3. Deployed credentials
are withheld, so the archived Cortex-M4 measured session is not rebuildable.
