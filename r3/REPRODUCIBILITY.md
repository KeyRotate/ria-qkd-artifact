# Independent re-check on NUC and Raspberry Pi 2B (2026-11-22)

To confirm the reported numbers are real and reproducible, the full client-path
benchmark (Table VI) was re-run from the artifact sources on both hosts.

Environment: NUC i7-8559U, governor=performance, no_turbo=1, 2.70 GHz,
`taskset -c 0`, 200 warmup + 1,000 iterations. RPi 2B Cortex-A7, 900 MHz,
governor=performance, `taskset -c 0`, 20 warmup + 200 iterations.

| Scheme | NUC recheck (us) | NUC published | delta | RPi recheck (ms) | RPi published | delta |
|---|---|---|---|---|---|---|
| KEMTLS server-auth lower bound (3 primitives) | 66.7 | 66.5 | +0.4% | 5.052 | 4.922 | +2.7% |
| RIA-QKD-Falcon | 133.9 | 133.6 | +0.3% | 8.098 | 7.690 | +5.3% |
| RIA-QKD L1/2 | 108.4 | 109.4 | -0.8% | 11.167 | 11.005 | +1.5% |
| RIA-QKD-L3 | 161.3 | 161.0 | +0.2% | 18.331 | 18.230 | +0.6% |
| RIA-QKD-Hybrid | 669.0 | 652.3 | +2.6% | 28.152 | 26.926 | +4.5% |
| mTLS-PQC | 182.0 | 178.5 | +2.0% | 18.937 | 17.787 | +6.5% |
| ETSI TS 104 146 | 317.3 | 321.2 | -1.2% | 20.932 | 20.376 | +2.7% |
| QKD-IPsec/IKEv2 | 311.9 | 316.3 | -1.4% | 22.402 | 19.975 | +12.2% |

NUC: all schemes within 2.6%. RPi 2B: within 0.6-12.2%; the larger spread is
consistent with the reported IQR of the signature-based schemes on the Pi
(>5.7 ms), and the relative ordering of all eight schemes is preserved.
The Hybrid delta reflects the ciphertext-binding dual-PRF combiner refinement
(added to match Theorem 4(b)); its timing effect is a few microseconds on NUC.

## Live SP 800-230 check (NUC)
`slh_cross gen sha2_128_24` -> pk=32 B, sig=3856 B, self-verify PASS;
`slh_cross verify` -> OK. Archived measurement: keygen 418.9 s,
sign 520.7 s (res_sha2_128_24.json). BouncyCastle 1.87 verifies the
C-generated SLH-DSA-SHA2-128s signature (bidirectional cross-check).

## BB84 model re-run
`python3 bb84_qkd_model.py` reproduces the archived values exactly:
50 km/2% finite-key 71.05 kbps, 360,332 pulses, 3.60 ms; gamma_dt(1 GHz)=0.7832;
M=8 -> 1.2 kbps; M=16 -> 0.


## Second re-check (2026-11-27): true mutual-auth KEMTLS and the unified BB84 model

Environment identical to the run above (NUC i7-8559U at 2.70 GHz, no_turbo=1,
governor=performance, `taskset -c 0`, 200 warmup + 1,000 iterations; RPi 2B
Cortex-A7 at 900 MHz, governor=performance, `taskset -c 0`, 20 warmup + 200
iterations).

### KEMTLS mutual-auth client path (`bench_kemtls_mutual.c`)
The 2026-11-22 recheck measured a three-primitive path (1 KeyGen + 1 Decap +
1 Encap), i.e. a server-authentication lower bound, while the wire bytes in
Table VI are mutual-authentication bytes. The mutual-auth path was therefore
re-measured as 1 KeyGen + **2 Decap** + 1 Encap + KDF/Hash/MAC:

| Host | Median | Mean | Decap component | Server-auth LB (median) |
|---|---|---|---|---|
| NUC (AVX2) | 81.7 us | 84.8 us | 29.11 us (two decapsulations) | 66.5 us |
| RPi 2B | 6.55 ms | 7.16 ms | 3.70 ms (two decapsulations) | 4.92 ms |

The increment over the lower bound equals one measured ML-KEM-512
decapsulation (14.1 us on NUC, 1.77 ms on the Pi), consistent with the
+13.6 us / +1.76 ms previously stated in the Table VI footnote. All seven other
schemes were re-measured in the same run and reproduce the published Table VI
medians within 0.3-4.5% (NUC) and 0.6-12.2% (RPi 2B), with the ordering
unchanged. Raw files: `results/nuc_kemtls_mutual.json`,
`results/rpi_kemtls_mutual.json`.

### Unified decoy-state BB84 model (`bb84_model_v21.py`)
`python3 benchmarks/bb84_model_v21.py` recomputes Table VII and Figure 5 from a
single channel/detector/decoy parameter set and **asserts every value printed in
the manuscript** (7 Table VII rows, 6 DWDM operating points for both rates and
for the single observed QBER, the block-size and repetition-rate sweeps). The
50 km / 2% QBER finite-key chain reported in the manuscript is reproduced with
its intermediate quantities: gamma_dt = 0.9731, E_mu = 2.179%, n_Z = 3,461,360,
e_Z = 2.241%, s_Z0 = 10,054, s_Z1 = 2,028,489, phi_Z^U = 6.533%,
lambda_EC = 621,464 bits, security-parameter terms 276.6 bits,
l_sec = 710,391 bits = 2,775 keys per 10 s block, 71.04 kbps, 360,365 pulses per
256-bit key (approximately 36 pulses per device per epoch over 10,000 devices);
the large-N limit gives 114.32 kbps and 223,932 pulses (approximately 22 per
device). Output: `results/bb84_unified.json`.
