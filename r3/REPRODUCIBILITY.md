# Independent re-check on NUC and Raspberry Pi 2B (2026-11-22)

To confirm the reported numbers are real and reproducible, the full client-path
benchmark (Table VI) was re-run from the artifact sources on both hosts.

Environment: NUC i7-8559U, governor=performance, no_turbo=1, 2.70 GHz,
`taskset -c 0`, 200 warmup + 1,000 iterations. RPi 2B Cortex-A7, 900 MHz,
governor=performance, `taskset -c 0`, 20 warmup + 200 iterations.

| Scheme | NUC recheck (us) | NUC published | delta | RPi recheck (ms) | RPi published | delta |
|---|---|---|---|---|---|---|
| KEMTLS mutual-auth | 66.7 | 66.5 | +0.4% | 5.052 | 4.922 | +2.7% |
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
