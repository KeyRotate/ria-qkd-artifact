# Cortex-M4 RIA-QKD End-to-End Handshake over Public Network (Evidence)

PROVENANCE NOTE: this top-level file documents two distinct sessions over the
same FRP path:
  * 2026-08-07: the N=30 server-side `handshake OK` log, the server-side
    latency statistics, and the M4-side DWT latencies (n=6) in
    `M4_latency_results.txt`; `ppk2_hs2_capture.bin` is a single 2026-08-07
    PPK2 power trace whose PA5 window (~1.1 s) corresponds to one of those
    short-latency handshakes (it carries no DWT results frame, so it is not
    paired to a specific n=6 entry).
  * 2026-08-11: the three PPK2 re-captures and their raw serial frames in
    `ppk2_20260811/` (see that directory's RESULTS_20260811.md for details and
    its calibration/provenance notes).

Setup (2026-08-07 path shown below; 08-11 is identical except the server EOF
handling was hardened for unattended re-runs):
  - M4: STM32F407G-DISC1 (Cortex-M4F, 168 MHz), USART2 (PA2/PA3) @115200 baud
  - Serial bridge: CP2102 (Dell /dev/ttyUSB0)
  - Path: M4 -> Dell CP2102 -> relay -> frp.vivon1031.top:36012 -> NUC RIA-QKD server
  - Server: Python + liboqs ML-KEM-512 / ML-DSA-44 (NUC)
  - Client crypto: pqm4 ML-KEM-512 (decap x2 + encap x1), ML-DSA-44 verify, SHA-256/HKDF/HMAC

Interop: All 3 negotiated shared secrets (ss1/ss2/ss3) byte-match liboqs.
Root-cause fix: M4 HKDF info used 9-byte "finished\0"; fixed to 8-byte "finished".

End-to-end handshake over public WAN:
  - Success: 30/30 server-side handshakes OK (CL_FIN + client Finished tag verified)
  - Server-side latency: min 0.64 s, median 4.67 s, mean 5.08 s, P90 9.64 s, P95 9.64 s, max 9.67 s
  - M4-measured full-handshake time (DWT cycles, accepted=1): ~0.9-4.4 s
  - Wall-clock dominated by 115200-baud UART (4.7 KB m2 ~0.4 s) + WAN round trips

Full-handshake energy (PPK2 source-meter, 3.3 V, 100 kHz, PA5-delimited) - recaptured 2026-08-11 (see ppk2_20260811/):
  capture1: 800.8 ms,  110.1 mA avg, 216.4 mA peak, 291.0 mJ
  capture2: 4165.2 ms, 115.4 mA avg, 208.1 mA peak, 1585.7 mJ
  capture3: 4316.8 ms, 115.3 mA avg, 206.7 mA peak, 1642.8 mJ
  avg ~110-115 mA; energy scales with handshake duration
  (dominated by UART transfer of m2 ~4.7 KB @115200 and public-network round trips)
  Raw waveforms, serial captures, analysis scripts and SHA-256 hashes: ppk2_20260811/

M4 primitive time/energy (from m4bench, per-operation):
  ML-KEM-512 decap 5.245 ms / ~2.17 mJ; ML-DSA-44 sign avg 101.3 ms / ~53.4 mJ

Supplementary files: server_handshake_log.txt (30 entries, 2026-08-07),
M4_latency_results.txt (n=6, 2026-08-07), ppk2_hs2_capture.bin (single
2026-08-07 raw PPK2 waveform, ~1.1 s PA5 window, no DWT frame).
