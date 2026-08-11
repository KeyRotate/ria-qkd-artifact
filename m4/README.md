# Cortex-M4 End-to-End Evidence (STM32F407)

This directory contains the bare-metal STM32F407 (Cortex-M4F, 168 MHz) firmware
and raw evidence for the end-to-end RIA-QKD handshake and the Cortex-M4
primitive measurements reported in Section V-D / Table III of the paper.

## Layout

- `firmware/src/` - bare-metal firmware sources:
  - `main_handshake.c` - end-to-end RIA-QKD client handshake over USART2
    (wire format B: 4-byte big-endian frame length; internal `>H` field
    lengths; ML-KEM-512 decap x2 + encap x1, ML-DSA-44 verify, SHA-256 /
    HKDF / HMAC on-device). The PA5 GPIO marks the handshake window that is
    correlated with the PPK2 power trace.
  - `usart2.c/h`, `sha256.c/h`, `system_stm32f407.c`, `startup_stm32f407.s`,
    `stm32f407vg.ld` - board support.
  - `m4_creds.h` - **template only**: the deployed test credentials (client
    static ML-KEM secret key, gateway ML-DSA public key, shared anchor) are
    not published; see the header for how to provision your own values.
- `firmware/scripts/build_handshake.sh` - self-contained build script
  (arm-none-eabi-gcc); extracts the pqm4 sources from the archive under
  `evidence/benchmark/archive/` and compiles the firmware in the git-ignored
  `m4/e2e-build/` workspace.
- `evidence/benchmark/` - per-operation primitive results
  (`results_energy.txt` is the canonical source: ML-KEM-512 decap 881,252
  cycles = 5.245 ms / ~2.17 mJ; ML-DSA-44 sign avg 17.0M cycles = 101.3 ms /
  ~53.4 mJ; `results.txt` is an earlier, superseded provenance pass).
- `evidence/benchmark/archive/` - `m4bench_evidence.tar.gz` (the full
  benchmark workspace: the pqm4/PQClean ML-KEM-512 and ML-DSA-44 sources under
  `m4bench/pqc/`, the benchmark firmware `m4bench/src/`, build scripts, the
  flashed binary, build log, and the raw PPK2 benchmark waveforms) plus its
  SHA-256 manifest. `firmware/scripts/build_handshake.sh` auto-extracts the
  `pqc/` sources from this archive, so the end-to-end firmware build is
  self-contained from the repository.
- `evidence/e2e_logs/` - 2026-08-07 end-to-end run: 30 server-side handshake
  OK entries, M4-side DWT latencies (n=6), PPK2 waveform, RESULTS.md, and
  the SHA-256 manifest.
- `evidence/e2e_ppk2_20260811/` - 2026-08-11 PPK2 re-capture of three end-to-end
  runs with the raw power traces (`ppk2_capture{1,2,3}.bin`), the relay-captured
  serial streams including the M4 results frames (`relay_serial_run{1,2,3}.bin`,
  accepted=1), analysis scripts, RESULTS_20260811.md and SHA-256 hashes.
  Energy: 0.29 J over ~0.8 s; 1.59-1.64 J over ~4.2-4.3 s at ~110-115 mA
  average current.

## Experimental path (2026-08-07 and 2026-08-11)

STM32F407G-DISC1 (USART2 PA2/PA3 @ 115200 baud) -> CP2102 on a remote Dell
Precision 5820 -> FRP TCP reverse-proxy over the public Internet ->
Intel NUC running the RIA-QKD server (`ria_server.py`, provisioned from
client static pk / server sig sk / shared anchor). The FRP path was
experimental transport and remote-control infrastructure, not a RIA-QKD
protocol endpoint. All negotiated shared secrets byte-match the liboqs
reference on the server, and the ML-DSA-44 server signature verifies on the M4.

## License note

The ML-KEM-512 / ML-DSA-44 C implementations used by the firmware derive from
the public pqm4 project (https://github.com/mupq/pqm4) and its upstream
PQClean/Crystals code; see their respective license terms. The firmware glue
code and evidence files are provided under the repository MIT license.
