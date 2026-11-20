#!/usr/bin/env bash
# RIA-QKD R3 artifact build & benchmark script.
# Reproduces the liboqs builds and the pure-C measurements in results/.
# Run from the artifact root. Requires: cmake, ninja, gcc, OpenSSL dev headers, python3.
set -euo pipefail
HERE="$(cd "$(dirname "$0")/.." && pwd)"
WORK="${WORK:-$HOME/ria-qkd-r3-build}"
OQS_TARBALL="${OQS_TARBALL:-$WORK/liboqs-0.15.0.tar.gz}"   # liboqs 0.15.0 source tarball (provide it)
if [ ! -f "$OQS_TARBALL" ]; then
  echo "ERROR: liboqs 0.15.0 source tarball not found at $OQS_TARBALL" >&2
  echo "Download liboqs 0.15.0 and set OQS_TARBALL=/path/to/liboqs-0.15.0.tar.gz" >&2
  exit 1
fi
mkdir -p "$WORK"; cd "$WORK"
[ -d liboqs-0.15.0 ] || tar -xzf "$OQS_TARBALL"

# --- liboqs x86-64 AVX2 runtime-dispatch build (HQC enabled) ---
cmake -S liboqs-0.15.0 -B build-avx2 -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$WORK/install-avx2" \
  -DOQS_DIST_BUILD=ON -DOQS_ENABLE_KEM_HQC=ON -DOQS_USE_OPENSSL=ON \
  -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=OFF
ninja -C build-avx2 -j"$(nproc)"; ninja -C build-avx2 install

# --- liboqs x86-64 portable clean C build (all SIMD disabled) ---
cmake -S liboqs-0.15.0 -B build-clean -GNinja \
  -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX="$WORK/install-clean" \
  -DOQS_DIST_BUILD=OFF -DOQS_OPT_TARGET=generic \
  -DOQS_USE_AVX_INSTRUCTIONS=OFF -DOQS_USE_AVX2_INSTRUCTIONS=OFF \
  -DOQS_USE_BMI1_INSTRUCTIONS=OFF -DOQS_USE_BMI2_INSTRUCTIONS=OFF \
  -DOQS_USE_ADX_INSTRUCTIONS=OFF -DOQS_USE_AES_INSTRUCTIONS=OFF \
  -DOQS_USE_PCLMULQDQ_INSTRUCTIONS=OFF -DOQS_USE_VPCLMULQDQ_INSTRUCTIONS=OFF \
  -DOQS_USE_AVX512_INSTRUCTIONS=OFF \
  -DOQS_ENABLE_KEM_HQC=ON -DOQS_USE_OPENSSL=ON -DBUILD_SHARED_LIBS=ON -DOQS_BUILD_ONLY_LIB=ON
ninja -C build-clean -j"$(nproc)"; ninja -C build-clean install

# --- Compile benchmarks against each backend ---
for B in avx2 clean; do
  gcc -O3 -march=native "$HERE/benchmarks/bench_table_v.c" \
    -I"$WORK/install-$B/include" -L"$WORK/install-$B/lib" \
    -Wl,-rpath,"$WORK/install-$B/lib" -loqs -lcrypto -lm -o "$WORK/bench_table_v_$B"
done
gcc -O3 -march=native "$HERE/benchmarks/bench_table_vi.c" \
  -I"$WORK/install-avx2/include" -L"$WORK/install-avx2/lib" \
  -Wl,-rpath,"$WORK/install-avx2/lib" -loqs -lcrypto -lm -o "$WORK/bench_table_vi_avx2"

# --- Run on NUC (fix frequency, disable turbo, pin core) ---
cpupower frequency-set -g performance || true
echo 1 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
taskset -c 0 "$WORK/bench_table_vi_avx2" nuc_x86_64_avx2 200 1000 > "$HERE/results/nuc_table_vi.json"
taskset -c 0 "$WORK/bench_table_v_avx2"  nuc_x86_64_avx2  > "$HERE/results/nuc_table_v_avx2.json"
taskset -c 0 "$WORK/bench_table_v_clean" nuc_x86_64_clean > "$HERE/results/nuc_table_v_clean.json"
echo 0 > /sys/devices/system/cpu/intel_pstate/no_turbo || true
cpupower frequency-set -g powersave || true

# --- SP 800-230: compile reference code + generate/verify vectors + benchmark verify ---
cd "$HERE/sp800_230"
gcc -O3 -march=native -I"$WORK/install-avx2/include" gen_vectors.c \
  sha2_256.c sha2_512.c sha3_api.c sha3_f1600.c slh_dsa.c slh_sha2.c slh_shake.c slh_prehash.c \
  -lm -o gen_vectors
mkdir -p vectors
for v in sha2_128_24 shake_128_24 sha2_192_24 sha2_256_24; do
  ./gen_vectors gen "$v" "vectors/$v.bin" > "res_$v.json"
done
for v in sha2_128_24 shake_128_24 sha2_192_24 sha2_256_24; do
  taskset -c 0 ./gen_vectors verify "$v" "vectors/$v.bin" 1000
done > "$HERE/results/nuc_sp800_230_verify.jsonl"

# --- BB84 model + wire accounting ---
python3 "$HERE/benchmarks/bb84_qkd_model.py"
python3 "$HERE/benchmarks/wire_accounting.py"

# --- Raspberry Pi 2B (run ON the Pi; copy artifact there first) ---
# On the Pi: build liboqs with -DOQS_MINIMAL_BUILD='KEM_ml_kem_512;...;SIG_slh_dsa_pure_sha2_256f'
#   (see README), then:
#   gcc -O3 -mfpu=neon -mfloat-abi=hard bench_table_v.c  -Iinstall/include -Linstall/lib \
#       -Wl,-rpath,$PWD/install/lib -loqs -lcrypto -lm -o bench_table_v
#   gcc -O3 -mfpu=neon -mfloat-abi=hard bench_table_vi.c -Iinstall/include -Linstall/lib \
#       -Wl,-rpath,$PWD/install/lib -loqs -lcrypto -lm -o bench_table_vi
#   taskset -c 0 ./bench_table_vi rpi2b_armv7 20 200 > results/rpi_table_vi.json
#   taskset -c 0 ./bench_table_v  rpi2b_armv7        > results/rpi_table_v.json
echo "DONE"
