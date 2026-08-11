#!/usr/bin/env bash
# Build the Cortex-M4 end-to-end handshake firmware.
#
# The ML-KEM-512 / ML-DSA-44 sources (pqm4-derived) are NOT committed verbatim
# in this repo; they ship as the archive
#   m4/evidence/benchmark/archive/m4bench_evidence.tar.gz
# (see m4/evidence/benchmark/archive/m4bench_evidence.sha256 for its manifest).
# This script extracts that archive into a local build dir and compiles against
# the firmware glue in m4/firmware/src.
#
# Requires: arm-none-eabi-gcc toolchain on PATH.
set -euo pipefail

# Repo layout (script lives at m4/firmware/scripts/build_handshake.sh)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M4_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
SRC="$M4_DIR/firmware/src"
ARCHIVE_DIR="$M4_DIR/evidence/benchmark/archive"
ARCHIVE="$ARCHIVE_DIR/m4bench_evidence.tar.gz"

# Local build workspace (git-ignored)
BUILD_DIR="${M4_DIR}/e2e-build"
PQC="$BUILD_DIR/pqc"
BIN="$BUILD_DIR/out"

mkdir -p "$BIN"

# Extract the pqm4/pqclean sources from the shipped archive if not already present
if [ ! -d "$PQC/kem" ]; then
    echo "Extracting PQC sources from $ARCHIVE ..."
    tar -xzf "$ARCHIVE" -C "$BUILD_DIR" --strip-components=1 m4bench/pqc
fi

CFLAGS="-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -std=gnu99 -I$PQC"

KEM_SRC=$(find "$PQC/kem" -maxdepth 1 -name "*.c" | sort)
SIGN_SRC=$(find "$PQC/sign" -maxdepth 1 -name "*.c" | sort)
KEM_ASM=$(find "$PQC/kem" -maxdepth 1 \( -name "*.S" -o -name "*.s" \) | sort)
SIGN_ASM=$(find "$PQC/sign" -maxdepth 1 \( -name "*.S" -o -name "*.s" \) | sort)

cd "$BIN"
arm-none-eabi-gcc $CFLAGS \
  -T "$SRC/stm32f407vg.ld" -nostartfiles -nostdlib \
  "$SRC/startup_stm32f407.s" \
  "$SRC/system_stm32f407.c" \
  "$SRC/sha256.c" \
  "$SRC/usart2.c" \
  "$PQC/randombytes.c" \
  "$PQC/fips202.c" \
  "$PQC/keccakf1600.c" \
  $KEM_SRC $SIGN_SRC $KEM_ASM $SIGN_ASM \
  "$SRC/main_handshake.c" \
  -o m4handshake.elf

arm-none-eabi-objcopy -O binary m4handshake.elf m4handshake.bin
arm-none-eabi-size m4handshake.elf
echo "Build OK -> $BIN/m4handshake.bin ($(stat -c%s m4handshake.bin) bytes)"