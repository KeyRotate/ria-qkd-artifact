#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/m4bench
SRC=$ROOT/src
PQC=$ROOT/pqc
BIN=$ROOT/out
mkdir -p "$BIN"
cd "$BIN"

CFLAGS="-mcpu=cortex-m4 -mthumb -mfpu=fpv4-sp-d16 -mfloat-abi=hard -O2 -ffunction-sections -fdata-sections -Wl,--gc-sections -Wall -std=gnu99 -I$PQC"

KEM_SRC=$(find $PQC/kem -maxdepth 1 -name "*.c" | sort)
SIGN_SRC=$(find $PQC/sign -maxdepth 1 -name "*.c" | sort)
KEM_ASM=$(find $PQC/kem -maxdepth 1 \( -name "*.S" -o -name "*.s" \) | sort)
SIGN_ASM=$(find $PQC/sign -maxdepth 1 \( -name "*.S" -o -name "*.s" \) | sort)

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
