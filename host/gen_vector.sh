#!/usr/bin/env bash
# Regenerates host/vectors/ml-dsa-87.bin (random key each time; run it on the Mac).
set -euo pipefail
cd "$(dirname "$0")/.."
cc -O2 -I. -Icommon -o /tmp/gen_vector_mldsa87 host/gen_vector.c crypto_sign/ml-dsa-87/clean/*.c common/fips202.c common/randombytes.c
/tmp/gen_vector_mldsa87 host/vectors/ml-dsa-87.bin
ls -l host/vectors/ml-dsa-87.bin
