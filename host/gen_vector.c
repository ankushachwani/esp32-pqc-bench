// Makes a public key and a signature for the benchmark message on the Mac, using the same PQClean code.
// Needed for ML-DSA-87: signing does not fit in the ESP32's RAM, but verifying a signature made elsewhere does.
// Output: u16 pklen, u16 siglen (little endian), pk, sig.   Build and run with host/gen_vector.sh.
#include <stdio.h>
#include <stdint.h>
#include "crypto_sign/ml-dsa-87/clean/api.h"

int main(int argc, char **argv) {
    static uint8_t pk[PQCLEAN_MLDSA87_CLEAN_CRYPTO_PUBLICKEYBYTES], sk[PQCLEAN_MLDSA87_CLEAN_CRYPTO_SECRETKEYBYTES];
    static uint8_t sig[PQCLEAN_MLDSA87_CLEAN_CRYPTO_BYTES], msg[64];
    size_t siglen;
    for (int i = 0; i < 64; i++) msg[i] = (uint8_t)(i * 7 + 1);   // same as setup() in firmware/src/main.cpp
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_keypair(pk, sk)) return 1;
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_signature(sig, &siglen, msg, 64, sk)) return 1;
    if (PQCLEAN_MLDSA87_CLEAN_crypto_sign_verify(sig, siglen, msg, 64, pk)) return 2;
    FILE *f = fopen(argv[1], "wb");
    uint8_t h[4] = { sizeof pk & 255, sizeof pk >> 8, siglen & 255, siglen >> 8 };
    fwrite(h, 1, 4, f); fwrite(pk, 1, sizeof pk, f); fwrite(sig, 1, siglen, f);
    fclose(f);
    return 0;
}
