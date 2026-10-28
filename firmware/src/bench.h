#pragma once
#include <stddef.h>
#include <stdint.h>

// Buffers are shared by all algorithms; sized for the largest one in the build
// (ML-DSA-87 keys, SPHINCS+-128f signature).
enum { MAX_PK = 2600, MAX_SK = 4900, MAX_CT = 1600, MAX_SIG = 17100, MSG_LEN = 64 };

struct Buf {
    uint8_t pk[MAX_PK], sk[MAX_SK], ct[MAX_CT], ss1[64], ss2[64], sig[MAX_SIG], msg[MSG_LEN];
    size_t siglen;
};
extern Buf g;

struct Sizes { size_t pk, sk, ct, sig; };   // sig is the maximum; ct is 0 for signature schemes

// Every operation works on the globals in g and returns 0 on success.
// For ECDH "encaps" means: generate an ephemeral key and derive the secret. "decaps" is just the derive.
struct Alg {
    const char *name, *family, *kind;       // kind is "kem" or "sig"
    bool pqc;
    int (*keygen)();
    int (*encaps)();                         // kem only
    int (*decaps)();
    int (*sign)();                           // sig only
    int (*verify)();
    void (*reset)();                         // free contexts/keys held by classical code
    void (*sizes)(Sizes *);                  // call after keygen (RSA sizes come from the key)
};

// rng.cpp
void rng_seed_det(uint32_t seed);            // seed==0 goes back to esp_fill_random
const char *rng_mode();
void rng_bytes(uint8_t *p, size_t n);
int rng_cb(void *, unsigned char *p, size_t n);   // mbedtls f_rng signature

// memtrack.c
extern "C" {
void memtrack_only_task(void *task);       // count only this task's allocations
void memtrack_reset(void);                   // current usage becomes the zero point
size_t memtrack_peak(void);                  // peak bytes above the zero point since reset
}
