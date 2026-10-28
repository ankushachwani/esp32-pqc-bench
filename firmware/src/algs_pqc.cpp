#include "bench.h"
extern "C" {
#include "crypto_kem/ml-kem-512/clean/api.h"
#include "crypto_kem/ml-kem-768/clean/api.h"
#include "crypto_kem/ml-kem-1024/clean/api.h"
#include "crypto_sign/ml-dsa-44/clean/api.h"
#include "crypto_sign/ml-dsa-65/clean/api.h"
#include "crypto_sign/ml-dsa-87/clean/api.h"
#include "crypto_sign/falcon-512/clean/api.h"
#include "crypto_sign/sphincs-sha2-128f-simple/clean/api.h"
#include "crypto_sign/sphincs-sha2-128s-simple/clean/api.h"
}

static void nop() {}

#define KEM(id, NS, label)                                                              \
    static int id##_kg()  { return NS##_crypto_kem_keypair(g.pk, g.sk); }               \
    static int id##_enc() { return NS##_crypto_kem_enc(g.ct, g.ss1, g.pk); }            \
    static int id##_dec() { return NS##_crypto_kem_dec(g.ss2, g.ct, g.sk); }            \
    static void id##_sz(Sizes *s) {                                                     \
        *s = { NS##_CRYPTO_PUBLICKEYBYTES, NS##_CRYPTO_SECRETKEYBYTES,                  \
               NS##_CRYPTO_CIPHERTEXTBYTES, 0 }; }                                      \
    static const Alg id = { label, "lattice", "kem", true, id##_kg, id##_enc, id##_dec, \
                            nullptr, nullptr, nop, id##_sz };

#define SIG(id, NS, label, fam)                                                         \
    static int id##_kg()   { return NS##_crypto_sign_keypair(g.pk, g.sk); }             \
    static int id##_sign() { return NS##_crypto_sign_signature(g.sig, &g.siglen, g.msg, MSG_LEN, g.sk); } \
    static int id##_ver()  { return NS##_crypto_sign_verify(g.sig, g.siglen, g.msg, MSG_LEN, g.pk); }     \
    static void id##_sz(Sizes *s) {                                                     \
        *s = { NS##_CRYPTO_PUBLICKEYBYTES, NS##_CRYPTO_SECRETKEYBYTES, 0, NS##_CRYPTO_BYTES }; } \
    static const Alg id = { label, fam, "sig", true, id##_kg, nullptr, nullptr,         \
                            id##_sign, id##_ver, nop, id##_sz };

KEM(mlkem512,  PQCLEAN_MLKEM512_CLEAN,  "ML-KEM-512")
KEM(mlkem768,  PQCLEAN_MLKEM768_CLEAN,  "ML-KEM-768")
KEM(mlkem1024, PQCLEAN_MLKEM1024_CLEAN, "ML-KEM-1024")
SIG(mldsa44, PQCLEAN_MLDSA44_CLEAN, "ML-DSA-44", "lattice")
SIG(mldsa65, PQCLEAN_MLDSA65_CLEAN, "ML-DSA-65", "lattice")
SIG(mldsa87, PQCLEAN_MLDSA87_CLEAN, "ML-DSA-87", "lattice")
SIG(falcon512, PQCLEAN_FALCON512_CLEAN, "Falcon-512", "lattice")
SIG(sphf, PQCLEAN_SPHINCSSHA2128FSIMPLE_CLEAN, "SPHINCS+-SHA2-128f", "hash")
SIG(sphs, PQCLEAN_SPHINCSSHA2128SSIMPLE_CLEAN, "SPHINCS+-SHA2-128s", "hash")

const Alg *pqc_algs[] = { &mlkem512, &mlkem768, &mlkem1024, &mldsa44, &mldsa65, &mldsa87,
                          &falcon512, &sphf, &sphs };
extern const int n_pqc = sizeof(pqc_algs) / sizeof(pqc_algs[0]);
