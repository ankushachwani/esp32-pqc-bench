// Classical baselines. RSA, ECDH P-256, X25519 and ECDSA P-256 use the mbedtls that ships with Arduino-ESP32
// (2.28.x; RSA exp-mod and big multiplications go through the ESP32 MPI accelerator). mbedtls has no Ed25519, so
// Ed25519 (and a second X25519 row) use libsodium, which the same framework also ships.
#include <string.h>
#include "bench.h"
#include "mbedtls/rsa.h"
#include "mbedtls/ecp.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecdsa.h"
#include "mbedtls/sha256.h"
#include "sodium.h"

static void sha256_msg(uint8_t out[32]) { mbedtls_sha256_ret(g.msg, MSG_LEN, out, 0); }

// ---- RSA-2048, e = 65537. Encaps/decaps = RSAES-OAEP(SHA-256) of a 32-byte secret; sign/verify = PKCS#1 v1.5 SHA-256.
static mbedtls_rsa_context rsa;
static bool rsa_up = false;

static void rsa_reset() { if (rsa_up) { mbedtls_rsa_free(&rsa); rsa_up = false; } }
static int rsa_kg() {
    rsa_reset();
    mbedtls_rsa_init(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    rsa_up = true;
    return mbedtls_rsa_gen_key(&rsa, rng_cb, nullptr, 2048, 65537);
}
static int rsa_enc() {
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    rng_bytes(g.ss1, 32);
    return mbedtls_rsa_rsaes_oaep_encrypt(&rsa, rng_cb, nullptr, MBEDTLS_RSA_PUBLIC, nullptr, 0, 32, g.ss1, g.ct);
}
static int rsa_dec() {
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V21, MBEDTLS_MD_SHA256);
    size_t olen = 0;
    int rc = mbedtls_rsa_rsaes_oaep_decrypt(&rsa, rng_cb, nullptr, MBEDTLS_RSA_PRIVATE, nullptr, 0, &olen, g.ct, g.ss2, 64);
    return rc ? rc : (olen == 32 ? 0 : -1);
}
static int rsa_sign() {
    uint8_t h[32]; sha256_msg(h);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    g.siglen = 256;
    return mbedtls_rsa_pkcs1_sign(&rsa, rng_cb, nullptr, MBEDTLS_RSA_PRIVATE, MBEDTLS_MD_SHA256, 32, h, g.sig);
}
static int rsa_ver() {
    uint8_t h[32]; sha256_msg(h);
    mbedtls_rsa_set_padding(&rsa, MBEDTLS_RSA_PKCS_V15, MBEDTLS_MD_NONE);
    return mbedtls_rsa_pkcs1_verify(&rsa, nullptr, nullptr, MBEDTLS_RSA_PUBLIC, MBEDTLS_MD_SHA256, 32, h, g.sig);
}
static void rsa_sz(Sizes *s) {
    // pk = n + e as raw big-endian integers; sk = the five CRT values (p, q, dp, dq, qinv), which is what a CRT signer stores
    size_t pk = mbedtls_mpi_size(&rsa.N) + mbedtls_mpi_size(&rsa.E);
    size_t sk = mbedtls_mpi_size(&rsa.P) + mbedtls_mpi_size(&rsa.Q) + mbedtls_mpi_size(&rsa.DP)
              + mbedtls_mpi_size(&rsa.DQ) + mbedtls_mpi_size(&rsa.QP);
    *s = { pk, sk, 256, 256 };
}
static const Alg rsa2048_kem = { "RSA-2048 (OAEP)", "rsa", "kem", false, rsa_kg, rsa_enc, rsa_dec, nullptr, nullptr, rsa_reset, rsa_sz };
static const Alg rsa2048_sig = { "RSA-2048 (PKCS1v1.5)", "rsa", "sig", false, rsa_kg, nullptr, nullptr, rsa_sign, rsa_ver, rsa_reset, rsa_sz };

// ---- ECDH over mbedtls: P-256 and Curve25519
struct Ecdh {
    mbedtls_ecp_group_id id; size_t pklen;
    mbedtls_ecp_group grp; mbedtls_mpi d, de, z; mbedtls_ecp_point Q, Qe, Qp;
    bool up;
};
static Ecdh p256 = { MBEDTLS_ECP_DP_SECP256R1, 65 }, x25519 = { MBEDTLS_ECP_DP_CURVE25519, 32 };

static void ec_reset(Ecdh &e) {
    if (!e.up) return;
    mbedtls_ecp_group_free(&e.grp); mbedtls_mpi_free(&e.d); mbedtls_mpi_free(&e.de); mbedtls_mpi_free(&e.z);
    mbedtls_ecp_point_free(&e.Q); mbedtls_ecp_point_free(&e.Qe); mbedtls_ecp_point_free(&e.Qp);
    e.up = false;
}
static int ec_put(Ecdh &e, const mbedtls_ecp_point *P, uint8_t *out) {
    size_t n = 0;
    int rc = mbedtls_ecp_point_write_binary(&e.grp, P, MBEDTLS_ECP_PF_UNCOMPRESSED, &n, out, e.pklen);
    return rc ? rc : (n == e.pklen ? 0 : -1);
}
static int ec_kg(Ecdh &e) {
    // The group stays loaded between calls, as it would in a real client: mbedtls builds a comb table for the
    // base point on first use and keeps it in the group. reset() (start of every BENCH) drops it again.
    if (!e.up) {
        mbedtls_ecp_group_init(&e.grp); mbedtls_mpi_init(&e.d); mbedtls_mpi_init(&e.de); mbedtls_mpi_init(&e.z);
        mbedtls_ecp_point_init(&e.Q); mbedtls_ecp_point_init(&e.Qe); mbedtls_ecp_point_init(&e.Qp);
        e.up = true;
        int rc = mbedtls_ecp_group_load(&e.grp, e.id);
        if (rc) return rc;
    }
    int rc = mbedtls_ecdh_gen_public(&e.grp, &e.d, &e.Q, rng_cb, nullptr);
    return rc ? rc : ec_put(e, &e.Q, g.pk);
}
static int ec_enc(Ecdh &e) {
    int rc = mbedtls_ecp_point_read_binary(&e.grp, &e.Qp, g.pk, e.pklen);   // parse the peer's public key
    if (!rc) rc = mbedtls_ecdh_gen_public(&e.grp, &e.de, &e.Qe, rng_cb, nullptr);
    if (!rc) rc = mbedtls_ecdh_compute_shared(&e.grp, &e.z, &e.Qp, &e.de, rng_cb, nullptr);
    if (!rc) rc = mbedtls_mpi_write_binary(&e.z, g.ss1, 32);
    return rc ? rc : ec_put(e, &e.Qe, g.ct);
}
static int ec_dec(Ecdh &e) {
    int rc = mbedtls_ecp_point_read_binary(&e.grp, &e.Qp, g.ct, e.pklen);
    if (!rc) rc = mbedtls_ecdh_compute_shared(&e.grp, &e.z, &e.Qp, &e.d, rng_cb, nullptr);
    return rc ? rc : mbedtls_mpi_write_binary(&e.z, g.ss2, 32);
}
#define ECDH_ALG(id, state, label)                                                        \
    static void id##_reset() { ec_reset(state); }                                         \
    static int id##_kg() { return ec_kg(state); }                                         \
    static int id##_enc() { return ec_enc(state); }                                       \
    static int id##_dec() { return ec_dec(state); }                                       \
    static void id##_sz(Sizes *s) { *s = { state.pklen, 32, state.pklen, 0 }; }           \
    static const Alg id = { label, "ecc", "kem", false, id##_kg, id##_enc, id##_dec,      \
                            nullptr, nullptr, id##_reset, id##_sz };
ECDH_ALG(ecdh_p256, p256, "ECDH P-256")
ECDH_ALG(ecdh_x25519, x25519, "X25519 (mbedtls)")

// ---- X25519 and Ed25519 from libsodium; all randomness still comes from rng_bytes
static bool sodium_up = false;
static void sodium_once() { if (!sodium_up) { if (sodium_init() < 0) abort();
        sodium_up = true; } }
static void nop() {}

static int sx_kg() {
    sodium_once(); rng_bytes(g.sk, 32);
    return crypto_scalarmult_curve25519_base(g.pk, g.sk);
}
static int sx_enc() {
    uint8_t e[32]; rng_bytes(e, 32);
    int rc = crypto_scalarmult_curve25519_base(g.ct, e);
    return rc ? rc : crypto_scalarmult_curve25519(g.ss1, e, g.pk);
}
static int sx_dec() { return crypto_scalarmult_curve25519(g.ss2, g.sk, g.ct); }
static void sx_sz(Sizes *s) { *s = { 32, 32, 32, 0 }; }
static const Alg x25519_sodium = { "X25519 (libsodium)", "ecc", "kem", false, sx_kg, sx_enc, sx_dec, nullptr, nullptr, nop, sx_sz };

static int ed_kg() {
    sodium_once(); uint8_t seed[32]; rng_bytes(seed, 32);
    return crypto_sign_seed_keypair(g.pk, g.sk, seed);
}
static int ed_sign() {
    unsigned long long n = 0;
    int rc = crypto_sign_detached(g.sig, &n, g.msg, MSG_LEN, g.sk);
    g.siglen = n; return rc;
}
static int ed_ver() { return crypto_sign_verify_detached(g.sig, g.msg, MSG_LEN, g.pk); }
static void ed_sz(Sizes *s) { *s = { 32, 64, 0, 64 }; }
static const Alg ed25519 = { "Ed25519 (libsodium)", "ecc", "sig", false, ed_kg, nullptr, nullptr, ed_sign, ed_ver, nop, ed_sz };

// ---- ECDSA P-256, SHA-256. mbedtls here is built with deterministic ECDSA (RFC 6979), so signing does not consume the rng.
static mbedtls_ecdsa_context ecdsa;
static bool ecdsa_up = false;
static void ecdsa_reset() { if (ecdsa_up) { mbedtls_ecdsa_free(&ecdsa); ecdsa_up = false; } }
static int ecdsa_kg() {
    if (!ecdsa_up) {      // group (and its base-point table) is kept across calls, like the ECDH state above
        mbedtls_ecdsa_init(&ecdsa); ecdsa_up = true;
        int rc = mbedtls_ecp_group_load(&ecdsa.grp, MBEDTLS_ECP_DP_SECP256R1);
        if (rc) return rc;
    }
    return mbedtls_ecp_gen_keypair(&ecdsa.grp, &ecdsa.d, &ecdsa.Q, rng_cb, nullptr);
}
static int ecdsa_sign() {
    uint8_t h[32]; sha256_msg(h);
    return mbedtls_ecdsa_write_signature(&ecdsa, MBEDTLS_MD_SHA256, h, 32, g.sig, &g.siglen, rng_cb, nullptr);
}
static int ecdsa_ver() {
    uint8_t h[32]; sha256_msg(h);
    return mbedtls_ecdsa_read_signature(&ecdsa, h, 32, g.sig, g.siglen);
}
static void ecdsa_sz(Sizes *s) { *s = { 65, 32, 0, 72 }; }     // DER signature is at most 72 bytes; pk is the uncompressed point
static const Alg ecdsa_p256 = { "ECDSA P-256", "ecc", "sig", false, ecdsa_kg, nullptr, nullptr, ecdsa_sign, ecdsa_ver, ecdsa_reset, ecdsa_sz };

const Alg *classic_algs[] = { &rsa2048_kem, &rsa2048_sig, &ecdh_p256, &ecdh_x25519, &x25519_sodium, &ecdsa_p256, &ed25519 };
extern const int n_classic = sizeof(classic_algs) / sizeof(classic_algs[0]);
