#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#if defined(__x86_64__)
#  include <x86intrin.h>
static inline uint64_t read_cycles(void) { unsigned int a; return __rdtscp(&a); }
static const char *CYCLE_SRC = "rdtscp";
#elif defined(__aarch64__)
static inline uint64_t read_cycles(void) { uint64_t v; asm volatile("mrs %0, cntvct_el0":"=r"(v)); return v; }
static const char *CYCLE_SRC = "cntvct_el0";
#else
static inline uint64_t read_cycles(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static const char *CYCLE_SRC = "CLOCK_MONOTONIC_RAW_ns";
#endif

static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

/* Pre-fetched HKDF / SHA helpers */
static void do_sha256(const uint8_t *in, size_t len, uint8_t out[32]) {
    SHA256(in, len, out);
}
static void do_hmac(const uint8_t key[32], const uint8_t *msg, size_t len, uint8_t out[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(), key, 32, msg, len, out, &olen);
}
static void do_hkdf_extract(const uint8_t salt[32], const uint8_t *ikm, size_t ikm_len, uint8_t prk[32]) {
    unsigned int olen = 32;
    HMAC(EVP_sha256(), salt, 32, ikm, ikm_len, prk, &olen);
}
static void do_hkdf_expand(const uint8_t prk[32], const uint8_t *info, size_t info_len, uint8_t okm[32]) {
    uint8_t buf[128];
    if (info_len > 120) info_len = 120;
    memcpy(buf, info, info_len);
    buf[info_len] = 0x01;
    unsigned int olen = 32;
    HMAC(EVP_sha256(), prk, 32, buf, info_len + 1, okm, &olen);
}
static void x25519_keygen(uint8_t pk[32], EVP_PKEY **out) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    *out = NULL;
    EVP_PKEY_keygen(pctx, out);
    size_t l = 32;
    EVP_PKEY_get_raw_public_key(*out, pk, &l);
    EVP_PKEY_CTX_free(pctx);
}
static void x25519_derive(EVP_PKEY *sk, const uint8_t peer_pk[32], uint8_t ss[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    size_t l = 32;
    EVP_PKEY_derive(ctx, ss, &l);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
}

typedef struct {
    double verify_us, keygen_us, encap_us, decap_us, sign_us, kdf_us, total_us;
    uint64_t total_cyc;
} Sample;

typedef struct {
    const char *name;
    double med_total_us, mean_total_us, std_total_us, iqr_total_us;
    uint64_t med_cycles;
    double mean_cycles;
    double mean_verify_us, mean_keygen_us, mean_encap_us, mean_decap_us, mean_sign_us, mean_kdf_us;
    int n;
} ProtoStat;

typedef struct {
    OQS_KEM *k512, *k768;
    OQS_SIG *d44, *d65, *f512;
    uint8_t *k512_pk, *k512_sk, *k512_ct1, *k512_ct2, *k512_ss;
    uint8_t *k768_pk, *k768_sk, *k768_ct1, *k768_ct2, *k768_ss;
    uint8_t *d44_pk, *d44_sk, *d44_sig; size_t d44_slen;
    uint8_t *d65_pk, *d65_sk, *d65_sig; size_t d65_slen;
    uint8_t *f512_pk, *f512_sk, *f512_sig; size_t f512_slen;
    EVP_PKEY *x_static_sk, *ed65_sk, *ed65_pk;
    uint8_t x_static_pk[32], x_peer_pk[32], ed65_sig[64];
    uint8_t msg[32], ak[32], qkd_key[32], tr_buf[512];
} AllCtx;

static void step_ria_l1(AllCtx *c, Sample *s) {
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t hsig[32], tr0[32], tr1[32], prk[32], kfin[32], ms[32], tag[32], comb[96];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *c3 = malloc(c->k512->length_ciphertext);
    uint8_t k1[32], k2[32], k3[32];

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, hsig);
    if (OQS_SIG_verify(c->d44, hsig, 32, c->d44_sig, c->d44_slen, c->d44_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    OQS_KEM_decaps(c->k512, k2, c->k512_ct2, c->k512_sk);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_encaps(c->k512, c3, k3, c->k512_pk);
    t1 = now_ns(); s->encap_us = (t1 - t0) / 1e3;

    s->sign_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr0);
    memcpy(comb, k1, 32); memcpy(comb+32, k2, 32); memcpy(comb+64, k3, 32);
    do_hkdf_extract(c->ak, comb, 96, prk);
    do_hkdf_expand(prk, (const uint8_t*)"finished", 8, kfin);
    do_hkdf_expand(prk, (const uint8_t*)"session", 7, ms);
    do_hmac(kfin, tr0, 32, tag);
    do_sha256(tr0, 32, tr1);
    do_hmac(kfin, tr1, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    free(eph_pk); free(eph_sk); free(c3);
}

static void step_ria_falcon(AllCtx *c, Sample *s) {
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t hsig[32], tr0[32], tr1[32], prk[32], kfin[32], ms[32], tag[32], comb[96];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *c3 = malloc(c->k512->length_ciphertext);
    uint8_t k1[32], k2[32], k3[32];

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, hsig);
    if (OQS_SIG_verify(c->f512, hsig, 32, c->f512_sig, c->f512_slen, c->f512_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    OQS_KEM_decaps(c->k512, k2, c->k512_ct2, c->k512_sk);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_encaps(c->k512, c3, k3, c->k512_pk);
    t1 = now_ns(); s->encap_us = (t1 - t0) / 1e3;

    s->sign_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr0);
    memcpy(comb, k1, 32); memcpy(comb+32, k2, 32); memcpy(comb+64, k3, 32);
    do_hkdf_extract(c->ak, comb, 96, prk);
    do_hkdf_expand(prk, (const uint8_t*)"finished", 8, kfin);
    do_hkdf_expand(prk, (const uint8_t*)"session", 7, ms);
    do_hmac(kfin, tr0, 32, tag);
    do_sha256(tr0, 32, tr1);
    do_hmac(kfin, tr1, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    free(eph_pk); free(eph_sk); free(c3);
}

static void step_ria_l3(AllCtx *c, Sample *s) {
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t hsig[32], tr0[32], tr1[32], prk[32], kfin[32], ms[32], tag[32], comb[96];
    uint8_t *eph_pk = malloc(c->k768->length_public_key);
    uint8_t *eph_sk = malloc(c->k768->length_secret_key);
    uint8_t *c3 = malloc(c->k768->length_ciphertext);
    uint8_t k1[32], k2[32], k3[32];

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, hsig);
    if (OQS_SIG_verify(c->d65, hsig, 32, c->d65_sig, c->d65_slen, c->d65_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k768, eph_pk, eph_sk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k768, k1, c->k768_ct1, c->k768_sk);
    OQS_KEM_decaps(c->k768, k2, c->k768_ct2, c->k768_sk);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_encaps(c->k768, c3, k3, c->k768_pk);
    t1 = now_ns(); s->encap_us = (t1 - t0) / 1e3;

    s->sign_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr0);
    memcpy(comb, k1, 32); memcpy(comb+32, k2, 32); memcpy(comb+64, k3, 32);
    do_hkdf_extract(c->ak, comb, 96, prk);
    do_hkdf_expand(prk, (const uint8_t*)"finished", 8, kfin);
    do_hkdf_expand(prk, (const uint8_t*)"session", 7, ms);
    do_hmac(kfin, tr0, 32, tag);
    do_sha256(tr0, 32, tr1);
    do_hmac(kfin, tr1, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    free(eph_pk); free(eph_sk); free(c3);
}

static void step_ria_hybrid(AllCtx *c, Sample *s) {
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t hsig[32], tr0[32], tr1[32], prk[32], kfin[32], ms[32], tag[32], comb[96];
    uint8_t *eph_pk = malloc(c->k768->length_public_key);
    uint8_t *eph_sk = malloc(c->k768->length_secret_key);
    uint8_t *c3 = malloc(c->k768->length_ciphertext);
    uint8_t k1[32], k2[32], k3[32], x1[32], x2[32], x3[32], x_epk[32], x_epk3[32];
    EVP_PKEY *x_esk = NULL, *x_esk3 = NULL;

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, hsig);
    if (OQS_SIG_verify(c->d65, hsig, 32, c->d65_sig, c->d65_slen, c->d65_pk) != OQS_SUCCESS) exit(3);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, c->ed65_pk);
    if (EVP_DigestVerify(mctx, c->ed65_sig, 64, hsig, 32) != 1) exit(4);
    EVP_MD_CTX_free(mctx);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k768, eph_pk, eph_sk);
    x25519_keygen(x_epk, &x_esk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k768, k1, c->k768_ct1, c->k768_sk);
    x25519_derive(c->x_static_sk, c->x_peer_pk, x1);
    OQS_KEM_decaps(c->k768, k2, c->k768_ct2, c->k768_sk);
    x25519_derive(x_esk, c->x_peer_pk, x2);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_encaps(c->k768, c3, k3, c->k768_pk);
    x25519_keygen(x_epk3, &x_esk3);
    x25519_derive(x_esk3, c->x_peer_pk, x3);
    t1 = now_ns(); s->encap_us = (t1 - t0) / 1e3;

    s->sign_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr0);
    /* Dual-PRF KEM combiner with ciphertext binding (Giacon-Heuer-Poettering):
       K_hyb,m = HKDF.Extract(salt=K_cl,m, IKM=K_pq,m || c_pq,m || c_cl,m),
       then PRK_sess = HKDF.Extract(AK_i, K_hyb,1 || K_hyb,2 || K_hyb,3). */
    size_t ctlen = c->k768->length_ciphertext;
    uint8_t ikm[32 + 1088 + 32];
    size_t ilen = 32 + ctlen + 32;
    memcpy(ikm, k1, 32); memcpy(ikm+32, c->k768_ct1, ctlen); memcpy(ikm+32+ctlen, c->x_peer_pk, 32);
    do_hkdf_extract(x1, ikm, ilen, comb);
    memcpy(ikm, k2, 32); memcpy(ikm+32, c->k768_ct2, ctlen); memcpy(ikm+32+ctlen, x_epk, 32);
    do_hkdf_extract(x2, ikm, ilen, comb+32);
    memcpy(ikm, k3, 32); memcpy(ikm+32, c3, ctlen); memcpy(ikm+32+ctlen, x_epk3, 32);
    do_hkdf_extract(x3, ikm, ilen, comb+64);
    do_hkdf_extract(c->ak, comb, 96, prk);
    do_hkdf_expand(prk, (const uint8_t*)"finished", 8, kfin);
    do_hkdf_expand(prk, (const uint8_t*)"session", 7, ms);
    do_hmac(kfin, tr0, 32, tag);
    do_sha256(tr0, 32, tr1);
    do_hmac(kfin, tr1, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    EVP_PKEY_free(x_esk); EVP_PKEY_free(x_esk3);
    free(eph_pk); free(eph_sk); free(c3);
}

static void step_mtls_pqc(AllCtx *c, Sample *s) {
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t tr[32], prk[32], okm[32], tag[32];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *csig = malloc(c->d44->length_signature);
    size_t cslen = 0;
    uint8_t k1[32];

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, tr);
    if (OQS_SIG_verify(c->d44, tr, 32, c->d44_sig, c->d44_slen, c->d44_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    s->encap_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr);
    OQS_SIG_sign(c->d44, csig, &cslen, tr, 32, c->d44_sk);
    t1 = now_ns(); s->sign_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    for (int i = 0; i < 3; i++) do_sha256(c->tr_buf, 256, tr);
    do_hkdf_extract(c->ak, k1, 32, prk);
    for (int i = 0; i < 4; i++) do_hkdf_expand(prk, tr, 32, okm);
    do_hmac(okm, tr, 32, tag);
    do_hmac(okm, tr, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    free(eph_pk); free(eph_sk); free(csig);
}

static void step_etsi_104146(AllCtx *c, Sample *s) {
    /* ETSI TS 104 146 Hybrid QKD+PQC+Classical (X25519 + ML-KEM-512 + ML-DSA-44 + chained HKDF CatKDF) */
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t tr[32], prk[32], okm[32], tag[32], xss[32], xpk[32], k1[32], comb[64];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *csig = malloc(c->d44->length_signature);
    size_t cslen = 0;
    EVP_PKEY *xsk = NULL;

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, tr);
    if (OQS_SIG_verify(c->d44, tr, 32, c->d44_sig, c->d44_slen, c->d44_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    x25519_keygen(xpk, &xsk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    x25519_derive(xsk, c->x_peer_pk, xss);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    s->encap_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr);
    OQS_SIG_sign(c->d44, csig, &cslen, tr, 32, c->d44_sk);
    t1 = now_ns(); s->sign_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    for (int i = 0; i < 3; i++) do_sha256(c->tr_buf, 256, tr);
    /* Chained HKDF combiner: classical || PQ || QKD */
    memcpy(comb, xss, 32); memcpy(comb+32, k1, 32);
    do_hkdf_extract(c->qkd_key, comb, 64, prk);
    do_hkdf_expand(prk, tr, 32, okm);
    do_hkdf_extract(okm, c->qkd_key, 32, prk);
    for (int i = 0; i < 4; i++) do_hkdf_expand(prk, tr, 32, okm);
    do_hmac(okm, tr, 32, tag);
    do_hmac(okm, tr, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    EVP_PKEY_free(xsk); free(eph_pk); free(eph_sk); free(csig);
}

static void step_qkd_ipsec(AllCtx *c, Sample *s) {
    /* RFC 7296 + RFC 9370 + RFC 8784 QKD PPK: X25519 + ML-KEM-512 + ML-DSA-44 + IKEv2 PRF+ */
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t tr[32], prk[32], okm[32], tag[32], xss[32], xpk[32], k1[32];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *csig = malloc(c->d44->length_signature);
    size_t cslen = 0;
    EVP_PKEY *xsk = NULL;

    t0 = now_ns();
    do_sha256(c->tr_buf, 256, tr);
    if (OQS_SIG_verify(c->d44, tr, 32, c->d44_sig, c->d44_slen, c->d44_pk) != OQS_SUCCESS) exit(3);
    t1 = now_ns(); s->verify_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    x25519_keygen(xpk, &xsk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    x25519_derive(xsk, c->x_peer_pk, xss);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    s->encap_us = 0.0;

    t0 = now_ns();
    do_sha256(c->tr_buf, 512, tr);
    OQS_SIG_sign(c->d44, csig, &cslen, tr, 32, c->d44_sk);
    t1 = now_ns(); s->sign_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    /* IKEv2 SKEYSEED + RFC 9370 intermediate PRF+ + RFC 8784 PPK mixing */
    do_hkdf_extract(xss, k1, 32, prk);
    for (int i = 0; i < 6; i++) do_hmac(prk, tr, 32, okm);
    do_hmac(c->qkd_key, okm, 32, tag);
    do_hmac(tag, tr, 32, okm);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    EVP_PKEY_free(xsk); free(eph_pk); free(eph_sk); free(csig);
}

static void step_kemtls(AllCtx *c, Sample *s) {
    /* KEMTLS Mutual-Auth (Schwabe et al., signature-free handshake: KGen + Decap + Encap) */
    uint64_t t0, t1, c0, c1, tot0 = now_ns();
    c0 = read_cycles();
    uint8_t tr[32], prk[32], okm[32], tag[32], k1[32], k2[32], comb[64];
    uint8_t *eph_pk = malloc(c->k512->length_public_key);
    uint8_t *eph_sk = malloc(c->k512->length_secret_key);
    uint8_t *ct = malloc(c->k512->length_ciphertext);

    s->verify_us = 0.0;

    t0 = now_ns();
    OQS_KEM_keypair(c->k512, eph_pk, eph_sk);
    t1 = now_ns(); s->keygen_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_decaps(c->k512, k1, c->k512_ct1, c->k512_sk);
    t1 = now_ns(); s->decap_us = (t1 - t0) / 1e3;

    t0 = now_ns();
    OQS_KEM_encaps(c->k512, ct, k2, c->k512_pk);
    t1 = now_ns(); s->encap_us = (t1 - t0) / 1e3;

    s->sign_us = 0.0;

    t0 = now_ns();
    for (int i = 0; i < 4; i++) do_sha256(c->tr_buf, 256, tr);
    memcpy(comb, k1, 32); memcpy(comb+32, k2, 32);
    do_hkdf_extract(c->ak, comb, 64, prk);
    for (int i = 0; i < 4; i++) do_hkdf_expand(prk, tr, 32, okm);
    do_hmac(okm, tr, 32, tag);
    do_hmac(okm, tr, 32, tag);
    t1 = now_ns(); s->kdf_us = (t1 - t0) / 1e3;

    c1 = read_cycles();
    s->total_us = (now_ns() - tot0) / 1e3;
    s->total_cyc = c1 - c0;
    free(eph_pk); free(eph_sk); free(ct);
}

static ProtoStat bench_proto(const char *name, void (*fn)(AllCtx*, Sample*), AllCtx *c, int warmup, int n) {
    Sample tmp;
    for (int i = 0; i < warmup; i++) fn(c, &tmp);

    double *tot = malloc((size_t)n * sizeof(double));
    uint64_t *cyc = malloc((size_t)n * sizeof(uint64_t));
    double sv=0, sk=0, se=0, sd=0, ss=0, skdf=0, stot=0, scyc=0;
    for (int i = 0; i < n; i++) {
        fn(c, &tmp);
        tot[i] = tmp.total_us;
        cyc[i] = tmp.total_cyc;
        sv += tmp.verify_us; sk += tmp.keygen_us; se += tmp.encap_us;
        sd += tmp.decap_us; ss += tmp.sign_us; skdf += tmp.kdf_us;
        stot += tmp.total_us; scyc += (double)tmp.total_cyc;
    }
    double mean_tot = stot / n;
    double var = 0;
    for (int i = 0; i < n; i++) { double d = tot[i] - mean_tot; var += d * d; }
    qsort(tot, (size_t)n, sizeof(double), cmp_d);
    qsort(cyc, (size_t)n, sizeof(uint64_t), cmp_u64);

    ProtoStat r = {
        .name = name,
        .med_total_us = tot[n / 2],
        .mean_total_us = mean_tot,
        .std_total_us = sqrt(var / n),
        .iqr_total_us = tot[(3 * n) / 4] - tot[n / 4],
        .med_cycles = cyc[n / 2],
        .mean_cycles = scyc / n,
        .mean_verify_us = sv / n,
        .mean_keygen_us = sk / n,
        .mean_encap_us = se / n,
        .mean_decap_us = sd / n,
        .mean_sign_us = ss / n,
        .mean_kdf_us = skdf / n,
        .n = n
    };
    free(tot); free(cyc);
    return r;
}

int main(int argc, char **argv) {
    const char *label = (argc > 1) ? argv[1] : "default";
    int warmup = (argc > 2) ? atoi(argv[2]) : 50;
    int n = (argc > 3) ? atoi(argv[3]) : 500;
    OQS_init();

    AllCtx c = {0};
    c.k512 = OQS_KEM_new("ML-KEM-512");
    c.k768 = OQS_KEM_new("ML-KEM-768");
    c.d44  = OQS_SIG_new("ML-DSA-44");
    c.d65  = OQS_SIG_new("ML-DSA-65");
    c.f512 = OQS_SIG_new("Falcon-padded-512");

    c.k512_pk = malloc(c.k512->length_public_key); c.k512_sk = malloc(c.k512->length_secret_key);
    c.k512_ct1 = malloc(c.k512->length_ciphertext); c.k512_ct2 = malloc(c.k512->length_ciphertext);
    c.k512_ss = malloc(c.k512->length_shared_secret);
    OQS_KEM_keypair(c.k512, c.k512_pk, c.k512_sk);
    OQS_KEM_encaps(c.k512, c.k512_ct1, c.k512_ss, c.k512_pk);
    OQS_KEM_encaps(c.k512, c.k512_ct2, c.k512_ss, c.k512_pk);

    c.k768_pk = malloc(c.k768->length_public_key); c.k768_sk = malloc(c.k768->length_secret_key);
    c.k768_ct1 = malloc(c.k768->length_ciphertext); c.k768_ct2 = malloc(c.k768->length_ciphertext);
    c.k768_ss = malloc(c.k768->length_shared_secret);
    OQS_KEM_keypair(c.k768, c.k768_pk, c.k768_sk);
    OQS_KEM_encaps(c.k768, c.k768_ct1, c.k768_ss, c.k768_pk);
    OQS_KEM_encaps(c.k768, c.k768_ct2, c.k768_ss, c.k768_pk);

    OQS_randombytes(c.msg, 32); OQS_randombytes(c.ak, 32); OQS_randombytes(c.qkd_key, 32); OQS_randombytes(c.tr_buf, 512);
    uint8_t hsig[32]; do_sha256(c.tr_buf, 256, hsig);

    c.d44_pk = malloc(c.d44->length_public_key); c.d44_sk = malloc(c.d44->length_secret_key); c.d44_sig = malloc(c.d44->length_signature);
    OQS_SIG_keypair(c.d44, c.d44_pk, c.d44_sk);
    OQS_SIG_sign(c.d44, c.d44_sig, &c.d44_slen, hsig, 32, c.d44_sk);

    c.d65_pk = malloc(c.d65->length_public_key); c.d65_sk = malloc(c.d65->length_secret_key); c.d65_sig = malloc(c.d65->length_signature);
    OQS_SIG_keypair(c.d65, c.d65_pk, c.d65_sk);
    OQS_SIG_sign(c.d65, c.d65_sig, &c.d65_slen, hsig, 32, c.d65_sk);

    c.f512_pk = malloc(c.f512->length_public_key); c.f512_sk = malloc(c.f512->length_secret_key); c.f512_sig = malloc(c.f512->length_signature);
    OQS_SIG_keypair(c.f512, c.f512_pk, c.f512_sk);
    OQS_SIG_sign(c.f512, c.f512_sig, &c.f512_slen, hsig, 32, c.f512_sk);

    EVP_PKEY *xp = NULL;
    x25519_keygen(c.x_static_pk, &c.x_static_sk);
    x25519_keygen(c.x_peer_pk, &xp);
    EVP_PKEY_free(xp);

    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx); EVP_PKEY_keygen(pctx, &c.ed65_sk); EVP_PKEY_CTX_free(pctx);
    uint8_t epk[32]; size_t el = 32;
    EVP_PKEY_get_raw_public_key(c.ed65_sk, epk, &el);
    c.ed65_pk = EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, NULL, epk, 32);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    size_t esl = 64;
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, c.ed65_sk);
    EVP_DigestSign(mctx, c.ed65_sig, &esl, hsig, 32);
    EVP_MD_CTX_free(mctx);

    ProtoStat stats[8];
    stats[0] = bench_proto("KEMTLS_MutualAuth", step_kemtls, &c, warmup, n);
    stats[1] = bench_proto("RIA_QKD_Falcon", step_ria_falcon, &c, warmup, n);
    stats[2] = bench_proto("RIA_QKD_L1", step_ria_l1, &c, warmup, n);
    stats[3] = bench_proto("RIA_QKD_L3", step_ria_l3, &c, warmup, n);
    stats[4] = bench_proto("RIA_QKD_Hybrid", step_ria_hybrid, &c, warmup, n);
    stats[5] = bench_proto("mTLS_PQC", step_mtls_pqc, &c, warmup, n);
    stats[6] = bench_proto("ETSI_TS_104_146_Hybrid", step_etsi_104146, &c, warmup, n);
    stats[7] = bench_proto("QKD_IPsec_IKEv2", step_qkd_ipsec, &c, warmup, n);

    printf("{\n  \"label\": \"%s\",\n  \"cycle_counter\": \"%s\",\n  \"n\": %d,\n  \"protocols\": {\n", label, CYCLE_SRC, n);
    for (int i = 0; i < 8; i++) {
        ProtoStat *p = &stats[i];
        printf("    \"%s\": {\n", p->name);
        printf("      \"med_total_us\": %.3f, \"mean_total_us\": %.3f, \"std_total_us\": %.3f, \"iqr_total_us\": %.3f,\n",
               p->med_total_us, p->mean_total_us, p->std_total_us, p->iqr_total_us);
        printf("      \"med_cycles\": %llu, \"mean_cycles\": %.0f,\n",
               (unsigned long long)p->med_cycles, p->mean_cycles);
        printf("      \"components_mean_us\": {\"verify\": %.3f, \"keygen\": %.3f, \"encap\": %.3f, \"decap\": %.3f, \"sign\": %.3f, \"kdf_hash_mac\": %.3f}\n",
               p->mean_verify_us, p->mean_keygen_us, p->mean_encap_us, p->mean_decap_us, p->mean_sign_us, p->mean_kdf_us);
        printf("    }%s\n", (i == 7) ? "" : ",");
    }
    printf("  }\n}\n");

    OQS_KEM_free(c.k512); OQS_KEM_free(c.k768);
    OQS_SIG_free(c.d44); OQS_SIG_free(c.d65); OQS_SIG_free(c.f512);
    EVP_PKEY_free(c.x_static_sk); EVP_PKEY_free(c.ed65_sk); EVP_PKEY_free(c.ed65_pk);
    free(c.k512_pk); free(c.k512_sk); free(c.k512_ct1); free(c.k512_ct2); free(c.k512_ss);
    free(c.k768_pk); free(c.k768_sk); free(c.k768_ct1); free(c.k768_ct2); free(c.k768_ss);
    free(c.d44_pk); free(c.d44_sk); free(c.d44_sig);
    free(c.d65_pk); free(c.d65_sk); free(c.d65_sig);
    free(c.f512_pk); free(c.f512_sk); free(c.f512_sig);
    OQS_destroy();
    return 0;
}
