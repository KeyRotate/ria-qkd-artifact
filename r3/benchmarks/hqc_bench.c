#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <oqs/oqs.h>
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>

#if defined(__x86_64__)
#  include <x86intrin.h>
static inline uint64_t read_cycles(void) {
    unsigned int aux;
    return __rdtscp(&aux);
}
static const char *CYCLE_SRC = "rdtscp";
#elif defined(__aarch64__)
static inline uint64_t read_cycles(void) {
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v));
    return v;
}
static const char *CYCLE_SRC = "cntvct_el0";
#else
static inline uint64_t read_cycles(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static const char *CYCLE_SRC = "CLOCK_MONOTONIC_RAW_ns";
#endif

static inline uint64_t now_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
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

typedef struct {
    double med_us;
    double mean_us;
    double std_us;
    double iqr_us;
    uint64_t med_cyc;
    double mean_cyc;
    int n;
} Stat;

static void pick_counts(double pilot_us, int *warmup, int *n) {
    if (pilot_us < 500.0) { *warmup = 200; *n = 1000; }
    else if (pilot_us < 5000.0) { *warmup = 50; *n = 500; }
    else if (pilot_us < 50000.0) { *warmup = 10; *n = 100; }
    else if (pilot_us < 400000.0) { *warmup = 3; *n = 20; }
    else if (pilot_us < 2000000.0) { *warmup = 1; *n = 5; }
    else { *warmup = 0; *n = 3; }
}

static Stat run_bench(void (*fn)(void *), void *ctx) {
    uint64_t t0 = now_ns();
    fn(ctx);
    double pilot_us = (now_ns() - t0) / 1000.0;
    int warmup = 0, n = 0;
    pick_counts(pilot_us, &warmup, &n);

    for (int i = 0; i < warmup; i++) fn(ctx);

    double *us = malloc((size_t)n * sizeof(double));
    uint64_t *cy = malloc((size_t)n * sizeof(uint64_t));
    for (int i = 0; i < n; i++) {
        uint64_t ts0 = now_ns();
        uint64_t c0 = read_cycles();
        fn(ctx);
        uint64_t c1 = read_cycles();
        uint64_t ts1 = now_ns();
        us[i] = (double)(ts1 - ts0) / 1000.0;
        cy[i] = c1 - c0;
    }
    double sum_us = 0, sum_cy = 0;
    for (int i = 0; i < n; i++) { sum_us += us[i]; sum_cy += (double)cy[i]; }
    double mean_us = sum_us / n;
    double mean_cy = sum_cy / n;
    double var = 0;
    for (int i = 0; i < n; i++) { double d = us[i] - mean_us; var += d * d; }
    double std_us = sqrt(var / n);

    qsort(us, (size_t)n, sizeof(double), cmp_d);
    qsort(cy, (size_t)n, sizeof(uint64_t), cmp_u64);
    double q25 = us[n / 4], q75 = us[(3 * n) / 4];

    Stat s = {
        .med_us = us[n / 2],
        .mean_us = mean_us,
        .std_us = std_us,
        .iqr_us = q75 - q25,
        .med_cyc = cy[n / 2],
        .mean_cyc = mean_cy,
        .n = n
    };
    free(us); free(cy);
    return s;
}

/* ── OpenSSL X25519 + Ed25519 helpers ── */
static void x25519_keygen(uint8_t pk[32], EVP_PKEY **out_pkey) {
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_keygen(pctx, &pkey);
    size_t len = 32;
    EVP_PKEY_get_raw_public_key(pkey, pk, &len);
    EVP_PKEY_CTX_free(pctx);
    *out_pkey = pkey;
}

static void x25519_derive(EVP_PKEY *sk_self, const uint8_t peer_pk[32], uint8_t out_ss[32]) {
    EVP_PKEY *peer = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, peer_pk, 32);
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(sk_self, NULL);
    EVP_PKEY_derive_init(ctx);
    EVP_PKEY_derive_set_peer(ctx, peer);
    size_t slen = 32;
    EVP_PKEY_derive(ctx, out_ss, &slen);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(peer);
}

static void hkdf_combine_2(const uint8_t *ss1, size_t l1, const uint8_t *ss2, size_t l2, uint8_t out[32]) {
    uint8_t buf[128];
    memcpy(buf, ss1, l1);
    memcpy(buf + l1, ss2, l2);
    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    EVP_KDF_CTX *kctx = EVP_KDF_CTX_new(kdf);
    OSSL_PARAM params[4];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", buf, l1 + l2);
    params[2] = OSSL_PARAM_construct_octet_string("info", (void *)"HYBRID-KEM", 10);
    params[3] = OSSL_PARAM_construct_end();
    EVP_KDF_derive(kctx, out, 32, params);
    EVP_KDF_CTX_free(kctx);
    EVP_KDF_free(kdf);
}

/* ── Contexts ── */
typedef struct { OQS_KEM *kem; uint8_t *pk, *sk, *ct, *ss; } KemCtx;
static void kem_kg(void *c)  { KemCtx *x = c; OQS_KEM_keypair(x->kem, x->pk, x->sk); }
static void kem_enc(void *c) { KemCtx *x = c; OQS_KEM_encaps(x->kem, x->ct, x->ss, x->pk); }
static void kem_dec(void *c) { KemCtx *x = c; OQS_KEM_decaps(x->kem, x->ss, x->ct, x->sk); }

typedef struct {
    OQS_KEM *kem;
    uint8_t *pq_pk, *pq_sk, *pq_ct, *pq_ss;
    EVP_PKEY *x_static_sk;
    uint8_t x_static_pk[32];
    uint8_t x_eph_pk[32];
    uint8_t out_ss[32];
} HybridKemCtx;

static void hyb_kem_kg(void *c) {
    HybridKemCtx *x = c;
    OQS_KEM_keypair(x->kem, x->pq_pk, x->pq_sk);
    EVP_PKEY *k = NULL;
    uint8_t pk[32];
    x25519_keygen(pk, &k);
    EVP_PKEY_free(k);
}
static void hyb_kem_enc(void *c) {
    HybridKemCtx *x = c;
    OQS_KEM_encaps(x->kem, x->pq_ct, x->pq_ss, x->pq_pk);
    EVP_PKEY *eph = NULL;
    uint8_t eph_pk[32], xss[32];
    x25519_keygen(eph_pk, &eph);
    x25519_derive(eph, x->x_static_pk, xss);
    hkdf_combine_2(x->pq_ss, x->kem->length_shared_secret, xss, 32, x->out_ss);
    EVP_PKEY_free(eph);
}
static void hyb_kem_dec(void *c) {
    HybridKemCtx *x = c;
    OQS_KEM_decaps(x->kem, x->pq_ss, x->pq_ct, x->pq_sk);
    uint8_t xss[32];
    x25519_derive(x->x_static_sk, x->x_eph_pk, xss);
    hkdf_combine_2(x->pq_ss, x->kem->length_shared_secret, xss, 32, x->out_ss);
}

typedef struct { OQS_SIG *sig; uint8_t *pk, *sk, *sm, *msg; size_t mlen, smlen; } SigCtx;
static void sig_kg(void *c)  { SigCtx *x = c; OQS_SIG_keypair(x->sig, x->pk, x->sk); }
static void sig_sn(void *c)  { SigCtx *x = c; OQS_SIG_sign(x->sig, x->sm, &x->smlen, x->msg, x->mlen, x->sk); }
static void sig_vf(void *c)  {
    SigCtx *x = c;
    if (OQS_SIG_verify(x->sig, x->msg, x->mlen, x->sm, x->smlen, x->pk) != OQS_SUCCESS) {
        fprintf(stderr, "VERIFY FAILED\n"); exit(2);
    }
}

typedef struct {
    OQS_SIG *sig;
    uint8_t *pq_pk, *pq_sk, *pq_sm, *msg;
    size_t mlen, pq_smlen;
    EVP_PKEY *ed_sk, *ed_pk;
    uint8_t ed_sig[64];
} HybridSigCtx;

static void hyb_sig_kg(void *c) {
    HybridSigCtx *x = c;
    OQS_SIG_keypair(x->sig, x->pq_pk, x->pq_sk);
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *k = NULL;
    EVP_PKEY_keygen(pctx, &k);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(pctx);
}
static void hyb_sig_sn(void *c) {
    HybridSigCtx *x = c;
    OQS_SIG_sign(x->sig, x->pq_sm, &x->pq_smlen, x->msg, x->mlen, x->pq_sk);
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    size_t slen = 64;
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, x->ed_sk);
    EVP_DigestSign(mctx, x->ed_sig, &slen, x->msg, x->mlen);
    EVP_MD_CTX_free(mctx);
}
static void hyb_sig_vf(void *c) {
    HybridSigCtx *x = c;
    if (OQS_SIG_verify(x->sig, x->msg, x->mlen, x->pq_sm, x->pq_smlen, x->pq_pk) != OQS_SUCCESS) {
        fprintf(stderr, "PQ VERIFY FAIL\n"); exit(2);
    }
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, x->ed_pk);
    int rc = EVP_DigestVerify(mctx, x->ed_sig, 64, x->msg, x->mlen);
    EVP_MD_CTX_free(mctx);
    if (rc != 1) { fprintf(stderr, "ED25519 VERIFY FAIL\n"); exit(2); }
}

typedef struct {
    EVP_PKEY *ed_sk, *ed_pk;
    uint8_t msg[32], sig[64];
} EdCtx;
static void ed_kg(void *c) {
    (void)c;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519, NULL);
    EVP_PKEY_keygen_init(pctx);
    EVP_PKEY *k = NULL;
    EVP_PKEY_keygen(pctx, &k);
    EVP_PKEY_free(k);
    EVP_PKEY_CTX_free(pctx);
}
static void ed_sn(void *c) {
    EdCtx *x = c;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    size_t slen = 64;
    EVP_DigestSignInit(mctx, NULL, NULL, NULL, x->ed_sk);
    EVP_DigestSign(mctx, x->sig, &slen, x->msg, 32);
    EVP_MD_CTX_free(mctx);
}
static void ed_vf(void *c) {
    EdCtx *x = c;
    EVP_MD_CTX *mctx = EVP_MD_CTX_new();
    EVP_DigestVerifyInit(mctx, NULL, NULL, NULL, x->ed_pk);
    if (EVP_DigestVerify(mctx, x->sig, 64, x->msg, 32) != 1) { fprintf(stderr, "ED FAIL\n"); exit(2); }
    EVP_MD_CTX_free(mctx);
}

typedef struct { EVP_PKEY *sk1; uint8_t pk1[32], pk2[32], ss[32]; } XCtx;
static void x_kg(void *c)  { (void)c; EVP_PKEY *k=NULL; uint8_t p[32]; x25519_keygen(p, &k); EVP_PKEY_free(k); }
static void x_enc(void *c) { XCtx *x = c; EVP_PKEY *e=NULL; uint8_t p[32]; x25519_keygen(p, &e); x25519_derive(e, x->pk1, x->ss); EVP_PKEY_free(e); }
static void x_dec(void *c) { XCtx *x = c; x25519_derive(x->sk1, x->pk2, x->ss); }

static void print_stat_json(const char *key, Stat s, int comma) {
    printf("      \"%s\": {\"med_us\": %.3f, \"mean_us\": %.3f, \"std_us\": %.3f, \"iqr_us\": %.3f, \"med_cycles\": %llu, \"mean_cycles\": %.0f, \"n\": %d}%s\n",
           key, s.med_us, s.mean_us, s.std_us, s.iqr_us, (unsigned long long)s.med_cyc, s.mean_cyc, s.n, comma ? "," : "");
}

static void get_cpu_model(char *buf, size_t sz) {
    buf[0] = '\0';
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return;
    char line[256];
    while (fgets(line, sizeof(line), f)) {
        char *p;
        if ((p = strstr(line, "model name")) && strchr(p, ':')) {
            p = strchr(p, ':') + 2;
            size_t l = strlen(p); if (l && p[l-1]=='\n') p[l-1]='\0';
            snprintf(buf, sz, "%s", p); break;
        }
        if ((p = strstr(line, "Hardware")) && strchr(p, ':')) {
            p = strchr(p, ':') + 2;
            size_t l = strlen(p); if (l && p[l-1]=='\n') p[l-1]='\0';
            snprintf(buf, sz, "%s", p);
        }
    }
    fclose(f);
}

int main(int argc, char **argv) {
    const char *label = (argc > 1) ? argv[1] : "hqc";
    OQS_init();
    char cpu_model[256]; get_cpu_model(cpu_model, sizeof(cpu_model));
    printf("{\n  \"label\": \"%s\",\n  \"oqs_version\": \"%s\",\n  \"cpu_model\": \"%s\",\n  \"cycle_counter\": \"%s\",\n  \"kems\": {\n", label, OQS_version(), cpu_model, CYCLE_SRC);
    const char *names[] = {"HQC-128","HQC-192","HQC-256"};
    for (int i=0;i<3;i++){
        OQS_KEM *kem=OQS_KEM_new(names[i]);
        if(!kem){fprintf(stderr,"missing %s\n",names[i]);continue;}
        KemCtx c={.kem=kem,.pk=malloc(kem->length_public_key),.sk=malloc(kem->length_secret_key),.ct=malloc(kem->length_ciphertext),.ss=malloc(kem->length_shared_secret)};
        OQS_KEM_keypair(kem,c.pk,c.sk); OQS_KEM_encaps(kem,c.ct,c.ss,c.pk);
        Stat skg=run_bench(kem_kg,&c), sen=run_bench(kem_enc,&c), sde=run_bench(kem_dec,&c);
        printf("    \"%s\": {\n      \"pk_bytes\": %zu, \"ct_bytes\": %zu,\n", names[i], kem->length_public_key, kem->length_ciphertext);
        print_stat_json("keygen",skg,1); print_stat_json("encap",sen,1); print_stat_json("decap",sde,0);
        printf("    }%s\n", i<2?",":"");
        free(c.pk);free(c.sk);free(c.ct);free(c.ss);OQS_KEM_free(kem);
    }
    printf("  }\n}\n");
    return 0;
}
