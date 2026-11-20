#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include "slh_dsa.h"

#if defined(__x86_64__)
#  include <x86intrin.h>
static inline uint64_t read_cycles(void) { unsigned int a; return __rdtscp(&a); }
#else
static inline uint64_t read_cycles(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
#endif

static inline uint64_t now_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}
static int dev_rbg(uint8_t *x, size_t xlen) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f) return -1;
    size_t r = fread(x, 1, xlen, f);
    fclose(f);
    return (r == xlen) ? 0 : -1;
}
static int cmp_d(const void *a, const void *b) {
    double x = *(const double *)a, y = *(const double *)b;
    return (x > y) - (x < y);
}
static int cmp_u64(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return (x > y) - (x < y);
}

static const slh_param_t *pick_param(const char *name) {
    if (strcmp(name, "sha2_128_24") == 0)  return &slh_dsa_sha2_128_24;
    if (strcmp(name, "shake_128_24") == 0) return &slh_dsa_shake_128_24;
    if (strcmp(name, "sha2_192_24") == 0)  return &slh_dsa_sha2_192_24;
    if (strcmp(name, "shake_192_24") == 0) return &slh_dsa_shake_192_24;
    if (strcmp(name, "sha2_256_24") == 0)  return &slh_dsa_sha2_256_24;
    if (strcmp(name, "shake_256_24") == 0) return &slh_dsa_shake_256_24;
    if (strcmp(name, "sha2_128s") == 0)    return &slh_dsa_sha2_128s;
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: %s <gen|verify> <param_name> <vec_file> [iters]\n", argv[0]);
        return 1;
    }
    const char *mode = argv[1];
    const char *pname = argv[2];
    const char *vpath = argv[3];
    int iters = (argc > 4) ? atoi(argv[4]) : 500;
    const slh_param_t *p = pick_param(pname);
    if (!p) { fprintf(stderr, "Unknown param: %s\n", pname); return 1; }

    size_t pk_sz = slh_pk_sz(p);
    size_t sk_sz = slh_sk_sz(p);
    size_t sig_sz = slh_sig_sz(p);
    uint8_t pk[64], sk[128], msg[32];
    uint8_t *sig = malloc(sig_sz);

    if (strcmp(mode, "gen") == 0) {
        dev_rbg(msg, 32);
        uint64_t t0 = now_ns(), c0 = read_cycles();
        slh_keygen(sk, pk, dev_rbg, p);
        uint64_t c_kg = read_cycles() - c0;
        double kg_ms = (now_ns() - t0) / 1e6;

        t0 = now_ns(); c0 = read_cycles();
        size_t slen = slh_sign(sig, msg, 32, NULL, 0, sk, NULL, p);
        uint64_t c_sg = read_cycles() - c0;
        double sg_ms = (now_ns() - t0) / 1e6;

        int ok = slh_verify(msg, 32, sig, slen, NULL, 0, pk, p);
        if (!ok || slen != sig_sz) {
            fprintf(stderr, "VERIFY FAILED for %s (ok=%d slen=%zu expected=%zu)\n", pname, ok, slen, sig_sz);
            return 2;
        }
        FILE *f = fopen(vpath, "wb");
        if (!f) { perror("fopen"); return 3; }
        uint32_t hdr[3] = {(uint32_t)pk_sz, (uint32_t)sig_sz, 32};
        fwrite(hdr, sizeof(uint32_t), 3, f);
        fwrite(pk, 1, pk_sz, f);
        fwrite(msg, 1, 32, f);
        fwrite(sig, 1, sig_sz, f);
        fclose(f);
        printf("{\"alg\": \"%s\", \"pk_bytes\": %zu, \"sk_bytes\": %zu, \"sig_bytes\": %zu, \"keygen_ms\": %.3f, \"keygen_cycles\": %llu, \"sign_ms\": %.3f, \"sign_cycles\": %llu, \"verified\": %d}\n",
               slh_alg_id(p), pk_sz, sk_sz, sig_sz, kg_ms, (unsigned long long)c_kg, sg_ms, (unsigned long long)c_sg, ok);
    } else if (strcmp(mode, "verify") == 0) {
        FILE *f = fopen(vpath, "rb");
        if (!f) { perror("fopen"); return 3; }
        uint32_t hdr[3];
        if (fread(hdr, sizeof(uint32_t), 3, f) != 3) return 4;
        if (hdr[0] != pk_sz || hdr[1] != sig_sz || hdr[2] != 32) return 5;
        if (fread(pk, 1, pk_sz, f) != pk_sz) return 6;
        if (fread(msg, 1, 32, f) != 32) return 7;
        if (fread(sig, 1, sig_sz, f) != sig_sz) return 8;
        fclose(f);

        for (int i = 0; i < 50; i++) {
            if (slh_verify(msg, 32, sig, sig_sz, NULL, 0, pk, p) != 1) return 9;
        }
        double *us = malloc((size_t)iters * sizeof(double));
        uint64_t *cy = malloc((size_t)iters * sizeof(uint64_t));
        for (int i = 0; i < iters; i++) {
            uint64_t t0 = now_ns(), c0 = read_cycles();
            int ok = slh_verify(msg, 32, sig, sig_sz, NULL, 0, pk, p);
            uint64_t c1 = read_cycles(), t1 = now_ns();
            if (ok != 1) return 10;
            us[i] = (t1 - t0) / 1e3;
            cy[i] = c1 - c0;
        }
        double sum = 0, sumc = 0;
        for (int i = 0; i < iters; i++) { sum += us[i]; sumc += (double)cy[i]; }
        double mean = sum / iters, var = 0;
        for (int i = 0; i < iters; i++) { double d = us[i] - mean; var += d * d; }
        qsort(us, (size_t)iters, sizeof(double), cmp_d);
        qsort(cy, (size_t)iters, sizeof(uint64_t), cmp_u64);
        printf("{\"alg\": \"%s\", \"pk_bytes\": %zu, \"sig_bytes\": %zu, \"verify_med_us\": %.3f, \"verify_mean_us\": %.3f, \"verify_std_us\": %.3f, \"verify_iqr_us\": %.3f, \"verify_med_cycles\": %llu, \"verify_mean_cycles\": %.0f, \"n\": %d}\n",
               slh_alg_id(p), pk_sz, sig_sz, us[iters/2], mean, sqrt(var/iters), us[(3*iters)/4]-us[iters/4], (unsigned long long)cy[iters/2], sumc/iters, iters);
        free(us); free(cy);
    }
    free(sig);
    return 0;
}
