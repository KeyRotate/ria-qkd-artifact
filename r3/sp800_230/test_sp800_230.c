#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "slh_dsa.h"

static int dummy_rbg(uint8_t *x, size_t xlen) {
    for (size_t i = 0; i < xlen; i++) x[i] = (uint8_t)(i * 37 + 13);
    return 0;
}
static double now_ms(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return ts.tv_sec * 1e3 + ts.tv_nsec / 1e6;
}
int main(void) {
    const slh_param_t *ps[] = {
        &slh_dsa_sha2_128s, &slh_dsa_sha2_128_24, &slh_dsa_shake_128_24,
        &slh_dsa_sha2_192_24, &slh_dsa_shake_192_24,
        &slh_dsa_sha2_256_24, &slh_dsa_shake_256_24
    };
    for (int i = 0; i < 7; i++) {
        printf("%-22s pk=%zu sk=%zu sig=%zu\n", slh_alg_id(ps[i]), slh_pk_sz(ps[i]), slh_sk_sz(ps[i]), slh_sig_sz(ps[i]));
    }
    /* Test 128s roundtrip & timing */
    const slh_param_t *p = &slh_dsa_sha2_128s;
    uint8_t pk[64], sk[128], msg[32] = {0x42};
    uint8_t *sig = malloc(slh_sig_sz(p));
    double t0 = now_ms();
    slh_keygen(sk, pk, dummy_rbg, p);
    double t_kg = now_ms() - t0;
    t0 = now_ms();
    size_t slen = slh_sign(sig, msg, 32, NULL, 0, sk, NULL, p);
    double t_sg = now_ms() - t0;
    t0 = now_ms();
    int ok = slh_verify(msg, 32, sig, slen, NULL, 0, pk, p);
    double t_vf = now_ms() - t0;
    printf("128s test: ok=%d slen=%zu kg=%.2f ms sign=%.2f ms verify=%.3f ms\n", ok, slen, t_kg, t_sg, t_vf);
    free(sig);
    return ok ? 0 : 1;
}
