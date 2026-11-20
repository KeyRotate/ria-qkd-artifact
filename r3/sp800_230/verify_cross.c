#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <oqs/oqs.h>
#include "slh_dsa.h"

static int my_rbg(uint8_t *x, size_t xlen) { OQS_randombytes(x, xlen); return 0; }
int main(void) {
    OQS_init();
    OQS_SIG *oqs_sig = OQS_SIG_new("SLH_DSA_PURE_SHA2_128S");
    uint8_t pk[64], sk[128], msg[32];
    OQS_randombytes(msg, 32);
    uint8_t *sig = malloc(7856);
    slh_keygen(sk, pk, my_rbg, &slh_dsa_sha2_128s);
    size_t slen = slh_sign(sig, msg, 32, NULL, 0, sk, NULL, &slh_dsa_sha2_128s);
    int ok_local = slh_verify(msg, 32, sig, slen, NULL, 0, pk, &slh_dsa_sha2_128s);
    int ok_oqs = (OQS_SIG_verify(oqs_sig, msg, 32, sig, slen, pk) == OQS_SUCCESS);
    printf("Cross-verify SLH-DSA-SHA2-128s: slen=%zu local=%d liboqs=%d\n", slen, ok_local, ok_oqs);
    free(sig); OQS_SIG_free(oqs_sig); OQS_destroy();
    return (ok_local && ok_oqs) ? 0 : 1;
}
