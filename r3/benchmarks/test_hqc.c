#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <oqs/oqs.h>
static double now_ms(void){ struct timespec ts; clock_gettime(CLOCK_MONOTONIC_RAW,&ts); return ts.tv_sec*1e3 + ts.tv_nsec/1e6; }
int main(void){
    OQS_init();
    const char *kems[] = {"HQC-128","HQC-192","HQC-256","FrodoKEM-640-AES","Classic-McEliece-348864"};
    for(int k=0;k<5;k++){
        OQS_KEM *kem = OQS_KEM_new(kems[k]);
        if(!kem){ printf("%s NULL\n", kems[k]); continue; }
        uint8_t *pk=malloc(kem->length_public_key), *sk=malloc(kem->length_secret_key), *ct=malloc(kem->length_ciphertext), *ss1=malloc(kem->length_shared_secret), *ss2=malloc(kem->length_shared_secret);
        double t0=now_ms(); OQS_KEM_keypair(kem,pk,sk); double t_kg=now_ms()-t0;
        t0=now_ms(); OQS_KEM_encaps(kem,ct,ss1,pk); double t_enc=now_ms()-t0;
        t0=now_ms(); OQS_KEM_decaps(kem,ss2,ct,sk); double t_dec=now_ms()-t0;
        printf("%-26s pk=%6zu sk=%5zu ct=%5zu ss=%2zu | kg=%7.3f enc=%7.3f dec=%7.3f ms\n",
               kems[k], kem->length_public_key, kem->length_secret_key, kem->length_ciphertext, kem->length_shared_secret, t_kg, t_enc, t_dec);
        free(pk); free(sk); free(ct); free(ss1); free(ss2); OQS_KEM_free(kem);
    }
    OQS_destroy(); return 0;
}
