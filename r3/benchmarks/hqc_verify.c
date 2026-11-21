#include <stdio.h>
#include <string.h>
#include <oqs/oqs.h>
int main(){ setbuf(stdout,NULL);
    const char*n[]={"HQC-128","HQC-192","HQC-256"};
    for(int a=0;a<3;a++){
        OQS_KEM*k=OQS_KEM_new(n[a]);
        uint8_t *pk=malloc(k->length_public_key),*sk=malloc(k->length_secret_key),*ct=malloc(k->length_ciphertext),*ss1=malloc(k->length_shared_secret),*ss2=malloc(k->length_shared_secret);
        int fail=0;
        for(int i=0;i<30;i++){
            OQS_KEM_keypair(k,pk,sk); OQS_KEM_encaps(k,ct,ss1,pk); OQS_KEM_decaps(k,ss2,ct,sk);
            if(memcmp(ss1,ss2,k->length_shared_secret)!=0){fail++;}
        }
        printf("%s: 30 round-trips, failures=%d -> %s\n",n[a],fail,fail?"FAIL":"OK");
        free(pk);free(sk);free(ct);free(ss1);free(ss2);OQS_KEM_free(k);
    }
    return 0;
}
