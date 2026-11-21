#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <math.h>
#include <openssl/evp.h>
#include <oqs/oqs.h>

static uint64_t now_ns(void){struct timespec ts;clock_gettime(CLOCK_MONOTONIC_RAW,&ts);return (uint64_t)ts.tv_sec*1000000000ULL+ts.tv_nsec;}
static int cmp_d(const void*a,const void*b){double x=*(const double*)a,y=*(const double*)b;return (x>y)-(x<y);}
typedef struct{double med,mean,iqr,std;int n;} St;
static St measure(void(*fn)(void*),void*ctx,int warm,int n){
    for(int i=0;i<warm;i++)fn(ctx);
    double*v=malloc(n*sizeof(double));double s=0;
    for(int i=0;i<n;i++){uint64_t t0=now_ns();fn(ctx);uint64_t t1=now_ns();v[i]=(t1-t0)/1000.0;s+=v[i];}
    double m=s/n,var=0;for(int i=0;i<n;i++){double d=v[i]-m;var+=d*d;}
    qsort(v,n,sizeof(double),cmp_d);
    St r={v[n/2],m,v[(3*n)/4]-v[n/4],sqrt(var/n),n};free(v);return r;
}
typedef struct{OQS_SIG*sig;uint8_t*pk,*sk,*sm,*msg;size_t mlen,smlen;} S;
static void s_kg(void*c){S*x=c;OQS_SIG_keypair(x->sig,x->pk,x->sk);}
static void s_sn(void*c){S*x=c;OQS_SIG_sign(x->sig,x->sm,&x->smlen,x->msg,x->mlen,x->sk);}
static void s_vf(void*c){S*x=c;if(OQS_SIG_verify(x->sig,x->msg,x->mlen,x->sm,x->smlen,x->pk)!=OQS_SUCCESS){fprintf(stderr,"VF FAIL\n");exit(2);}}
typedef struct{OQS_SIG*sig;uint8_t*pk,*sk,*sm,*msg;size_t mlen,smlen;EVP_PKEY*ed_sk,*ed_pk;uint8_t esig[64];} H;
static void h_kg(void*c){H*x=c;OQS_SIG_keypair(x->sig,x->pk,x->sk);}
static void h_sn(void*c){H*x=c;OQS_SIG_sign(x->sig,x->sm,&x->smlen,x->msg,x->mlen,x->sk);
    EVP_MD_CTX*m=EVP_MD_CTX_new();size_t l=64;EVP_DigestSignInit(m,NULL,NULL,NULL,x->ed_sk);EVP_DigestSign(m,x->esig,&l,x->msg,x->mlen);EVP_MD_CTX_free(m);}
static void h_vf(void*c){H*x=c;if(OQS_SIG_verify(x->sig,x->msg,x->mlen,x->sm,x->smlen,x->pk)!=OQS_SUCCESS){fprintf(stderr,"PQVF\n");exit(2);}
    EVP_MD_CTX*m=EVP_MD_CTX_new();EVP_DigestVerifyInit(m,NULL,NULL,NULL,x->ed_pk);int r=EVP_DigestVerify(m,x->esig,64,x->msg,x->mlen);EVP_MD_CTX_free(m);if(r!=1){fprintf(stderr,"EDVF\n");exit(2);}}
static void ps(const char*k,St s,int c){printf("    \"%s\": {\"med_us\": %.3f, \"mean_us\": %.3f, \"iqr_us\": %.3f, \"std_us\": %.3f, \"n\": %d}%s\n",k,s.med,s.mean,s.iqr,s.std,s.n,c?",":"");}
int main(int c,char**v){
    const char*label=c>1?v[1]:"sig";int n=c>2?atoi(v[2]):2000;OQS_init();
    uint8_t msg[32];for(int i=0;i<32;i++)msg[i]=(uint8_t)(i*7+3);
    printf("{\n  \"label\": \"%s\",\n  \"n\": %d,\n  \"fixed_msg\": true,\n  \"sigs\": {\n",label,n);
    /* ML-DSA-65 */
    {OQS_SIG*sg=OQS_SIG_new("ML-DSA-65");S x={.sig=sg,.pk=malloc(sg->length_public_key),.sk=malloc(sg->length_secret_key),.sm=malloc(sg->length_signature),.msg=msg,.mlen=32};
     s_kg(&x);St kg=measure(s_kg,&x,100,500);St sn=measure(s_sn,&x,50,n);St vf=measure(s_vf,&x,50,n);
     printf("  \"ML-DSA-65\": {\n");ps("keygen",kg,1);ps("sign",sn,1);ps("verify",vf,0);printf("  }%s\n",",");}
    /* Ed25519+ML-DSA-65 */
    {OQS_SIG*sg=OQS_SIG_new("ML-DSA-65");H x={.sig=sg,.pk=malloc(sg->length_public_key),.sk=malloc(sg->length_secret_key),.sm=malloc(sg->length_signature),.msg=msg,.mlen=32};
     EVP_PKEY_CTX*p=EVP_PKEY_CTX_new_id(EVP_PKEY_ED25519,NULL);EVP_PKEY_keygen_init(p);EVP_PKEY*ed=NULL;EVP_PKEY_keygen(p,&ed);EVP_PKEY_CTX_free(p);
     x.ed_pk=ed;x.ed_sk=ed;
     s_kg((S*)&x);St kg=measure(h_kg,&x,100,500);St sn=measure(h_sn,&x,50,n);St vf=measure(h_vf,&x,50,n);
     printf("  \"Ed25519+ML-DSA-65\": {\n");ps("keygen",kg,1);ps("sign",sn,1);ps("verify",vf,0);printf("  }\n");}
    printf("  }\n}\n");return 0;
}
