#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "slh_dsa.h"
static int rbg(uint8_t*x,size_t n){FILE*f=fopen("/dev/urandom","rb");if(!f)return -1;size_t r=fread(x,1,n,f);fclose(f);return r==n?0:-1;}
static const slh_param_t* pick(const char*n){
  if(!strcmp(n,"sha2_128s"))return &slh_dsa_sha2_128s;
  if(!strcmp(n,"sha2_128f"))return &slh_dsa_sha2_128f;
  if(!strcmp(n,"sha2_192s"))return &slh_dsa_sha2_192s;
  if(!strcmp(n,"sha2_256s"))return &slh_dsa_sha2_256s;
  if(!strcmp(n,"sha2_128_24"))return &slh_dsa_sha2_128_24;
  return NULL;}
int main(int c,char**v){
  if(c<4){fprintf(stderr,"usage: %s gen|verify <alg> <prefix> [pk msg sig]\n",v[0]);return 1;}
  const slh_param_t*p=pick(v[2]); if(!p){fprintf(stderr,"unknown %s\n",v[2]);return 1;}
  size_t pkn=slh_pk_sz(p), sign=slh_sig_sz(p);
  if(!strcmp(v[1],"gen")){
    char fn[256]; uint8_t pk[64],sk[128],msg[32]; uint8_t*sig=malloc(sign);
    rbg(msg,32); slh_keygen(sk,pk,rbg,p); size_t sl=slh_sign(sig,msg,32,NULL,0,sk,NULL,p);
    snprintf(fn,sizeof fn,"%s_pk.bin",v[3]); FILE*f=fopen(fn,"wb");fwrite(pk,1,pkn,f);fclose(f);
    snprintf(fn,sizeof fn,"%s_msg.bin",v[3]); f=fopen(fn,"wb");fwrite(msg,1,32,f);fclose(f);
    snprintf(fn,sizeof fn,"%s_sig.bin",v[3]); f=fopen(fn,"wb");fwrite(sig,1,sl,f);fclose(f);
    int ok=slh_verify(msg,32,sig,sl,NULL,0,pk,p);
    printf("C gen %s: pk=%zu sig=%zu selfverify=%d\n",v[2],pkn,sl,ok); free(sig); return ok?0:2;
  } else {
    char fn[256]; uint8_t pk[64],msg[32]; uint8_t*sig=malloc(sign); size_t sl=0;
    snprintf(fn,sizeof fn,"%s_pk.bin",v[3]); FILE*f=fopen(fn,"rb");if(!f){perror(fn);return 3;}fread(pk,1,pkn,f);fclose(f);
    snprintf(fn,sizeof fn,"%s_msg.bin",v[3]); f=fopen(fn,"rb");fread(msg,1,32,f);fclose(f);
    snprintf(fn,sizeof fn,"%s_sig.bin",v[3]); f=fopen(fn,"rb");fseek(f,0,SEEK_END);sl=ftell(f);fseek(f,0,SEEK_SET);fread(sig,1,sl,f);fclose(f);
    int ok=slh_verify(msg,32,sig,sl,NULL,0,pk,p);
    printf("C verify %s: pk=%zu sig=%zu -> %s\n",v[2],pkn,sl,ok?"OK":"FAIL"); free(sig); return ok?0:2;
  }
}
